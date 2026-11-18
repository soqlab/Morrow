"""Make it safe: Done. The one-click change at Cloudflare, its preview, undo, refusals and the token rule.

No network. Cloudflare's API v4 is a fake built from recorded responses (fixtures/cloudflare/*.json,
in the shapes the API reference documents); it keeps the records' state so a PATCH is visible to the
next GET, and it records every call so a test can prove what was (and was not) sent. The grade is
services.public_grade.check replaced, as in test_make_safe.py.
"""

import copy
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import make_safe as ms
from services import make_safe_done as done
from services import org_rate_limits as _limits
from services import proof_signing
from services import public_check as _check
from services import public_grade as _grade

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "cloudflare")
TOKEN = "Tq8rZ1x9VbN4mK2pLw7sYd3fHj6gQe5cRt0uIo-_"
HOST = "www.example.com"
ZONE_ID = "023e105f4ecef8ad9ca31a8372d0c353"
REC_A = "372e67954025e0ba6aaa6d586b9e0b59"
REC_AAAA = "9a7806061c88ada191ed06f989cc3dac"


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


class FakeCloudflare:
    """api.cloudflare.com/client/v4 for one zone, answering with the recorded bodies."""

    def __init__(self, token=TOKEN, deny=(), tls="on", zones="zones_example_com.json"):
        self.token = token
        self.deny = set(deny)  # "zones", "dns_read", "dns_edit", "settings_read", "settings_edit"
        self.tls = tls
        self.zones = fixture(zones)
        self.records = {r["id"]: r for r in fixture("dns_records_dns_only.json")["result"]}
        self.calls = []

    def __call__(self, method, url, headers, body):
        assert url.startswith("https://api.cloudflare.com/client/v4/")
        parts = urlsplit(url)
        path, query = parts.path[len("/client/v4"):], parse_qs(parts.query)
        self.calls.append((method, path, query, json.loads(body) if body else None))
        if headers.get("Authorization") != "Bearer " + self.token:
            return 400, json.dumps(fixture("error_invalid_token_400.json")).encode()
        denied = (403, json.dumps(fixture("error_auth_403.json")).encode())
        if path == "/zones":
            if "zones" in self.deny:
                return denied
            want = (query.get("name") or [None])[0]
            result = [z for z in self.zones["result"] if want is None or z["name"] == want]
            return 200, json.dumps({**self.zones, "result": result}).encode()
        zone_prefix = f"/zones/{ZONE_ID}"
        if not path.startswith(zone_prefix) or not any(z["id"] == ZONE_ID for z in self.zones["result"]):
            return denied
        rest = path[len(zone_prefix):]
        if rest == "/dns_records" and method == "GET":
            if "dns_read" in self.deny:
                return denied
            name = (query.get("name.exact") or [""])[0]
            result = [copy.deepcopy(r) for r in self.records.values() if r["name"] == name]
            return 200, json.dumps({"success": True, "errors": [], "messages": [], "result": result}).encode()
        if rest.startswith("/dns_records/") and method == "PATCH":
            if "dns_edit" in self.deny:
                return denied
            rec = self.records[rest.rsplit("/", 1)[1]]
            payload = json.loads(body)
            assert set(payload) == {"proxied"}, "Done sends only the proxy status"
            rec["proxied"] = payload["proxied"]
            rec["ttl"] = 1
            return 200, json.dumps({"success": True, "errors": [], "messages": [], "result": rec}).encode()
        if rest == "/settings/tls_1_3":
            if method == "GET":
                if "settings_read" in self.deny:
                    return denied
                return 200, json.dumps(fixture(f"setting_tls_1_3_{'off' if self.tls == 'off' else 'on'}.json")).encode()
            if "settings_edit" in self.deny:
                return denied
            self.tls = json.loads(body)["value"]
            out = fixture("setting_tls_1_3_on.json")
            out["result"]["value"] = self.tls
            return 200, json.dumps(out).encode()
        return 404, b'{"success":false,"errors":[{"code":7003,"message":"No route for that URI"}]}'

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    db = tmp_path / "make-safe-done.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    for mod in (_check, _grade, ms, done):
        mod._TABLES_READY.clear()
    ms._detect_cache.clear()
    proof_signing.reset_cache_for_tests()
    _limits.reset()
    yield db
    for mod in (_check, _grade, ms, done):
        mod._TABLES_READY.clear()
    proof_signing.reset_cache_for_tests()
    _limits.reset()


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCloudflare()
    monkeypatch.setattr(done, "transport", fake)
    return fake


def graded(post_quantum=False, **over):
    group = "X25519MLKEM768" if post_quantum else "x25519"
    out = {"domain": HOST, "scanned_at": ms.iso(datetime.now(timezone.utc)), "grade": "A" if post_quantum else "C",
           "key_exchange": {"group": group, "post_quantum": post_quantum, "hybrid": post_quantum},
           "certificate": {"issuer": "CN=R11,O=Let's Encrypt,C=US"}, "server_software": "nginx/1.27.4",
           "edge_headers": {}, "fixes": []}
    out.update(over)
    return out


def cf_dns(host):
    return {"cname": [], "addresses": ["192.0.2.10"], "ns": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
            "ns_zone": "example.com"}


# ── the offer ────────────────────────────────────────────────────────────────


def test_a_grey_cloud_host_on_cloudflare_dns_is_offered_done():
    plan = ms.plan(HOST, graded(), lookup=cf_dns)
    assert plan["detected"]["stack"] == "nginx"  # visitors reach the origin: no Cloudflare edge signal
    offer = plan["one_click"]
    assert offer["provider"] == "cloudflare" and offer["proxied"] is False and offer["token_kept"] is False
    tpl = offer["token_template"]
    assert tpl["permissions"] == ["Zone > Zone > Read", "Zone > DNS > Edit"]
    assert tpl["url"].startswith("https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=")
    assert "%22dns%22" in tpl["url"] and "%22edit%22" in tpl["url"] and "zone_settings" not in tpl["url"]
    assert "example.com" in tpl["zone_resources"]


def test_no_offer_for_a_safe_host_or_dns_elsewhere_or_another_edge():
    assert ms.plan(HOST, graded(True), lookup=cf_dns)["one_click"] is None
    assert ms.plan(HOST, graded(), lookup=lambda h: {"cname": [], "addresses": ["192.0.2.10"],
                                                     "ns": ["ns1.example.net"]})["one_click"] is None
    behind_cloudfront = lambda h: {**cf_dns(h), "cname": ["d111111abcdef8.cloudfront.net"]}  # noqa: E731
    assert ms.plan(HOST, graded(), lookup=behind_cloudfront)["one_click"] is None


def test_a_proxied_host_that_is_still_classical_is_offered_done():
    plan = ms.plan(HOST, graded(server_software="cloudflare"), lookup=cf_dns)
    assert plan["one_click"]["proxied"] is True


def test_nameservers_are_read_from_the_closest_zone():
    answers = {("www.example.com", "NS"): [], ("example.com", "NS"): ["bob.ns.cloudflare.com", "ada.ns.cloudflare.com"]}
    ns, zone = ms._nameservers("www.example.com", lambda n, t: answers.get((n, t), []))
    assert zone == "example.com" and ns == ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]


# ── preview: exactly one change, nothing changed ─────────────────────────────


def test_the_preview_names_exactly_one_change_and_changes_nothing(cf):
    out = done.preview(HOST, TOKEN)
    change = out["change"]
    assert change["kind"] == done.KIND_PROXY
    assert change["title"] == "www.example.com from DNS only to Proxied"
    assert {(r["type"], r["from"], r["to"]) for r in change["records"]} == {("A", "DNS only", "Proxied"),
                                                                            ("AAAA", "DNS only", "Proxied")}
    assert change["nothing_else"].startswith("Nothing else.")
    assert any("certificate" in c for c in change["consequences"])
    assert any("192.0.2.10" in c for c in change["consequences"])
    assert "60 minutes" in change["propagation"]
    assert out["token_kept"] is False and out["preview_id"]
    assert cf.writes() == []
    assert all(r["proxied"] is False for r in cf.records.values())


def test_nothing_changes_without_confirm(cf):
    done.preview(HOST, TOKEN)
    done.preview(HOST, TOKEN)
    assert cf.writes() == []


def test_confirm_makes_only_the_previewed_change_and_undo_puts_it_back(cf):
    pre = done.preview(HOST, TOKEN)
    out = done.apply(HOST, pre["preview_id"], TOKEN)
    assert out["applied"] is True and out["propagation_seconds"] == 3600
    assert [(m, p, b) for m, p, _, b in cf.writes()] == [
        ("PATCH", f"/zones/{ZONE_ID}/dns_records/{REC_A}", {"proxied": True}),
        ("PATCH", f"/zones/{ZONE_ID}/dns_records/{REC_AAAA}", {"proxied": True}),
    ]
    assert all(r["proxied"] is True for r in cf.records.values())
    with pytest.raises(done.DoneError) as again:
        done.apply(HOST, pre["preview_id"], TOKEN)
    assert again.value.error == "already_applied"

    back = done.undo(HOST, out["change_id"], TOKEN)
    assert back["undone"] is True and back["skipped"] == []
    assert all(r["proxied"] is False for r in cf.records.values())
    with pytest.raises(done.DoneError) as twice:
        done.undo(HOST, out["change_id"], TOKEN)
    assert twice.value.error == "already_undone"


def test_undo_leaves_alone_a_record_someone_changed_since(cf):
    pre = done.preview(HOST, TOKEN)
    out = done.apply(HOST, pre["preview_id"], TOKEN)
    cf.records[REC_AAAA]["proxied"] = False  # the owner switched it back by hand
    back = done.undo(HOST, out["change_id"], TOKEN)
    assert back["skipped"] == ["AAAA 2001:db8::10"]
    assert cf.writes()[-1][1].endswith(REC_A)


def test_undo_has_a_window(cf, monkeypatch):
    pre = done.preview(HOST, TOKEN)
    out = done.apply(HOST, pre["preview_id"], TOKEN)
    later = datetime.now(timezone.utc) + timedelta(seconds=done.UNDO_SECONDS + 60)
    monkeypatch.setattr(done, "now_utc", lambda: later)
    with pytest.raises(done.DoneError) as exc:
        done.undo(HOST, out["change_id"], TOKEN)
    assert exc.value.error == "undo_expired" and "by hand" in exc.value.next_step


def test_a_record_that_moved_after_the_preview_is_not_changed(cf):
    pre = done.preview(HOST, TOKEN)
    cf.records[REC_A]["content"] = "198.51.100.7"
    with pytest.raises(done.DoneError) as exc:
        done.apply(HOST, pre["preview_id"], TOKEN)
    assert exc.value.error == "changed_since_preview"
    assert cf.writes() == []


def test_an_old_preview_is_refused(cf, monkeypatch):
    pre = done.preview(HOST, TOKEN)
    later = datetime.now(timezone.utc) + timedelta(seconds=done.PREVIEW_SECONDS + 5)
    monkeypatch.setattr(done, "now_utc", lambda: later)
    with pytest.raises(done.DoneError) as exc:
        done.apply(HOST, pre["preview_id"], TOKEN)
    assert exc.value.error == "preview_expired" and cf.writes() == []


def test_tls_1_3_off_is_the_change_when_the_record_is_already_proxied(cf):
    for r in cf.records.values():
        r["proxied"] = True
    cf.tls = "off"
    pre = done.preview(HOST, TOKEN)
    assert pre["change"]["kind"] == done.KIND_TLS13
    assert pre["needs_permission"] == "Zone > Zone Settings > Edit"
    assert "zone_settings" in pre["token_template"]["url"]
    done.apply(HOST, pre["preview_id"], TOKEN)
    assert cf.tls == "on"
    assert [(m, p, b) for m, p, _, b in cf.writes()] == [("PATCH", f"/zones/{ZONE_ID}/settings/tls_1_3", {"value": "on"})]


def test_tls_off_with_a_grey_record_is_still_one_change_with_a_note(cf):
    cf.tls = "off"
    pre = done.preview(HOST, TOKEN)
    assert pre["change"]["kind"] == done.KIND_PROXY and "TLS 1.3 is also off" in pre["note"]


def test_nothing_to_change_says_so(cf):
    for r in cf.records.values():
        r["proxied"] = True
    out = done.preview(HOST, TOKEN)
    assert out["nothing_to_change"] is True and "preview_id" not in out


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_zone_that_does_not_contain_the_domain_is_refused(monkeypatch):
    fake = FakeCloudflare(zones="zones_other.json")
    monkeypatch.setattr(done, "transport", fake)
    with pytest.raises(done.DoneError) as exc:
        done.preview(HOST, TOKEN)
    assert exc.value.error == "wrong_zone" and "none of them contains www.example.com" in exc.value.detail
    assert fake.writes() == []


def test_a_lookalike_zone_name_is_not_a_match(monkeypatch):
    fake = FakeCloudflare()
    fake.zones["result"][0]["name"] = "ample.com"
    monkeypatch.setattr(done, "transport", fake)
    with pytest.raises(done.DoneError) as exc:
        done.preview("www.example.com", TOKEN)
    assert exc.value.error == "wrong_zone"


@pytest.mark.parametrize("deny,permission", [
    ({"zones"}, "Zone > Zone > Read"),
    ({"dns_read"}, "Zone > DNS > Edit"),
])
def test_an_insufficient_token_says_which_permission(monkeypatch, deny, permission):
    monkeypatch.setattr(done, "transport", FakeCloudflare(deny=deny))
    with pytest.raises(done.DoneError) as exc:
        done.preview(HOST, TOKEN)
    assert exc.value.error == "token_scope" and exc.value.extra["missing_permission"] == permission
    assert "Nothing was changed" in exc.value.next_step


def test_dns_read_without_edit_fails_at_the_change_with_nothing_left_half_done(monkeypatch):
    fake = FakeCloudflare(deny={"dns_edit"})
    monkeypatch.setattr(done, "transport", fake)
    pre = done.preview(HOST, TOKEN)
    with pytest.raises(done.DoneError) as exc:
        done.apply(HOST, pre["preview_id"], TOKEN)
    assert exc.value.error == "token_scope" and exc.value.extra["missing_permission"] == "Zone > DNS > Edit"
    assert all(r["proxied"] is False for r in fake.records.values())


def test_a_settings_read_refusal_is_not_an_error(monkeypatch):
    monkeypatch.setattr(done, "transport", FakeCloudflare(deny={"settings_read"}))
    pre = done.preview(HOST, TOKEN)
    assert pre["change"]["kind"] == done.KIND_PROXY and "could not read the zone's TLS 1.3" in pre["note"]


def test_a_wrong_token_and_a_malformed_one(monkeypatch):
    monkeypatch.setattr(done, "transport", FakeCloudflare(token="SomeOtherTokenValue0123456789abcdefABCD"))
    with pytest.raises(done.DoneError) as exc:
        done.preview(HOST, TOKEN)
    assert exc.value.error == "token_invalid"
    for bad in ("", "short", "has spaces in it and is long enough", "x" * 201, None, 123):
        with pytest.raises(done.DoneError) as exc:
            done.check_token(bad)
        assert exc.value.error == "token_invalid"


# ── HTTP, the token rule, opt-out ────────────────────────────────────────────


@pytest.fixture
def client(isolated_store, monkeypatch, cf):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    monkeypatch.setattr(ms, "_dns_lookup", cf_dns)
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def url(action):
    return f"/api/public/make-safe/{HOST}/done/{action}"


def test_the_routes_refuse_without_a_token(client, cf):
    for action, body in (("preview", {}), ("apply", {"preview_id": "0" * 32}), ("undo", {"change_id": "0" * 32})):
        r = client.post(url(action), json=body)
        assert r.status_code == 400 and r.json()["error"] == "token_invalid", action
    assert client.post(url("preview"), content=b"not json", headers={"Content-Type": "application/json"}).status_code == 400
    assert client.post(url("preview"), content=b"x" * 5000).status_code == 413
    assert cf.calls == []


def test_the_whole_flow_over_http_ends_in_the_signed_proof_and_never_keeps_the_token(client, cf, isolated_store,
                                                                                         monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    _grade.store(graded())
    plan = client.get(f"/api/public/make-safe/{HOST}").json()
    assert plan["one_click"]["provider"] == "cloudflare"

    pre = client.post(url("preview"), json={"provider": "cloudflare", "token": TOKEN})
    assert pre.status_code == 200 and pre.headers["Cache-Control"] == "no-store"
    assert pre.json()["change"]["title"] == "www.example.com from DNS only to Proxied"
    assert cf.writes() == []
    applied = client.post(url("apply"), json={"preview_id": pre.json()["preview_id"], "token": TOKEN})
    assert applied.status_code == 200 and applied.json()["applied"] is True

    def fake_check(domain, ip="", fresh=False, **_):  # the outside now sees Cloudflare's edge
        result = graded(True, server_software="cloudflare")
        _grade.store(result)
        return result

    monkeypatch.setattr(_grade, "check", fake_check)
    rc = client.post(f"/api/public/make-safe/{HOST}/recheck", json={"start": True}).json()
    assert rc["watch"]["status"] == "live" and rc["result"]["key_exchange"] == "X25519MLKEM768"
    assert rc["result"]["grade"] == "A" and rc["proof_url"] == f"/r/{HOST}/proof"
    env = client.get(rc["proof_url"] + ".json").json()
    assert ms.verify_envelope(env)["valid"] is True and env["document"]["status"] == "quantum_safe"

    undo = client.post(url("undo"), json={"change_id": applied.json()["change_id"], "token": TOKEN})
    assert undo.status_code == 200 and undo.json()["undone"] is True

    # The token: in no response, no log line, no byte of the database.
    for r in (pre, applied, undo):
        assert TOKEN not in r.text and r.json()["token_kept"] is False
    assert TOKEN not in caplog.text
    for path in [isolated_store] + [isolated_store.with_name(isolated_store.name + s) for s in ("-wal", "-journal")]:
        if path.exists():
            assert TOKEN.encode() not in path.read_bytes()
    log = done.audit_log(HOST)
    assert [e["action"] for e in log][::-1] == ["preview", "apply", "undo"]
    assert all(e["outcome"] == "ok" for e in log)
    assert TOKEN not in json.dumps(log)


def test_a_refusal_over_http_never_echoes_the_token(client, monkeypatch):
    monkeypatch.setattr(done, "transport", FakeCloudflare(zones="zones_other.json"))
    bad = "Bad" + TOKEN[3:]
    r = client.post(url("preview"), json={"token": TOKEN})
    assert r.status_code == 403 and r.json()["error"] == "wrong_zone" and TOKEN not in r.text
    r = client.post(url("preview"), json={"token": bad})
    assert r.status_code == 401 and bad not in r.text
    r = client.post(url("preview"), json={"token": ["not", "a", "string", TOKEN]})
    assert r.status_code == 400 and TOKEN not in r.text
    assert done.audit_log(HOST)[0]["outcome"] in ("token_invalid", "wrong_zone")


def test_an_opted_out_domain_is_refused_before_cloudflare_is_called(client, cf, monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    r = client.post(url("preview"), json={"token": TOKEN})
    assert r.status_code == 403 and r.json()["error"] == "refused_optout"
    assert cf.calls == []


def test_done_is_rate_limited_per_address(client, cf):
    codes = [client.post(url("preview"), json={"token": "x"}).status_code for _ in range(25)]
    assert codes[:20] == [400] * 20 and 429 in codes[20:]


def test_done_can_be_switched_off(client, cf, monkeypatch):
    monkeypatch.setenv("MORROW_MAKE_SAFE_DONE_ENABLED", "0")
    assert client.post(url("preview"), json={"token": TOKEN}).status_code == 404
    _grade.store(graded())
    assert client.get(f"/api/public/make-safe/{HOST}").json()["one_click"] is None


# ── the pages ────────────────────────────────────────────────────────────────


def test_the_record_offers_done_only_when_not_safe():
    from services import registry_page

    html = registry_page.render_record({"domain": "example.com", "posture": _check.POSTURE_CLASSICAL, "result": {}},
                                       [], "https://morrow.test")
    assert 'data-morrow-done="example.com"' in html and "/ui/make-safe-done.js" in html
    assert "style=" not in html and "onclick" not in html
    safe = registry_page.render_record({"domain": "example.com", "posture": _check.POSTURE_HYBRID, "result": {}},
                                       [], "https://morrow.test")
    assert "data-morrow-done" not in safe and "make-safe-done.js" not in safe


def test_a_graded_page_without_a_full_record_offers_done_when_classical():
    from services import registry_page

    classical = registry_page.render_missing("example.com", "https://morrow.test",
                                             {"scanned_at": "2026-11-18T00:00:00Z", "grade": "C", "post_quantum": False})
    assert 'data-morrow-done="example.com"' in classical
    pq = registry_page.render_missing("example.com", "https://morrow.test",
                                      {"scanned_at": "2026-11-18T00:00:00Z", "grade": "A", "post_quantum": True})
    assert "data-morrow-done" not in pq
    assert "data-morrow-done" not in registry_page.render_missing("example.com", "https://morrow.test")


def test_the_done_ui_never_writes_the_token_anywhere():
    with open(os.path.join(HERE, "static", "make-safe-done.js"), encoding="utf-8") as fh:
        js = fh.read()
    for line in js.splitlines():
        if "localStorage" in line or "sessionStorage" in line or "location" in line:
            assert "token" not in line.replace("tokenTimer", ""), line
    assert "credentials: \"omit\"" in js
