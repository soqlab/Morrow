"""Watch mode, domain claims, Web Push and the scanner's name. No network: DNS, probes and
outbound sends are replaced, and every refusal path is exercised against the real guards."""

import base64
import json
import os
import xml.etree.ElementTree as ET

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from db_feature_store import feature_conn
from services import alert_routing, domain_verification, not_ready, postgres_rls, public_check, public_grade
from services import org_rate_limits as _limits
from services import third_party, watch, web_push

ORG, OTHER = "org-watch-1", "org-watch-2"
ATOM = "{http://www.w3.org/2005/Atom}"
# A throwaway P-256 scalar for tests only (base64url of 32 bytes), never a deployment key.
TEST_VAPID = base64.urlsafe_b64encode(bytes(range(1, 33))).rstrip(b"=").decode()


def _reset():
    public_check._TABLES_READY.clear()
    public_grade._TABLES_READY.clear()
    watch._ready = ""
    not_ready._ready = ""
    domain_verification._ready = ""
    domain_verification._cache.clear()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "watch.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://morrow.example")
    monkeypatch.delenv("MORROW_VAPID_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("MORROW_VAPID_PUBLIC_KEY", raising=False)
    for name in ("MORROW_WATCH_INTERVAL_HOURS", "MORROW_WATCH_TICK_MAX", "MORROW_WATCH_MAX_PER_USER"):
        monkeypatch.delenv(name, raising=False)
    _reset()
    yield
    _reset()


def _result(domain, grade="C", group="x25519", pq=False, when="2026-11-14T06:00:00Z", cert=None, verified=True):
    return {"domain": domain, "scanned_at": when, "cached": False, "grade": grade, "rubric_version": public_grade.RUBRIC_VERSION,
            "key_exchange": {"group": group, "post_quantum": pq},
            "certificate": cert or {"key_type": "EC", "key_bits": 256, "signature_algorithm": "ecdsa-with-SHA256",
                                    "not_after": "2027-01-01T00:00:00Z", "issuer": "CN=Test CA", "verified": verified},
            "reasons": [f"Grade {grade} reason."]}


# ── settings and scheduling bounds ──────────────────────────────────────────

def test_the_cadence_is_bounded_whatever_the_environment_says(monkeypatch):
    assert watch.interval_hours() == 24 and watch.tick_max() == 10 and watch.max_per_user() == 25
    monkeypatch.setenv("MORROW_WATCH_INTERVAL_HOURS", "0.01")
    monkeypatch.setenv("MORROW_WATCH_TICK_MAX", "100000")
    assert watch.interval_hours() == 1 and watch.tick_max() == 50
    monkeypatch.setenv("MORROW_WATCH_INTERVAL_HOURS", "99999")
    monkeypatch.setenv("MORROW_WATCH_TICK_MAX", "nonsense")
    assert watch.interval_hours() == 168 and watch.tick_max() == 10


def test_due_domains_are_bounded_oldest_first_and_skip_opt_outs(monkeypatch):
    for i in range(5):
        watch.watch(ORG, "alice", f"d{i}.example")
    watch.watch(OTHER, "bob", "d0.example")  # two watchers, one domain: checked once
    with feature_conn() as conn:
        watch._save_state(conn, "d1.example", watch.iso(watch.now_utc()), {"grade": "C"})  # fresh: not due
        watch._save_state(conn, "d2.example", "2026-01-01T00:00:00Z", {"grade": "C"})      # old: due
        conn.commit()
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "d3.example")
    due = watch.due_domains(10)
    assert "d1.example" not in due and "d3.example" not in due
    assert due.count("d0.example") == 1
    assert due[0] == "d0.example"           # never checked comes first
    assert watch.due_domains(1) == ["d0.example"]


def test_a_tick_checks_at_most_tick_max_and_each_domain_once(monkeypatch):
    monkeypatch.setenv("MORROW_WATCH_TICK_MAX", "2")
    monkeypatch.setenv("MORROW_WATCH_THIRD_PARTY", "0")
    for i in range(4):
        watch.watch(ORG, "alice", f"t{i}.example")
    seen = []

    def grade(d):
        seen.append(d)
        return _result(d)

    run = watch.tick(50, grade=grade)
    assert run["due"] == 2 and run["checked"] == 2 and len(seen) == 2 == len(set(seen))
    run = watch.tick(grade=grade)
    assert len(seen) == 4 and len(set(seen)) == 4  # the next tick takes the others, not the same two


def test_a_watcher_has_a_limit(monkeypatch):
    monkeypatch.setenv("MORROW_WATCH_MAX_PER_USER", "2")
    watch.watch(ORG, "alice", "a.example")
    watch.watch(ORG, "alice", "b.example")
    with pytest.raises(watch.WatchError) as exc:
        watch.watch(ORG, "alice", "c.example")
    assert exc.value.code == "too_many"
    watch.watch(ORG, "bob", "c.example")  # the limit is per person


# ── change detection ────────────────────────────────────────────────────────

def test_becoming_post_quantum_ready_reads_answer_first():
    before = watch.snapshot(_result("statements.example.com", "C", "x25519", False))
    after = watch.snapshot(_result("statements.example.com", "A", "X25519MLKEM768", True, when="2026-11-14T06:00:00Z"))
    events = watch.diff("statements.example.com", before, after)
    assert events[0]["kind"] == "pq_ready"
    assert events[0]["sentence"].startswith("statements.example.com became post-quantum ready on Sat 14 Nov — "
                                            "the handshake now uses X25519MLKEM768.")


def test_regression_grade_moves_and_certificates():
    a = watch.snapshot(_result("x.example", "A", "X25519MLKEM768", True))
    b = watch.snapshot(_result("x.example", "C", "x25519", False))
    assert [e["kind"] for e in watch.diff("x.example", a, b)] == ["pq_lost"]
    c = watch.snapshot(_result("x.example", "D", "x25519", False, cert={"key_type": "RSA", "key_bits": 1024,
                                                                         "issuer": "CN=Other CA", "verified": True,
                                                                         "not_after": "2027-02-02T00:00:00Z"}))
    kinds = [e["kind"] for e in watch.diff("x.example", b, c)]
    assert kinds == ["grade_down", "cert_changed"]
    # A certificate renewal that does not move the grade is not news.
    renewed = watch.snapshot(_result("x.example", "C", "x25519", False, cert={"key_type": "EC", "key_bits": 256,
                                                                               "issuer": "CN=Test CA", "verified": True,
                                                                               "not_after": "2028-01-01T00:00:00Z"}))
    assert watch.diff("x.example", b, renewed) == []
    broken = watch.snapshot(_result("x.example", "F", "x25519", False, verified=False))
    assert "cert_unverified" in [e["kind"] for e in watch.diff("x.example", b, broken)]
    assert watch.diff("x.example", None, b) == []  # the first answer is a baseline, not a change


def test_outside_services_changes():
    tp0 = {"services": [{"host": "js.stripe.com", "vendor": "Stripe", "role": "payment", "status": "classical", "key_exchange": "x25519"}]}
    tp1 = {"services": [{"host": "js.stripe.com", "vendor": "Stripe", "role": "payment", "status": "pq", "key_exchange": "X25519MLKEM768"},
                        {"host": "cdn.newvendor.example", "vendor": "", "role": "script", "status": "classical", "key_exchange": "x25519"},
                        {"host": "slow.example", "role": "analytics", "status": "unreachable"}]}
    r = _result("shop.example")
    events = watch.diff("shop.example", watch.snapshot(r, tp0), watch.snapshot(r, tp1))
    kinds = {e["kind"]: e for e in events}
    assert "Stripe (js.stripe.com), your payment provider on shop.example, became post-quantum ready" in kinds["service_pq_ready"]["sentence"]
    assert kinds["service_added"]["host"] == "cdn.newvendor.example"
    assert len(events) == 2  # an unreachable newcomer says nothing


def test_a_failed_check_changes_nothing(monkeypatch):
    monkeypatch.setenv("MORROW_WATCH_THIRD_PARTY", "0")
    watch.watch(ORG, "alice", "flaky.example")
    watch.check_domain("flaky.example", grade=lambda d: _result(d, "A", "X25519MLKEM768", True))
    out = watch.check_domain("flaky.example", grade=lambda d: {"domain": d, "error": "unreachable", "detail": "timeout"})
    assert out["ok"] is False and out["events"] == []
    st = watch.domain_state("flaky.example")
    assert st["snapshot"]["grade"] == "A" and st["last_error"] == "timeout"
    out = watch.check_domain("flaky.example", grade=lambda d: _result(d, "A", "X25519MLKEM768", True))
    assert out["events"] == []


# ── fan-out ─────────────────────────────────────────────────────────────────

def test_push_is_off_without_vapid_keys_and_says_so():
    st = web_push.status()
    assert st["enabled"] is False and "MORROW_VAPID_PRIVATE_KEY" in st["reason"]
    sent = web_push.send({"endpoint": "https://fcm.googleapis.com/fcm/send/x", "p256dh": "x", "auth": "y"}, {"title": "t"})
    assert sent["disabled"] and not sent["ok"]
    with pytest.raises(watch.WatchError) as exc:
        watch.add_push(ORG, "alice", {"endpoint": "https://fcm.googleapis.com/fcm/send/x", "keys": {}}, resolve=False)
    assert exc.value.code == "push_disabled"


def test_a_change_reaches_every_watcher_by_every_channel(monkeypatch):
    monkeypatch.setenv("MORROW_VAPID_PRIVATE_KEY", TEST_VAPID)
    monkeypatch.setattr(alert_routing, "seal", lambda plain: "plain:" + plain)
    watch.watch(ORG, "alice", "bank.example")
    watch.watch(OTHER, "bob", "bank.example")
    watch.add_channel(ORG, "alice", "generic_webhook", "https://hooks.example/abc", resolve=False)
    watch.add_channel(OTHER, "bob", "slack_webhook", "https://hooks.slack.com/services/T/B/x", resolve=False)
    key = _browser_key()
    sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": {"p256dh": key["p256dh"], "auth": key["auth"]}}
    watch.add_push(ORG, "alice", sub, resolve=False)
    watch.add_push(OTHER, "bob", {**sub, "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gone"}, resolve=False)
    posts, pushes = [], []

    def hook(url, payload):
        posts.append((url, payload))
        return {"ok": True}

    def push(s, msg):
        pushes.append((s["endpoint"], msg))
        return {"ok": "gone" not in s["endpoint"], "gone": "gone" in s["endpoint"]}

    events = watch.diff("bank.example", watch.snapshot(_result("bank.example")),
                        watch.snapshot(_result("bank.example", "A", "X25519MLKEM768", True)))
    out = watch.fan_out("bank.example", events, push_sender=push, webhook_sender=hook)
    assert out["watchers"] == 2 and out["webhooks"]["sent"] == 2 and out["push"] == {"sent": 1, "failed": 0, "disabled": 0, "gone": 1}
    generic = next(p for u, p in posts if u == "https://hooks.example/abc")
    assert generic["type"] == "watch.change" and generic["domain"] == "bank.example"
    assert generic["link"] == "https://morrow.example/bank.example"
    assert generic["changes"][0]["kind"] == "pq_ready" and "became post-quantum ready" in generic["changes"][0]["sentence"]
    slack = next(p for u, p in posts if "slack" in u)
    assert slack["text"].startswith("bank.example became post-quantum ready")
    assert pushes[0][1]["url"] == "https://morrow.example/bank.example"
    # Both watchers see it in their list; the dropped browser subscription was removed.
    assert watch.overview(ORG, "alice")["events"][0]["kind"] == "pq_ready"
    assert watch.overview(OTHER, "bob")["events"][0]["kind"] == "pq_ready"
    assert watch.overview(OTHER, "bob")["push"]["subscriptions"] == 0


def test_webhooks_and_push_endpoints_go_through_the_ssrf_guard(monkeypatch):
    monkeypatch.setattr(alert_routing, "resolve_host", lambda host, port: ["10.0.0.5"])
    monkeypatch.setattr(alert_routing, "seal", lambda plain: "plain:" + plain)
    with pytest.raises(watch.WatchError):
        watch.add_channel(ORG, "alice", "generic_webhook", "https://inside.example/hook")
    with pytest.raises(watch.WatchError):
        watch.add_channel(ORG, "alice", "generic_webhook", "http://hooks.example/hook", resolve=False)
    with pytest.raises(web_push.PushError):
        web_push.validate_endpoint("https://fcm.googleapis.com/fcm/send/x")  # resolves privately: refused
    with pytest.raises(web_push.PushError) as exc:
        web_push.validate_endpoint("https://evil.example/push", resolve=False)
    assert exc.value.code == "unknown_push_service"
    with pytest.raises(web_push.PushError):
        web_push.validate_endpoint("https://fcm.googleapis.com:8443/x", resolve=False)


# ── Web Push crypto ─────────────────────────────────────────────────────────

def _browser_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {"priv": priv, "p256dh": web_push.b64u(pub), "auth": web_push.b64u(auth), "auth_raw": auth, "pub_raw": pub}


def _decrypt(body, key):
    """The browser's side of RFC 8291, written out separately from the sender."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_pub = body[21:21 + idlen]
    assert rs == 4096 and idlen == 65
    shared = key["priv"].exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    hk = lambda s, ikm, info, n: HKDF(algorithm=hashes.SHA256(), length=n, salt=s, info=info).derive(ikm)  # noqa: E731
    ikm = hk(key["auth_raw"], shared, b"WebPush: info\x00" + key["pub_raw"] + as_pub, 32)
    cek = hk(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = hk(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    plain = AESGCM(cek).decrypt(nonce, body[21 + idlen:], None)
    assert plain.endswith(b"\x02")
    return plain[:-1]


def test_the_push_payload_decrypts_in_the_browser():
    key = _browser_key()
    body = web_push.encrypt(b'{"title":"Morrow"}', key["p256dh"], key["auth"])
    assert _decrypt(body, key) == b'{"title":"Morrow"}'


def test_the_vapid_header_verifies_with_the_published_key(monkeypatch):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    monkeypatch.setenv("MORROW_VAPID_PRIVATE_KEY", TEST_VAPID)
    st = web_push.status()
    assert st["enabled"] and len(web_push.unb64u(st["public_key"])) == 65
    header = web_push.vapid_header("https://fcm.googleapis.com/fcm/send/abc", now=1_800_000_000)
    token = header.split("t=", 1)[1].split(",", 1)[0]
    k = header.split("k=", 1)[1]
    assert k == st["public_key"]
    head, claims, sig = token.split(".")
    payload = json.loads(web_push.unb64u(claims))
    assert payload["aud"] == "https://fcm.googleapis.com" and payload["sub"] == "https://morrow.example/about-scanner"
    raw = web_push.unb64u(sig)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), web_push.unb64u(k))
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
               f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    monkeypatch.setenv("MORROW_VAPID_PUBLIC_KEY", "AAAA")
    assert web_push.status()["enabled"] is False


# ── the private feed ────────────────────────────────────────────────────────

def test_the_feed_token_is_the_only_way_in():
    watch.watch(ORG, "alice", "feed.example")
    events = watch.diff("feed.example", watch.snapshot(_result("feed.example")),
                        watch.snapshot(_result("feed.example", "A", "X25519MLKEM768", True)))
    watch.fan_out("feed.example", events, push_sender=lambda s, m: {"ok": True}, webhook_sender=lambda u, p: {"ok": True})
    made = watch.new_feed(ORG, "alice")
    assert made["url"] == f"https://morrow.example/api/public/watch-feed/{made['token']}.atom"
    feed = ET.fromstring(watch.feed_atom(made["token"]))
    titles = [e.find(ATOM + "title").text for e in feed.findall(ATOM + "entry")]
    assert titles and titles[0].startswith("feed.example became post-quantum ready")
    assert watch.feed_atom("x" * 43) is None and watch.feed_atom("") is None
    with feature_conn() as conn:  # only the hash is stored
        assert conn.execute("SELECT COUNT(*) AS n FROM watch_feed_tokens WHERE token_hash = ?", (made["token"],)).fetchone()["n"] == 0
    newer = watch.new_feed(ORG, "alice")
    assert watch.feed_atom(made["token"]) is None and watch.feed_atom(newer["token"]) is not None
    # Bob's feed shows Bob's changes, never Alice's.
    bob = watch.new_feed(OTHER, "bob")
    assert ET.fromstring(watch.feed_atom(bob["token"])).findall(ATOM + "entry") == []


# ── claims ──────────────────────────────────────────────────────────────────

class _DNS:
    def __init__(self):
        self.values = {}
        self.fail = False

    def __call__(self, name):
        if self.fail:
            raise domain_verification.DomainError(504, "timeout")
        return list(self.values.get(name, []))


@pytest.fixture
def dns(monkeypatch):
    fake = _DNS()
    monkeypatch.setattr(domain_verification, "_txt_values", fake)
    return fake


def _publish(dns, org, domain):
    rec = watch.start_claim(org, domain)["record"]
    dns.values.setdefault(rec["name"], []).append(rec["value"])
    return rec


def test_claiming_by_dns(dns):
    with pytest.raises(watch.WatchError) as exc:
        watch.claim(ORG, "alice", "acme.example")
    assert exc.value.code == "not_started"
    rec = watch.start_claim(ORG, "acme.example")["record"]
    assert rec["name"] == "_morrow-verify.acme.example" and rec["value"].startswith("morrow-verify=")
    dns.values[rec["name"]] = ["morrow-verify=wrong-token"]
    with pytest.raises(watch.WatchError) as exc:
        watch.claim(ORG, "alice", "acme.example")
    assert exc.value.code == "record_missing"
    assert watch.public_claim("acme.example")["claimed"] is False
    dns.values[rec["name"]] = [rec["value"]]
    out = watch.claim(ORG, "alice", "acme.example")
    assert out["claimed"] and out["contact"] == "contact@soqlab.com"
    assert watch.watching(ORG, "alice", "acme.example")["source"] == "claim"  # watching is on
    again = watch.claim(ORG, "alice", "acme.example")  # re-claim by the same organization is harmless
    assert again["claimed"] and again["moved"] is False
    public = watch.public_claim("acme.example")
    assert public["claimed"] and ORG not in json.dumps(public)
    not_ready.set_reply(ORG, "acme.example", "Rolling out X25519MLKEM768 in Q1.")
    assert watch.public_claim("acme.example")["reply"]["text"] == "Rolling out X25519MLKEM768 in Q1."


def test_someone_elses_claim_holds_while_their_record_stays(dns):
    first = _publish(dns, ORG, "shared.example")
    watch.claim(ORG, "alice", "shared.example")
    _publish(dns, OTHER, "shared.example")
    with pytest.raises(watch.WatchError) as exc:
        watch.claim(OTHER, "bob", "shared.example")
    assert exc.value.code == "claimed_by_other"
    assert watch.claim_status(OTHER, "shared.example")["claimed_by_other"] is True
    dns.fail = True
    with pytest.raises(watch.WatchError):
        watch.claim(OTHER, "bob", "shared.example")
    dns.fail = False
    # The domain changed hands: the first organization's record is gone, so the claim moves.
    dns.values[first["name"]].remove(first["value"])
    moved = watch.claim(OTHER, "bob", "shared.example")
    assert moved["claimed"] and moved["moved"] is True
    assert watch.claim_status(ORG, "shared.example")["claimed"] is False
    with pytest.raises(watch.WatchError):
        watch.require_claim(ORG, "shared.example")
    assert watch.require_claim(OTHER, "shared.example") == "shared.example"


# ── tenant isolation ────────────────────────────────────────────────────────

def test_one_organization_never_sees_anothers_watches(monkeypatch):
    monkeypatch.setattr(alert_routing, "seal", lambda plain: "plain:" + plain)
    watch.watch(ORG, "alice", "private.example")
    watch.add_channel(ORG, "alice", "generic_webhook", "https://hooks.example/secret", resolve=False)
    other = watch.overview(OTHER, "alice")  # same user id, other tenant
    assert other["watches"] == [] and other["channels"] == []
    assert watch.overview(ORG, "mallory")["watches"] == []  # same tenant, another person
    assert not watch.remove_channel(OTHER, "alice", watch.list_channels(ORG, "alice")[0]["id"])
    assert watch.watching(OTHER, "alice", "private.example")["watching"] is False
    for table in watch.ORG_TABLES:
        assert table in postgres_rls.ORG_SCOPED_TABLES and postgres_rls.TENANT_COLUMNS[table] == "org_id"
        assert table in postgres_rls.build_rls_plan()["tables"]
    assert "watch_domain_state" not in postgres_rls.ORG_SCOPED_TABLES


# ── the scanner says who it is ──────────────────────────────────────────────

class _Sock:
    def __init__(self, sent):
        self.sent = sent

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, t):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        return b""


class _Ctx:
    def __init__(self, sent):
        self.sent = sent

    def wrap_socket(self, sock, server_hostname=None):
        return _Sock(self.sent)


def test_every_http_request_names_the_scanner_and_the_result_page(monkeypatch):
    sent = []
    monkeypatch.setattr(public_grade.socket, "create_connection", lambda *a, **k: _Sock(sent))
    monkeypatch.setattr(public_grade, "_context", lambda *a, **k: _Ctx(sent))
    public_grade._http_head("192.0.2.1", "corp.example", 1.0)
    third_party._http_get("192.0.2.1", "corp.example", "/", 1.0)
    assert len(sent) == 2
    for raw in sent:
        text = raw.decode("ascii")
        assert "\r\nUser-Agent: MorrowPQCheck/1.0 (+https://morrow.soqlab.com/about-scanner)\r\n" in text
        assert "\r\nX-Morrow-Check: post-quantum readiness check by Morrow" in text
        assert "your result: https://morrow.example/corp.example;" in text
        assert "\r\nFrom:" not in text
    assert "MorrowPQCheck" in watch.about_scanner()["user_agent"]


def test_a_watched_domain_that_resolves_inside_is_still_refused(monkeypatch):
    monkeypatch.setenv("MORROW_WATCH_THIRD_PARTY", "0")
    monkeypatch.setattr(alert_routing, "resolve_host", lambda host, port: ["127.0.0.1"])
    watch.watch(ORG, "alice", "rebind.example")
    probed = []
    monkeypatch.setattr(public_grade, "probe", lambda *a, **k: probed.append(a) or {})
    out = watch.check_domain("rebind.example")
    assert out["ok"] is False and out["error"] == "refused_target" and probed == []


# ── the routes ──────────────────────────────────────────────────────────────

def test_the_routes(monkeypatch, dns):
    import app as application
    from routers import instrument

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as client:
        viewer = {"x-user-role": "viewer", "x-user-id": "viewer-1"}
        admin = {"x-user-role": "admin", "x-user-id": "admin-1"}
        r = client.put("/instrument/watch/route.example", headers=viewer)
        assert r.status_code == 200 and r.json()["watching"] is True, r.text
        assert [w["domain"] for w in client.get("/instrument/watch", headers=viewer).json()["watches"]] == ["route.example"]
        assert client.get("/instrument/watch", headers=admin).json()["watches"] == []
        assert client.put("/instrument/watch/not a domain", headers=viewer).status_code == 400
        # Claims speak for the organization: an admin, not a viewer.
        assert client.post("/instrument/claims/route.example", headers=viewer).status_code == 403
        rec = client.post("/instrument/claims/route.example", headers=admin).json()["record"]
        assert client.post("/instrument/claims/route.example/check", headers=admin).status_code == 409
        dns.values[rec["name"]] = [rec["value"]]
        ok = client.post("/instrument/claims/route.example/check", headers=admin)
        assert ok.status_code == 200 and ok.json()["claimed"] is True, ok.text
        assert client.get("/api/public/claim/route.example").json()["claimed"] is True
        key = client.get("/api/public/push-key").json()
        assert key["enabled"] is False and "MORROW_VAPID_PRIVATE_KEY" in key["reason"]
        assert client.post("/instrument/watch-push", headers=viewer,
                           json={"endpoint": "https://fcm.googleapis.com/fcm/send/x", "keys": {}}).status_code == 503
        feed = client.post("/instrument/watch-feed", headers=viewer).json()
        token = feed["url"].rsplit("/", 1)[1][:-len(".atom")]
        got = client.get(f"/api/public/watch-feed/{token}.atom")
        assert got.status_code == 200 and got.headers["content-type"].startswith("application/atom+xml")
        assert client.get("/api/public/watch-feed/" + "z" * 43 + ".atom").status_code == 404
        facts = client.get("/api/public/scanner?host=corp.example").json()
        assert facts["your_result"].endswith("/corp.example") and facts["from_header"] is False
        for path in ("/watching", "/about-scanner"):
            page = client.get(path, headers={"Accept": "text/html"})
            assert page.status_code == 200 and '<script src="/ui/instrument-watch.js' in page.text
            assert page.headers["content-security-policy"] == instrument.CSP and "worker-src 'self'" in instrument.CSP
        plain = client.get("/plain/about-scanner")
        assert plain.status_code == 200 and "MorrowPQCheck/1.0" in plain.text
        assert client.post("/instrument/claims/route.example/opt-out", headers=admin).status_code == 200
        assert public_check.opted_out("route.example")
        assert client.delete("/instrument/watch/route.example", headers=viewer).json()["removed"] is True


def test_the_public_parts_need_no_account_and_the_rest_do(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        for path in ("/api/public/claim/example.com", "/api/public/push-key", "/api/public/scanner", "/about-scanner",
                     "/watching", "/plain/about-scanner"):
            assert anonymous.get(path).status_code == 200, path
        assert anonymous.get("/api/public/watch-feed/" + "z" * 43 + ".atom").status_code == 404
        assert anonymous.get("/instrument/watch").status_code == 401
        assert anonymous.put("/instrument/watch/example.com").status_code == 401
        assert anonymous.post("/instrument/claims/example.com").status_code == 401


def test_the_watch_tick_is_on_the_beat():
    import tasks

    if not hasattr(tasks, "celery_app") or tasks.celery_app is None:
        pytest.skip("celery is not installed here")
    assert tasks.celery_app.conf.beat_schedule["watch-tick-every-15m"]["task"] == "morrow.watch_tick"
