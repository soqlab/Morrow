"""Make it safe: stack detection, recipe selection, the spaced re-check, and the signed proof.

No network: DNS is an injected lookup, the grade is services.public_grade with resolve_pinned and
probe replaced (the seam test_public_grade.py uses), and the proof is signed with the throwaway
vault key conftest.py sets.
"""

import copy
import json
import os
import re
from datetime import datetime, timedelta, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import make_safe as ms
from services import org_rate_limits as _limits
from services import proof_signing
from services import public_check as _check
from services import public_grade as _grade

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    db = tmp_path / "make-safe.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    for mod in (_check, _grade, ms):
        mod._TABLES_READY.clear()
    ms._detect_cache.clear()
    proof_signing.reset_cache_for_tests()
    _limits.reset()
    yield db
    for mod in (_check, _grade, ms):
        mod._TABLES_READY.clear()
    proof_signing.reset_cache_for_tests()
    _limits.reset()


def no_dns(host):
    return {"cname": [], "addresses": []}


def graded(post_quantum=False, **over):
    group = "X25519MLKEM768" if post_quantum else "x25519"
    out = {"domain": "example.com", "scanned_at": "2026-11-15T12:00:00Z", "grade": "A" if post_quantum else "C",
           "key_exchange": {"group": group, "post_quantum": post_quantum, "hybrid": post_quantum},
           "certificate": {"issuer": "CN=R11,O=Let's Encrypt,C=US"}, "server_software": None, "edge_headers": {},
           "fixes": []}
    out.update(over)
    return out


# ── detection ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("server,headers,stack", [
    ("cloudflare", {}, "cloudflare"),
    (None, {"cf-ray": "8f1-AMS"}, "cloudflare"),
    ("CloudFront", {}, "cloudfront"),
    (None, {"x-amz-cf-id": "abc", "via": "1.1 abc.cloudfront.net (CloudFront)"}, "cloudfront"),
    ("awselb/2.0", {}, "aws_elb"),
    (None, {"x-amz-apigw-id": "abc="}, "aws_apigateway"),
    (None, {"x-azure-ref": "20261115T1200Z-abc"}, "azure_front_door"),
    ("Microsoft-Azure-Application-Gateway/v2", {}, "azure_app_gateway"),
    (None, {"x-served-by": "cache-ams21080-AMS", "via": "1.1 varnish"}, "fastly"),
    ("AkamaiGHost", {}, "akamai"),
    ("nginx/1.27.4", {}, "nginx"),
    ("openresty", {}, "nginx"),
    ("Apache/2.4.62 (Debian)", {}, "apache"),
    ("Caddy", {}, "caddy"),
    ("HAProxy", {}, "haproxy"),
    ("Microsoft-IIS/10.0", {}, "iis"),
])
def test_the_stack_is_named_from_response_headers(server, headers, stack):
    out = ms.detect("example.com", graded(server_software=server, edge_headers=headers), lookup=no_dns)
    assert out["stack"] == stack
    assert out["confidence"] == "high"
    assert out["evidence"]


@pytest.mark.parametrize("cname,stack", [
    ("example.com.cdn.cloudflare.net", "cloudflare"),
    ("d111111abcdef8.cloudfront.net", "cloudfront"),
    ("my-alb-123.eu-west-1.elb.amazonaws.com", "aws_elb"),
    ("d-abc123.execute-api.eu-west-1.amazonaws.com", "aws_apigateway"),
    ("example-abc.z01.azurefd.net", "azure_front_door"),
    ("dualstack.example.map.fastly.net", "fastly"),
    ("example.com.edgekey.net", "akamai"),
])
def test_the_stack_is_named_from_the_cname_chain(cname, stack):
    out = ms.detect("www.example.com", graded(), lookup=lambda h: {"cname": [cname], "addresses": []})
    assert out["stack"] == stack and out["confidence"] == "high"
    assert any(cname in e for e in out["evidence"])


@pytest.mark.parametrize("address,stack", [
    ("104.16.132.229", "cloudflare"), ("172.67.1.1", "cloudflare"), ("2606:4700::6810:84e5", "cloudflare"),
    ("151.101.1.140", "fastly"), ("2a04:4e42::1", "fastly"),
])
def test_an_apex_on_a_cdn_is_named_from_its_published_ranges(address, stack):
    out = ms.detect("example.com", graded(), lookup=lambda h: {"cname": [], "addresses": [address]})
    assert out["stack"] == stack
    assert "published ranges" in out["evidence"][0]


def test_an_ordinary_address_names_nothing():
    out = ms.detect("example.com", graded(), lookup=lambda h: {"cname": [], "addresses": ["93.184.216.34"]})
    assert out["stack"] == "unknown" and out["confidence"] == "none"


def test_the_edge_wins_over_the_origin_server_header_it_passes_through():
    result = graded(server_software="nginx/1.25.3", edge_headers={"x-amz-cf-id": "abc"})
    out = ms.detect("example.com", result, lookup=no_dns)
    assert out["stack"] == "cloudfront"
    assert out["origin_server"] == "nginx"
    plan = ms.plan("example.com", result, lookup=no_dns)
    assert plan["recipe"]["id"] == "cloudfront" and plan["origin_recipe"]["id"] == "nginx"


def test_a_certificate_issuer_alone_names_no_stack_only_candidates():
    result = graded(certificate={"issuer": "CN=Amazon RSA 2048 M02,O=Amazon,C=US"})
    out = ms.detect("example.com", result, lookup=no_dns)
    assert out["stack"] == "unknown"
    assert {a["stack"] for a in out["alternatives"]} == {"cloudfront", "aws_elb", "aws_apigateway"}


def test_google_front_end_headers_are_only_medium_confidence():
    out = ms.detect("example.com", graded(edge_headers={"via": "1.1 google"}), lookup=no_dns)
    assert out["stack"] == "google_lb" and out["confidence"] == "medium"


def test_two_edges_disagreeing_lower_the_confidence():
    out = ms.detect("example.com", graded(edge_headers={"cf-ray": "x"}),
                    lookup=lambda h: {"cname": ["x.cloudfront.net"], "addresses": []})
    assert out["confidence"] == "medium"
    assert {out["stack"], out["alternatives"][0]["stack"]} == {"cloudflare", "cloudfront"}


def test_the_grade_keeps_the_fingerprinting_headers_and_nothing_else():
    kept = _grade.edge_headers({"server": "cloudflare", "cf-ray": "8f-AMS", "set-cookie": "secret=1",
                                "x-azure-ref": "a" * 400})
    assert set(kept) == {"server", "cf-ray", "x-azure-ref"}
    assert len(kept["x-azure-ref"]) <= 100
    facts = _grade.empty_facts("example.com", "93.184.216.34")
    facts["edge_headers"] = kept
    assert _grade.build_result(facts, "2026-11-15T00:00:00Z")["edge_headers"] == kept


# ── recipes ──────────────────────────────────────────────────────────────────


def test_every_recipe_names_its_vendor_source_and_the_date_it_was_checked():
    data = ms.recipes()
    assert data["checked_on"] == "2026-11-15"
    for key, rc in data["recipes"].items():
        assert rc["support"] in {"default_on", "opt_in", "not_documented", "unknown"}, key
        assert rc["confidence"] in {"high", "medium", "low"}, key
        assert rc["summary"] and rc["snippet"] and rc["snippet_label"], key
        if key == "unknown":
            continue
        assert rc["sources"], key
        for src in rc["sources"]:
            assert src["url"].startswith("https://"), (key, src)
            assert re.match(r"^\d{4}-\d{2}-\d{2}$", src["checked"]), (key, src)
            assert src["quote"], (key, src)


@pytest.mark.parametrize("stack,needle,version", [
    ("nginx", "ssl_ecdh_curve X25519MLKEM768", "OpenSSL 3.5"),
    ("apache", "SSLOpenSSLConfCmd Groups X25519MLKEM768", "OpenSSL 3.5"),
    ("haproxy", "ssl-default-bind-curves X25519MLKEM768", "AWS-LC"),
    ("caddy", "curves x25519mlkem768", "Caddy 2.10"),
    ("traefik", "X25519MLKEM768", "Traefik 3.5"),
    ("iis", 'Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0', "Windows Server 2025"),
    ("aws_elb", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", "PQ"),
    ("google_lb", "--post-quantum-key-exchange ENABLED", "SSL policy"),
    ("akamai", "pqcClientToEdge", "TLS 1.3"),
])
def test_the_recipe_carries_the_documented_setting_and_minimum_version(stack, needle, version):
    rc = ms.recipe(stack)
    assert rc["id"] == stack
    assert needle in rc["snippet"]
    assert any(version in req for req in rc["requires"])


def test_no_recipe_cites_an_update_number_microsoft_does_not_document():
    assert "KB5099536" not in json.dumps(ms.recipes())
    assert "KB5099536" not in json.dumps(_grade.fixes_for("iis", {"pq": True, "protocols": False,
                                                                     "ciphers": False, "certificate": False}))


def test_a_stack_without_vendor_support_gets_the_honest_next_step_not_a_setting():
    rc = ms.recipe("azure_app_gateway")
    assert rc["support"] == "not_documented"
    assert all(line.startswith("#") or not line.strip() for line in rc["snippet"].splitlines())
    assert "Front Door" in rc["snippet"]


def test_an_unknown_stack_invents_nothing():
    rc = ms.recipe("no-such-stack")
    assert rc["id"] == "unknown" and rc["support"] == "unknown" and rc["sources"] == []
    assert all(line.startswith("#") for line in rc["snippet"].splitlines() if line.strip())


def test_the_plan_follows_detection_and_a_hand_picked_stack_overrides_it():
    result = graded(server_software="nginx")
    assert ms.plan("example.com", result, lookup=no_dns)["recipe"]["id"] == "nginx"
    picked = ms.plan("example.com", result, chosen="caddy", lookup=no_dns)
    assert picked["recipe"]["id"] == "caddy" and picked["chosen"] == "caddy"
    assert ms.plan("example.com", result, chosen="bogus", lookup=no_dns)["recipe"]["id"] == "nginx"
    assert {s["id"] for s in picked["stacks"]} == set(ms.stack_ids())
    assert picked["proof_url"] == "/r/example.com/proof"


def test_a_safe_host_is_told_so():
    assert ms.plan("example.com", graded(post_quantum=True), lookup=no_dns)["safe"] is True


# ── the watch: spaced re-checks ──────────────────────────────────────────────


def test_backoff_doubles_up_to_fifteen_minutes():
    assert [ms.backoff(n) for n in range(1, 9)] == [30, 60, 120, 240, 480, 900, 900, 900]


def test_advance_moves_from_waiting_to_live():
    s = ms.new_session(T0)
    s = ms.advance(s, {"post_quantum": False, "group": "x25519"}, T0)
    assert s["status"] == "waiting" and s["attempts"] == 1
    assert s["next_allowed_at"] == ms.iso(T0 + timedelta(seconds=30))
    s = ms.advance(s, {"post_quantum": True, "group": "X25519MLKEM768"}, T0 + timedelta(seconds=40))
    assert s["status"] == "live" and s["last_group"] == "X25519MLKEM768"
    assert ms.public_state(s, T0 + timedelta(seconds=40))["auto"] is False


def test_a_failed_check_waits_at_least_as_long_as_the_grade_asks():
    s = ms.advance(ms.new_session(T0), {"error": "rate limited", "retry_after": 600}, T0)
    assert s["status"] == "error"
    assert ms.public_state(s, T0)["next_check_in"] == 600


def test_the_page_stops_asking_by_itself_after_the_limit():
    s = ms.new_session(T0)
    for i in range(ms.MAX_AUTO_ATTEMPTS):
        s = ms.advance(s, {"post_quantum": False}, T0)
    assert ms.public_state(s, T0)["auto"] is False


@pytest.fixture
def fake_grade():
    state = {"pq": False, "calls": 0}

    def run(host, client_ip="", fresh=False, **_):
        assert fresh is True
        state["calls"] += 1
        result = graded(post_quantum=state["pq"], domain=host,
                        scanned_at=ms.iso(T0 + timedelta(minutes=state["calls"])))
        _grade.store(result)
        return result
    state["run"] = run
    return state


def test_recheck_is_spaced_and_says_when_it_may_ask_again(fake_grade):
    out = ms.recheck("example.com", "198.51.100.7", start=True, grade=fake_grade["run"], now=T0)
    assert out["watch"]["status"] == "waiting" and out["watch"]["next_check_in"] == 30
    with pytest.raises(ms.MakeSafeError) as too_soon:
        ms.recheck("example.com", "198.51.100.7", grade=fake_grade["run"], now=T0 + timedelta(seconds=10))
    assert too_soon.value.status_code == 429 and 19 <= too_soon.value.retry_after <= 20
    assert fake_grade["calls"] == 1  # refused before anything was contacted
    # Saying "I've made the change" again does not reset the spacing of a running session.
    with pytest.raises(ms.MakeSafeError):
        ms.recheck("example.com", "198.51.100.7", start=True, grade=fake_grade["run"], now=T0 + timedelta(seconds=11))
    fake_grade["pq"] = True
    live = ms.recheck("example.com", "198.51.100.7", grade=fake_grade["run"], now=T0 + timedelta(seconds=31))
    assert live["watch"]["status"] == "live" and live["result"]["post_quantum"] is True
    assert live["proof_url"] == "/r/example.com/proof"


def test_an_opted_out_domain_is_never_rechecked(fake_grade, monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    _limits.reset()
    with pytest.raises(ms.MakeSafeError) as refused:
        ms.recheck("example.com", "198.51.100.7", start=True, now=T0)
    assert refused.value.status_code == 403


# ── the proof ────────────────────────────────────────────────────────────────


def rows(*flags):
    """History newest first from flags given oldest first."""
    out = [{"scanned_at": ms.iso(T0 + timedelta(days=i)), "post_quantum": f,
            "group": "X25519MLKEM768" if f else "x25519"} for i, f in enumerate(flags)]
    return list(reversed(out))


def test_derive_names_the_start_of_the_current_safe_run():
    rec = ms.derive(rows(False, True, False, True, True))
    assert rec["status"] == "safe"
    assert rec["safe_since"] == ms.iso(T0 + timedelta(days=3))
    assert rec["last_confirmed"] == ms.iso(T0 + timedelta(days=4)) and rec["checks_in_run"] == 2


def test_derive_says_truthfully_when_a_safe_host_turned_classical():
    rec = ms.derive(rows(True, True, False, False))
    assert rec["status"] == "lapsed"
    assert rec["safe_since"] == ms.iso(T0)
    assert rec["last_confirmed"] == ms.iso(T0 + timedelta(days=1))
    assert rec["lapsed_at"] == ms.iso(T0 + timedelta(days=2)) and rec["lapsed_key_exchange"] == "x25519"


def test_derive_without_a_post_quantum_check_has_nothing_to_prove():
    assert ms.derive(rows(False, False))["status"] == "never"
    assert ms.derive([])["status"] == "never"
    with pytest.raises(ms.MakeSafeError) as none:
        ms.proof_envelope("example.com", "https://morrow.test", history=rows(False))
    assert none.value.status_code == 404


def test_the_proof_is_signed_with_both_keys_and_verifies_against_the_published_keys():
    env = ms.proof_envelope("example.com", "https://morrow.test", history=rows(False, True))
    doc = env["document"]
    assert doc["format"] == ms.PROOF_FORMAT and doc["status"] == "quantum_safe"
    assert doc["safe_since"] == ms.iso(T0 + timedelta(days=1))
    assert doc["page"] == "https://morrow.test/r/example.com/proof"
    assert {s["alg"] for s in env["signatures"]} == set(proof_signing.describe_algorithms())
    assert ms.verify_envelope(env)["valid"] is True


def test_a_changed_proof_does_not_verify():
    env = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True))
    forged = copy.deepcopy(env)
    forged["document"]["safe_since"] = "2020-01-01T00:00:00Z"
    assert ms.verify_envelope(forged)["valid"] is False


def test_a_proof_signature_is_not_a_migration_proof_signature():
    env = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True))
    keys = {k["kid"]: k for k in proof_signing.published_keys()["keys"]}
    message = proof_signing.canonical_bytes(env["document"])
    sig = env["signatures"][0]
    assert proof_signing.verify_signature(sig["alg"], keys[sig["kid"]]["public_key"], sig["signature"], message,
                                          context=ms.PROOF_CONTEXT)
    assert not proof_signing.verify_signature(sig["alg"], keys[sig["kid"]]["public_key"], sig["signature"], message)


def test_the_proof_is_reused_until_the_history_changes_and_then_says_so():
    first = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True))
    again = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True))
    assert again == first
    lapsed = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True, False))
    assert lapsed["document"]["status"] == "no_longer_quantum_safe"
    assert "instead" in lapsed["document"]["statement"]
    assert ms.verify_envelope(lapsed)["valid"] is True


def test_the_proof_names_a_dns_claim_but_never_who_holds_it(monkeypatch):
    from services import watch

    monkeypatch.setattr(watch, "public_claim", lambda d: {"claimed": True, "since": "2026-10-01T00:00:00Z",
                                                          "reply": None})
    env = ms.proof_envelope("example.com", "https://morrow.test", history=rows(True))
    assert env["document"]["owner"] == {"claimed_by_dns": True, "claimed_since": "2026-10-01T00:00:00Z"}
    assert "org" not in json.dumps(env["document"]["owner"])


# ── HTTP ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def client(isolated_store, monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    monkeypatch.setattr(ms, "_dns_lookup", no_dns)
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def store(post_quantum, minutes, **over):
    _grade.store(graded(post_quantum=post_quantum, scanned_at=ms.iso(T0 + timedelta(minutes=minutes)), **over))


def test_the_plan_needs_a_grade_first_and_then_names_the_fix(client):
    assert client.get("/api/public/make-safe/example.com").status_code == 404
    store(False, 0, server_software="nginx/1.27.4")
    r = client.get("/api/public/make-safe/example.com")
    assert r.status_code == 200
    body = r.json()
    assert body["detected"]["stack"] == "nginx" and body["recipe"]["id"] == "nginx"
    assert body["recipe"]["sources"][0]["url"].startswith("https://nginx.org/")
    assert client.get("/api/public/make-safe/example.com?stack=caddy").json()["recipe"]["id"] == "caddy"
    assert client.get("/api/public/make-safe/recipes").json()["format"] == "morrow.make-safe-recipes/v1"


def test_the_recheck_route_answers_429_with_retry_after_before_the_next_slot(client, monkeypatch):
    calls = []

    def fake_check(domain, ip="", fresh=False, **_):
        calls.append(fresh)
        result = graded(domain=domain, scanned_at=ms.iso(datetime.now(timezone.utc)))
        _grade.store(result)
        return result

    monkeypatch.setattr(_grade, "check", fake_check)
    first = client.post("/api/public/make-safe/example.com/recheck", json={"start": True})
    assert first.status_code == 200 and first.json()["watch"]["status"] == "waiting"
    second = client.post("/api/public/make-safe/example.com/recheck", json={})
    assert second.status_code == 429 and int(second.headers["Retry-After"]) >= 1
    assert second.json()["watch"]["attempts"] == 1
    assert calls == [True]
    assert client.get("/api/public/make-safe/example.com/watch").json()["watch"]["status"] == "waiting"


def test_the_proof_page_is_public_complete_and_verifiable(client):
    missing = client.get("/r/example.com/proof")
    assert missing.status_code == 404 and "Make it safe" in missing.text
    store(False, 0)
    store(True, 5)
    page = client.get("/r/example.com/proof")
    assert page.status_code == 200
    assert "Quantum-safe since 2026-11-15" in page.text
    assert "<script src=\"/ui/make-safe-proof.js" in page.text and "/ui/vendor/morrow-pq-verify.js" in page.text
    assert "style=" not in page.text and "onclick" not in page.text
    env = client.get("/r/example.com/proof.json").json()
    assert ms.verify_envelope(env)["valid"] is True
    assert env["document"]["safe_since"] == ms.iso(T0 + timedelta(minutes=5))
    store(False, 10)
    lapsed = client.get("/r/example.com/proof")
    assert lapsed.status_code == 200 and "No longer quantum-safe" in lapsed.text
    assert client.get("/r/Example.COM/proof", follow_redirects=False).status_code == 301


def test_an_opted_out_domain_has_no_proof_and_no_plan(client, monkeypatch):
    store(True, 0)
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    assert client.get("/r/example.com/proof").status_code == 403
    assert client.get("/r/example.com/proof.json").status_code == 403
    assert client.get("/api/public/make-safe/example.com").status_code == 403


def test_the_record_page_makes_make_it_safe_the_primary_action():
    from services import registry_page

    html = registry_page.render_record({"domain": "example.com", "posture": _check.POSTURE_CLASSICAL, "result": {}},
                                       [], "https://morrow.test")
    assert '<a class="btn" href="/example.com#make-safe">Make it safe</a>' in html
