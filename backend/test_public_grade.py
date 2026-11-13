"""The public quantum-readiness grade: rubric, guardrails and the /api/public surface.

No network. The rubric is tested on fixture facts (grade_from_facts is pure); the API with
services.public_grade.resolve_pinned and .probe replaced; the SSRF guard with
services.alert_routing.resolve_host replaced (the seam the checker's tests use); and the probe's
pinning with socket.create_connection and the scanner's ClientHello probe replaced.
"""

import json
import os
import socket

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import alert_routing as _alert_routing
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    db = tmp_path / "public-grade.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.setattr(_grade, "own_addresses", lambda: frozenset({"203.0.113.250"}))
    _check._TABLES_READY.clear()
    _grade._TABLES_READY.clear()
    _limits.reset()
    yield db
    _check._TABLES_READY.clear()
    _grade._TABLES_READY.clear()
    _limits.reset()


def facts(**overrides):
    """Probe facts for a model grade-A endpoint; override to build the others."""
    base = _grade.empty_facts("example.com", "93.184.216.34")
    base.update({
        "tls": True,
        "tls_versions": {"1.0": False, "1.1": False, "1.2": True, "1.3": True},
        "negotiated_version": "TLSv1.3", "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
        "certificate_verified": True,
        "certificate": {"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "sha256WithRSAEncryption",
                        "not_after": "2027-03-01T00:00:00Z", "issuer": "CN=R11,O=Let's Encrypt,C=US",
                        "days_until_expiry": 100},
        "kx_group": "X25519MLKEM768", "kx_family": "pq_hybrid", "kx_observed": True,
        "pq_groups_accepted": ["X25519MLKEM768"], "rsa_kx_accepted": False,
        "weak_ciphers_accepted": [], "weak_cipher_probe": "tested",
        "server_header": "nginx/1.27.4", "platform": "nginx", "connections": 11,
    })
    base.update(overrides)
    return base


CLASSICAL = {"kx_group": "x25519", "kx_family": "classical", "pq_groups_accepted": []}


@pytest.fixture
def mocked(monkeypatch):
    """Replace DNS+guard and the probe. Returns a state dict the test can steer."""
    state = {"facts": facts(), "probed": [], "address": "93.184.216.34"}

    def fake_resolve(host):
        return state["address"]

    def fake_probe(host, address, timeout=None, deadline=None):
        state["probed"].append((host, address))
        out = dict(state["facts"])
        out["domain"] = host
        out["address"] = address
        return out

    monkeypatch.setattr(_grade, "resolve_pinned", fake_resolve)
    monkeypatch.setattr(_grade, "probe", fake_probe)
    return state


@pytest.fixture
def client(isolated_store, monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


# ── the rubric (pure) ────────────────────────────────────────────────────────


def test_hybrid_pq_with_tls13_and_no_legacy_is_an_a():
    result = _grade.grade_from_facts(facts())
    assert result["grade"] == "A"
    assert result["key_exchange"] == {"group": "X25519MLKEM768", "post_quantum": True, "hybrid": True,
                                      "offered_pq_groups_accepted": ["X25519MLKEM768"], "observed": True}
    assert result["fixes"] == []
    assert result["summary"] == "example.com protects new connections against future quantum decryption."


def test_a_classical_certificate_signature_is_not_penalised_and_the_cryptographer_is_told_why():
    result = _grade.grade_from_facts(facts())
    assert result["certificate"]["signature_algorithm"] == "sha256WithRSAEncryption"
    assert result["grade"] == "A"
    assert "ML-DSA" in result["summaries"]["cryptographer"]
    assert "not penalised" in result["summaries"]["cryptographer"]


@pytest.mark.parametrize("override,needle", [
    ({"tls_versions": {"1.0": True, "1.1": True, "1.2": True, "1.3": True}}, "TLS 1.0/1.1"),
    ({"weak_ciphers_accepted": ["DES-CBC3-SHA"]}, "DES-CBC3-SHA"),
    ({"certificate": dict(facts()["certificate"], days_until_expiry=5)}, "expires in 5 days"),
    ({"rsa_kx_accepted": True, "rsa_kx_cipher": "AES128-GCM-SHA256"}, "RSA key transport"),
])
def test_pq_with_a_remaining_weakness_is_a_b(override, needle):
    result = _grade.grade_from_facts(facts(**override))
    assert result["grade"] == "B"
    assert needle in result["summary"]
    assert result["exposure"]["recorded_traffic_at_risk"] is False


def test_tls13_with_classical_forward_secret_key_exchange_is_a_c():
    result = _grade.grade_from_facts(facts(**CLASSICAL))
    assert result["grade"] == "C"
    assert result["forward_secrecy"] is True
    assert result["exposure"]["recorded_traffic_at_risk"] is True


def test_tls12_max_with_ecdhe_is_a_d():
    result = _grade.grade_from_facts(facts(
        **CLASSICAL, tls_versions={"1.0": False, "1.1": False, "1.2": True, "1.3": False},
        negotiated_version="TLSv1.2", negotiated_cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert result["grade"] == "D"


def test_legacy_tls_without_tls13_is_an_e():
    result = _grade.grade_from_facts(facts(
        **CLASSICAL, tls_versions={"1.0": True, "1.1": True, "1.2": True, "1.3": False},
        negotiated_version="TLSv1.2", negotiated_cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert result["grade"] == "E"


def test_weak_ciphers_without_pq_are_an_e_even_with_tls13():
    result = _grade.grade_from_facts(facts(**CLASSICAL, weak_ciphers_accepted=["DES-CBC3-SHA"]))
    assert result["grade"] == "E"


def test_classical_tls13_with_legacy_enabled_stays_c_as_the_rubric_says():
    result = _grade.grade_from_facts(facts(**CLASSICAL, tls_versions={"1.0": True, "1.1": True,
                                                                     "1.2": True, "1.3": True}))
    assert result["grade"] == "C"
    assert any("TLS 1.0/1.1" in reason for reason in result["reasons"])


def test_no_tls_is_an_f():
    result = _grade.grade_from_facts(_grade.empty_facts("example.com"))
    assert result["grade"] == "F"
    assert result["summary"] == "example.com does not offer TLS on port 443."


def test_an_invalid_certificate_is_an_f_even_with_pq():
    result = _grade.grade_from_facts(facts(certificate_verified=False, verify_error="self-signed certificate"))
    assert result["grade"] == "F"
    assert "certificate" in result["summary"]
    assert any(fix["id"] == "certificate-renew" for fix in result["fixes"])


def test_an_expired_certificate_is_an_f():
    result = _grade.grade_from_facts(facts(certificate=dict(facts()["certificate"], days_until_expiry=-2)))
    assert result["grade"] == "F"


def test_a_modern_client_given_rsa_key_transport_is_an_f():
    result = _grade.grade_from_facts(facts(
        **CLASSICAL, tls_versions={"1.0": False, "1.1": False, "1.2": True, "1.3": False},
        negotiated_version="TLSv1.2", negotiated_cipher="AES256-GCM-SHA384", rsa_kx_accepted=True,
        rsa_kx_cipher="AES256-GCM-SHA384"))
    assert result["grade"] == "F"
    assert result["forward_secrecy"] is False


def test_rsa_key_transport_only_as_a_fallback_is_reported_but_does_not_fail_a_classical_site():
    result = _grade.grade_from_facts(facts(**CLASSICAL, rsa_kx_accepted=True, rsa_kx_cipher="AES128-GCM-SHA256"))
    assert result["grade"] == "C"
    assert any("RSA key transport" in reason for reason in result["reasons"])


def test_the_decrypt_years_come_from_the_cited_source_and_are_null_when_pq():
    at_risk = _grade.grade_from_facts(facts(**CLASSICAL))["exposure"]
    assert (at_risk["decrypt_year_low"], at_risk["decrypt_year_high"]) == (2035, 2040)
    assert "Global Risk Institute" in at_risk["basis"]
    assert at_risk["source_url"].startswith("https://globalriskinstitute.org/")
    safe = _grade.grade_from_facts(facts())["exposure"]
    assert safe == {"recorded_traffic_at_risk": False, "decrypt_year_low": None, "decrypt_year_high": None,
                    "basis": _grade.PQ_BASIS, "source_url": _grade.PQ_SOURCE_URL}


def test_every_grade_has_three_summaries_and_one_sentence():
    cases = [facts(), facts(tls_versions={"1.0": True, "1.1": False, "1.2": True, "1.3": True}),
             facts(**CLASSICAL),
             facts(**CLASSICAL, tls_versions={"1.0": False, "1.1": False, "1.2": True, "1.3": False},
                   negotiated_version="TLSv1.2", negotiated_cipher="ECDHE-RSA-AES128-GCM-SHA256"),
             facts(**CLASSICAL, weak_ciphers_accepted=["RC4-SHA"]), _grade.empty_facts("example.com")]
    seen = set()
    for case in cases:
        result = _grade.grade_from_facts(case)
        seen.add(result["grade"])
        assert set(result["summaries"]) == {"executive", "engineer", "cryptographer"}
        assert all(text.strip() for text in result["summaries"].values())
        assert result["summary"].endswith(".") and result["summary"].count(". ") == 0
    assert seen == set("ABCDEF")


@pytest.mark.parametrize("platform,needle,requires", [
    ("nginx", "ssl_ecdh_curve X25519MLKEM768", "OpenSSL 3.5"),
    ("apache", "SSLOpenSSLConfCmd Groups X25519MLKEM768", "OpenSSL 3.5"),
    ("caddy", "curves x25519mlkem768", "Caddy 2.10"),
    ("haproxy", "ssl-default-bind-curves X25519MLKEM768", "OpenSSL 3.5"),
    ("iis", 'Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0', "Windows Server 2025"),
    ("cloudflare", "min_tls_version", "Cloudflare"),
])
def test_the_fix_matches_the_detected_server(platform, needle, requires):
    result = _grade.grade_from_facts(facts(**CLASSICAL, platform=platform))
    fix = result["fixes"][0]
    assert set(fix) == {"id", "title", "applies_to", "snippet", "notes", "requires"}
    assert needle in fix["snippet"]
    assert requires in fix["requires"]


def test_an_unknown_server_gets_every_server_fix():
    result = _grade.grade_from_facts(facts(**CLASSICAL, platform="unknown", server_header=None))
    assert {fix["id"] for fix in result["fixes"]} == {
        "nginx-pq-tls", "apache-pq-tls", "caddy-pq-tls", "haproxy-pq-tls", "iis-pq-tls"}
    assert result["server_software"] is None


@pytest.mark.parametrize("server,headers,expected", [
    ("nginx/1.27.4", {}, "nginx"), ("openresty", {}, "nginx"), ("Apache/2.4.62 (Debian)", {}, "apache"),
    ("Caddy", {}, "caddy"), ("Microsoft-IIS/10.0", {}, "iis"), ("cloudflare", {}, "cloudflare"),
    (None, {"cf-ray": "x"}, "cloudflare"), ("AkamaiGHost", {}, "cdn"), (None, {"x-amz-cf-id": "x"}, "cdn"),
    ("gunicorn", {}, "unknown"), (None, {}, "unknown"),
])
def test_the_platform_is_read_from_response_headers(server, headers, expected):
    assert _grade.detect_platform(server, headers) == expected


def test_the_result_carries_every_contract_field():
    result = _grade.build_result(facts(), "2026-11-12T00:00:00Z")
    for key in ("domain", "scanned_at", "cached", "grade", "summary", "summaries", "tls", "key_exchange",
                "certificate", "forward_secrecy", "exposure", "server_software", "fixes", "rubric_version"):
        assert key in result, key
    assert set(result["tls"]["versions"]) == {"1.0", "1.1", "1.2", "1.3"}
    assert set(result["certificate"]) >= {"key_type", "key_bits", "signature_algorithm", "not_after", "issuer"}
    assert set(result["exposure"]) == {"recorded_traffic_at_risk", "decrypt_year_low", "decrypt_year_high",
                                       "basis", "source_url"}
    assert result["rubric_version"] == _grade.RUBRIC_VERSION
    json.dumps(result)


# ── validation and the SSRF guard ────────────────────────────────────────────


@pytest.mark.parametrize("value", [
    "", "127.0.0.1", "10.0.0.1", "[::1]", "::1", "example.com:443", "example.com:8443",
    "https://example.com", "example.com/path", "user@example.com", "user:pw@example.com",
    "localhost", "*.example.com", "exa mple.com", "example.com?x=1", "a" * 64 + ".com",
    ("a" * 60 + ".") * 5 + "com",
])
def test_anything_but_a_bare_public_hostname_is_refused_with_400(value):
    with pytest.raises(_grade.GradeError) as caught:
        _grade.normalize(value)
    assert caught.value.status_code == 400
    assert caught.value.error == "invalid_domain"


@pytest.mark.parametrize("value,expected", [
    ("Example.COM.", "example.com"), ("www.example.com", "www.example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_hostnames_are_idna_normalised_and_lowercased(value, expected):
    assert _grade.normalize(value) == expected


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "100.127.255.254", "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "::",
    "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
    "2002:a00:1::1", "203.0.113.250",
])
def test_every_non_public_address_and_the_servers_own_is_refused(address):
    assert _grade.refusal_reason(address, {"203.0.113.250"}) != ""


@pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700::6810:84e5"])
def test_ordinary_public_addresses_pass(address):
    assert _grade.refusal_reason(address, {"203.0.113.250"}) == ""


def test_one_private_answer_among_public_ones_refuses_the_target(monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["93.184.216.34", "10.0.0.5"])
    with pytest.raises(_grade.GradeError) as caught:
        _grade.resolve_pinned("example.com")
    assert caught.value.status_code == 403
    assert "10.0.0.5" in caught.value.detail and "private" in caught.value.detail


def test_a_name_resolving_to_this_server_is_refused(monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["203.0.113.250"])
    with pytest.raises(_grade.GradeError) as caught:
        _grade.resolve_pinned("example.com")
    assert caught.value.status_code == 403
    assert "own address" in caught.value.detail


def test_an_unresolvable_name_is_a_504(monkeypatch):
    def nxdomain(host, port):
        raise socket.gaierror("no such name")

    monkeypatch.setattr(_alert_routing, "resolve_host", nxdomain)
    with pytest.raises(_grade.GradeError) as caught:
        _grade.resolve_pinned("nope.example.com")
    assert caught.value.status_code == 504


def test_ipv4_is_preferred_for_the_pinned_address(monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host",
                        lambda host, port: ["2606:4700::6810:84e5", "104.16.132.229"])
    assert _grade.resolve_pinned("example.com") == "104.16.132.229"


def test_every_connection_goes_to_the_pinned_address_and_never_resolves(monkeypatch):
    import scanner

    targets, probes = [], []

    def refuse(address, *args, **kwargs):
        targets.append(address)
        raise ConnectionRefusedError("refused")

    def no_dns(*args, **kwargs):
        raise AssertionError("the probe must not resolve the name again")

    def fake_kx(host, port, timeout=6, address="", groups=None):
        probes.append((host, port, address))
        return {"key_exchange_observed": False}

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(scanner, "_probe_key_exchange_group", fake_kx)
    result = _grade.probe("example.com", "93.184.216.34", timeout=1, deadline=5)
    assert result["reachable"] is False
    assert targets == [("93.184.216.34", 443)]


def test_the_probes_after_the_first_handshake_are_pinned_too(monkeypatch):
    import scanner

    targets, probes = [], []

    def fake_handshake(address, host, ctx, timeout, read_cert=False):
        targets.append((address, host))
        return {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "der": None}

    def fake_kx(host, port, timeout=6, address="", groups=None):
        probes.append((host, port, address, groups))
        return {"key_exchange_observed": True, "key_exchange": "X25519MLKEM768",
                "key_exchange_group_id": 0x11EC, "key_exchange_family": "pq_hybrid"}

    def fake_head(address, host, timeout, max_bytes=8192):
        targets.append((address, host))
        return {"server": "nginx"}

    monkeypatch.setattr(_grade, "_handshake", fake_handshake)
    monkeypatch.setattr(_grade, "_http_head", fake_head)
    monkeypatch.setattr(scanner, "_probe_key_exchange_group", fake_kx)
    result = _grade.probe("example.com", "93.184.216.34", timeout=1, deadline=10)
    assert result["tls"] is True
    assert {t for t in targets} == {("93.184.216.34", "example.com")}
    assert probes and all(p[2] == "93.184.216.34" and p[1] == 443 for p in probes)
    assert {p[3] for p in probes} == {None, (0x11EC,), (0x11EB,), (0x11ED,)}
    assert result["platform"] == "nginx"


def test_the_single_group_client_hello_offers_only_that_group():
    import scanner

    one = scanner._build_client_hello("example.com", (0x11EB,))
    assert bytes.fromhex("000a0004000211eb") in one          # supported_groups = [SecP256r1MLKEM768]
    assert bytes.fromhex("003300020000") in one              # key_share: empty list -> HelloRetryRequest
    full = scanner._build_client_hello("example.com")
    assert bytes.fromhex("11ec04c0") in full                 # unchanged default: the 1216-byte hybrid share


# ── the API ──────────────────────────────────────────────────────────────────


def test_a_grade_is_served_and_then_cached(client, mocked):
    first = client.get("/api/public/grade/Example.COM")
    assert first.status_code == 200
    body = first.json()
    assert body["domain"] == "example.com" and body["grade"] == "A" and body["cached"] is False
    second = client.get("/api/public/grade/example.com")
    assert second.json()["cached"] is True
    assert len(mocked["probed"]) == 1
    assert mocked["probed"][0] == ("example.com", "93.184.216.34")


def test_fresh_bypasses_the_cache_and_has_a_stricter_limit(client, mocked):
    assert client.get("/api/public/grade/example.com").status_code == 200
    for _ in range(3):
        response = client.get("/api/public/grade/example.com?fresh=1")
        assert response.status_code == 200
        assert response.json()["cached"] is False
    limited = client.get("/api/public/grade/example.com?fresh=1")
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    assert set(limited.json()) == {"error", "detail"}
    assert len(mocked["probed"]) == 4


def test_requests_are_limited_per_client_ip(client, mocked):
    for _ in range(10):
        assert client.get("/api/public/grade/example.com").status_code == 200
    limited = client.get("/api/public/grade/example.com")
    assert limited.status_code == 429
    assert limited.json()["error"] == "rate_limited"
    assert "Retry-After" in limited.headers


def test_the_concurrency_cap_answers_429_rather_than_queueing(client, mocked, monkeypatch):
    class Full:
        def acquire(self, timeout=None):
            return False

        def release(self):
            pass

    monkeypatch.setattr(_grade, "_semaphore", lambda: Full())
    response = client.get("/api/public/grade/example.com")
    assert response.status_code == 429
    assert response.json()["error"] == "busy"
    assert mocked["probed"] == []


def test_an_invalid_domain_is_a_400_with_error_and_detail(client, mocked):
    response = client.get("/api/public/grade/127.0.0.1")
    assert response.status_code == 400
    assert set(response.json()) == {"error", "detail"}
    assert mocked["probed"] == []


def test_a_private_target_is_a_403_with_a_plain_reason(client, monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["169.254.169.254"])
    monkeypatch.setattr(_grade, "probe", lambda *a, **k: pytest.fail("a refused target was probed"))
    response = client.get("/api/public/grade/metadata.example.com")
    assert response.status_code == 403
    assert response.json()["error"] == "refused_target"
    assert "link-local" in response.json()["detail"]


def test_an_unreachable_host_is_a_504(client, mocked):
    mocked["facts"] = dict(_grade.empty_facts("example.com"), reachable=False, error="timed out")
    response = client.get("/api/public/grade/example.com")
    assert response.status_code == 504
    assert response.json()["error"] == "unreachable"


def test_an_opted_out_domain_is_refused_before_anything_is_resolved(client, monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    monkeypatch.setattr(_grade, "resolve_pinned", lambda host: pytest.fail("an opted-out domain was resolved"))
    response = client.get("/api/public/grade/www.example.com")
    assert response.status_code == 403
    assert response.json()["error"] == "refused_optout"


def test_the_text_form_is_short_plain_and_carries_the_grade(client, mocked):
    mocked["facts"] = facts(**CLASSICAL)
    response = client.get("/api/public/grade/example.com.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    text = response.text
    assert "\x1b" not in text
    assert 10 <= len(text.strip().splitlines()) <= 20
    assert text.startswith("example.com  grade C")
    assert "2035-2040" in text
    assert mocked["probed"][0][0] == "example.com"


def test_the_text_form_reports_errors_in_plain_text(client, mocked):
    response = client.get("/api/public/grade/10.0.0.1.txt")
    assert response.status_code == 400
    assert response.text.startswith("error: invalid_domain")


def test_the_badge_carries_the_grade_in_text_and_caches_for_hours(client, mocked):
    response = client.get("/api/public/badge/example.com.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert ">A</text>" in response.text and "quantum-ready" in response.text
    assert 'aria-label="quantum-ready: grade A"' in response.text
    assert "max-age=10800" in response.headers["cache-control"]
    # Served from the stored result the second time.
    client.get("/api/public/badge/example.com.svg")
    assert len(mocked["probed"]) == 1


def test_a_badge_for_a_refused_target_is_the_neutral_one(client, monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["10.0.0.1"])
    response = client.get("/api/public/badge/internal.example.com.svg")
    assert response.status_code == 200
    assert ">?</text>" in response.text
    assert "max-age=300" in response.headers["cache-control"]


def test_every_grade_has_its_own_badge_colour():
    colours = set()
    for grade in "ABCDEF":
        svg = _grade.badge_svg(grade)
        assert f">{grade}</text>" in svg
        colours.add(svg.split('<rect x="96"')[1].split('fill="')[1].split('"')[0])
    assert len(colours) == 6


def test_history_lists_stored_checks_newest_first(client, mocked):
    client.get("/api/public/grade/example.com")
    mocked["facts"] = facts(**CLASSICAL)
    client.get("/api/public/grade/example.com?fresh=1")
    rows = client.get("/api/public/history/example.com").json()
    assert [row["grade"] for row in rows] == ["C", "A"]
    assert set(rows[0]) == {"scanned_at", "grade", "group", "post_quantum"}
    assert rows[-1]["post_quantum"] is True
    assert client.get("/api/public/history/10.0.0.1").status_code == 400


def test_stats_are_aggregate_counts_and_name_nothing(client, mocked):
    client.get("/api/public/grade/example.com")
    mocked["facts"] = facts(**CLASSICAL)
    client.get("/api/public/grade/example.org")
    body = client.get("/api/public/stats").json()
    assert body["public_checks_total"] == 2 and body["public_checks_7d"] == 2
    assert body["domains_checked"] == 2
    assert body["pq_share_7d"] == 0.5
    assert "generated_at" in body
    assert "example" not in json.dumps(body)


def test_the_check_table_carries_no_organization_column(isolated_store):
    from db_feature_store import feature_conn

    _grade.init_tables()
    with feature_conn() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(public_grade_checks)").fetchall()}
    assert {"domain", "scanned_at", "grade", "key_exchange_group", "post_quantum", "result_json"} <= columns
    assert not any("org" in column for column in columns)


# ── CORS and authentication ──────────────────────────────────────────────────


def test_cors_allows_soqlab_for_get_without_credentials(client, mocked):
    response = client.get("/api/public/stats", headers={"Origin": "https://soqlab.com"})
    assert response.headers["access-control-allow-origin"] == "https://soqlab.com"
    assert "access-control-allow-credentials" not in response.headers
    assert "Origin" in response.headers["vary"]


def test_cors_ignores_other_origins(client, mocked):
    response = client.get("/api/public/stats", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_a_preflight_is_answered_for_get_only(client):
    ok = client.options("/api/public/grade/example.com", headers={
        "Origin": "http://localhost:3100", "Access-Control-Request-Method": "GET"})
    assert ok.status_code == 204
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3100"
    assert "POST" not in ok.headers["access-control-allow-methods"]
    post = client.options("/api/public/grade/example.com", headers={
        "Origin": "https://soqlab.com", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in post.headers
    other = client.options("/api/public/stats", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in other.headers


def test_the_public_api_is_exempt_from_the_auth_gate_and_nothing_else_is():
    import app as application

    for path in ("/api/public/grade/example.com", "/api/public/stats", "/v1/api/public/stats",
                 "/api/public/badge/example.com.svg"):
        assert application._auth_public_path(path) is True, path
    for path in ("/api/publicity", "/api/public-checkx", "/api", "/scan", "/assets"):
        assert application._auth_public_path(path) is False, path


def test_the_public_api_answers_with_production_auth_required(isolated_store, mocked, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/stats").status_code == 200
        assert anonymous.get("/api/public/grade/example.com").status_code == 200
        assert anonymous.get("/api/public/history/example.com").status_code == 200
        # The rest of the API still demands a login.
        assert anonymous.get("/scans").status_code in {401, 403}


# ── the command line ─────────────────────────────────────────────────────────


def test_the_batch_cli_writes_one_contract_object_per_line_and_resumes(tmp_path, mocked):
    domains = tmp_path / "domains.txt"
    domains.write_text("# top sites\n1,example.com\nexample.org\n\nEXAMPLE.org.\n10.0.0.1\n", encoding="utf-8")
    out = tmp_path / "results.jsonl"
    counts = _grade.run_batch(str(domains), str(out), concurrency_n=4, timeout=2)
    assert counts == {"total": 3, "skipped": 0, "ok": 2, "error": 1}
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    by_domain = {row["domain"]: row for row in rows}
    assert by_domain["example.com"]["grade"] == "A"
    assert by_domain["10.0.0.1"]["error"] == "invalid_domain"
    again = _grade.run_batch(str(domains), str(out), concurrency_n=4, timeout=2)
    assert again["skipped"] == 3 and again["ok"] == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 3


def test_the_cli_never_opens_the_database(tmp_path, mocked, monkeypatch):
    import db_feature_store

    monkeypatch.setattr(db_feature_store, "feature_conn", lambda: pytest.fail("the CLI opened the database"))
    monkeypatch.setattr(_check, "opted_out", lambda host: pytest.fail("the CLI read the opt-out table"))
    assert _grade.grade_one("example.com")["grade"] == "A"
