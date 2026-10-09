"""The free public post-quantum readiness checker: guardrails, verdicts and boundaries.

No network. Certificate Transparency is mocked at the provider callable, the TLS handshake and the
key-exchange probe at the two functions in services/public_check.py that make them, and DNS at
services/alert_routing.resolve_host -- the same seam the alert-routing tests use. A test that
reached the internet would measure the internet, not this code, and would be refused by this
project's own rules.

Covered here:
  * the SSRF refusals: private, loopback, link-local, CGNAT, metadata, IPv4-mapped, credentials,
    IP literals, wildcards, single labels, ports, bad hostnames
  * rate limiting per IP and per target domain, and the global budget
  * cache hit, cache expiry, and that a cache hit spends no check budget
  * the opt-out list, refused before anything is resolved
  * the bounded queue: full, and the wait timeout
  * the verdict for RSA-2048, P-256, a hybrid endpoint and an unreachable host
  * that a failed check is reported as failed and never as clean
  * that no tenant table is written by a check
  * the public routes, the permalink, the exports, and the operator surface
"""

import json
import os
import socket
import sqlite3
import ssl
import time

os.environ.setdefault("PQC_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("PQC_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import alert_routing as _alert_routing
from services import org_rate_limits as _limits
from services import public_check as _check


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Every test gets its own feature-store file, and no leftover counters or caches."""
    db = tmp_path / "public-check.db"
    monkeypatch.setenv("PQC_SCANNER_DB", str(db))
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_ENABLED", "1")
    _check._TABLES_READY.clear()
    _limits.reset()
    _check._ct_last_call[0] = 0.0
    _check._waiting[0] = 0
    yield db
    _check._TABLES_READY.clear()
    _limits.reset()


@pytest.fixture
def no_network(monkeypatch):
    """Fail loudly if anything in this file opens a socket or asks for DNS."""
    def forbidden(*args, **kwargs):
        raise AssertionError("this test must not touch the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(_alert_routing, "resolve_host", forbidden)
    return forbidden


def resolves_to(monkeypatch, *addresses):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: list(addresses))


# A handshake observation, shaped exactly as services/public_check.observe_endpoint returns one.
def observation(**overrides):
    facts = {
        "host": "example.com", "port": 443, "address_checked": "93.184.216.34",
        "error": "", "error_code": "", "scan_status": "ok",
        "tls_version": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256, "alpn": "h2", "certificate_verified": True, "verify_error": "",
        "key_exchange": "x25519", "key_exchange_group_id": 29, "key_exchange_family": "classical",
        "key_exchange_observed": True, "key_exchange_observation_method": "tls_client_hello_probe",
        "key_exchange_unobservable_reason": "", "key_exchange_hello_retry": False,
        "subject": "CN=example.com", "issuer": "CN=R11,O=Let's Encrypt,C=US",
        "not_before": "2026-08-01T00:00:00Z", "not_after": "2026-11-01T00:00:00Z",
        "days_until_expiry": 28,
        "key_type": "RSA", "key_detail": "2048", "key_bits": 2048, "key_curve": "",
        "sig_algorithm": "sha256WithRSAEncryption", "san_dns": ["example.com"],
        "tls_supported_versions": ["TLSv1.3"], "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [], "ocsp_urls": [], "crl_urls": [],
        "cert_chain": [], "chain_length": 2, "chain_issues": [],
    }
    facts.update(overrides)
    return facts


CT_OK = {
    "status": "ok", "provider": "crt.sh", "provider_url": "https://crt.sh/",
    "certificate_count": 7, "entries": [
        {"issuer": "CN=R11,O=Let's Encrypt,C=US", "common_name": "example.com",
         "names": ["example.com"], "not_before": "2026-08-01", "not_after": "2026-11-01",
         "logged_at": "2026-08-01"},
    ],
    "issuers": [{"issuer": "CN=R11,O=Let's Encrypt,C=US", "certificates": 7}],
    "key_history": [{"not_before": "2026-08-01", "not_after": "2026-11-01",
                     "issuer": "CN=R11", "key_type": "RSA", "key_bits": 2048,
                     "key_curve": "", "sig_algorithm": "sha256WithRSAEncryption"}],
    "earliest_not_before": "2025-01-01", "latest_not_after": "2026-11-01", "reason": "",
}


@pytest.fixture
def mocked_check(monkeypatch):
    """Mock the two boundaries: the TLS observation and the CT lookup. Returns a setter."""
    state = {"observation": observation(), "ct": dict(CT_OK), "observed_with": []}

    def fake_observe(host, address="", timeout=None, deadline=None):
        state["observed_with"].append({"host": host, "address": address})
        facts = dict(state["observation"])
        facts["host"] = host
        facts["address_checked"] = address
        return facts

    def fake_ct(domain, deadline=None):
        return dict(state["ct"])

    monkeypatch.setattr(_check, "observe_endpoint", fake_observe)
    monkeypatch.setattr(_check, "certificate_transparency", fake_ct)
    return state


@pytest.fixture
def client(isolated_store, monkeypatch):
    monkeypatch.setenv("PQC_AUTH_MODE", "header")
    monkeypatch.setenv("PQC_DEFAULT_ROLE", "admin")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


# ── target validation and the SSRF refusals ──────────────────────────────────


@pytest.mark.parametrize("value,outcome", [
    ("", "refused_invalid"),
    ("   ", "refused_invalid"),
    ("localhost", "refused_invalid"),            # single label: not a registrable name
    ("example", "refused_invalid"),
    ("*.example.com", "refused_wildcard"),
    ("exa mple.com", "refused_invalid"),
    ("user:pass@example.com", "refused_credentials"),
    ("admin@example.com", "refused_credentials"),
    ("127.0.0.1", "refused_ip_literal"),
    ("169.254.169.254", "refused_ip_literal"),   # the cloud metadata address, as a literal
    ("10.0.0.1", "refused_ip_literal"),
    ("[::1]", "refused_ip_literal"),
    ("::1", "refused_ip_literal"),
    ("example.com:22", "refused_port"),
    ("example.com:8443", "refused_port"),
    ("ftp://example.com", "refused_invalid"),
    ("example.com_", "refused_wildcard"),        # underscore is not a hostname character
    ("-example.com", "refused_invalid"),
    ("example.123", "refused_invalid"),          # numeric TLD is not a TLD
    ("a" * 70 + ".com", "refused_invalid"),      # label over 63 characters
])
def test_a_target_this_tool_will_not_touch_is_refused_before_anything_is_contacted(
        value, outcome, no_network):
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.normalize_domain(value)
    assert caught.value.status_code == 400
    assert caught.value.outcome == outcome


@pytest.mark.parametrize("value,expected", [
    ("Example.COM", "example.com"),
    ("example.com.", "example.com"),
    ("https://example.com/path?q=1", "example.com"),
    ("http://sub.example.co.uk", "sub.example.co.uk"),
    ("example.com:443", "example.com"),
    ("  example.com  ", "example.com"),
])
def test_what_a_person_actually_pastes_is_normalised_to_one_hostname(value, expected, no_network):
    assert _check.normalize_domain(value) == expected


@pytest.mark.parametrize("address", [
    "127.0.0.1",            # loopback
    "10.1.2.3",             # private
    "192.168.1.1",          # private
    "172.16.0.9",           # private
    "169.254.169.254",      # link-local, and the cloud metadata address
    "100.64.0.1",           # carrier-grade NAT
    "0.0.0.0",              # unspecified
    "224.0.0.1",            # multicast
    "240.0.0.1",            # reserved
    "::1",                  # IPv6 loopback
    "fd00::1",              # IPv6 unique local
    "fe80::1",              # IPv6 link-local
    "::ffff:127.0.0.1",     # IPv4-mapped loopback, which a naive is_private test passes
    "::ffff:169.254.169.254",
    "2002:7f00:1::1",       # 6to4 wrapping 127.0.0.0/8
])
def test_a_name_that_resolves_off_the_public_internet_is_refused(address, monkeypatch):
    resolves_to(monkeypatch, address)
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.resolve_public_address("internal.example.com")
    assert caught.value.status_code == 403
    assert caught.value.outcome == "refused_private"


def test_one_private_answer_among_public_ones_refuses_the_whole_target(monkeypatch):
    """Which address a later connect would pick is not something this code can promise."""
    resolves_to(monkeypatch, "93.184.216.34", "10.0.0.5")
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.resolve_public_address("split.example.com")
    assert caught.value.outcome == "refused_private"


def test_a_name_that_does_not_resolve_is_refused_not_connected_to(monkeypatch):
    def fails(host, port):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(_alert_routing, "resolve_host", fails)
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.resolve_public_address("nope.example.com")
    assert caught.value.outcome == "refused_dns"


def test_the_address_that_was_checked_is_the_address_that_is_connected_to(
        monkeypatch, mocked_check):
    """Pinning: resolve once, vet it, then hand that address to the handshake."""
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.2.3.4")
    assert mocked_check["observed_with"] == [{"host": "example.com", "address": "93.184.216.34"}]


def test_the_guard_is_the_same_function_that_guards_outbound_webhooks():
    """One definition of "public address" in the process, not two that can drift."""
    assert _check.resolve_public_address.__module__ == "services.public_check"
    assert _alert_routing.ip_is_public("93.184.216.34") is True
    assert _alert_routing.ip_is_public("::ffff:127.0.0.1") is False


def test_the_port_is_not_configurable():
    """A configurable port would turn this into the port prober the guardrails exist to prevent."""
    assert _check.PORT == 443
    source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "services", "public_check.py"), encoding="utf-8").read()
    assert "PORT = 443" in source
    assert "PQC_PUBLIC_CHECK_PORT" not in source


# ── opt-out ──────────────────────────────────────────────────────────────────


def test_an_opted_out_domain_is_refused_before_it_is_even_resolved(no_network, mocked_check):
    _check.add_optout("example.com", reason="owner asked")
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("example.com", client_ip="1.2.3.4")
    assert caught.value.status_code == 403
    assert caught.value.outcome == "refused_optout"
    assert mocked_check["observed_with"] == []


def test_an_opt_out_covers_everything_under_the_domain(no_network):
    _check.add_optout("example.com")
    assert _check.opted_out("www.example.com") == "example.com"
    assert _check.opted_out("deep.nested.example.com") == "example.com"
    assert _check.opted_out("example.com") == "example.com"
    assert _check.opted_out("notexample.com") == ""
    assert _check.opted_out("example.com.evil.net") == ""


def test_an_opt_out_from_configuration_is_honoured_without_a_table_row(monkeypatch, no_network):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example, other.test")
    assert _check.opted_out("www.quiet.example") == "quiet.example"
    assert _check.opted_out("other.test") == "other.test"


def test_opting_out_deletes_the_cached_result(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.2.3.4")
    assert _check.cached_result("example.com") is not None
    _check.add_optout("example.com")
    assert _check.cached_result("example.com") is None


def test_an_opt_out_can_be_removed(no_network):
    _check.add_optout("example.com")
    assert _check.opted_out("example.com") == "example.com"
    _check.remove_optout("example.com")
    assert _check.opted_out("example.com") == ""


# ── rate limits ──────────────────────────────────────────────────────────────


def test_checks_are_limited_per_client_ip(monkeypatch, mocked_check):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_LIMIT", "2")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_BURST", "99")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "99")
    resolves_to(monkeypatch, "93.184.216.34")

    _check.run_check("one.example.com", client_ip="9.9.9.9")
    _check.run_check("two.example.com", client_ip="9.9.9.9")
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("three.example.com", client_ip="9.9.9.9")
    assert caught.value.status_code == 429
    assert caught.value.outcome == "rate_limited"
    # A different address has its own budget.
    assert _check.run_check("three.example.com", client_ip="8.8.8.8")["domain"] == "three.example.com"


def test_a_burst_from_one_address_is_limited_per_minute(monkeypatch, mocked_check):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_BURST", "1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_LIMIT", "99")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "99")
    resolves_to(monkeypatch, "93.184.216.34")

    _check.run_check("one.example.com", client_ip="9.9.9.9")
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("two.example.com", client_ip="9.9.9.9")
    assert caught.value.outcome == "rate_limited"


def test_checks_are_limited_per_target_domain_whoever_asks(monkeypatch, mocked_check):
    """The guardrail that stops the service being used to hammer one host."""
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "2")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_LIMIT", "99")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_BURST", "99")
    resolves_to(monkeypatch, "93.184.216.34")

    _check.run_check("victim.example.com", client_ip="1.1.1.1", force=True)
    _check.run_check("victim.example.com", client_ip="2.2.2.2", force=True)
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("victim.example.com", client_ip="3.3.3.3", force=True)
    assert caught.value.status_code == 429
    assert caught.value.outcome == "rate_limited"
    assert "victim.example.com" in caught.value.detail


def test_the_whole_service_has_an_hourly_budget(monkeypatch, mocked_check):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_GLOBAL_LIMIT", "1")
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("one.example.com", client_ip="1.1.1.1")
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("two.example.com", client_ip="2.2.2.2")
    assert caught.value.outcome == "rate_limited"


def test_a_rate_limited_refusal_carries_a_retry_hint(monkeypatch, mocked_check):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "1")
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.1.1.1", force=True)
    with pytest.raises(_check.PublicCheckError) as caught:
        _check.run_check("example.com", client_ip="2.2.2.2", force=True)
    assert caught.value.retry_after is not None and caught.value.retry_after > 0


# ── cache ────────────────────────────────────────────────────────────────────


def test_a_second_visitor_gets_the_cache_and_the_target_is_not_contacted_again(
        monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    first = _check.run_check("example.com", client_ip="1.1.1.1")
    assert first["cache"]["hit"] is False
    second = _check.run_check("example.com", client_ip="2.2.2.2")
    assert second["cache"]["hit"] is True
    assert len(mocked_check["observed_with"]) == 1, "the endpoint was contacted twice"


def test_a_cache_hit_spends_no_check_budget(monkeypatch, mocked_check):
    """A popular domain must be checked once, not once per visitor -- including its own budget."""
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_LIMIT", "1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_BURST", "1")
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.1.1.1")
    for ip in ("2.2.2.2", "3.3.3.3", "4.4.4.4", "1.1.1.1"):
        assert _check.run_check("example.com", client_ip=ip)["cache"]["hit"] is True
    assert len(mocked_check["observed_with"]) == 1


def test_an_expired_cache_entry_is_not_served(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.1.1.1")
    assert _check.cached_result("example.com") is not None

    # Age the row past its expiry rather than waiting an hour.
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE public_check_results SET expires_at = ? WHERE domain = ?",
                     ("2020-01-01T00:00:00Z", "example.com"))
        conn.commit()
    assert _check.cached_result("example.com") is None

    _check.run_check("example.com", client_ip="1.1.1.1")
    assert len(mocked_check["observed_with"]) == 2


def test_refresh_bypasses_the_cache_but_not_the_budget(monkeypatch, mocked_check):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "2")
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="1.1.1.1")
    assert _check.run_check("example.com", client_ip="1.1.1.1", force=True)["cache"]["hit"] is False
    with pytest.raises(_check.PublicCheckError):
        _check.run_check("example.com", client_ip="1.1.1.1", force=True)


# ── the bounded queue ────────────────────────────────────────────────────────


def test_a_full_queue_is_refused_rather_than_queued_forever(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_MAX_QUEUE", "2")
    _check._waiting[0] = 2
    try:
        with pytest.raises(_check.PublicCheckError) as caught:
            with _check._Admission():
                pass
        assert caught.value.status_code == 503
        assert caught.value.outcome == "queue_full"
    finally:
        _check._waiting[0] = 0


def test_a_check_that_cannot_get_a_slot_in_time_is_refused(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CONCURRENCY", "1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_QUEUE_WAIT_SECONDS", "0.1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_MAX_QUEUE", "8")
    _check._resize_slots()
    with _check._Admission():                       # the only slot is taken
        started = time.monotonic()
        with pytest.raises(_check.PublicCheckError) as caught:
            with _check._Admission():
                pass
        waited = time.monotonic() - started
    assert caught.value.status_code == 503
    assert caught.value.outcome == "queue_timeout"
    assert waited < 3.0, "a slow target held the request far longer than the configured wait"


def test_a_slot_is_released_even_when_the_check_raises(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CONCURRENCY", "1")
    _check._resize_slots()
    with pytest.raises(RuntimeError):
        with _check._Admission():
            raise RuntimeError("the target hung up")
    with _check._Admission():                       # the slot came back
        pass


def test_the_queue_bound_and_the_deadline_are_published(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_MAX_QUEUE", "17")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DEADLINE_SECONDS", "9")
    settings = _check.settings_public()
    assert settings["max_queued_checks"] == 17
    assert settings["deadline_seconds"] == 9.0


# ── Certificate Transparency ─────────────────────────────────────────────────


def test_certificate_transparency_being_down_is_reported_as_unavailable(monkeypatch):
    def explodes(domain, timeout):
        raise OSError("crt.sh timed out")

    monkeypatch.setitem(_check.CT_PROVIDERS, "crtsh", explodes)
    result = _check.certificate_transparency("example.com")
    assert result["status"] == "unavailable"
    assert "crt.sh timed out" in result["reason"]
    assert "not evidence that the domain has no certificates" in result["reason"]
    assert result["certificate_count"] is None


def test_certificate_transparency_unavailable_never_becomes_no_certificates(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["ct"] = {"status": "unavailable", "provider": "crt.sh", "provider_url": "",
                          "certificate_count": None, "entries": [], "issuers": [],
                          "key_history": [], "earliest_not_before": "", "latest_not_after": "",
                          "reason": "HTTP 502"}
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    ct = result["certificate_transparency"]
    assert ct["status"] == "unavailable"
    assert ct["certificate_count"] is None
    assert ct["issuers"] == []
    # and the verdict still stands on the handshake
    assert result["verdict"]["status"] == "quantum_vulnerable"


def test_a_check_still_produces_a_verdict_when_ct_is_switched_off(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CT_ENABLED", "0")
    result = _check.certificate_transparency("example.com")
    assert result["status"] == "skipped"
    assert "switched off" in result["reason"]


def test_the_ct_politeness_throttle_skips_rather_than_blocking(monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS", "30")
    monkeypatch.setitem(_check.CT_PROVIDERS, "crtsh",
                        lambda domain, timeout: dict(CT_OK, total=1, entries=[]))
    _check._ct_last_call[0] = time.monotonic()      # a call just happened
    result = _check.certificate_transparency("example.com", deadline=time.monotonic() + 2.0)
    assert result["status"] == "unavailable"
    assert "one request every" in result["reason"]


def test_the_crtsh_adapter_parses_the_json_index_and_tolerates_junk(monkeypatch):
    rows = [
        {"id": 1, "issuer_name": "CN=R11", "common_name": "example.com",
         "name_value": "example.com\nwww.example.com", "not_before": "2026-08-01",
         "not_after": "2026-11-01", "entry_timestamp": "2026-08-01"},
        {"id": 2, "issuer_name": "CN=R10", "common_name": "example.com",
         "name_value": "example.com", "not_before": "2026-05-01",
         "not_after": "2026-08-01", "entry_timestamp": "2026-05-01"},
        "this is not an object",
        {},
    ]
    monkeypatch.setattr(_check, "_http_get_json", lambda url, timeout, headers=None: rows)
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CT_CERT_FETCH", "0")
    data = _check._ct_crtsh("example.com", 5.0)
    assert data["total"] == 3                       # the junk string is dropped, {} is kept as an entry
    assert data["entries"][0]["not_before"] == "2026-08-01"   # newest first
    assert data["entries"][0]["names"] == ["example.com", "www.example.com"]
    assert data["provider"] == "crt.sh"


def test_a_ct_provider_that_returns_a_non_array_is_an_error_not_an_empty_result(monkeypatch):
    monkeypatch.setattr(_check, "_http_get_json",
                        lambda url, timeout, headers=None: {"error": "rate limited"})
    with pytest.raises(RuntimeError):
        _check._ct_crtsh("example.com", 5.0)


def test_a_data_source_is_added_by_registering_one_callable(monkeypatch):
    """The documented extension point: one entry in CT_PROVIDERS."""
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CT_PROVIDER", "fake")
    monkeypatch.setitem(_check.CT_PROVIDERS, "fake", lambda domain, timeout: {
        "entries": [{"issuer": "CN=Test CA", "not_before": "2026-01-01", "not_after": "2027-01-01"}],
        "total": 1, "keys": [], "provider": "fake", "provider_url": "https://example.invalid/",
    })
    result = _check.certificate_transparency("example.com")
    assert result["status"] == "ok"
    assert result["provider"] == "fake"
    assert result["issuers"] == [{"issuer": "CN=Test CA", "certificates": 1}]


# ── the verdict ──────────────────────────────────────────────────────────────


def test_rsa_2048_is_called_quantum_vulnerable_in_words_a_non_expert_reads(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    verdict = result["verdict"]
    assert verdict["status"] == "quantum_vulnerable"
    assert verdict["quantum_vulnerable"] is True
    assert "Quantum-vulnerable" in verdict["headline"]
    assert "RSA-2048" in verdict["explanation"]
    assert "breakable by a sufficiently large quantum computer" in verdict["explanation"]
    assert result["observed"]["certificate"]["key_bits"] == 2048
    # The raw wire strings are resolved to the names the rest of the platform uses, so the key size
    # is in the verdict rather than a bare "RSA".
    by_role = {a["role"]: a for a in result["algorithms"]}
    assert by_role["certificate key"]["resolved_as"] == "RSA-2048"
    assert by_role["certificate key"]["status"] == "quantum_vulnerable"
    assert by_role["certificate signature"]["resolved_as"] == "RSA-2048"
    assert by_role["signature digest"]["resolved_as"] == "SHA-256"
    assert by_role["signature digest"]["status"] == "compliant"


def test_a_p256_certificate_is_quantum_vulnerable_too(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        key_type="EC", key_detail="secp256r1", key_bits=256, key_curve="secp256r1",
        sig_algorithm="ecdsa-with-SHA256", cipher_name="ECDHE-ECDSA-AES128-GCM-SHA256")
    result = _check.run_check("ec.example.com", client_ip="1.1.1.1")
    assert result["verdict"]["status"] == "quantum_vulnerable"
    assert result["verdict"]["quantum_vulnerable"] is True
    assert "EC-256" in result["verdict"]["explanation"]
    by_role = {a["role"]: a for a in result["algorithms"]}
    assert by_role["certificate key"]["resolved_as"] == "ECDSA-P256"
    assert by_role["certificate key"]["status"] == "quantum_vulnerable"


def test_a_hybrid_endpoint_is_credited_for_its_key_exchange_and_not_for_its_certificate(
        monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        key_exchange="X25519MLKEM768", key_exchange_group_id=0x11EC,
        key_exchange_family="pqc_hybrid", key_exchange_observed=True)
    result = _check.run_check("hybrid.example.com", client_ip="1.1.1.1")
    verdict = result["verdict"]
    assert verdict["status"] == "hybrid_key_exchange"
    assert "Partly protected" in verdict["headline"]
    assert "X25519MLKEM768" in verdict["explanation"]
    assert "cannot be decrypted later" in verdict["explanation"]
    assert "certificate still uses RSA-2048" in verdict["explanation"]
    # A hybrid group is split into its two halves, because that is what hybrid means: the
    # post-quantum part is compliant and the classical part is still breakable.
    kx = {a["resolved_as"]: a["status"] for a in result["algorithms"] if a["role"] == "key exchange"}
    assert kx == {"X25519": "quantum_vulnerable", "ML-KEM-768": "compliant"}
    assert result["harvest_now_decrypt_later"]["algorithm_class"] == "pqc_hybrid"


def test_a_key_exchange_group_that_was_not_observed_is_not_reported_as_absent(
        monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        key_exchange="", key_exchange_group_id=None, key_exchange_family="",
        key_exchange_observed=False,
        key_exchange_unobservable_reason="server rejected the probe ClientHello")
    result = _check.run_check("quiet.example.com", client_ip="1.1.1.1")
    observed = result["observed"]
    assert observed["key_exchange_observed"] is False
    assert observed["key_exchange"] == ""
    assert "rejected the probe" in observed["key_exchange_unobservable_reason"]
    row = next(r for r in result["evidence"] if r["label"] == "Key-exchange group")
    assert row["value"] == "not observed"
    assert "rejected the probe" in row["note"]


@pytest.mark.parametrize("status,error_code,phrase", [
    ("dns_error", "DNS_ERROR", "the name did not resolve"),
    ("timeout", "TIMEOUT", "did not answer in time"),
    ("unreachable", "CONNECTION_ERROR", "could not be reached"),
    ("tls_error", "TLS_ERROR", "TLS handshake failed"),
    ("no_certificate", "", "no certificate could be read"),
])
def test_an_unreachable_host_is_reported_as_failed_never_as_clean(
        status, error_code, phrase, monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        scan_status=status, error_code=error_code, error="connection failed",
        tls_version="", cipher_name="", cipher_bits=None, certificate_verified=False,
        subject="", issuer="", not_before="", not_after="", days_until_expiry=None,
        key_type="", key_detail="", key_bits=0, key_curve="", sig_algorithm="",
        key_exchange="", key_exchange_family="", key_exchange_observed=False,
        tls_supported_versions=[])
    result = _check.run_check("down.example.com", client_ip="1.1.1.1")

    assert result["outcome"] == "failed"
    assert result["verdict"]["status"] == "not_assessed"
    assert result["verdict"]["quantum_vulnerable"] is None
    assert result["verdict"]["risk_level"] is None
    assert result["verdict"]["crypto_agility_score"] is None
    assert phrase in result["verdict"]["explanation"]
    assert "not a clean result" in result["verdict"]["explanation"]
    assert result["observed"]["reachable"] is False
    assert result["harvest_now_decrypt_later"]["risk_tier"] == "unmeasured"
    assert result["harvest_now_decrypt_later"]["break_probability_by_q_day"] is None


def test_a_failed_check_never_scores_better_than_an_honest_rsa_one(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    rsa = _check.run_check("rsa.example.com", client_ip="1.1.1.1")
    mocked_check["observation"] = observation(
        scan_status="unreachable", error_code="CONNECTION_ERROR", error="refused",
        tls_version="", cipher_name="", key_type="", key_bits=0, sig_algorithm="",
        subject="", issuer="", key_exchange="", key_exchange_observed=False,
        key_exchange_family="", tls_supported_versions=[], certificate_verified=False)
    failed = _check.run_check("down.example.com", client_ip="2.2.2.2")
    assert rsa["verdict"]["crypto_agility_score"] is not None
    assert failed["verdict"]["crypto_agility_score"] is None, (
        "an unreachable host must not be given a score; absence of evidence is not a pass")


# ── sourcing, limits and honesty ─────────────────────────────────────────────


def test_every_figure_on_the_page_names_its_source(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    assert result["evidence"], "the page would have figures with no stated source"
    allowed = {"handshake", "certificate_transparency", "model", "reference"}
    for row in result["evidence"]:
        assert row["source"] in allowed, row
        assert row["label"]
    sources = {row["source"] for row in result["evidence"]}
    assert "handshake" in sources
    assert "certificate_transparency" in sources


def test_the_result_carries_a_model_basis_that_separates_measurement_from_model(
        monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    basis = _check.run_check("example.com", client_ip="1.1.1.1")["model_basis"]
    assert set(basis) == {"kind", "summary", "assumptions", "sources", "as_of"}
    assert basis["kind"] == "model"
    assert "measured" in basis["summary"]
    assert any("Q-Day year used" in a for a in basis["assumptions"])
    assert any("never counted as absent" in a for a in basis["assumptions"])
    assert basis["as_of"] == "2026-10"


def test_the_result_states_its_own_limits_and_what_a_full_assessment_adds(
        monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    joined = " ".join(result["limits"]).lower()
    assert "one endpoint" in joined
    assert "one moment" in joined
    assert "public data only" in joined
    assert len(result["what_a_full_assessment_adds"]) >= 4


def test_the_deadlines_come_from_the_platforms_own_regulatory_data(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    deadlines = _check.run_check("example.com", client_ip="1.1.1.1")["deadlines"]
    frameworks = {row["framework"] for row in deadlines}
    assert {"NIST_SP_800_208", "CNSA_2_0"} <= frameworks
    for row in deadlines:
        assert row["hard_deadline"]
        assert row["authority"]


def test_the_free_answer_and_the_paid_product_share_one_classification(monkeypatch, mocked_check):
    """Same fips_pqc verdict for the same algorithm, so the two cannot disagree."""
    from services import fips_pqc

    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    for item in result["algorithms"]:
        assert item["status"] == fips_pqc.classify_algorithm(item["resolved_as"])["status"]


def test_a_standard_endpoint_produces_no_unknown_algorithm_card(monkeypatch, mocked_check):
    """"Unknown -- manual review required" on a public page reads as "probably fine".

    The wire strings (sha256WithRSAEncryption, secp256r1, X25519MLKEM768) all classified as
    unknown before they were resolved through the CBOM algorithm resolvers.
    """
    resolves_to(monkeypatch, "93.184.216.34")
    for observation_kwargs in (
        {},
        {"key_type": "EC", "key_bits": 256, "key_curve": "secp256r1",
         "sig_algorithm": "ecdsa-with-SHA256"},
        {"key_exchange": "X25519MLKEM768", "key_exchange_family": "pqc_hybrid"},
    ):
        mocked_check["observation"] = observation(**observation_kwargs)
        result = _check.run_check(f"d{len(observation_kwargs)}x.example.com", client_ip="1.1.1.1",
                                  force=True)
        statuses = {a["resolved_as"]: a["status"] for a in result["algorithms"]}
        assert statuses, observation_kwargs
        assert "unknown" not in statuses.values(), statuses


def test_an_algorithm_card_carries_the_reason_and_the_action(monkeypatch, mocked_check):
    """The page renders `details` and `action`; empty ones would leave bare name-plus-chip cards."""
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    for item in result["algorithms"]:
        assert item.get("details"), item
        assert item.get("action"), item
        assert item.get("role")
        assert item.get("resolved_as")
        assert item.get("observed_as")


def test_migration_advice_fits_what_the_algorithm_is_doing(monkeypatch, mocked_check):
    """ML-KEM cannot sign anything, so it is not the answer for a certificate.

    services/fips_pqc.py keys its advice by algorithm, not by role, and answers RSA-2048 with
    "Migrate to ML-KEM-768" wherever it appears. Printed under a card headed CERTIFICATE KEY that
    is advice that does not work.
    """
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    by_role = {a["role"]: a for a in result["algorithms"]}

    for role in ("certificate key", "certificate signature"):
        action = by_role[role]["action"].upper().replace("-", "")
        assert "MLDSA" in action or "SLHDSA" in action, (role, by_role[role]["action"])
        # The catalogue's own wording is kept, never silently rewritten.
        assert by_role[role]["action_from_catalogue"] == "Migrate to ML-KEM-768"
        # The classification itself is untouched, so the free and paid answers still agree.
        assert by_role[role]["status"] == "quantum_vulnerable"
        assert by_role[role]["risk"] == "critical"

    # A suggestion that already fits the role is left exactly as the catalogue wrote it.
    mocked_check["observation"] = observation(key_exchange="x25519", key_exchange_family="classical")
    kx = next(a for a in _check.run_check("kx.example.com", client_ip="1.1.1.1")["algorithms"]
              if a["role"] == "key exchange")
    assert kx["action"] == "Migrate to X25519MLKEM768"
    assert "action_from_catalogue" not in kx


def test_a_compliant_algorithm_is_given_no_migration_action(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        key_exchange="X25519MLKEM768", key_exchange_family="pqc_hybrid")
    result = _check.run_check("hybrid.example.com", client_ip="1.1.1.1")
    for item in result["algorithms"]:
        if item["status"] == "compliant":
            assert item["action"] == "none"
            assert "action_from_catalogue" not in item


def test_the_result_says_how_many_connections_were_made(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    assert result["observed"]["connections_made"] == 2
    assert result["observed"]["port"] == 443


# ── the log ──────────────────────────────────────────────────────────────────


def test_each_check_is_logged_with_a_hashed_address_and_an_outcome(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    _check.run_check("example.com", client_ip="203.0.113.9")
    rows = _check.recent_log(limit=10)
    assert rows and rows[0]["domain"] == "example.com"
    assert rows[0]["outcome"] == "ok"
    assert rows[0]["requester_ip_hash"] and "203.0.113" not in rows[0]["requester_ip_hash"]
    assert rows[0]["duration_ms"] is not None


def test_a_refusal_is_logged_so_abuse_can_be_investigated(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "10.0.0.1")
    with pytest.raises(_check.PublicCheckError):
        _check.run_check("internal.example.com", client_ip="203.0.113.9")
    outcomes = {row["outcome"] for row in _check.recent_log(limit=10)}
    assert "refused_private" in outcomes


def test_the_same_address_hashes_the_same_way_and_a_different_one_does_not():
    assert _check.hash_ip("203.0.113.9") == _check.hash_ip("203.0.113.9")
    assert _check.hash_ip("203.0.113.9") != _check.hash_ip("203.0.113.10")
    assert "203.0.113.9" not in _check.hash_ip("203.0.113.9")


def test_an_unsalted_hash_is_never_used(monkeypatch):
    """A bare sha256 of an IPv4 address is reversible by brute force in seconds."""
    import hashlib

    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_SALT", "")
    _check._TABLES_READY.clear()
    bare = hashlib.sha256(b"203.0.113.9").hexdigest()[:32]
    assert _check.hash_ip("203.0.113.9") != bare


# ── no tenant data ───────────────────────────────────────────────────────────


def test_a_check_writes_only_its_own_tables_and_touches_no_tenant_data(
        isolated_store, monkeypatch, mocked_check):
    import db

    resolves_to(monkeypatch, "93.184.216.34")
    db_path = str(isolated_store)
    _check.init_tables()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT, host TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT, asset_key TEXT)""")
        conn.commit()
        before = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scan_results", "assets")
        }
    finally:
        conn.close()

    _check.run_check("example.com", client_ip="1.1.1.1")

    conn = sqlite3.connect(db_path)
    try:
        after = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scan_results", "assets")
        }
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()

    assert after == before, "a public check wrote into a tenant table"
    assert {"public_check_results", "public_check_log", "public_check_optouts",
            "public_check_meta"} <= tables
    assert db is not None


def test_no_public_check_table_carries_an_organization_column(isolated_store):
    _check.init_tables()
    conn = sqlite3.connect(str(isolated_store))
    try:
        for table in ("public_check_results", "public_check_log", "public_check_optouts",
                      "public_check_meta"):
            columns = {row[1].lower() for row in conn.execute(f"PRAGMA table_info({table})")}
            assert not ({"organization_id", "org_id", "tenant_id"} & columns), (
                f"{table} carries a tenant column; results must not live in a workspace")
    finally:
        conn.close()


def test_the_module_imports_nothing_that_reads_a_workspace():
    source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "services", "public_check.py"), encoding="utf-8").read()
    for forbidden in ("from services import tenant_scope", "list_organizations",
                      "current_organization_id", "save_scan_row", "from db import"):
        assert forbidden not in source, f"public_check.py references {forbidden}"


# ── the active check itself (the one function that opens a socket) ───────────


def test_the_handshake_is_pinned_to_the_vetted_address_and_sni_keeps_the_hostname(monkeypatch):
    calls = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, value):
            pass

    class FakeTLS:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def selected_alpn_protocol(self):
            return "h2"

        def getpeercert(self, binary_form=False):
            return None

    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def set_alpn_protocols(self, protocols):
            pass

        def wrap_socket(self, sock, server_hostname=None):
            calls["sni"] = server_hostname
            return FakeTLS()

    def fake_create_connection(address, timeout=None):
        calls["connected_to"] = address
        return FakeSocket()

    monkeypatch.setattr(ssl, "create_default_context", lambda *a, **k: FakeContext())
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    monkeypatch.setattr("scanner._probe_key_exchange_group",
                        lambda host, port, timeout=6.0, address="": {
                            "key_exchange": "x25519", "key_exchange_observed": True,
                            "key_exchange_family": "classical",
                            "key_exchange_observation_method": "tls_client_hello_probe",
                            "key_exchange_unobservable_reason": "", "key_exchange_group_id": 29,
                            "key_exchange_hello_retry": False, "probe_address": address})

    facts = _check.observe_endpoint("example.com", address="93.184.216.34")
    assert calls["connected_to"] == ("93.184.216.34", 443)
    assert calls["sni"] == "example.com", "SNI must still be the hostname, or the server answers wrong"
    assert facts["tls_version"] == "TLSv1.3"
    assert facts["scan_status"] == "no_certificate"


def test_the_key_exchange_probe_is_also_pinned_to_the_checked_address(monkeypatch):
    """scanner._probe_key_exchange_group takes the address, so DNS cannot be re-resolved."""
    import scanner

    seen = {}
    monkeypatch.setattr(socket, "create_connection",
                        lambda address, timeout=None: (_ for _ in ()).throw(OSError("blocked")))

    def record(address, timeout=None):
        seen["address"] = address
        raise OSError("blocked for this test")

    monkeypatch.setattr(socket, "create_connection", record)
    out = scanner._probe_key_exchange_group("example.com", 443, timeout=1.0,
                                            address="93.184.216.34")
    assert seen["address"] == ("93.184.216.34", 443)
    assert out["key_exchange_observed"] is False
    assert "connection failed" in out["key_exchange_unobservable_reason"]


def test_the_checker_never_calls_the_full_internal_scanner():
    """scanner.scan_host enumerates TLS versions and ciphers. That is more contact than allowed."""
    import ast

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "services", "public_check.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(func.attr)
            elif isinstance(func, ast.Name):
                called.add(func.id)
    forbidden = {"scan_host", "run_scan", "_probe_tls_versions", "_probe_tls12_accepted_ciphers",
                 "_probe_revocation_endpoints", "_probe_http_endpoint", "_probe_ocsp_post_endpoint"}
    assert not (called & forbidden), f"the public checker calls {called & forbidden}"
    # The two scanner entry points it is allowed to use, and no others that open a socket.
    assert "_leaf_cert_facts" in called
    assert "_probe_key_exchange_group" in called


def test_a_verification_failure_does_not_trigger_a_second_unverified_handshake(monkeypatch):
    attempts = []

    def fake_create_connection(address, timeout=None):
        attempts.append(address)
        raise ssl.SSLCertVerificationError("certificate has expired")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    facts = _check.observe_endpoint("expired.example.com", address="93.184.216.34")
    assert len(attempts) <= 2, "the public checker must not retry the handshake unverified"
    assert facts["certificate_verified"] is False
    assert facts["scan_status"] != "ok"


# ── exports ──────────────────────────────────────────────────────────────────


def test_the_json_export_is_small_stable_and_keeps_the_sources(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    export = _check.export_json(result)
    assert export["schema"] == "airlock.public-check/1"
    assert export["domain"] == "example.com"
    for key in ("verdict", "observed", "evidence", "limits", "sources", "model_basis", "deadlines"):
        assert key in export
    json.dumps(export)                               # it has to serialise


def test_the_cbom_export_is_a_cyclonedx_document_for_the_one_endpoint(monkeypatch, mocked_check):
    resolves_to(monkeypatch, "93.184.216.34")
    result = _check.run_check("example.com", client_ip="1.1.1.1")
    document = _check.export_cbom(result)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["components"], "the CBOM names no components"
    json.dumps(document)


# ── the HTTP surface ─────────────────────────────────────────────────────────


def test_the_public_pages_and_api_are_served_without_a_login(client):
    response = client.get("/check")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Is your TLS quantum" in response.text

    # The old permalink is a permanent redirect to the record at /r/{domain}, which is where a
    # shared link now resolves; the record itself is covered by test_public_registry.py.
    moved = client.get("/check/example.com", follow_redirects=False)
    assert moved.status_code == 301
    assert moved.headers["location"] == "/r/example.com"

    config = client.get("/api/public-check/config")
    assert config.status_code == 200
    body = config.json()
    assert body["guardrails"]["port"] == 443
    assert body["acceptable_use"]["does_not"]
    assert body["deadlines"]


def test_the_page_makes_no_third_party_request():
    here = os.path.dirname(os.path.abspath(__file__))
    html = open(os.path.join(here, "static", "check.html"), encoding="utf-8").read()
    for attribute in ("src=", "href="):
        for fragment in html.split(attribute)[1:]:
            value = fragment.split(fragment[0])[1] if fragment[0] in "\"'" else fragment.split()[0]
            assert not value.startswith(("http://", "https://", "//")), (
                f"check.html reaches off-origin: {value}")
    js = open(os.path.join(here, "static", "check.js"), encoding="utf-8").read()
    assert "https://" not in js.replace("https://", "", 0) or "fetch(\"https://" not in js
    assert "<script" not in html.split("</head>")[1], "no inline script in the body"


def test_the_page_carries_the_acceptable_use_statement_and_an_abuse_route(client):
    html = client.get("/check").text
    assert "Acceptable use" in html
    assert "Abuse reports and opt" in html
    assert "no cached result" not in html.lower()
    for phrase in ("No port scanning", "No subdomain discovery", "No vulnerability probing"):
        assert phrase in html


def test_a_get_never_starts_a_check(client, monkeypatch):
    """A shared permalink, a crawler or a link preview must not become a connection."""
    import services.public_check as module

    called = []
    monkeypatch.setattr(module, "observe_endpoint",
                        lambda *a, **k: called.append(1) or observation())
    assert client.get("/check/example.com", follow_redirects=False).status_code == 301
    assert client.get("/api/public-check/example.com").status_code == 404
    assert client.get("/api/public-check/example.com/export.json").status_code == 404
    assert client.get("/api/public-check/example.com/cbom.json").status_code == 404
    assert called == [], "a GET reached the network"


def test_the_api_refuses_a_private_target_with_403_and_an_explanation(client, monkeypatch):
    resolves_to(monkeypatch, "127.0.0.1")
    response = client.post("/api/public-check", json={"domain": "internal.example.com"})
    assert response.status_code == 403
    body = response.json()
    assert body["outcome"] == "refused_private"
    assert "public internet" in body["detail"]
    assert body["domain_checked"] is False


@pytest.mark.parametrize("domain,status", [
    ("127.0.0.1", 400),
    ("user:pass@example.com", 400),
    ("*.example.com", 400),
    ("localhost", 400),
    ("example.com:22", 400),
])
def test_the_api_refuses_a_bad_target_without_contacting_anything(client, domain, status):
    response = client.post("/api/public-check", json={"domain": domain})
    assert response.status_code == status
    assert response.json()["domain_checked"] is False


def test_the_api_answers_429_with_a_retry_after_header(client, monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_DOMAIN_LIMIT", "1")
    resolves_to(monkeypatch, "93.184.216.34")
    monkeypatch.setattr(_check, "observe_endpoint",
                        lambda host, address="", timeout=None, deadline=None: observation(
                            host=host, address_checked=address))
    monkeypatch.setattr(_check, "certificate_transparency", lambda domain, deadline=None: dict(CT_OK))

    first = client.post("/api/public-check", json={"domain": "example.com", "refresh": True})
    assert first.status_code == 200
    second = client.post("/api/public-check", json={"domain": "example.com", "refresh": True})
    assert second.status_code == 429
    assert second.headers.get("retry-after")
    assert second.json()["outcome"] == "rate_limited"


def test_a_cached_result_is_served_from_its_permalink_and_exports(client, monkeypatch):
    resolves_to(monkeypatch, "93.184.216.34")
    monkeypatch.setattr(_check, "observe_endpoint",
                        lambda host, address="", timeout=None, deadline=None: observation(
                            host=host, address_checked=address))
    monkeypatch.setattr(_check, "certificate_transparency", lambda domain, deadline=None: dict(CT_OK))

    created = client.post("/api/public-check", json={"domain": "example.com"})
    assert created.status_code == 200
    assert created.json()["permalink"] == "/r/example.com"

    cached = client.get("/api/public-check/example.com")
    assert cached.status_code == 200
    assert cached.json()["cache"]["hit"] is True

    export = client.get("/api/public-check/example.com/export.json")
    assert export.status_code == 200
    assert export.json()["schema"] == "airlock.public-check/1"
    assert "attachment" in export.headers.get("content-disposition", "")

    cbom = client.get("/api/public-check/example.com/cbom.json")
    assert cbom.status_code == 200
    assert cbom.json()["bomFormat"] == "CycloneDX"


def test_the_api_refuses_an_opted_out_domain_on_every_route(client, monkeypatch):
    _check.add_optout("quiet.example.com")
    assert client.post("/api/public-check", json={"domain": "quiet.example.com"}).status_code == 403
    for path in ("/api/public-check/quiet.example.com",
                 "/api/public-check/quiet.example.com/export.json",
                 "/api/public-check/quiet.example.com/cbom.json",
                 # The opt-out covers everything under the domain on every route, not just the name
                 # that was added.
                 "/api/public-check/www.quiet.example.com/export.json"):
        response = client.get(path)
        assert response.status_code == 403, path
        assert response.json()["outcome"] == "refused_optout", path


def test_a_configured_opt_out_refuses_the_exports_even_with_a_result_still_cached(client, monkeypatch, no_network):
    """Adding an opt-out to the table deletes the cached result; the environment list cannot.

    So the exports must consult the opt-out themselves. They used to serve the stale cached result
    as JSON and as a CBOM while the page beside them answered 403.
    """
    _check.store_result("cached.example", _check.build_result("cached.example", observation(), dict(CT_OK)))
    assert client.get("/api/public-check/cached.example/export.json").status_code == 200
    monkeypatch.setenv("PQC_PUBLIC_CHECK_OPTOUT_DOMAINS", "cached.example")
    for path in ("/api/public-check/cached.example",
                 "/api/public-check/cached.example/export.json",
                 "/api/public-check/cached.example/cbom.json"):
        assert client.get(path).status_code == 403, path


def test_the_public_check_paths_are_exempt_from_the_customer_auth_gate(monkeypatch):
    import app as application

    for path in ("/check", "/check/example.com", "/api/public-check",
                 "/api/public-check/config", "/v1/check"):
        assert application._auth_public_path(path) is True, path
    # The operator surface is not public.
    assert application._auth_public_path("/platform/public-check/log") is False
    assert application._auth_public_path("/platform/public-check/opt-outs") is False


def test_the_public_check_is_exempt_from_the_per_organization_limiter():
    """It has no organization, so an org budget would be charged to the wrong tenant."""
    import app as application
    from services import org_rate_limits

    for path in ("/check", "/api/public-check", "/api/public-check/example.com"):
        assert org_rate_limits.is_exempt(path, is_public=application._auth_public_path) is True


def test_the_public_pages_still_answer_with_production_auth_required(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as authed:
        assert authed.get("/check").status_code == 200
        assert authed.get("/check/example.com", follow_redirects=False).status_code == 301
        assert authed.get("/api/public-check/config").status_code == 200


def test_the_check_page_runs_under_the_strict_content_security_policy():
    import app as application

    policy = application._csp_for("/check")
    assert "script-src 'self'" in policy
    assert "script-src 'self' 'unsafe-inline'" not in policy
    assert "default-src 'self'" in policy


def test_the_operator_log_and_opt_out_routes_need_a_platform_key(client):
    """The check log names every domain that was checked, so it is never public.

    503 is the answer when no platform key is configured at all (the guard says what to set);
    401/403 when one is configured and the caller has not presented it. Never 200.
    """
    for path in ("/platform/public-check/log", "/platform/public-check/opt-outs"):
        response = client.get(path)
        assert response.status_code in {401, 403, 503}, path
        assert response.status_code != 200


def test_an_operator_can_add_and_remove_an_opt_out(client, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "_PLATFORM_ADMIN_KEY", "opt-out-test-key")
    headers = {"x-platform-key": "opt-out-test-key", "x-platform-admin-role": "owner"}

    added = client.post("/platform/public-check/opt-outs",
                        json={"domain": "quiet.example.com", "reason": "owner asked"},
                        headers=headers)
    assert added.status_code == 200
    assert added.json()["opted_out"] is True

    listed = client.get("/platform/public-check/opt-outs", headers=headers)
    assert listed.status_code == 200
    assert "quiet.example.com" in {row["domain"] for row in listed.json()["opt_outs"]}

    assert client.post("/api/public-check", json={"domain": "quiet.example.com"}).status_code == 403

    removed = client.request("DELETE", "/platform/public-check/opt-outs/quiet.example.com",
                             headers=headers)
    assert removed.status_code == 200
    assert removed.json()["opted_out"] is False


def test_the_disabled_switch_turns_the_checker_off_without_breaking_the_page(
        client, monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_CHECK_ENABLED", "0")
    assert client.get("/check").status_code == 200
    config = client.get("/api/public-check/config").json()
    assert config["guardrails"]["enabled"] is False
    response = client.post("/api/public-check", json={"domain": "example.com"})
    assert response.status_code == 503
    assert response.json()["outcome"] == "disabled"


# ── the CLI ──────────────────────────────────────────────────────────────────


def _cli():
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scripts", "pqc-check.py")
    spec = importlib.util.spec_from_file_location("pqc_check_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_cli_prints_the_same_verdict_and_exits_zero(monkeypatch, mocked_check, capsys):
    resolves_to(monkeypatch, "93.184.216.34")
    assert _cli().main(["example.com"]) == 0
    printed = capsys.readouterr().out
    assert "Quantum-vulnerable today" in printed
    assert "RSA-2048" in printed
    assert "Harvest now, decrypt later (modelled, not measured)" in printed
    assert "What this check does not tell you" in printed


def test_the_cli_reports_an_unreachable_host_as_a_failure(monkeypatch, mocked_check, capsys):
    resolves_to(monkeypatch, "93.184.216.34")
    mocked_check["observation"] = observation(
        scan_status="timeout", error_code="TIMEOUT", error="timed out",
        tls_version="", cipher_name="", key_type="", key_bits=0, sig_algorithm="",
        subject="", issuer="", key_exchange="", key_exchange_observed=False,
        key_exchange_family="", tls_supported_versions=[], certificate_verified=False)
    assert _cli().main(["down.example.com"]) == 1
    assert "Not checked" in capsys.readouterr().out


def test_the_cli_refuses_the_same_targets_the_web_route_refuses(monkeypatch, capsys):
    cli = _cli()
    for target in ("127.0.0.1", "localhost", "*.example.com", "user:pass@example.com"):
        assert cli.main([target]) == 2, target
    resolves_to(monkeypatch, "10.0.0.1")
    assert cli.main(["internal.example.com"]) == 2
    assert "refused_private" in capsys.readouterr().err


def test_the_cli_emits_json_and_a_cbom(monkeypatch, mocked_check, capsys):
    resolves_to(monkeypatch, "93.184.216.34")
    cli = _cli()
    assert cli.main(["example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == "example.com"
    assert payload["model_basis"]["kind"] == "model"

    assert cli.main(["example.com", "--cbom"]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def test_the_cli_can_manage_the_opt_out_list(monkeypatch, capsys):
    cli = _cli()
    assert cli.main(["--opt-out", "quiet.example.com"]) == 0
    capsys.readouterr()
    assert cli.main(["--list-opt-outs"]) == 0
    assert "quiet.example.com" in capsys.readouterr().out
    assert _check.opted_out("www.quiet.example.com") == "quiet.example.com"


def test_the_cli_prints_the_guardrails(capsys):
    assert _cli().main(["--settings"]) == 0
    settings = json.loads(capsys.readouterr().out)
    assert settings["port"] == 443
    assert settings["checks_per_domain_per_hour"] >= 1


# ── defaults ─────────────────────────────────────────────────────────────────


def test_the_shipped_defaults_are_the_documented_ones(monkeypatch):
    for name in ("PQC_PUBLIC_CHECK_CACHE_SECONDS", "PQC_PUBLIC_CHECK_IP_LIMIT",
                 "PQC_PUBLIC_CHECK_IP_BURST", "PQC_PUBLIC_CHECK_DOMAIN_LIMIT",
                 "PQC_PUBLIC_CHECK_GLOBAL_LIMIT", "PQC_PUBLIC_CHECK_CONCURRENCY",
                 "PQC_PUBLIC_CHECK_MAX_QUEUE", "PQC_PUBLIC_CHECK_QUEUE_WAIT_SECONDS",
                 "PQC_PUBLIC_CHECK_DEADLINE_SECONDS", "PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    assert _check.cache_seconds() == 3600
    assert _check.ip_limit() == 10
    assert _check.ip_burst() == 3
    assert _check.domain_limit() == 4
    assert _check.global_limit() == 240
    assert _check.concurrency() == 4
    assert _check.max_queue() == 32
    assert _check.queue_wait_seconds() == 5.0
    assert _check.deadline_seconds() == 15.0
    assert _check.ct_min_interval_seconds() == 5.0


def test_the_cache_window_cannot_be_set_below_ten_minutes(monkeypatch):
    """Serving the cache is what stops one visitor per check reaching the target."""
    monkeypatch.setenv("PQC_PUBLIC_CHECK_CACHE_SECONDS", "1")
    assert _check.cache_seconds() == 600
