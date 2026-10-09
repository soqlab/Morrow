"""The permanent public record at /r/{domain}: the ledger, the page and the badge.

Same conventions as test_public_checker.py: nothing here contacts a third-party host. A result is
built by hand or from a local fixture and written straight into the registry, because what is under
test is the record, not the scanner that fills it.
"""

from __future__ import annotations

import json
import re
import xml.dom.minidom
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def registry(tmp_path, monkeypatch):
    """A fresh feature store per test, so one test's records cannot be another's.

    Same shape as test_public_checker.isolated_store: the feature store is the SQLite file named
    by PQC_SCANNER_DB, and _TABLES_READY is keyed by database, so it has to be cleared when the
    file changes or init_tables() believes it has already run.
    """
    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "registry.db"))
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_ENABLED", "1")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("PQC_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("PQC_LLM_DISABLED", "1")
    from services import public_check

    public_check._TABLES_READY.clear()
    public_check.init_tables()
    yield public_check
    public_check._TABLES_READY.clear()


def _result(domain: str = "example.test", *, status: str = "quantum_vulnerable",
            key_type: str = "RSA", key_bits: int = 2048, tls: str = "TLSv1.3",
            reachable: bool = True, checked_at: str = "2026-10-01T10:00:00Z") -> Dict[str, Any]:
    """A result payload shaped like build_result's, with only the fields the record reads."""
    return {
        "domain": domain,
        "checked_at": checked_at,
        "outcome": "ok" if reachable else "failed",
        "verdict": {
            "status": status,
            "headline": "Quantum-vulnerable today" if reachable else "Not checked",
            "explanation": "Everything this endpoint negotiated is breakable by a quantum computer."
                           if reachable else "Nothing was measured here.",
        },
        "observed": {
            "reachable": reachable,
            "scan_status": "ok" if reachable else "timeout",
            "error": "" if reachable else "the host did not answer in time",
            "error_code": "" if reachable else "timeout",
            "port": 443,
            "tls_version": tls if reachable else "",
            "cipher_name": "TLS_AES_256_GCM_SHA384" if reachable else "",
            "key_exchange": "X25519" if reachable else "",
            "key_exchange_family": "classical" if reachable else "",
            "key_exchange_observed": reachable,
            "certificate": {
                "subject": f"CN={domain}",
                "issuer": "CN=Test CA",
                "not_after": "2027-01-01T00:00:00Z",
                "key_type": key_type if reachable else "",
                "key_bits": key_bits if reachable else 0,
                "key_curve": "",
                "sig_algorithm": "sha256WithRSAEncryption" if reachable else "",
            },
            "connections_made": 2,
        },
        "algorithms": [
            {"algorithm": f"{key_type}-{key_bits}", "status": "quantum_vulnerable",
             "risk": "critical", "action": "Migrate to ML-DSA-65", "standards": [],
             "details": "Shor's algorithm breaks RSA in polynomial time",
             "observed_as": key_type, "resolved_as": f"{key_type}-{key_bits}",
             "role": "certificate key"},
        ],
        "harvest_now_decrypt_later": {
            "algorithm_class": "classical", "risk_tier": "high",
            "break_probability_by_q_day": 0.5, "q_day_year_used": 2032,
            "q_day_year_source": "model", "rationale": "Recorded traffic can be decrypted later.",
        },
        "certificate_transparency": {"status": "skipped", "provider": "none"},
        "deadlines": [],
        "limits": ["One endpoint, one moment, public data only."],
        "what_a_full_assessment_adds": ["Every endpoint you operate, not one."],
    }


# ── The ledger ───────────────────────────────────────────────────────────────


def test_record_survives_the_cache_expiring(registry, monkeypatch):
    """The bug this whole feature exists to fix: a shared link must not rot with the cache."""
    result = _result()
    registry.store_result("example.test", result)

    assert registry.cached_result("example.test") is not None, "cached straight after the check"

    # Expire the cache the way time would, without waiting an hour.
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE public_check_results SET expires_at = ?", ("2000-01-01T00:00:00Z",))
        conn.commit()

    assert registry.cached_result("example.test") is None, "cache has expired"
    entry = registry.registry_entry("example.test")
    assert entry is not None, "the permanent record outlives the cache"
    assert entry["posture"] == registry.POSTURE_CLASSICAL
    assert entry["result"]["verdict"]["headline"] == "Quantum-vulnerable today"


def test_unchanged_endpoint_extends_instead_of_appending(registry):
    first = _result(checked_at="2026-10-01T10:00:00Z")
    registry.store_result("example.test", first)
    again = _result(checked_at="2026-10-02T10:00:00Z")
    registry.store_result("example.test", again)

    history = registry.registry_history("example.test")
    assert len(history) == 1, "identical cryptography is one observation, not two"
    assert registry.registry_entry("example.test")["observations"] == 1

    # A real change appends exactly one row.
    changed = _result(key_type="ECDSA", key_bits=256, checked_at="2026-10-03T10:00:00Z")
    registry.store_result("example.test", changed)
    history = registry.registry_history("example.test")
    assert len(history) == 2, "changed cryptography appends one row"
    assert registry.registry_entry("example.test")["observations"] == 2
    assert history[0]["observed_at"] >= history[1]["observed_at"], "newest first"


def test_certificate_renewal_is_not_a_change(registry):
    """A renewal with the same algorithm must not append a row, or every domain grows one
    observation per renewal and the history becomes noise."""
    first = _result()
    registry.store_result("example.test", first)
    renewed = _result()
    renewed["observed"]["certificate"]["not_after"] = "2028-06-01T00:00:00Z"
    renewed["checked_at"] = "2026-12-01T10:00:00Z"
    registry.store_result("example.test", renewed)
    assert len(registry.registry_history("example.test")) == 1


def test_a_failed_check_is_recorded_and_is_not_called_clean(registry):
    registry.store_result("down.test", _result("down.test", status="not_assessed", reachable=False))
    entry = registry.registry_entry("down.test")
    assert entry["posture"] == registry.POSTURE_UNREACHABLE
    assert entry["posture"] != registry.POSTURE_PQC_READY
    meaning = registry.POSTURE_MEANING[registry.POSTURE_UNREACHABLE]
    assert "not a clean result" in meaning


def test_posture_ladder_covers_every_verdict_status(registry):
    """Any status the checker can produce has a posture, and an unknown one never reads as ready."""
    for status in ("post_quantum", "hybrid_key_exchange", "quantum_vulnerable", "not_assessed",
                   "inconclusive"):
        assert registry.posture_of({"verdict": {"status": status}}) in registry.POSTURE_MEANING
    assert registry.posture_of({"verdict": {"status": "something_new"}}) == registry.POSTURE_UNKNOWN
    assert registry.posture_of({}) == registry.POSTURE_UNKNOWN


# ── Opt-out ──────────────────────────────────────────────────────────────────


def test_optout_hides_the_record_and_its_subdomains(registry):
    registry.store_result("example.test", _result("example.test"))
    registry.store_result("api.example.test", _result("api.example.test"))
    assert registry.registry_entry("example.test") is not None
    assert registry.registry_entry("api.example.test") is not None

    registry.add_optout("example.test", reason="owner asked")

    assert registry.registry_entry("example.test") is None
    assert registry.registry_entry("api.example.test") is None, "subdomains are covered too"
    assert registry.registry_history("example.test") == []

    # Hidden, not deleted: the evidence of what we saw is what answers an abuse complaint.
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        kept = conn.execute("SELECT COUNT(*) AS n FROM public_check_observations").fetchone()
    assert int(kept["n"]) == 2

    registry.remove_optout("example.test")
    assert registry.registry_entry("example.test") is not None, "an operator can restore it"


# ── The badge ────────────────────────────────────────────────────────────────


def test_badge_is_valid_svg_and_scales_with_its_label(registry):
    from services import registry_page

    widths = {}
    for posture in (registry.POSTURE_PQC_READY, registry.POSTURE_CLASSICAL,
                    registry.POSTURE_UNREACHABLE, None):
        svg = registry_page.badge_svg(posture)
        xml.dom.minidom.parseString(svg)  # raises if malformed
        widths[posture] = int(re.search(r'width="(\d+)"', svg).group(1))
    assert widths[registry.POSTURE_UNREACHABLE] > widths[registry.POSTURE_PQC_READY], \
        "a longer word needs a wider badge or the text clips"
    assert registry_page.badge_size(registry.POSTURE_CLASSICAL)[0] == \
        widths[registry.POSTURE_CLASSICAL], "the declared size matches the drawing"


def test_badge_for_an_optout_is_identical_to_a_never_checked_one(registry):
    from services import registry_page

    assert registry_page.badge_svg(None) == registry_page.badge_svg("not_a_posture"), \
        "an unrecognised posture is the neutral badge, never a pass"


# ── The routes ───────────────────────────────────────────────────────────────


@pytest.fixture()
def client(registry, monkeypatch):
    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://airlock.test")
    import app as app_module

    return TestClient(app_module.app, raise_server_exceptions=False)


def test_record_page_is_complete_without_javascript(client, registry):
    registry.store_result("example.test", _result("example.test"))
    response = client.get("/r/example.test")
    assert response.status_code == 200
    body = response.text

    # The verdict is in the first response, not fetched by a script. This is what a crawler and a
    # link unfurler see, and the reason the page is rendered on the server at all.
    assert "Quantum-vulnerable today" in body
    assert "breakable by a quantum computer" in body
    assert "RSA-2048" in body
    assert '<link rel="canonical" href="https://airlock.test/r/example.test">' in body
    assert 'property="og:title"' in body
    assert "application/ld+json" in body

    # Strict CSP applies to /r/, so nothing may be inline except the JSON-LD data block in head.
    assert response.headers["content-security-policy"].count("script-src 'self'") == 1
    assert "unsafe-inline" not in response.headers["content-security-policy"].split("style-src")[0]
    head, _, rest = body.partition("</head>")
    assert "<script" not in rest, "no inline script in the body"
    assert "onclick" not in body and "onload" not in body
    assert "style=" not in body, "no inline style attribute under a strict CSP"


def test_record_page_etag_round_trip(client, registry):
    registry.store_result("example.test", _result("example.test"))
    first = client.get("/r/example.test")
    etag = first.headers["etag"]
    assert "stale-while-revalidate" in first.headers["cache-control"]

    again = client.get("/r/example.test", headers={"If-None-Match": etag})
    assert again.status_code == 304, "an unchanged record is a 304, which is what makes it cheap"


def test_etag_changes_when_the_page_does_even_if_the_crypto_does_not(client, registry):
    """Re-checking an unchanged endpoint moves "last confirmed", and the visitor has to see it.

    An ETag built from the cryptography alone would answer 304 here and show a stale date.
    """
    registry.store_result("example.test", _result("example.test"))
    first = client.get("/r/example.test")
    assert "Last confirmed" in first.text

    import time
    time.sleep(1.1)  # the stored timestamps are whole seconds
    registry.store_result("example.test", _result("example.test"))

    again = client.get("/r/example.test", headers={"If-None-Match": first.headers["etag"]})
    assert again.status_code == 200, "a moved confirmation date is a new page, not a 304"
    assert again.headers["etag"] != first.headers["etag"]

    # And still exactly one observation: the ETag moved, the history did not.
    assert len(registry.registry_history("example.test")) == 1


def test_domain_is_canonicalised_with_one_redirect(client, registry):
    registry.store_result("example.test", _result("example.test"))
    response = client.get("/r/Example.TEST", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/r/example.test"


def test_old_permalink_redirects_to_the_record(client, registry):
    registry.store_result("example.test", _result("example.test"))
    response = client.get("/check/example.test", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/r/example.test"


def test_unknown_domain_is_404_and_noindex(client):
    response = client.get("/r/never-checked.test")
    assert response.status_code == 404
    # /r/{anything} is unbounded crawl space; a 200 here would invite a crawler to mine it.
    assert 'name="robots" content="noindex' in response.text
    assert "no record for this domain" in response.text.lower()
    # And as a header, which is the signal a client can check without parsing HTML -- the launch
    # script could not verify the meta tag at all, because PowerShell strips tags out of an error
    # response body.
    assert "noindex" in response.headers.get("x-robots-tag", "")


def test_every_non_indexable_registry_response_says_so_in_a_header(client, registry):
    """The current record of a real observation is the only /r page that should be indexed."""
    registry.store_result("example.test", _result("example.test"))
    registry.store_result("example.test", _result("example.test", key_type="ECDSA", key_bits=256,
                                                  checked_at="2026-10-06T10:00:00Z"))
    oldest = registry.registry_history("example.test")[-1]["observation_id"]

    indexable = client.get("/r/example.test")
    assert indexable.status_code == 200
    assert "x-robots-tag" not in {k.lower() for k in indexable.headers},         "the current record is the page that should be indexed"

    past = client.get(f"/r/example.test/at/{oldest}")
    assert past.status_code == 200
    assert "noindex" in past.headers.get("x-robots-tag", ""),         "a past observation competing with the current record splits its ranking"

    registry.add_optout("example.test")
    refused = client.get("/r/example.test")
    assert refused.status_code == 403
    assert "noindex" in refused.headers.get("x-robots-tag", "")


def test_badge_route_never_starts_a_check(client, registry, monkeypatch):
    """A README is viewed thousands of times. None of those views may touch the endpoint."""
    from services import public_check

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the badge route tried to contact the endpoint")

    monkeypatch.setattr(public_check, "observe_endpoint", explode)
    monkeypatch.setattr(public_check, "resolve_public_address", explode)
    monkeypatch.setattr(public_check, "certificate_transparency", explode)

    registry.store_result("example.test", _result("example.test"))
    response = client.get("/r/example.test/badge.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "classical" in response.text
    assert "vary" not in {k.lower() for k in response.headers}, \
        "a proxied README image must not vary per viewer"

    # A domain with no record at all answers the same way, without contacting anything.
    neutral = client.get("/r/never-checked.test/badge.svg")
    assert neutral.status_code == 200
    assert "unknown" in neutral.text


def test_badge_for_an_optout_leaks_nothing(client, registry):
    registry.store_result("example.test", _result("example.test"))
    registry.add_optout("example.test")

    opted_out = client.get("/r/example.test/badge.svg")
    never_checked = client.get("/r/never-checked.test/badge.svg")
    assert opted_out.status_code == 200, "a 403 would break the README it is embedded in"
    assert opted_out.text == never_checked.text, \
        "the badge must not reveal that this domain asked to be left out"


def test_record_page_refuses_an_optout_in_the_promised_wording(client, registry):
    registry.store_result("example.test", _result("example.test"))
    registry.add_optout("example.test")
    response = client.get("/r/example.test")
    # /abuse promises a refusal saying the domain asked not to be checked and that nothing was
    # contacted. The API already answers that way; the page says the same thing.
    assert response.status_code == 403
    assert "asked not to be checked" in response.text
    assert "no connection was made" in response.text


def test_exports_are_served_from_the_record_not_the_cache(client, registry):
    registry.store_result("example.test", _result("example.test"))
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("DELETE FROM public_check_results")
        conn.commit()

    for path, key in (("/r/example.test/export.json", "domain"),
                      ("/r/example.test/cbom.json", "bomFormat")):
        response = client.get(path)
        assert response.status_code == 200, path
        payload = response.json()
        assert key in json.dumps(payload) or key in payload, path
    assert client.get("/r/never-checked.test/export.json").status_code == 404


def test_historical_observation_has_its_own_citable_page(client, registry):
    registry.store_result("example.test", _result("example.test"))
    registry.store_result("example.test", _result("example.test", key_type="ECDSA", key_bits=256,
                                                  checked_at="2026-10-05T10:00:00Z"))
    history = registry.registry_history("example.test")
    assert len(history) == 2
    oldest = history[-1]["observation_id"]

    response = client.get(f"/r/example.test/at/{oldest}")
    assert response.status_code == 200
    assert "past observation" in response.text
    assert 'name="robots" content="noindex' in response.text, \
        "only the current record should be indexed, or one domain competes with itself"
    assert client.get("/r/example.test/at/999999").status_code == 404


def test_registry_is_reachable_without_authentication(client, registry, monkeypatch):
    """A record is read by strangers and crawlers; it must answer with no account."""
    import app as app_module

    assert app_module._auth_public_path("/r/example.test")
    assert app_module._auth_public_path("/r/example.test/badge.svg")
    # The segment-aware check must not hand these away as public.
    assert not app_module._auth_public_path("/repositories")
    assert not app_module._auth_public_path("/remediations")


def test_robots_allows_the_registry_and_its_stylesheet(client):
    body = client.get("/robots.txt").text
    assert "Allow: /r/" in body
    # A crawler that cannot fetch the stylesheet renders the record unstyled and judges it so.
    assert "Allow: /ui/*.css" in body


def test_strict_csp_covers_the_registry_but_not_lookalike_paths():
    import app as app_module

    assert app_module._csp_for("/r/example.test") == app_module._CSP_STRICT_VALUE
    for path in ("/robots.txt", "/repositories", "/remediations"):
        assert app_module._csp_for(path) != app_module._CSP_STRICT_VALUE, path
