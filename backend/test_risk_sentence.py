"""Your quantum risk in one sentence (services/risk_sentence.py): the sentence across every case, the
public grade's settings count, and the endpoint. No network."""

import os
from datetime import datetime, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import decrypt_window as dw
from services import public_grade
from services import risk_sentence as rs
from services import shelf_life as sl

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
LOW, LIKELY = dw.CRQC_ESTIMATE["low"], dw.CRQC_ESTIMATE["likely"]


@pytest.fixture(autouse=True)
def fresh():
    sl.reset_cache()
    yield
    sl.reset_cache()


# ── the sentence ─────────────────────────────────────────────────────────────


def test_at_risk_names_the_assumed_data_the_about_year_the_range_the_deadline_and_the_fix():
    out = rs.build("api.example.com", "at_risk", 2, now=NOW)
    # personal data, EU (no country TLD): 10 to 70 years; the clock uses the conservative 70.
    assert out["sentence"] == (
        f"Your personal data sent to api.example.com today could be read from about {LOW} "
        f"(expert estimates: {LOW} to {LIKELY}), but it needs to stay private until 2096. "
        "Fix 2 settings and traffic from then on can't be read with a quantum computer.")
    assert out["readable_from"] == LOW and out["secret_until"] == 2096 and out["exposed"] is True
    assert out["data"]["assumed"] is True and out["data"]["category"] == "personal-data-general"
    assert out["data"]["jurisdiction"] == "EU" and out["data"]["jurisdiction_assumed"] is True
    assert out["assumption"].startswith("Assumes personal data under EU law: Shelf-Life v0.1 says 10 to 70 years")
    assert "Pick the kind of data" in out["assumption"]
    assert out["estimate"]["is_estimate"] is True and out["estimate"]["source_url"] == dw.EXPOSURE_SOURCE_URL
    assert {c["id"] for c in out["choices"]["categories"]} >= {"health-records", "personal-data-general"}
    assert all(j["code"] != "INT" for j in out["choices"]["jurisdictions"])


def test_the_same_numbers_as_the_harvest_clock():
    out = rs.build("api.example.com", "at_risk", 1, data="health", jurisdiction="GB", now=NOW)
    clock = dw.harvest(True, False, 100, crqc_year=LOW, now=NOW)
    assert out["secret_until"] == clock["secret_until"] == 2126
    assert out["exposed"] == clock["exposed"]


def test_a_chosen_kind_of_data_is_not_called_an_assumption_and_plural_labels_agree():
    out = rs.build("clinic.example.co.uk", "at_risk", 1, data="health", now=NOW)
    assert out["data"]["assumed"] is False and out["data"]["jurisdiction"] == "GB"  # from the .uk TLD
    assert "Your health records sent to clinic.example.co.uk today" in out["sentence"]
    assert "but they need to stay private until 2126." in out["sentence"]
    assert "Fix 1 setting and" in out["sentence"]
    assert out["assumption"].startswith("For health records under UK law")
    assert "Pick the kind" not in out["assumption"]


def test_the_tld_sets_the_law_unless_one_is_chosen():
    assert rs.build("shop.example.de", "at_risk", 1, now=NOW)["data"]["jurisdiction"] == "DE"
    chosen = rs.build("shop.example.de", "at_risk", 1, jurisdiction="us", now=NOW)
    assert chosen["data"]["jurisdiction"] == "US" and chosen["data"]["jurisdiction_assumed"] is False


def test_an_unknown_kind_of_data_falls_back_to_the_assumption():
    out = rs.build("a.example", "at_risk", 1, data="nonsense", now=NOW)
    assert out["data"]["assumed"] is True and out["data"]["category"] == "personal-data-general"


def test_a_safe_host_says_so_instead():
    out = rs.build("good.example", "safe", 0, now=NOW)
    assert out["sentence"] == ("Your personal data on good.example is already quantum-safe: traffic recorded today can't be "
                               "read later with a quantum computer.")
    assert out["readable_from"] is None and out["exposed"] is False
    housekeeping = rs.build("good.example", "safe", 1, data="health", now=NOW)["sentence"]
    assert "Your health records on good.example are already quantum-safe" in housekeeping
    assert housekeeping.endswith("1 setting still needs attention, but none of them change that.")


def test_data_that_expires_before_the_estimate_is_not_called_exposed():
    # In 2010, passwords and keys (at most 20 years) had to last until 2030: before the earliest estimate.
    out = rs.build("old.example", "at_risk", 1, data="auth", now=datetime(2010, 1, 1, tzinfo=timezone.utc))
    assert out["exposed"] is False
    assert f"could be read from about {LOW}" in out["sentence"]
    assert "after they need to stay private (until 2030)." in out["sentence"]


def test_no_encryption_is_readable_today():
    out = rs.build("plain.example", "no_tls", 0, now=NOW)
    assert out["sentence"].startswith("Your personal data sent to plain.example is not encrypted at all: anyone on the path can read it today.")
    assert out["sentence"].endswith("Turn on HTTPS first; Morrow then shows the exact settings.")
    assert out["readable_from"] == 2026
    assert "Fix 3 settings to encrypt it." in rs.build("plain.example", "no_tls", 3, now=NOW)["sentence"]


def test_an_unreached_host_makes_no_claim():
    out = rs.build("down.example", "unknown", 4, now=NOW)
    assert out["sentence"].startswith("Morrow could not read down.example's encryption, so it can't say when")
    assert "Fix" not in out["sentence"] and out["exposed"] is None and out["readable_from"] is None


def test_unobserved_key_exchange_says_it_assumes_the_worst():
    out = rs.build("hidden.example", "at_risk", 1, observed=False, now=NOW)
    assert out["sentence"].endswith("Morrow couldn't see the key exchange, so it assumes a classical one.")


def test_no_fixable_setting_says_so_honestly():
    assert rs.build("cdn.example", "at_risk", 0, now=NOW)["sentence"].endswith(
        "No server setting Morrow knows of fixes this yet; it depends on your provider.")


def test_other_endpoints_are_counted():
    assert "sent to a.example and 3 other endpoints today" in rs.build("a.example", "at_risk", 1, others=3, now=NOW)["sentence"]
    assert "a.example and 1 other endpoint today" in rs.build("a.example", "at_risk", 1, others=1, now=NOW)["sentence"]


def test_without_the_catalogue_the_sentence_still_stands(monkeypatch, tmp_path):
    monkeypatch.setattr(sl, "DATA_DIR", str(tmp_path))
    sl.reset_cache()
    out = rs.build("api.example.com", "at_risk", 2, now=NOW)
    assert out["data"] is None and out["secret_until"] is None
    assert out["sentence"].startswith(f"Data sent to api.example.com today could be read from about {LOW} (expert estimates")
    assert "Fix 2 settings" in out["sentence"] and "Shelf-Life catalogue" in out["assumption"]


def test_hosts_are_quoted_only_when_they_look_like_hosts():
    assert rs.clean_host("API.Example.com.") == "api.example.com"
    assert rs.clean_host("10.0.0.1:8443") == "10.0.0.1:8443"
    assert rs.clean_host("your bank was hacked") is None
    assert rs.clean_host("<script>") is None
    assert rs.build("<b>", "at_risk", 1, now=NOW)["host"] == "this host"


# ── from a public grade ──────────────────────────────────────────────────────


def _facts(**over):
    facts = {"domain": "shop.example", "tls": True, "tls_versions": {"1.2": True, "1.3": True},
             "negotiated_version": "TLSv1.3", "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
             "kx_family": "classical", "kx_group": "x25519", "kx_observed": True, "certificate_verified": True,
             "certificate": {"days_until_expiry": 200, "key_type": "EC"}}
    facts.update(over)
    return facts


def test_the_grade_counts_the_settings_its_fixes_change():
    c = public_grade.grade_from_facts(_facts())
    assert c["grade"] == "C" and c["settings_to_fix"] == ["pq"] and rs.settings_to_fix(c) == 1
    e = public_grade.grade_from_facts(_facts(tls_versions={"1.0": True, "1.2": True, "1.3": True},
                                             weak_ciphers_accepted=["DES-CBC3-SHA"]))
    assert e["settings_to_fix"] == ["pq", "protocols", "ciphers"]
    a = public_grade.grade_from_facts(_facts(kx_family="pq_hybrid", kx_group="X25519MLKEM768"))
    assert a["grade"] == "A" and a["settings_to_fix"] == []


def test_a_stored_result_without_the_count_is_derived():
    c = public_grade.grade_from_facts(_facts(tls_versions={"1.1": True, "1.2": True, "1.3": True}))
    c.pop("settings_to_fix")
    assert rs.settings_to_fix(c) == 2


def test_for_grade_reads_the_exposure_block():
    c = public_grade.build_result(_facts(), "2026-11-15T00:00:00Z")
    out = rs.for_grade(c, now=NOW)
    assert out["state"] == "at_risk" and out["fixable"] == 1 and out["host"] == "shop.example"
    a = public_grade.build_result(_facts(kx_family="pq_hybrid", kx_group="X25519MLKEM768"), "2026-11-15T00:00:00Z")
    assert rs.for_grade(a, now=NOW)["state"] == "safe"
    f = public_grade.build_result(_facts(tls=False), "2026-11-15T00:00:00Z")
    assert rs.for_grade(f, now=NOW)["state"] == "no_tls"


# ── the endpoint ─────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "risk.db"))
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_endpoint(client):
    r = client.get("/api/public/risk-sentence?host=api.example.com&state=at_risk&fixable=2&data=health&jur=GB")
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=3600"
    body = r.json()
    assert body["data"]["category"] == "health-records" and body["fixable"] == 2
    assert "Your health records sent to api.example.com" in body["sentence"]
    assert client.get("/api/public/risk-sentence?host=a.example&state=at_risk&observed=0").json()["sentence"].endswith(
        "assumes a classical one.")
    assert client.get("/api/public/risk-sentence?host=a%20b&state=at_risk").status_code == 400
    assert client.get("/api/public/risk-sentence?host=a.example&state=nope").status_code == 400


def test_endpoint_is_anonymous(monkeypatch, tmp_path):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "risk.db"))
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/risk-sentence?host=a.example&state=safe").status_code == 200
