"""The scan's verdict must survive the trip to every report that quotes it.

test_scanner_accuracy.py pins what a scan of a known certificate reports. This file pins what the
reporting layer then does with it. Every test here is a regression for a bug found by scanning a
matrix of purpose-built TLS servers and following each field through the product: the classification
was correct at the scanner and wrong by the time it reached the customer.

The shared failure mode is that a field the scan never produced -- or a value the lookup table did
not know -- silently became a *safe* answer:

  * "EC" was missing from the migration-velocity vulnerable list, so every elliptic-curve asset was
    counted as already migrated.
  * x25519 and ed25519 were on the compliance export's "quantum-safe" list, so Ed25519 endpoints were
    exported to auditors as compliant.
  * generate_cbom read cert_* keys the scanner does not emit, so exported CBOMs held no certificate,
    no public key and no signature algorithm at all.
  * The trust passport counted high-risk rows out of the `scans` table, which has no risk_level
    column, so every estate scored 90 "monitored" however many critical endpoints it had.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

import pytest

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")

from services.cbom import generate_cbom
from services.migration_velocity import build_velocity_report


# ── Migration velocity ────────────────────────────────────────────────────────

def _velocity(algorithms):
    scans = [
        {"host": f"h{i}.example", "port": 443, "algorithm": a, "scan_time": "2026-01-01T00:00:00Z"}
        for i, a in enumerate(algorithms)
    ]
    return build_velocity_report(scans=scans, remediations=[])["snapshot"]


def test_ec_assets_are_not_counted_as_migrated():
    """Regression: scan_results stores the bare "EC" for every elliptic-curve certificate.

    The vulnerable-algorithm list held ECDSA, ECDH, P-256 and friends but not "EC", and the report
    had only two buckets, so each of those assets landed in "quantum safe" and inflated the
    migration progress percentage.
    """
    snapshot = _velocity(["EC", "EC", "EC", "RSA"])

    assert snapshot["quantum_vulnerable_assets"] == 4, snapshot
    assert snapshot["quantum_safe_assets"] == 0, snapshot
    assert snapshot["progress_pct"] == 0.0, snapshot


@pytest.mark.parametrize("algorithm", ["EC", "ECC", "Ed25519", "Ed448", "X25519", "DSA", "RSA"])
def test_every_classical_key_type_counts_as_vulnerable(algorithm):
    snapshot = _velocity([algorithm])
    assert snapshot["quantum_vulnerable_assets"] == 1, (algorithm, snapshot)
    assert snapshot["quantum_safe_assets"] == 0, (algorithm, snapshot)


def test_unobserved_algorithm_is_unknown_not_migrated():
    """A blank algorithm means the scan failed. That is not evidence of a completed migration."""
    snapshot = _velocity(["", "", "RSA"])

    assert snapshot["quantum_vulnerable_assets"] == 1, snapshot
    assert snapshot["quantum_unknown_assets"] == 2, snapshot
    assert snapshot["quantum_safe_assets"] == 0, snapshot


def test_pq_algorithms_are_the_only_thing_that_counts_as_migrated():
    snapshot = _velocity(["ML-KEM-768", "ML-DSA-65", "RSA"])

    assert snapshot["quantum_safe_assets"] == 2, snapshot
    assert snapshot["quantum_vulnerable_assets"] == 1, snapshot


# ── CBOM export ───────────────────────────────────────────────────────────────

def _scanner_shaped_result(**overrides):
    """A result in the shape scanner.scan_host() actually returns."""
    base = {
        "host": "api.example", "port": 443,
        "tls_version": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384",
        "subject": "CN=api.example", "issuer": "CN=Example CA",
        "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2027-01-01T00:00:00+00:00",
        "key_type": "RSA", "key_bits": 4096, "key_curve": "",
        "sig_algorithm": "sha256WithRSAEncryption",
        "error": "",
    }
    base.update(overrides)
    return base


def _crypto_components(cbom, asset_type):
    return [
        c for c in cbom.get("components", [])
        if c.get("cryptoProperties", {}).get("assetType") == asset_type
    ]


def test_cbom_from_a_real_scan_contains_the_certificate():
    """Regression: the CBOM read cert_subject/cert_key_type/cert_key_bits/cert_sig_alg.

    scan_host emits subject/key_type/key_bits/sig_algorithm. Nothing bridged the two, so `subject`
    was always empty, the whole certificate block was skipped, and a CBOM exported from a real scan
    listed cipher-suite algorithms and no certificate at all -- which is the part of a CBOM that an
    auditor is asking for.
    """
    cbom = generate_cbom([_scanner_shaped_result()], org_name="acme", scan_id="s1")

    certs = _crypto_components(cbom, "certificate")
    assert len(certs) == 1, [c.get("name") for c in cbom.get("components", [])]
    props = certs[0]["cryptoProperties"]["certificateProperties"]
    assert props["subjectName"] == "CN=api.example"
    assert props["issuerName"] == "CN=Example CA"
    assert props["notValidAfter"].startswith("2027-01-01")
    assert props.get("subjectPublicKeyRef"), "certificate has no public key reference"
    assert props.get("signatureAlgorithmRef"), "certificate has no signature algorithm reference"


@pytest.mark.parametrize("key_type,key_bits,expected", [
    ("RSA", 2048, "RSA-2048"),
    ("RSA", 3072, "RSA-3072"),
    ("RSA", 4096, "RSA-4096"),
    ("EC", 256, "ECDSA-P256"),
    ("EC", 384, "ECDSA-P384"),
    ("EC", 521, "ECDSA-P521"),
    ("Ed25519", 256, "Ed25519"),
])
def test_cbom_reports_the_actual_key_size(key_type, key_bits, expected):
    """Without key_bits the resolver defaults to RSA-2048 / ECDSA-P256 for the whole estate."""
    cbom = generate_cbom(
        [_scanner_shaped_result(key_type=key_type, key_bits=key_bits)],
        org_name="acme", scan_id="s1",
    )

    names = {c["name"] for c in _crypto_components(cbom, "algorithm")}
    assert expected in names, sorted(names)


def test_cbom_omits_endpoints_that_were_never_reached():
    cbom = generate_cbom(
        [_scanner_shaped_result(error="connection refused", subject="", key_type="")],
        org_name="acme", scan_id="s1",
    )
    assert _crypto_components(cbom, "certificate") == []


# ── Reporting endpoints over a seeded estate ──────────────────────────────────

ORG = "pipeline-accuracy-org"
HEADERS = {"x-user-role": "admin", "x-user-id": "pipeline-admin", "x-org-id": ORG}

# The key facts a scan observes, in the shape scanner.scan_host() emits them. key_bits, key_curve,
# cipher_name, scan_status and key_exchange are columns on scan_results now; before that every
# report downstream had to invent them, which is what made the org-wide CBOM describe a 4096-bit
# estate as RSA-2048 and the HNDL model price a P-521 endpoint as P-256.
_SEED = [
    {"host": "rsa.example", "risk": "high", "pq_relevance": "HIGH", "key_type": "RSA",
     "key_bits": 4096, "key_curve": "", "cipher_name": "TLS_AES_256_GCM_SHA384",
     "scan_status": "ok", "key_exchange": "x25519"},
    {"host": "ec.example", "risk": "medium", "pq_relevance": "MEDIUM", "key_type": "EC",
     "key_bits": 521, "key_curve": "secp521r1", "cipher_name": "TLS_AES_128_GCM_SHA256",
     "scan_status": "ok", "key_exchange": "X25519MLKEM768"},
    {"host": "ed.example", "risk": "high", "pq_relevance": "HIGH", "key_type": "Ed25519",
     "key_bits": 256, "key_curve": "Curve25519", "cipher_name": "TLS_AES_256_GCM_SHA384",
     "scan_status": "ok", "key_exchange": "x25519"},
    # Never reached: no key, no size, no group. Every one of these must stay unknown downstream.
    {"host": "unreachable.example", "risk": "medium", "pq_relevance": "UNKNOWN", "key_type": "",
     "key_bits": 0, "key_curve": "", "cipher_name": "", "scan_status": "unreachable",
     "key_exchange": ""},
]


def _seed_result(row):
    """One scan result, in the shape scanner.scan_host() returns."""
    key_type = row["key_type"]
    return {
        "host": row["host"], "port": 443,
        "risk": row["risk"], "risk_level": row["risk"],
        "quantum_risk_score": 50.0,
        "findings": [{"rule_id": "SEED"}] * 3,
        "pq_relevance": row["pq_relevance"],
        "tls_version": "TLSv1.3" if key_type else "",
        "key_type": key_type,
        "key_bits": row["key_bits"],
        "key_curve": row["key_curve"],
        "cipher_name": row["cipher_name"],
        "scan_status": row["scan_status"],
        "key_exchange": row["key_exchange"],
        "key_exchange_observed": bool(row["key_exchange"]),
        "sig_algorithm": "sha256WithRSAEncryption" if key_type else "",
    }


@pytest.fixture(scope="module")
def seeded_client():
    import app as fastapi_app
    from db import (
        init_db, save_scan_asset_summaries,
        set_current_organization_id, reset_current_organization_id,
    )

    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_db.close()
    previous = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    token = set_current_organization_id(ORG)
    try:
        # Deliberately no upsert_asset() here. Nothing in the scan path used to register an asset,
        # so after scanning an estate /assets was empty and the HNDL dashboard reported $0 over
        # zero assets; save_scan_asset_summaries registers them now and these tests prove it.
        save_scan_asset_summaries("scan-pipeline-1", scanned_at_iso=now,
                                  results=[_seed_result(row) for row in _SEED])
    finally:
        reset_current_organization_id(token)

    from fastapi.testclient import TestClient
    with TestClient(fastapi_app.app) as client:
        yield client

    if previous is None:
        os.environ.pop("MORROW_SCANNER_DB", None)
    else:
        os.environ["MORROW_SCANNER_DB"] = previous


def _csv_rows(text):
    import csv
    import io
    return list(csv.DictReader(io.StringIO(text)))


def test_ed25519_is_not_exported_to_auditors_as_pq_safe(seeded_client):
    """Regression: "x25519" and "ed25519" were on the compliance export's quantum-safe list.

    Both are classical elliptic-curve algorithms broken by Shor's algorithm. An Ed25519 endpoint
    was exported with compliant=YES and the finding "quantum-safe".
    """
    r = seeded_client.get("/compliance/export.csv", headers=HEADERS)
    assert r.status_code == 200
    rows = {row["host"]: row for row in _csv_rows(r.text)}

    assert rows["ed.example"]["compliant"] == "NO", rows["ed.example"]
    assert "quantum-vulnerable" in rows["ed.example"]["finding"]
    assert rows["rsa.example"]["compliant"] == "NO"
    assert rows["ec.example"]["compliant"] == "NO"


def test_unscanned_asset_is_exported_as_unknown_not_as_a_verdict(seeded_client):
    r = seeded_client.get("/compliance/export.csv", headers=HEADERS)
    rows = {row["host"]: row for row in _csv_rows(r.text)}

    unknown = rows["unreachable.example"]
    assert unknown["compliant"] == "UNKNOWN", unknown
    assert "not observed" in unknown["finding"], unknown


def test_org_cbom_is_not_a_single_empty_endpoint(seeded_client):
    """Regression: /cbom read host/port/algorithm off scan_results, which has none of them.

    Every row got the dedup key ":" and a blank algorithm, so an entire estate collapsed into one
    nameless "TLS endpoint" component containing no cryptography -- and still returned HTTP 200.
    """
    r = seeded_client.get("/cbom", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()

    protocols = _crypto_components(body, "protocol")
    certificates = _crypto_components(body, "certificate")
    assert len(protocols) == 3, [c["name"] for c in protocols]   # the unreachable asset is excluded
    assert len(certificates) == 3, [c["name"] for c in certificates]
    assert all("TLS endpoint " in c["name"] for c in protocols), [c["name"] for c in protocols]


def test_trust_passport_reflects_high_risk_assets(seeded_client):
    """Regression: high_risk was counted from the `scans` table, which has no risk_level column.

    The lookup always returned None, so the shareable passport scored 90 "monitored" for any
    estate, however many critical endpoints it contained.
    """
    r = seeded_client.get("/trust-passport", headers=HEADERS)
    assert r.status_code == 200
    passport = r.json()["payload"]["passport"]

    assert passport["evidence"]["scan_count"] == len(_SEED), passport["evidence"]
    assert passport["evidence"]["high_risk_findings"] == 2, passport["evidence"]
    assert passport["score"] < 90, passport["score"]
    assert passport["status"] != "verified", passport["status"]


# ── Observed key facts survive into the org-wide reports ──────────────────────
#
# scan_results held key_type and nothing else about the key, so every org-level report had to
# invent the size. The four tests below are the whole point of adding key_bits / key_curve /
# cipher_name / scan_status / key_exchange to the table: the value the scanner measured must be
# the value the customer is shown, and where nothing was measured the customer must be told that
# rather than shown a default.


def test_org_cbom_reports_the_key_size_that_was_observed(seeded_client):
    """Regression: the org-wide CBOM described every RSA asset as RSA-2048 and every EC asset as
    ECDSA-P256, because cbom.canonical_algorithm() defaulted when key_bits was absent -- and it
    was always absent, because scan_results had no such column. The fixture estate is RSA-4096
    and P-521."""
    r = seeded_client.get("/cbom", headers=HEADERS)
    assert r.status_code == 200
    names = {c["name"] for c in _crypto_components(r.json(), "algorithm")}

    assert "RSA-4096" in names, sorted(names)
    assert "ECDSA-P521" in names, sorted(names)
    assert "RSA-2048" not in names, f"a 4096-bit estate reported RSA-2048: {sorted(names)}"
    assert "ECDSA-P256" not in names, f"a P-521 estate reported ECDSA-P256: {sorted(names)}"


def test_org_cbom_names_the_hybrid_key_exchange_group(seeded_client):
    """The CBOM has always read `key_exchange`; the scanner never set it, so it was always absent.

    ec.example negotiated X25519MLKEM768, which must appear as the ML-KEM component rather than
    being resolved to plain X25519 -- reporting a migrated endpoint as classical would be exactly
    backwards.
    """
    body = seeded_client.get("/cbom", headers=HEADERS).json()
    names = {c["name"] for c in _crypto_components(body, "algorithm")}
    assert "ML-KEM-768" in names, sorted(names)


@pytest.mark.parametrize("group,expected", [
    # A group name is not a signature algorithm: "secp384r1" resolved through the generic
    # algorithm table to ECDSA-P384, which would describe a Diffie-Hellman key exchange with a
    # signature component.
    ("secp384r1", ["ECDH"]),
    ("x25519", ["X25519"]),
    ("ffdhe2048", ["DH"]),
    # A hybrid group really is two algorithms. Naming only one would hide either the
    # post-quantum half or the classical half that is still there to be broken.
    ("X25519MLKEM768", ["X25519", "ML-KEM-768"]),
    ("SecP256r1MLKEM768", ["ECDH", "ML-KEM-768"]),
    ("MLKEM1024", ["ML-KEM-1024"]),
    ("", []),
])
def test_key_exchange_group_decomposes_into_key_agreement_algorithms(group, expected):
    from services.cbom import key_exchange_algorithms
    assert key_exchange_algorithms(group) == expected


def test_an_unknown_key_stays_unknown_in_the_org_cbom(seeded_client):
    """The unreachable endpoint has no key, no size and no group, and must contribute none."""
    body = seeded_client.get("/cbom", headers=HEADERS).json()
    subjects = {c["name"] for c in _crypto_components(body, "certificate")}
    assert not any("unreachable" in s for s in subjects), subjects


def test_compliance_export_states_the_observed_key_size(seeded_client):
    r = seeded_client.get("/compliance/export.csv", headers=HEADERS)
    rows = {row["host"]: row for row in _csv_rows(r.text)}

    assert rows["rsa.example"]["key_bits"] == "4096", rows["rsa.example"]
    assert rows["rsa.example"]["algorithm"] == "RSA-4096", rows["rsa.example"]
    assert rows["ec.example"]["algorithm"] == "P-521", rows["ec.example"]
    # Nothing was observed here, so the size cell is empty rather than a filled-in default.
    assert rows["unreachable.example"]["key_bits"] == "", rows["unreachable.example"]


def test_fips_report_grades_rsa_4096_below_rsa_2048(seeded_client):
    """Regression: with no key size every RSA asset got the RSA-2048 verdict, `critical`.

    fips_pq's table holds a separate row for RSA-4096 (`high`), but prefix matching over an
    ordered dict meant "RSA-4096" hit the bare "RSA" row first and never reached it.
    """
    body = seeded_client.get("/fips-pq/report", headers=HEADERS).json()
    report = body["report"]
    blob = str(report)
    assert "RSA-4096" in blob, "the FIPS report never saw the observed key size"

    from services.fips_pq import classify_algorithm
    assert classify_algorithm("RSA-4096")["risk"] == "high"
    assert classify_algorithm("RSA-2048")["risk"] == "critical"
    assert classify_algorithm("P-521")["risk"] == "high"


# ── A completed scan creates the asset it scanned ─────────────────────────────


def test_a_scan_registers_every_endpoint_as_an_asset(seeded_client):
    """Regression: nothing in the scan path called upsert_asset().

    After scanning 18 endpoints /assets returned {"items": []} and /hndl/dashboard reported
    asset_count 0 with $0 exposure, because both iterate the asset inventory and the inventory
    was never written.
    """
    r = seeded_client.get("/assets", headers=HEADERS)
    assert r.status_code == 200
    keys = sorted(str(a.get("asset_key") or "") for a in (r.json().get("items") or r.json().get("assets") or []))

    assert keys == sorted(f"{row['host']}:443" for row in _SEED), keys


def test_rescanning_updates_the_asset_instead_of_duplicating_it(seeded_client):
    """One asset row per host and port, however many times the endpoint is scanned."""
    from db import (
        list_assets, save_scan_asset_summaries, get_asset_history,
        set_current_organization_id, reset_current_organization_id,
    )

    token = set_current_organization_id(ORG)
    try:
        before = len(list_assets(limit=500) or [])
        save_scan_asset_summaries(
            "scan-pipeline-rescan",
            scanned_at_iso=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            results=[_seed_result(row) for row in _SEED],
        )
        after = list_assets(limit=500) or []
        keys = [str(a.get("asset_key") or "") for a in after]

        assert len(after) == before, f"re-scan created {len(after) - before} extra asset rows"
        assert len(keys) == len(set(keys)), keys
        # The scan history does grow: two scans, one asset.
        assert len(get_asset_history("rsa.example:443")) >= 2
    finally:
        reset_current_organization_id(token)


def test_a_scan_does_not_overwrite_ownership_the_customer_set(seeded_client):
    """upsert_asset() writes empty strings over owner/team/environment/criticality when called
    with its defaults, so registering assets through it would erase the customer's inventory
    metadata on every re-scan."""
    from db import (
        upsert_asset, get_asset, save_scan_asset_summaries,
        set_current_organization_id, reset_current_organization_id,
    )

    token = set_current_organization_id(ORG)
    try:
        upsert_asset("rsa.example:443", owner="platform-team", team="crypto",
                     environment="production", criticality="high")
        save_scan_asset_summaries(
            "scan-pipeline-ownership",
            scanned_at_iso=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            results=[_seed_result(_SEED[0])],
        )
        asset = get_asset("rsa.example:443") or {}

        assert asset.get("owner") == "platform-team", asset
        assert asset.get("environment") == "production", asset
        assert asset.get("criticality") == "high", asset
    finally:
        reset_current_organization_id(token)


# ── HNDL exposure is built from what was observed ─────────────────────────────


@pytest.mark.parametrize("key_type,key_bits,expected", [
    ("RSA", 4096, "rsa4096"),
    ("RSA", 3072, "rsa3072"),
    ("RSA", 2048, "rsa2048"),
    ("EC", 521, "ecc384"),
    ("EC", 256, "ecc256"),
    # Observed as RSA, but the size was never recorded. It is classical, and that is all that can
    # be said; claiming rsa2048 would price it at the Q-Day probability of the weakest RSA key.
    ("RSA", 0, "unknown_classical"),
    ("EC", 0, "unknown_classical"),
])
def test_hndl_buckets_use_the_observed_key_size(key_type, key_bits, expected):
    from services.hndl import _classify_algorithm
    assert _classify_algorithm("TLSv1.3", "TLS_AES_256_GCM_SHA384", key_type, key_bits) == expected


def test_hndl_reaches_the_hybrid_bucket_from_an_observed_group():
    """Regression: _classify_algorithm looked for "kyber"/"mlkem" in the cipher suite name.

    TLS 1.3 suite names (TLS_AES_256_GCM_SHA384) never name the key exchange, so the pq_hybrid
    and pq_pure buckets were unreachable from any TLS 1.3 scan.
    """
    from services.hndl import _classify_algorithm

    assert _classify_algorithm("TLSv1.3", "TLS_AES_256_GCM_SHA384", "RSA", 2048,
                               "X25519MLKEM768") == "pq_hybrid"
    assert _classify_algorithm("TLSv1.3", "TLS_AES_256_GCM_SHA384", "RSA", 2048,
                               "MLKEM768") == "pq_pure"
    assert _classify_algorithm("TLSv1.3", "TLS_AES_256_GCM_SHA384", "RSA", 2048,
                               "x25519") == "rsa2048"


def test_hndl_does_not_price_an_asset_that_was_never_scanned():
    from services.hndl import score_tls_endpoint_hndl

    scored = score_tls_endpoint_hndl("never.example", 443, "", "", "", 0)

    assert scored["algo_class"] == "unmeasured", scored
    assert scored["exposure_usd"] is None, scored
    assert scored["p_broken"] is None, scored
    assert scored["risk_tier"] == "unmeasured", scored


def test_hndl_dashboard_counts_scanned_assets_and_excludes_unmeasured_ones(seeded_client):
    """Regression: the dashboard iterated list_assets(), which nothing populated, so a scanned
    estate reported asset_count 0 and total_exposure_usd 0."""
    r = seeded_client.get("/hndl/dashboard", headers=HEADERS)
    assert r.status_code == 200
    dash = r.json()

    assert dash["asset_count"] == len(_SEED), dash["asset_count"]
    assert dash["measured_asset_count"] == 3, dash
    assert dash["unmeasured_asset_count"] == 1, dash
    assert dash["total_exposure_usd"] > 0, dash
    assert dash["risk_tier_counts"].get("unmeasured") == 1, dash["risk_tier_counts"]

    by_host = {x["host"]: x for x in dash["priority_queue"]}
    assert by_host["rsa.example"]["algo_class"] == "rsa4096", by_host["rsa.example"]
    assert by_host["ec.example"]["algo_class"] == "pq_hybrid", by_host["ec.example"]
    assert by_host["unreachable.example"]["exposure_usd"] is None, by_host["unreachable.example"]


def test_trust_passport_counts_hybrid_key_exchange_it_actually_observed(seeded_client):
    """Regression: hybrid_tls_observations was counted by looking for "MLKEM" in the certificate
    algorithm, where it can never appear, so the count was structurally 0 -- a fixed 10-point
    deduction on every estate and an unreachable `verified` status."""
    passport = seeded_client.get("/trust-passport", headers=HEADERS).json()["payload"]["passport"]
    evidence = passport["evidence"]

    assert evidence["hybrid_tls_observations"] == 1, evidence
    assert evidence["key_exchange_observed_endpoints"] == 3, evidence
    assert evidence["key_exchange_unobserved_endpoints"] == 1, evidence
    assert "of 3 endpoint" in evidence["hybrid_tls_basis"], evidence["hybrid_tls_basis"]


# ── The schema change against a database that already has data in it ──────────
#
# Adding columns is the easy half. The half that breaks deployments is applying them to a
# populated database on both backends, and backfilling only what the existing rows actually
# determine. Ed25519/Ed448/X25519/X448 have exactly one key size and curve each, so those can be
# filled in from key_type alone. A stored "RSA" could be 2048 or 4096 and a stored "EC" could be
# P-256 or P-521, so those rows must stay NULL -- filling them with a plausible number is the
# original bug wearing a migration costume.

_PRE_CHANGE_SCAN_RESULTS_SQLITE = """
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL DEFAULT '',
    asset_key TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    quantum_score REAL NOT NULL,
    findings_count INTEGER NOT NULL,
    pq_relevance TEXT NOT NULL,
    tls_version TEXT NOT NULL,
    key_type TEXT NOT NULL,
    sig_algorithm TEXT NOT NULL,
    owner TEXT NOT NULL,
    team TEXT NOT NULL,
    environment TEXT NOT NULL,
    criticality TEXT NOT NULL
)
"""

_LEGACY_ROWS = [
    ("legacy-org", "rsa.legacy:443", "RSA"),
    ("legacy-org", "ec.legacy:443", "EC"),
    ("legacy-org", "ed.legacy:443", "Ed25519"),
    ("legacy-org", "x.legacy:443", "X25519"),
    ("legacy-org", "failed.legacy:443", ""),
]

_NEW_COLUMNS = ("key_bits", "key_curve", "cipher_name", "scan_status", "key_exchange")


def _populated_pre_change_sqlite(path):
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute(_PRE_CHANGE_SCAN_RESULTS_SQLITE)
    for org, ak, key_type in _LEGACY_ROWS:
        conn.execute(
            "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at,"
            " risk_level, quantum_score, findings_count, pq_relevance, tls_version, key_type,"
            " sig_algorithm, owner, team, environment, criticality)"
            " VALUES (?,?,'legacy-scan','2026-01-01T00:00:00Z','high',20,2,'HIGH','TLSv1.3',?,"
            "'sha256WithRSAEncryption','','','','')",
            (org, ak, key_type),
        )
    conn.commit()
    return conn


def _assert_upgraded(rows_by_key, columns):
    for col in _NEW_COLUMNS:
        assert col in columns, f"{col} missing after upgrade: {sorted(columns)}"
    assert len(rows_by_key) == len(_LEGACY_ROWS), rows_by_key

    # Fixed-size algorithms are backfilled, because key_type determines them.
    assert rows_by_key["ed.legacy:443"]["key_bits"] == 256, rows_by_key["ed.legacy:443"]
    assert rows_by_key["ed.legacy:443"]["key_curve"] == "Curve25519", rows_by_key["ed.legacy:443"]
    assert rows_by_key["x.legacy:443"]["key_bits"] == 256, rows_by_key["x.legacy:443"]

    # Everything else stays NULL. "Not recorded" must not become a number.
    for key in ("rsa.legacy:443", "ec.legacy:443", "failed.legacy:443"):
        assert rows_by_key[key]["key_bits"] is None, (key, rows_by_key[key])
        assert rows_by_key[key]["key_curve"] is None, (key, rows_by_key[key])
    # No historic row claims a scan status it never had.
    for row in rows_by_key.values():
        assert row["scan_status"] is None, row


def test_populated_sqlite_database_upgrades_cleanly(tmp_path):
    """The runtime path: db._ensure_sprint5_tables() on an existing database."""
    import sqlite3

    import db as db_module

    path = str(tmp_path / "legacy.db")
    conn = _populated_pre_change_sqlite(path)
    before = {r[1] for r in conn.execute("PRAGMA table_info(scan_results)").fetchall()}
    assert not (before & set(_NEW_COLUMNS)), before

    db_module._ensure_sprint5_tables(conn)
    conn.commit()

    conn.row_factory = sqlite3.Row
    columns = {r[1] for r in conn.execute("PRAGMA table_info(scan_results)").fetchall()}
    rows = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM scan_results")}
    conn.close()
    _assert_upgraded(rows, columns)


def test_populated_sqlite_database_upgrades_through_alembic(tmp_path):
    """The declared migration path, run against data rather than an empty file."""
    import sqlite3
    import subprocess
    import sys

    path = str(tmp_path / "alembic.db")
    conn = _populated_pre_change_sqlite(path)
    conn.close()

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, MORROW_PRODUCT_DATABASE_URL=f"sqlite:///{path}",
               DATABASE_URL=f"sqlite:///{path}")
    for args in (["stamp", "0006_external_findings_security_truth"], ["upgrade", "head"]):
        done = subprocess.run([sys.executable, "-m", "alembic", *args],
                              cwd=backend_dir, env=env, capture_output=True, text=True)
        assert done.returncode == 0, f"alembic {args[0]} failed:\n{done.stdout}\n{done.stderr}"

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    columns = {r[1] for r in conn.execute("PRAGMA table_info(scan_results)").fetchall()}
    rows = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM scan_results")}
    conn.close()
    _assert_upgraded(rows, columns)


_PG_DSN = os.environ.get("MORROW_TEST_PG_DSN", "").strip()


@pytest.mark.skipif(not _PG_DSN, reason="set MORROW_TEST_PG_DSN to a throwaway Postgres database")
def test_populated_postgres_database_upgrades_cleanly():
    """Postgres is the production backend, and the column change has to reach it.

    ensure_postgres_core_schema() runs the core DDL list on every start; that list is where every
    column previously added to this schema has reached an already-populated deployment, and the
    ALTER ... ADD COLUMN IF NOT EXISTS statements for the observed key facts live there too.
    """
    psycopg2 = pytest.importorskip("psycopg2")

    import db_postgres

    con = psycopg2.connect(_PG_DSN)
    con.autocommit = True
    try:
        with con.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS scan_results")
            cur.execute("""
                CREATE TABLE scan_results (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    asset_key TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    scanned_at TIMESTAMPTZ NOT NULL,
                    risk_level TEXT NOT NULL,
                    quantum_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    pq_relevance TEXT NOT NULL DEFAULT '',
                    tls_version TEXT NOT NULL DEFAULT '',
                    key_type TEXT NOT NULL DEFAULT '',
                    sig_algorithm TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '',
                    team TEXT NOT NULL DEFAULT '',
                    environment TEXT NOT NULL DEFAULT '',
                    criticality TEXT NOT NULL DEFAULT ''
                )
            """)
            for org, ak, key_type in _LEGACY_ROWS:
                cur.execute(
                    "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at,"
                    " risk_level, key_type) VALUES (%s,%s,'legacy-scan',NOW(),'high',%s)",
                    (org, ak, key_type),
                )

        db_postgres._SCHEMA_READY.clear()
        db_postgres.ensure_postgres_core_schema(_PG_DSN)

        with con.cursor() as cur:
            cur.execute(
                "SELECT column_name, is_nullable FROM information_schema.columns"
                " WHERE table_name = 'scan_results'"
            )
            col_rows = cur.fetchall()
            columns = {str(r[0]) for r in col_rows}
            nullable = {str(r[0]): str(r[1]) for r in col_rows}
            cur.execute("SELECT asset_key, key_bits, key_curve, scan_status FROM scan_results")
            rows = {
                str(r[0]): {"key_bits": r[1], "key_curve": r[2], "scan_status": r[3]}
                for r in cur.fetchall()
            }
    finally:
        con.close()

    _assert_upgraded(rows, columns)
    for col in _NEW_COLUMNS:
        assert nullable[col] == "YES", f"{col} must be nullable so absence stays absence"
