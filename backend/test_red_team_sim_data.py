"""The red team simulation must read real scan data.

It did not. `_load_assets` selected host, port, algorithm, key_bits, risk_level
and scanned_at from `scans` where org_id -- and not one of those seven columns
exists on that table. `scans` holds id, organization_id, status, created_at and
JSON blobs; the per-asset facts live in `scan_results`.

Every call raised OperationalError, a bare `except Exception: return []`
swallowed it, and the caller answered "No scanned assets found. Run a scan
first." So the feature ran on zero assets on every deployment and blamed the
operator for it.

Nothing failed, no test caught it, and no log line was emitted. These tests
assert on the outcome a user sees, not on the query, so a future rewrite that
reintroduces a wrong column is caught by the same assertions.
"""

import os
import sqlite3
import tempfile

import pytest


@pytest.fixture()
def seeded(monkeypatch):
    """A database with real scan_results rows, wired the way production is."""
    path = os.path.join(tempfile.mkdtemp(), "rt.db")
    monkeypatch.setenv("PQC_SCANNER_DB", path)
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")

    import importlib
    import db
    importlib.reload(db)
    db.init_db()

    org = "00000000-0000-0000-0000-000000000001"
    conn = sqlite3.connect(path)
    rows = [
        ("api.example.com:443", "critical", "RSA", "sha256WithRSAEncryption", "2026-02-07T09:00:00Z"),
        ("db.example.com:5432", "high",     "EC",  "ecdsa-with-SHA256",       "2026-02-07T08:00:00Z"),
        # Same asset scanned twice; the newer row must win after dedup.
        ("api.example.com:443", "low",      "RSA", "sha256WithRSAEncryption", "2026-01-01T00:00:00Z"),
    ]
    for asset_key, risk, key_type, sig, when in rows:
        conn.execute(
            "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at, risk_level,"
            " quantum_score, findings_count, pqc_relevance, tls_version, key_type, sig_algorithm,"
            " owner, team, environment, criticality)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org, asset_key, "scan-1", when, risk, 80.0, 2, "high", "TLSv1.3", key_type, sig,
             "", "", "prod", "high"),
        )
    conn.commit()
    conn.close()

    import db_feature_store
    importlib.reload(db_feature_store)
    import services.red_team_sim as module
    importlib.reload(module)
    return module, org


def test_scanned_assets_are_actually_loaded(seeded):
    module, org = seeded
    assets = module._load_assets(org)

    assert assets, "scan_results rows exist but none were loaded"
    hosts = {a["host"] for a in assets}
    assert hosts == {"api.example.com", "db.example.com"}

    api = next(a for a in assets if a["host"] == "api.example.com")
    assert api["port"] == 443, "port must be parsed out of asset_key"
    assert api["risk_level"] == "critical"
    assert "RSA" in api["algorithm"].upper()

    db_asset = next(a for a in assets if a["host"] == "db.example.com")
    assert db_asset["port"] == 5432, "a non-443 port must survive parsing"


def test_newest_scan_wins_for_a_repeated_asset(seeded):
    module, org = seeded
    assets = module._load_assets(org)
    # Ordered newest first, so the caller's dedup keeps the current risk level.
    first_api = next(a for a in assets if a["host"] == "api.example.com")
    assert first_api["risk_level"] == "critical", "stale scan overwrote the current one"


def test_simulation_runs_instead_of_claiming_no_assets(seeded):
    """The user-visible symptom: a populated estate was told to go and scan."""
    module, org = seeded
    result = module.run_simulation(org)

    assert result.get("ok") is not False, f"simulation refused to run: {result.get('error')}"
    assert "No scanned assets found" not in str(result.get("error") or "")
    targets = result.get("target_list") or []
    assert targets, "simulation produced no targets from real scan data"
    assert {t["host"] for t in targets} == {"api.example.com", "db.example.com"}
    # Highest adversary priority first.
    assert targets[0]["target_score"] >= targets[-1]["target_score"]


def test_an_empty_org_still_reports_no_assets(seeded):
    """The 'run a scan first' message is correct when it is actually true."""
    module, _ = seeded
    result = module.run_simulation("11111111-1111-1111-1111-111111111111")
    assert result.get("ok") is False
    assert "No scanned assets" in result.get("error", "")


def test_read_failures_are_logged_rather_than_silently_empty(seeded, monkeypatch):
    """The bare except is what hid this for so long.

    Uses its own handler rather than pytest's caplog: caplog comes from the
    logging plugin, so a run with -p no:logging would error instead of testing
    anything.
    """
    import logging

    module, org = seeded
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    def _boom():
        raise sqlite3.OperationalError("no such column: nonsense")

    monkeypatch.setattr(module, "feature_conn", _boom)
    handler = _Collect(level=logging.ERROR)
    module.logger.addHandler(handler)
    try:
        assert module._load_assets(org) == []
    finally:
        module.logger.removeHandler(handler)

    assert records, "a failed read must leave a log record, not vanish"
