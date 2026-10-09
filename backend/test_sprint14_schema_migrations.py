import os
import sqlite3
import tempfile

from db import (
    get_baseline,
    init_db,
    reset_current_organization_id,
    set_baseline,
    set_current_organization_id,
    upsert_asset,
    upsert_repository,
)


def test_legacy_schema_migrates_to_tenant_unique_keys():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    db_path = tmp_db.name
    os.environ["PQC_SCANNER_DB"] = db_path

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL UNIQUE,
            html_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE assets (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            confidentiality_lifetime TEXT NOT NULL,
            notes TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            repository_id INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE baselines (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT PRIMARY KEY,
            baseline_scan_id TEXT NOT NULL,
            set_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO repositories (organization_id, name, html_url, created_at, updated_at)
        VALUES ('', 'legacy/shared', 'https://github.com/legacy/shared', '2026-02-01T00:00:00Z', '2026-02-01T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO assets (
            organization_id, asset_key, owner, team, environment, criticality, confidentiality_lifetime,
            notes, metadata_json, repository_id, updated_at
        )
        VALUES ('', 'legacy.example:443', '', '', '', '', '', '', '{}', 0, '2026-02-01T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO baselines (organization_id, asset_key, baseline_scan_id, set_at)
        VALUES ('', 'legacy.example:443', 'legacy-scan', '2026-02-01T00:00:00Z')
        """
    )
    conn.commit()
    conn.close()

    try:
        init_db()

        t1 = set_current_organization_id("org-alpha")
        try:
            repo_a = upsert_repository("legacy/shared", "https://github.com/legacy/shared")
            upsert_asset("legacy.example:443", repository_id=int(repo_a["id"]))
            set_baseline("legacy.example:443", "scan-alpha")
        finally:
            reset_current_organization_id(t1)

        t2 = set_current_organization_id("org-beta")
        try:
            repo_b = upsert_repository("legacy/shared", "https://github.com/legacy/shared")
            upsert_asset("legacy.example:443", repository_id=int(repo_b["id"]))
            set_baseline("legacy.example:443", "scan-beta")
        finally:
            reset_current_organization_id(t2)

        assert int(repo_a["id"]) != int(repo_b["id"])

        t3 = set_current_organization_id("org-alpha")
        try:
            b_alpha = get_baseline("legacy.example:443")
        finally:
            reset_current_organization_id(t3)
        t4 = set_current_organization_id("org-beta")
        try:
            b_beta = get_baseline("legacy.example:443")
        finally:
            reset_current_organization_id(t4)

        assert (b_alpha or {}).get("baseline_scan_id") == "scan-alpha"
        assert (b_beta or {}).get("baseline_scan_id") == "scan-beta"
    finally:
        try:
            os.remove(db_path)
        except OSError:
            pass
