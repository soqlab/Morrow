
import db_postgres
from db_postgres import (
    CORE_TABLE_SPECS,
    DEFAULT_ORG_ID,
    TableSpec,
    _build_upsert_sql,
    _normalize_row,
    postgres_main_db_requested,
    product_database_url,
)


def test_product_database_url_prefers_product_specific_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fallback/db")
    monkeypatch.setenv("MORROW_PRODUCT_DATABASE_URL", "postgresql://product/db")
    assert product_database_url() == "postgresql://product/db"


def test_postgres_main_db_requested(monkeypatch):
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "postgres")
    assert postgres_main_db_requested() is True
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    assert postgres_main_db_requested() is False


def test_normalize_row_defaults_org_json_and_timestamps():
    spec = TableSpec(
        name="assets",
        columns=("organization_id", "asset_key", "metadata_json", "repository_id", "updated_at"),
        json_defaults={"metadata_json": {}},
        integer_columns=("repository_id",),
        timestamp_columns=("updated_at",),
    )
    row = {
        "organization_id": "",
        "asset_key": "example.com:443",
        "metadata_json": "",
        "repository_id": "",
        "updated_at": "",
    }
    normalized = _normalize_row(spec, row)
    assert normalized["organization_id"] == DEFAULT_ORG_ID
    assert normalized["metadata_json"] == {}
    assert normalized["repository_id"] == 0
    assert normalized["updated_at"] is None


def test_build_upsert_sql_uses_conflict_target():
    spec = TableSpec(
        name="repositories",
        columns=("organization_id", "name", "html_url", "updated_at"),
        conflict_target=("organization_id", "name"),
        update_columns=("html_url", "updated_at"),
    )
    sql = _build_upsert_sql(spec)
    assert "ON CONFLICT (organization_id, name) DO UPDATE SET" in sql
    assert "html_url=EXCLUDED.html_url" in sql


def test_core_table_specs_cover_expected_initial_cutover_tables():
    names = {spec.name for spec in CORE_TABLE_SPECS}
    assert {
        "organizations",
        "repositories",
        "assets",
        "asset_tags",
        "baselines",
        "scans",
        "scan_results",
        "remediations",
        "audit_logs",
        "github_installations",
        "webhooks",
        "webhook_events",
        "collections",
        "schedules",
        "integrations_settings",
        "event_rules",
        "event_rule_fires",
    }.issubset(names)


class _FakeCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if sql.lstrip().startswith("UPDATE scans"):
            self.rowcount = 0
        else:
            self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self, *args, **kwargs):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_pg_update_scan_job_inserts_stub_when_update_misses(monkeypatch):
    cur = _FakeCursor()
    monkeypatch.setattr(db_postgres, "ensure_postgres_core_schema", lambda dsn=None: None)
    monkeypatch.setattr(db_postgres, "pg_product_conn", lambda dsn=None: _FakeConn(cur))

    db_postgres.pg_update_scan_job("org-test", "scan-1", job_id="job-1", job_state="PENDING")

    assert len(cur.calls) == 2
    assert cur.calls[0][0].lstrip().startswith("UPDATE scans")
    assert "INSERT INTO scans" in cur.calls[1][0]
    assert cur.calls[1][1][0] == "scan-1"
    assert cur.calls[1][1][1] == "org-test"
    assert cur.calls[1][1][8] == "job-1"
    assert cur.calls[1][1][9] == "PENDING"


def test_pg_save_scan_results_inserts_stub_when_update_misses(monkeypatch):
    cur = _FakeCursor()
    monkeypatch.setattr(db_postgres, "ensure_postgres_core_schema", lambda dsn=None: None)
    monkeypatch.setattr(db_postgres, "pg_product_conn", lambda dsn=None: _FakeConn(cur))

    db_postgres.pg_save_scan_results("org-test", "scan-2", [{"host": "example.com"}], {"total": 1}, status="completed")

    assert len(cur.calls) == 2
    assert cur.calls[0][0].lstrip().startswith("UPDATE scans")
    assert "INSERT INTO scans" in cur.calls[1][0]
    assert cur.calls[1][1][0] == "scan-2"
    assert cur.calls[1][1][1] == "org-test"
    assert cur.calls[1][1][2] == "completed"


def test_ensure_postgres_core_schema_adds_drift_columns_for_existing_remediations(monkeypatch):
    cur = _FakeCursor()
    key = "postgresql://example/db"
    monkeypatch.setattr(db_postgres, "pg_product_conn", lambda dsn=None: _FakeConn(cur))
    monkeypatch.setattr(db_postgres, "product_database_url", lambda: key)
    db_postgres._SCHEMA_READY.discard(key)

    db_postgres.ensure_postgres_core_schema(key)

    sql_text = "\n".join(call[0] for call in cur.calls)
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS parent_remediation_id" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS origin_kind" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_followup_remediation_id" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_status" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS last_drift_checked_at" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_detected_at" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_acknowledged_at" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_acknowledged_by" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_ack_note" in sql_text
    assert "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_details_json" in sql_text
    db_postgres._SCHEMA_READY.discard(key)
