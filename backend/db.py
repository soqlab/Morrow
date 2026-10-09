from __future__ import annotations

import os
import sqlite3
import json
import hashlib
import contextvars
import threading
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence
import uuid
import secrets

# Schema initialisation guard â€” ensures _ensure_* calls run once after startup.
_schema_initialized = threading.Event()
_schema_initialized_db_path: Optional[str] = None

from db_postgres import (
    ensure_postgres_core_schema,
    ensure_postgres_default_org,
    register_deferred_schema,
    tolerate_missing_ddl_privilege,
    pg_append_audit_log,
    pg_append_flight_recorder_event,
    pg_archive_organization,
    pg_auto_close_merged_remediations,
    pg_bump_webhook_attempt,
    pg_claim_due_webhook_events,
    pg_create_schedule,
    pg_create_migration_task,
    pg_create_remediation,
    pg_delete_webhook,
    pg_delete_collection,
    pg_delete_event_rule,
    pg_delete_schedule,
    pg_delete_organization,
    pg_due_schedules,
    pg_get_asset,
    pg_get_collection,
    pg_get_event_rule_fire,
    pg_get_github_installation,
    pg_get_remediation,
    pg_get_repository_by_id,
    pg_get_repository_by_name,
    pg_get_asset_history,
    pg_get_baseline,
    pg_get_schedule,
    pg_get_webhook_public,
    pg_get_integration_setting,
    pg_get_latest_validation_job_for_remediation,
    pg_get_validation_job,
    pg_latest_scan_facts_for_org,
    pg_latest_scan_result_for_asset,
    pg_latest_scan_results_for_assets,
    pg_link_asset_repository,
    pg_list_assets,
    pg_list_assets_by_repository,
    pg_list_audit_logs,
    pg_list_flight_recorder_events,
    pg_list_baselines,
    pg_list_collections,
    pg_list_event_rules,
    pg_list_github_installations,
    pg_list_organizations,
    pg_list_migration_tasks,
    pg_list_remediations,
    pg_list_repositories,
    pg_list_schedules,
    pg_list_scan_results,
    pg_list_scan_results_since,
    pg_list_validation_jobs,
    pg_count_assets,
    pg_count_scans,
    pg_recent_scan_result_times,
    pg_list_scan_rows,
    pg_list_tags,
    pg_list_due_webhook_events,
    pg_list_pending_webhook_events,
    pg_list_webhook_events,
    pg_list_webhooks,
    pg_list_webhooks_public,
    pg_mark_remediation_merged,
    pg_mark_remediation_merged_by_pr_url,
    pg_update_remediation_status_by_pr_url,
    pg_record_webhook_event,
    pg_rotate_webhook_secret,
    pg_save_scan_asset_summaries,
    pg_save_scan_results,
    pg_save_scan_row,
    pg_set_asset_metadata,
    pg_set_baseline,
    pg_set_integration_setting,
    pg_set_remediation_pr,
    pg_create_validation_job,
    pg_update_webhook_event,
    pg_update_scan_job,
    pg_update_scan_progress,
    pg_update_validation_job,
    pg_update_migration_task_status,
    pg_acknowledge_remediation_drift,
    pg_set_remediation_drift_followup,
    pg_update_remediation_branch_cleanup,
    pg_update_remediation_drift_state,
    pg_update_remediation_status,
    pg_update_schedule,
    pg_load_scan_row,
    pg_upsert_collection,
    pg_upsert_event_rule,
    pg_upsert_event_rule_fire,
    pg_upsert_asset,
    pg_register_scanned_asset,
    pg_upsert_github_installation,
    pg_upsert_organization,
    pg_upsert_repository,
    pg_upsert_webhook,
    pg_mark_schedule_ran,
    pg_should_fire_event_rule,
    pg_product_conn,
    product_database_url,
    postgres_main_db_requested,
)
from scan_observation import scan_result_observation


def _default_db_path() -> str:
    env = os.environ.get("PQC_SCANNER_DB", "").strip()
    if env:
        return env
    # If DATABASE_URL points at postgres, signal callers via env so get_connection uses PG
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if db_url.startswith("postgresql"):
        os.environ.setdefault("PQC_MAIN_DB_BACKEND", "postgres")
    # Prefer /data if it exists (docker volume). Otherwise, fall back to local backend file.
    data_dir = os.path.dirname("/data/pqc_scanner.db")
    if os.path.isdir(data_dir):
        return "/data/pqc_scanner.db"
    return os.path.join(os.path.dirname(__file__), "pqc_scanner.db")


DB_PATH = _default_db_path()
DEFAULT_ORG_ID = os.environ.get("PQC_DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001").strip() or "00000000-0000-0000-0000-000000000001"
_ORG_ID_CTX: contextvars.ContextVar[str] = contextvars.ContextVar("pqc_org_id", default=DEFAULT_ORG_ID)


def current_organization_id() -> str:
    return str(_ORG_ID_CTX.get() or DEFAULT_ORG_ID)


def set_current_organization_id(org_id: str):
    oid = str(org_id or "").strip() or DEFAULT_ORG_ID
    return _ORG_ID_CTX.set(oid)


def reset_current_organization_id(token) -> None:
    try:
        _ORG_ID_CTX.reset(token)
    except Exception:
        pass



def _table_has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r[1] == col for r in rows)
    except Exception:
        return False

class _PooledConnection(sqlite3.Connection):
    """sqlite3.Connection whose close() hands it back to the idle pool when pooling is on.

    Opening a connection is by far the most expensive part of most requests here: every open reads
    the WAL index and re-parses a ~130-table schema, and when the last connection closes SQLite
    checkpoints and deletes the -wal/-shm files, which the next open recreates. Callers keep using
    `closing(get_connection())`; the pool is invisible to them.
    """

    _pool_path: Optional[str] = None
    _pool_idle: bool = False

    def close(self) -> None:  # noqa: D401 - sqlite3 API
        if self._pool_idle:
            return  # already back in the pool; a second close() must not hand it out twice
        if self._pool_path is not None and _pool_release(self):
            return
        sqlite3.Connection.close(self)


# Opt-in, single-path connection pool. The server enables it at startup for the database it serves
# (see app._lifespan); anything that points PQC_SCANNER_DB elsewhere (tests with temp files that are
# deleted straight after use) gets plain connections that really close.
_POOL_LOCK = threading.Lock()
_POOL: Dict[str, Any] = {"path": None, "idle": []}
_POOL_MAX_IDLE = max(0, int(os.environ.get("PQC_SQLITE_POOL_MAX_IDLE", "32") or 32))


def enable_connection_pool(db_path: Optional[str] = None) -> Optional[str]:
    """Reuse SQLite connections for db_path (default: the current database). Returns the pooled path."""
    if str(os.environ.get("PQC_SQLITE_POOL", "1") or "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    path = db_path or os.environ.get("PQC_SCANNER_DB", DB_PATH)
    disable_connection_pool()
    with _POOL_LOCK:
        _POOL["path"] = path
    return path


def disable_connection_pool() -> None:
    """Stop pooling and really close every idle connection (releases the file handles)."""
    with _POOL_LOCK:
        idle, _POOL["idle"], _POOL["path"] = list(_POOL["idle"]), [], None
    for conn in idle:
        conn._pool_idle = False
        conn._pool_path = None
        try:
            sqlite3.Connection.close(conn)
        except Exception:
            pass


def _pool_release(conn: "_PooledConnection") -> bool:
    """Reset per-connection state and park the connection. False means: really close it."""
    if _POOL["path"] is None or conn._pool_path != _POOL["path"]:
        return False
    try:
        if conn.in_transaction:
            conn.rollback()  # close() would have discarded uncommitted work; keep that contract
        conn.row_factory = None
        conn.text_factory = str
        conn.isolation_level = ""
        conn.execute("PRAGMA foreign_keys=OFF")  # some writers turn it on for their own statements
    except Exception:
        return False
    with _POOL_LOCK:
        if _POOL["path"] != conn._pool_path or len(_POOL["idle"]) >= _POOL_MAX_IDLE:
            return False
        conn._pool_idle = True
        _POOL["idle"].append(conn)
    return True


def _pool_checkout(db_path: str) -> Optional["_PooledConnection"]:
    if _POOL["path"] != db_path:
        return None
    with _POOL_LOCK:
        if _POOL["path"] != db_path or not _POOL["idle"]:
            return None
        conn = _POOL["idle"].pop()
    conn._pool_idle = False
    return conn


def _new_sqlite_connection(db_path: str, factory: Any = sqlite3.Connection) -> sqlite3.Connection:
    """Open a fresh SQLite connection with performance PRAGMAs."""
    conn = sqlite3.connect(db_path, check_same_thread=False, factory=factory)
    try:
        conn.execute("PRAGMA journal_mode=WAL")   # WAL: concurrent readers don't block writers
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL") # Safe with WAL; faster than FULL
        conn.execute("PRAGMA cache_size=-8000")   # 8 MB page cache per connection
    except Exception:
        pass
    return conn


def pooled_sqlite_connection(db_path: str) -> Optional[sqlite3.Connection]:
    """A pooled connection for db_path when the pool serves that path, else None (caller opens its own)."""
    if _POOL["path"] != db_path:
        return None
    return get_connection()


# Per-process memo of "CREATE TABLE IF NOT EXISTS"-style schema work that used to run on every call.
# Keyed by database path and cleared whenever the connection layer switches database (the same trigger
# that re-runs the core _ensure_* migrations), so a fresh database always gets its tables.
_SCHEMA_ONCE: set = set()
_WEBHOOK_CLAIM_COLUMNS_READY: set = set()


def _current_sqlite_path() -> str:
    return os.environ.get('PQC_SCANNER_DB', DB_PATH)


def schema_ensured(key: str) -> bool:
    path = _current_sqlite_path()
    return path == _schema_initialized_db_path and (key, path) in _SCHEMA_ONCE


def mark_schema_ensured(key: str) -> None:
    path = _current_sqlite_path()
    if path == _schema_initialized_db_path:
        _SCHEMA_ONCE.add((key, path))


def _ensure_webhook_claim_columns_once(conn: sqlite3.Connection, db_path: str) -> None:
    """Claim/lease columns on webhook_events. Once they exist (or the ALTER reports they do) this is a no-op."""
    if db_path in _WEBHOOK_CLAIM_COLUMNS_READY:
        return
    ready = True
    for column in ("claimed_at", "claimed_by"):
        try:
            conn.execute(f"ALTER TABLE webhook_events ADD COLUMN {column} TEXT DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                ready = False  # e.g. table not created yet: try again on a later connection
        except Exception:
            ready = False
    if ready:
        _WEBHOOK_CLAIM_COLUMNS_READY.add(db_path)


def get_connection():
    # Fresh (or pooled) connection per call; closing() callers manage lifetime.
    # WAL mode means concurrent connections are cheap and non-blocking.
    global _schema_initialized_db_path
    db_path = os.environ.get('PQC_SCANNER_DB', DB_PATH)
    pooled = _pool_checkout(db_path)
    if pooled is not None and _schema_initialized_db_path == db_path:
        return pooled
    if pooled is not None:
        conn = pooled
    elif _POOL["path"] == db_path:
        conn = _new_sqlite_connection(db_path, factory=_PooledConnection)
        conn._pool_path = db_path
    else:
        conn = _new_sqlite_connection(db_path)

    # Ensure claim/lease columns exist (safe if already present)
    _ensure_webhook_claim_columns_once(conn, db_path)

    # Run schema migrations if init_db() has not run for this SQLite file.
    if (not _schema_initialized.is_set()) or (_schema_initialized_db_path != db_path):
        _SCHEMA_ONCE.clear()
        _WEBHOOK_CLAIM_COLUMNS_READY.discard(db_path)
        _ensure_columns(conn)
        _ensure_sprint5_tables(conn)
        _ensure_integrations_tables(conn)
        _ensure_sprint11_tables(conn)
        _ensure_sprint12_tables(conn)
        _ensure_sprint13_tables(conn)
        _ensure_flight_recorder_tables(conn)
        _ensure_vendor_attestation_tables(conn)
        _ensure_sprint14_tables(conn)
        try:
            if conn.in_transaction:
                conn.commit()
        except Exception:
            pass
        _schema_initialized_db_path = db_path
        _schema_initialized.set()

    return conn



def _parse_iso_datetime(dt_str: str) -> datetime:
    """Parse an ISO datetime string into a naive UTC datetime.

    Accepts:
      - naive ISO strings (e.g. 2026-01-06T12:34:56.123456)
      - 'Z' suffix (UTC)
      - timezone offsets (e.g. +00:00)
    """
    if not dt_str:
        return datetime.utcfromtimestamp(0)

    s = str(dt_str).strip()
    try:
        # Support 'Z' (UTC) and offset-aware timestamps.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        # Fallback for a few common formats
        s2 = s[:-1] if s.endswith("Z") else s
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s2, fmt)
            except Exception:
                pass

    return datetime.utcfromtimestamp(0)

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _iso_z(dt: datetime) -> str:
    """ISO-8601 UTC with a trailing Z.

    Not isoformat()+"Z": a timezone-aware datetime already ends in "+00:00", so appending "Z"
    yields "...+00:00Z", which Postgres rejects as invalid timestamptz. SQLite stored it as text,
    so schedule rows written this way only failed once the deployment moved to Postgres.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _claim_token() -> str:
    return uuid.uuid4().hex


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """
    Ensure the scans table exists and has the expected columns.
    If you previously created an older schema, we ALTER TABLE to add missing columns.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            progress_json TEXT NOT NULL,
            error_text TEXT NOT NULL,
            results_json TEXT NOT NULL,
            summary_json TEXT NOT NULL
        )
        """
    )

    # Baselines table: map an asset (host:port) to a baseline scan id.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            baseline_scan_id TEXT NOT NULL,
            set_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, asset_key)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines (baseline_scan_id)")
    scan_cols = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    # Assets inventory table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            confidentiality_lifetime TEXT NOT NULL,
            notes TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, asset_key)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets (owner)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_team ON assets (team)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_env ON assets (environment)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets (criticality)")

    asset_cols = {row[1] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}

    # Tags (many-to-many)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_tags (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            tag TEXT NOT NULL,
            PRIMARY KEY(organization_id, asset_key, tag)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags (tag)")

    def add_scan(col: str, ddl: str):
        if col not in scan_cols:
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    raise

    def add_asset(col: str, ddl: str):
        if col not in asset_cols:
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    raise

    add_scan("organization_id", "ALTER TABLE scans ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
    try:
        conn.execute("UPDATE scans SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id)")

    add_scan("progress_json", "ALTER TABLE scans ADD COLUMN progress_json TEXT NOT NULL DEFAULT '{}'")
    add_scan("error_text", "ALTER TABLE scans ADD COLUMN error_text TEXT NOT NULL DEFAULT ''")

    add_scan("job_id", "ALTER TABLE scans ADD COLUMN job_id TEXT NOT NULL DEFAULT ''")
    add_scan("job_state", "ALTER TABLE scans ADD COLUMN job_state TEXT NOT NULL DEFAULT ''")
    add_scan("job_started_at", "ALTER TABLE scans ADD COLUMN job_started_at TEXT NOT NULL DEFAULT ''")
    add_scan("job_finished_at", "ALTER TABLE scans ADD COLUMN job_finished_at TEXT NOT NULL DEFAULT ''")

    add_scan("results_json", "ALTER TABLE scans ADD COLUMN results_json TEXT NOT NULL DEFAULT '[]'")
    add_scan("summary_json", "ALTER TABLE scans ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'")

    add_asset("metadata_json", "ALTER TABLE assets ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'")
    add_asset("repository_id", "ALTER TABLE assets ADD COLUMN repository_id INTEGER NOT NULL DEFAULT 0")

    conn.commit()


def _ensure_sprint5_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 5 tables exist (collections, schedules, scan_results)."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            targets_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        '''
    )

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            collection_id INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            interval_minutes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL,
            next_run_at TEXT NOT NULL,
            last_scan_id TEXT NOT NULL,
            FOREIGN KEY(collection_id) REFERENCES collections(id) ON DELETE CASCADE
        )
        '''
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_collection ON schedules(collection_id)")
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(collections)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE collections ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        if "description" not in cols:
            conn.execute("ALTER TABLE collections ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE collections SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(organization_id)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_collections_org_name_unique ON collections(organization_id, name)")
    except Exception:
        pass
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(schedules)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE schedules ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE schedules SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_org ON schedules(organization_id)")
    except Exception:
        pass

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            quantum_score REAL NOT NULL,
            findings_count INTEGER NOT NULL,
            pqc_relevance TEXT NOT NULL,
            tls_version TEXT NOT NULL,
            key_type TEXT NOT NULL,
            sig_algorithm TEXT NOT NULL,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            key_bits INTEGER,
            key_curve TEXT,
            cipher_name TEXT,
            scan_status TEXT,
            key_exchange TEXT
        )
        '''
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_asset ON scan_results(asset_key, scanned_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)")
    _ensure_scan_result_observation_columns(conn)


#: Key types whose size and curve are fixed by the algorithm itself, so they can be backfilled onto
#: historic rows without inventing a measurement. RSA and bare "EC" cannot: a stored "RSA" could be
#: 2048 or 4096 and a stored "EC" could be P-256 or P-521, so those rows keep a NULL key_bits, which
#: every reader must render as "not observed" rather than as a number.
_FIXED_SIZE_KEY_TYPES: Dict[str, tuple] = {
    "ed25519": (256, "Curve25519"),
    "ed448":   (448, "Curve448"),
    "x25519":  (256, "Curve25519"),
    "x448":    (448, "Curve448"),
}


def _ensure_scan_result_observation_columns(conn: sqlite3.Connection) -> None:
    """Add the observed-key columns to scan_results, on new and already-populated databases.

    `scan_results` recorded `key_type` but never the key size, the curve, the negotiated cipher or
    whether the scan actually succeeded. Every reader therefore had to guess: the org-wide CBOM
    reported the whole estate as RSA-2048/ECDSA-P256 and the HNDL model priced every RSA asset at
    the RSA-2048 Q-Day probability. These columns are deliberately NULLable -- NULL means "this scan
    predates the column", which is not the same as zero-bit key, and readers must not conflate them.
    """
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_results)").fetchall()}
    except sqlite3.OperationalError:
        return  # table does not exist yet; CREATE TABLE above will include the columns
    added = False
    for name, ddl in (
        ("key_bits", "ALTER TABLE scan_results ADD COLUMN key_bits INTEGER"),
        ("key_curve", "ALTER TABLE scan_results ADD COLUMN key_curve TEXT"),
        ("cipher_name", "ALTER TABLE scan_results ADD COLUMN cipher_name TEXT"),
        ("scan_status", "ALTER TABLE scan_results ADD COLUMN scan_status TEXT"),
        ("key_exchange", "ALTER TABLE scan_results ADD COLUMN key_exchange TEXT"),
    ):
        if name in cols:
            continue
        try:
            conn.execute(ddl)
            added = True
        except sqlite3.OperationalError as exc:
            # A duplicate column means a concurrent caller got there first, and a missing table
            # means this ran before the CREATE TABLE above. Neither is a reason to abort
            # init_db() and take every other table down with it.
            message = str(exc).lower()
            if "duplicate column name" not in message and "no such table" not in message:
                raise
    if not added:
        # Nothing changed, so there is nothing to backfill. _ensure_sprint5_tables runs on several
        # code paths; scanning the whole table on each of them would be a full pass over every scan
        # result the deployment has ever recorded, for no work.
        return
    # Backfill only what the stored key_type determines on its own.
    try:
        for key_type, (bits, curve) in _FIXED_SIZE_KEY_TYPES.items():
            conn.execute(
                "UPDATE scan_results SET key_bits=?, key_curve=? "
                "WHERE key_bits IS NULL AND LOWER(TRIM(key_type))=?",
                (bits, curve, key_type),
            )
    except sqlite3.OperationalError:
        pass  # columns were not added on this connection; nothing to backfill

def _ensure_integrations_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 8 integrations tables exist (webhooks + delivery log)."""
    conn.execute(
    '''
    CREATE TABLE IF NOT EXISTS webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT NOT NULL,
        credential_id INTEGER,   -- <--- ADD THIS LINE
        events_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
        timeout_seconds INTEGER NOT NULL DEFAULT 10,
        UNIQUE(organization_id, name)
    )
    '''
)


    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            webhook_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            error_text TEXT NOT NULL,
            response_excerpt TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt_at TEXT NOT NULL DEFAULT '',
            next_attempt_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
            UNIQUE(organization_id, webhook_id, dedupe_key)
        )
        '''
    )

    # Backward-compatible migrations if table already existed with fewer columns

    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(webhooks)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE webhooks SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
        if "events_json" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN events_json TEXT NOT NULL DEFAULT '[]'")
        if "enabled" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        if "created_at" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        if "credential_id" not in cols:  # <--- ADD THIS
            conn.execute("ALTER TABLE webhooks ADD COLUMN credential_id INTEGER")
        if "rate_limit_per_minute" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN rate_limit_per_minute INTEGER NOT NULL DEFAULT 60")
        if "timeout_seconds" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 10")
    except Exception:
        pass


    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE webhook_events SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
        if "status" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
        if "http_status" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN http_status INTEGER NOT NULL DEFAULT 0")
        if "error_text" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN error_text TEXT NOT NULL DEFAULT ''")
        if "response_excerpt" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN response_excerpt TEXT NOT NULL DEFAULT ''")
        if "attempts" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        if "last_attempt_at" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
        if "next_attempt_at" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN next_attempt_at TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_org ON webhook_events(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook ON webhook_events(webhook_id)")


def _ensure_sprint11_tables(conn: sqlite3.Connection) -> None:
    """Sprint 11: repositories + asset metadata/repo linkage."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            html_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(organization_id, name)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repositories_name ON repositories(name)")

    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
        if "metadata_json" not in cols:
            conn.execute("ALTER TABLE assets ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'")
        if "repository_id" not in cols:
            conn.execute("ALTER TABLE assets ADD COLUMN repository_id INTEGER NOT NULL DEFAULT 0")
    except Exception:
        # Don't crash startup if PRAGMA fails; other calls re-run this.
        pass


def _ensure_sprint12_tables(conn: sqlite3.Connection) -> None:
    """Sprint 12: remediation tracking table."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS remediations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            repo_id INTEGER NOT NULL DEFAULT 0,
            vulnerability TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            original_content TEXT NOT NULL DEFAULT '',
            suggested_fix TEXT NOT NULL DEFAULT '',
            suggested_content TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            pr_url TEXT NOT NULL DEFAULT '',
            pr_branch TEXT NOT NULL DEFAULT '',
            pr_base_branch TEXT NOT NULL DEFAULT '',
            github_credential_id INTEGER NOT NULL DEFAULT 0,
            branch_cleanup_status TEXT NOT NULL DEFAULT '',
            branch_cleanup_at TEXT NOT NULL DEFAULT '',
            branch_cleanup_error TEXT NOT NULL DEFAULT '',
            branch_cleanup_attempts INTEGER NOT NULL DEFAULT 0,
            review_note TEXT NOT NULL DEFAULT '',
            merged_at TEXT NOT NULL DEFAULT '',
            verification_scan_id TEXT NOT NULL DEFAULT '',
            closed_at TEXT NOT NULL DEFAULT '',
            parent_remediation_id INTEGER NOT NULL DEFAULT 0,
            origin_kind TEXT NOT NULL DEFAULT '',
            drift_followup_remediation_id INTEGER NOT NULL DEFAULT 0,
            drift_status TEXT NOT NULL DEFAULT '',
            last_drift_checked_at TEXT NOT NULL DEFAULT '',
            drift_detected_at TEXT NOT NULL DEFAULT '',
            drift_acknowledged_at TEXT NOT NULL DEFAULT '',
            drift_acknowledged_by TEXT NOT NULL DEFAULT '',
            drift_ack_note TEXT NOT NULL DEFAULT '',
            drift_details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_repo_id ON remediations(repo_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_asset_key ON remediations(asset_key)")
    # Add columns that may be missing from older DB snapshots before creating indexes on them
    try:
        rem_cols = {row[1] for row in conn.execute("PRAGMA table_info(remediations)").fetchall()}
        for col, ddl in [
            ("branch_cleanup_status", "ALTER TABLE remediations ADD COLUMN branch_cleanup_status TEXT NOT NULL DEFAULT ''"),
            ("branch_cleanup_at",     "ALTER TABLE remediations ADD COLUMN branch_cleanup_at TEXT NOT NULL DEFAULT ''"),
            ("branch_cleanup_error",  "ALTER TABLE remediations ADD COLUMN branch_cleanup_error TEXT NOT NULL DEFAULT ''"),
            ("branch_cleanup_attempts","ALTER TABLE remediations ADD COLUMN branch_cleanup_attempts INTEGER NOT NULL DEFAULT 0"),
            ("parent_remediation_id", "ALTER TABLE remediations ADD COLUMN parent_remediation_id INTEGER NOT NULL DEFAULT 0"),
            ("drift_status",          "ALTER TABLE remediations ADD COLUMN drift_status TEXT NOT NULL DEFAULT ''"),
            ("drift_detected_at",     "ALTER TABLE remediations ADD COLUMN drift_detected_at TEXT NOT NULL DEFAULT ''"),
            ("drift_ack_at",          "ALTER TABLE remediations ADD COLUMN drift_ack_at TEXT NOT NULL DEFAULT ''"),
            ("drift_ack_actor",       "ALTER TABLE remediations ADD COLUMN drift_ack_actor TEXT NOT NULL DEFAULT ''"),
            ("drift_ack_note",        "ALTER TABLE remediations ADD COLUMN drift_ack_note TEXT NOT NULL DEFAULT ''"),
            ("drift_details_json",    "ALTER TABLE remediations ADD COLUMN drift_details_json TEXT NOT NULL DEFAULT '{}'"),
            ("review_note",           "ALTER TABLE remediations ADD COLUMN review_note TEXT NOT NULL DEFAULT ''"),
            ("merged_at",             "ALTER TABLE remediations ADD COLUMN merged_at TEXT NOT NULL DEFAULT ''"),
        ]:
            if col not in rem_cols:
                conn.execute(ddl)
    except Exception:
        pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_branch_cleanup ON remediations(branch_cleanup_status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_parent_id ON remediations(parent_remediation_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_drift_status ON remediations(drift_status)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS migration_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL DEFAULT '',
            repository_name TEXT NOT NULL DEFAULT '',
            repo_id INTEGER NOT NULL DEFAULT 0,
            file_path TEXT NOT NULL DEFAULT '',
            rule_id TEXT NOT NULL DEFAULT '',
            legacy_dependency TEXT NOT NULL DEFAULT '',
            migration_target TEXT NOT NULL DEFAULT '',
            safety_class TEXT NOT NULL DEFAULT 'migration_task',
            confidence TEXT NOT NULL DEFAULT 'medium',
            safety_reason TEXT NOT NULL DEFAULT '',
            recommended_workflow TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            source TEXT NOT NULL DEFAULT 'repo_crypto_discovery',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_migration_tasks_status ON migration_tasks(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_migration_tasks_repo_id ON migration_tasks(repo_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_migration_tasks_asset_key ON migration_tasks(asset_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_migration_tasks_repository_name ON migration_tasks(repository_name)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS validation_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            remediation_id INTEGER NOT NULL DEFAULT 0,
            validator_type TEXT NOT NULL DEFAULT 'auto',
            status TEXT NOT NULL DEFAULT 'queued',
            git_ref TEXT NOT NULL DEFAULT '',
            job_id TEXT NOT NULL DEFAULT '',
            stdout TEXT NOT NULL DEFAULT '',
            stderr TEXT NOT NULL DEFAULT '',
            exit_code INTEGER NOT NULL DEFAULT -1,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_remediation_id ON validation_jobs(remediation_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_status ON validation_jobs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_job_id ON validation_jobs(job_id)")

    # Backward-compatible migrations
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(remediations)").fetchall()}
        if "asset_key" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN asset_key TEXT NOT NULL DEFAULT ''")
        if "repo_id" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN repo_id INTEGER NOT NULL DEFAULT 0")
        if "vulnerability" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN vulnerability TEXT NOT NULL DEFAULT ''")
        if "file_path" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN file_path TEXT NOT NULL DEFAULT ''")
        if "original_content" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN original_content TEXT NOT NULL DEFAULT ''")
        if "suggested_fix" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN suggested_fix TEXT NOT NULL DEFAULT ''")
        if "suggested_content" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN suggested_content TEXT NOT NULL DEFAULT ''")
        if "status" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        if "pr_url" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN pr_url TEXT NOT NULL DEFAULT ''")
        if "pr_branch" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN pr_branch TEXT NOT NULL DEFAULT ''")
        if "pr_base_branch" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN pr_base_branch TEXT NOT NULL DEFAULT ''")
        if "github_credential_id" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN github_credential_id INTEGER NOT NULL DEFAULT 0")
        if "branch_cleanup_status" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN branch_cleanup_status TEXT NOT NULL DEFAULT ''")
        if "branch_cleanup_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN branch_cleanup_at TEXT NOT NULL DEFAULT ''")
        if "branch_cleanup_error" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN branch_cleanup_error TEXT NOT NULL DEFAULT ''")
        if "branch_cleanup_attempts" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN branch_cleanup_attempts INTEGER NOT NULL DEFAULT 0")
        if "review_note" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN review_note TEXT NOT NULL DEFAULT ''")
        if "merged_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN merged_at TEXT NOT NULL DEFAULT ''")
        if "verification_scan_id" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN verification_scan_id TEXT NOT NULL DEFAULT ''")
        if "closed_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN closed_at TEXT NOT NULL DEFAULT ''")
        if "parent_remediation_id" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN parent_remediation_id INTEGER NOT NULL DEFAULT 0")
        if "origin_kind" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN origin_kind TEXT NOT NULL DEFAULT ''")
        if "drift_followup_remediation_id" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_followup_remediation_id INTEGER NOT NULL DEFAULT 0")
        if "drift_status" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_status TEXT NOT NULL DEFAULT ''")
        if "last_drift_checked_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN last_drift_checked_at TEXT NOT NULL DEFAULT ''")
        if "drift_detected_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_detected_at TEXT NOT NULL DEFAULT ''")
        if "drift_acknowledged_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_acknowledged_at TEXT NOT NULL DEFAULT ''")
        if "drift_acknowledged_by" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_acknowledged_by TEXT NOT NULL DEFAULT ''")
        if "drift_ack_note" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_ack_note TEXT NOT NULL DEFAULT ''")
        if "drift_details_json" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN drift_details_json TEXT NOT NULL DEFAULT '{}'")
        if "created_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_parent_id ON remediations(parent_remediation_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_drift_status ON remediations(drift_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_branch_cleanup ON remediations(branch_cleanup_status)")
    except Exception:
        pass

    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(validation_jobs)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        if "remediation_id" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN remediation_id INTEGER NOT NULL DEFAULT 0")
        if "validator_type" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN validator_type TEXT NOT NULL DEFAULT 'auto'")
        if "status" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
        if "git_ref" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN git_ref TEXT NOT NULL DEFAULT ''")
        if "job_id" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN job_id TEXT NOT NULL DEFAULT ''")
        if "stdout" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN stdout TEXT NOT NULL DEFAULT ''")
        if "stderr" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN stderr TEXT NOT NULL DEFAULT ''")
        if "exit_code" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN exit_code INTEGER NOT NULL DEFAULT -1")
        if "details_json" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'")
        if "created_at" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        if "finished_at" not in cols:
            conn.execute("ALTER TABLE validation_jobs ADD COLUMN finished_at TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass


def _ensure_sprint13_tables(conn: sqlite3.Connection) -> None:
    """Sprint 13: append-only audit log with SHA-256 hash chaining.
    SQLite triggers prevent UPDATE and DELETE. The hash chain links each entry
    to the previous one, enabling tamper detection. For full immutability
    guarantees (defence against DBA-level attacks), export the chain to
    WORM or object-lock storage and verify hashes externally."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            actor_id TEXT NOT NULL DEFAULT '',
            actor_role TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            resource_type TEXT NOT NULL DEFAULT '',
            resource_id TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL DEFAULT 'allow',
            reason TEXT NOT NULL DEFAULT '',
            details_json TEXT NOT NULL DEFAULT '{}',
            prev_hash TEXT NOT NULL DEFAULT '',
            entry_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_decision ON audit_logs(decision)")
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit_logs is immutable');
        END;
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit_logs is immutable');
        END;
        """
    )


def _ensure_flight_recorder_tables(conn: sqlite3.Connection) -> None:
    """Intent-based cryptographic governance event log."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS flight_recorder_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            actor_type TEXT NOT NULL DEFAULT 'human',
            actor_id TEXT NOT NULL DEFAULT '',
            actor_role TEXT NOT NULL DEFAULT '',
            intent TEXT NOT NULL DEFAULT '',
            resource_type TEXT NOT NULL DEFAULT '',
            resource_id TEXT NOT NULL DEFAULT '',
            policy_version TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL DEFAULT 'allowed',
            outcome TEXT NOT NULL DEFAULT 'pending',
            reason TEXT NOT NULL DEFAULT '',
            evidence_refs_json TEXT NOT NULL DEFAULT '{}',
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flight_events_org ON flight_recorder_events(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flight_events_created_at ON flight_recorder_events(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flight_events_intent ON flight_recorder_events(intent)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flight_events_resource ON flight_recorder_events(resource_type, resource_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flight_events_decision ON flight_recorder_events(decision)")


def _ensure_vendor_attestation_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_attestation_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            vendor_name TEXT NOT NULL DEFAULT '',
            vendor_email TEXT NOT NULL DEFAULT '',
            token_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'open',
            expires_at TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_attestation_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            invite_id INTEGER NOT NULL,
            vendor_name TEXT NOT NULL DEFAULT '',
            submitted_by TEXT NOT NULL DEFAULT '',
            signer_title TEXT NOT NULL DEFAULT '',
            domains_json TEXT NOT NULL DEFAULT '[]',
            answers_json TEXT NOT NULL DEFAULT '{}',
            evidence_refs_json TEXT NOT NULL DEFAULT '{}',
            readiness_score REAL NOT NULL DEFAULT 0,
            signed_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(invite_id) REFERENCES vendor_attestation_invites(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_attest_invites_org ON vendor_attestation_invites(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_attest_invites_status ON vendor_attestation_invites(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_attest_submissions_org ON vendor_attestation_submissions(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_attest_submissions_invite ON vendor_attestation_submissions(invite_id)")


def _pk_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return []
    pairs = []
    for r in rows:
        try:
            order = int(r[5] or 0)
        except Exception:
            order = 0
        if order > 0:
            pairs.append((order, str(r[1])))
    pairs.sort(key=lambda x: x[0])
    return [name for _, name in pairs]


def _has_unique_index_on_columns(conn: sqlite3.Connection, table: str, columns: List[str]) -> bool:
    want = [str(c).lower() for c in (columns or [])]
    if not want:
        return False
    try:
        idx_rows = conn.execute(f"PRAGMA index_list({table})").fetchall()
    except Exception:
        return False
    for idx in idx_rows:
        try:
            is_unique = int(idx[2] or 0) == 1
        except Exception:
            is_unique = False
        if not is_unique:
            continue
        idx_name = str(idx[1] or "")
        if not idx_name:
            continue
        safe_idx = idx_name.replace("'", "''")
        cols = [str(r[2] or "").lower() for r in conn.execute(f"PRAGMA index_info('{safe_idx}')").fetchall()]
        if cols == want:
            return True
    return False


def _migrate_baselines_to_org_pk(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(baselines)").fetchall()}
    if not cols:
        return
    if _pk_columns(conn, "baselines") == ["organization_id", "asset_key"]:
        return

    conn.execute("DROP TABLE IF EXISTS __baselines_m14_new")
    conn.execute(
        """
        CREATE TABLE __baselines_m14_new (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            baseline_scan_id TEXT NOT NULL,
            set_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, asset_key)
        )
        """
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO __baselines_m14_new (organization_id, asset_key, baseline_scan_id, set_at)
        SELECT
            CASE WHEN COALESCE(organization_id, '') = '' THEN ? ELSE organization_id END,
            asset_key, baseline_scan_id, set_at
        FROM baselines
        """,
        (DEFAULT_ORG_ID,),
    )
    conn.execute("ALTER TABLE baselines RENAME TO __baselines_m14_old")
    conn.execute("ALTER TABLE __baselines_m14_new RENAME TO baselines")
    conn.execute("DROP TABLE __baselines_m14_old")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines (baseline_scan_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_org ON baselines (organization_id)")


def _migrate_assets_to_org_pk(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()}
    if not cols:
        return
    if _pk_columns(conn, "assets") == ["organization_id", "asset_key"]:
        return

    conn.execute("DROP TABLE IF EXISTS __assets_m14_new")
    conn.execute(
        """
        CREATE TABLE __assets_m14_new (
            organization_id TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            confidentiality_lifetime TEXT NOT NULL,
            notes TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            repository_id INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, asset_key)
        )
        """
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO __assets_m14_new (
            organization_id, asset_key, owner, team, environment, criticality,
            confidentiality_lifetime, notes, metadata_json, repository_id, updated_at
        )
        SELECT
            CASE WHEN COALESCE(organization_id, '') = '' THEN ? ELSE organization_id END,
            asset_key,
            COALESCE(owner, ''),
            COALESCE(team, ''),
            COALESCE(environment, ''),
            COALESCE(criticality, ''),
            COALESCE(confidentiality_lifetime, ''),
            COALESCE(notes, ''),
            COALESCE(metadata_json, '{}'),
            COALESCE(repository_id, 0),
            COALESCE(updated_at, '')
        FROM assets
        """,
        (DEFAULT_ORG_ID,),
    )
    conn.execute("ALTER TABLE assets RENAME TO __assets_m14_old")
    conn.execute("ALTER TABLE __assets_m14_new RENAME TO assets")
    conn.execute("DROP TABLE __assets_m14_old")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets (owner)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_team ON assets (team)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_env ON assets (environment)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets (criticality)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_org ON assets (organization_id)")


def _migrate_repositories_to_org_unique(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(repositories)").fetchall()}
    if not cols:
        return
    has_composite_unique = _has_unique_index_on_columns(conn, "repositories", ["organization_id", "name"])
    has_legacy_name_unique = _has_unique_index_on_columns(conn, "repositories", ["name"])
    if has_composite_unique and not has_legacy_name_unique:
        return

    conn.execute("DROP TABLE IF EXISTS __repositories_m14_new")
    conn.execute(
        """
        CREATE TABLE __repositories_m14_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            html_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(organization_id, name)
        )
        """
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO __repositories_m14_new (id, organization_id, name, html_url, created_at, updated_at)
        SELECT
            id,
            CASE WHEN COALESCE(organization_id, '') = '' THEN ? ELSE organization_id END,
            name,
            COALESCE(html_url, ''),
            COALESCE(created_at, ''),
            COALESCE(updated_at, '')
        FROM repositories
        ORDER BY id ASC
        """,
        (DEFAULT_ORG_ID,),
    )
    conn.execute("ALTER TABLE repositories RENAME TO __repositories_m14_old")
    conn.execute("ALTER TABLE __repositories_m14_new RENAME TO repositories")
    conn.execute("DROP TABLE __repositories_m14_old")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repositories_name ON repositories(name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repositories_org ON repositories(organization_id)")


def _ensure_sprint14_tables(conn: sqlite3.Connection) -> None:
    """Sprint 14.1: organizations + tenant-aware columns."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            plan_type TEXT NOT NULL DEFAULT 'starter',
            subscription_status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS github_installations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            installation_id INTEGER NOT NULL,
            account_login TEXT NOT NULL DEFAULT '',
            account_type TEXT NOT NULL DEFAULT '',
            target_type TEXT NOT NULL DEFAULT '',
            permissions_json TEXT NOT NULL DEFAULT '{}',
            repositories_count INTEGER NOT NULL DEFAULT 0,
            suspended_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(organization_id, installation_id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_installations_org ON github_installations(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_installations_installation_id ON github_installations(installation_id)")

    try:
        assets_cols = {row[1] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
        if "organization_id" not in assets_cols:
            conn.execute("ALTER TABLE assets ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        # Backfill legacy empty org ids so tenant-scoped queries stay consistent.
        conn.execute("UPDATE assets SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        tags_cols = {row[1] for row in conn.execute("PRAGMA table_info(asset_tags)").fetchall()}
        if "organization_id" not in tags_cols:
            conn.execute("ALTER TABLE asset_tags ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE asset_tags SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        baseline_cols = {row[1] for row in conn.execute("PRAGMA table_info(baselines)").fetchall()}
        if "organization_id" not in baseline_cols:
            conn.execute("ALTER TABLE baselines ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE baselines SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        results_cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_results)").fetchall()}
        if "organization_id" not in results_cols:
            conn.execute("ALTER TABLE scan_results ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE scan_results SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        rem_cols = {row[1] for row in conn.execute("PRAGMA table_info(remediations)").fetchall()}
        if "organization_id" not in rem_cols:
            conn.execute("ALTER TABLE remediations ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE remediations SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        repo_cols = {row[1] for row in conn.execute("PRAGMA table_info(repositories)").fetchall()}
        if "organization_id" not in repo_cols:
            conn.execute("ALTER TABLE repositories ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE repositories SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        audit_cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_logs)").fetchall()}
        if "organization_id" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE audit_logs SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    try:
        _migrate_baselines_to_org_pk(conn)
    except Exception:
        pass
    try:
        _migrate_assets_to_org_pk(conn)
    except Exception:
        pass
    try:
        _migrate_repositories_to_org_unique(conn)
    except Exception:
        pass

    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_tags_org ON asset_tags(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_org ON baselines(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_org ON scan_results(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_remediations_org ON remediations(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repositories_org ON repositories(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repositories_name ON repositories(name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id)")


def _compute_audit_entry_hash(
    prev_hash: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    decision: str,
    reason: str,
    details_json: str,
    created_at: str,
) -> str:
    payload = "|".join(
        [
            str(prev_hash or ""),
            str(actor_id or ""),
            str(actor_role or ""),
            str(action or ""),
            str(resource_type or ""),
            str(resource_id or ""),
            str(decision or ""),
            str(reason or ""),
            str(details_json or "{}"),
            str(created_at or ""),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _ensure_event_rules_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 8 rules engine tables exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS event_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,

            -- routing
            event_types_json TEXT NOT NULL DEFAULT '[]',
            webhook_ids_json TEXT NOT NULL DEFAULT '[]',

            -- filters
            rule_ids_json TEXT NOT NULL DEFAULT '[]',
            environments_json TEXT NOT NULL DEFAULT '[]',
            teams_json TEXT NOT NULL DEFAULT '[]',
            criticalities_json TEXT NOT NULL DEFAULT '[]',
            tags_json TEXT NOT NULL DEFAULT '[]',

            -- conditions
            min_severity TEXT NOT NULL DEFAULT '',
            quantum_score_min REAL NOT NULL DEFAULT -1,

            -- firing controls
            fire_mode TEXT NOT NULL DEFAULT 'always',
            cooldown_minutes INTEGER NOT NULL DEFAULT 0,

            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    try:
        er_cols = {row[1] for row in conn.execute("PRAGMA table_info(event_rules)").fetchall()}
        if "organization_id" not in er_cols:
            conn.execute("ALTER TABLE event_rules ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rules_org ON event_rules(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rules_enabled ON event_rules(enabled)")


def _ensure_login_events_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            user_id        TEXT NOT NULL DEFAULT '',
            actor_role     TEXT NOT NULL DEFAULT '',
            login_method   TEXT NOT NULL DEFAULT '',
            ip_address     TEXT NOT NULL DEFAULT '',
            user_agent     TEXT NOT NULL DEFAULT '',
            created_at     TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_events_org      ON login_events(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_events_user     ON login_events(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_events_created  ON login_events(created_at)")


def record_login_event(
    organization_id: str,
    user_id: str,
    actor_role: str,
    login_method: str,
    ip_address: str = "",
    user_agent: str = "",
) -> None:
    if postgres_main_db_requested():
        # Fall back to audit_log for Postgres deployments until Postgres migration is added
        try:
            pg_append_audit_log(
                organization_id=organization_id or DEFAULT_ORG_ID,
                actor_id=user_id,
                actor_role=actor_role,
                action="user.login",
                resource_type="session",
                resource_id=user_id,
                decision="allow",
                reason=login_method,
                details={"ip_address": ip_address, "user_agent": user_agent[:200]},
                created_at=_utc_now_iso(),
            )
        except Exception:
            pass
        return
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_login_events_table(conn)
        conn.execute(
            "INSERT INTO login_events (organization_id, user_id, actor_role, login_method, ip_address, user_agent, created_at) VALUES (?,?,?,?,?,?,?)",
            (
                str(organization_id or DEFAULT_ORG_ID),
                str(user_id or "")[:256],
                str(actor_role or "")[:32],
                str(login_method or "")[:32],
                str(ip_address or "")[:64],
                str(user_agent or "")[:300],
                now,
            ),
        )
        conn.commit()


def list_login_events(
    organization_id: str = "",
    user_id: str = "",
    limit: int = 200,
    since_iso: str = "",
) -> List[Dict[str, Any]]:
    if postgres_main_db_requested():
        return []  # reads from audit_log in Postgres mode â€” use list_audit_logs with action=user.login
    lim = max(1, min(int(limit or 200), 2000))
    org_id = organization_id or ""
    with closing(get_connection()) as conn:
        _ensure_login_events_table(conn)
        conn.row_factory = sqlite3.Row
        where, params = [], []
        if org_id:
            where.append("organization_id = ?"); params.append(org_id)
        if user_id:
            where.append("user_id = ?"); params.append(user_id)
        if since_iso:
            where.append("created_at >= ?"); params.append(since_iso)
        clause = "WHERE " + " AND ".join(where) if where else ""
        rows = conn.execute(
            f"SELECT * FROM login_events {clause} ORDER BY created_at DESC LIMIT ?",
            (*params, lim),
        ).fetchall()
        return [dict(r) for r in rows]


def platform_customer_stats() -> List[Dict[str, Any]]:
    """Cross-org stats for the platform admin dashboard.

    Returns one row per organization with: last_login, scan_count,
    asset_count, remediation_count, user_count, last_scan_at.
    """
    if postgres_main_db_requested():
        return []  # Postgres: query directly via pg_product_conn
    with closing(get_connection()) as conn:
        _ensure_login_events_table(conn)
        conn.row_factory = sqlite3.Row
        orgs = conn.execute(
            "SELECT id, name, plan_type, subscription_status, created_at, updated_at FROM organizations ORDER BY updated_at DESC LIMIT 1000"
        ).fetchall()
        stats = []
        for org in orgs:
            oid = str(org["id"])
            scan_count = (conn.execute(
                "SELECT COUNT(*) FROM scans WHERE organization_id=?", (oid,)
            ).fetchone() or [0])[0]
            asset_count = (conn.execute(
                "SELECT COUNT(*) FROM assets WHERE organization_id=?", (oid,)
            ).fetchone() or [0])[0]
            rem_count = (conn.execute(
                "SELECT COUNT(*) FROM remediations WHERE organization_id=?", (oid,)
            ).fetchone() or [0])[0]
            try:
                last_scan = conn.execute(
                    "SELECT created_at FROM scans WHERE organization_id=? ORDER BY created_at DESC LIMIT 1", (oid,)
                ).fetchone()
                last_scan_at = str(last_scan[0]) if last_scan else ""
            except Exception:
                last_scan_at = ""
            last_login_row = conn.execute(
                "SELECT created_at, user_id FROM login_events WHERE organization_id=? ORDER BY created_at DESC LIMIT 1", (oid,)
            ).fetchone()
            last_login_at  = str(last_login_row[0]) if last_login_row else ""
            last_login_user = str(last_login_row[1]) if last_login_row else ""
            login_count_7d = (conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM login_events WHERE organization_id=? AND created_at >= datetime('now','-7 days')", (oid,)
            ).fetchone() or [0])[0]
            try:
                user_count = (conn.execute(
                    "SELECT COUNT(*) FROM organization_members WHERE organization_id=?", (oid,)
                ).fetchone() or [0])[0]
            except Exception:
                user_count = 0
            stats.append({
                "organization_id":    oid,
                "name":               str(org["name"] or ""),
                "plan_type":          str(org["plan_type"] or "starter"),
                "subscription_status": str(org["subscription_status"] or "active"),
                "created_at":         str(org["created_at"] or ""),
                "updated_at":         str(org["updated_at"] or ""),
                "scan_count":         int(scan_count or 0),
                "asset_count":        int(asset_count or 0),
                "remediation_count":  int(rem_count or 0),
                "user_count":         int(user_count or 0),
                "last_scan_at":       last_scan_at,
                "last_login_at":      last_login_at,
                "last_login_user":    last_login_user,
                "active_users_7d":    int(login_count_7d or 0),
            })
        return stats


def init_db():
    global _schema_initialized_db_path
    if postgres_main_db_requested():
        ensure_postgres_core_schema()
        ensure_postgres_default_org(name="Default Organization")
        return
    db_path = os.environ.get('PQC_SCANNER_DB', DB_PATH)
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        _ensure_sprint5_tables(conn)
        _ensure_integrations_tables(conn)
        _ensure_sprint11_tables(conn)
        _ensure_sprint12_tables(conn)
        _ensure_sprint13_tables(conn)
        _ensure_flight_recorder_tables(conn)
        _ensure_vendor_attestation_tables(conn)
        _ensure_sprint14_tables(conn)
        _ensure_event_rules_tables(conn)   # âœ… ADD THIS ONE LINE
        _ensure_login_events_table(conn)
        now = _utc_now_iso()
        conn.execute(
            """
            INSERT OR IGNORE INTO organizations (id, name, plan_type, subscription_status, created_at, updated_at)
            VALUES (?, ?, 'starter', 'active', ?, ?)
            """,
            (DEFAULT_ORG_ID, "Default Organization", now, now),
        )
        conn.commit()
    # Signal that schema migrations have run â€” get_connection() will skip re-running them
    if _schema_initialized_db_path != db_path:
        _SCHEMA_ONCE.clear()
        _WEBHOOK_CLAIM_COLUMNS_READY.discard(db_path)
    _schema_initialized_db_path = db_path
    _schema_initialized.set()



def save_scan_row(
    scan_id: str,
    status: str,
    created_at: datetime,
    progress: Dict[str, Any],
    error_text: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_save_scan_row(
            org_id,
            scan_id,
            status,
            created_at,
            progress,
            error_text,
            results,
            summary,
        )
        return
    created_at_str = created_at.isoformat()
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        _ensure_sprint5_tables(conn)
        conn.execute(
            '''
            INSERT OR REPLACE INTO scans (id, organization_id, status, created_at, progress_json, error_text, results_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                scan_id,
                org_id,
                status,
                created_at_str,
                json.dumps(progress or {}),
                error_text or "",
                json.dumps(results or []),
                json.dumps(summary or {}),
            ),
        )
        conn.commit()


def update_scan_progress(
    scan_id: str,
    progress: Dict[str, Any],
    status: str = "running",
    error_text: str = "",
) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_update_scan_progress(org_id, scan_id, progress, status=status, error_text=error_text)
        return
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        if _table_has_column(conn, "scans", "error_text"):
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, progress_json = ?, error_text = ?
                WHERE organization_id = ? AND id = ?
                ''',
                (status, json.dumps(progress), error_text or "", org_id, scan_id),
            )
        else:
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, progress_json = ?
                WHERE organization_id = ? AND id = ?
                ''',
                (status, json.dumps(progress), org_id, scan_id),
            )
        conn.commit()

def save_scan_results(
    scan_id: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    status: str = "completed",
    error_text: str = "",
) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_save_scan_results(org_id, scan_id, results, summary, status=status, error_text=error_text)
        return
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        if _table_has_column(conn, "scans", "error_text"):
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, error_text = ?, results_json = ?, summary_json = ?
                WHERE organization_id = ? AND id = ?
                ''',
                (status, error_text or "", json.dumps(results), json.dumps(summary), org_id, scan_id),
            )
        else:
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, results_json = ?, summary_json = ?
                WHERE organization_id = ? AND id = ?
                ''',
                (status, json.dumps(results), json.dumps(summary), org_id, scan_id),
            )
        conn.commit()

def load_scan_row(scan_id: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_load_scan_row(org_id, scan_id)
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, status, created_at, progress_json, error_text, results_json, summary_json,
                   job_id, job_state, job_started_at, job_finished_at
            FROM scans
            WHERE organization_id = ? AND id = ?
            """,
            (org_id, scan_id),
        )
        row = cur.fetchone()

    if not row:
        return None

    id_, status, created_at_str, progress_json, error_text, results_json, summary_json, job_id, job_state, job_started_at, job_finished_at = row
    created_at = _parse_iso_datetime(created_at_str)

    try:
        progress = json.loads(progress_json or "{}")
    except Exception:
        progress = {}

    try:
        results = json.loads(results_json or "[]")
    except Exception:
        results = []

    try:
        summary = json.loads(summary_json or "{}")
    except Exception:
        summary = {}

    return {
        "id": id_,
        "status": status,
        "created_at": created_at,
        "progress": progress,
        "error": error_text or "",
        "results": results,
        "summary": summary,
        "job_id": job_id or "",
        "job_state": job_state or "",
        "job_started_at": job_started_at or "",
        "job_finished_at": job_finished_at or "",
    }


def count_scans() -> int:
    """How many scans this organization has, without fetching them."""
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_count_scans(org_id)
    with closing(get_connection()) as conn:
        row = conn.execute("SELECT COUNT(*) FROM scans WHERE organization_id = ?", (org_id,)).fetchone()
    return int((row or [0])[0] or 0)


def list_scan_rows(limit: int = 20) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_scan_rows(org_id, limit=limit)
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, status, created_at, progress_json, error_text, summary_json,
                   job_id, job_state, job_started_at, job_finished_at
            FROM scans
            WHERE organization_id = ?
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (org_id, limit),
        )
        rows = cur.fetchall()

    out: List[Dict[str, Any]] = []
    for id_, status, created_at_str, progress_json, error_text, summary_json, job_id, job_state, job_started_at, job_finished_at in rows:
        try:
            created_at = _parse_iso_datetime(created_at_str)
        except Exception:
            created_at = datetime.utcfromtimestamp(0)

        try:
            progress = json.loads(progress_json or "{}")
        except Exception:
            progress = {}

        try:
            summary = json.loads(summary_json or "{}")
        except Exception:
            summary = {}

        out.append(
            {
                "id": id_,
                "status": status,
                "created_at": created_at.isoformat(),
                "progress": progress,
                "error": error_text or "",
                "summary": summary,
                "job_id": job_id or "",
                "job_state": job_state or "",
                "job_started_at": job_started_at or "",
                "job_finished_at": job_finished_at or "",
            }
        )

    return out


def list_scan_results_bulk(limit: int = 10) -> List[Dict[str, Any]]:
    """Return (id, created_at, results) for the most recent `limit` scans in one query."""
    org_id = current_organization_id()
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, created_at, results_json
            FROM scans
            WHERE organization_id = ?
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (org_id, limit),
        )
        rows = cur.fetchall()

    out: List[Dict[str, Any]] = []
    for scan_id, created_at_str, results_json in rows:
        try:
            results = json.loads(results_json or "[]")
        except Exception:
            results = []
        out.append({"id": scan_id, "created_at": created_at_str or "", "results": results})
    return out


def asset_key(host: str, port: int) -> str:
    return f"{host}:{int(port)}"


def set_baseline(asset_key_str: str, baseline_scan_id: str, set_at: Optional[datetime] = None) -> None:
    set_at = set_at or datetime.now(timezone.utc)
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_set_baseline(org_id, asset_key_str, baseline_scan_id, set_at=set_at)
        return
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO baselines (organization_id, asset_key, baseline_scan_id, set_at)
            VALUES (?, ?, ?, ?)
            """,
            (org_id, asset_key_str, baseline_scan_id, set_at.isoformat()),
        )
        conn.commit()


def get_baseline(asset_key_str: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_get_baseline(org_id, asset_key_str)
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        row = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines WHERE organization_id=? AND asset_key = ?",
            (org_id, asset_key_str),
        ).fetchone()
        if not row:
            return None
        return {"asset_key": row[0], "baseline_scan_id": row[1], "set_at": row[2]}


def list_baselines(limit: int = 500) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_baselines(org_id, limit=limit)
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        rows = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines WHERE organization_id=? ORDER BY set_at DESC LIMIT ?",
            (org_id, int(limit)),
        ).fetchall()
        return [{"asset_key": r[0], "baseline_scan_id": r[1], "set_at": r[2]} for r in rows]


def set_baselines_from_scan(scan_id: str) -> Dict[str, Any]:
    scan = load_scan_row(scan_id)
    if not scan:
        raise ValueError("scan_id not found")
    results = scan.get("results") or []
    updated = 0
    now = datetime.now(timezone.utc)
    for r in results:
        host = r.get("host") or r.get("hostname") or ""
        port = int(r.get("port") or 443)
        if not host:
            continue
        set_baseline(asset_key(host, port), scan_id, set_at=now)
        updated += 1
    return {"scan_id": scan_id, "updated": updated, "set_at": now.isoformat()}


# -----------------------------
# Sprint 3/4: Asset inventory
# -----------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def upsert_asset(
    asset_key_str: str,
    owner: str = "",
    team: str = "",
    environment: str = "",
    criticality: str = "",
    confidentiality_lifetime: str = "",
    notes: str = "",
    tags: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    repository_id: Optional[int] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_upsert_asset(
            org_id,
            asset_key_str,
            owner=owner,
            team=team,
            environment=environment,
            criticality=criticality,
            confidentiality_lifetime=confidentiality_lifetime,
            notes=notes,
            tags=tags,
            metadata=metadata,
            repository_id=repository_id,
        )
    tags = tags or []
    metadata = metadata if metadata is not None else {}
    owner = owner or ""
    team = team or ""
    environment = environment or ""
    criticality = criticality or ""
    confidentiality_lifetime = confidentiality_lifetime or ""
    notes = notes or ""
    now = _utc_now_iso()

    existing = get_asset(asset_key_str) or {}
    if repository_id is None:
        try:
            repository_id = int(existing.get("repository_id") or 0)
        except Exception:
            repository_id = 0
    try:
        repository_id = int(repository_id or 0)
    except Exception:
        repository_id = 0
    if metadata is None or metadata == {}:
        metadata = existing.get("metadata") or {}
    meta_json = json.dumps(metadata or {})

    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO assets (organization_id, asset_key, owner, team, environment, criticality, confidentiality_lifetime, notes, metadata_json, repository_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, asset_key) DO UPDATE SET
                owner=excluded.owner,
                team=excluded.team,
                environment=excluded.environment,
                criticality=excluded.criticality,
                confidentiality_lifetime=excluded.confidentiality_lifetime,
                notes=excluded.notes,
                metadata_json=excluded.metadata_json,
                repository_id=excluded.repository_id,
                updated_at=excluded.updated_at
            """,
            (org_id, asset_key_str, owner, team, environment, criticality, confidentiality_lifetime, notes, meta_json, repository_id, now),
        )
        # Replace tags
        conn.execute("DELETE FROM asset_tags WHERE organization_id=? AND asset_key = ?", (org_id, asset_key_str))
        for t in tags:
            t = (t or "").strip()
            if not t:
                continue
            conn.execute("INSERT OR IGNORE INTO asset_tags (organization_id, asset_key, tag) VALUES (?, ?, ?)", (org_id, asset_key_str, t))
        conn.commit()

    return get_asset(asset_key_str) or {
        "asset_key": asset_key_str,
        "owner": owner,
        "team": team,
        "environment": environment,
        "criticality": criticality,
        "confidentiality_lifetime": confidentiality_lifetime,
        "notes": notes,
        "metadata": metadata,
        "repository_id": repository_id,
        "tags": tags,
        "updated_at": now,
    }


def get_asset(asset_key_str: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_get_asset(org_id, asset_key_str)
    with closing(get_connection()) as conn:
        cur = conn.execute(
            "SELECT asset_key, owner, team, environment, criticality, confidentiality_lifetime, notes, metadata_json, repository_id, updated_at FROM assets WHERE organization_id=? AND asset_key = ?",
            (org_id, asset_key_str),
        )
        row = cur.fetchone()
        if not row:
            return None
        tags_cur = conn.execute("SELECT tag FROM asset_tags WHERE organization_id=? AND asset_key = ? ORDER BY tag", (org_id, asset_key_str))
        tags = [r[0] for r in tags_cur.fetchall()]
        repo = get_repository_by_id(row[8]) if "get_repository_by_id" in globals() else None
        return {
            "asset_key": row[0],
            "owner": row[1],
            "team": row[2],
            "environment": row[3],
            "criticality": row[4],
            "confidentiality_lifetime": row[5],
            "notes": row[6],
            "metadata": _json_obj(row[7]),
            "repository_id": int(row[8] or 0),
            "repository_name": (repo or {}).get("name") if repo else "",
            "repository_html_url": (repo or {}).get("html_url") if repo else "",
            "updated_at": row[9],
            "tags": tags,
        }


def list_assets(
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 2000,
) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_assets(
            org_id,
            owner=owner,
            team=team,
            environment=environment,
            criticality=criticality,
            tag=tag,
            limit=limit,
        )
    limit = max(1, min(int(limit or 2000), 5000))
    sql = "SELECT a.asset_key, a.owner, a.team, a.environment, a.criticality, a.confidentiality_lifetime, a.notes, a.metadata_json, a.repository_id, a.updated_at FROM assets a"
    params: List[Any] = []
    wh: List[str] = ["a.organization_id = ?"]
    params.append(org_id)

    if tag:
        sql += " JOIN asset_tags t ON t.asset_key = a.asset_key AND t.organization_id = a.organization_id"
        wh.append("t.tag = ?")
        params.append(tag)

    if owner is not None and owner != "":
        wh.append("a.owner = ?")
        params.append(owner)
    if team is not None and team != "":
        wh.append("a.team = ?")
        params.append(team)
    if environment is not None and environment != "":
        wh.append("a.environment = ?")
        params.append(environment)
    if criticality is not None and criticality != "":
        wh.append("a.criticality = ?")
        params.append(criticality)

    if wh:
        sql += " WHERE " + " AND ".join(wh)
    sql += " ORDER BY a.updated_at DESC LIMIT ?"
    params.append(limit)

    out: List[Dict[str, Any]] = []
    with closing(get_connection()) as conn:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        for row in rows:
            ak = row[0]
            tags_cur = conn.execute("SELECT tag FROM asset_tags WHERE organization_id=? AND asset_key = ? ORDER BY tag", (org_id, ak))
            tags = [r[0] for r in tags_cur.fetchall()]
            repo = get_repository_by_id(row[8]) if "get_repository_by_id" in globals() else None
            out.append({
                "asset_key": ak,
                "owner": row[1],
                "team": row[2],
                "environment": row[3],
                "criticality": row[4],
                "confidentiality_lifetime": row[5],
                "notes": row[6],
                "metadata": _json_obj(row[7]),
                "repository_id": int(row[8] or 0),
                "repository_name": (repo or {}).get("name") if repo else "",
                "repository_html_url": (repo or {}).get("html_url") if repo else "",
                "updated_at": row[9],
                "tags": tags,
            })
    return out


def list_tags(limit: int = 2000) -> List[str]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_tags(org_id, limit=limit)
    limit = max(1, min(int(limit or 2000), 5000))
    with closing(get_connection()) as conn:
        cur = conn.execute("SELECT DISTINCT tag FROM asset_tags WHERE organization_id=? ORDER BY tag LIMIT ?", (org_id, limit))
        return [r[0] for r in cur.fetchall()]


# -----------------------------
# Sprint 11: repositories + linkage
# -----------------------------


def upsert_repository(name: str, html_url: str) -> Dict[str, Any]:
    org_id = current_organization_id()
    name = (name or "").strip()
    html_url = (html_url or "").strip()
    if not name:
        raise ValueError("repository name is required")
    if not html_url:
        raise ValueError("repository html_url is required")
    if postgres_main_db_requested():
        return pg_upsert_repository(org_id, name, html_url)

    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.execute(
            """
            INSERT INTO repositories (organization_id, name, html_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, name) DO UPDATE SET html_url=excluded.html_url, updated_at=excluded.updated_at
            """,
            (org_id, name, html_url, now, now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, name, html_url, created_at, updated_at FROM repositories WHERE organization_id=? AND name = ?",
            (org_id, name),
        ).fetchone()
        if not row:
            return {"name": name, "html_url": html_url}
        return {"id": row[0], "name": row[1], "html_url": row[2], "created_at": row[3], "updated_at": row[4]}


def list_repositories(limit: int = 2000) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_repositories(org_id, limit=limit)
    limit = max(1, min(int(limit or 2000), 5000))
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, html_url, created_at, updated_at FROM repositories WHERE organization_id=? ORDER BY updated_at DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_repository_by_name(name: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    name = (name or "").strip()
    if not name:
        return None
    if postgres_main_db_requested():
        return pg_get_repository_by_name(org_id, name)
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, html_url, created_at, updated_at FROM repositories WHERE organization_id=? AND name = ?",
            (org_id, name),
        ).fetchone()
        return dict(row) if row else None


def get_repository_by_id(repo_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        repo_id = int(repo_id)
    except Exception:
        return None
    if postgres_main_db_requested():
        return pg_get_repository_by_id(org_id, repo_id)
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, html_url, created_at, updated_at FROM repositories WHERE organization_id=? AND id = ?",
            (org_id, repo_id),
        ).fetchone()
        return dict(row) if row else None


def upsert_github_installation(
    installation_id: int,
    account_login: str,
    account_type: str = "",
    target_type: str = "",
    permissions: Optional[Dict[str, Any]] = None,
    repositories_count: int = 0,
    suspended_at: str = "",
) -> Dict[str, Any]:
    org_id = current_organization_id()
    try:
        installation_id = int(installation_id)
    except Exception as e:
        raise ValueError("installation_id must be an integer") from e
    if installation_id < 1:
        raise ValueError("installation_id must be >= 1")
    if postgres_main_db_requested():
        return pg_upsert_github_installation(
            org_id,
            installation_id,
            account_login,
            account_type=account_type,
            target_type=target_type,
            permissions=permissions,
            repositories_count=repositories_count,
            suspended_at=suspended_at,
        )

    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.execute(
            """
            INSERT INTO github_installations (
                organization_id, installation_id, account_login, account_type, target_type,
                permissions_json, repositories_count, suspended_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, installation_id) DO UPDATE SET
                account_login=excluded.account_login,
                account_type=excluded.account_type,
                target_type=excluded.target_type,
                permissions_json=excluded.permissions_json,
                repositories_count=excluded.repositories_count,
                suspended_at=excluded.suspended_at,
                updated_at=excluded.updated_at
            """,
            (
                org_id,
                installation_id,
                str(account_login or "").strip(),
                str(account_type or "").strip(),
                str(target_type or "").strip(),
                json.dumps(permissions or {}),
                int(repositories_count or 0),
                str(suspended_at or "").strip(),
                now,
                now,
            ),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, installation_id, account_login, account_type, target_type, permissions_json,
                   repositories_count, suspended_at, created_at, updated_at
            FROM github_installations
            WHERE organization_id=? AND installation_id=?
            """,
            (org_id, installation_id),
        ).fetchone()
        if not row:
            return {"installation_id": installation_id}
        out = dict(row)
        out["permissions"] = _json_obj(out.pop("permissions_json", "{}"))
        return out


def list_github_installations(limit: int = 2000) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_github_installations(org_id, limit=limit)
    limit = max(1, min(int(limit or 2000), 5000))
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, installation_id, account_login, account_type, target_type, permissions_json,
                   repositories_count, suspended_at, created_at, updated_at
            FROM github_installations
            WHERE organization_id=?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (org_id, limit),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["permissions"] = _json_obj(d.pop("permissions_json", "{}"))
            out.append(d)
        return out


def get_github_installation(installation_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        installation_id = int(installation_id)
    except Exception:
        return None
    if postgres_main_db_requested():
        return pg_get_github_installation(org_id, installation_id)
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, installation_id, account_login, account_type, target_type, permissions_json,
                   repositories_count, suspended_at, created_at, updated_at
            FROM github_installations
            WHERE organization_id=? AND installation_id=?
            """,
            (org_id, installation_id),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["permissions"] = _json_obj(d.pop("permissions_json", "{}"))
        return d


def list_assets_by_repository(repo_id: int, limit: int = 5000) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        repo_id = int(repo_id)
    except Exception:
        return []
    if postgres_main_db_requested():
        return pg_list_assets_by_repository(org_id, repo_id, limit=limit)
    limit = max(1, min(int(limit or 5000), 10000))
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT asset_key, owner, team, environment, criticality, confidentiality_lifetime,
                   notes, metadata_json, repository_id, updated_at
            FROM assets
            WHERE organization_id = ? AND repository_id = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (org_id, repo_id, limit),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            ak = r["asset_key"]
            tags_cur = conn.execute("SELECT tag FROM asset_tags WHERE organization_id=? AND asset_key = ? ORDER BY tag", (org_id, ak))
            tags = [t[0] for t in tags_cur.fetchall()]
            out.append(
                {
                    "asset_key": ak,
                    "owner": r["owner"],
                    "team": r["team"],
                    "environment": r["environment"],
                    "criticality": r["criticality"],
                    "confidentiality_lifetime": r["confidentiality_lifetime"],
                    "notes": r["notes"],
                    "metadata": _json_obj(r["metadata_json"]),
                    "repository_id": int(r["repository_id"] or 0),
                    "updated_at": r["updated_at"],
                    "tags": tags,
                }
            )
        return out


def link_asset_repository(asset_key_str: str, repository_id: int) -> None:
    org_id = current_organization_id()
    try:
        repository_id = int(repository_id or 0)
    except Exception:
        repository_id = 0
    if postgres_main_db_requested():
        pg_link_asset_repository(org_id, asset_key_str, repository_id)
        return
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.execute(
            "UPDATE assets SET repository_id=?, updated_at=? WHERE organization_id=? AND asset_key=?",
            (repository_id, _utc_now_iso(), org_id, asset_key_str),
        )
        conn.commit()


def set_asset_metadata(asset_key_str: str, metadata: Dict[str, Any]) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_set_asset_metadata(org_id, asset_key_str, metadata or {})
        return
    meta_json = json.dumps(metadata or {})
    with closing(get_connection()) as conn:
        _ensure_sprint11_tables(conn)
        conn.execute(
            "UPDATE assets SET metadata_json=?, updated_at=? WHERE organization_id=? AND asset_key=?",
            (meta_json, _utc_now_iso(), org_id, asset_key_str),
        )
        conn.commit()


def latest_scan_results_for_assets(asset_keys: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """{asset_key: newest scan_results row} for many assets, without a query per asset.

    Callers that need the latest result for a whole inventory used to loop over
    latest_scan_result_for_asset, which is one round trip each.
    """
    keys = [str(k).strip() for k in (asset_keys or []) if str(k or "").strip()]
    if not keys:
        return {}
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_latest_scan_results_for_assets(org_id, keys)
    placeholders = ",".join("?" for _ in keys)
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   key_bits, key_curve, cipher_name, scan_status, key_exchange
            FROM scan_results
            WHERE organization_id = ? AND asset_key IN ({placeholders})
            ORDER BY asset_key, scanned_at ASC
            """,
            (org_id, *keys),
        ).fetchall()
    # Ascending, so the last row written for each key is the newest one.
    return {str(row["asset_key"]): dict(row) for row in rows}


def latest_scan_result_for_asset(asset_key_str: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_latest_scan_result_for_asset(org_id, asset_key_str)
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   key_bits, key_curve, cipher_name, scan_status, key_exchange
            FROM scan_results
            WHERE organization_id = ? AND asset_key = ?
            ORDER BY scanned_at DESC
            LIMIT 1
            """,
            (org_id, asset_key_str),
        ).fetchone()
        return dict(row) if row else None


# -----------------------------
# Sprint 12: remediation workflow
# -----------------------------

def _remediation_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["repo_id"] = int(d.get("repo_id") or 0)
    except Exception:
        d["repo_id"] = 0
    try:
        d["github_credential_id"] = int(d.get("github_credential_id") or 0)
    except Exception:
        d["github_credential_id"] = 0
    try:
        d["branch_cleanup_attempts"] = int(d.get("branch_cleanup_attempts") or 0)
    except Exception:
        d["branch_cleanup_attempts"] = 0
    try:
        d["parent_remediation_id"] = int(d.get("parent_remediation_id") or 0)
    except Exception:
        d["parent_remediation_id"] = 0
    try:
        d["drift_followup_remediation_id"] = int(d.get("drift_followup_remediation_id") or 0)
    except Exception:
        d["drift_followup_remediation_id"] = 0
    d["origin_kind"] = str(d.get("origin_kind") or "").strip().lower()
    d["drift_status"] = str(d.get("drift_status") or "").strip().lower()
    d["drift_details"] = _json_obj(d.pop("drift_details_json", "{}"))
    d["drift_acknowledged_at"] = str(d.get("drift_acknowledged_at") or "").strip()
    d["drift_acknowledged_by"] = str(d.get("drift_acknowledged_by") or "").strip()
    d["drift_ack_note"] = str(d.get("drift_ack_note") or "").strip()
    repo = get_repository_by_id(d["repo_id"]) if d["repo_id"] else None
    d["repository_name"] = (repo or {}).get("name", "")
    d["repository_html_url"] = (repo or {}).get("html_url", "")
    return d


def _validation_job_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["id"] = int(d.get("id") or 0)
    except Exception:
        d["id"] = 0
    try:
        d["remediation_id"] = int(d.get("remediation_id") or 0)
    except Exception:
        d["remediation_id"] = 0
    try:
        raw_exit_code = d.get("exit_code")
        d["exit_code"] = -1 if raw_exit_code in (None, "") else int(raw_exit_code)
    except Exception:
        d["exit_code"] = -1
    d["details"] = _json_obj(d.pop("details_json", "{}"))
    return d


def create_validation_job(
    remediation_id: int,
    validator_type: str = "auto",
    git_ref: str = "",
    status: str = "queued",
    job_id: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_create_validation_job(
            org_id,
            remediation_id,
            validator_type=validator_type,
            git_ref=git_ref,
            status=status,
            job_id=job_id,
            details=details or {},
        )
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO validation_jobs (
                organization_id, remediation_id, validator_type, status, git_ref, job_id,
                stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, '', '', -1, ?, ?, ?, '')
            """,
            (
                org_id,
                int(remediation_id or 0),
                str(validator_type or "auto").strip().lower() or "auto",
                str(status or "queued").strip().lower() or "queued",
                str(git_ref or "").strip(),
                str(job_id or "").strip(),
                json.dumps(details or {}),
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                   stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
            FROM validation_jobs
            WHERE organization_id = ? AND id = ?
            """,
            (org_id, int(cur.lastrowid or 0)),
        ).fetchone()
        conn.commit()
    return _validation_job_row_to_dict(row) if row else {"remediation_id": int(remediation_id or 0)}


def get_validation_job(validation_job_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        validation_job_id = int(validation_job_id)
    except Exception:
        return None
    if postgres_main_db_requested():
        return pg_get_validation_job(org_id, validation_job_id)
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                   stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
            FROM validation_jobs
            WHERE organization_id = ? AND id = ?
            """,
            (org_id, validation_job_id),
        ).fetchone()
    return _validation_job_row_to_dict(row) if row else None


def list_validation_jobs(
    remediation_id: Optional[int] = None,
    status: str = "",
    limit: int = 200,
) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_validation_jobs(org_id, remediation_id=remediation_id, status=status, limit=limit)
    limit = max(1, min(int(limit or 200), 2000))
    clauses: List[str] = ["organization_id = ?"]
    params: List[Any] = [org_id]
    if remediation_id is not None:
        clauses.append("remediation_id = ?")
        params.append(int(remediation_id))
    if str(status or "").strip():
        clauses.append("status = ?")
        params.append(str(status or "").strip().lower())
    where = "WHERE " + " AND ".join(clauses)
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                   stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
            FROM validation_jobs
            {where}
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return [_validation_job_row_to_dict(r) for r in rows]


def get_latest_validation_job_for_remediation(remediation_id: int, passed_only: bool = False) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        remediation_id = int(remediation_id)
    except Exception:
        return None
    if postgres_main_db_requested():
        return pg_get_latest_validation_job_for_remediation(org_id, remediation_id, passed_only=passed_only)
    clauses = ["organization_id = ?", "remediation_id = ?"]
    params: List[Any] = [org_id, remediation_id]
    if passed_only:
        clauses.append("status = 'passed'")
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            f"""
            SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                   stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
            FROM validation_jobs
            WHERE {' AND '.join(clauses)}
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
            """,
            params,
        ).fetchone()
    return _validation_job_row_to_dict(row) if row else None


def update_validation_job(
    validation_job_id: int,
    *,
    status: Optional[str] = None,
    validator_type: Optional[str] = None,
    git_ref: Optional[str] = None,
    job_id: Optional[str] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    exit_code: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    finished: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_update_validation_job(
            org_id,
            validation_job_id,
            status=status,
            validator_type=validator_type,
            git_ref=git_ref,
            job_id=job_id,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            details=details,
            finished=finished,
        )
    sets: List[str] = ["updated_at = ?"]
    params: List[Any] = [_utc_now_iso()]
    if status is not None:
        sets.append("status = ?")
        params.append(str(status or "").strip().lower())
    if validator_type is not None:
        sets.append("validator_type = ?")
        params.append(str(validator_type or "").strip().lower() or "auto")
    if git_ref is not None:
        sets.append("git_ref = ?")
        params.append(str(git_ref or "").strip())
    if job_id is not None:
        sets.append("job_id = ?")
        params.append(str(job_id or "").strip())
    if stdout is not None:
        sets.append("stdout = ?")
        params.append(str(stdout or ""))
    if stderr is not None:
        sets.append("stderr = ?")
        params.append(str(stderr or ""))
    if exit_code is not None:
        sets.append("exit_code = ?")
        params.append(int(exit_code))
    if details is not None:
        sets.append("details_json = ?")
        params.append(json.dumps(details or {}))
    if finished is True:
        sets.append("finished_at = ?")
        params.append(_utc_now_iso())
    elif finished is False:
        sets.append("finished_at = ?")
        params.append("")
    if len(sets) == 1:
        return get_validation_job(validation_job_id)
    params.extend([org_id, int(validation_job_id)])
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            f"UPDATE validation_jobs SET {', '.join(sets)} WHERE organization_id = ? AND id = ?",
            params,
        )
        conn.commit()
    return get_validation_job(validation_job_id)


MIGRATION_TASK_STATUSES = {"open", "planned", "in_progress", "done", "accepted_risk"}


def _migration_task_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    out = dict(row)
    for key in ("id", "repo_id"):
        try:
            out[key] = int(out.get(key) or 0)
        except Exception:
            out[key] = 0
    out["status"] = str(out.get("status") or "open").strip().lower() or "open"
    out["safety_class"] = str(out.get("safety_class") or "migration_task").strip().lower()
    out["confidence"] = str(out.get("confidence") or "medium").strip().lower()
    return out


def create_migration_task(
    asset_key_str: str = "",
    repository_name: str = "",
    repo_id: int = 0,
    file_path: str = "",
    rule_id: str = "",
    legacy_dependency: str = "",
    migration_target: str = "",
    safety_class: str = "migration_task",
    confidence: str = "medium",
    safety_reason: str = "",
    recommended_workflow: str = "",
    status: str = "open",
    source: str = "repo_crypto_discovery",
) -> Dict[str, Any]:
    org_id = current_organization_id()
    clean_status = str(status or "open").strip().lower() or "open"
    if clean_status not in MIGRATION_TASK_STATUSES:
        clean_status = "open"
    if postgres_main_db_requested():
        return pg_create_migration_task(
            org_id,
            asset_key_str=asset_key_str,
            repository_name=repository_name,
            repo_id=repo_id,
            file_path=file_path,
            rule_id=rule_id,
            legacy_dependency=legacy_dependency,
            migration_target=migration_target,
            safety_class=safety_class,
            confidence=confidence,
            safety_reason=safety_reason,
            recommended_workflow=recommended_workflow,
            status=clean_status,
            source=source,
        )
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO migration_tasks (
                organization_id, asset_key, repository_name, repo_id, file_path, rule_id,
                legacy_dependency, migration_target, safety_class, confidence, safety_reason,
                recommended_workflow, status, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                str(asset_key_str or "").strip(),
                str(repository_name or "").strip(),
                int(repo_id or 0),
                str(file_path or "").strip(),
                str(rule_id or "").strip(),
                str(legacy_dependency or "").strip(),
                str(migration_target or "").strip(),
                str(safety_class or "migration_task").strip().lower() or "migration_task",
                str(confidence or "medium").strip().lower() or "medium",
                str(safety_reason or "").strip(),
                str(recommended_workflow or "").strip(),
                clean_status,
                str(source or "repo_crypto_discovery").strip().lower() or "repo_crypto_discovery",
                now,
                now,
            ),
        )
        task_id = int(cur.lastrowid or 0)
        row = conn.execute("SELECT * FROM migration_tasks WHERE organization_id=? AND id=?", (org_id, task_id)).fetchone()
        conn.commit()
    return _migration_task_row_to_dict(row) if row else {"id": task_id}


def list_migration_tasks(
    status: str = "",
    asset_key_str: str = "",
    repository_name: str = "",
    limit: int = 200,
) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_migration_tasks(
            org_id,
            status=status,
            asset_key_str=asset_key_str,
            repository_name=repository_name,
            limit=limit,
        )
    clauses = ["organization_id = ?"]
    params: List[Any] = [org_id]
    if str(status or "").strip():
        clauses.append("status = ?")
        params.append(str(status or "").strip().lower())
    if str(asset_key_str or "").strip():
        clauses.append("asset_key = ?")
        params.append(str(asset_key_str or "").strip())
    if str(repository_name or "").strip():
        clauses.append("repository_name = ?")
        params.append(str(repository_name or "").strip())
    params.append(max(1, min(int(limit or 200), 2000)))
    sql = f"SELECT * FROM migration_tasks WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, id DESC LIMIT ?"
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [_migration_task_row_to_dict(r) for r in rows]


def update_migration_task_status(task_id: int, status: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    clean_status = str(status or "open").strip().lower() or "open"
    if clean_status not in MIGRATION_TASK_STATUSES:
        clean_status = "open"
    if postgres_main_db_requested():
        return pg_update_migration_task_status(org_id, task_id, clean_status)
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE migration_tasks SET status=?, updated_at=? WHERE organization_id=? AND id=?",
            (clean_status, now, org_id, int(task_id)),
        )
        row = conn.execute("SELECT * FROM migration_tasks WHERE organization_id=? AND id=?", (org_id, int(task_id))).fetchone()
        conn.commit()
    return _migration_task_row_to_dict(row) if row else None


def create_remediation(
    asset_key_str: str,
    repo_id: int,
    file_path: str,
    vulnerability: str,
    suggested_fix: str,
    original_content: str = "",
    suggested_content: str = "",
    status: str = "pending",
    review_note: str = "",
    parent_remediation_id: int = 0,
    origin_kind: str = "",
) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_create_remediation(
            org_id,
            asset_key_str,
            repo_id,
            file_path,
            vulnerability,
            suggested_fix,
            original_content=original_content,
            suggested_content=suggested_content,
            status=status,
            review_note=review_note,
            parent_remediation_id=parent_remediation_id,
            origin_kind=origin_kind,
        )
    now = _utc_now_iso()
    try:
        repo_id = int(repo_id or 0)
    except Exception:
        repo_id = 0

    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO remediations (
                organization_id, asset_key, repo_id, vulnerability, file_path, original_content, suggested_fix, suggested_content,
                status, pr_url, review_note, merged_at, verification_scan_id, closed_at,
                parent_remediation_id, origin_kind, drift_followup_remediation_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, '', '', '', ?, ?, 0, ?, ?)
            """,
            (
                org_id,
                str(asset_key_str or "").strip(),
                repo_id,
                str(vulnerability or "").strip(),
                str(file_path or "").strip(),
                str(original_content or ""),
                str(suggested_fix or ""),
                str(suggested_content or ""),
                str(status or "pending").strip() or "pending",
                str(review_note or ""),
                int(parent_remediation_id or 0),
                str(origin_kind or "").strip().lower(),
                now,
                now,
            ),
        )
        remediation_id = int(cur.lastrowid or 0)
        row = conn.execute(
            """
            SELECT id, asset_key, repo_id, vulnerability, file_path, original_content, suggested_fix, suggested_content,
                   status, pr_url, pr_branch, pr_base_branch, github_credential_id,
                   branch_cleanup_status, branch_cleanup_at, branch_cleanup_error, branch_cleanup_attempts,
                   review_note, merged_at, verification_scan_id, closed_at,
                   parent_remediation_id, origin_kind, drift_followup_remediation_id,
                   drift_status, last_drift_checked_at, drift_detected_at,
                   drift_acknowledged_at, drift_acknowledged_by, drift_ack_note, drift_details_json,
                   created_at, updated_at
            FROM remediations
            WHERE organization_id = ? AND id = ?
            """,
            (org_id, remediation_id),
        ).fetchone()
        conn.commit()

    if not row:
        return {"id": remediation_id}
    return _remediation_row_to_dict(row)


def get_remediation(remediation_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    try:
        remediation_id = int(remediation_id)
    except Exception:
        return None
    if postgres_main_db_requested():
        return pg_get_remediation(org_id, remediation_id)

    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, asset_key, repo_id, vulnerability, file_path, original_content, suggested_fix, suggested_content,
                   status, pr_url, pr_branch, pr_base_branch, github_credential_id,
                   branch_cleanup_status, branch_cleanup_at, branch_cleanup_error, branch_cleanup_attempts,
                   review_note, merged_at, verification_scan_id, closed_at,
                   parent_remediation_id, origin_kind, drift_followup_remediation_id,
                   drift_status, last_drift_checked_at, drift_detected_at,
                   drift_acknowledged_at, drift_acknowledged_by, drift_ack_note, drift_details_json,
                   created_at, updated_at
            FROM remediations
            WHERE organization_id = ? AND id = ?
            """,
            (org_id, remediation_id),
        ).fetchone()
    return _remediation_row_to_dict(row) if row else None


def list_remediations(
    status: str = "",
    repo_id: Optional[int] = None,
    asset_key_str: str = "",
    drift_status: str = "",
    parent_remediation_id: Optional[int] = None,
    origin_kind: str = "",
    text_query: str = "",
    limit: int = 200,
) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_remediations(
            org_id,
            status=status,
            repo_id=repo_id,
            asset_key_str=asset_key_str,
            drift_status=drift_status,
            parent_remediation_id=parent_remediation_id,
            origin_kind=origin_kind,
            text_query=text_query,
            limit=limit,
        )
    limit = max(1, min(int(limit or 200), 2000))
    clauses: List[str] = ["organization_id = ?"]
    params: List[Any] = [org_id]

    status = str(status or "").strip().lower()
    if status:
        clauses.append("status = ?")
        params.append(status)

    if repo_id is not None:
        try:
            rid = int(repo_id)
            clauses.append("repo_id = ?")
            params.append(rid)
        except Exception:
            pass

    asset_key_str = str(asset_key_str or "").strip()
    if asset_key_str:
        clauses.append("asset_key = ?")
        params.append(asset_key_str)

    drift_status = str(drift_status or "").strip().lower()
    if drift_status:
        clauses.append("drift_status = ?")
        params.append(drift_status)

    if parent_remediation_id is not None:
        try:
            clauses.append("parent_remediation_id = ?")
            params.append(int(parent_remediation_id))
        except Exception:
            pass

    origin_kind = str(origin_kind or "").strip().lower()
    if origin_kind:
        clauses.append("origin_kind = ?")
        params.append(origin_kind)

    text_query = str(text_query or "").strip().lower()
    if text_query:
        # Free-text filter for the in-app search; wildcards typed by the operator stay literal.
        pattern = _like_contains(text_query)
        clauses.append(
            r"(LOWER(vulnerability) LIKE ? ESCAPE '\' OR LOWER(suggested_fix) LIKE ? ESCAPE '\' "
            r"OR LOWER(asset_key) LIKE ? ESCAPE '\' OR LOWER(status) LIKE ? ESCAPE '\')"
        )
        params.extend([pattern] * 4)

    where = ""
    if clauses:
        where = "WHERE " + " AND ".join(clauses)

    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT id, asset_key, repo_id, vulnerability, file_path, original_content, suggested_fix, suggested_content,
                   status, pr_url, pr_branch, pr_base_branch, github_credential_id,
                   branch_cleanup_status, branch_cleanup_at, branch_cleanup_error, branch_cleanup_attempts,
                   review_note, merged_at, verification_scan_id, closed_at,
                   parent_remediation_id, origin_kind, drift_followup_remediation_id,
                   drift_status, last_drift_checked_at, drift_detected_at,
                   drift_acknowledged_at, drift_acknowledged_by, drift_ack_note, drift_details_json,
                   created_at, updated_at
            FROM remediations
            {where}
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return [_remediation_row_to_dict(r) for r in rows]


def update_remediation_status(remediation_id: int, status: str, review_note: str = "") -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_update_remediation_status(org_id, remediation_id, status, review_note=review_note)
    now = _utc_now_iso()
    status = str(status or "").strip().lower() or "pending"
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            "UPDATE remediations SET status=?, review_note=?, updated_at=? WHERE organization_id=? AND id=?",
            (status, str(review_note or ""), now, org_id, int(remediation_id)),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def set_remediation_pr(
    remediation_id: int,
    pr_url: str,
    status: str = "pr_created",
    branch: str = "",
    base_branch: str = "",
    github_credential_id: int = 0,
) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_set_remediation_pr(
            org_id,
            remediation_id,
            pr_url,
            status=status,
            branch=branch,
            base_branch=base_branch,
            github_credential_id=github_credential_id,
        )
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET pr_url=?, pr_branch=?, pr_base_branch=?, github_credential_id=?,
                branch_cleanup_status='', branch_cleanup_at='', branch_cleanup_error='', branch_cleanup_attempts=0,
                status=?, updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (
                str(pr_url or "").strip(),
                str(branch or "").strip(),
                str(base_branch or "").strip(),
                int(github_credential_id or 0),
                str(status or "pr_created").strip().lower(),
                now,
                org_id,
                int(remediation_id),
            ),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def update_remediation_branch_cleanup(
    remediation_id: int,
    status: str,
    error: str = "",
    cleanup_at_iso: str = "",
) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_update_remediation_branch_cleanup(
            org_id,
            remediation_id,
            status=status,
            error=error,
            cleanup_at_iso=cleanup_at_iso,
        )
    now = _utc_now_iso()
    cleanup_at = str(cleanup_at_iso or "").strip() or now
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET branch_cleanup_status=?,
                branch_cleanup_at=?,
                branch_cleanup_error=?,
                branch_cleanup_attempts=branch_cleanup_attempts + 1,
                updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (
                str(status or "").strip().lower(),
                cleanup_at,
                str(error or "")[:2000],
                now,
                org_id,
                int(remediation_id),
            ),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def mark_remediation_merged(remediation_id: int, merged_at_iso: str = "") -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_mark_remediation_merged(org_id, remediation_id, merged_at_iso=merged_at_iso)
    merged_at = str(merged_at_iso or "").strip() or _utc_now_iso()
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET status='merged',
                merged_at=?,
                drift_acknowledged_at='',
                drift_acknowledged_by='',
                drift_ack_note='',
                drift_status='',
                last_drift_checked_at='',
                drift_detected_at='',
                drift_details_json='{}',
                updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (merged_at, now, org_id, int(remediation_id)),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def mark_remediation_merged_by_pr_url(
    pr_url: str,
    merged_at_iso: str = "",
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    if postgres_main_db_requested():
        return pg_mark_remediation_merged_by_pr_url(
            pr_url,
            merged_at_iso=merged_at_iso,
            organization_id=organization_id,
        )
    org_id = str(organization_id or "").strip()
    pr_url = str(pr_url or "").strip()
    if not pr_url:
        return {"matched": 0, "updated": 0, "already_merged": 0, "remediation_ids": []}

    merged_at = str(merged_at_iso or "").strip() or _utc_now_iso()
    now = _utc_now_iso()
    matched = 0
    updated = 0
    already_merged = 0
    remediation_ids: List[int] = []

    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        if org_id:
            rows = conn.execute(
                "SELECT id, status, organization_id FROM remediations WHERE organization_id=? AND pr_url = ?",
                (org_id, pr_url),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, status, organization_id FROM remediations WHERE pr_url = ?",
                (pr_url,),
            ).fetchall()
        matched = len(rows or [])

        for row in rows or []:
            rid = int(row["id"])
            status = str(row["status"] or "").strip().lower()
            row_org_id = str(row["organization_id"] or "").strip() or DEFAULT_ORG_ID
            remediation_ids.append(rid)
            if status in ("merged", "verified_closed"):
                already_merged += 1
                continue
            conn.execute(
                """
                UPDATE remediations
                SET status='merged',
                    merged_at=?,
                    drift_acknowledged_at='',
                    drift_acknowledged_by='',
                    drift_ack_note='',
                    drift_status='',
                    last_drift_checked_at='',
                    drift_detected_at='',
                    drift_details_json='{}',
                    updated_at=?
                WHERE organization_id=? AND id=?
                """,
                (merged_at, now, row_org_id, rid),
            )
            updated += 1
        conn.commit()

    return {
        "matched": matched,
        "updated": updated,
        "already_merged": already_merged,
        "remediation_ids": remediation_ids,
    }


def update_remediation_status_by_pr_url(
    pr_url: str,
    status: str,
    review_note: str = "",
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    if postgres_main_db_requested():
        return pg_update_remediation_status_by_pr_url(
            pr_url,
            status,
            review_note=review_note,
            organization_id=organization_id,
        )
    org_id = str(organization_id or "").strip()
    pr_url = str(pr_url or "").strip()
    next_status = str(status or "").strip().lower()
    if not pr_url or not next_status:
        return {"matched": 0, "updated": 0, "already": 0, "remediation_ids": []}
    now = _utc_now_iso()
    matched = 0
    updated = 0
    already = 0
    remediation_ids: List[int] = []
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.row_factory = sqlite3.Row
        if org_id:
            rows = conn.execute(
                "SELECT id, status, organization_id FROM remediations WHERE organization_id=? AND pr_url=?",
                (org_id, pr_url),
            ).fetchall()
        else:
            rows = conn.execute("SELECT id, status, organization_id FROM remediations WHERE pr_url=?", (pr_url,)).fetchall()
        matched = len(rows or [])
        for row in rows or []:
            rid = int(row["id"])
            remediation_ids.append(rid)
            current_status = str(row["status"] or "").strip().lower()
            row_org_id = str(row["organization_id"] or "").strip() or DEFAULT_ORG_ID
            if current_status == next_status or (current_status == "verified_closed" and next_status != "verified_closed"):
                already += 1
                continue
            conn.execute(
                """
                UPDATE remediations
                SET status=?, review_note=CASE WHEN ?='' THEN review_note ELSE ? END, updated_at=?
                WHERE organization_id=? AND id=?
                """,
                (next_status, str(review_note or ""), str(review_note or ""), now, row_org_id, rid),
            )
            updated += 1
        conn.commit()
    return {"matched": matched, "updated": updated, "already": already, "remediation_ids": remediation_ids}


def _ensure_github_history_sqlite(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS github_pr_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            pr_url TEXT NOT NULL,
            event TEXT NOT NULL,
            action TEXT NOT NULL,
            delivery TEXT NOT NULL,
            status TEXT NOT NULL,
            remediation_ids_json TEXT NOT NULL DEFAULT '[]',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_pr_events_org ON github_pr_events(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_pr_events_pr_url ON github_pr_events(pr_url)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS github_status_publishes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            repo TEXT NOT NULL,
            ref TEXT NOT NULL,
            context TEXT NOT NULL,
            publish_mode TEXT NOT NULL,
            state TEXT NOT NULL,
            target_url TEXT NOT NULL DEFAULT '',
            ok INTEGER NOT NULL DEFAULT 0,
            http_status INTEGER NOT NULL DEFAULT 0,
            response_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_status_publishes_org ON github_status_publishes(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_status_publishes_repo ON github_status_publishes(repo)")
    conn.commit()


def _ensure_github_history_postgres() -> None:
    ensure_postgres_core_schema()
    with pg_product_conn(product_database_url()) as conn, tolerate_missing_ddl_privilege(
        conn, ("github_pr_events", "github_status_publishes"), "github history"
    ):
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS github_pr_events (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    pr_url TEXT NOT NULL,
                    event TEXT NOT NULL,
                    action TEXT NOT NULL,
                    delivery TEXT NOT NULL,
                    status TEXT NOT NULL,
                    remediation_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_github_pr_events_org ON github_pr_events(organization_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_github_pr_events_pr_url ON github_pr_events(pr_url)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS github_status_publishes (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    ref TEXT NOT NULL,
                    context TEXT NOT NULL,
                    publish_mode TEXT NOT NULL,
                    state TEXT NOT NULL,
                    target_url TEXT NOT NULL DEFAULT '',
                    ok INTEGER NOT NULL DEFAULT 0,
                    http_status INTEGER NOT NULL DEFAULT 0,
                    response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_github_status_publishes_org ON github_status_publishes(organization_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_github_status_publishes_repo ON github_status_publishes(repo)")


def record_github_pr_event(
    *,
    pr_url: str,
    event: str,
    action: str,
    delivery: str,
    status: str,
    remediation_ids: Optional[List[int]] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    now = _utc_now_iso()
    remediation_ids = [int(x) for x in (remediation_ids or []) if str(x).strip().lstrip("-").isdigit()]
    payload = payload or {}
    if postgres_main_db_requested():
        _ensure_github_history_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO github_pr_events(
                        organization_id, pr_url, event, action, delivery, status,
                        remediation_ids_json, payload_json, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
                    RETURNING id
                    """,
                    (
                        org_id,
                        str(pr_url or ""),
                        str(event or ""),
                        str(action or ""),
                        str(delivery or ""),
                        str(status or ""),
                        json.dumps(remediation_ids),
                        json.dumps(payload, default=str),
                        now,
                    ),
                )
                rid = int((cur.fetchone() or [0])[0] or 0)
                return {"id": rid, "created_at": now}
    with closing(get_connection()) as conn:
        _ensure_github_history_sqlite(conn)
        cur = conn.execute(
            """
            INSERT INTO github_pr_events(
                organization_id, pr_url, event, action, delivery, status,
                remediation_ids_json, payload_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                str(pr_url or ""),
                str(event or ""),
                str(action or ""),
                str(delivery or ""),
                str(status or ""),
                json.dumps(remediation_ids),
                json.dumps(payload, default=str),
                now,
            ),
        )
        conn.commit()
        return {"id": int(cur.lastrowid or 0), "created_at": now}


def record_github_status_publish(
    *,
    repo: str,
    ref: str,
    context: str,
    publish_mode: str,
    state: str,
    target_url: str = "",
    ok: bool = False,
    http_status: int = 0,
    response: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    now = _utc_now_iso()
    response = response or {}
    if postgres_main_db_requested():
        _ensure_github_history_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO github_status_publishes(
                        organization_id, repo, ref, context, publish_mode, state,
                        target_url, ok, http_status, response_json, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                    RETURNING id
                    """,
                    (
                        org_id,
                        str(repo or ""),
                        str(ref or ""),
                        str(context or ""),
                        str(publish_mode or ""),
                        str(state or ""),
                        str(target_url or ""),
                        1 if ok else 0,
                        int(http_status or 0),
                        json.dumps(response, default=str),
                        now,
                    ),
                )
                rid = int((cur.fetchone() or [0])[0] or 0)
                return {"id": rid, "created_at": now}
    with closing(get_connection()) as conn:
        _ensure_github_history_sqlite(conn)
        cur = conn.execute(
            """
            INSERT INTO github_status_publishes(
                organization_id, repo, ref, context, publish_mode, state,
                target_url, ok, http_status, response_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                str(repo or ""),
                str(ref or ""),
                str(context or ""),
                str(publish_mode or ""),
                str(state or ""),
                str(target_url or ""),
                1 if ok else 0,
                int(http_status or 0),
                json.dumps(response, default=str),
                now,
            ),
        )
        conn.commit()
        return {"id": int(cur.lastrowid or 0), "created_at": now}


def list_github_pr_events(limit: int = 100, pr_url: str = "") -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 100), 1000))
    pr_url = str(pr_url or "").strip()
    if postgres_main_db_requested():
        _ensure_github_history_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                if pr_url:
                    cur.execute(
                        """
                        SELECT id, pr_url, event, action, delivery, status, remediation_ids_json, payload_json, created_at
                        FROM github_pr_events
                        WHERE organization_id=%s AND pr_url=%s
                        ORDER BY id DESC LIMIT %s
                        """,
                        (org_id, pr_url, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT id, pr_url, event, action, delivery, status, remediation_ids_json, payload_json, created_at
                        FROM github_pr_events
                        WHERE organization_id=%s
                        ORDER BY id DESC LIMIT %s
                        """,
                        (org_id, limit),
                    )
                rows = cur.fetchall()
                return [
                    {
                        "id": int(r[0]),
                        "pr_url": r[1],
                        "event": r[2],
                        "action": r[3],
                        "delivery": r[4],
                        "status": r[5],
                        "remediation_ids": r[6] or [],
                        "payload": r[7] or {},
                        "created_at": str(r[8] or ""),
                    }
                    for r in rows
                ]
    with closing(get_connection()) as conn:
        _ensure_github_history_sqlite(conn)
        conn.row_factory = sqlite3.Row
        if pr_url:
            rows = conn.execute(
                """
                SELECT id, pr_url, event, action, delivery, status, remediation_ids_json, payload_json, created_at
                FROM github_pr_events
                WHERE organization_id=? AND pr_url=?
                ORDER BY id DESC LIMIT ?
                """,
                (org_id, pr_url, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, pr_url, event, action, delivery, status, remediation_ids_json, payload_json, created_at
                FROM github_pr_events
                WHERE organization_id=?
                ORDER BY id DESC LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "pr_url": r["pr_url"],
                "event": r["event"],
                "action": r["action"],
                "delivery": r["delivery"],
                "status": r["status"],
                "remediation_ids": json.loads(r["remediation_ids_json"] or "[]"),
                "payload": json.loads(r["payload_json"] or "{}"),
                "created_at": r["created_at"],
            }
            for r in rows
        ]


def list_github_status_publishes(limit: int = 100, repo: str = "") -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 100), 1000))
    repo = str(repo or "").strip()
    if postgres_main_db_requested():
        _ensure_github_history_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                if repo:
                    cur.execute(
                        """
                        SELECT id, repo, ref, context, publish_mode, state, target_url, ok, http_status, response_json, created_at
                        FROM github_status_publishes
                        WHERE organization_id=%s AND repo=%s
                        ORDER BY id DESC LIMIT %s
                        """,
                        (org_id, repo, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT id, repo, ref, context, publish_mode, state, target_url, ok, http_status, response_json, created_at
                        FROM github_status_publishes
                        WHERE organization_id=%s
                        ORDER BY id DESC LIMIT %s
                        """,
                        (org_id, limit),
                    )
                rows = cur.fetchall()
                return [
                    {
                        "id": int(r[0]),
                        "repo": r[1],
                        "ref": r[2],
                        "context": r[3],
                        "publish_mode": r[4],
                        "state": r[5],
                        "target_url": r[6],
                        "ok": bool(r[7]),
                        "http_status": int(r[8] or 0),
                        "response": r[9] or {},
                        "created_at": str(r[10] or ""),
                    }
                    for r in rows
                ]
    with closing(get_connection()) as conn:
        _ensure_github_history_sqlite(conn)
        conn.row_factory = sqlite3.Row
        if repo:
            rows = conn.execute(
                """
                SELECT id, repo, ref, context, publish_mode, state, target_url, ok, http_status, response_json, created_at
                FROM github_status_publishes
                WHERE organization_id=? AND repo=?
                ORDER BY id DESC LIMIT ?
                """,
                (org_id, repo, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, repo, ref, context, publish_mode, state, target_url, ok, http_status, response_json, created_at
                FROM github_status_publishes
                WHERE organization_id=?
                ORDER BY id DESC LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "repo": r["repo"],
                "ref": r["ref"],
                "context": r["context"],
                "publish_mode": r["publish_mode"],
                "state": r["state"],
                "target_url": r["target_url"],
                "ok": bool(r["ok"]),
                "http_status": int(r["http_status"] or 0),
                "response": json.loads(r["response_json"] or "{}"),
                "created_at": r["created_at"],
            }
            for r in rows
        ]


def update_remediation_drift_state(
    remediation_id: int,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    checked_at_iso: str = "",
    detected_at_iso: str = "",
) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_update_remediation_drift_state(
            org_id,
            remediation_id,
            status,
            details=details,
            checked_at_iso=checked_at_iso,
            detected_at_iso=detected_at_iso,
        )
    drift_status = str(status or "").strip().lower()
    checked_at = str(checked_at_iso or "").strip() or _utc_now_iso()
    detected_at = str(detected_at_iso or "").strip()
    if drift_status == "drifted" and not detected_at:
        detected_at = checked_at
    if drift_status != "drifted":
        detected_at = ""
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET drift_status=?,
                last_drift_checked_at=?,
                drift_detected_at=?,
                drift_details_json=?,
                updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (
                drift_status,
                checked_at,
                detected_at,
                json.dumps(details or {}),
                now,
                org_id,
                int(remediation_id),
            ),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def set_remediation_drift_followup(parent_remediation_id: int, followup_remediation_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_set_remediation_drift_followup(org_id, parent_remediation_id, followup_remediation_id)
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET drift_followup_remediation_id=?,
                updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (int(followup_remediation_id or 0), now, org_id, int(parent_remediation_id)),
        )
        conn.commit()
    return get_remediation(int(parent_remediation_id))


def acknowledge_remediation_drift(remediation_id: int, actor_id: str, note: str = "") -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_acknowledge_remediation_drift(org_id, remediation_id, actor_id=actor_id, note=note)
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        conn.execute(
            """
            UPDATE remediations
            SET drift_acknowledged_at=?,
                drift_acknowledged_by=?,
                drift_ack_note=?,
                updated_at=?
            WHERE organization_id=? AND id=?
            """,
            (
                now,
                str(actor_id or "").strip(),
                str(note or ""),
                now,
                org_id,
                int(remediation_id),
            ),
        )
        conn.commit()
    return get_remediation(int(remediation_id))


def auto_close_merged_remediations(scan_id: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_auto_close_merged_remediations(org_id, scan_id, results)
    closed = 0
    assets_checked = 0
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint12_tables(conn)
        for r in results or []:
            host = str(r.get("host") or r.get("hostname") or "").strip()
            if not host:
                continue
            port = int(r.get("port") or 443)
            ak = asset_key(host, port)
            assets_checked += 1

            risk = str(r.get("risk") or r.get("risk_level") or r.get("quantum_risk_level") or "").strip().lower()
            findings = r.get("findings") or []
            findings_count = len(findings) if isinstance(findings, list) else int(r.get("findings_count") or 0)
            passed = findings_count == 0 or risk in ("none", "ok", "pass", "info", "low")
            if not passed:
                continue

            due = conn.execute(
                "SELECT COUNT(1) FROM remediations WHERE organization_id=? AND asset_key=? AND status='merged'",
                (org_id, ak),
            ).fetchone()
            to_close = int((due or [0])[0] or 0)
            if to_close <= 0:
                continue

            conn.execute(
                """
                UPDATE remediations
                SET status='verified_closed',
                    verification_scan_id=?,
                    closed_at=?,
                    updated_at=?
                WHERE organization_id=? AND asset_key=? AND status='merged'
                """,
                (str(scan_id or ""), now, now, org_id, ak),
            )
            closed += to_close
        conn.commit()

    return {"scan_id": str(scan_id or ""), "assets_checked": assets_checked, "closed": closed}


# -----------------------------
# Sprint 13: RBAC + immutable audit log
# -----------------------------

#: One audit-chain writer at a time per tenant within this process. On Postgres the chain is also
#: serialized across replicas by a transaction-scoped advisory lock (pg_append_audit_log); on
#: SQLite there is only ever one process writing the file.
_AUDIT_CHAIN_LOCKS: Dict[str, threading.Lock] = {}
_AUDIT_CHAIN_LOCKS_GUARD = threading.Lock()


@contextmanager
def _audit_chain_lock(org_id: str):
    key = str(org_id or "")
    with _AUDIT_CHAIN_LOCKS_GUARD:
        lock = _AUDIT_CHAIN_LOCKS.get(key)
        if lock is None:
            lock = _AUDIT_CHAIN_LOCKS[key] = threading.Lock()
    with lock:
        yield


def append_audit_log(
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str = "",
    decision: str = "allow",
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_append_audit_log(
            org_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision,
            reason=reason,
            details=details,
        )
    created_at = _utc_now_iso()
    details_json = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    # The chain is a read-modify-write (read the newest entry_hash, hash it into this entry,
    # insert). Two concurrent appends for the same tenant used to read the same prev_hash and fork
    # the chain, so verification failed on an honest log. One writer at a time per tenant.
    with _audit_chain_lock(org_id), closing(get_connection()) as conn:
        # Runs on every authorized request (via _require_role); the 7 DDL statements only need to run once.
        if not schema_ensured("sprint13_audit_logs"):
            _ensure_sprint13_tables(conn)
            mark_schema_ensured("sprint13_audit_logs")
        conn.row_factory = sqlite3.Row
        prev = conn.execute(
            "SELECT entry_hash FROM audit_logs WHERE organization_id=? ORDER BY id DESC LIMIT 1",
            (org_id,),
        ).fetchone()
        prev_hash = str((prev or {}).get("entry_hash") if isinstance(prev, dict) else (prev["entry_hash"] if prev else ""))
        entry_hash = _compute_audit_entry_hash(
            prev_hash=prev_hash,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision,
            reason=reason,
            details_json=details_json,
            created_at=created_at,
        )
        cur = conn.execute(
            """
            INSERT INTO audit_logs (
                organization_id, actor_id, actor_role, action, resource_type, resource_id, decision,
                reason, details_json, prev_hash, entry_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                str(actor_id or "").strip(),
                str(actor_role or "").strip().lower(),
                str(action or "").strip(),
                str(resource_type or "").strip(),
                str(resource_id or "").strip(),
                str(decision or "allow").strip().lower(),
                str(reason or "").strip(),
                details_json,
                prev_hash,
                entry_hash,
                created_at,
            ),
        )
        audit_id = int(cur.lastrowid or 0)
        row = conn.execute("SELECT * FROM audit_logs WHERE organization_id=? AND id=?", (org_id, audit_id)).fetchone()
        conn.commit()
    return dict(row) if row else {"id": audit_id}


def list_audit_logs(
    limit: int = 200,
    actor_id: str = "",
    action: str = "",
    decision: str = "",
) -> List[Dict[str, Any]]:
    # Routine "allowed" records are written by a background writer (services/audit_queue); drain it
    # first so an entry is never missing from a list or a chain verification that should hold it.
    try:
        from services.audit_queue import flush as _flush_audit_queue
        _flush_audit_queue()
    except Exception:
        pass
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_audit_logs(
            org_id,
            limit=limit,
            actor_id=actor_id,
            action=action,
            decision=decision,
        )
    limit = max(1, min(int(limit or 200), 2000))
    clauses: List[str] = ["organization_id = ?"]
    params: List[Any] = [org_id]
    actor_id = str(actor_id or "").strip()
    action = str(action or "").strip()
    decision = str(decision or "").strip().lower()

    if actor_id:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if decision:
        clauses.append("decision = ?")
        params.append(decision)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with closing(get_connection()) as conn:
        _ensure_sprint13_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def _normalize_flight_event(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row or {})
    out["evidence_refs"] = _json_obj(out.pop("evidence_refs_json", "{}"))
    out["details"] = _json_obj(out.pop("details_json", "{}"))
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    return out


def append_flight_recorder_event(
    *,
    actor_type: str,
    actor_id: str,
    actor_role: str,
    intent: str,
    resource_type: str,
    resource_id: str = "",
    policy_version: str = "",
    decision: str = "allowed",
    outcome: str = "pending",
    reason: str = "",
    evidence_refs: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_append_flight_recorder_event(
            org_id,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_role=actor_role,
            intent=intent,
            resource_type=resource_type,
            resource_id=resource_id,
            policy_version=policy_version,
            decision=decision,
            outcome=outcome,
            reason=reason,
            evidence_refs=evidence_refs or {},
            details=details or {},
        )
    created_at = _utc_now_iso()
    evidence_refs_json = json.dumps(evidence_refs or {}, separators=(",", ":"), sort_keys=True)
    details_json = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    with closing(get_connection()) as conn:
        _ensure_flight_recorder_tables(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO flight_recorder_events (
                organization_id, actor_type, actor_id, actor_role, intent, resource_type, resource_id,
                policy_version, decision, outcome, reason, evidence_refs_json, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id,
                str(actor_type or "human").strip().lower() or "human",
                str(actor_id or "").strip(),
                str(actor_role or "").strip().lower(),
                str(intent or "").strip(),
                str(resource_type or "").strip(),
                str(resource_id or "").strip(),
                str(policy_version or "").strip(),
                str(decision or "allowed").strip().lower(),
                str(outcome or "pending").strip().lower(),
                str(reason or "").strip(),
                evidence_refs_json,
                details_json,
                created_at,
            ),
        )
        event_id = int(cur.lastrowid or 0)
        row = conn.execute("SELECT * FROM flight_recorder_events WHERE organization_id=? AND id=?", (org_id, event_id)).fetchone()
        conn.commit()
    return _normalize_flight_event(dict(row)) if row else {"id": event_id}


def list_flight_recorder_events(
    *,
    limit: int = 200,
    intent: str = "",
    resource_type: str = "",
    resource_id: str = "",
    decision: str = "",
    actor_id: str = "",
) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_flight_recorder_events(
            org_id,
            limit=limit,
            intent=intent,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision,
            actor_id=actor_id,
        )
    limit = max(1, min(int(limit or 200), 2000))
    clauses: List[str] = ["organization_id = ?"]
    params: List[Any] = [org_id]
    filters = {
        "intent": str(intent or "").strip(),
        "resource_type": str(resource_type or "").strip(),
        "resource_id": str(resource_id or "").strip(),
        "decision": str(decision or "").strip().lower(),
        "actor_id": str(actor_id or "").strip(),
    }
    for key, value in filters.items():
        if value:
            clauses.append(f"{key} = ?")
            params.append(value)
    with closing(get_connection()) as conn:
        _ensure_flight_recorder_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM flight_recorder_events WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [_normalize_flight_event(dict(r)) for r in rows]


def _vendor_token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _normalize_vendor_invite(row: Dict[str, Any], include_token: str = "") -> Dict[str, Any]:
    out = dict(row or {})
    out.pop("token_hash", None)
    if include_token:
        out["token"] = include_token
    return out


def _normalize_vendor_submission(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row or {})
    for key in ("domains_json", "answers_json", "evidence_refs_json"):
        dest = key[:-5]
        try:
            out[dest] = json.loads(out.get(key) or ("[]" if key == "domains_json" else "{}"))
        except Exception:
            out[dest] = [] if key == "domains_json" else {}
        out.pop(key, None)
    return out


def create_vendor_attestation_invite(
    *,
    vendor_name: str,
    vendor_email: str = "",
    expires_days: int = 30,
    created_by: str = "",
) -> Dict[str, Any]:
    org_id = current_organization_id()
    token = secrets.token_urlsafe(32)
    now = _utc_now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=max(1, min(int(expires_days or 30), 365)))).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with closing(get_connection()) as conn:
        _ensure_vendor_attestation_tables(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO vendor_attestation_invites (
                organization_id, vendor_name, vendor_email, token_hash, status, expires_at, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)
            """,
            (org_id, str(vendor_name or "").strip(), str(vendor_email or "").strip(), _vendor_token_hash(token), expires_at, str(created_by or "").strip(), now, now),
        )
        invite_id = int(cur.lastrowid or 0)
        row = conn.execute("SELECT * FROM vendor_attestation_invites WHERE id=?", (invite_id,)).fetchone()
        conn.commit()
    return _normalize_vendor_invite(dict(row), include_token=token) if row else {"id": invite_id, "token": token}


def get_vendor_attestation_invite_by_token(token: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_vendor_attestation_tables(conn)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM vendor_attestation_invites WHERE token_hash=?", (_vendor_token_hash(token),)).fetchone()
    return _normalize_vendor_invite(dict(row)) if row else None


def list_vendor_attestation_invites(limit: int = 200) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 200), 1000))
    with closing(get_connection()) as conn:
        _ensure_vendor_attestation_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM vendor_attestation_invites WHERE organization_id=? ORDER BY id DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    return [_normalize_vendor_invite(dict(r)) for r in rows]


def submit_vendor_attestation(
    *,
    token: str,
    submitted_by: str,
    signer_title: str = "",
    domains: Optional[List[str]] = None,
    answers: Optional[Dict[str, Any]] = None,
    evidence_refs: Optional[Dict[str, Any]] = None,
    readiness_score: float = 0,
) -> Dict[str, Any]:
    token_hash = _vendor_token_hash(token)
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_vendor_attestation_tables(conn)
        conn.row_factory = sqlite3.Row
        invite = conn.execute("SELECT * FROM vendor_attestation_invites WHERE token_hash=?", (token_hash,)).fetchone()
        if not invite:
            raise ValueError("invalid attestation token")
        invite_d = dict(invite)
        if str(invite_d.get("status") or "") not in {"open", "submitted"}:
            raise ValueError("attestation invite is not open")
        expires_at = str(invite_d.get("expires_at") or "")
        if expires_at and expires_at < now:
            raise ValueError("attestation invite is expired")
        score = max(0.0, min(float(readiness_score or 0), 100.0))
        cur = conn.execute(
            """
            INSERT INTO vendor_attestation_submissions (
                organization_id, invite_id, vendor_name, submitted_by, signer_title, domains_json,
                answers_json, evidence_refs_json, readiness_score, signed_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(invite_d.get("organization_id") or ""),
                int(invite_d.get("id") or 0),
                str(invite_d.get("vendor_name") or ""),
                str(submitted_by or "").strip(),
                str(signer_title or "").strip(),
                json.dumps([str(x).strip() for x in (domains or []) if str(x).strip()], separators=(",", ":"), sort_keys=True),
                json.dumps(answers or {}, separators=(",", ":"), sort_keys=True),
                json.dumps(evidence_refs or {}, separators=(",", ":"), sort_keys=True),
                score,
                now,
                now,
            ),
        )
        conn.execute("UPDATE vendor_attestation_invites SET status='submitted', updated_at=? WHERE id=?", (now, int(invite_d.get("id") or 0)))
        row = conn.execute("SELECT * FROM vendor_attestation_submissions WHERE id=?", (int(cur.lastrowid or 0),)).fetchone()
        conn.commit()
    return _normalize_vendor_submission(dict(row)) if row else {}


def list_vendor_attestations(limit: int = 200) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 200), 1000))
    with closing(get_connection()) as conn:
        _ensure_vendor_attestation_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM vendor_attestation_submissions WHERE organization_id=? ORDER BY id DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    return [_normalize_vendor_submission(dict(r)) for r in rows]


# -----------------------------
# Sprint 14.1: organizations
# -----------------------------

def upsert_organization(
    organization_id: str,
    name: str,
    plan_type: str = "starter",
    subscription_status: str = "active",
) -> Dict[str, Any]:
    oid = str(organization_id or "").strip()
    if not oid:
        raise ValueError("organization_id is required")
    nm = str(name or "").strip()
    if not nm:
        raise ValueError("organization name is required")
    if postgres_main_db_requested():
        return pg_upsert_organization(
            oid,
            name=nm,
            plan_type=plan_type,
            subscription_status=subscription_status,
        )
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.execute(
            """
            INSERT INTO organizations (id, name, plan_type, subscription_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                plan_type=excluded.plan_type,
                subscription_status=excluded.subscription_status,
                updated_at=excluded.updated_at
            """,
            (oid, nm, str(plan_type or "starter").strip(), str(subscription_status or "active").strip(), now, now),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, plan_type, subscription_status, created_at, updated_at FROM organizations WHERE id=?",
            (oid,),
        ).fetchone()
    return dict(row) if row else {"id": oid, "name": nm}


def list_organizations(limit: int = 200, *, offset: int = 0) -> List[Dict[str, Any]]:
    if postgres_main_db_requested():
        return pg_list_organizations(limit=limit, offset=offset)
    lim = max(1, min(int(limit or 200), 2000))
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, plan_type, subscription_status, created_at, updated_at FROM organizations ORDER BY updated_at DESC,id LIMIT ? OFFSET ?",
            (lim, max(0, int(offset))),
        ).fetchall()
    return [dict(r) for r in rows]


def archive_organization(organization_id: str) -> Optional[Dict[str, Any]]:
    oid = str(organization_id or "").strip()
    if not oid:
        raise ValueError("organization_id is required")
    if postgres_main_db_requested():
        return pg_archive_organization(oid)
    now = _utc_now_iso()
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE organizations SET subscription_status='archived', updated_at=? WHERE id=?",
            (now, oid),
        )
        row = conn.execute(
            "SELECT id, name, plan_type, subscription_status, created_at, updated_at FROM organizations WHERE id=?",
            (oid,),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def delete_organization(organization_id: str, mode: str = "archive") -> Dict[str, Any]:
    oid = str(organization_id or "").strip()
    if not oid:
        raise ValueError("organization_id is required")
    if postgres_main_db_requested():
        return pg_delete_organization(oid, mode=mode)
    if str(mode or "archive").strip().lower() != "purge":
        return {"ok": True, "mode": "archive", "organization": archive_organization(oid)}

    tables = [
        "event_rule_fires",
        "event_rules",
        "webhook_events",
        "webhooks",
        "validation_jobs",
        "migration_tasks",
        "remediations",
        "scan_results",
        "baselines",
        "asset_tags",
        "assets",
        "repositories",
        "github_installations",
        "organization_memberships",
        "credentials",
        "audit_logs",
        "schedules",
        "collections",
        "scans",
    ]
    counts: Dict[str, int] = {}
    with closing(get_connection()) as conn:
        _ensure_sprint14_tables(conn)
        for table in tables:
            try:
                cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                if "organization_id" not in cols:
                    continue
                cur = conn.execute(f"DELETE FROM {table} WHERE organization_id=?", (oid,))
                counts[table] = int(cur.rowcount or 0)
            except Exception:
                continue
        cur = conn.execute("DELETE FROM organizations WHERE id=?", (oid,))
        counts["organizations"] = int(cur.rowcount or 0)
        conn.commit()
    return {"ok": True, "mode": "purge", "organization_id": oid, "deleted": counts}


# -----------------------------
# Sprint 5: collections + scheduling + history
# -----------------------------

def upsert_collection(name: str, targets_text: str, description: str = "") -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_upsert_collection(org_id, name, targets_text)
    name = (name or "").strip()
    if not name:
        raise ValueError("collection name is required")
    targets_text = (targets_text or "").strip()
    if not targets_text:
        raise ValueError("targets_text is required")
    description = (description or "").strip()

    now = _utc_now_iso()
    with closing(get_connection()) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _ensure_sprint5_tables(conn)
        row = conn.execute("SELECT id FROM collections WHERE organization_id=? AND name = ?", (org_id, name)).fetchone()
        if row:
            cid = int(row[0])
            conn.execute(
                "UPDATE collections SET targets_text=?, description=?, updated_at=? WHERE organization_id=? AND id=?",
                (targets_text, description, now, org_id, cid),
            )
        else:
            cur = conn.execute(
                "INSERT INTO collections (organization_id, name, targets_text, description, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (org_id, name, targets_text, description, now, now),
            )
            cid = int(cur.lastrowid)
        conn.commit()
    return get_collection(cid)

def list_collections() -> list[dict]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_collections(org_id)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, organization_id, name, targets_text, description, created_at, updated_at FROM collections WHERE organization_id=? ORDER BY name ASC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

def get_collection(collection_id: int) -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_get_collection(org_id, collection_id)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, organization_id, name, targets_text, description, created_at, updated_at FROM collections WHERE organization_id=? AND id = ?",
            (org_id, int(collection_id)),
        ).fetchone()
        if not row:
            raise KeyError("collection not found")
        return dict(row)

def delete_collection(collection_id: int) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_delete_collection(org_id, collection_id)
        return
    with closing(get_connection()) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DELETE FROM collections WHERE organization_id=? AND id = ?", (org_id, int(collection_id)))
        conn.commit()

def create_schedule(collection_id: int, interval_minutes: int, enabled: bool = True) -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_create_schedule(org_id, collection_id, interval_minutes, enabled=enabled)
    if int(interval_minutes) <= 0:
        raise ValueError("interval_minutes must be > 0")
    now = _utc_now_iso()
    dt = _parse_iso_datetime(now)
    next_dt = dt + timedelta(minutes=int(interval_minutes))
    next_run = _iso_z(next_dt)

    with closing(get_connection()) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        exists = conn.execute("SELECT id FROM collections WHERE organization_id=? AND id = ?", (org_id, int(collection_id))).fetchone()
        if not exists:
            raise KeyError("collection not found")
        cur = conn.execute(
            """
            INSERT INTO schedules (organization_id, collection_id, enabled, interval_minutes, created_at, updated_at, last_run_at, next_run_at, last_scan_id)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (org_id, int(collection_id), 1 if enabled else 0, int(interval_minutes), now, now, "", next_run, ""),
        )
        conn.commit()
        sid = int(cur.lastrowid)
    return get_schedule(sid)

def list_schedules() -> list[dict]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_schedules(org_id)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT s.id, s.organization_id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
            WHERE s.organization_id = ?
            ORDER BY s.id DESC
            """,
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

def get_schedule(schedule_id: int) -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_get_schedule(org_id, schedule_id)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT s.id, s.organization_id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
            WHERE s.organization_id = ? AND s.id = ?
            """,
            (org_id, int(schedule_id)),
        ).fetchone()
        if not row:
            raise KeyError("schedule not found")
        return dict(row)

def update_schedule(schedule_id: int, interval_minutes: int | None = None, enabled: bool | None = None) -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_update_schedule(org_id, schedule_id, interval_minutes=interval_minutes, enabled=enabled)
    now = _utc_now_iso()
    with closing(get_connection()) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        row = conn.execute("SELECT interval_minutes, enabled FROM schedules WHERE organization_id=? AND id=?", (org_id, int(schedule_id))).fetchone()
        if not row:
            raise KeyError("schedule not found")
        cur_interval = int(row[0])
        cur_enabled = int(row[1])

        new_interval = int(interval_minutes) if interval_minutes is not None else cur_interval
        if new_interval <= 0:
            raise ValueError("interval_minutes must be > 0")
        new_enabled = (1 if enabled else 0) if enabled is not None else cur_enabled

        dt = _parse_iso_datetime(now)
        next_dt = dt + timedelta(minutes=int(new_interval))
        next_run = _iso_z(next_dt)

        conn.execute(
            "UPDATE schedules SET enabled=?, interval_minutes=?, updated_at=?, next_run_at=? WHERE organization_id=? AND id=?",
            (new_enabled, new_interval, now, next_run, org_id, int(schedule_id)),
        )
        conn.commit()
    return get_schedule(int(schedule_id))

def delete_schedule(schedule_id: int) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_delete_schedule(org_id, schedule_id)
        return
    with closing(get_connection()) as conn, conn:
        conn.execute("DELETE FROM schedules WHERE organization_id=? AND id = ?", (org_id, int(schedule_id)))
        conn.commit()

def due_schedules(now_iso: str) -> list[dict]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_due_schedules(org_id, now_iso)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT s.id, s.organization_id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
            WHERE s.organization_id=? AND s.enabled=1 AND s.next_run_at <> '' AND s.next_run_at <= ?
            ORDER BY s.next_run_at ASC
            """,
            (org_id, now_iso),
        ).fetchall()
        return [dict(r) for r in rows]

def mark_schedule_ran(schedule_id: int, run_at_iso: str, interval_minutes: int, last_scan_id: str) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_mark_schedule_ran(org_id, schedule_id, run_at_iso, interval_minutes, last_scan_id)
        return
    run_dt = _parse_iso_datetime(run_at_iso)
    next_dt = run_dt + timedelta(minutes=int(interval_minutes))
    next_run = _iso_z(next_dt)
    with closing(get_connection()) as conn, conn:
        conn.execute(
            "UPDATE schedules SET last_run_at=?, next_run_at=?, last_scan_id=?, updated_at=? WHERE organization_id=? AND id=?",
            (run_at_iso, next_run, last_scan_id, _utc_now_iso(), org_id, int(schedule_id)),
        )
        conn.commit()

def save_scan_asset_summaries(scan_id: str, scanned_at_iso: str, results: list[dict]) -> None:
    org_id = current_organization_id()
    scanned_at_iso = scanned_at_iso or _utc_now_iso()
    if postgres_main_db_requested():
        pg_save_scan_asset_summaries(org_id, scan_id, scanned_at_iso, results)
        return
    with closing(get_connection()) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        for r in results or []:
            ak = asset_key(r.get("host",""), int(r.get("port",443)))
            findings = r.get("findings") or []
            findings_count = len(findings) if isinstance(findings, list) else 0
            risk_level = str(r.get("risk") or r.get("risk_level") or "unknown")
            quantum_score = float(r.get("quantum_risk_score") or r.get("quantum_score") or r.get("score") or 0.0)
            pqc_rel = str(r.get("pqc_relevance") or "")
            tls_ver = str(r.get("tls_version") or "")
            key_type = str(r.get("key_type") or "")
            sig_alg = str(r.get("sig_algorithm") or "")
            observed = scan_result_observation(r)

            # A scanned endpoint is an asset. Nothing in the scan path registered one, so after
            # scanning an estate /assets was empty and every report that iterates the inventory --
            # the HNDL dashboard above all -- reported zero assets and $0 exposure. Registration
            # only creates the row; owner, team, environment and criticality stay exactly as the
            # customer set them, and stay blank when the customer has not set them.
            register_scanned_asset(ak, conn=conn)

            a = get_asset(ak)
            owner = (a.get("owner") or "") if isinstance(a, dict) else ""
            team = (a.get("team") or "") if isinstance(a, dict) else ""
            env = (a.get("environment") or "") if isinstance(a, dict) else ""
            crit = (a.get("criticality") or "") if isinstance(a, dict) else ""

            conn.execute(
                """
                INSERT INTO scan_results (
                    organization_id,
                    asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                    pqc_relevance, tls_version, key_type, sig_algorithm,
                    owner, team, environment, criticality,
                    key_bits, key_curve, cipher_name, scan_status, key_exchange
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (org_id, ak, scan_id, scanned_at_iso, risk_level, quantum_score, findings_count,
                 pqc_rel, tls_ver, key_type, sig_alg,
                 owner, team, env, crit,
                 observed["key_bits"], observed["key_curve"],
                 observed["cipher_name"], observed["scan_status"], observed["key_exchange"]),
            )
        conn.commit()


def register_scanned_asset(asset_key_str: str, conn: Optional[sqlite3.Connection] = None) -> None:
    """Create the inventory row for a scanned endpoint, without touching what the customer owns.

    `upsert_asset()` cannot be used for this: called with its defaults it writes empty strings over
    owner/team/environment/criticality, so re-scanning an endpoint would silently erase the
    ownership and data-classification the customer entered. This inserts and then stops -- a second
    scan of the same host and port updates nothing and creates no second row, because
    (organization_id, asset_key) is the primary key.
    """
    ak = str(asset_key_str or "").strip()
    if not ak:
        return
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_register_scanned_asset(org_id, ak)
        return

    def _insert(c: sqlite3.Connection) -> None:
        c.execute(
            """
            INSERT INTO assets (organization_id, asset_key, owner, team, environment, criticality,
                                confidentiality_lifetime, notes, metadata_json, repository_id, updated_at)
            VALUES (?, ?, '', '', '', '', '', '', '{}', 0, ?)
            ON CONFLICT(organization_id, asset_key) DO NOTHING
            """,
            (org_id, ak, _utc_now_iso()),
        )

    if conn is not None:
        _insert(conn)
        return
    with closing(get_connection()) as own:
        _insert(own)
        own.commit()

def get_asset_history(asset_key_str: str, limit: int = 50) -> list[dict]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit), 200))
    if postgres_main_db_requested():
        return pg_get_asset_history(org_id, asset_key_str, limit=limit)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT scanned_at, scan_id, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   owner, team, environment, criticality,
                   key_bits, key_curve, cipher_name, scan_status, key_exchange
            FROM scan_results
            WHERE organization_id = ? AND asset_key = ?
            ORDER BY scanned_at DESC
            LIMIT ?
            """,
            (org_id, asset_key_str, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def list_scan_results(scan_id: str, owner: str = "", team: str = "", environment: str = "", criticality: str = "", limit: int = 5000) -> list[dict]:
    org_id = current_organization_id()
    """Return scan_results rows for a scan, optionally filtered by inventory snapshot fields."""
    limit = max(1, min(int(limit), 20000))
    owner = (owner or "").strip()
    team = (team or "").strip()
    environment = (environment or "").strip()
    criticality = (criticality or "").strip()
    if postgres_main_db_requested():
        return pg_list_scan_results(
            org_id,
            scan_id,
            owner=owner,
            team=team,
            environment=environment,
            criticality=criticality,
            limit=limit,
        )

    clauses = ["organization_id = ?", "scan_id = ?"]
    params = [org_id, scan_id]

    if owner:
        clauses.append("owner = ?")
        params.append(owner)
    if team:
        clauses.append("team = ?")
        params.append(team)
    if environment:
        clauses.append("environment = ?")
        params.append(environment)
    if criticality:
        clauses.append("criticality = ?")
        params.append(criticality)

    where = " AND ".join(clauses)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   owner, team, environment, criticality,
                   key_bits, key_curve, cipher_name, scan_status, key_exchange
            FROM scan_results
            WHERE {where}
            ORDER BY quantum_score DESC, findings_count DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            d = dict(r)
            try:
                a = get_asset(d.get("asset_key") or "")
                if a:
                    d["repository_id"] = a.get("repository_id") or 0
                    d["repository_name"] = a.get("repository_name") or ""
                    d["repository_html_url"] = a.get("repository_html_url") or ""
            except Exception:
                pass
            out.append(d)
        return out

#: Columns every per-asset scan-fact reader needs. One list so the SQLite and Postgres statements
#: below cannot drift apart.
_SCAN_FACT_COLUMNS = (
    "asset_key", "scan_id", "scanned_at", "risk_level", "quantum_score", "findings_count",
    "pqc_relevance", "tls_version", "key_type", "sig_algorithm",
    "owner", "team", "environment", "criticality",
    "key_bits", "key_curve", "cipher_name", "scan_status", "key_exchange",
)


def _like_contains(text: str) -> str:
    r"""A `LIKE ... ESCAPE '\'` "contains" pattern in which the caller's %, _ and \ stay literal."""
    escaped = str(text or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def count_assets() -> int:
    """How many assets this organization has, without fetching them."""
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_count_assets(org_id)
    with closing(get_connection()) as conn, conn:
        try:
            row = conn.execute("SELECT COUNT(*) FROM assets WHERE organization_id = ?", (org_id,)).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return 0
            raise
    return int((row or [0])[0] or 0)


def recent_scan_result_times(limit: int = 2000) -> list[str]:
    """The `scanned_at` of this organization's newest scan results, newest first.

    Scan cadence is derived from these. Reading them through the dialect router matters: the
    handler that measures cadence used to run the query against the local SQLite file directly,
    so on a Postgres deployment it saw no timestamps at all and reported "cadence not measured".
    """
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 2000), 20000))
    if postgres_main_db_requested():
        return pg_recent_scan_result_times(org_id, limit=limit)
    with closing(get_connection()) as conn, conn:
        try:
            rows = conn.execute(
                "SELECT scanned_at FROM scan_results WHERE organization_id = ? ORDER BY scanned_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return []
            raise
    return [str(r[0] or "") for r in rows if r and r[0]]


def latest_scan_facts_for_org(limit: int = 5000) -> list[dict]:
    """The newest scan_results row per asset for the current tenant, newest scan first.

    This replaces `list_scan_results_since("1970-01-01", limit=50000)` followed by a Python
    de-duplication and sort. That shape read every scan result the tenant had ever recorded --
    50,000 rows materialised as Python dicts before a caller's `limit=5000` was applied -- on the
    path used by /executive-dashboard, /board-risk, /heatmap, /cbom and /crypto-agility. It also
    truncated the *oldest* 50,000 rows (the read was ordered ascending), so a tenant past that
    cap lost its newest scans rather than its oldest ones.

    One statement per dialect now does the same work: DISTINCT ON in Postgres, a ROW_NUMBER()
    window in SQLite. `LIMIT` is applied by the database, so the row count this returns is
    bounded by the caller's limit rather than by the size of the tenant's history.
    """
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 5000), 50000))
    if postgres_main_db_requested():
        return pg_latest_scan_facts_for_org(org_id, limit=limit)
    columns = ", ".join(_SCAN_FACT_COLUMNS)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                f"""
                SELECT {columns} FROM (
                    SELECT {columns},
                           ROW_NUMBER() OVER (
                               PARTITION BY asset_key ORDER BY scanned_at DESC, id DESC
                           ) AS _rn
                    FROM scan_results
                    WHERE organization_id = ?
                ) ranked
                WHERE _rn = 1
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                try:
                    _ensure_sprint5_tables(conn)
                    conn.commit()
                except Exception:
                    pass
                return []
            raise
        return [dict(r) for r in rows]


def list_scan_results_since(since_iso: str, limit: int = 10000) -> list[dict]:
    org_id = current_organization_id()
    """Return scan_results rows since a timestamp (ISO).
    This is used for trends. If the scan_results table is missing (e.g., DB was created before Sprint 5/6),
    we gracefully return an empty list instead of crashing the API.
    """
    limit = max(1, min(int(limit), 50000))  # Hard cap at 50k; callers should paginate for larger ranges
    if postgres_main_db_requested():
        return pg_list_scan_results_since(org_id, since_iso, limit=limit)
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       owner, team, environment, criticality,
                       key_bits, key_curve, cipher_name, scan_status, key_exchange
                FROM scan_results
                WHERE organization_id = ? AND scanned_at >= ?
                ORDER BY scanned_at ASC
                LIMIT ?
                """,
                (org_id, since_iso, limit),
            ).fetchall()
        except sqlite3.OperationalError as e:
            # Typical: "no such table: scan_results"
            if "no such table" in str(e).lower():
                # Ensure tables exist for future calls
                try:
                    _ensure_sprint5_tables(conn)
                    conn.commit()
                except Exception:
                    pass
                return []
            raise
        return [dict(r) for r in rows]


# -----------------------------
# Sprint 8 Integrations: Webhooks + Delivery Log
# -----------------------------

def _ensure_integrations_settings_table(conn: sqlite3.Connection) -> None:
    """Ensure settings table exists for integrations."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS integrations_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        '''
    )
    conn.commit()


def get_integration_setting(key: str, default: str = "") -> str:
    """Fetch a persisted integrations setting."""
    if postgres_main_db_requested():
        return pg_get_integration_setting(key, default=default)
    with closing(get_connection()) as conn:
        _ensure_integrations_settings_table(conn)
        row = conn.execute("SELECT value FROM integrations_settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_integration_setting(key: str, value: str) -> None:
    """Persist an integrations setting."""
    if postgres_main_db_requested():
        pg_set_integration_setting(key, value)
        return
    with closing(get_connection()) as conn:
        _ensure_integrations_settings_table(conn)
        conn.execute(
            "INSERT INTO integrations_settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        conn.commit()


# -----------------------------
# Sprint 10.3: Connector settings helpers (Cloudflare, etc.)
# These are thin wrappers around integrations_settings.
# -----------------------------

def get_cloudflare_credential_id() -> Optional[int]:
    raw = str(get_integration_setting("cloudflare_credential_id", "") or "").strip()
    try:
        return int(raw) if raw else None
    except Exception:
        return None


def set_cloudflare_credential_id(cred_id: Optional[int]) -> None:
    if cred_id is None:
        set_integration_setting("cloudflare_credential_id", "")
        return
    try:
        cid = int(cred_id)
    except Exception:
        cid = 0
    if cid < 1:
        set_integration_setting("cloudflare_credential_id", "")
    else:
        set_integration_setting("cloudflare_credential_id", str(cid))


def get_cloudflare_last_verified_at() -> str:
    return str(get_integration_setting("cloudflare_last_verified_at", "") or "")


def set_cloudflare_last_verified_at(ts_iso: str) -> None:
    set_integration_setting("cloudflare_last_verified_at", str(ts_iso or ""))


def get_cloudflare_last_verify_ok() -> bool:
    return str(get_integration_setting("cloudflare_last_verify_ok", "0") or "0").strip() == "1"


def set_cloudflare_last_verify_ok(ok: bool) -> None:
    set_integration_setting("cloudflare_last_verify_ok", "1" if ok else "0")

def get_cloudflare_token_expires_on() -> str:
    return str(get_integration_setting("cloudflare_token_expires_on", "") or "")


def get_cloudflare_last_zones_at() -> str:
    return str(get_integration_setting("cloudflare_last_zones_at", "") or "")


def get_cloudflare_last_zones_count() -> int:
    raw = str(get_integration_setting("cloudflare_last_zones_count", "0") or "0").strip()
    try:
        return int(raw)
    except Exception:
        return 0


def get_cloudflare_last_rotated_at() -> str:
    return str(get_integration_setting("cloudflare_last_rotated_at", "") or "")


def get_cloudflare_last_rotate_ok() -> bool:
    return str(get_integration_setting("cloudflare_last_rotate_ok", "0") or "0").strip() == "1"


def get_cloudflare_last_rotate_error() -> str:
    return str(get_integration_setting("cloudflare_last_rotate_error", "") or "")


def list_webhooks(limit: int = 200, include_secret: bool = False) -> list[dict]:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_webhooks(org_id, limit=limit, include_secret=include_secret)
    limit = max(1, min(int(limit), 500))
    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        _ensure_integrations_tables(conn)
        rows = conn.execute(
            "SELECT id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at, rate_limit_per_minute, timeout_seconds "
            "FROM webhooks WHERE organization_id=? ORDER BY id DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
        out = []
        for r in rows:
            try:
                ev = json.loads(r["events_json"] or "[]")
            except Exception:
                ev = []
            item = {
                "id": r["id"],
                "name": r["name"],
                "url": r["url"],
                "credential_id": r["credential_id"],
                "events": ev,
                "enabled": bool(r["enabled"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "rate_limit_per_minute": int(r["rate_limit_per_minute"] or 60),
                "timeout_seconds": int(r["timeout_seconds"] or 10),
                "has_secret": bool((r["secret"] or "") or r["credential_id"]),
                "secret_masked": "********" if ((r["secret"] or "") or r["credential_id"]) else "",
            }
            if include_secret:
                item["secret"] = r["secret"]
            out.append(item)
        return out


def list_webhooks_public(limit: int = 200) -> list[dict]:
    """
    Public/safe list of webhooks for the UI.
    Never returns secrets.
    Works across older DB schemas (no 'events' column).
    """
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_list_webhooks_public(org_id, limit=limit)
    limit = int(limit or 200)
    limit = max(1, min(500, limit))

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        _ensure_integrations_tables(conn)

        # detect existing columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(webhooks)").fetchall()}

        select_cols = ["id"]
        if "name" in cols: select_cols.append("name")
        if "url" in cols: select_cols.append("url")
        if "enabled" in cols: select_cols.append("enabled")
        if "created_at" in cols: select_cols.append("created_at")
        if "updated_at" in cols: select_cols.append("updated_at")

        # IMPORTANT: only include these if they exist
        if "events" in cols: select_cols.append("events")          # some DBs have it
        if "event_types" in cols: select_cols.append("event_types")# some DBs use this name
        if "secret" in cols: select_cols.append("secret")

        q = f"SELECT {', '.join(select_cols)} FROM webhooks WHERE organization_id=? ORDER BY id DESC LIMIT ?"
        rows = conn.execute(q, (org_id, limit)).fetchall()

        out = []
        for r in rows:
            d = dict(r)

            # compute safe/derived fields
            secret = (d.get("secret") or "").strip()
            d["has_secret"] = bool(secret or d.get("credential_id"))
            d["secret_masked"] = "********" if d["has_secret"] else ""
            d["secret"] = None  # never return secret

            # normalize events list for UI if present
            # (UI can ignore these if it doesn't use them)
            if "events" in d and d["events"] is None:
                d["events"] = ""
            if "event_types" in d and d["event_types"] is None:
                d["event_types"] = ""

            out.append(d)

        return out
    finally:
        conn.close()



def upsert_webhook(
    name: str,
    url: str,
    secret: str = "",
    credential_id: Optional[int] = None,  # NEW
    events: Optional[List[str]] = None,
    enabled: bool = True,
    webhook_id: Optional[int] = None,
    rate_limit_per_minute: int = 60,
    timeout_seconds: int = 10,
) -> dict:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_upsert_webhook(
            org_id=org_id,
            name=name,
            url=url,
            secret=secret,
            credential_id=credential_id,
            events=events,
            enabled=enabled,
            webhook_id=webhook_id,
            rate_limit_per_minute=rate_limit_per_minute,
            timeout_seconds=timeout_seconds,
        )
    name = (name or "").strip()
    url = (url or "").strip()
    secret = secret or ""
    events = (["*"] if events is None else events)
    if not name:
        raise ValueError("name is required")
    if not url:
        raise ValueError("url is required")

    now = _utc_now_iso()
    ev_json = json.dumps(events)
    try:
        rate_limit_per_minute = max(1, int(rate_limit_per_minute or 60))
    except Exception:
        rate_limit_per_minute = 60
    try:
        timeout_seconds = max(1, int(timeout_seconds or 10))
    except Exception:
        timeout_seconds = 10

    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row
        if webhook_id:
            conn.execute(
                "UPDATE webhooks SET name=?, url=?, secret=?, credential_id=?, events_json=?, enabled=?, updated_at=?, rate_limit_per_minute=?, timeout_seconds=? WHERE organization_id=? AND id=?",
                (name, url, secret, credential_id, ev_json, 1 if enabled else 0, now, rate_limit_per_minute, timeout_seconds, org_id, int(webhook_id)),
            )
        else:
            # Insert or update by name
            conn.execute(
                "INSERT INTO webhooks(organization_id,name,url,secret,credential_id,events_json,enabled,created_at,updated_at,rate_limit_per_minute,timeout_seconds) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(organization_id,name) DO UPDATE SET "
                "url=excluded.url, secret=excluded.secret, credential_id=excluded.credential_id, "
                "events_json=excluded.events_json, enabled=excluded.enabled, updated_at=excluded.updated_at, "
                "rate_limit_per_minute=excluded.rate_limit_per_minute, timeout_seconds=excluded.timeout_seconds",
                (org_id, name, url, secret, credential_id, ev_json, 1 if enabled else 0, now, now, rate_limit_per_minute, timeout_seconds),
            )
        conn.commit()

        row = conn.execute(
            "SELECT id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at, rate_limit_per_minute, timeout_seconds FROM webhooks WHERE organization_id=? AND name=?",
            (org_id, name),
        ).fetchone()
        if not row:
            raise RuntimeError("failed to upsert webhook")

        try:
            ev = json.loads(row["events_json"] or "[]")
        except Exception:
            ev = []
        return {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "secret": row["secret"],
            "credential_id": row["credential_id"],
            "events": ev,
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "rate_limit_per_minute": int(row["rate_limit_per_minute"] or 60),
            "timeout_seconds": int(row["timeout_seconds"] or 10),
        }



def delete_webhook(webhook_id: int) -> None:
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_delete_webhook(org_id, webhook_id)
        return
    with closing(get_connection()) as conn, conn:
        conn.execute("DELETE FROM webhooks WHERE organization_id=? AND id = ?", (org_id, int(webhook_id)))
        conn.commit()


def record_webhook_event(
    webhook_id: int,
    event_type: str,
    dedupe_key: str,
    payload: dict,
    status: str = "queued",
    http_status: int = 0,
    error_text: str = "",
    max_attempts: int = 5,
) -> Optional[int]:
    """Insert (or re-queue) an outgoing webhook delivery.

    Supports both:
      - New schema (payload_json/status/http_status/attempts/last_attempt_at)
      - Legacy schema where scan_id/asset_key/payload_sha256 are NOT NULL
    """
    org_id = current_organization_id()
    if postgres_main_db_requested():
        return pg_record_webhook_event(
            org_id=org_id,
            webhook_id=webhook_id,
            event_type=event_type,
            dedupe_key=dedupe_key,
            payload=payload,
            status=status,
            http_status=http_status,
            error_text=error_text,
            max_attempts=max_attempts,
        )
    import hashlib as _hashlib

    now = _utc_now_iso()
    payload_json = json.dumps(payload or {})
    payload_sha256 = _hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    with closing(get_connection()) as conn, conn:
        conn.row_factory = sqlite3.Row

        # Best-effort add of optional columns (never adds NOT NULL without default)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
            if "organization_id" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
                conn.execute("UPDATE webhook_events SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
            if "payload_json" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'")
            if "status" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
            if "http_status" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN http_status INTEGER NOT NULL DEFAULT 0")
            if "attempts" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if "last_attempt_at" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
            if "response_excerpt" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN response_excerpt TEXT NOT NULL DEFAULT ''")
            if "next_attempt_at" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN next_attempt_at TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        existing = conn.execute(
            "SELECT id, status, attempts FROM webhook_events WHERE organization_id=? AND webhook_id=? AND dedupe_key=?",
            (org_id, int(webhook_id), str(dedupe_key)),
        ).fetchone()

        if existing:
            st = str(existing["status"] or "")
            attempts = int(existing["attempts"] or 0)
            if st == "sent":
                return None
            if attempts >= int(max_attempts):
                return None

            # Re-queue: clear any backoff timer and prior response excerpt.
            cols2 = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
            sets = ["payload_json=?", "status=?", "http_status=?", "error_text=?"]
            vals = [payload_json, str(status), int(http_status), str(error_text or "")]
            if "next_attempt_at" in cols2:
                sets.append("next_attempt_at=?")
                vals.append("")
            if "response_excerpt" in cols2:
                sets.append("response_excerpt=?")
                vals.append("")
            vals.extend([org_id, int(existing["id"])])
            conn.execute(
                f"UPDATE webhook_events SET {', '.join(sets)} WHERE organization_id=? AND id=?",
                tuple(vals),
            )
            conn.commit()
            return int(existing["id"])

        # Schema-adaptive insert
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        data = payload.get("data") if isinstance(payload, dict) else {}
        if not isinstance(data, dict):
            data = {}

        scan_id = str(data.get("scan_id") or "")
        asset_key = str(data.get("asset_key") or "")

        insert_cols = []
        insert_vals = []

        def add(col: str, val):
            if col in cols:
                insert_cols.append(col)
                insert_vals.append(val)

        add("organization_id", org_id)
        add("webhook_id", int(webhook_id))
        add("event_type", str(event_type))
        add("dedupe_key", str(dedupe_key))

        # legacy required columns
        add("scan_id", scan_id)
        add("asset_key", asset_key)
        add("payload_sha256", payload_sha256)

        # time + payload
        add("created_at", now)
        add("payload_json", payload_json)

        # status fields
        add("status", str(status))
        add("http_status", int(http_status))
        add("error_text", str(error_text or ""))
        add("response_excerpt", "")

        # retry bookkeeping
        add("attempts", 0)
        add("last_attempt_at", "")
        add("next_attempt_at", "")

        # legacy delivery fields (safe defaults)
        add("ok", 0)
        add("status_code", int(http_status) if http_status else 0)
        add("delivered_at", "")

        sql = f"INSERT INTO webhook_events({','.join(insert_cols)}) VALUES ({','.join(['?']*len(insert_cols))})"
        try:
            cur = conn.execute(sql, tuple(insert_vals))
            row_id = int(cur.lastrowid)
            if "payload_json" in cols and isinstance(payload, dict):
                payload_with_delivery_id = dict(payload)
                payload_with_delivery_id.setdefault("delivery_id", str(row_id))
                conn.execute(
                    "UPDATE webhook_events SET payload_json=? WHERE organization_id=? AND id=?",
                    (json.dumps(payload_with_delivery_id), org_id, row_id),
                )
            conn.commit()
            return row_id
        except sqlite3.IntegrityError:
            return None


def bump_webhook_attempt(event_row_id: int) -> None:
    """Increment attempts and set last_attempt_at."""
    if postgres_main_db_requested():
        pg_bump_webhook_attempt(current_organization_id(), event_row_id)
        return
    now = _utc_now_iso()
    with closing(get_connection()) as conn, conn:
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
            if "attempts" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if "last_attempt_at" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        conn.execute(
            "UPDATE webhook_events SET attempts = attempts + 1, last_attempt_at=? WHERE organization_id=? AND id=?",
            (now, current_organization_id(), int(event_row_id)),
        )
        conn.commit()


def update_webhook_event(
    event_row_id: int,
    status: str,
    http_status: int = 0,
    error_text: str = "",
    response_excerpt: str = "",
    next_attempt_at: str = "",
) -> None:
    """Update delivery status in a schema-adaptive way."""
    if postgres_main_db_requested():
        pg_update_webhook_event(
            org_id=current_organization_id(),
            event_row_id=event_row_id,
            status=status,
            http_status=http_status,
            error_text=error_text,
            response_excerpt=response_excerpt,
            next_attempt_at=next_attempt_at,
        )
        return
    now = _utc_now_iso()
    with closing(get_connection()) as conn, conn:
        cols = set()
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            pass

        sets = []
        vals = []

        if "status" in cols:
            sets.append("status=?")
            vals.append(str(status))
        if "http_status" in cols:
            sets.append("http_status=?")
            vals.append(int(http_status))
        if "error_text" in cols:
            sets.append("error_text=?")
            vals.append(str(error_text or ""))
        if "response_excerpt" in cols:
            sets.append("response_excerpt=?")
            vals.append(str(response_excerpt or ""))
        if "next_attempt_at" in cols:
            sets.append("next_attempt_at=?")
            vals.append(str(next_attempt_at or ""))

        if "ok" in cols and status in ("sent", "failed"):
            sets.append("ok=?")
            vals.append(1 if status == "sent" else 0)
        if "status_code" in cols and http_status:
            sets.append("status_code=?")
            vals.append(int(http_status))
        if "delivered_at" in cols and status in ("sent", "failed"):
            sets.append("delivered_at=?")
            vals.append(now)

        if not sets:
            return

        vals.extend([current_organization_id(), int(event_row_id)])
        conn.execute(f"UPDATE webhook_events SET {', '.join(sets)} WHERE organization_id=? AND id=?", tuple(vals))
        conn.commit()


def list_webhook_events(limit: int = 50):
    """Return recent delivery attempts (powers the UI).

    Schema-adaptive: some installs have legacy webhook_events tables without
    columns like ok/delivered_at/status_code.
    """
    if postgres_main_db_requested():
        return pg_list_webhook_events(current_organization_id(), limit=limit)
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    limit = max(1, min(500, limit))

    with closing(get_connection()) as conn:
        _ensure_integrations_tables(conn)
        conn.row_factory = sqlite3.Row

        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        # Build expressions only using existing columns
        if "status" in cols:
            status_expr = "CASE WHEN status IS NOT NULL AND status != '' THEN status ELSE 'queued' END"
        else:
            status_expr = "'queued'"

        if "ok" in cols and "delivered_at" in cols:
            if "status" in cols:
                status_expr = (
                    "CASE "
                    "WHEN status IS NOT NULL AND status != '' THEN status "
                    "WHEN ok = 1 THEN 'sent' "
                    "WHEN ok = 0 AND delivered_at != '' THEN 'failed' "
                    "ELSE 'queued' END"
                )
            else:
                status_expr = (
                    "CASE "
                    "WHEN ok = 1 THEN 'sent' "
                    "WHEN ok = 0 AND delivered_at != '' THEN 'failed' "
                    "ELSE 'queued' END"
                )

        if "http_status" in cols and "status_code" in cols:
            http_expr = "COALESCE(http_status, status_code, 0)"
        elif "http_status" in cols:
            http_expr = "COALESCE(http_status, 0)"
        elif "status_code" in cols:
            http_expr = "COALESCE(status_code, 0)"
        else:
            http_expr = "0"

        payload_expr = "COALESCE(payload_json, '{}')" if "payload_json" in cols else "'{}'"
        error_expr = "COALESCE(error_text, '')" if "error_text" in cols else "''"
        response_expr = "COALESCE(response_excerpt, '')" if "response_excerpt" in cols else "''"
        attempts_expr = "COALESCE(attempts, 0)" if "attempts" in cols else "0"
        last_attempt_expr = "COALESCE(last_attempt_at, '')" if "last_attempt_at" in cols else "''"
        next_attempt_expr = "COALESCE(next_attempt_at, '')" if "next_attempt_at" in cols else "''"

        select_cols = [
            "id",
            ("webhook_id" if "webhook_id" in cols else "0 AS webhook_id"),
            ("created_at" if "created_at" in cols else "'' AS created_at"),
            ("event_type" if "event_type" in cols else "'' AS event_type"),
            ("dedupe_key" if "dedupe_key" in cols else "'' AS dedupe_key"),
            f"{status_expr} AS status",
            f"{http_expr} AS http_status",
            f"{error_expr} AS error_text",
            f"{response_expr} AS response_excerpt",
            f"{attempts_expr} AS attempts",
            f"{last_attempt_expr} AS last_attempt_at",
            f"{next_attempt_expr} AS next_attempt_at",
            f"{payload_expr} AS payload_json",
        ]

        rows = conn.execute(
            f"""SELECT {', '.join(select_cols)}
                 FROM webhook_events
                 WHERE organization_id=?
                 ORDER BY id DESC
                 LIMIT ?""",
            (current_organization_id(), limit),
        ).fetchall()

    out = []
    for r in rows:
        d = dict(r)
        pj = d.get("payload_json") or "{}"
        try:
            d["payload"] = json.loads(pj)
        except Exception:
            d["payload"] = pj
        d.pop("payload_json", None)
        out.append(d)
    return out


def list_pending_webhook_events(limit: int = 100, max_attempts: int = 5) -> List[Dict[str, Any]]:
    """Pending deliveries = queued OR failed (or empty status), attempts < max_attempts.

    Schema-adaptive for legacy webhook_events tables.
    """
    if postgres_main_db_requested():
        return pg_list_pending_webhook_events(current_organization_id(), limit=limit, max_attempts=max_attempts)
    try:
        limit = int(limit or 100)
    except Exception:
        limit = 100
    limit = max(1, min(500, limit))

    with closing(get_connection()) as conn:
        _ensure_integrations_tables(conn)
        conn.row_factory = sqlite3.Row

        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        status_select = "status" if "status" in cols else "'' AS status"
        http_expr = "COALESCE(http_status, 0)" if "http_status" in cols else ("COALESCE(status_code, 0)" if "status_code" in cols else "0")
        error_expr = "COALESCE(error_text, '')" if "error_text" in cols else "''"
        response_expr = "COALESCE(response_excerpt, '')" if "response_excerpt" in cols else "''"
        attempts_expr = "COALESCE(attempts, 0)" if "attempts" in cols else "0"
        last_attempt_expr = "COALESCE(last_attempt_at, '')" if "last_attempt_at" in cols else "''"
        next_attempt_expr = "COALESCE(next_attempt_at, '')" if "next_attempt_at" in cols else "''"
        payload_expr = "COALESCE(payload_json, '{}')" if "payload_json" in cols else "'{}'"

        where_clause = "(status='queued' OR status='failed' OR status='' )" if "status" in cols else "1=1"

        rows = conn.execute(
            f"""SELECT
                    id,
                    webhook_id,
                    created_at,
                    event_type,
                    dedupe_key,
                    {status_select},
                    {http_expr} AS http_status,
                    {error_expr} AS error_text,
                    {attempts_expr} AS attempts,
                    {last_attempt_expr} AS last_attempt_at,
                    {next_attempt_expr} AS next_attempt_at,
                    {response_expr} AS response_excerpt,
                    {payload_expr} AS payload_json
                 FROM webhook_events
                 WHERE organization_id=?
                   AND {where_clause}
                   AND {attempts_expr} < ?
                 ORDER BY id ASC
                 LIMIT ?""",
            (current_organization_id(), int(max_attempts), int(limit)),
        ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except Exception:
            d["payload"] = d.get("payload_json") or "{}"
        d.pop("payload_json", None)
        out.append(d)
    return out


def list_due_webhook_events(limit: int = 100, max_attempts: int = 5, now_iso: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return webhook events that are due for delivery.

    Definition:
    - status in ('queued','failed','')
    - attempts < max_attempts
    - next_attempt_at is empty OR <= now_iso

    This is the selector used by the asynchronous delivery worker to implement backoff.
    """
    if postgres_main_db_requested():
        return pg_list_due_webhook_events(current_organization_id(), limit=limit, max_attempts=max_attempts, now_iso=now_iso)
    if not now_iso:
        now_iso = _utc_now_iso()

    # Start with the standard pending selection (schema-adaptive), then filter.
    pending = list_pending_webhook_events(limit=limit, max_attempts=max_attempts)
    due: List[Dict[str, Any]] = []
    for ev in pending:
        na = str(ev.get("next_attempt_at") or "").strip()
        if not na:
            due.append(ev)
            continue
        # ISO timestamps compare lexicographically when in UTC "YYYY-MM-DDTHH:MM:SSZ" form.
        if na <= str(now_iso):
            due.append(ev)
    return due

# -----------------------------
# Sprint 10: Multi-worker safe webhook queue draining (claim/lease)
# -----------------------------

def _ensure_webhook_claim_columns(conn: sqlite3.Connection) -> None:
    """Ensure claim/lease columns exist on webhook_events.

    These columns support multi-worker safe draining by marking rows as 'processing'
    and recording which worker claimed them.
    """
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
    except Exception:
        cols = set()

    if "claimed_at" not in cols:
        try:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN claimed_at TEXT DEFAULT ''")
        except Exception:
            pass
    if "claimed_by" not in cols:
        try:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN claimed_by TEXT DEFAULT ''")
        except Exception:
            pass
# (sanitize_webhook_for_api and get_webhook_public are defined once, further down in this module.)


def get_webhook_public(webhook_id: int) -> dict | None:
    """
    Public-safe single webhook fetch for API/UI (no plaintext secret).
    """
    if postgres_main_db_requested():
        return pg_get_webhook_public(current_organization_id(), webhook_id)
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        _ensure_integrations_tables(conn)
        r = conn.execute(
            """
            SELECT id, name, url, enabled, events_json AS events, created_at, updated_at,
                   COALESCE(secret, '') AS secret
            FROM webhooks
            WHERE organization_id=? AND id=?
            """,
            (current_organization_id(), int(webhook_id)),
        ).fetchone()
        if not r:
            return None
        return sanitize_webhook_for_api(dict(r))
    finally:
        conn.close()


def claim_due_webhook_events(
    limit: int = 100,
    max_attempts: int = 5,
    now_iso: Optional[str] = None,
    worker_id: Optional[str] = None,
    lease_seconds: int = 600,
) -> List[Dict[str, Any]]:
    """
    Atomically claim due webhook_events rows for delivery (multi-worker safe).

    Key property: a row can only be claimed by one worker because we use:
      - BEGIN IMMEDIATE (SQLite write lock)
      - UPDATE ... WHERE id IN (SELECT id ... LIMIT N)
      - unique claim_mark stored in claimed_at: "<iso>|<uuid>"

    Stale recovery: rows stuck in 'processing' with old claimed_at are requeued.
    """
    if postgres_main_db_requested():
        return pg_claim_due_webhook_events(
            current_organization_id(),
            limit=limit,
            max_attempts=max_attempts,
            now_iso=now_iso,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )
    import time as _time
    import uuid as _uuid
    import socket as _socket
    import os as _os

    if not now_iso:
        now_iso = _utc_now_iso()

    if not worker_id:
        worker_id = f"{_socket.gethostname()}:{_os.getpid()}"

    # Unique claim marker per call, even if now_iso is the same second for multiple workers
    claim_mark = f"{now_iso}|{_uuid.uuid4().hex}"

    # Stale threshold (ISO-Z). Compare only the timestamp part of claimed_at (first 20 chars).
    stale_ts = _time.time() - max(1, int(lease_seconds))
    stale_before_iso = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(stale_ts))

    try:
        limit = int(limit or 100)
    except Exception:
        limit = 100
    limit = max(1, min(500, limit))

    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row

        # Ensure required columns exist (your get_connection() also does this now)
        _ensure_integrations_tables(conn)
        _ensure_webhook_claim_columns(conn)

        # Use simple, strict SQL (avoid schema-adaptive expressions here)
        conn.execute("BEGIN IMMEDIATE")

        # 1) Requeue stale processing rows (compare only the ISO timestamp prefix)
        conn.execute(
            """
            UPDATE webhook_events
               SET status='queued', claimed_at='', claimed_by=''
             WHERE organization_id=?
               AND status='processing'
               AND claimed_at != ''
               AND substr(claimed_at, 1, 20) < ?
            """,
            (current_organization_id(), stale_before_iso),
        )

        # 2) Claim due rows
        # Due means: status queued/failed, attempts < max_attempts, and next_attempt_at is empty or <= now_iso
        conn.execute(
            """
            UPDATE webhook_events
               SET status='processing', claimed_at=?, claimed_by=?
             WHERE id IN (
                 SELECT id
                   FROM webhook_events
                  WHERE organization_id=?
                    AND status IN ('queued','failed')
                    AND COALESCE(attempts, 0) < ?
                    AND (COALESCE(next_attempt_at, '') = '' OR COALESCE(next_attempt_at, '') <= ?)
                  ORDER BY id ASC
                  LIMIT ?
             )
            """,
            (claim_mark, str(worker_id), current_organization_id(), int(max_attempts), str(now_iso), int(limit)),
        )

        # 3) Fetch ONLY what THIS call claimed
        rows = conn.execute(
            """
            SELECT
                id,
                webhook_id,
                created_at,
                event_type,
                dedupe_key,
                status,
                COALESCE(http_status, 0) AS http_status,
                COALESCE(error_text, '') AS error_text,
                COALESCE(attempts, 0) AS attempts,
                COALESCE(last_attempt_at, '') AS last_attempt_at,
                COALESCE(next_attempt_at, '') AS next_attempt_at,
                COALESCE(response_excerpt, '') AS response_excerpt,
                COALESCE(payload_json, '{}') AS payload_json,
                COALESCE(claimed_at, '') AS claimed_at,
                COALESCE(claimed_by, '') AS claimed_by
             FROM webhook_events
            WHERE organization_id=?
              AND status='processing'
              AND claimed_by=?
              AND claimed_at=?
            ORDER BY id ASC
            """,
            (current_organization_id(), str(worker_id), claim_mark),
        ).fetchall()

        conn.commit()

    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except Exception:
            d["payload"] = d.get("payload_json") or "{}"
        d.pop("payload_json", None)
        out.append(d)
    return out


def update_scan_job(
    scan_id: str,
    job_id: str = "",
    job_state: str = "",
    started_at_iso: str = "",
    finished_at_iso: str = "",
) -> None:
    """Persist Celery job metadata for a scan."""
    org_id = current_organization_id()
    if postgres_main_db_requested():
        pg_update_scan_job(
            org_id,
            scan_id,
            job_id=job_id,
            job_state=job_state,
            started_at_iso=started_at_iso,
            finished_at_iso=finished_at_iso,
        )
        return
    with closing(get_connection()) as conn:
        sets = []
        vals: list[Any] = []
        if job_id != "":
            sets.append("job_id = ?")
            vals.append(job_id)
        if job_state != "":
            sets.append("job_state = ?")
            vals.append(job_state)
        if started_at_iso != "":
            sets.append("job_started_at = ?")
            vals.append(started_at_iso)
        if finished_at_iso != "":
            sets.append("job_finished_at = ?")
            vals.append(finished_at_iso)
        if not sets:
            return
        vals.extend([org_id, scan_id])
        conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE organization_id = ? AND id = ?", vals)
        conn.commit()

# -----------------------------
# Sprint 8.2: Event Rules Engine (configurable routing)
# -----------------------------


def _ensure_event_rules_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 8.2 tables exist.

    event_rules: configurable matching + routing rules.
    event_rule_fires: optional state tracking for cooldown / "only when it changes" (used in later steps).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS event_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            webhook_ids_json TEXT NOT NULL DEFAULT '[]',
            event_types_json TEXT NOT NULL DEFAULT '["*"]',
            min_severity TEXT NOT NULL DEFAULT '',
            rule_ids_json TEXT NOT NULL DEFAULT '[]',
            quantum_score_min REAL NOT NULL DEFAULT -1,
            environments_json TEXT NOT NULL DEFAULT '[]',
            teams_json TEXT NOT NULL DEFAULT '[]',
            criticalities_json TEXT NOT NULL DEFAULT '[]',
            tags_json TEXT NOT NULL DEFAULT '[]',
            cooldown_minutes INTEGER NOT NULL DEFAULT 0,
            fire_mode TEXT NOT NULL DEFAULT 'always',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS event_rule_fires (
            organization_id TEXT NOT NULL DEFAULT '',
            rule_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            last_fired_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, rule_id, fingerprint),
            FOREIGN KEY(rule_id) REFERENCES event_rules(id) ON DELETE CASCADE
        )
        """
    )

    # Backward-compatible migrations BEFORE creating indexes that reference the new columns.
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(event_rules)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE event_rules ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE event_rules SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
        if "cooldown_minutes" not in cols:
            conn.execute("ALTER TABLE event_rules ADD COLUMN cooldown_minutes INTEGER NOT NULL DEFAULT 0")
        if "quantum_score_min" not in cols:
            conn.execute("ALTER TABLE event_rules ADD COLUMN quantum_score_min REAL NOT NULL DEFAULT -1")
        if "fire_mode" not in cols:
            conn.execute("ALTER TABLE event_rules ADD COLUMN fire_mode TEXT NOT NULL DEFAULT 'always'")
    except Exception:
        pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rules_org ON event_rules(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rules_enabled ON event_rules(enabled)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rule_fires_rule ON event_rule_fires(rule_id)")
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(event_rule_fires)").fetchall()}
        if "organization_id" not in cols:
            conn.execute("ALTER TABLE event_rule_fires ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE event_rule_fires SET organization_id=? WHERE organization_id=''", (DEFAULT_ORG_ID,))
    except Exception:
        pass

    conn.commit()

# -----------------------------
# Point 3: Noise control helpers
# -----------------------------

def _utcnow_iso() -> str:
    # Some files may already define _utcnow_iso earlier; keep this as fallback.
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def get_event_rule_fire(rule_id: int, fingerprint: str) -> Optional[Dict[str, Any]]:
    if postgres_main_db_requested():
        return pg_get_event_rule_fire(current_organization_id(), rule_id, fingerprint)
    with closing(get_connection()) as conn:
        _ensure_event_rules_tables(conn)
        row = conn.execute(
            "SELECT rule_id, fingerprint, last_fired_at FROM event_rule_fires WHERE organization_id=? AND rule_id=? AND fingerprint=?",
            (current_organization_id(), int(rule_id), str(fingerprint)),
        ).fetchone()
        return dict(row) if row else None


def upsert_event_rule_fire(rule_id: int, fingerprint: str, fired_at_iso: str) -> None:
    if postgres_main_db_requested():
        pg_upsert_event_rule_fire(current_organization_id(), rule_id, fingerprint, fired_at_iso)
        return
    with closing(get_connection()) as conn:
        _ensure_event_rules_tables(conn)
        conn.execute(
            "INSERT INTO event_rule_fires(organization_id,rule_id,fingerprint,last_fired_at) VALUES (?,?,?,?) "
            "ON CONFLICT(organization_id,rule_id,fingerprint) DO UPDATE SET last_fired_at=excluded.last_fired_at",
            (current_organization_id(), int(rule_id), str(fingerprint), str(fired_at_iso)),
        )
        conn.commit()


def should_fire_event_rule(rule_id: int, fingerprint: str, cooldown_minutes: int, fire_mode: str) -> bool:
    """Noise control decision.

    - always: always fire (no suppression)
    - cooldown: fire, then suppress until cooldown has elapsed
    - state_change/escalate: fire once per fingerprint; if cooldown>0 allow periodic reminders
    """
    if postgres_main_db_requested():
        return pg_should_fire_event_rule(current_organization_id(), rule_id, fingerprint, cooldown_minutes, fire_mode)
    mode = (fire_mode or 'always').strip().lower()
    if mode == 'always':
        return True

    now = datetime.now(timezone.utc)
    rec = get_event_rule_fire(int(rule_id), str(fingerprint))
    if not rec:
        upsert_event_rule_fire(int(rule_id), str(fingerprint), now.isoformat().replace('+00:00','Z'))
        return True

    # Already fired for this fingerprint
    cd = int(cooldown_minutes or 0)
    if cd <= 0:
        return False

    last = _parse_iso_datetime(str(rec.get('last_fired_at') or ''))
    last = last.replace(tzinfo=timezone.utc)
    delta = (now - last).total_seconds()
    if delta >= cd * 60:
        upsert_event_rule_fire(int(rule_id), str(fingerprint), now.isoformat().replace('+00:00','Z'))
        return True
    return False



def _json_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    try:
        obj = json.loads(s)
        if isinstance(obj, list):
            return [str(x) for x in obj if str(x).strip()]
    except Exception:
        pass
    # comma-separated fallback
    return [x.strip() for x in s.split(",") if x.strip()]


def _json_obj(v: Any) -> Dict[str, Any]:
    if v is None:
        return {}
    if isinstance(v, dict):
        return v
    try:
        obj = json.loads(v)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return {}


def list_event_rules(limit: int = 200) -> List[Dict[str, Any]]:
    if postgres_main_db_requested():
        return pg_list_event_rules(current_organization_id(), limit=limit)
    try:
        limit = int(limit or 200)
    except Exception:
        limit = 200
    limit = max(1, min(1000, limit))

    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT id, name, enabled, webhook_ids_json, event_types_json,
                       min_severity, rule_ids_json, quantum_score_min,
                       environments_json, teams_json, criticalities_json, tags_json,
                       cooldown_minutes, created_at, updated_at
                FROM event_rules
                WHERE organization_id=?
                ORDER BY id DESC
                LIMIT ?
                """,
                (current_organization_id(), limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return []
            raise

    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        # decode json lists
        for k in ("webhook_ids_json", "event_types_json", "rule_ids_json", "environments_json", "teams_json", "criticalities_json", "tags_json"):
            try:
                d[k[:-5]] = json.loads(d.get(k) or "[]")
            except Exception:
                d[k[:-5]] = []
            d.pop(k, None)
        d["enabled"] = bool(int(d.get("enabled") or 0))
        out.append(d)
    return out


def upsert_event_rule(
    *,
    name: str,
    webhook_ids: List[int],
    event_types: List[str],
    enabled: bool = True,
    min_severity: str = "",
    rule_ids: Optional[List[str]] = None,
    quantum_score_min: float = -1,
    environments: Optional[List[str]] = None,
    teams: Optional[List[str]] = None,
    criticalities: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    cooldown_minutes: int = 0,
    rule_id: Optional[int] = None,
    **_extra: Any,
) -> Dict[str, Any]:
    if postgres_main_db_requested():
        return pg_upsert_event_rule(
            org_id=current_organization_id(),
            name=name,
            webhook_ids=webhook_ids,
            event_types=event_types,
            enabled=enabled,
            min_severity=min_severity,
            rule_ids=rule_ids,
            quantum_score_min=quantum_score_min,
            environments=environments,
            teams=teams,
            criticalities=criticalities,
            tags=tags,
            cooldown_minutes=cooldown_minutes,
            rule_id=rule_id,
            **_extra,
        )
    name = (name or "").strip()
    if not name:
        raise ValueError("rule name is required")

    webhook_ids = [int(x) for x in (webhook_ids or [])]
    if not webhook_ids:
        raise ValueError("select at least one destination webhook")

    if event_types is None:
        event_types = ['*']
    else:
        event_types = _json_list(event_types)

    min_severity = (min_severity or "").strip().lower()
    if min_severity and min_severity not in ("low", "medium", "high", "critical"):
        raise ValueError("min_severity must be one of: low, medium, high, critical")

    rule_ids = _json_list(rule_ids)
    environments = _json_list(environments)
    teams = _json_list(teams)
    criticalities = _json_list(criticalities)
    tags = _json_list(tags)

    try:
        quantum_score_min = float(quantum_score_min)
    except Exception:
        quantum_score_min = -1

    try:
        cooldown_minutes = int(cooldown_minutes or 0)
    except Exception:
        cooldown_minutes = 0
    cooldown_minutes = max(0, min(60 * 24 * 30, cooldown_minutes))

    now = _utc_now_iso()

    with closing(get_connection()) as conn:

        if rule_id is not None:
            conn.execute(
                """
                UPDATE event_rules
                SET name=?, enabled=?, webhook_ids_json=?, event_types_json=?,
                    min_severity=?, rule_ids_json=?, quantum_score_min=?,
                    environments_json=?, teams_json=?, criticalities_json=?, tags_json=?,
                    cooldown_minutes=?, updated_at=?
                WHERE organization_id=? AND id=?
                """,
                (
                    name,
                    1 if enabled else 0,
                    json.dumps(webhook_ids),
                    json.dumps(event_types),
                    min_severity,
                    json.dumps(rule_ids),
                    float(quantum_score_min),
                    json.dumps(environments),
                    json.dumps(teams),
                    json.dumps(criticalities),
                    json.dumps(tags),
                    int(cooldown_minutes),
                    now,
                    current_organization_id(),
                    int(rule_id),
                ),
            )
            rid = int(rule_id)
        else:
            cur = conn.execute(
                """
                INSERT INTO event_rules (
                    organization_id, name, enabled, webhook_ids_json, event_types_json,
                    min_severity, rule_ids_json, quantum_score_min,
                    environments_json, teams_json, criticalities_json, tags_json,
                    cooldown_minutes, created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    current_organization_id(),
                    name,
                    1 if enabled else 0,
                    json.dumps(webhook_ids),
                    json.dumps(event_types),
                    min_severity,
                    json.dumps(rule_ids),
                    float(quantum_score_min),
                    json.dumps(environments),
                    json.dumps(teams),
                    json.dumps(criticalities),
                    json.dumps(tags),
                    int(cooldown_minutes),
                    now,
                    now,
                ),
            )
            rid = int(cur.lastrowid)

        conn.commit()

    # Return fresh row
    rules = [r for r in list_event_rules(limit=500) if int(r.get("id") or 0) == rid]
    return rules[0] if rules else {"id": rid, "name": name}


def delete_event_rule(rule_id: int) -> None:
    if postgres_main_db_requested():
        pg_delete_event_rule(current_organization_id(), rule_id)
        return
    with closing(get_connection()) as conn:
        conn.execute("DELETE FROM event_rules WHERE organization_id=? AND id=?", (current_organization_id(), int(rule_id)))
        conn.execute("DELETE FROM event_rule_fires WHERE organization_id=? AND rule_id=?", (current_organization_id(), int(rule_id)))
        conn.commit()

def sanitize_webhook_for_api(row: dict) -> dict:
    """
    Return a webhook dict safe for API/UI:
    - never include plaintext secret
    - include has_secret + secret_masked

    This was defined three times in this module. Only the last definition was ever in effect, so the
    other two were dead code that a reader could edit with no result -- a hazard for a function whose
    job is to keep a webhook secret out of API responses. One definition now.
    """
    d = dict(row or {})
    secret = d.pop("secret", "") or ""
    d["has_secret"] = 1 if secret else 0
    d["secret_masked"] = "********" if d["has_secret"] else ""
    return d


# (get_webhook_public is defined once, above -- this file previously carried a byte-identical copy here.)


def rotate_webhook_secret(webhook_id: int) -> dict:
    """
    Generate a new secret, store it, and return a sanitized webhook.
    """
    if postgres_main_db_requested():
        return pg_rotate_webhook_secret(current_organization_id(), webhook_id)
    new_secret = secrets.token_hex(32)  # 64 hex chars
    now = _utc_now_iso() if "_utc_now_iso" in globals() else ""

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    try:
        _ensure_integrations_tables(conn)

        conn.execute(
            "UPDATE webhooks SET secret=?, updated_at=? WHERE organization_id=? AND id=?",
            (new_secret, now, current_organization_id(), int(webhook_id)),
        )
        conn.commit()

        r = conn.execute(
            """
            SELECT id, name, url, enabled, events_json AS events, created_at, updated_at,
                   COALESCE(secret, '') AS secret
            FROM webhooks
            WHERE organization_id=? AND id=?
            """,
            (current_organization_id(), int(webhook_id)),
        ).fetchone()

        if not r:
            return {"ok": True}
        return sanitize_webhook_for_api(dict(r))
    finally:
        conn.close()

# -----------------------------
# Runtime traffic observations
# -----------------------------

def _ensure_runtime_observations_sqlite(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_traffic_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 443,
            protocol TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            server_name TEXT NOT NULL DEFAULT '',
            tls_version TEXT NOT NULL DEFAULT '',
            cipher TEXT NOT NULL DEFAULT '',
            status_code INTEGER NOT NULL DEFAULT 0,
            observed_count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            sample_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_org ON runtime_traffic_observations(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_asset ON runtime_traffic_observations(organization_id, asset_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_source ON runtime_traffic_observations(organization_id, source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_last_seen ON runtime_traffic_observations(organization_id, last_seen)")
    conn.commit()


def _ensure_runtime_observations_postgres() -> None:
    ensure_postgres_core_schema()
    with pg_product_conn(product_database_url()) as conn, tolerate_missing_ddl_privilege(
        conn, ("runtime_traffic_observations",), "runtime traffic observations"
    ):
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_traffic_observations (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT '',
                    asset_key TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 443,
                    protocol TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '',
                    path TEXT NOT NULL DEFAULT '',
                    server_name TEXT NOT NULL DEFAULT '',
                    tls_version TEXT NOT NULL DEFAULT '',
                    cipher TEXT NOT NULL DEFAULT '',
                    status_code INTEGER NOT NULL DEFAULT 0,
                    observed_count INTEGER NOT NULL DEFAULT 1,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL,
                    sample_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_org ON runtime_traffic_observations(organization_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_asset ON runtime_traffic_observations(organization_id, asset_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_source ON runtime_traffic_observations(organization_id, source)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runtime_obs_last_seen ON runtime_traffic_observations(organization_id, last_seen)")


def record_runtime_traffic_observations(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    org_id = current_organization_id()
    now = _utc_now_iso()
    clean_records = [r for r in (records or []) if isinstance(r, dict) and r.get("asset_key")]
    if not clean_records:
        return {"inserted": 0}
    if postgres_main_db_requested():
        _ensure_runtime_observations_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                for r in clean_records:
                    cur.execute(
                        """
                        INSERT INTO runtime_traffic_observations(
                            organization_id, source, provider, asset_key, host, port, protocol, method, path,
                            server_name, tls_version, cipher, status_code, observed_count, first_seen, last_seen,
                            sample_json, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                        """,
                        (
                            org_id,
                            str(r.get("source") or ""),
                            str(r.get("provider") or ""),
                            str(r.get("asset_key") or ""),
                            str(r.get("host") or ""),
                            int(r.get("port") or 443),
                            str(r.get("protocol") or ""),
                            str(r.get("method") or ""),
                            str(r.get("path") or ""),
                            str(r.get("server_name") or ""),
                            str(r.get("tls_version") or ""),
                            str(r.get("cipher") or ""),
                            int(r.get("status_code") or 0),
                            int(r.get("observed_count") or 1),
                            str(r.get("observed_at") or now),
                            str(r.get("observed_at") or now),
                            json.dumps(r.get("raw") or r, default=str),
                            now,
                        ),
                    )
        return {"inserted": len(clean_records)}
    with closing(get_connection()) as conn:
        _ensure_runtime_observations_sqlite(conn)
        for r in clean_records:
            conn.execute(
                """
                INSERT INTO runtime_traffic_observations(
                    organization_id, source, provider, asset_key, host, port, protocol, method, path,
                    server_name, tls_version, cipher, status_code, observed_count, first_seen, last_seen,
                    sample_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    org_id,
                    str(r.get("source") or ""),
                    str(r.get("provider") or ""),
                    str(r.get("asset_key") or ""),
                    str(r.get("host") or ""),
                    int(r.get("port") or 443),
                    str(r.get("protocol") or ""),
                    str(r.get("method") or ""),
                    str(r.get("path") or ""),
                    str(r.get("server_name") or ""),
                    str(r.get("tls_version") or ""),
                    str(r.get("cipher") or ""),
                    int(r.get("status_code") or 0),
                    int(r.get("observed_count") or 1),
                    str(r.get("observed_at") or now),
                    str(r.get("observed_at") or now),
                    json.dumps(r.get("raw") or r, default=str),
                    now,
                ),
            )
        conn.commit()
    return {"inserted": len(clean_records)}


def list_runtime_traffic_observations(asset_key_str: str = "", source: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 200), 2000))
    asset_key_str = str(asset_key_str or "").strip()
    source = str(source or "").strip().lower()
    if postgres_main_db_requested():
        _ensure_runtime_observations_postgres()
        clauses = ["organization_id=%s"]
        params: List[Any] = [org_id]
        if asset_key_str:
            clauses.append("asset_key=%s")
            params.append(asset_key_str)
        if source:
            clauses.append("source=%s")
            params.append(source)
        params.append(limit)
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT id, source, provider, asset_key, host, port, protocol, method, path, server_name,
                           tls_version, cipher, status_code, observed_count, first_seen, last_seen, sample_json, created_at
                    FROM runtime_traffic_observations
                    WHERE {' AND '.join(clauses)}
                    ORDER BY last_seen DESC, id DESC LIMIT %s
                    """,
                    tuple(params),
                )
                rows = cur.fetchall()
                return [
                    {
                        "id": int(r[0]), "source": r[1], "provider": r[2], "asset_key": r[3], "host": r[4],
                        "port": int(r[5] or 0), "protocol": r[6], "method": r[7], "path": r[8], "server_name": r[9],
                        "tls_version": r[10], "cipher": r[11], "status_code": int(r[12] or 0),
                        "observed_count": int(r[13] or 0), "first_seen": str(r[14] or ""), "last_seen": str(r[15] or ""),
                        "sample": r[16] or {}, "created_at": str(r[17] or ""),
                    }
                    for r in rows
                ]
    with closing(get_connection()) as conn:
        _ensure_runtime_observations_sqlite(conn)
        conn.row_factory = sqlite3.Row
        clauses = ["organization_id=?"]
        params2: List[Any] = [org_id]
        if asset_key_str:
            clauses.append("asset_key=?")
            params2.append(asset_key_str)
        if source:
            clauses.append("source=?")
            params2.append(source)
        params2.append(limit)
        rows = conn.execute(
            f"""
            SELECT id, source, provider, asset_key, host, port, protocol, method, path, server_name,
                   tls_version, cipher, status_code, observed_count, first_seen, last_seen, sample_json, created_at
            FROM runtime_traffic_observations
            WHERE {' AND '.join(clauses)}
            ORDER BY last_seen DESC, id DESC LIMIT ?
            """,
            tuple(params2),
        ).fetchall()
        return [
            {
                "id": int(r["id"]), "source": r["source"], "provider": r["provider"], "asset_key": r["asset_key"],
                "host": r["host"], "port": int(r["port"] or 0), "protocol": r["protocol"], "method": r["method"],
                "path": r["path"], "server_name": r["server_name"], "tls_version": r["tls_version"], "cipher": r["cipher"],
                "status_code": int(r["status_code"] or 0), "observed_count": int(r["observed_count"] or 0),
                "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "sample": json.loads(r["sample_json"] or "{}"), "created_at": r["created_at"],
            }
            for r in rows
        ]


def list_runtime_observed_assets(limit: int = 500) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    limit = max(1, min(int(limit or 500), 2000))
    if postgres_main_db_requested():
        _ensure_runtime_observations_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT asset_key, host, port, ARRAY_AGG(DISTINCT source), ARRAY_AGG(DISTINCT provider),
                           ARRAY_AGG(DISTINCT protocol), ARRAY_AGG(DISTINCT tls_version), SUM(observed_count),
                           MIN(first_seen), MAX(last_seen), COUNT(*)
                    FROM runtime_traffic_observations
                    WHERE organization_id=%s
                    GROUP BY asset_key, host, port
                    ORDER BY MAX(last_seen) DESC LIMIT %s
                    """,
                    (org_id, limit),
                )
                rows = cur.fetchall()
                return [
                    {
                        "asset_key": r[0], "host": r[1], "port": int(r[2] or 0),
                        "sources": sorted([x for x in (r[3] or []) if x]),
                        "providers": sorted([x for x in (r[4] or []) if x]),
                        "protocols": sorted([x for x in (r[5] or []) if x]),
                        "tls_versions": sorted([x for x in (r[6] or []) if x]),
                        "observed_count": int(r[7] or 0), "first_seen": str(r[8] or ""), "last_seen": str(r[9] or ""),
                        "observation_rows": int(r[10] or 0),
                    }
                    for r in rows
                ]
    with closing(get_connection()) as conn:
        _ensure_runtime_observations_sqlite(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT asset_key, host, port, GROUP_CONCAT(DISTINCT source) AS sources, GROUP_CONCAT(DISTINCT provider) AS providers,
                   GROUP_CONCAT(DISTINCT protocol) AS protocols, GROUP_CONCAT(DISTINCT tls_version) AS tls_versions,
                   SUM(observed_count) AS observed_count, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen, COUNT(*) AS observation_rows
            FROM runtime_traffic_observations
            WHERE organization_id=?
            GROUP BY asset_key, host, port
            ORDER BY MAX(last_seen) DESC LIMIT ?
            """,
            (org_id, limit),
        ).fetchall()
        def split_csv(value: str) -> List[str]:
            return sorted([x for x in str(value or "").split(",") if x])
        return [
            {
                "asset_key": r["asset_key"], "host": r["host"], "port": int(r["port"] or 0),
                "sources": split_csv(r["sources"]), "providers": split_csv(r["providers"]),
                "protocols": split_csv(r["protocols"]), "tls_versions": split_csv(r["tls_versions"]),
                "observed_count": int(r["observed_count"] or 0), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "observation_rows": int(r["observation_rows"] or 0),
            }
            for r in rows
        ]

# -----------------------------
# Organization memberships
# -----------------------------

def _ensure_org_memberships_sqlite(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_memberships (
            organization_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            display_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, user_id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON organization_memberships(organization_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON organization_memberships(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_role ON organization_memberships(role)")
    conn.commit()


def _ensure_org_memberships_postgres() -> None:
    ensure_postgres_core_schema()
    with pg_product_conn(product_database_url()) as conn, tolerate_missing_ddl_privilege(
        conn, ("organization_memberships",), "organization memberships"
    ):
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS organization_memberships (
                    organization_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    display_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (organization_id, user_id)
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON organization_memberships(organization_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON organization_memberships(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_org_memberships_role ON organization_memberships(role)")


def _membership_row_to_dict(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    if isinstance(row, dict):
        out = dict(row)
    else:
        keys = ["organization_id", "user_id", "role", "display_name", "email", "status", "created_at", "updated_at"]
        out = {keys[i]: row[i] for i in range(min(len(keys), len(row)))}
    out["organization_id"] = str(out.get("organization_id") or "")
    out["user_id"] = str(out.get("user_id") or "")
    out["role"] = str(out.get("role") or "viewer").strip().lower() or "viewer"
    out["display_name"] = str(out.get("display_name") or "")
    out["email"] = str(out.get("email") or "")
    out["status"] = str(out.get("status") or "active").strip().lower() or "active"
    out["created_at"] = str(out.get("created_at") or "")
    out["updated_at"] = str(out.get("updated_at") or "")
    return out


def upsert_organization_member(
    organization_id: str,
    user_id: str,
    role: str = "viewer",
    display_name: str = "",
    email: str = "",
    status: str = "active",
) -> Dict[str, Any]:
    oid = str(organization_id or current_organization_id() or DEFAULT_ORG_ID).strip() or DEFAULT_ORG_ID
    uid = str(user_id or "").strip()
    if not uid:
        raise ValueError("user_id is required")
    role = str(role or "viewer").strip().lower()
    if role not in {"viewer", "operator", "admin"}:
        raise ValueError("role must be viewer, operator, or admin")
    status = str(status or "active").strip().lower()
    if status not in {"active", "disabled"}:
        raise ValueError("status must be active or disabled")
    now = _utc_now_iso()
    if postgres_main_db_requested():
        _ensure_org_memberships_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO organization_memberships(
                        organization_id, user_id, role, display_name, email, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (organization_id, user_id) DO UPDATE SET
                        role=EXCLUDED.role,
                        display_name=EXCLUDED.display_name,
                        email=EXCLUDED.email,
                        status=EXCLUDED.status,
                        updated_at=EXCLUDED.updated_at
                    RETURNING organization_id, user_id, role, display_name, email, status, created_at, updated_at
                    """,
                    (oid, uid, role, str(display_name or ""), str(email or ""), status, now, now),
                )
                return _membership_row_to_dict(cur.fetchone()) or {"organization_id": oid, "user_id": uid, "role": role}
    with closing(get_connection()) as conn:
        _ensure_org_memberships_sqlite(conn)
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            INSERT INTO organization_memberships(
                organization_id, user_id, role, display_name, email, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, user_id) DO UPDATE SET
                role=excluded.role,
                display_name=excluded.display_name,
                email=excluded.email,
                status=excluded.status,
                updated_at=excluded.updated_at
            """,
            (oid, uid, role, str(display_name or ""), str(email or ""), status, now, now),
        )
        row = conn.execute(
            """
            SELECT organization_id, user_id, role, display_name, email, status, created_at, updated_at
            FROM organization_memberships WHERE organization_id=? AND user_id=?
            """,
            (oid, uid),
        ).fetchone()
        conn.commit()
        return _membership_row_to_dict(dict(row)) or {"organization_id": oid, "user_id": uid, "role": role}


def get_organization_member(organization_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    oid = str(organization_id or current_organization_id() or DEFAULT_ORG_ID).strip() or DEFAULT_ORG_ID
    uid = str(user_id or "").strip()
    if not uid:
        return None
    if postgres_main_db_requested():
        _ensure_org_memberships_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT organization_id, user_id, role, display_name, email, status, created_at, updated_at
                    FROM organization_memberships WHERE organization_id=%s AND user_id=%s
                    """,
                    (oid, uid),
                )
                return _membership_row_to_dict(cur.fetchone())
    with closing(get_connection()) as conn:
        # Called for every authorized request; the DDL + commit only needs to run once per database.
        if not schema_ensured("org_memberships"):
            _ensure_org_memberships_sqlite(conn)
            mark_schema_ensured("org_memberships")
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT organization_id, user_id, role, display_name, email, status, created_at, updated_at
            FROM organization_memberships WHERE organization_id=? AND user_id=?
            """,
            (oid, uid),
        ).fetchone()
        return _membership_row_to_dict(dict(row)) if row else None


def list_organization_members(organization_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    oid = str(organization_id or current_organization_id() or DEFAULT_ORG_ID).strip() or DEFAULT_ORG_ID
    lim = max(1, min(int(limit or 500), 2000))
    if postgres_main_db_requested():
        _ensure_org_memberships_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT organization_id, user_id, role, display_name, email, status, created_at, updated_at
                    FROM organization_memberships WHERE organization_id=%s
                    ORDER BY updated_at DESC LIMIT %s
                    """,
                    (oid, lim),
                )
                return [_membership_row_to_dict(r) or {} for r in cur.fetchall()]
    with closing(get_connection()) as conn:
        _ensure_org_memberships_sqlite(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT organization_id, user_id, role, display_name, email, status, created_at, updated_at
            FROM organization_memberships WHERE organization_id=?
            ORDER BY updated_at DESC LIMIT ?
            """,
            (oid, lim),
        ).fetchall()
        return [_membership_row_to_dict(dict(r)) or {} for r in rows]


def list_user_memberships(user_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    uid = str(user_id or "").strip()
    if not uid:
        return []
    lim = max(1, min(int(limit or 500), 2000))
    if postgres_main_db_requested():
        _ensure_org_memberships_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT m.organization_id, m.user_id, m.role, m.display_name, m.email, m.status, m.created_at, m.updated_at,
                           COALESCE(o.name, '') AS organization_name
                    FROM organization_memberships m
                    LEFT JOIN organizations o ON o.id = m.organization_id
                    WHERE m.user_id=%s
                    ORDER BY m.updated_at DESC LIMIT %s
                    """,
                    (uid, lim),
                )
                rows = []
                for r in cur.fetchall():
                    item = _membership_row_to_dict(r[:8]) or {}
                    item["organization_name"] = str(r[8] or "")
                    rows.append(item)
                return rows
    with closing(get_connection()) as conn:
        _ensure_org_memberships_sqlite(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT m.organization_id, m.user_id, m.role, m.display_name, m.email, m.status, m.created_at, m.updated_at,
                   COALESCE(o.name, '') AS organization_name
            FROM organization_memberships m
            LEFT JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id=?
            ORDER BY m.updated_at DESC LIMIT ?
            """,
            (uid, lim),
        ).fetchall()
        out = []
        for r in rows:
            item = _membership_row_to_dict(dict(r)) or {}
            item["organization_name"] = str(r["organization_name"] or "")
            out.append(item)
        return out


def remove_organization_member(organization_id: str, user_id: str) -> Dict[str, Any]:
    oid = str(organization_id or current_organization_id() or DEFAULT_ORG_ID).strip() or DEFAULT_ORG_ID
    uid = str(user_id or "").strip()
    if not uid:
        raise ValueError("user_id is required")
    if postgres_main_db_requested():
        _ensure_org_memberships_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM organization_memberships WHERE organization_id=%s AND user_id=%s", (oid, uid))
                return {"ok": True, "deleted": int(cur.rowcount or 0), "organization_id": oid, "user_id": uid}
    with closing(get_connection()) as conn:
        _ensure_org_memberships_sqlite(conn)
        cur = conn.execute("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?", (oid, uid))
        conn.commit()
        return {"ok": True, "deleted": int(cur.rowcount or 0), "organization_id": oid, "user_id": uid}



# Register the Postgres schemas this module creates lazily on first use, so that a migration run
# with an owner role can create them all up front. A least-privilege runtime role has no DDL
# rights, so without this the tables would only ever appear if someone happened to exercise the
# feature while connected as a privileged role. See db_postgres.apply_deferred_schemas().
register_deferred_schema("github_history", _ensure_github_history_postgres)
register_deferred_schema("runtime_traffic_observations", _ensure_runtime_observations_postgres)
register_deferred_schema("organization_memberships", _ensure_org_memberships_postgres)
