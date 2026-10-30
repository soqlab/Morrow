"""Durable, platform-admin-only security metadata; never accepts arbitrary event payloads."""
from __future__ import annotations

import atexit
import hashlib
import hmac
import ipaddress
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import db_feature_store as store

logger = logging.getLogger(__name__)
_lock = threading.RLock()
_ready = set()
_health = {}
AUTH_EVENTS = {
    "login.success", "login.failure", "login.unavailable", "login.invalid_request",
    "saml.success", "saml.failure", "refresh.success", "refresh.failure",
    "logout.revoked", "logout.no_session", "logout.failure", "token.rejected", "auth.rate_limited",
    "invite_register.refused", "password_reset.requested", "password_reset.refused", "password_reset.completed",
}


class JournalUnavailable(RuntimeError):
    pass


def _key():
    value = store._feature_dsn() if store.postgres_enabled() else store._sqlite_path()
    return store.dialect() + ":" + hashlib.sha256(str(value).encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


#: Retention ceilings. The traffic ceiling was 30 days while the operator analytics offer a 90-day
#: range, so a 90-day question could never be answered from raw rows however an operator configured
#: the platform -- and the days beyond 30 were deleted before the daily rollups could aggregate
#: them (see prune() and services/usage_rollups). The ceiling is now the longest analytics range,
#: so "keep 90 days of raw traffic" is at least expressible. The default is still 7 days: rollups,
#: not raw rows, are what make the long ranges cheap.
RETENTION_LIMITS = {"auth": (90, 365), "traffic": (7, 90)}


def _days(kind):
    default, maximum = RETENTION_LIMITS["auth" if kind == "auth" else "traffic"]
    value = os.getenv("MORROW_AUTH_LOG_RETENTION_DAYS" if kind == "auth" else "MORROW_TRAFFIC_RETENTION_DAYS", str(default))
    return max(1, min(maximum, int(value)))


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _cutoff(kind):
    return _iso(datetime.now(timezone.utc) - timedelta(days=_days(kind)))


def _holdback_days():
    """How long past its retention a day may be kept while it waits to be rolled up.

    Deleting a day's raw rows before services/usage_rollups has aggregated it makes that day
    permanently unanswerable: the rollup can only read rows that still exist. That is what left
    the 90-day analytics range reporting "unknown" for two thirds of its span. The pruner now
    waits for the rollup -- but only this long, so a rollup that is broken or switched off can
    never make the journal grow without limit. 0 disables the wait.
    """
    try:
        return max(0, min(30, int(os.getenv("MORROW_TRAFFIC_ROLLUP_HOLDBACK_DAYS", "3") or 3)))
    except ValueError:
        return 3


def _prune_cutoff(kind):
    """The instant before which rows may be deleted: the retention cutoff, held back (by at most
    _holdback_days) behind the oldest closed day the usage rollups have not aggregated yet."""
    cutoff = _cutoff(kind)
    if kind != "traffic" or not _holdback_days():
        return cutoff
    try:
        from services import usage_rollups
        if not usage_rollups.enabled():
            return cutoff
        floor = usage_rollups.unrolled_floor()
    except Exception:
        return cutoff
    if floor is None:
        return cutoff
    waiting = _iso(floor)
    if waiting >= cutoff:
        return cutoff
    # Never hold anything back beyond the cap, whatever the rollup is doing.
    hard = _iso(datetime.now(timezone.utc) - timedelta(days=_days(kind) + _holdback_days()))
    return max(waiting, hard)


def _text(value, limit=128):
    return "".join(c for c in str(value or "") if c.isprintable())[:limit]


def address(value):
    try:
        return str(ipaddress.ip_address(str(value or "")))
    except ValueError:
        return ""


def browser(value):
    value = str(value or "").lower()
    for needle, name in (("edg/", "Edge"), ("firefox/", "Firefox"), ("chrome/", "Chrome"), ("safari/", "Safari")):
        if needle in value:
            return name
    return "Other"


def subject_reference(value):
    secret = os.getenv("MORROW_VAULT_MASTER_KEY") or os.getenv("MORROW_AUTH_JWT_SECRET")
    if not secret or not value:
        return ""
    return hmac.new(secret.encode(), ("auth-subject:" + str(value).strip().lower()[:320]).encode(), hashlib.sha256).hexdigest()


def init_tables():
    key = _key()
    with _lock:
        if key in _ready:
            return
        with store.feature_conn() as conn:
            # Do not require DDL privileges on an already migrated Postgres runtime.
            present = False
            if store.postgres_enabled():
                row = conn.execute("SELECT to_regclass('public.platform_auth_events'), to_regclass('public.platform_request_events')").fetchone()
                present = bool(row[0] and row[1])
            if not present:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS platform_auth_events (
                        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, organization_id TEXT NOT NULL,
                        user_id TEXT NOT NULL, actor_role TEXT NOT NULL, event_type TEXT NOT NULL,
                        login_method TEXT NOT NULL, ip_address TEXT NOT NULL, user_agent TEXT NOT NULL,
                        subject_ref TEXT NOT NULL, status_code INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_auth_journal_time ON platform_auth_events(created_at);
                    CREATE INDEX IF NOT EXISTS idx_auth_journal_org_time ON platform_auth_events(organization_id, created_at);
                    CREATE TABLE IF NOT EXISTS platform_request_events (
                        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, organization_id TEXT NOT NULL,
                        actor_id TEXT NOT NULL, actor_role TEXT NOT NULL, source_ip TEXT NOT NULL,
                        method TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL,
                        duration_ms REAL NOT NULL, user_agent TEXT NOT NULL, authenticated INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_request_journal_time ON platform_request_events(created_at);
                    CREATE INDEX IF NOT EXISTS idx_request_journal_ip_time ON platform_request_events(source_ip, created_at);
                """)
                conn.commit()
        _ready.add(key)


def mark_failure(kind):
    with _lock:
        state = _health.setdefault(_key(), {})
        item = state.setdefault(kind, {"failed_writes": 0})
        item["failed_writes"] += 1
        item["last_failure_at"] = _now()
        # Do not flood logs during a dependency outage, or stringify SQL exceptions/parameters.
        now = time.monotonic()
        if now - item.get("last_warning", 0) > 60:
            logger.error("Security journal write unavailable (%s); consult the authenticated logging health endpoint", kind)
            item["last_warning"] = now


def mark_success(kind):
    with _lock:
        _health.setdefault(_key(), {}).setdefault(kind, {"failed_writes": 0})["last_success_at"] = _now()


def _insert(kind, values):
    table = "platform_auth_events" if kind == "auth" else "platform_request_events"
    try:
        init_tables()
        with store.feature_conn() as conn:
            conn.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
            conn.commit()
        mark_success(kind)
    except Exception as exc:
        mark_failure(kind)
        raise JournalUnavailable("Security journal storage unavailable") from exc


def record_auth(event_type, *, user=None, method="password", source_ip="", user_agent="", subject="", status_code=200):
    if event_type not in AUTH_EVENTS or method not in {"password", "saml", "jwt", "refresh_token", "api_key"}:
        raise ValueError("Unsupported authentication event")
    # Identity is supplied only after authentication, never from a requested role/org or failed email.
    user = user or {}
    row = {"id": uuid.uuid4().hex, "created_at": _now(), "organization_id": _text(user.get("org_id")),
           "user_id": _text(user.get("id")), "actor_role": _text(user.get("role"), 32), "event_type": event_type,
           "login_method": method, "ip_address": address(source_ip), "user_agent": browser(user_agent),
           "subject_ref": subject_reference(subject), "status_code": int(status_code)}
    _insert("auth", row)
    return row


def _request_row(event):
    return {"id": uuid.uuid4().hex, "created_at": _now(), "organization_id": _text(event.get("organization_id")),
            "actor_id": _text(event.get("actor_id")), "actor_role": _text(event.get("actor_role"), 32),
            "source_ip": address(event.get("source_ip")), "method": _text(event.get("method"), 12),
            "path": _text(event.get("path"), 240).split("?", 1)[0].split("#", 1)[0],
            "status_code": int(event.get("status_code") or 0), "duration_ms": max(0.0, float(event.get("duration_ms") or 0)),
            "user_agent": browser(event.get("user_agent")), "authenticated": int(bool(event.get("authenticated")))}


def record_request(event):
    _insert("traffic", _request_row(event))


# Request-path journaling. The traffic middleware used to insert one row per request inline, which
# took a connection and SQLite's single write lock on every request. Rows are now queued in memory and
# committed in batches by one background writer (at most ~_FLUSH_INTERVAL_SECONDS later). Readers of
# the journal flush first, so a request is always visible to the admin views that list it. Rows are
# bound to the store they were queued for and are never written into a different database.
_FLUSH_INTERVAL_SECONDS = 0.25
_PENDING_MAX = 10000
_pending_lock = threading.Lock()
_flush_lock = threading.Lock()
_pending = {"key": None, "rows": []}
_flush_wakeup = threading.Event()
_flusher = {"thread": None}


def _flush_loop():
    while True:
        _flush_wakeup.wait(_FLUSH_INTERVAL_SECONDS)
        _flush_wakeup.clear()
        try:
            flush_pending()
        except Exception:  # never let the writer thread die; failures are recorded by flush_pending
            pass


def _ensure_flusher():
    thread = _flusher["thread"]
    if thread is not None and thread.is_alive():
        return
    with _pending_lock:
        thread = _flusher["thread"]
        if thread is not None and thread.is_alive():
            return
        thread = threading.Thread(target=_flush_loop, name="security-journal-writer", daemon=True)
        _flusher["thread"] = thread
        thread.start()


def enqueue_request(event):
    """Queue a request event for the background writer. Does no I/O."""
    row = _request_row(event)
    key = _key()
    dropped = False
    with _pending_lock:
        if _pending["key"] != key:
            _pending["key"], _pending["rows"] = key, []
        rows = _pending["rows"]
        if len(rows) >= _PENDING_MAX:  # storage is stuck; bound memory rather than grow without limit
            del rows[0]
            dropped = True
        rows.append(row)
    if dropped:
        mark_failure("traffic")
    _ensure_flusher()


def flush_pending():
    """Commit every queued request event now. Returns the number of rows written.

    Runs under the platform scope (services/tenant_scope). The batch this writer drains is a mix of
    every tenant that made a request in the last interval plus the anonymous ones, and it runs on a
    background thread with no tenant context at all, so under row-level security an ordinary
    tenant-scoped connection would reject most of the batch. The privilege is taken explicitly and
    recorded, rather than being inherited by accident from whichever request happened to trigger the
    flush.
    """
    with _flush_lock:
        with _pending_lock:
            key, rows = _pending["key"], _pending["rows"]
            _pending["rows"] = []
        if not rows or key != _key():
            return 0
        columns = list(rows[0])
        sql = f"INSERT INTO platform_request_events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})"
        try:
            from services.tenant_scope import platform_scope

            init_tables()
            with platform_scope("security-journal writer: cross-tenant request batch"):
                with store.feature_conn() as conn:
                    for row in rows:
                        conn.execute(sql, tuple(row[c] for c in columns))
                    conn.commit()
            mark_success("traffic")
        except Exception:
            mark_failure("traffic")
            return 0
        return len(rows)


atexit.register(flush_pending)


def auth_events(*, organization_id="", user_id="", limit=200, since_iso="", event_type="", successful_logins=False):
    init_tables()
    clauses, params = ["created_at >= ?"], [_cutoff("auth")]
    if successful_logins:
        clauses.append("event_type IN ('login.success','saml.success')")
    for column, value in (("organization_id", organization_id), ("user_id", user_id), ("event_type", event_type)):
        if value:
            clauses.append(column + "=?"); params.append(value)
    if since_iso:
        clauses.append("created_at>=?"); params.append(since_iso)
    with store.feature_conn() as conn:
        rows = conn.execute(f"SELECT * FROM platform_auth_events WHERE {' AND '.join(clauses)} ORDER BY created_at DESC,id DESC LIMIT ?",
                            (*params, max(1, min(2000, int(limit))))).fetchall()
    return [dict(row) for row in rows]


def request_events(*, limit=200, source_ip="", path_prefix=""):
    flush_pending()
    init_tables()
    clauses, params = ["created_at >= ?"], [_cutoff("traffic")]
    if source_ip:
        clauses.append("source_ip=?"); params.append(source_ip)
    if path_prefix:
        # Prefix matching is literal; SQL wildcards in a user-entered filter must not broaden it.
        clauses.append("substr(path,1,?)=?"); params.extend([len(path_prefix), path_prefix])
    with store.feature_conn() as conn:
        rows = conn.execute(f"SELECT * FROM platform_request_events WHERE {' AND '.join(clauses)} ORDER BY created_at DESC,id DESC LIMIT ?",
                            (*params, max(1, min(5000, int(limit))))).fetchall()
    return [{**dict(row), "ip_hash": "", "authenticated": bool(row["authenticated"])} for row in rows]


def login_count(since_iso):
    init_tables()
    with store.feature_conn() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM platform_auth_events WHERE created_at>=? AND created_at>=? AND event_type IN ('login.success','saml.success')",
                                (_cutoff("auth"), since_iso)).fetchone()[0])


def customer_login_stats():
    init_tables()
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    with store.feature_conn() as conn:
        rows = conn.execute("""SELECT organization_id, MAX(created_at) AS last_login_at,
            COUNT(DISTINCT CASE WHEN created_at>=? THEN user_id END) AS active_users_7d
            FROM platform_auth_events WHERE created_at>=? AND event_type IN ('login.success','saml.success')
            GROUP BY organization_id""", (week, _cutoff("auth"))).fetchall()
    return {row["organization_id"]: dict(row) for row in rows}


def health(*, verify_writes=False):
    flush_pending()
    insert_permission_verified = False
    readable = False
    try:
        init_tables()
        with store.feature_conn() as conn:
            conn.execute("SELECT id FROM platform_auth_events LIMIT 1").fetchall()
            conn.execute("SELECT id FROM platform_request_events LIMIT 1").fetchall()
            readable = True
            if verify_writes:
                # Exercise INSERT privileges without manufacturing a login or traffic event.
                for table in ("platform_auth_events", "platform_request_events"):
                    conn.execute(f"INSERT INTO {table} SELECT * FROM {table} WHERE 1=0")
                conn.commit()
                insert_permission_verified = True
    except Exception:
        pass
    with _lock:
        writes = {kind: {k: v for k, v in value.items() if k != "last_warning"} for kind, value in _health.get(_key(), {}).items()}
    failed = any(v.get("last_failure_at", "") > v.get("last_success_at", "") for v in writes.values())
    return {"status": "degraded" if not readable or failed or (verify_writes and not insert_permission_verified) else "available", "backend": store.dialect(),
            "readable": readable, "writes": writes, "insert_permission_verified": insert_permission_verified,
            "auth_retention_days": _days("auth"), "traffic_retention_days": _days("traffic"),
            "scope": "Durable metadata, not tamper-proof storage or a complete click/session recording"}


# ── Retention ────────────────────────────────────────────────────────────────
#
# One 5,000-row batch per 60-second tick is a ceiling of 5,000 rows a minute. At the request rate
# a mid-size customer base produces, rows arrive faster than that, so the journal grows even
# though retention is configured -- and a retention change or a restore from an older backup left
# a backlog that took most of a day to drain (docs/LOAD_TEST_REPORT.md section 6).
#
# prune() now drains inside a time budget rather than deleting a fixed number of rows: it keeps
# issuing batches until the backlog is gone or the budget is spent, and sizes each batch from how
# long the last one took, so a fast database gets big batches and a busy one gets small ones
# instead of a single statement that holds locks for 19 seconds. It reports whether a backlog
# remains, and the maintenance loop uses that to come straight back instead of sleeping a minute.

_PRUNE_BUDGET_SECONDS = 20.0
_PRUNE_TARGET_BATCH_SECONDS = 2.0
_PRUNE_BATCH_START = 5000
_PRUNE_BATCH_MIN = 500
_PRUNE_BATCH_MAX = 100000
_prune_batch = {}


def _prune_batch_size(kind):
    return int(_prune_batch.get(kind) or _PRUNE_BATCH_START)


def _record_batch(kind, size, seconds):
    """Halve the batch when a statement runs long, grow it while they stay quick."""
    if seconds > _PRUNE_TARGET_BATCH_SECONDS * 2:
        size = max(_PRUNE_BATCH_MIN, size // 2)
    elif seconds < _PRUNE_TARGET_BATCH_SECONDS / 2:
        size = min(_PRUNE_BATCH_MAX, size * 2)
    _prune_batch[kind] = size


def _delete_batch(conn, table, cutoff, size):
    """One bounded delete. The row identifier is the physical one (ctid / rowid) rather than the
    TEXT primary key, so the delete goes straight to the row instead of probing the PK index for
    every one of thousands of random uuids."""
    if store.postgres_enabled():
        sql = (f"DELETE FROM {table} WHERE ctid IN "
               f"(SELECT ctid FROM {table} WHERE created_at < ? ORDER BY created_at LIMIT ?)")
    else:
        sql = (f"DELETE FROM {table} WHERE rowid IN "
               f"(SELECT rowid FROM {table} WHERE created_at < ? ORDER BY created_at LIMIT ?)")
    return int(conn.execute(sql, (cutoff, int(size))).rowcount or 0)


def prune(budget_seconds=None, flush=True):
    """Delete expired rows in bounded batches until the backlog is gone or the budget is spent.

    All reads independently apply the same TTL, so a row that is still here past its cutoff is
    never served. Returns {"auth": n, "traffic": n, "backlog": bool, "seconds": float}; `backlog`
    is True when the budget ran out with rows still expired.
    """
    if flush:
        flush_pending()
    init_tables()
    budget = float(_PRUNE_BUDGET_SECONDS if budget_seconds is None else budget_seconds)
    started = time.monotonic()
    deleted = {"auth": 0, "traffic": 0}
    backlog = False
    with store.feature_conn() as conn:
        for kind, table in (("auth", "platform_auth_events"), ("traffic", "platform_request_events")):
            cutoff = _prune_cutoff(kind)
            while True:
                left = budget - (time.monotonic() - started)
                if left <= 0:
                    backlog = True
                    break
                size = _prune_batch_size(kind)
                batch_started = time.monotonic()
                removed = _delete_batch(conn, table, cutoff, size)
                conn.commit()
                elapsed = time.monotonic() - batch_started
                deleted[kind] += removed
                _record_batch(kind, size, elapsed)
                if removed < size:  # fewer than asked for: nothing expired is left
                    break
    mark_success("retention")
    return {**deleted, "backlog": backlog, "seconds": round(time.monotonic() - started, 3)}
