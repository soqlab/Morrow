"""Daily usage rollups: long-term request, sign-in and active-user trends per organization.

The security journal keeps raw request rows for MORROW_TRAFFIC_RETENTION_DAYS (default 7) and sign-in rows
for MORROW_AUTH_LOG_RETENTION_DAYS (default 90). The admin analytics need 30- and 90-day trends and a
previous period to compare with, so every closed UTC day is summarised here before its raw rows expire.

Tables (feature store: SQLite file or Postgres, the same home as the journal):
  platform_usage_daily        one row per (day, organization_id): request counts by outcome, authenticated
                              requests, a latency histogram plus exact p50/p95 for that org-day, sign-ins
                              and scans. organization_id '' holds unattributed (anonymous) traffic.
  platform_active_users_daily one row per (day, organization_id, actor_hash). actor_hash is a keyed HMAC of
                              the user or API-key actor id; the raw id is never stored.
  platform_usage_rollup_days  one row per day that was rolled up from complete raw data, with exact
                              platform-wide p50/p95. A day missing here is unknown, never zero.
  platform_usage_routes_daily one row per (day, path): requests, 5xx and 4xx counts, for the admin
                              overview's routes-by-errors list.
  platform_usage_rollup_state key/value run state (last run, last error, and a generated salt when no
                              secret is configured).

A day is rolled up only when it is closed (ended at least ROLLUP_GRACE ago) and every raw row for it is
still inside both retention windows, so a rollup is never built from partially pruned data. Rolling a day
replaces its rows, so a rerun is idempotent. The first run backfills every complete day still held in raw
storage; after that the periodic task (hourly by default) picks up each newly closed day.

Nothing here stores request bodies, query strings, tokens, IP addresses or user agents.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import db_feature_store as store

logger = logging.getLogger(__name__)
UTC = timezone.utc
DAY = timedelta(days=1)
ROLLUP_GRACE = timedelta(minutes=10)

#: Upper bounds (ms, inclusive) of the latency histogram buckets; the last column counts everything slower.
LATENCY_BOUNDS: Tuple[int, ...] = (10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)
LATENCY_COLUMNS: Tuple[str, ...] = tuple(f"lat_le_{b}" for b in LATENCY_BOUNDS) + ("lat_gt_10000",)
COUNT_COLUMNS: Tuple[str, ...] = ("requests", "client_errors", "server_errors", "rate_limited", "authenticated_requests",
                                  "logins_success", "logins_failed", "scans")
USAGE_TABLES = ("platform_usage_daily", "platform_active_users_daily", "platform_usage_rollup_days",
                "platform_usage_routes_daily", "platform_usage_rollup_state")
#: Bumped when roll_day changes what a rolled day holds. run() re-rolls every day still in raw retention once
#: per bump; the analytics overview only reads retained rolled days in place of raw rows while this matches
#: the stored format_version (2: route counts, and day bounds that match the raw created_at format exactly).
ROLLUP_FORMAT = "2"

_LOGIN_SUCCESS = ("login.success", "saml.success")
_LOGIN_FAILURE = ("login.failure", "saml.failure")

_lock = threading.RLock()
_ready: Set[str] = set()
_salt_cache: Dict[str, bytes] = {}


def enabled() -> bool:
    return str(os.getenv("MORROW_USAGE_ROLLUPS_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def interval_seconds() -> float:
    try:
        return max(60.0, float(os.getenv("MORROW_USAGE_ROLLUP_INTERVAL_SECONDS", "3600") or 3600))
    except ValueError:
        return 3600.0


def max_days_per_pass() -> int:
    """How many days one rollup pass may aggregate before yielding. Bounds a backfill."""
    try:
        return max(1, min(3650, int(os.getenv("MORROW_USAGE_ROLLUP_MAX_DAYS_PER_PASS", "40") or 40)))
    except ValueError:
        return 40


def retention_days() -> int:
    try:
        return max(35, min(3650, int(os.getenv("MORROW_USAGE_ROLLUP_RETENTION_DAYS", "400") or 400)))
    except ValueError:
        return 400


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def day_floor(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def day_ceil(dt: datetime) -> datetime:
    floor = day_floor(dt)
    return floor if floor == dt.astimezone(UTC) else floor + DAY


def day_key(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d")


def day_start(key: str) -> datetime:
    return datetime.strptime(key[:10], "%Y-%m-%d").replace(tzinfo=UTC)


def _key() -> str:
    value = store._feature_dsn() if store.postgres_enabled() else store._sqlite_path()
    return store.dialect() + ":" + hashlib.sha256(str(value).encode()).hexdigest()


# ── Schema ───────────────────────────────────────────────────────────────────

_LAT_DDL = ",\n        ".join(f"{c} INTEGER NOT NULL DEFAULT 0" for c in LATENCY_COLUMNS)
SCHEMA = f"""
    CREATE TABLE IF NOT EXISTS platform_usage_daily (
        day TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        requests INTEGER NOT NULL DEFAULT 0,
        client_errors INTEGER NOT NULL DEFAULT 0,
        server_errors INTEGER NOT NULL DEFAULT 0,
        rate_limited INTEGER NOT NULL DEFAULT 0,
        authenticated_requests INTEGER NOT NULL DEFAULT 0,
        logins_success INTEGER NOT NULL DEFAULT 0,
        logins_failed INTEGER NOT NULL DEFAULT 0,
        scans INTEGER NOT NULL DEFAULT 0,
        duration_sum_ms REAL NOT NULL DEFAULT 0,
        duration_max_ms REAL NOT NULL DEFAULT 0,
        p50_ms REAL,
        p95_ms REAL,
        {_LAT_DDL},
        rolled_at TEXT NOT NULL,
        PRIMARY KEY (day, organization_id)
    );
    CREATE INDEX IF NOT EXISTS idx_usage_daily_org_day ON platform_usage_daily(organization_id, day);
    CREATE TABLE IF NOT EXISTS platform_active_users_daily (
        day TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        actor_hash TEXT NOT NULL,
        PRIMARY KEY (day, organization_id, actor_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_active_users_daily_org_day ON platform_active_users_daily(organization_id, day);
    CREATE TABLE IF NOT EXISTS platform_usage_rollup_days (
        day TEXT PRIMARY KEY,
        requests INTEGER NOT NULL DEFAULT 0,
        p50_ms REAL,
        p95_ms REAL,
        rolled_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS platform_usage_routes_daily (
        day TEXT NOT NULL,
        path TEXT NOT NULL,
        requests INTEGER NOT NULL DEFAULT 0,
        server_errors INTEGER NOT NULL DEFAULT 0,
        client_errors INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (day, path)
    );
    CREATE TABLE IF NOT EXISTS platform_usage_rollup_state (
        state_key TEXT PRIMARY KEY,
        state_value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
"""


def init_tables() -> None:
    key = _key()
    with _lock:
        if key in _ready:
            return
        with store.feature_conn() as conn:
            present = False
            if store.postgres_enabled():
                row = conn.execute("SELECT to_regclass('public.platform_usage_daily'), to_regclass('public.platform_active_users_daily'), "
                                   "to_regclass('public.platform_usage_rollup_days'), "
                                   "to_regclass('public.platform_usage_routes_daily'), "
                                   "to_regclass('public.platform_usage_rollup_state')").fetchone()
                present = all(row)
            if not present:
                conn.executescript(SCHEMA)
                conn.commit()
        _ready.add(key)


# ── Actor hashing ────────────────────────────────────────────────────────────


def _state_get(conn: Any, name: str) -> Optional[str]:
    row = conn.execute("SELECT state_value FROM platform_usage_rollup_state WHERE state_key = ?", (name,)).fetchone()
    return str(row[0]) if row else None


def _state_set(conn: Any, name: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO platform_usage_rollup_state (state_key, state_value, updated_at) VALUES (?, ?, ?)",
                 (name, str(value), _iso(_now())))


def salt() -> bytes:
    """Key for actor hashes: MORROW_USAGE_ACTOR_SALT, else derived from the vault/JWT secret, else a random
    salt generated once and kept in platform_usage_rollup_state (development only)."""
    configured = os.getenv("MORROW_USAGE_ACTOR_SALT") or ""
    if configured:
        return hashlib.sha256(("usage-actor-salt:" + configured).encode()).digest()
    secret = os.getenv("MORROW_VAULT_MASTER_KEY") or os.getenv("MORROW_AUTH_JWT_SECRET") or ""
    if secret:
        return hmac.new(secret.encode(), b"pq-usage-actor-salt", hashlib.sha256).digest()
    key = _key()
    with _lock:
        if key in _salt_cache:
            return _salt_cache[key]
        init_tables()
        with store.feature_conn() as conn:
            value = _state_get(conn, "generated_salt")
            if not value:
                value = secrets.token_hex(32)
                _state_set(conn, "generated_salt", value)
                conn.commit()
        _salt_cache[key] = bytes.fromhex(value)
        return _salt_cache[key]


def actor_hash(actor_id: str, key: Optional[bytes] = None) -> str:
    return hmac.new(key or salt(), ("actor:" + str(actor_id)).encode(), hashlib.sha256).hexdigest()[:40]


# ── Latency helpers ──────────────────────────────────────────────────────────


def latency_bucket(duration_ms: float) -> str:
    for bound, column in zip(LATENCY_BOUNDS, LATENCY_COLUMNS):
        if duration_ms <= bound:
            return column
    return LATENCY_COLUMNS[-1]


def nearest_rank(sorted_values: Sequence[float], pct: int) -> Optional[float]:
    if not sorted_values:
        return None
    rank = (len(sorted_values) * pct + 99) // 100
    return round(float(sorted_values[max(1, rank) - 1]), 1)


def histogram_percentile(hist: Dict[str, int], pct: int, max_ms: Optional[float] = None) -> Optional[float]:
    """Nearest-rank percentile estimated from bucket counts, interpolated linearly inside the bucket."""
    total = sum(int(hist.get(c) or 0) for c in LATENCY_COLUMNS)
    if total <= 0:
        return None
    rank = max(1, (total * pct + 99) // 100)
    seen = 0
    lower = 0.0
    for i, column in enumerate(LATENCY_COLUMNS):
        n = int(hist.get(column) or 0)
        upper = float(LATENCY_BOUNDS[i]) if i < len(LATENCY_BOUNDS) else float(max(max_ms or 0.0, lower))
        if n and seen + n >= rank:
            value = lower + (upper - lower) * (rank - seen) / n
            if max_ms is not None:
                value = min(value, float(max_ms))
            return round(value, 1)
        seen += n
        lower = upper
    return round(float(max_ms), 1) if max_ms is not None else None


def raw_histogram_exprs() -> Dict[str, str]:
    """SQL (both dialects) that buckets platform_request_events.duration_ms like the rollup columns."""
    exprs: Dict[str, str] = {}
    lower = None
    for bound, column in zip(LATENCY_BOUNDS, LATENCY_COLUMNS):
        cond = f"duration_ms <= {bound}" if lower is None else f"duration_ms > {lower} AND duration_ms <= {bound}"
        exprs[column] = f"SUM(CASE WHEN {cond} THEN 1 ELSE 0 END)"
        lower = bound
    exprs[LATENCY_COLUMNS[-1]] = f"SUM(CASE WHEN duration_ms > {LATENCY_BOUNDS[-1]} THEN 1 ELSE 0 END)"
    exprs["duration_max_ms"] = "MAX(duration_ms)"
    return exprs


# ── Rolling up ───────────────────────────────────────────────────────────────


def _retention_cutoff(now: datetime) -> datetime:
    from services import security_journal
    return max(now - timedelta(days=int(security_journal._days("traffic"))),
               now - timedelta(days=int(security_journal._days("auth"))))


def _complete_from(now: datetime) -> Optional[datetime]:
    """The first whole UTC day for which *both* journals still hold every row, or None.

    A journal restored from an older backup, or one whose retention was just lowered, holds rows
    that are already past their cutoff. Rolling only from the retention cutoff forward left those
    days unrolled while the pruner deleted them, which is why the 90-day analytics range could
    never be answered.

    Two rules keep a rollup from being built on partial data, which is the reason the old bound
    existed and is worth more than covering one extra day:
      * day_ceil, not day_floor: the pruner deletes oldest-first, so the day the oldest surviving
        row falls in may have been partly deleted. Only whole days after it are known complete.
      * the *later* of the two journals' boundaries: a day where request rows survive but sign-in
        rows do not would be rolled up with zero logins, which is a wrong number, not a missing one.
    Each read is one index probe on created_at.
    """
    bounds: List[datetime] = []
    with store.feature_conn() as conn:
        for table in ("platform_request_events", "platform_auth_events"):
            try:
                row = conn.execute(f"SELECT MIN(created_at) FROM {table}").fetchone()
            except Exception:
                return None
            found = _parse_ts(row[0] if row else None)
            if found is not None:
                bounds.append(day_ceil(found))
    if not bounds:
        return None
    # Never older than the rollup's own retention horizon: those days are deleted by run() anyway.
    return max(max(bounds), day_floor(now) - timedelta(days=retention_days()))


def _parse_ts(value: Any) -> Optional[datetime]:
    """A stored journal timestamp (ISO text or a Postgres timestamptz) as an aware UTC instant."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        try:
            return day_start(str(value)[:10])
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def rollup_start(now: Optional[datetime] = None) -> datetime:
    """The first day run() aggregates: the older of the retention cutoff and the oldest raw row."""
    now = (now or _now()).astimezone(UTC)
    cutoff = day_ceil(_retention_cutoff(now))
    complete = _complete_from(now)
    return cutoff if complete is None else min(cutoff, complete)


def unrolled_floor(now: Optional[datetime] = None) -> Optional[datetime]:
    """The start of the oldest closed UTC day that run() should have rolled up but has not.

    security_journal.prune() holds its cutoff back to this so a day's raw rows are never deleted
    before they have been aggregated. None means every closed day in scope is rolled up.
    """
    if not enabled():
        return None
    now = (now or _now()).astimezone(UTC)
    init_tables()
    first = rollup_start(now)
    last_end = day_floor(now - ROLLUP_GRACE)
    if first >= last_end:
        return None
    with store.feature_conn() as conn:
        done = {str(r[0]) for r in conn.execute(
            "SELECT day FROM platform_usage_rollup_days WHERE day >= ? AND day < ?",
            (day_key(first), day_key(last_end))).fetchall()}
    day = first
    while day < last_end:
        if day_key(day) not in done:
            return day
        day += DAY
    return None


def _blank(org: str, day: str, rolled_at: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {"day": day, "organization_id": org, "duration_sum_ms": 0.0, "duration_max_ms": 0.0,
                           "p50_ms": None, "p95_ms": None, "rolled_at": rolled_at}
    for column in COUNT_COLUMNS + LATENCY_COLUMNS:
        row[column] = 0
    return row


def _scan_counts(start: datetime, end: datetime) -> Dict[str, int]:
    """Scans per organization for one day. The scans table can live in a different database from the journal."""
    from services import platform_analytics as pa
    out: Dict[str, int] = {}
    with pa.Reader() as r:
        if not r.has("scans", "created_at", "organization_id"):
            return out
        kind = r.ts_kind("scans", "created_at")
        for row in r.rows("scans", "SELECT organization_id AS org, COUNT(*) AS n FROM scans WHERE created_at >= ? AND created_at < ? "
                                   "GROUP BY organization_id", [pa.ts_bound(kind, start), pa.ts_bound(kind, end)]):
            out[str(row.get("org") or "")] = int(row.get("n") or 0)
    return out


def roll_day(day: datetime, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Replace the rollup rows for one UTC day from the raw journal. Returns a small summary."""
    start = day_floor(day)
    end = start + DAY
    key = day_key(start)
    rolled_at = _iso(now or _now())
    # Bounds without a zone suffix, like the analytics reads: '...T00:00:00.5Z' sorts before '...T00:00:00Z'
    # ('.' < 'Z'), so a 'Z' bound put the first second after midnight into the previous day.
    lo, hi = start.strftime("%Y-%m-%dT%H:%M:%S"), end.strftime("%Y-%m-%dT%H:%M:%S")
    rows: Dict[str, Dict[str, Any]] = {}
    routes: Dict[str, List[int]] = {}
    durations: Dict[str, List[float]] = {}
    everything: List[float] = []
    actors: Set[Tuple[str, str]] = set()
    with store.feature_conn() as conn:
        cur = conn.execute("SELECT organization_id, actor_id, status_code, duration_ms, authenticated, path FROM platform_request_events "
                           "WHERE created_at >= ? AND created_at < ?", (lo, hi))
        for org, actor, status, duration, authenticated, path in cur.fetchall():
            org = str(org or "")
            row = rows.get(org) or rows.setdefault(org, _blank(org, key, rolled_at))
            status = int(status or 0)
            duration = max(0.0, float(duration or 0.0))
            route = routes.get(path) or routes.setdefault(path, [0, 0, 0])
            route[0] += 1
            if status >= 500:
                route[1] += 1
            elif 400 <= status < 500:
                route[2] += 1
            row["requests"] += 1
            if status == 429:
                row["rate_limited"] += 1
            elif 400 <= status < 500:
                row["client_errors"] += 1
            elif status >= 500:
                row["server_errors"] += 1
            if int(authenticated or 0):
                row["authenticated_requests"] += 1
                if actor:
                    actors.add((org, str(actor)))
            row[latency_bucket(duration)] += 1
            row["duration_sum_ms"] += duration
            row["duration_max_ms"] = max(row["duration_max_ms"], duration)
            durations.setdefault(org, []).append(duration)
            everything.append(duration)
        cur = conn.execute("SELECT organization_id, user_id, event_type FROM platform_auth_events "
                           "WHERE created_at >= ? AND created_at < ? AND event_type IN ('login.success','saml.success','login.failure','saml.failure')",
                           (lo, hi))
        for org, user, event in cur.fetchall():
            org = str(org or "")
            row = rows.get(org) or rows.setdefault(org, _blank(org, key, rolled_at))
            if event in _LOGIN_SUCCESS:
                row["logins_success"] += 1
                if user:
                    actors.add((org, str(user)))
            else:
                row["logins_failed"] += 1
    try:
        for org, n in _scan_counts(start, end).items():
            row = rows.get(org) or rows.setdefault(org, _blank(org, key, rolled_at))
            row["scans"] = n
    except Exception as exc:  # scans are informational here; the analytics read them from the scans table
        logger.debug("usage rollup: scan counts unavailable for %s: %s", key, exc.__class__.__name__)
    for org, values in durations.items():
        values.sort()
        rows[org]["p50_ms"] = nearest_rank(values, 50)
        rows[org]["p95_ms"] = nearest_rank(values, 95)
        rows[org]["duration_sum_ms"] = round(rows[org]["duration_sum_ms"], 2)
    everything.sort()
    hkey = salt()
    columns = ["day", "organization_id", *COUNT_COLUMNS, "duration_sum_ms", "duration_max_ms", "p50_ms", "p95_ms",
               *LATENCY_COLUMNS, "rolled_at"]
    with store.feature_conn() as conn:
        if store.postgres_enabled():
            # Every API replica runs maintain(). Without this, two replicas replacing the same day both delete
            # nothing and then both insert, and one fails on the primary key. The lock serializes the
            # delete-and-insert per day; the second writer simply replaces the first's identical rows.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("pq_usage_rollup:" + key,))
        conn.execute("DELETE FROM platform_usage_daily WHERE day = ?", (key,))
        conn.execute("DELETE FROM platform_active_users_daily WHERE day = ?", (key,))
        conn.execute("DELETE FROM platform_usage_routes_daily WHERE day = ?", (key,))
        if routes:
            conn.executemany("INSERT INTO platform_usage_routes_daily (day, path, requests, server_errors, client_errors) "
                             "VALUES (?, ?, ?, ?, ?)", [(key, str(p), n, e, c) for p, (n, e, c) in routes.items()])
        if rows:
            conn.executemany(f"INSERT INTO platform_usage_daily ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                             [tuple(r[c] for c in columns) for r in rows.values()])
        hashed = sorted({(org, actor_hash(actor, hkey)) for org, actor in actors})
        if hashed:
            conn.executemany("INSERT INTO platform_active_users_daily (day, organization_id, actor_hash) VALUES (?, ?, ?)",
                             [(key, org, h) for org, h in hashed])
        conn.execute("DELETE FROM platform_usage_rollup_days WHERE day = ?", (key,))
        conn.execute("INSERT INTO platform_usage_rollup_days (day, requests, p50_ms, p95_ms, rolled_at) VALUES (?, ?, ?, ?, ?)",
                     (key, len(everything), nearest_rank(everything, 50), nearest_rank(everything, 95), rolled_at))
        conn.commit()
    return {"day": key, "organizations": len(rows), "requests": len(everything), "active_actors": len(hashed)}


def run(now: Optional[datetime] = None, rebuild: bool = False) -> Dict[str, Any]:
    """Roll up every closed day whose raw rows are complete and not yet rolled up (all of them with rebuild).

    Runs under the platform scope (services/tenant_scope): a rollup reads one day of raw events for
    every tenant and writes one platform_usage_daily row per tenant, including the '' bucket for
    anonymous traffic. Both those tables are covered by the row-level-security plan, so this is a
    genuine cross-tenant operation and takes the privilege explicitly rather than depending on
    whatever tenant context the periodic task happened to inherit.
    """
    from services.tenant_scope import platform_scope

    with platform_scope("usage rollups: cross-tenant daily aggregate"):
        return _run_unscoped(now=now, rebuild=rebuild)


def _run_unscoped(now: Optional[datetime] = None, rebuild: bool = False) -> Dict[str, Any]:
    now = (now or _now()).astimezone(UTC)
    from services import security_journal
    security_journal.flush_pending()
    security_journal.init_tables()
    init_tables()
    # From the oldest raw row, not from the retention cutoff: a restored or over-retained journal
    # holds days that are already past their cutoff, and those days have to be aggregated before
    # the pruner is allowed to delete them (security_journal._prune_cutoff waits for exactly this).
    first = rollup_start(now)
    # Where the journal's complete range began when this pass started. A day that is below this is
    # simply a day the journal never held rows for (a young journal inside a long retention
    # window), and rolling it up as zero is the right answer. A day that drops below the *current*
    # floor while the pass is running is a different thing entirely -- see the loop.
    start_floor = _complete_from(now)
    last_end = day_floor(now - ROLLUP_GRACE)
    rolled: List[Dict[str, Any]] = []
    error = ""
    backlog = False
    skipped_partial = 0
    try:
        with store.feature_conn() as conn:
            done = {str(r[0]) for r in conn.execute("SELECT day FROM platform_usage_rollup_days WHERE day >= ?",
                                                    (day_key(first),)).fetchall()}
            # Days rolled by an older format are rebuilt while their raw rows are still retained.
            reformat = _state_get(conn, "format_version") != ROLLUP_FORMAT
        cursor = first
        budget = max_days_per_pass()
        floor = first
        while cursor < last_end:
            if rebuild or reformat or day_key(cursor) not in done:
                # The completeness floor is re-read, not taken once at the top. A long backfill
                # takes minutes, and the pruner is deleting from the other end of the journal
                # while it runs: without this, a pass that starts when day D is complete reaches
                # day D after the pruner has removed it and rolls it up **as zero** -- exactly the
                # silent wrong number the whole design is meant to prevent. One indexed MIN() per
                # day is nothing next to aggregating that day.
                #
                # Only a floor that has *advanced since this pass began* means rows were deleted
                # under us. A day below where the floor already was is a day the journal never
                # held rows for, and zero is the truth about it.
                if start_floor is not None:
                    floor = _complete_from(now) or floor
                    if floor > start_floor and cursor < floor:
                        skipped_partial += 1
                        cursor += DAY
                        continue
                if len(rolled) >= budget:
                    # A backfill (a restore, or a journal that has never been rolled) can be
                    # hundreds of days. Roll a bounded number per pass so one catch-up cannot
                    # occupy the maintenance thread for an unbounded time; maintain() comes
                    # straight back while there is more to do.
                    backlog = True
                    break
                rolled.append(roll_day(cursor, now))
            cursor += DAY
        horizon = day_key(day_floor(now) - timedelta(days=retention_days()))
        with store.feature_conn() as conn:
            for table in ("platform_usage_daily", "platform_active_users_daily", "platform_usage_rollup_days",
                          "platform_usage_routes_daily"):
                conn.execute(f"DELETE FROM {table} WHERE day < ?", (horizon,))
            if reformat:
                _state_set(conn, "format_version", ROLLUP_FORMAT)
            conn.commit()
    except Exception as exc:
        error = exc.__class__.__name__
        logger.error("usage rollup failed: %s", error)
    try:
        with store.feature_conn() as conn:
            _state_set(conn, "last_run_at", _iso(now))
            _state_set(conn, "last_days_rolled", str(len(rolled)))
            _state_set(conn, "last_skipped_partial", str(skipped_partial))
            _state_set(conn, "last_error", error)
            if not error:
                _state_set(conn, "last_success_at", _iso(now))
            conn.commit()
    except Exception:
        pass
    return {"rolled": rolled, "error": error or None, "complete_from": day_key(first),
            "closed_through": day_key(last_end), "backlog": backlog,
            "skipped_partial": skipped_partial}


def state() -> Dict[str, str]:
    init_tables()
    with store.feature_conn() as conn:
        rows = conn.execute("SELECT state_key, state_value FROM platform_usage_rollup_state WHERE state_key <> 'generated_salt'").fetchall()
    return {str(r[0]): str(r[1]) for r in rows}


async def maintain(run_in_threadpool: Callable[..., Any]) -> None:
    """Periodic task for the API lifespan: backfill on the first pass, then roll newly closed days."""
    while True:
        backlog = False
        if enabled():
            try:
                result = await run_in_threadpool(run)
                backlog = bool((result or {}).get("backlog"))
            except Exception as exc:  # never let the loop die
                logger.error("usage rollup task error: %s", exc.__class__.__name__)
        # A bounded pass that stopped early has more days waiting; come straight back instead of
        # sleeping out the interval, so a backfill drains in minutes rather than in passes-per-hour.
        await asyncio.sleep(2.0 if backlog else interval_seconds())


# ── Reading (used by services/platform_analytics) ────────────────────────────


def _org_sql(org: Optional[str]) -> Tuple[str, List[Any]]:
    return (" AND organization_id = ?", [org]) if org is not None else ("", [])


def rolled_days(r: Any, start: datetime, end: datetime) -> Set[str]:
    """Day keys in [start, end) that have a complete rollup. r is a platform_analytics.Reader."""
    if not r.has("platform_usage_rollup_days", "day"):
        return set()
    return {str(row["day"]) for row in r.rows("platform_usage_rollup_days", "SELECT day FROM platform_usage_rollup_days "
                                                                           "WHERE day >= ? AND day < ?", [day_key(start), day_key(end)])}


def rollup_extent(r: Any) -> Dict[str, Any]:
    if not r.has("platform_usage_rollup_days", "day"):
        return {"days": 0, "first_day": None, "last_day": None}
    row = r.one("platform_usage_rollup_days", "SELECT COUNT(*) AS n, MIN(day) AS lo, MAX(day) AS hi FROM platform_usage_rollup_days")
    return {"days": int(row.get("n") or 0), "first_day": row.get("lo"), "last_day": row.get("hi")}


def sums(r: Any, start: datetime, end: datetime, org: Optional[str] = None) -> Dict[str, Any]:
    extra, params = _org_sql(org)
    select = ", ".join(f"SUM({c}) AS {c}" for c in COUNT_COLUMNS + LATENCY_COLUMNS)
    row = r.one("platform_usage_daily", f"SELECT {select}, MAX(duration_max_ms) AS duration_max_ms FROM platform_usage_daily "
                                        f"WHERE day >= ? AND day < ?{extra}", [day_key(start), day_key(end), *params])
    return {k: (v or 0) for k, v in row.items()}


def by_day(r: Any, start: datetime, end: datetime, org: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    extra, params = _org_sql(org)
    select = ", ".join(f"SUM({c}) AS {c}" for c in COUNT_COLUMNS)
    # p50/p95 are exact per org-day; for a single organization there is one row per day.
    pct = ", MAX(p50_ms) AS p50_ms, MAX(p95_ms) AS p95_ms" if org is not None else ""
    out: Dict[str, Dict[str, Any]] = {}
    for row in r.rows("platform_usage_daily", f"SELECT day, {select}{pct} FROM platform_usage_daily WHERE day >= ? AND day < ?{extra} "
                                              "GROUP BY day", [day_key(start), day_key(end), *params]):
        out[str(row.pop("day")) + "T00:00:00Z"] = row
    return out


def by_org(r: Any, start: datetime, end: datetime) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in r.rows("platform_usage_daily", "SELECT organization_id AS org, SUM(requests) AS requests, SUM(logins_success) AS logins, "
                                              "MAX(CASE WHEN requests > 0 THEN day END) AS last_request_day, "
                                              "MAX(CASE WHEN logins_success > 0 THEN day END) AS last_login_day "
                                              "FROM platform_usage_daily WHERE day >= ? AND day < ? GROUP BY organization_id",
                      [day_key(start), day_key(end)]):
        out[str(row.pop("org") or "")] = row
    return out


def day_latency(r: Any, start: datetime, end: datetime) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in r.rows("platform_usage_rollup_days", "SELECT day, requests, p50_ms, p95_ms FROM platform_usage_rollup_days "
                                                    "WHERE day >= ? AND day < ?", [day_key(start), day_key(end)]):
        out[str(row["day"]) + "T00:00:00Z"] = {"p50": row.get("p50_ms"), "p95": row.get("p95_ms")}
    return out


def active_hashes(r: Any, start: datetime, end: datetime, org: Optional[str] = None) -> Set[str]:
    extra, params = _org_sql(org)
    return {str(row["h"]) for row in r.rows("platform_active_users_daily", "SELECT DISTINCT actor_hash AS h FROM platform_active_users_daily "
                                                                           f"WHERE day >= ? AND day < ?{extra}",
                                            [day_key(start), day_key(end), *params])}


def active_by_day(r: Any, start: datetime, end: datetime, org: Optional[str] = None) -> Dict[str, int]:
    extra, params = _org_sql(org)
    return {str(row["day"]) + "T00:00:00Z": int(row["n"] or 0)
            for row in r.rows("platform_active_users_daily", "SELECT day, COUNT(DISTINCT actor_hash) AS n FROM platform_active_users_daily "
                                                             f"WHERE day >= ? AND day < ?{extra} GROUP BY day",
                              [day_key(start), day_key(end), *params])}


def active_orgs(r: Any, start: datetime, end: datetime) -> Set[str]:
    return {str(row["org"]) for row in r.rows("platform_usage_daily", "SELECT DISTINCT organization_id AS org FROM platform_usage_daily "
                                                                      "WHERE day >= ? AND day < ? AND organization_id <> '' "
                                                                      "AND (logins_success > 0 OR authenticated_requests > 0)",
                                              [day_key(start), day_key(end)])}


def format_current(r: Any) -> bool:
    """True when every rolled day still inside raw retention was rolled by the current ROLLUP_FORMAT."""
    if not r.has("platform_usage_rollup_state", "state_key", "state_value") or not r.has("platform_usage_routes_daily", "path"):
        return False
    row = r.one("platform_usage_rollup_state", "SELECT state_value FROM platform_usage_rollup_state WHERE state_key = ?",
                ["format_version"])
    return str(row.get("state_value") or "") == ROLLUP_FORMAT


def routes(r: Any, start: datetime, end: datetime) -> Dict[str, Dict[str, int]]:
    """{path: {requests, errors (5xx), client_errors (4xx)}} summed over the rolled days in [start, end)."""
    out: Dict[str, Dict[str, int]] = {}
    for row in r.rows("platform_usage_routes_daily", "SELECT path, SUM(requests) AS requests, SUM(server_errors) AS errors, "
                                                     "SUM(client_errors) AS client_errors FROM platform_usage_routes_daily "
                                                     "WHERE day >= ? AND day < ? GROUP BY path", [day_key(start), day_key(end)]):
        out[str(row["path"])] = {k: int(row.get(k) or 0) for k in ("requests", "errors", "client_errors")}
    return out


def hash_all(ids: Iterable[str]) -> Set[str]:
    key = salt()
    return {actor_hash(i, key) for i in ids if i}
