"""Vendor admin portal analytics: KPIs over time, customer 360, feature adoption, search,
notifications and background-job status.

Every number is an aggregate over real rows. Nothing here seeds, estimates or pads:
  * a metric whose source table or column does not exist is reported in ``unavailable``;
  * a value that cannot be known (for example a "previous period" that predates the security
    journal's retention window, or a stock count with no history) is ``None``, never 0;
  * empty time buckets are zero only when the source could have recorded rows for them.

Storage layout. Tables live in one of three homes, mirroring the code that writes them:
  core     db_postgres schema and the platform admin tables  -> Postgres when MORROW_MAIN_DB_BACKEND=postgres
  feature  db_feature_store tables (security journal, feedback, api keys, announcements)
                                                              -> Postgres when the feature store is
  sqlite   service-owned tables that only have a SQLite implementation
With SQLite everything is one file and one (pooled) connection per request.

Timestamps come in four storage formats, handled per column rather than by normalising in SQL
(which would defeat the indexes):
  iso    TEXT 'YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+00:00)'   - most tables
  space  TEXT 'YYYY-MM-DD HH:MM:SS'                        - digest_snapshots.taken_at
  epoch  INTEGER seconds                                   - morrow_users, morrow_refresh_tokens, cbom ingests
  tstz   Postgres TIMESTAMPTZ                              - core tables on Postgres
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

UTC = timezone.utc

RANGES: Dict[str, Tuple[str, int]] = {"24h": ("hour", 24), "7d": ("day", 7), "30d": ("day", 30), "90d": ("day", 90)}
DEFAULT_RANGE = "30d"

CORE_TABLES = frozenset({
    "organizations", "repositories", "assets", "asset_tags", "baselines", "scans", "scan_results", "remediations",
    "migration_tasks", "validation_jobs", "audit_logs", "flight_recorder_events", "github_installations", "webhooks",
    "webhook_events", "collections", "schedules", "event_rules", "event_rule_fires", "github_pr_events",
    "organization_memberships", "platform_admin_events", "platform_autopatches", "platform_feature_flags",
    "platform_customer_notes", "external_findings",
})
FEATURE_TABLES = frozenset({
    "platform_auth_events", "platform_request_events", "feedback", "platform_api_keys", "platform_announcements",
    "platform_maintenance",
    # services/usage_rollups.py: daily summaries that outlive the raw journal rows.
    "platform_usage_daily", "platform_active_users_daily", "platform_usage_rollup_days", "platform_usage_rollup_state",
    "platform_usage_routes_daily",
})
SPACE_FORMAT = frozenset({("digest_snapshots", "taken_at")})

LOGIN_SUCCESS = ("login.success", "saml.success")
LOGIN_FAILURE = ("login.failure", "saml.failure")
CLOSED_REMEDIATION_STATUSES = ("rejected", "verified_closed")  # services/remediation_feed.py
OPEN_FEEDBACK_STATUSES = ("new", "triaged")                      # services/feedback.py STATUSES
PENDING_AUTOPATCH_STATUS = "needs_review"                         # set on create; approve/reject move it on
AI_ASSISTANT_ACTIONS = ("agent.chat", "assistant.chat", "assistant.intent")

_IN_SUCCESS = "('login.success','saml.success')"
_IN_FAILURE = "('login.failure','saml.failure')"


class SourceMissing(Exception):
    """A metric's table or column does not exist in this deployment."""


# ── Small utilities ──────────────────────────────────────────────────────────


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ts(value: Any) -> Optional[datetime]:
    """Any stored timestamp (ISO text, 'YYYY-MM-DD HH:MM:SS', epoch seconds, datetime) -> aware UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return parse_ts(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def ts_iso(value: Any) -> Optional[str]:
    return iso(parse_ts(value))


def delta_pct(value: Optional[float], previous: Optional[float]) -> Optional[float]:
    if value is None or previous is None or float(previous) == 0:
        return None
    return round((float(value) - float(previous)) / float(previous) * 100.0, 1)


def kpi(label: str, source: str, value: Optional[float], previous: Optional[float]) -> Dict[str, Any]:
    return {"value": value, "previous": previous, "delta_pct": delta_pct(value, previous), "label": label, "source": source}


def like_pattern(text: str) -> str:
    escaped = str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _num(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _round(value: Any, places: int = 1) -> Optional[float]:
    if value is None:
        return None
    try:
        return round(float(value), places)
    except (TypeError, ValueError):
        return None


# ── Backends and connections ─────────────────────────────────────────────────


def _pg_main() -> bool:
    from db_postgres import postgres_main_db_requested
    return bool(postgres_main_db_requested())


def _pg_feature() -> bool:
    import db_feature_store as store
    return bool(store.postgres_enabled())


def backend_for(table: str) -> str:
    if table in CORE_TABLES:
        return "pg" if _pg_main() else "sqlite"
    if table in FEATURE_TABLES:
        return "pg" if _pg_feature() else "sqlite"
    return "sqlite"


def sqlite_path() -> str:
    import db
    return os.environ.get("MORROW_SCANNER_DB", db.DB_PATH)


def db_identity() -> str:
    parts = ["sqlite:" + sqlite_path()]
    try:
        if _pg_main() or _pg_feature():
            from db_postgres import product_database_url
            parts.append("pg:" + hashlib.sha256(str(product_database_url()).encode()).hexdigest()[:16])
    except Exception:
        pass
    return "|".join(parts)


_META_LOCK = threading.Lock()
_META: Dict[Tuple[str, str], Tuple[float, Optional[Dict[str, str]]]] = {}


class Reader:
    """Lazily opens at most one connection per backend for the duration of a request. Read-only."""

    def __init__(self) -> None:
        self._sqlite = None
        self._pg_cm = None
        self._pg = None
        self._identity = db_identity()

    def __enter__(self) -> "Reader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._sqlite is not None:
            try:
                self._sqlite.close()
            except Exception:
                pass
            self._sqlite = None
        if self._pg_cm is not None:
            try:
                self._pg.rollback()
            except Exception:
                pass
            try:
                self._pg_cm.__exit__(None, None, None)
            except Exception:
                pass
            self._pg_cm = self._pg = None

    def _conn(self, backend: str):
        if backend == "sqlite":
            if self._sqlite is None:
                from db import get_connection
                self._sqlite = get_connection()
            return self._sqlite
        if self._pg is None:
            from db_postgres import pg_product_conn
            self._pg_cm = pg_product_conn()
            self._pg = self._pg_cm.__enter__()
        return self._pg

    def rows(self, table: str, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        backend = backend_for(table)
        conn = self._conn(backend)
        if backend == "pg":
            cur = conn.cursor()
            try:
                cur.execute(sql.replace("?", "%s"), tuple(params))
                names = [d[0] for d in cur.description]
                return [dict(zip(names, r)) for r in cur.fetchall()]
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                cur.close()
        cur = conn.execute(sql, tuple(params))
        names = [d[0] for d in cur.description]
        return [dict(zip(names, r)) for r in cur.fetchall()]

    def one(self, table: str, sql: str, params: Sequence[Any] = ()) -> Dict[str, Any]:
        found = self.rows(table, sql, params)
        return found[0] if found else {}

    def columns(self, table: str) -> Optional[Dict[str, str]]:
        """{column: declared type (upper case)} or None when the table does not exist."""
        backend = backend_for(table)
        key = (self._identity + "|" + backend, table)
        now = time.monotonic()
        with _META_LOCK:
            hit = _META.get(key)
        if hit and hit[0] > now:
            return hit[1]
        cols: Optional[Dict[str, str]]
        try:
            if backend == "sqlite":
                found = self._conn("sqlite").execute(f"PRAGMA table_info({table})").fetchall()
                cols = {str(r[1]): str(r[2] or "").upper() for r in found} or None
            else:
                found = self.rows(table, "SELECT column_name, data_type FROM information_schema.columns "
                                         "WHERE table_schema = current_schema() AND table_name = ?", (table,))
                cols = {str(r["column_name"]): str(r["data_type"] or "").upper() for r in found} or None
        except Exception:
            cols = None
        with _META_LOCK:
            _META[key] = (now + (300.0 if cols else 30.0), cols)
        return cols

    def has(self, table: str, *columns: str) -> bool:
        cols = self.columns(table)
        return bool(cols) and all(c in cols for c in columns)

    def require(self, table: str, *columns: str) -> None:
        cols = self.columns(table)
        if not cols:
            raise SourceMissing(f"Table {table} does not exist in this deployment.")
        missing = [c for c in columns if c not in cols]
        if missing:
            raise SourceMissing(f"{table} has no {', '.join(missing)} column.")

    def ts_kind(self, table: str, column: str) -> str:
        self.require(table, column)
        declared = (self.columns(table) or {}).get(column, "")
        if (table, column) in SPACE_FORMAT:
            return "space"
        if "WITH TIME ZONE" in declared or declared == "TIMESTAMPTZ":
            return "tstz"
        if "TIMESTAMP" in declared or declared == "DATE":
            return "ts"
        if "INT" in declared:
            return "epoch"
        return "iso"


def clear_meta_cache() -> None:
    with _META_LOCK:
        _META.clear()


def ts_bound(kind: str, dt: datetime) -> Any:
    dt = dt.astimezone(UTC)
    if kind == "epoch":
        return int(dt.timestamp())
    if kind == "space":
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if kind == "tstz":
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def bucket_sql(kind: str, column: str, bucket: str) -> str:
    hour = bucket == "hour"
    if kind == "epoch":
        return f"({column} / {3600 if hour else 86400})"
    pg_fmt = "YYYY-MM-DD\"T\"HH24" if hour else "YYYY-MM-DD"
    if kind == "tstz":
        return f"to_char({column} AT TIME ZONE 'UTC', '{pg_fmt}')"
    if kind == "ts":
        return f"to_char({column}, '{pg_fmt}')"
    return f"SUBSTR({column}, 1, {13 if hour else 10})"


def bucket_label(kind: str, raw: Any, bucket: str) -> Optional[str]:
    if raw is None or raw == "":
        return None
    if kind == "epoch":
        try:
            return iso(datetime.fromtimestamp(int(raw) * (3600 if bucket == "hour" else 86400), tz=UTC))
        except (TypeError, ValueError, OverflowError, OSError):
            return None
    text = str(raw)
    if len(text) < 10:
        return None
    hour = text[11:13] if bucket == "hour" and len(text) >= 13 else "00"
    return f"{text[:10]}T{hour}:00:00Z"


# ── Time windows ─────────────────────────────────────────────────────────────


class Window:
    def __init__(self, range_key: str, now: Optional[datetime] = None) -> None:
        if range_key not in RANGES:
            raise ValueError("range must be one of 24h, 7d, 30d, 90d")
        self.range = range_key
        self.bucket, self.count = RANGES[range_key]
        self.now = (now or now_utc()).astimezone(UTC)
        self.step = timedelta(hours=1) if self.bucket == "hour" else timedelta(days=1)
        floor = self.now.replace(minute=0, second=0, microsecond=0)
        if self.bucket == "day":
            floor = floor.replace(hour=0)
        self.start = floor - self.step * (self.count - 1)
        # Second-granular bounds; +1s so rows written in the current second are included.
        self.end = self.now.replace(microsecond=0) + timedelta(seconds=1)
        self.prev_end = self.start
        self.prev_start = self.start - (self.end - self.start)
        self.starts = [self.start + self.step * i for i in range(self.count)]
        self.labels = [iso(s) for s in self.starts]

    def series(self, data: Dict[str, Dict[str, Any]], fields: Dict[str, Any],
               unknown_before: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Zero-filled (or default-filled) points, oldest first. Buckets that end before
        unknown_before (data outside a retention window) carry None for every field."""
        out = []
        for start, label in zip(self.starts, self.labels):
            point: Dict[str, Any] = {"t": label}
            known = unknown_before is None or start + self.step > unknown_before
            row = data.get(label) or {}
            for name, default in fields.items():
                point[name] = (row.get(name, default) if known else None)
            out.append(point)
        return out


def journal_cutoff(kind: str, now: datetime) -> Optional[datetime]:
    """Oldest instant the security journal still answers for (reads apply the same TTL)."""
    try:
        from services import security_journal
        return now - timedelta(days=int(security_journal._days(kind)))
    except Exception:
        return None


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _where(extra: str) -> str:
    return f" AND ({extra})" if extra else ""


def period_agg(r: Reader, table: str, ts_col: str, start: datetime, end: datetime, exprs: Dict[str, str],
               where: str = "", params: Sequence[Any] = ()) -> Dict[str, Any]:
    kind = r.ts_kind(table, ts_col)
    select = ", ".join(f"{expr} AS {name}" for name, expr in exprs.items())
    sql = f"SELECT {select} FROM {table} WHERE {ts_col} >= ? AND {ts_col} < ?{_where(where)}"
    return r.one(table, sql, [ts_bound(kind, start), ts_bound(kind, end), *params])


def bucket_agg(r: Reader, table: str, ts_col: str, win: Window, exprs: Dict[str, str],
               where: str = "", params: Sequence[Any] = (), ranges: Optional[List[Tuple[datetime, datetime]]] = None
               ) -> Dict[str, Dict[str, Any]]:
    """ranges: read only these [start, end) spans of whole buckets (JournalView.raw_ranges) instead of the window."""
    kind = r.ts_kind(table, ts_col)
    bexpr = bucket_sql(kind, ts_col, win.bucket)
    select = ", ".join(f"{expr} AS {name}" for name, expr in exprs.items())
    sql = (f"SELECT {bexpr} AS b, {select} FROM {table} WHERE {ts_col} >= ? AND {ts_col} < ?{_where(where)} "
           f"GROUP BY {bexpr}")
    out: Dict[str, Dict[str, Any]] = {}
    for lo, hi in (ranges if ranges is not None else [(win.start, win.end)]):
        for row in r.rows(table, sql, [ts_bound(kind, lo), ts_bound(kind, hi), *params]):
            label = bucket_label(kind, row.pop("b"), win.bucket)
            if label:
                out[label] = row
    return out


def count_before(r: Reader, table: str, ts_col: str, before: datetime, where: str = "", params: Sequence[Any] = ()) -> int:
    kind = r.ts_kind(table, ts_col)
    row = r.one(table, f"SELECT COUNT(*) AS n FROM {table} WHERE {ts_col} < ?{_where(where)}",
                [ts_bound(kind, before), *params])
    return _num(row.get("n"))


def count_all(r: Reader, table: str, where: str = "", params: Sequence[Any] = ()) -> int:
    r.require(table)
    row = r.one(table, f"SELECT COUNT(*) AS n FROM {table}{' WHERE ' + where if where else ''}", params)
    return _num(row.get("n"))


def _in_list(values: Iterable[str]) -> str:
    # Only ever called with module constants, never request input.
    return "(" + ",".join("'" + v.replace("'", "''") + "'" for v in values) + ")"


def active_users_sql(org_filter: bool, bucket_expr: Optional[str] = None, who: str = "user") -> str:
    """Distinct users (who="user") or organizations (who="organization") with a successful login or an
    authenticated request, from the security journal. Placeholders: start, end[, org] twice."""
    org_sql = " AND organization_id = ?" if org_filter else ""
    auth_col = "user_id" if who == "user" else "organization_id"
    req_col = "actor_id" if who == "user" else "organization_id"
    b = f"{bucket_expr} AS b, " if bucket_expr else ""
    inner = (
        f"SELECT {b}{auth_col} AS u FROM platform_auth_events WHERE created_at >= ? AND created_at < ? "
        f"AND event_type IN {_IN_SUCCESS} AND {auth_col} <> ''{org_sql} "
        f"UNION ALL "
        f"SELECT {b}{req_col} AS u FROM platform_request_events WHERE created_at >= ? AND created_at < ? "
        f"AND authenticated = 1 AND {req_col} <> ''{org_sql}"
    )
    if bucket_expr:
        return f"SELECT b, COUNT(DISTINCT u) AS value FROM ({inner}) x GROUP BY b"
    return f"SELECT COUNT(DISTINCT u) AS value FROM ({inner}) x"


def active_ids_sql(org_filter: bool, who: str = "user") -> str:
    """The distinct ids behind active_users_sql (same placeholders), for merging with rollup hashes."""
    return active_users_sql(org_filter, who=who).replace("SELECT COUNT(DISTINCT u) AS value FROM", "SELECT DISTINCT u FROM", 1)


# ── Journal metrics beyond raw retention (daily rollups) ─────────────────────
#
# Raw journal rows answer exactly for their retention window. Older closed days are answered from
# services/usage_rollups.py. A period is planned as: whole rolled-up UTC days before the first midnight
# fully inside raw retention, then raw rows from that midnight to the period end. A period start that is
# not a midnight is aligned to the nearest midnight for the rolled-up part (sources say so). If any
# needed day was never rolled up, the period is incomplete: a current period falls back to the raw rows
# it has (flagged by coverage.range_complete = false), a previous period is None.


def _round_day(dt: datetime) -> datetime:
    from services import usage_rollups as ur
    floor = ur.day_floor(dt)
    return floor + timedelta(days=1) if dt - floor >= timedelta(hours=12) else floor


class Plan:
    def __init__(self, raw: Optional[Tuple[datetime, datetime]], days: Optional[Tuple[datetime, datetime]], complete: bool) -> None:
        self.raw, self.days, self.complete = raw, days, complete

    @property
    def uses_rollups(self) -> bool:
        return self.complete and self.days is not None


class FastPlan:
    """A Plan split into raw [start, end) pieces and rolled-up day spans. `retained` is the span of days still
    inside raw retention (read from the rollup instead of raw rows), if any. A current period whose base plan
    is incomplete still answers from what it has, as before; a previous one is unknown."""

    def __init__(self, base: Plan, pieces: List[Tuple[datetime, datetime]], spans: List[Tuple[datetime, datetime]],
                 retained: Optional[Tuple[datetime, datetime]]) -> None:
        self.base, self.pieces, self.spans, self.retained = base, pieces, spans, retained

    @property
    def complete(self) -> bool:
        return self.base.complete


class JournalView:
    """Rollup coverage for one analytics request."""

    def __init__(self, r: Reader, win: Window, c: Collector) -> None:
        from services import usage_rollups as ur
        self.r, self.win, self.ur = r, win, ur
        self.auth_cut = journal_cutoff("auth", win.now)
        self.traffic_cut = journal_cutoff("traffic", win.now)
        cuts = [x for x in (self.auth_cut, self.traffic_cut) if x is not None]
        self.both_cut = max(cuts) if cuts else None
        self.rolled: set = set()
        self.extent: Dict[str, Any] = {"days": 0, "first_day": None, "last_day": None}
        try:
            self.rolled = ur.rolled_days(r, ur.day_floor(win.prev_start) - timedelta(days=1), win.end)
            self.extent = ur.rollup_extent(r)
        except Exception as exc:
            c.missing("usage_rollups", f"Daily rollups could not be read: {exc.__class__.__name__}")

    def plan(self, start: datetime, end: datetime, cut: Optional[datetime]) -> Plan:
        if cut is None or start >= cut:
            return Plan((start, end), None, True)
        boundary = self.ur.day_ceil(cut)
        ds = _round_day(start)
        if end <= boundary:
            de, raw = _round_day(end), None
        else:
            de, raw = boundary, (boundary, end)
        if de <= ds:
            return Plan(raw or (start, end), None, raw is not None)
        day, complete = ds, True
        while day < de:
            if self.ur.day_key(day) not in self.rolled:
                complete = False
                break
            day += timedelta(days=1)
        return Plan(raw, (ds, de), complete)

    # Retained rolled days. A closed UTC day that is rolled up holds exactly what its raw rows say (roll_day reads
    # those rows with the same bounds and the same rules), so with fast = True (the overview) reads take such days
    # from the rollup and scan raw rows only for today and any day not rolled up yet. The result is identical;
    # only the source changes. Off unless every retained rolled day was built by the current rollup format.

    fast = False
    _format_ok: Optional[bool] = None
    _memo: Optional[Dict[Tuple[Any, ...], Any]] = None

    def once(self, key: Tuple[Any, ...], fn: Callable[[], Any]) -> Any:
        """Compute an identical sub-result (for example a rollup sum two metrics need) once per request."""
        if self._memo is None:
            self._memo = {}
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    def sums(self, start: datetime, end: datetime, org: Optional[str]) -> Dict[str, Any]:
        return self.once(("sums", start, end, org), lambda: self.ur.sums(self.r, start, end, org))

    def fast_ok(self) -> bool:
        if not self.fast or not self.rolled or self.both_cut is None:
            return False
        if self._format_ok is None:
            try:
                self._format_ok = bool(self.ur.format_current(self.r))
            except Exception:
                self._format_ok = False
        return self._format_ok

    def retained_floor(self) -> datetime:
        """The first day whose raw rows are still complete in both journals. usage_rollups.run() rolls (and
        re-rolls on a format change) exactly these days, so only they are read from rollups in fast mode."""
        return self.ur.day_ceil(self.both_cut)

    def rolled_run(self, lo: datetime, hi: datetime) -> Optional[Tuple[datetime, datetime]]:
        """The longest run of consecutive rolled-up days inside [day_ceil(lo), hi), or None."""
        day, best, run_start = self.ur.day_ceil(lo), None, None
        while day < hi:
            if self.ur.day_key(day) in self.rolled:
                run_start = run_start or day
                if best is None or day + timedelta(days=1) - run_start > best[1] - best[0]:
                    best = (run_start, day + timedelta(days=1))
            else:
                run_start = None
            day += timedelta(days=1)
        return best

    def fast_plan(self, start: datetime, end: datetime, cut: Optional[datetime]) -> "FastPlan":
        """plan(), with the longest run of retained rolled-up days inside its raw rows read from the rollup.
        A current period plan() calls incomplete reads raw rows for the whole period, so the same split applies."""
        base = self.plan(start, end, cut)
        if not base.complete:
            pieces, spans = [(start, end)], []
        else:
            pieces, spans = ([base.raw] if base.raw else []), ([base.days] if base.days else [])
        run = None
        if pieces and self.fast and self.both_cut is not None:
            lo, hi = pieces[-1]
            floor = max(lo, self.ur.day_ceil(self.both_cut), self.ur.day_ceil(cut) if cut is not None else lo)
            limit = min(self.ur.day_floor(self.win.now), self.ur.day_floor(hi))
            # No whole retained day inside the raw part (the 24h range): nothing to read from a rollup.
            run = self.rolled_run(floor, limit) if floor < limit and self.fast_ok() else None
            if run:
                pieces = pieces[:-1] + [p for p in ((lo, run[0]), (run[1], hi)) if p[1] > p[0]]
                spans = spans + [run]
        return FastPlan(base, pieces, spans, run)

    def _replaced(self, start: datetime, boundary: datetime, fast: bool) -> bool:
        return (start < boundary or (fast and start >= self.retained_floor())) and self.ur.day_key(start) in self.rolled

    def raw_ranges(self, unknown_before: Optional[datetime], cut: Optional[datetime]) -> List[Tuple[datetime, datetime]]:
        """The [start, end) spans whose buckets series(..., cut) takes from raw rows: known buckets
        (see Window.series unknown_before) that are not replaced by a rollup. Contiguous buckets are merged."""
        win = self.win
        if win.bucket != "day" or cut is None or not self.rolled or not self.fast_ok():
            return [(win.start, win.end)]
        boundary, out = self.ur.day_ceil(cut), []
        for start in win.starts:
            known = unknown_before is None or start + win.step > unknown_before
            if not known or self._replaced(start, boundary, True):
                continue
            end = min(start + win.step, win.end)
            if out and out[-1][1] == start:
                out[-1] = (out[-1][0], end)
            else:
                out.append((start, end))
        return out

    def series(self, points: List[Dict[str, Any]], roll: Dict[str, Dict[str, Any]], cut: Optional[datetime],
               fields: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Replace day buckets that raw retention does not fully cover with their rollup, when rolled up (in
        fast mode: every rolled-up day, see fast_plan)."""
        if self.win.bucket != "day" or cut is None or not self.rolled:
            return points
        boundary = self.ur.day_ceil(cut)
        fast = self.fast_ok()
        for point, start in zip(points, self.win.starts):
            if self._replaced(start, boundary, fast):
                row = roll.get(point["t"]) or {}
                for name, default in fields.items():
                    value = row.get(name)
                    point[name] = default if value is None else value
        return points

    def rolled_in(self, start: datetime, end: datetime) -> int:
        day, n = self.ur.day_floor(start), 0
        while day < end:
            n += self.ur.day_key(day) in self.rolled
            day += timedelta(days=1)
        return n


ROLLUP_NOTE = ("; days older than raw retention come from platform_usage_daily (whole UTC days, rolled up from the raw "
               "rows before they expired)")
#: The overview reads retained closed days that are already rolled up from the rollup too (same values, see
#: JournalView.fast_plan). False restores raw-row reads for every retained day.
FAST_OVERVIEW = True


def journal_requests(jv: JournalView, start: datetime, end: datetime, exprs: Dict[str, str], roll_map: Dict[str, Callable[[Dict[str, Any]], int]],
                     org: Optional[str], current: bool) -> Tuple[Optional[Dict[str, Any]], Optional[Plan]]:
    """Request counts for a period. roll_map derives each expr's value from rollup column sums."""
    r = jv.r
    where, params = ("organization_id = ?", [org]) if org is not None else ("", [])
    p = jv.plan(start, end, jv.traffic_cut)
    if not p.complete:
        if not current:
            return None, p
        return period_agg(r, "platform_request_events", "created_at", start, end, exprs, where, params), p
    out: Dict[str, Any] = {name: 0 for name in exprs}
    if p.raw:
        raw = period_agg(r, "platform_request_events", "created_at", p.raw[0], p.raw[1], exprs, where, params)
        out = {name: _num(raw.get(name)) for name in exprs}
    if p.days:
        s = jv.sums(p.days[0], p.days[1], org)
        for name in exprs:
            out[name] += int(roll_map[name](s))
    return out, p


def journal_p95(jv: JournalView, p: Optional[Plan], start: datetime, end: datetime, org: Optional[str] = None) -> Optional[float]:
    """Exact nearest-rank p95 from raw rows; estimated from histogram buckets when rollups are involved."""
    if p is None or not p.complete:
        return None
    if not p.days:
        return latency_stats(jv.r, start, end, org=org)[0]
    ur = jv.ur
    s = jv.sums(p.days[0], p.days[1], org)
    hist = {c: _num(v) for c, v in s.items() if c in ur.LATENCY_COLUMNS}
    max_ms = float(s.get("duration_max_ms") or 0)
    if p.raw:
        where, params = ("organization_id = ?", [org]) if org is not None else ("", [])
        raw = period_agg(jv.r, "platform_request_events", "created_at", p.raw[0], p.raw[1], ur.raw_histogram_exprs(), where, params)
        for column in ur.LATENCY_COLUMNS:
            hist[column] = hist.get(column, 0) + _num(raw.get(column))
        max_ms = max(max_ms, float(raw.get("duration_max_ms") or 0))
    return ur.histogram_percentile(hist, 95, max_ms)


def journal_logins(jv: JournalView, start: datetime, end: datetime, org: Optional[str], current: bool) -> Optional[Dict[str, int]]:
    exprs = {"success": f"SUM(CASE WHEN event_type IN {_IN_SUCCESS} THEN 1 ELSE 0 END)",
             "failed": f"SUM(CASE WHEN event_type IN {_IN_FAILURE} THEN 1 ELSE 0 END)"}
    where, params = ("organization_id = ?", [org]) if org is not None else ("", [])
    p = jv.plan(start, end, jv.auth_cut)
    if not p.complete:
        if not current:
            return None
        row = period_agg(jv.r, "platform_auth_events", "created_at", start, end, exprs, where, params)
        return {"success": _num(row.get("success")), "failed": _num(row.get("failed"))}
    out = {"success": 0, "failed": 0}
    if p.raw:
        row = period_agg(jv.r, "platform_auth_events", "created_at", p.raw[0], p.raw[1], exprs, where, params)
        out = {"success": _num(row.get("success")), "failed": _num(row.get("failed"))}
    if p.days:
        s = jv.sums(p.days[0], p.days[1], org)
        out["success"] += _num(s.get("logins_success"))
        out["failed"] += _num(s.get("logins_failed"))
    return out


def journal_active(jv: JournalView, start: datetime, end: datetime, org: Optional[str], who: str, current: bool) -> Optional[int]:
    """Distinct active users (who="user") or organizations; see active_users_sql for the rule."""
    r = jv.r
    p = jv.plan(start, end, jv.both_cut)
    org_filter = org is not None

    def params(s: datetime, e: datetime) -> List[Any]:
        return ([ts_bound("iso", s), ts_bound("iso", e)] + ([org] if org_filter else [])) * 2

    if not p.uses_rollups:
        if not p.complete and not current:
            return None
        return _num(r.one("platform_auth_events", active_users_sql(org_filter, who=who), params(start, end)).get("value"))
    ids: set = set()
    if p.raw:
        ids = {str(row["u"]) for row in r.rows("platform_auth_events", active_ids_sql(org_filter, who), params(*p.raw)) if row.get("u")}
    if who == "user":
        return len(jv.ur.active_hashes(r, p.days[0], p.days[1], org) | jv.ur.hash_all(ids))
    return len(jv.ur.active_orgs(r, p.days[0], p.days[1]) | ids)


def _active_pairs_sql(select: str) -> str:
    """Platform-wide active users and organizations in one pass (the rule of active_users_sql, with the
    non-empty tests moved into the aggregate). Placeholders: start, end twice."""
    inner = (f"SELECT user_id AS u, organization_id AS o FROM platform_auth_events WHERE created_at >= ? AND created_at < ? "
             f"AND event_type IN {_IN_SUCCESS} UNION ALL "
             f"SELECT actor_id AS u, organization_id AS o FROM platform_request_events WHERE created_at >= ? AND created_at < ? "
             f"AND authenticated = 1")
    return f"SELECT {select} FROM ({inner}) x"


def journal_active_pair(jv: JournalView, start: datetime, end: datetime, current: bool) -> Tuple[Optional[int], Optional[int]]:
    """(journal_active(..., "user"), journal_active(..., "organization")) platform-wide, reading the raw rows once."""
    r = jv.r
    p = jv.fast_plan(start, end, jv.both_cut)
    if not p.complete and not current:
        return None, None

    def params(s: datetime, e: datetime) -> List[Any]:
        return [ts_bound("iso", s), ts_bound("iso", e)] * 2

    if not p.spans:
        lo, hi = p.pieces[0] if p.pieces else (start, end)
        row = r.one("platform_auth_events", _active_pairs_sql("COUNT(DISTINCT CASE WHEN u <> '' THEN u END) AS users, "
                                                              "COUNT(DISTINCT CASE WHEN o <> '' THEN o END) AS orgs"), params(lo, hi))
        return _num(row.get("users")), _num(row.get("orgs"))
    users: set = set()
    orgs: set = set()
    for piece in p.pieces:
        for row in r.rows("platform_auth_events", _active_pairs_sql("DISTINCT u, o"), params(*piece)):
            if row.get("u"):
                users.add(str(row["u"]))
            if row.get("o"):
                orgs.add(str(row["o"]))
    hashes, rolled_orgs = jv.ur.hash_all(users), set(orgs)
    for s, e in p.spans:
        hashes |= jv.ur.active_hashes(r, s, e)
        rolled_orgs |= jv.ur.active_orgs(r, s, e)
    return len(hashes), len(rolled_orgs)


def adjacent_raw(win: Window, cur: FastPlan, prev: FastPlan) -> bool:
    """Both periods are answered from raw rows alone and meet at win.start (the 24h range)."""
    return (cur.complete and prev.complete and not cur.spans and not prev.spans and win.prev_end == win.start
            and cur.pieces == [(win.start, win.end)] and prev.pieces == [(win.prev_start, win.prev_end)])


def bucket_sum(win: Window, data: Dict[str, Dict[str, int]], ranges: List[Tuple[datetime, datetime]]
               ) -> Callable[[datetime, datetime], Optional[Dict[str, int]]]:
    """raw_sum for journal_counts: a [lo, hi) of whole buckets inside the ranges `data` was read over is the sum of
    those buckets (bucket_agg's bounds and GROUP BY partition the same rows)."""
    def answer(lo: datetime, hi: datetime) -> Optional[Dict[str, int]]:
        lo_label = iso(lo)
        hi_label = None if hi == win.end else iso(hi)
        if lo_label not in win.labels or (hi_label is not None and hi_label not in win.labels):
            return None
        if not any(a <= lo and hi <= b for a, b in ranges):
            return None
        out: Dict[str, int] = {}
        for label, row in data.items():
            if label >= lo_label and (hi_label is None or label < hi_label):
                for name, value in row.items():
                    out[name] = out.get(name, 0) + _num(value)
        return out
    return answer


def journal_counts(jv: JournalView, p: FastPlan, table: str, exprs: Dict[str, str], roll_map: Dict[str, Callable[[Dict[str, Any]], int]],
                   current: bool, raw_sum: Optional[Callable[[datetime, datetime], Optional[Dict[str, int]]]] = None
                   ) -> Optional[Dict[str, int]]:
    """Platform-wide journal counts for a FastPlan: raw pieces plus rollup sums. raw_sum(lo, hi) may answer a
    piece from rows already read (None: query it)."""
    if not p.complete and not current:
        return None
    out = {name: 0 for name in exprs}
    for lo, hi in p.pieces:
        row = raw_sum(lo, hi) if raw_sum else None
        if row is None:
            row = period_agg(jv.r, table, "created_at", lo, hi, exprs)
        for name in exprs:
            out[name] += _num(row.get(name))
    for s, e in p.spans:
        sums = jv.sums(s, e, None)
        for name in exprs:
            out[name] += int(roll_map[name](sums))
    return out


def journal_p95_fast(jv: JournalView, p: FastPlan, start: datetime, end: datetime, current: bool) -> Optional[float]:
    """journal_p95 for a FastPlan. A period the base plan answers from raw rows alone keeps the exact nearest-rank
    p95: the histogram of the retained rolled-up days plus the raw pieces locates the latency bucket holding the
    rank, and only that bucket's durations are read and ranked (a count mismatch falls back to reading them all).
    A period whose base plan needs rolled-up days beyond raw retention is estimated from the histogram, as before."""
    if not p.complete and not current:
        return None
    if not p.spans or (not p.base.uses_rollups and backend_for("platform_request_events") == "pg"):
        return latency_stats(jv.r, start, end)[0]
    ur = jv.ur
    hist: Dict[str, int] = {column: 0 for column in ur.LATENCY_COLUMNS}
    max_ms = 0.0
    for s, e in p.spans:
        sums = jv.sums(s, e, None)
        for column in ur.LATENCY_COLUMNS:
            hist[column] += _num(sums.get(column))
        max_ms = max(max_ms, float(sums.get("duration_max_ms") or 0))
    for lo, hi in p.pieces:
        raw = period_agg(jv.r, "platform_request_events", "created_at", lo, hi, ur.raw_histogram_exprs())
        for column in ur.LATENCY_COLUMNS:
            hist[column] += _num(raw.get(column))
        max_ms = max(max_ms, float(raw.get("duration_max_ms") or 0))
    if p.base.uses_rollups:
        return ur.histogram_percentile(hist, 95, max_ms)
    total = sum(hist.values())
    if total <= 0:
        return None
    rank, seen = max(1, (total * 95 + 99) // 100), 0
    for i, column in enumerate(ur.LATENCY_COLUMNS):
        n = hist[column]
        if n and seen + n >= rank:
            lower = ur.LATENCY_BOUNDS[i - 1] if i > 0 else None
            upper = ur.LATENCY_BOUNDS[i] if i < len(ur.LATENCY_BOUNDS) else None
            cond = " AND ".join(c for c in ((f"duration_ms > {lower}" if lower is not None else ""),
                                            (f"duration_ms <= {upper}" if upper is not None else "")) if c)
            found = jv.r.rows("platform_request_events", "SELECT duration_ms AS d FROM platform_request_events "
                                                         f"WHERE created_at >= ? AND created_at < ? AND {cond}",
                              [ts_bound("iso", start), ts_bound("iso", end)])
            values = sorted(float(row["d"]) for row in found if row.get("d") is not None)
            if len(values) != n:
                break
            return _round(values[rank - seen - 1], 1)
        seen += n
    return latency_stats(jv.r, start, end)[0]


class Collector:
    """Accumulates sources/unavailable while metrics are computed; one failure never sinks the rest."""

    def __init__(self) -> None:
        self.sources: Dict[str, str] = {}
        self.unavailable: List[Dict[str, str]] = []

    def missing(self, metric: str, reason: str) -> None:
        if not any(u["metric"] == metric for u in self.unavailable):
            self.unavailable.append({"metric": metric, "reason": reason})

    def run(self, metric: str, fn: Callable[[], Any], default: Any = None) -> Any:
        try:
            return fn()
        except SourceMissing as exc:
            self.missing(metric, str(exc))
        except Exception as exc:  # a broken query must surface as unavailable, not as a 500 or a zero
            self.missing(metric, f"Query failed: {exc.__class__.__name__}")
        return default


# ── TTL cache ────────────────────────────────────────────────────────────────

_CACHE_LOCK = threading.Lock()
_CACHE: Dict[Tuple[Any, ...], Tuple[float, Any]] = {}


def cached(key: Tuple[Any, ...], ttl: float, fn: Callable[[], Any]) -> Any:
    full = (db_identity(),) + tuple(key)
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _CACHE.get(full)
        if hit and hit[0] > now:
            return hit[1]
    value = fn()
    if value is None:
        return None  # never cache "not found": the record may be created a moment later
    with _CACHE_LOCK:
        if len(_CACHE) > 512:
            for k in [k for k, v in _CACHE.items() if v[0] <= now]:
                _CACHE.pop(k, None)
        _CACHE[full] = (now + ttl, value)
    return value


def clear_cache() -> None:
    """Forget every cached answer, including the stored overview snapshots.

    This is the "the rows underneath may have changed" signal: an operator forcing a refresh, and
    every test that seeds rows and then asks for the numbers. A stored snapshot has to go with the
    in-process cache, or the next read would serve figures computed before the change.
    """
    global _CACHE_GEN
    with _CACHE_LOCK:
        _CACHE.clear()
        _CACHE_GEN += 1
    clear_meta_cache()
    try:
        from services import analytics_snapshots
        analytics_snapshots.invalidate()
    except Exception:
        pass


# The overview is served from a stored snapshot (services/analytics_snapshots), refreshed on a
# schedule by the API lifespan. WARM_ENABLED stays as the switch that says "this process runs
# background work"; tests and scripts leave it off and compute on demand.
#
# What was here before was a thread that recomputed every range "past half its TTL" after each
# request. Against a 20-second TTL and a computation that took 30-250 seconds, every range was
# permanently past half its TTL, so one page view started a thread that looped over four
# multi-minute aggregations forever, each holding a pooled database connection.
WARM_ENABLED = False
_CACHE_GEN = 0


def warm_overviews(ttl: float = 0.0) -> bool:
    """Ask the snapshot refresher for any range that is past its refresh interval.

    Rate-limited and serialized inside services/analytics_snapshots: at most one refresh thread in
    this process, and at most one refresh per range per interval.
    """
    if not WARM_ENABLED:
        return False
    try:
        from services import analytics_snapshots
    except Exception:
        return False
    started = False
    for key in RANGES:
        snapshot = analytics_snapshots.read(key)
        if snapshot is None or analytics_snapshots._age_seconds(snapshot) >= analytics_snapshots.interval_seconds():
            started = analytics_snapshots.request_refresh(key) or started
    return started


# ── Indexes ──────────────────────────────────────────────────────────────────

ANALYTICS_INDEXES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    ("idx_pa_scans_created", "scans", ("created_at",)),
    ("idx_pa_scans_org_created", "scans", ("organization_id", "created_at")),
    ("idx_pa_audit_logs_org_created", "audit_logs", ("organization_id", "created_at")),
    ("idx_pa_login_events_org_created", "login_events", ("organization_id", "created_at")),
    ("idx_pa_organizations_created", "organizations", ("created_at",)),
    ("idx_pa_remediations_created", "remediations", ("created_at",)),
    ("idx_pa_feedback_created", "feedback", ("created_at",)),
    ("idx_pa_pq_users_created", "morrow_users", ("created_at",)),
    ("idx_pa_pq_users_org", "morrow_users", ("org_id",)),
    ("idx_pa_refresh_tokens_user", "morrow_refresh_tokens", ("user_id", "expires_at")),
    ("idx_pa_cbom_ingests_org_created", "cbom_webhook_ingests", ("org_id", "created_at")),
    ("idx_pa_mobile_iot_org_created", "mobile_iot_scans", ("organization_id", "created_at")),
    ("idx_pa_hndl_tokens_created", "hndl_canary_tokens", ("created_at",)),
    ("idx_pa_vendor_invites_created", "vendor_attestation_invites", ("created_at",)),
    ("idx_pa_github_pr_events_created", "github_pr_events", ("created_at",)),
    ("idx_pa_sbom_imports_imported", "sbom_imports", ("imported_at",)),
    ("idx_pa_webhook_deliveries_created", "morrow_webhook_deliveries", ("created_at",)),
    ("idx_pa_sla_breaches_status", "sla_breaches", ("status",)),
    ("idx_pa_digest_snapshots_taken", "digest_snapshots", ("taken_at",)),
    ("idx_pa_api_keys_expires", "platform_api_keys", ("expires_at",)),
    # Covering index for the request-journal aggregates and percentiles: the time-range scans never
    # touch the (wide) table rows.
    ("idx_pa_request_events_cover", "platform_request_events",
     ("created_at", "status_code", "duration_ms", "organization_id", "authenticated", "actor_id", "path")),
    ("idx_pa_audit_logs_action_org_created", "audit_logs", ("action", "organization_id", "created_at")),
)

#: The columns search() puts a leading-wildcard LIKE on. `LIKE '%text%'` cannot use a b-tree index
#: -- it is unindexable by construction -- so on Postgres each of these gets a trigram GIN index,
#: on the exact expression the predicate uses. On a 200,000-row table that took a term matching
#: nothing from a 232 ms sequential scan to under a millisecond. Where pg_trgm is unavailable (no
#: extension, or a role without rights to create it) the index is skipped and the scan stands;
#: search still answers, just linearly in the size of the table.
SEARCH_TRIGRAM_COLUMNS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("organizations", ("id", "name")),
    ("organization_memberships", ("email", "display_name", "user_id")),
    ("platform_api_keys", ("name", "prefix", "id")),
    ("platform_announcements", ("title", "body")),
    ("platform_autopatches", ("title", "repo_full_name", "issue_type")),
    ("feedback", ("message", "email", "category")),
    ("morrow_users", ("email", "full_name", "id")),
)

_INDEXES_READY: set = set()
_INDEX_LOCK = threading.Lock()


def ensure_indexes() -> None:
    """Create the timestamp indexes the analytics queries filter on, once per database per process.

    Runs before the first analytics read of a database, never per request. Tables that do not exist
    yet are skipped (and retried by the next process). On Postgres the statements need DDL rights; a
    least-privilege runtime role skips them and the migration role applies them through
    db_postgres.apply_deferred_schemas().
    """
    identity = db_identity()
    memo_key = "platform_analytics_indexes"
    try:
        from db import mark_schema_ensured, schema_ensured
        if schema_ensured(memo_key):
            return
    except Exception:
        schema_ensured = mark_schema_ensured = None  # type: ignore
    if identity in _INDEXES_READY:
        return
    with _INDEX_LOCK:
        if identity in _INDEXES_READY:
            return
        apply_indexes()
        _INDEXES_READY.add(identity)
        if mark_schema_ensured:
            try:
                mark_schema_ensured(memo_key)
            except Exception:
                pass


def apply_indexes(pg_only: bool = False) -> Dict[str, Any]:
    """pg_only: the Postgres migration hook, which must not open (or create) a SQLite file."""
    applied, skipped = [], []
    with Reader() as r:
        def run(name: str, table: str, sql: str) -> None:
            backend = backend_for(table)
            try:
                conn = r._conn(backend)
                if backend == "pg":
                    with conn.cursor() as cur:
                        cur.execute(sql)
                    conn.commit()
                else:
                    conn.execute(sql)
                    conn.commit()
                applied.append(name)
            except Exception:
                skipped.append(name)
                if backend == "pg":
                    try:
                        conn.rollback()
                    except Exception:
                        pass

        for name, table, cols in ANALYTICS_INDEXES:
            if pg_only and backend_for(table) != "pg":
                continue
            if not r.has(table, *cols):
                skipped.append(name)
                continue
            run(name, table, f"CREATE INDEX IF NOT EXISTS {name} ON {table}({', '.join(cols)})")

        # Trigram indexes for the global search. Postgres only: SQLite has no equivalent, so there
        # the LIKE scan stands and the endpoint's cache is what bounds repeat cost.
        pg_search = [(t, c) for t, c in SEARCH_TRIGRAM_COLUMNS if backend_for(t) == "pg"]
        trgm = False
        if pg_search:
            try:
                conn = r._conn("pg")
                with conn.cursor() as cur:
                    cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
                conn.commit()
                trgm = True
            except Exception:
                # pg_trgm is "trusted" from Postgres 13, so a database owner can create it; a
                # least-privilege role that cannot simply goes without the index.
                skipped.append("pg_trgm")
                try:
                    r._conn("pg").rollback()
                except Exception:
                    pass
        if trgm:
            for table, cols in pg_search:
                built = False
                for col in cols:
                    if not r.has(table, col):
                        skipped.append(f"idx_trgm_{table}_{col}")
                        continue
                    before = len(applied)
                    run(f"idx_trgm_{table}_{col}", table,
                        f"CREATE INDEX IF NOT EXISTS idx_trgm_{table}_{col} ON {table} "
                        f"USING gin (LOWER(CAST({col} AS TEXT)) gin_trgm_ops)")
                    built = built or len(applied) > before
                if built:
                    # An expression index has no statistics until the table is analysed, and
                    # without them the planner picks the trigram scan even for a term that matches
                    # most of the table -- where the old sequential scan stopped at LIMIT and was
                    # twenty times faster. Measured: a common term went 10 ms -> 187 ms before this
                    # ANALYZE and back to 9 ms after it.
                    run(f"analyze_{table}", table, f"ANALYZE {table}")
    return {"applied": applied, "skipped": skipped}


# ── 1) Overview ──────────────────────────────────────────────────────────────


def flush_journal() -> None:
    """Write queued request events before reading them; the traffic journal batches writes every ~0.25 s,
    so without this the newest requests are missing from counts computed right after them."""
    try:
        from services import security_journal
        security_journal.flush_pending()
    except Exception:
        pass


#: Every KPI the overview answers with, and its label. overview() fills in the ones it could not
#: measure; services/analytics_snapshots builds the same set for a range whose first snapshot is
#: still being computed, so the response contract is identical either way.
OVERVIEW_KPI_LABELS: Tuple[Tuple[str, str], ...] = (
    ("organizations", "Organizations"), ("new_organizations", "New organizations"),
    ("active_organizations", "Active organizations"), ("users", "Users"), ("new_users", "New users"),
    ("active_users", "Active users"), ("logins", "Successful logins"), ("failed_logins", "Failed logins"),
    ("scans", "Scans"), ("assets", "Assets"), ("open_remediations", "Open remediations"),
    ("api_requests", "API requests"), ("error_rate_pct", "Server error rate (5xx) %"),
    ("p95_latency_ms", "p95 latency (ms)"), ("rate_limited_requests", "Rate-limited requests (429)"),
    ("open_feedback", "Open feedback"), ("pending_autopatches", "Autopatches awaiting approval"),
    ("active_api_keys", "Active API keys"), ("active_sessions", "Active sessions"),
    ("admin_actions", "Admin actions"),
)


def overview(range_key: str) -> Dict[str, Any]:
    flush_journal()
    win = Window(range_key)
    c = Collector()
    k: Dict[str, Dict[str, Any]] = {}
    series: Dict[str, List[Dict[str, Any]]] = {}
    top: Dict[str, Any] = {}
    auth_cut = journal_cutoff("auth", win.now)
    traffic_cut = journal_cutoff("traffic", win.now)

    with Reader() as r:
        # Organizations
        def orgs():
            total = count_all(r, "organizations")
            prev = count_before(r, "organizations", "created_at", win.start)
            new = period_agg(r, "organizations", "created_at", win.start, win.end, {"n": "COUNT(*)"})
            new_prev = period_agg(r, "organizations", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"})
            k["organizations"] = kpi("Organizations", "organizations.id", total, prev)
            k["new_organizations"] = kpi("New organizations", "organizations.created_at", _num(new.get("n")), _num(new_prev.get("n")))
            c.sources["organizations"] = "organizations.id (all rows; previous = created_at before range start)"
            c.sources["new_organizations"] = "organizations.created_at"
        c.run("organizations", orgs)

        def users():
            total = count_all(r, "morrow_users")
            prev = count_before(r, "morrow_users", "created_at", win.start)
            new = period_agg(r, "morrow_users", "created_at", win.start, win.end, {"n": "COUNT(*)"})
            new_prev = period_agg(r, "morrow_users", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"})
            k["users"] = kpi("Users", "morrow_users.id", total, prev)
            k["new_users"] = kpi("New users", "morrow_users.created_at", _num(new.get("n")), _num(new_prev.get("n")))
            c.sources["users"] = "morrow_users.id (sign-in accounts; previous = created_at before range start)"
            c.sources["new_users"] = "morrow_users.created_at"
        c.run("users", users)

        def signups():
            org_b = c.run("signups.organizations",
                          lambda: bucket_agg(r, "organizations", "created_at", win, {"organizations": "COUNT(*)"}), None)
            usr_b = c.run("signups.users", lambda: bucket_agg(r, "morrow_users", "created_at", win, {"users": "COUNT(*)"}), None)
            merged: Dict[str, Dict[str, Any]] = {}
            for data in (org_b or {}, usr_b or {}):
                for label, row in data.items():
                    merged.setdefault(label, {}).update(row)
            points = win.series(merged, {"organizations": 0, "users": 0})
            if org_b is None or usr_b is None:
                for p in points:
                    if org_b is None:
                        p["organizations"] = None
                    if usr_b is None:
                        p["users"] = None
            series["signups"] = points
            c.sources["signups"] = "organizations.created_at, morrow_users.created_at"
        signups()

        jv = JournalView(r, win, c)
        jv.fast = FAST_OVERVIEW

        # Activity (security journal)
        def active():
            r.require("platform_auth_events", "user_id", "event_type", "created_at")
            r.require("platform_request_events", "actor_id", "authenticated", "created_at")
            value, ovalue = journal_active_pair(jv, win.start, win.end, True)
            previous, oprev = journal_active_pair(jv, win.prev_start, win.prev_end, False)
            if previous is None:
                c.missing("active_users.previous", "The previous period predates the security journal retention window "
                                                   "and is not covered by daily usage rollups.")
            k["active_users"] = kpi("Active users", "platform_auth_events.user_id + platform_request_events.actor_id", value, previous)
            k["active_organizations"] = kpi("Active organizations",
                                            "platform_auth_events.organization_id + platform_request_events.organization_id",
                                            ovalue, oprev)
            bexpr = bucket_sql("iso", "created_at", win.bucket)
            data = {}
            for lo, hi in jv.raw_ranges(auth_cut, jv.both_cut):
                for row in r.rows("platform_auth_events", active_users_sql(False, bexpr), [ts_bound("iso", lo), ts_bound("iso", hi)] * 2):
                    label = bucket_label("iso", row["b"], win.bucket)
                    if label:
                        data[label] = {"value": _num(row["value"])}
            points = win.series(data, {"value": 0}, unknown_before=auth_cut)
            roll = {label: {"value": n} for label, n in jv.ur.active_by_day(r, win.start, win.end).items()} if jv.rolled else {}
            series["active_users"] = jv.series(points, roll, jv.both_cut, {"value": 0})
            c.sources["active_users"] = ("distinct platform_auth_events.user_id with event_type in (login.success, saml.success) "
                                         "UNION platform_request_events.actor_id with authenticated = 1"
                                         + ROLLUP_NOTE.replace("platform_usage_daily", "platform_active_users_daily (salted actor hashes)"))
            c.sources["active_organizations"] = "same rule as active_users, by organization_id"
        c.run("active_users", active)
        if "active_users" not in series:
            series["active_users"] = win.series({}, {"value": None})

        def logins():
            exprs = {"success": f"SUM(CASE WHEN event_type IN {_IN_SUCCESS} THEN 1 ELSE 0 END)",
                     "failed": f"SUM(CASE WHEN event_type IN {_IN_FAILURE} THEN 1 ELSE 0 END)"}
            roll_map = {"success": lambda s: _num(s.get("logins_success")), "failed": lambda s: _num(s.get("logins_failed"))}
            ranges = jv.raw_ranges(auth_cut, auth_cut)
            data = bucket_agg(r, "platform_auth_events", "created_at", win, exprs, ranges=ranges)
            data = {label: {"success": _num(v.get("success")), "failed": _num(v.get("failed"))} for label, v in data.items()}
            cur = journal_counts(jv, jv.fast_plan(win.start, win.end, auth_cut), "platform_auth_events", exprs, roll_map, True,
                                 bucket_sum(win, data, ranges)) or {}
            prev = journal_counts(jv, jv.fast_plan(win.prev_start, win.prev_end, auth_cut), "platform_auth_events", exprs, roll_map, False)
            prev_known = prev is not None
            prev = prev or {}
            if not prev_known:
                c.missing("logins.previous", "The previous period predates the security journal retention window "
                                             "and is not covered by daily usage rollups.")
            k["logins"] = kpi("Successful logins", "platform_auth_events.event_type", _num(cur.get("success")),
                              _num(prev.get("success")) if prev_known else None)
            k["failed_logins"] = kpi("Failed logins", "platform_auth_events.event_type", _num(cur.get("failed")),
                                     _num(prev.get("failed")) if prev_known else None)
            points = win.series(data, {"success": 0, "failed": 0}, unknown_before=auth_cut)
            day_rolls = jv.once(("by_day",), lambda: jv.ur.by_day(r, win.start, win.end)) if jv.rolled else {}
            roll = {label: {"success": _num(v.get("logins_success")), "failed": _num(v.get("logins_failed"))} for label, v in day_rolls.items()}
            series["logins"] = jv.series(points, roll, auth_cut, {"success": 0, "failed": 0})
            c.sources["logins"] = "platform_auth_events.event_type in (login.success, saml.success)" + ROLLUP_NOTE
            c.sources["failed_logins"] = "platform_auth_events.event_type in (login.failure, saml.failure)"
        c.run("logins", logins)
        series.setdefault("logins", win.series({}, {"success": None, "failed": None}))

        def scans():
            cur = period_agg(r, "scans", "created_at", win.start, win.end, {"n": "COUNT(*)"})
            prev = period_agg(r, "scans", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"})
            k["scans"] = kpi("Scans", "scans.created_at", _num(cur.get("n")), _num(prev.get("n")))
            data = bucket_agg(r, "scans", "created_at", win, {"value": "COUNT(*)"})
            series["scans"] = win.series({label: {"value": _num(v["value"])} for label, v in data.items()}, {"value": 0})
            c.sources["scans"] = "scans.created_at"
        c.run("scans", scans)
        series.setdefault("scans", win.series({}, {"value": None}))

        def assets():
            k["assets"] = kpi("Assets", "assets.asset_key", count_all(r, "assets"), None)
            c.sources["assets"] = "assets.asset_key (current inventory)"
            c.missing("assets.previous", "assets has no created_at column, so the inventory size at the start of the range is not recorded.")
        c.run("assets", assets)

        def remediations():
            n = count_all(r, "remediations", f"status NOT IN {_in_list(CLOSED_REMEDIATION_STATUSES)}")
            k["open_remediations"] = kpi("Open remediations", "remediations.status", n, None)
            c.sources["open_remediations"] = "remediations.status not in (rejected, verified_closed)"
            c.missing("open_remediations.previous", "Remediation status history is not stored, so the open count at the start of the range is unknown.")
        c.run("open_remediations", remediations)

        def requests_block():
            r.require("platform_request_events", "status_code", "duration_ms", "path", "created_at")
            exprs = {"total": "COUNT(*)",
                     "client_errors": "SUM(CASE WHEN status_code >= 400 AND status_code < 500 AND status_code <> 429 THEN 1 ELSE 0 END)",
                     "server_errors": "SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END)",
                     "rate_limited": "SUM(CASE WHEN status_code = 429 THEN 1 ELSE 0 END)"}
            roll_map = {"total": lambda s: _num(s.get("requests")), "client_errors": lambda s: _num(s.get("client_errors")),
                        "server_errors": lambda s: _num(s.get("server_errors")), "rate_limited": lambda s: _num(s.get("rate_limited"))}
            # One bucketed read of the raw spans the series needs; the current-period counts are summed from it
            # when its raw part is covered by those spans (always for 24h; today for rolled-up day ranges).
            req_ranges = jv.raw_ranges(traffic_cut, traffic_cut)
            cur_plan = jv.fast_plan(win.start, win.end, traffic_cut)
            prev_plan = jv.fast_plan(win.prev_start, win.prev_end, traffic_cut)
            # 24h: both periods are plain raw rows back to back, so one bucketed read covers both (the previous
            # period is the buckets before win.start, which is a bucket boundary).
            joint = req_ranges == [(win.start, win.end)] and adjacent_raw(win, cur_plan, prev_plan)
            data = bucket_agg(r, "platform_request_events", "created_at", win, exprs,
                              ranges=[(win.prev_start, win.end)] if joint else req_ranges)
            data = {label: {n: _num(v.get(n)) for n in exprs} for label, v in data.items()}
            prev_sum = None
            if joint:
                split = iso(win.start)
                prev_sum = {n: sum(v[n] for label, v in data.items() if label < split) for n in exprs}
                data = {label: v for label, v in data.items() if label >= split}
            cur = journal_counts(jv, cur_plan, "platform_request_events", exprs, roll_map, True, bucket_sum(win, data, req_ranges)) or {}
            prev = journal_counts(jv, prev_plan, "platform_request_events", exprs, roll_map, False,
                                  (lambda lo, hi: prev_sum) if joint else None)
            prev_known = prev is not None
            prev = prev or {}
            if not prev_known:
                c.missing("api_requests.previous", "The previous period predates the request journal retention window "
                                                   "(MORROW_TRAFFIC_RETENTION_DAYS) and is not covered by daily usage rollups, "
                                                   "so previous request metrics are unknown.")
            total, ptotal = _num(cur.get("total")), (_num(prev.get("total")) if prev_known else None)
            err = (round(_num(cur.get("server_errors")) * 100.0 / total, 2) if total else None)
            perr = (round(_num(prev.get("server_errors")) * 100.0 / ptotal, 2) if ptotal else None)
            k["api_requests"] = kpi("API requests", "platform_request_events.id", total, ptotal)
            k["error_rate_pct"] = kpi("Server error rate (5xx) %", "platform_request_events.status_code", err, perr)
            k["rate_limited_requests"] = kpi("Rate-limited requests (429)", "platform_request_events.status_code",
                                             _num(cur.get("rate_limited")), _num(prev.get("rate_limited")) if prev_known else None)
            lat_buckets: Dict[str, Dict[str, Any]] = {}
            if joint:
                pp95, p95, lat_buckets = latency_stats_split(r, win.prev_start, win.start, win.end, win.bucket)
            else:
                if req_ranges == [(win.start, win.end)] and not cur_plan.spans:
                    p95, lat_buckets = latency_stats(r, win.start, win.end, win.bucket)  # exact p95 and buckets in one read
                else:
                    for lo, hi in req_ranges:
                        lat_buckets.update(latency_stats(r, lo, hi, win.bucket)[1])
                    p95 = journal_p95_fast(jv, cur_plan, win.start, win.end, True)
                pp95 = journal_p95_fast(jv, prev_plan, win.prev_start, win.prev_end, False) if prev_known else None
            k["p95_latency_ms"] = kpi("p95 latency (ms)", "platform_request_events.duration_ms", p95, pp95)
            req_fields = {"total": 0, "client_errors": 0, "server_errors": 0, "rate_limited": 0}
            points = win.series(data, req_fields, unknown_before=traffic_cut)
            day_rolls = jv.once(("by_day",), lambda: jv.ur.by_day(r, win.start, win.end)) if jv.rolled else {}
            roll = {label: {n: fn(v) for n, fn in roll_map.items()} for label, v in day_rolls.items()}
            series["requests"] = jv.series(points, roll, traffic_cut, req_fields)
            lat_points = win.series(lat_buckets, {"p50": None, "p95": None}, unknown_before=traffic_cut)
            lat_roll = jv.ur.day_latency(r, win.start, win.end) if jv.rolled else {}
            series["latency"] = jv.series(lat_points, lat_roll, traffic_cut, {"p50": None, "p95": None})
            top["routes_by_errors"] = routes_by_errors(jv)
            c.sources.update({
                "api_requests": "platform_request_events.id" + ROLLUP_NOTE,
                "error_rate_pct": "platform_request_events.status_code >= 500 / all requests" + ROLLUP_NOTE,
                "rate_limited_requests": "platform_request_events.status_code = 429" + ROLLUP_NOTE,
                "p95_latency_ms": ("platform_request_events.duration_ms (nearest-rank p95; percentile_disc on Postgres). A period "
                                   "that needs rolled-up days is estimated from the platform_usage_daily latency histogram "
                                   "(linear within buckets bounded at 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 ms)"),
                "requests": "platform_request_events.status_code (client_errors = 4xx except 429)" + ROLLUP_NOTE,
                "latency": ("platform_request_events.duration_ms (nearest-rank p50/p95 per bucket); rolled-up days use the exact "
                            "platform-wide p50/p95 stored in platform_usage_rollup_days"),
                "routes_by_errors": "platform_request_events.path, status_code >= 500",
            })
        c.run("api_requests", requests_block)
        series.setdefault("requests", win.series({}, {"total": None, "client_errors": None, "server_errors": None, "rate_limited": None}))
        series.setdefault("latency", win.series({}, {"p50": None, "p95": None}))
        top.setdefault("routes_by_errors", [])

        def feedback():
            n = count_all(r, "feedback", f"status IN {_in_list(OPEN_FEEDBACK_STATUSES)}")
            k["open_feedback"] = kpi("Open feedback", "feedback.status", n, None)
            c.missing("open_feedback.previous", "Feedback status history is not stored, so the open count at the start of the range is unknown.")
            data = bucket_agg(r, "feedback", "created_at", win, {"value": "COUNT(*)"})
            series["feedback"] = win.series({label: {"value": _num(v["value"])} for label, v in data.items()}, {"value": 0})
            c.sources["open_feedback"] = "feedback.status in (new, triaged)"
            c.sources["feedback"] = "feedback.created_at"
        c.run("open_feedback", feedback)
        series.setdefault("feedback", win.series({}, {"value": None}))

        def autopatches():
            n = count_all(r, "platform_autopatches", "status = ?", [PENDING_AUTOPATCH_STATUS])
            k["pending_autopatches"] = kpi("Autopatches awaiting approval", "platform_autopatches.status", n, None)
            c.sources["pending_autopatches"] = "platform_autopatches.status = needs_review"
            c.missing("pending_autopatches.previous", "Autopatch status history is not stored.")
        c.run("pending_autopatches", autopatches)

        def api_keys():
            r.require("platform_api_keys", "created_at", "expires_at", "revoked_at")
            now_b = ts_bound("iso", win.now)
            n = count_all(r, "platform_api_keys",
                          "(revoked_at IS NULL OR revoked_at = '') AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?)", [now_b])
            s_b = ts_bound("iso", win.start)
            prev = count_all(r, "platform_api_keys",
                             "created_at < ? AND (revoked_at IS NULL OR revoked_at = '' OR revoked_at >= ?) "
                             "AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?)", [s_b, s_b, s_b])
            k["active_api_keys"] = kpi("Active API keys", "platform_api_keys.revoked_at, expires_at", n, prev)
            c.sources["active_api_keys"] = "platform_api_keys not revoked and not expired (previous: as of range start)"
        c.run("active_api_keys", api_keys)

        def sessions():
            r.require("morrow_refresh_tokens", "expires_at")
            n = count_all(r, "morrow_refresh_tokens", "expires_at > ?", [int(win.now.timestamp())])
            k["active_sessions"] = kpi("Active sessions", "morrow_refresh_tokens.expires_at", n, None)
            c.sources["active_sessions"] = "morrow_refresh_tokens with expires_at in the future (built-in issuer sessions)"
            c.missing("active_sessions.previous", "Revoked and expired refresh sessions are deleted, so the count at the start of the range cannot be reconstructed.")
        c.run("active_sessions", sessions)

        def admin_actions():
            cur = period_agg(r, "platform_admin_events", "created_at", win.start, win.end, {"n": "COUNT(*)"})
            prev = period_agg(r, "platform_admin_events", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"})
            k["admin_actions"] = kpi("Admin actions", "platform_admin_events.id", _num(cur.get("n")), _num(prev.get("n")))
            data = bucket_agg(r, "platform_admin_events", "created_at", win, {"value": "COUNT(*)"})
            series["admin_actions"] = win.series({label: {"value": _num(v["value"])} for label, v in data.items()}, {"value": 0})
            c.sources["admin_actions"] = "platform_admin_events.created_at"
        c.run("admin_actions", admin_actions)
        series.setdefault("admin_actions", win.series({}, {"value": None}))

        top["organizations_by_activity"] = c.run("organizations_by_activity", lambda: orgs_by_activity(r, win, c, jv), []) or []

        def plans():
            r.require("organizations", "plan_type")
            rows = r.rows("organizations", "SELECT plan_type AS plan, COUNT(*) AS n FROM organizations GROUP BY plan_type ORDER BY n DESC")
            top["plans"] = [{"plan": row["plan"] or "", "organizations": _num(row["n"])} for row in rows]
            c.sources["plans"] = "organizations.plan_type"
        c.run("plans", plans)
        top.setdefault("plans", [])

    for key, label in OVERVIEW_KPI_LABELS:
        k.setdefault(key, kpi(label, "", None, None))

    coverage = _coverage(win, auth_cut, traffic_cut, jv)
    return {
        "api_version": "v1", "generated_at": iso(now_utc()), "range": win.range, "bucket": win.bucket,
        "kpis": k, "series": series, "top": top, "sources": c.sources, "unavailable": c.unavailable,
        "coverage": coverage,
    }


def _coverage(win: Window, auth_cut: Optional[datetime], traffic_cut: Optional[datetime],
              jv: Optional[JournalView] = None) -> Dict[str, Any]:
    """retained_from is the raw journal horizon. range_complete / previous_complete are true when raw rows plus
    daily rollups answer the whole period; rollups_used says whether rolled-up days were needed (additive)."""
    out: Dict[str, Any] = {}
    for table, cut in (("platform_auth_events", auth_cut), ("platform_request_events", traffic_cut)):
        if cut is None:
            continue
        entry = {"retained_from": iso(cut), "range_complete": win.start >= cut, "previous_complete": win.prev_start >= cut}
        if jv is not None:
            cur, prev = jv.plan(win.start, win.end, cut), jv.plan(win.prev_start, win.prev_end, cut)
            entry.update({"range_complete": cur.complete, "previous_complete": prev.complete,
                          "rollups_used": bool(cur.uses_rollups or prev.uses_rollups)})
        out[table] = entry
    if jv is not None:
        first, last = jv.extent.get("first_day"), jv.extent.get("last_day")
        out["platform_usage_daily"] = {
            "rolled_from": f"{first}T00:00:00Z" if first else None,
            "rolled_through": iso(jv.ur.day_start(str(last)) + timedelta(days=1)) if last else None,
            "days_rolled": _num(jv.extent.get("days")),
            "range_days_rolled": jv.rolled_in(win.start, win.end) if win.bucket == "day" else 0,
            "previous_days_rolled": jv.rolled_in(jv.ur.day_floor(win.prev_start), win.prev_end) if win.bucket == "day" else 0,
        }
    return out


def _nearest_rank(sorted_values: List[float], pct: int) -> Optional[float]:
    if not sorted_values:
        return None
    rank = (len(sorted_values) * pct + 99) // 100  # ceil(pct/100 * n), 1-based
    return _round(sorted_values[max(1, rank) - 1], 1)


def latency_stats(r: Reader, start: datetime, end: datetime, bucket: Optional[str] = None,
                  org: Optional[str] = None) -> Tuple[Optional[float], Dict[str, Dict[str, Any]]]:
    """Nearest-rank p95 over [start, end) and, when bucket is given, p50/p95 per bucket.

    Postgres computes both with percentile_disc. SQLite has no percentile aggregate and its window-function
    form sorted the range twice (~300 ms on 14k rows), so there the durations are read through the covering
    index (created_at, status_code, duration_ms, ...) and ranked in memory; the rows read are bounded by
    the request journal's retention window.
    """
    org_sql = " AND organization_id = ?" if org is not None else ""
    params = [ts_bound("iso", start), ts_bound("iso", end)] + ([org] if org is not None else [])
    if backend_for("platform_request_events") == "pg":
        overall = r.one("platform_request_events",
                        "SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95 FROM platform_request_events "
                        f"WHERE created_at >= ? AND created_at < ?{org_sql}", params)
        out: Dict[str, Dict[str, Any]] = {}
        if bucket:
            bexpr = bucket_sql("iso", "created_at", bucket)
            for row in r.rows("platform_request_events",
                              f"SELECT {bexpr} AS b, percentile_disc(0.5) WITHIN GROUP (ORDER BY duration_ms) AS p50, "
                              "percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95 FROM platform_request_events "
                              f"WHERE created_at >= ? AND created_at < ?{org_sql} GROUP BY {bexpr}", params):
                label = bucket_label("iso", row["b"], bucket)
                if label:
                    out[label] = {"p50": _round(row["p50"], 1), "p95": _round(row["p95"], 1)}
        return _round(overall.get("p95"), 1), out
    r.require("platform_request_events", "duration_ms", "created_at")
    width = 13 if bucket == "hour" else 10
    conn = r._conn("sqlite")
    cur = conn.execute(f"SELECT SUBSTR(created_at, 1, {width}) AS b, duration_ms FROM platform_request_events "
                       f"WHERE created_at >= ? AND created_at < ?{org_sql}", params)
    groups: Dict[str, List[float]] = {}
    everything: List[float] = []
    for b, d in cur.fetchall():
        if d is None:
            continue
        everything.append(d)
        if bucket:
            groups.setdefault(b, []).append(d)
    everything.sort()
    out = {}
    for b, values in groups.items():
        label = bucket_label("iso", b, bucket or "day")
        if label:
            values.sort()
            out[label] = {"p50": _nearest_rank(values, 50), "p95": _nearest_rank(values, 95)}
    return _nearest_rank(everything, 95), out


def latency_stats_split(r: Reader, before: datetime, split: datetime, end: datetime, bucket: str
                        ) -> Tuple[Optional[float], Optional[float], Dict[str, Dict[str, Any]]]:
    """(p95 over [before, split), latency_stats(split, end, bucket)) with one read on SQLite. split is a bucket start."""
    if backend_for("platform_request_events") == "pg":
        return (latency_stats(r, before, split)[0],) + latency_stats(r, split, end, bucket)
    r.require("platform_request_events", "duration_ms", "created_at")
    width = 13 if bucket == "hour" else 10
    split_key = ts_bound("iso", split)[:width]
    cur = r._conn("sqlite").execute(f"SELECT SUBSTR(created_at, 1, {width}) AS b, duration_ms FROM platform_request_events "
                                    "WHERE created_at >= ? AND created_at < ?", [ts_bound("iso", before), ts_bound("iso", end)])
    earlier: List[float] = []
    everything: List[float] = []
    groups: Dict[str, List[float]] = {}
    for b, d in cur.fetchall():
        if d is None:
            continue
        if b < split_key:
            earlier.append(d)
        else:
            everything.append(d)
            groups.setdefault(b, []).append(d)
    earlier.sort()
    everything.sort()
    out: Dict[str, Dict[str, Any]] = {}
    for b, values in groups.items():
        label = bucket_label("iso", b, bucket)
        if label:
            values.sort()
            out[label] = {"p50": _nearest_rank(values, 50), "p95": _nearest_rank(values, 95)}
    return _nearest_rank(earlier, 95), _nearest_rank(everything, 95), out


_ROUTE_COUNTS = ("COUNT(*) AS requests, SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS errors, "
                 "SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS client_errors")


def routes_by_errors(jv: JournalView) -> List[Dict[str, Any]]:
    """Top 10 routes by 5xx responses in the range (then by requests, then by path)."""
    r, win, ur = jv.r, jv.win, jv.ur

    def entry(route: Any, requests: Any, errors: Any, client_errors: Any) -> Dict[str, Any]:
        return {"route": route, "requests": _num(requests), "errors": _num(errors),
                "error_rate_pct": round(_num(errors) * 100.0 / max(1, _num(requests)), 2), "client_errors": _num(client_errors)}

    days = None
    if win.bucket == "day" and jv.traffic_cut is not None and jv.fast_ok():
        days = jv.rolled_run(max(win.start, ur.day_ceil(jv.traffic_cut), jv.retained_floor()), ur.day_floor(win.now))
    if days is None:
        rows = r.rows("platform_request_events",
                      f"SELECT path AS route, {_ROUTE_COUNTS} FROM platform_request_events WHERE created_at >= ? AND created_at < ? "
                      "GROUP BY path HAVING SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) > 0 "
                      "ORDER BY errors DESC, requests DESC, path LIMIT 10",
                      [ts_bound("iso", win.start), ts_bound("iso", win.end)])
        return [entry(row["route"], row["requests"], row["errors"], row["client_errors"]) for row in rows]
    # Raw rows before and after the rolled-up days, platform_usage_routes_daily (identical counts) in between.
    totals: Dict[str, List[int]] = {}
    for lo, hi in ((win.start, days[0]), (days[1], win.end)):
        if hi <= lo:
            continue
        for row in r.rows("platform_request_events",
                          f"SELECT path AS route, {_ROUTE_COUNTS} FROM platform_request_events WHERE created_at >= ? AND created_at < ? "
                          "GROUP BY path", [ts_bound("iso", lo), ts_bound("iso", hi)]):
            t = totals.setdefault(str(row["route"]), [0, 0, 0])
            t[0], t[1], t[2] = t[0] + _num(row["requests"]), t[1] + _num(row["errors"]), t[2] + _num(row["client_errors"])
    for path, agg in ur.routes(r, days[0], days[1]).items():
        t = totals.setdefault(path, [0, 0, 0])
        t[0], t[1], t[2] = t[0] + agg["requests"], t[1] + agg["errors"], t[2] + agg["client_errors"]
    ranked = sorted(((p, t) for p, t in totals.items() if t[1] > 0), key=lambda x: (-x[1][1], -x[1][0], x[0]))
    return [entry(p, t[0], t[1], t[2]) for p, t in ranked[:10]]


def orgs_by_activity(r: Reader, win: Window, c: Collector, jv: Optional[JournalView] = None) -> List[Dict[str, Any]]:
    r.require("organizations", "id", "name")
    names = {str(row["id"]): row["name"] for row in r.rows("organizations", "SELECT id, name FROM organizations")}
    stats: Dict[str, Dict[str, Any]] = {oid: {"requests": 0, "logins": 0, "scans": 0, "last_seen": None} for oid in names}

    def merge(rows: List[Dict[str, Any]], field: str) -> None:
        for row in rows:
            oid = str(row.get("org") or "")
            if oid not in stats:
                continue
            stats[oid][field] += _num(row.get("n"))
            seen = parse_ts(row.get("last"))
            cur = parse_ts(stats[oid]["last_seen"])
            if seen and (cur is None or seen > cur):
                stats[oid]["last_seen"] = iso(seen)

    def grouped(table: str, extra: str = "", start: Optional[datetime] = None, end: Optional[datetime] = None) -> List[Dict[str, Any]]:
        kind = r.ts_kind(table, "created_at")
        return r.rows(table, f"SELECT organization_id AS org, COUNT(*) AS n, MAX(created_at) AS last FROM {table} "
                             f"WHERE created_at >= ? AND created_at < ?{_where(extra)} GROUP BY organization_id",
                      [ts_bound(kind, start or win.start), ts_bound(kind, end or win.end)])

    # Fast mode (see JournalView.fast_plan) counts retained rolled-up days from the rollup, which only knows the
    # day. An organization whose newest activity is on such a day gets its exact time from that one day's raw
    # rows, and only when it can reach the top 10 (below), so last_seen is what the raw rows alone would say.
    pending: Dict[str, Dict[str, str]] = {}

    def journal(table: str, cut: Optional[datetime], extra: str, n_col: str, day_col: str) -> List[Dict[str, Any]]:
        plan = jv.fast_plan(win.start, win.end, cut) if jv is not None else None
        if plan is None or not plan.spans:
            return grouped(table, extra)
        rows: List[Dict[str, Any]] = []
        newer: set = set()  # organizations with raw rows after the retained rolled-up days
        for lo, hi in plan.pieces:
            found = grouped(table, extra, lo, hi)
            rows.extend(found)
            if plan.retained and lo >= plan.retained[1]:
                newer.update(str(row.get("org") or "") for row in found if row.get("last"))
        for span in plan.spans:
            by_org = jv.once(("by_org",) + span, lambda: jv.ur.by_org(r, span[0], span[1]))
            for oid, agg in by_org.items():
                if _num(agg.get(n_col)):
                    last = agg.get(day_col)
                    if last and span == plan.retained and oid not in newer:
                        pending.setdefault(table, {})[oid] = str(last)
                        rows.append({"org": oid, "n": agg.get(n_col), "last": None})
                    else:
                        rows.append({"org": oid, "n": agg.get(n_col), "last": f"{last}T00:00:00Z" if last else None})
        return rows

    login_extra = f"event_type IN {_IN_SUCCESS}"
    merge(c.run("organizations_by_activity.requests",
                lambda: journal("platform_request_events", jv.traffic_cut if jv else None, "", "requests", "last_request_day"), [])
          or [], "requests")
    merge(c.run("organizations_by_activity.logins",
                lambda: journal("platform_auth_events", jv.auth_cut if jv else None, login_extra, "logins",
                                "last_login_day"), []) or [], "logins")
    merge(c.run("organizations_by_activity.scans", lambda: grouped("scans"), []) or [], "scans")

    if pending:
        totals = sorted((s["requests"] + s["logins"] + s["scans"] for s in stats.values()), reverse=True)
        floor_total = max(1, totals[9] if len(totals) >= 10 else 1)
        for table, extra in (("platform_request_events", ""), ("platform_auth_events", login_extra)):
            days: Dict[str, List[str]] = {}
            for oid, day in (pending.get(table) or {}).items():
                s = stats.get(oid)
                if s and s["requests"] + s["logins"] + s["scans"] >= floor_total:
                    days.setdefault(day, []).append(oid)
            for day, oids in sorted(days.items()):
                start = jv.ur.day_start(day)
                for i in range(0, len(oids), 200):
                    chunk = oids[i:i + 200]
                    merge(c.run("organizations_by_activity." + ("requests" if table == "platform_request_events" else "logins"),
                                lambda: r.rows(table, f"SELECT organization_id AS org, MAX(created_at) AS last FROM {table} "
                                                      f"WHERE created_at >= ? AND created_at < ?{_where(extra)} AND organization_id IN "
                                                      f"({', '.join('?' for _ in chunk)}) GROUP BY organization_id",
                                               [ts_bound("iso", start), ts_bound("iso", start + timedelta(days=1)), *chunk]), [])
                          or [], "scans")
    c.sources["organizations_by_activity"] = ("platform_request_events.organization_id, platform_auth_events (successful logins), "
                                              "scans.organization_id; last_seen = newest of those within the range"
                                              + ROLLUP_NOTE + " (last_seen from a rolled-up day is that day's start)")
    ranked = [{"organization_id": oid, "name": names.get(oid) or "", **s} for oid, s in stats.items()
              if s["requests"] or s["logins"] or s["scans"]]
    ranked.sort(key=lambda x: (x["requests"] + x["logins"] + x["scans"], x["last_seen"] or ""), reverse=True)
    return ranked[:10]


# ── 3) Usage and adoption ────────────────────────────────────────────────────

# (key, label, [(table, ts_column, org_column, extra_where, keeps_history)])
# keeps_history=False: the timestamp is overwritten in place (last run / last use), so earlier events
# are not retained and previous-period counts are unknown.
FEATURES: Tuple[Tuple[str, str, Tuple[Tuple[str, str, str, str, bool], ...]], ...] = (
    ("tls_scans", "TLS scans", (("scans", "created_at", "organization_id", "", True),)),
    ("assets", "Asset inventory updates", (("assets", "updated_at", "organization_id", "", False),)),
    ("remediations", "Remediations", (("remediations", "created_at", "organization_id", "", True),)),
    ("cbom_ingest", "CBOM ingest", (("cbom_webhook_ingests", "created_at", "org_id", "", True),)),
    ("github", "GitHub integration", (("github_installations", "created_at", "organization_id", "", True),
                                      ("github_pr_events", "created_at", "organization_id", "", True))),
    ("sbom", "SBOM imports", (("sbom_imports", "imported_at", "organization_id", "", True),)),
    ("mobile_iot", "Mobile / IoT scans", (("mobile_iot_scans", "created_at", "organization_id", "", True),)),
    ("zk_proofs", "ZK compliance proofs", (("zk_compliance_proofs", "generated_at", "org_id", "", True),)),
    ("vendor_attestations", "Vendor attestations", (("vendor_attestation_invites", "created_at", "organization_id", "", True),
                                                    ("vendor_attestation_submissions", "created_at", "organization_id", "", True))),
    ("hndl_canaries", "HNDL canaries", (("hndl_canary_tokens", "created_at", "organization_id", "", True),)),
    ("quantum_canaries", "Quantum canaries", (("quantum_canaries", "deployed_at", "org_id", "", True),)),
    ("scan_schedules", "Scheduled scans", (("scan_schedules", "last_run_at", "org_id", "", False),)),
    ("webhooks", "Webhook deliveries", (("morrow_webhook_deliveries", "created_at", "organization_id", "", True),
                                        ("webhook_events", "created_at", "organization_id", "", True))),
    ("ai_assistant", "AI assistant", (("audit_logs", "created_at", "organization_id",
                                       "action IN ('agent.chat','assistant.chat','assistant.intent')", True),)),
    ("api_keys", "API keys used", (("platform_api_keys", "last_used_at", "organization_id", "", False),)),
)


def _feature_source_label(sources: Sequence[Tuple[str, str, str, str, bool]]) -> str:
    parts = []
    for table, ts_col, _org, extra, _hist in sources:
        parts.append(f"{table}.{ts_col}" + (f" where {extra}" if extra else ""))
    return "; ".join(parts)


def feature_usage(r: Reader, win: Window, c: Collector, org: Optional[str] = None,
                  with_series: bool = True) -> List[Dict[str, Any]]:
    out = []
    for key, label, sources in FEATURES:
        present = [s for s in sources if r.has(s[0], s[1], s[2])]
        if not present:
            c.missing(f"feature.{key}", "No data source: " + ", ".join(f"{t}.{col}" for t, col, *_ in sources) + " not present.")
            continue
        orgs_using: set = set()
        events = 0
        previous: Optional[int] = 0
        last_used: Optional[datetime] = None
        buckets: Dict[str, int] = {}
        failed = False
        for table, ts_col, org_col, extra, keeps_history in present:
            try:
                kind = r.ts_kind(table, ts_col)
                not_empty = f"{ts_col} IS NOT NULL" + ("" if kind in ("epoch", "tstz", "ts") else f" AND {ts_col} <> ''")
                # With an action filter, "org || ''" keeps the planner on the (action, organization_id, created_at)
                # index instead of scanning every row the tenant ever wrote. Portable to Postgres.
                org_sql = (f"{org_col} || '' = ?" if extra else f"{org_col} = ?") if org is not None else ""
                where = " AND ".join(x for x in (not_empty, extra, org_sql) if x)
                oparams = [org] if org is not None else []
                bexpr = bucket_sql(kind, ts_col, win.bucket)
                rows = r.rows(table, f"SELECT {org_col} AS org, {bexpr} AS b, COUNT(*) AS n FROM {table} "
                                     f"WHERE {ts_col} >= ? AND {ts_col} < ? AND {where} GROUP BY {org_col}, {bexpr}",
                              [ts_bound(kind, win.start), ts_bound(kind, win.end), *oparams])
                for row in rows:
                    n = _num(row["n"])
                    events += n
                    if row.get("org"):
                        orgs_using.add(str(row["org"]))
                    lab = bucket_label(kind, row["b"], win.bucket)
                    if lab:
                        buckets[lab] = buckets.get(lab, 0) + n
                if keeps_history and previous is not None:
                    prow = r.one(table, f"SELECT COUNT(*) AS n FROM {table} WHERE {ts_col} >= ? AND {ts_col} < ? AND {where}",
                                 [ts_bound(kind, win.prev_start), ts_bound(kind, win.prev_end), *oparams])
                    previous += _num(prow.get("n"))
                else:
                    previous = None
                mrow = r.one(table, f"SELECT MAX({ts_col}) AS m FROM {table} WHERE {where}", oparams)
                seen = parse_ts(mrow.get("m"))
                if seen and (last_used is None or seen > last_used):
                    last_used = seen
            except Exception as exc:
                failed = True
                c.missing(f"feature.{key}.{table}", f"Query failed: {exc.__class__.__name__}")
        if failed and events == 0 and last_used is None:
            continue
        item: Dict[str, Any] = {
            "key": key, "label": label, "organizations_using": len(orgs_using), "events": events,
            "previous_events": previous, "delta_pct": delta_pct(events, previous),
            "last_used_at": iso(last_used), "source": _feature_source_label(present),
        }
        if not all(s[4] for s in present):
            c.missing(f"feature.{key}.previous_events",
                      "The source timestamp is overwritten in place (last run / last use), so only the latest event per "
                      "record is kept and previous-period counts are unknown.")
        if with_series:
            item["series"] = [{"t": lab, "value": buckets.get(lab, 0)} for lab in win.labels]
        c.sources[f"feature.{key}"] = item["source"]
        out.append(item)
    return out


def usage(range_key: str) -> Dict[str, Any]:
    flush_journal()
    win = Window(range_key)
    c = Collector()
    with Reader() as r:
        features = feature_usage(r, win, c)
        total = c.run("organizations_total", lambda: count_all(r, "organizations"), None)
    c.sources["organizations_total"] = "organizations.id"
    c.sources["organizations_using"] = "distinct organization id with at least one event in the range"
    return {"api_version": "v1", "generated_at": iso(now_utc()), "range": win.range, "bucket": win.bucket,
            "features": features, "organizations_total": total, "sources": c.sources, "unavailable": c.unavailable}


# ── 2) Customer 360 ──────────────────────────────────────────────────────────


def org_row(r: Reader, organization_id: str) -> Optional[Dict[str, Any]]:
    rows = r.rows("organizations", "SELECT id, name, plan_type, subscription_status, created_at, updated_at "
                                   "FROM organizations WHERE id = ?", [organization_id])
    return rows[0] if rows else None


def organization_exists(organization_id: str) -> bool:
    with Reader() as r:
        try:
            return org_row(r, organization_id) is not None
        except Exception:
            return False


def _org_status(value: Any) -> str:
    text = str(value or "active").lower()
    return text if text in ("suspended", "archived") else "active"


def customer(organization_id: str, range_key: str) -> Optional[Dict[str, Any]]:
    flush_journal()
    win = Window(range_key)
    c = Collector()
    oid = organization_id
    auth_cut = journal_cutoff("auth", win.now)
    traffic_cut = journal_cutoff("traffic", win.now)
    k: Dict[str, Dict[str, Any]] = {}
    series: Dict[str, Any] = {}
    with Reader() as r:
        row = org_row(r, oid)
        if row is None:
            return None
        organization = {
            "organization_id": str(row["id"]), "name": row.get("name") or "", "status": _org_status(row.get("subscription_status")),
            "plan": row.get("plan_type") or "", "created_at": ts_iso(row.get("created_at")),
            "subscription_status": row.get("subscription_status") or "",
        }
        if organization["status"] == "suspended":
            reason = c.run("organization.suspended_reason", lambda: r.one(
                "platform_admin_events", "SELECT reason, created_at FROM platform_admin_events WHERE organization_id = ? "
                "AND action = 'platform.customer_suspended' ORDER BY created_at DESC LIMIT 1", [oid]), {}) or {}
            organization["suspended_reason"] = reason.get("reason") or None
            organization["suspended_at"] = ts_iso(reason.get("created_at"))

        members = c.run("members", lambda: customer_members(r, oid, win, k, c), []) or []
        jv = JournalView(r, win, c)

        def active():
            r.require("platform_auth_events", "organization_id")
            previous = journal_active(jv, win.prev_start, win.prev_end, oid, "user", False)
            if previous is None:
                c.missing("active_users.previous", "The previous period predates the security journal retention window "
                                                   "and is not covered by daily usage rollups.")
            k["active_users"] = kpi("Active users", "platform_auth_events.user_id + platform_request_events.actor_id",
                                    journal_active(jv, win.start, win.end, oid, "user", True), previous)
            c.sources["active_users"] = ("distinct platform_auth_events.user_id (login.success, saml.success) UNION "
                                         "platform_request_events.actor_id (authenticated = 1) for this organization"
                                         + ROLLUP_NOTE.replace("platform_usage_daily", "platform_active_users_daily (salted actor hashes)"))
        c.run("active_users", active)

        def logins():
            exprs = {"success": f"SUM(CASE WHEN event_type IN {_IN_SUCCESS} THEN 1 ELSE 0 END)",
                     "failed": f"SUM(CASE WHEN event_type IN {_IN_FAILURE} THEN 1 ELSE 0 END)"}
            cur = journal_logins(jv, win.start, win.end, oid, True) or {}
            prev = journal_logins(jv, win.prev_start, win.prev_end, oid, False)
            prev_known = prev is not None
            prev = prev or {}
            if not prev_known:
                c.missing("logins.previous", "The previous period predates the security journal retention window "
                                             "and is not covered by daily usage rollups.")
            k["logins"] = kpi("Successful logins", "platform_auth_events.event_type", _num(cur.get("success")),
                              _num(prev.get("success")) if prev_known else None)
            k["failed_logins"] = kpi("Failed logins", "platform_auth_events.event_type", _num(cur.get("failed")),
                                     _num(prev.get("failed")) if prev_known else None)
            data = bucket_agg(r, "platform_auth_events", "created_at", win, exprs, "organization_id = ?", [oid])
            points = win.series({label: {"success": _num(v.get("success")), "failed": _num(v.get("failed"))}
                                 for label, v in data.items()}, {"success": 0, "failed": 0}, unknown_before=auth_cut)
            roll = ({label: {"success": _num(v.get("logins_success")), "failed": _num(v.get("logins_failed"))}
                     for label, v in jv.ur.by_day(r, win.start, win.end, oid).items()} if jv.rolled else {})
            series["logins"] = jv.series(points, roll, auth_cut, {"success": 0, "failed": 0})
            c.sources["logins"] = "platform_auth_events.event_type in (login.success, saml.success)" + ROLLUP_NOTE
            c.sources["failed_logins"] = "platform_auth_events.event_type in (login.failure, saml.failure)"
        c.run("logins", logins)
        series.setdefault("logins", win.series({}, {"success": None, "failed": None}))

        def scans():
            cur = period_agg(r, "scans", "created_at", win.start, win.end, {"n": "COUNT(*)"}, "organization_id = ?", [oid])
            prev = period_agg(r, "scans", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"}, "organization_id = ?", [oid])
            k["scans"] = kpi("Scans", "scans.created_at", _num(cur.get("n")), _num(prev.get("n")))
            data = bucket_agg(r, "scans", "created_at", win, {"value": "COUNT(*)"}, "organization_id = ?", [oid])
            series["scans"] = win.series({label: {"value": _num(v["value"])} for label, v in data.items()}, {"value": 0})
            c.sources["scans"] = "scans.created_at"
        c.run("scans", scans)
        series.setdefault("scans", win.series({}, {"value": None}))

        def assets():
            k["assets"] = kpi("Assets", "assets.asset_key", count_all(r, "assets", "organization_id = ?", [oid]), None)
            c.sources["assets"] = "assets.asset_key (current inventory)"
        c.run("assets", assets)

        def remediations():
            r.require("remediations", "status", "organization_id")
            row2 = r.one("remediations",
                         f"SELECT SUM(CASE WHEN status IN {_in_list(CLOSED_REMEDIATION_STATUSES)} THEN 1 ELSE 0 END) AS closed, "
                         "COUNT(*) AS total FROM remediations WHERE organization_id = ?", [oid])
            closed = _num(row2.get("closed"))
            k["open_remediations"] = kpi("Open remediations", "remediations.status", _num(row2.get("total")) - closed, None)
            k["closed_remediations"] = kpi("Closed remediations", "remediations.status", closed, None)
            c.sources["open_remediations"] = "remediations.status not in (rejected, verified_closed)"
            c.sources["closed_remediations"] = "remediations.status in (rejected, verified_closed)"
        c.run("remediations", remediations)

        def requests_block():
            exprs = {"total": "COUNT(*)",
                     "client_errors": "SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END)",
                     "server_errors": "SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END)"}
            roll_map = {"total": lambda s: _num(s.get("requests")),
                        "client_errors": lambda s: _num(s.get("client_errors")) + _num(s.get("rate_limited")),
                        "server_errors": lambda s: _num(s.get("server_errors"))}
            cur = journal_requests(jv, win.start, win.end, exprs, roll_map, oid, True)[0] or {}
            prev = journal_requests(jv, win.prev_start, win.prev_end, exprs, roll_map, oid, False)[0]
            prev_known = prev is not None
            prev = prev or {}
            total, ptotal = _num(cur.get("total")), (_num(prev.get("total")) if prev_known else None)
            k["api_requests"] = kpi("API requests", "platform_request_events.id", total, ptotal)
            k["error_rate_pct"] = kpi("Server error rate (5xx) %", "platform_request_events.status_code",
                                      round(_num(cur.get("server_errors")) * 100.0 / total, 2) if total else None,
                                      round(_num(prev.get("server_errors")) * 100.0 / ptotal, 2) if ptotal else None)
            data = bucket_agg(r, "platform_request_events", "created_at", win, exprs, "organization_id = ?", [oid])
            req_fields = {"total": 0, "client_errors": 0, "server_errors": 0}
            points = win.series({label: {n: _num(v.get(n)) for n in exprs} for label, v in data.items()}, req_fields, unknown_before=traffic_cut)
            roll = ({label: {n: fn(v) for n, fn in roll_map.items()} for label, v in jv.ur.by_day(r, win.start, win.end, oid).items()}
                    if jv.rolled else {})
            series["requests"] = jv.series(points, roll, traffic_cut, req_fields)
            c.sources["api_requests"] = ("platform_request_events.organization_id (requests authenticated as this organization: "
                                         "JWT org claim, organization API key, or header identity in MORROW_AUTH_MODE=headers)" + ROLLUP_NOTE)
            c.sources["error_rate_pct"] = "platform_request_events.status_code >= 500 / all requests"
            if not prev_known:
                c.missing("api_requests.previous", "The previous period predates the request journal retention window "
                                                   "and is not covered by daily usage rollups.")
        c.run("api_requests", requests_block)
        series.setdefault("requests", win.series({}, {"total": None, "client_errors": None, "server_errors": None}))

        def api_keys():
            r.require("platform_api_keys", "organization_id", "expires_at", "revoked_at")
            n = count_all(r, "platform_api_keys", "organization_id = ? AND (revoked_at IS NULL OR revoked_at = '') "
                                                  "AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?)",
                          [oid, ts_bound("iso", win.now)])
            k["active_api_keys"] = kpi("Active API keys", "platform_api_keys.revoked_at, expires_at", n, None)
            c.sources["active_api_keys"] = "platform_api_keys for this organization, not revoked and not expired"
        c.run("active_api_keys", api_keys)

        def sessions():
            r.require("morrow_refresh_tokens", "user_id", "expires_at")
            r.require("morrow_users", "id", "org_id")
            row2 = r.one("morrow_refresh_tokens", "SELECT COUNT(*) AS n FROM morrow_refresh_tokens t JOIN morrow_users u ON u.id = t.user_id "
                                               "WHERE u.org_id = ? AND t.expires_at > ?", [oid, int(win.now.timestamp())])
            k["active_sessions"] = kpi("Active sessions", "morrow_refresh_tokens.expires_at", _num(row2.get("n")), None)
            c.sources["active_sessions"] = "morrow_refresh_tokens joined to morrow_users.org_id, expires_at in the future"
        c.run("active_sessions", sessions)

        def flags():
            k["feature_flags_overridden"] = kpi("Feature flags overridden", "platform_feature_flags.flag_key",
                                                count_all(r, "platform_feature_flags", "organization_id = ?", [oid]), None)
            c.sources["feature_flags_overridden"] = "platform_feature_flags rows for this organization"
        c.run("feature_flags_overridden", flags)

        def feedback():
            cur = period_agg(r, "feedback", "created_at", win.start, win.end, {"n": "COUNT(*)"}, "organization_id = ?", [oid])
            prev = period_agg(r, "feedback", "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"}, "organization_id = ?", [oid])
            k["feedback"] = kpi("Feedback submitted", "feedback.created_at", _num(cur.get("n")), _num(prev.get("n")))
            c.sources["feedback"] = "feedback.created_at"
        c.run("feedback", feedback)

        recent, heads = customer_events(r, oid, c, jv)
        last = None
        for kind_name, at in heads:
            if at and (last is None or at > last[1]):
                last = (kind_name, at)
        adoption = [{"feature": f["key"], "used": f["last_used_at"] is not None, "events": f["events"],
                     "last_used_at": f["last_used_at"]} for f in feature_usage(r, win, c, org=oid, with_series=False)]

    labels = {"members": "Members", "active_users": "Active users", "logins": "Successful logins",
              "failed_logins": "Failed logins", "scans": "Scans", "assets": "Assets", "open_remediations": "Open remediations",
              "closed_remediations": "Closed remediations", "api_requests": "API requests",
              "error_rate_pct": "Server error rate (5xx) %", "active_api_keys": "Active API keys",
              "active_sessions": "Active sessions", "feature_flags_overridden": "Feature flags overridden",
              "feedback": "Feedback submitted"}
    for key, label in labels.items():
        k.setdefault(key, kpi(label, "", None, None))
    for key in ("assets", "open_remediations", "closed_remediations", "active_api_keys", "active_sessions", "feature_flags_overridden"):
        if k[key]["value"] is not None:
            c.missing(f"{key}.previous", "Current state only; the source keeps no history to reconstruct the start of the range.")
    return {
        "api_version": "v1", "generated_at": iso(now_utc()), "range": win.range, "bucket": win.bucket,
        "organization": organization, "kpis": k, "series": series,
        "last_activity": {"at": iso(last[1]) if last else None, "kind": last[0] if last else None},
        "members": members, "recent_events": recent, "adoption": adoption,
        "sources": c.sources, "unavailable": c.unavailable, "coverage": _coverage(win, auth_cut, traffic_cut, jv),
    }


def customer_members(r: Reader, oid: str, win: Window, k: Dict[str, Any], c: Collector) -> List[Dict[str, Any]]:
    people: Dict[str, Dict[str, Any]] = {}
    created: Dict[str, Optional[datetime]] = {}
    found_source = False
    if r.has("organization_memberships", "organization_id", "user_id"):
        found_source = True
        for row in r.rows("organization_memberships", "SELECT user_id, email, role, status, created_at FROM organization_memberships "
                                                      "WHERE organization_id = ?", [oid]):
            uid = str(row["user_id"])
            people[uid] = {"user_id": uid, "email": row.get("email") or "", "role": row.get("role") or "",
                           "status": "disabled" if str(row.get("status") or "") == "disabled" else "active",
                           "last_login_at": None}
            created[uid] = parse_ts(row.get("created_at"))
    if r.has("morrow_users", "id", "org_id"):
        found_source = True
        for row in r.rows("morrow_users", "SELECT id, email, role, is_active, created_at, last_login_at FROM morrow_users WHERE org_id = ?", [oid]):
            uid = str(row["id"])
            entry = people.setdefault(uid, {"user_id": uid, "email": "", "role": "", "status": "active", "last_login_at": None})
            entry["email"] = entry["email"] or row.get("email") or ""
            entry["role"] = entry["role"] or row.get("role") or ""
            if not _num(row.get("is_active")):
                entry["status"] = "disabled"
            entry["last_login_at"] = ts_iso(row.get("last_login_at")) if row.get("last_login_at") else None
            created[uid] = created.get(uid) or parse_ts(row.get("created_at"))
    if not found_source:
        raise SourceMissing("Neither organization_memberships nor morrow_users exists.")
    if r.has("platform_auth_events", "organization_id", "user_id"):
        for row in r.rows("platform_auth_events", "SELECT user_id, MAX(created_at) AS last FROM platform_auth_events "
                                                  f"WHERE organization_id = ? AND event_type IN {_IN_SUCCESS} AND user_id <> '' "
                                                  "GROUP BY user_id", [oid]):
            entry = people.get(str(row["user_id"]))
            if entry:
                seen, cur = parse_ts(row["last"]), parse_ts(entry["last_login_at"])
                if seen and (cur is None or seen > cur):
                    entry["last_login_at"] = iso(seen)
    total = len(people)
    previous = sum(1 for uid in people if created.get(uid) and created[uid] < win.start)
    unknown_created = any(created.get(uid) is None for uid in people)
    k["members"] = kpi("Members", "organization_memberships.user_id + morrow_users.id", total, None if unknown_created else previous)
    c.sources["members"] = ("organization_memberships (role assignments) merged with morrow_users.org_id (sign-in accounts) by user id; "
                            "last_login_at = newest of morrow_users.last_login_at and platform_auth_events login.success")
    ordered = sorted(people.values(), key=lambda p: (p["last_login_at"] or "", (p["email"] or p["user_id"]).lower()), reverse=True)
    return ordered[:50]


def customer_events(r: Reader, oid: str, c: Collector,
                    jv: Optional[JournalView] = None) -> Tuple[List[Dict[str, Any]], List[Tuple[str, Optional[datetime]]]]:
    events: List[Dict[str, Any]] = []
    heads: List[Tuple[str, Optional[datetime]]] = []

    def add(kind: str, rows: List[Dict[str, Any]], build: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        for i, row in enumerate(rows):
            item = build(row)
            at = parse_ts(row.get("created_at"))
            if i == 0:
                heads.append((kind, at))
            events.append({"at": iso(at), "kind": kind, **item})

    def audit():
        rows = r.rows("audit_logs", "SELECT created_at, action, actor_id, decision, reason, resource_type, resource_id FROM audit_logs "
                                    "WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30", [oid])
        add("audit", rows, lambda x: {"action": x.get("action") or "", "actor": x.get("actor_id") or "",
                                      "detail": " ".join(p for p in (str(x.get("decision") or ""),
                                                                     f"{x.get('resource_type') or ''}/{x.get('resource_id') or ''}".strip("/"),
                                                                     str(x.get("reason") or "")[:160]) if p)})
    c.run("recent_events.audit", audit)

    def admin():
        rows = r.rows("platform_admin_events", "SELECT created_at, action, actor_id, reason FROM platform_admin_events "
                                               "WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30", [oid])
        add("admin", rows, lambda x: {"action": x.get("action") or "", "actor": x.get("actor_id") or "",
                                      "detail": str(x.get("reason") or "")[:200]})
    c.run("recent_events.admin", admin)

    def auth():
        rows = r.rows("platform_auth_events", "SELECT created_at, event_type, user_id, login_method, status_code FROM platform_auth_events "
                                              "WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30", [oid])
        add("auth", rows, lambda x: {"action": x.get("event_type") or "", "actor": x.get("user_id") or "",
                                     "detail": f"{x.get('login_method') or ''} ({x.get('status_code')})".strip()})
    c.run("recent_events.auth", auth)

    def login():
        # login_events only exists in the SQLite file; on a Postgres deployment it is absent, which is "no source",
        # not a failed query.
        r.require("login_events", "created_at", "organization_id")
        rows = r.rows("login_events", "SELECT created_at, user_id, actor_role, login_method FROM login_events "
                                      "WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30", [oid])
        add("login", rows, lambda x: {"action": "user.login", "actor": x.get("user_id") or "",
                                      "detail": f"{x.get('login_method') or ''} as {x.get('actor_role') or ''}".strip()})
    c.run("recent_events.login", login)

    def last_request():
        row = r.one("platform_request_events", "SELECT MAX(created_at) AS m FROM platform_request_events WHERE organization_id = ?", [oid])
        last = parse_ts(row.get("m"))
        if last is None and jv is not None and jv.rolled:
            # Older than raw retention: the newest rolled-up day with requests (day granularity).
            day = r.one("platform_usage_daily", "SELECT MAX(day) AS d FROM platform_usage_daily WHERE organization_id = ? AND requests > 0", [oid])
            last = parse_ts(str(day.get("d")) + "T00:00:00Z") if day.get("d") else None
        heads.append(("request", last))
        row = r.one("scans", "SELECT MAX(created_at) AS m FROM scans WHERE organization_id = ?", [oid])
        heads.append(("scan", parse_ts(row.get("m"))))
    c.run("last_activity", last_request)
    c.sources["recent_events"] = "audit_logs, platform_admin_events, platform_auth_events, login_events (organization_id)"
    c.sources["last_activity"] = "newest of recent_events sources, platform_request_events and scans for this organization"
    events.sort(key=lambda e: e["at"] or "", reverse=True)
    return events[:30], heads


# ── 4) Search ────────────────────────────────────────────────────────────────

_TYPE_ORDER = {"organization": 0, "user": 1, "api_key": 2, "announcement": 3, "autopatch": 4, "feedback": 5, "operator": 6}


def _rank(q: str, *fields: Any) -> int:
    best = 3
    for f in fields:
        text = str(f or "").lower()
        if not text:
            continue
        if text == q:
            return 0
        if text.startswith(q):
            best = min(best, 1)
        elif q in text:
            best = min(best, 2)
    return best


def _like_where(columns: Sequence[str]) -> str:
    return "(" + " OR ".join(f"LOWER(CAST({col} AS TEXT)) LIKE ? ESCAPE '\\'" for col in columns) + ")"


def search(q: str, limit: int, include_operators: bool, operators: Callable[[], List[Dict[str, str]]]) -> Dict[str, Any]:
    ql = q.strip().lower()
    pattern = like_pattern(ql)
    results: List[Tuple[int, int, Dict[str, Any]]] = []
    unavailable: List[Dict[str, str]] = []

    def run(kind: str, table: str, columns: Sequence[str], select: str, build: Callable[[Dict[str, Any]], Dict[str, Any]],
            rank_fields: Callable[[Dict[str, Any]], Sequence[Any]], order: str = "") -> None:
        if not r.has(table, *columns):
            return
        try:
            rows = r.rows(table, f"SELECT {select} FROM {table} WHERE {_like_where(columns)}{order} LIMIT ?",
                          [pattern] * len(columns) + [limit])
        except Exception as exc:
            unavailable.append({"metric": f"search.{kind}", "reason": f"Query failed: {exc.__class__.__name__}"})
            return
        for row in rows:
            results.append((_rank(ql, *rank_fields(row)), _TYPE_ORDER[kind], {"type": kind, **build(row)}))

    with Reader() as r:
        run("organization", "organizations", ("id", "name"), "id, name, plan_type, subscription_status",
            lambda x: {"id": str(x["id"]), "title": x.get("name") or str(x["id"]),
                       "subtitle": " · ".join(p for p in (str(x["id"]), x.get("plan_type") or "", x.get("subscription_status") or "") if p),
                       "organization_id": str(x["id"]), "route": f"#/customers/{quote(str(x['id']), safe='')}"},
            lambda x: (x.get("name"), x.get("id")))
        seen_users: set = set()

        def user_build(uid: str, email: str, name: str, role: str, org: str) -> Dict[str, Any]:
            return {"id": uid, "title": email or name or uid,
                    "subtitle": " · ".join(p for p in (name if email else "", role, org) if p),
                    "organization_id": org or None, "route": "#/users?q=" + quote(email or uid, safe="@")}

        if r.has("morrow_users", "id", "email", "full_name"):
            try:
                for x in r.rows("morrow_users", f"SELECT id, email, full_name, role, org_id FROM morrow_users WHERE "
                                             f"{_like_where(('email', 'full_name', 'id'))} LIMIT ?", [pattern] * 3 + [limit]):
                    seen_users.add((str(x.get("org_id") or ""), str(x["id"])))
                    results.append((_rank(ql, x.get("email"), x.get("full_name"), x.get("id")), 1,
                                    {"type": "user", **user_build(str(x["id"]), x.get("email") or "", x.get("full_name") or "",
                                                                  x.get("role") or "", str(x.get("org_id") or ""))}))
            except Exception as exc:
                unavailable.append({"metric": "search.user", "reason": f"Query failed: {exc.__class__.__name__}"})
        if r.has("organization_memberships", "user_id", "email", "display_name"):
            try:
                for x in r.rows("organization_memberships",
                                f"SELECT user_id, email, display_name, role, organization_id FROM organization_memberships WHERE "
                                f"{_like_where(('email', 'display_name', 'user_id'))} LIMIT ?", [pattern] * 3 + [limit]):
                    key = (str(x.get("organization_id") or ""), str(x["user_id"]))
                    if key in seen_users:
                        continue
                    seen_users.add(key)
                    results.append((_rank(ql, x.get("email"), x.get("display_name"), x.get("user_id")), 1,
                                    {"type": "user", **user_build(str(x["user_id"]), x.get("email") or "", x.get("display_name") or "",
                                                                  x.get("role") or "", key[0])}))
            except Exception as exc:
                unavailable.append({"metric": "search.user", "reason": f"Query failed: {exc.__class__.__name__}"})

        # Only public identifiers: never salt or key_hash.
        run("api_key", "platform_api_keys", ("name", "prefix", "id"), "id, organization_id, name, prefix, expires_at, revoked_at",
            lambda x: {"id": str(x["id"]), "title": x.get("name") or str(x["id"]),
                       "subtitle": " · ".join(p for p in (f"pq_{x.get('prefix')}_…" if x.get("prefix") else "",
                                                          "revoked" if x.get("revoked_at") else "", str(x.get("organization_id") or "")) if p),
                       "organization_id": str(x.get("organization_id") or "") or None,
                       "route": "#/api-keys?id=" + quote(str(x["id"]), safe="")},
            lambda x: (x.get("name"), x.get("prefix"), x.get("id")))
        run("announcement", "platform_announcements", ("title", "body"), "id, title, severity, audience",
            lambda x: {"id": str(x["id"]), "title": x.get("title") or "", "subtitle": f"{x.get('severity') or ''} · {x.get('audience') or ''}",
                       "organization_id": None, "route": f"#/announcements?id={x['id']}"},
            lambda x: (x.get("title"),), " ORDER BY id DESC")
        run("autopatch", "platform_autopatches", ("title", "repo_full_name", "issue_type"), "id, title, status, severity, repo_full_name",
            lambda x: {"id": str(x["id"]), "title": x.get("title") or f"Autopatch {x['id']}",
                       "subtitle": " · ".join(p for p in (x.get("status") or "", x.get("severity") or "", x.get("repo_full_name") or "") if p),
                       "organization_id": None, "route": f"#/autopatch?id={x['id']}"},
            lambda x: (x.get("title"), x.get("repo_full_name")), " ORDER BY id DESC")
        run("feedback", "feedback", ("message", "email", "category"), "id, organization_id, category, status, message, email",
            lambda x: {"id": str(x["id"]), "title": (str(x.get("message") or "")[:80] or f"Feedback {x['id']}"),
                       "subtitle": " · ".join(p for p in (x.get("category") or "", x.get("status") or "", x.get("email") or "") if p),
                       "organization_id": str(x.get("organization_id") or "") or None, "route": f"#/feedback?id={x['id']}"},
            lambda x: (x.get("message"), x.get("email"), x.get("category")), " ORDER BY id DESC")

    if include_operators:
        for op in operators() or []:
            name, role = str(op.get("name") or ""), str(op.get("role") or "")
            if ql in name.lower() or ql in role.lower():
                results.append((_rank(ql, name, role), _TYPE_ORDER["operator"],
                                {"type": "operator", "id": name, "title": name, "subtitle": role,
                                 "organization_id": None, "route": "#/operators"}))
    results.sort(key=lambda x: (x[0], x[1], str(x[2].get("title") or "").lower()))
    return {"api_version": "v1", "query": q, "results": [x[2] for x in results[:limit]], "unavailable": unavailable}


# ── 5) Notifications ─────────────────────────────────────────────────────────

# The single catalogue of notification kinds that notifications() emits: kind -> (collector metric that
# produces it, label). services/alert_routing.py validates channel kind filters and decides what may be
# auto-resolved from it, and GET /platform/alert-channels serves it to the admin portal's channel editor.
# test_alert_routing.py parses notifications() and fails if a kind is emitted that is not listed here.
NOTIFICATION_KIND_CATALOG: Dict[str, Tuple[str, str]] = {
    "sla_breach": ("sla_breach", "SLA breach"),
    "failed_login_spike": ("failed_login_spike", "Failed-login spike"),
    "maintenance_overdue": ("maintenance", "Maintenance overdue"),
    "maintenance": ("maintenance", "Maintenance on"),
    "go_live_blockers": ("go_live_blockers", "Go-live blockers"),
    "incident": ("incident", "Incident"),
    "abuse": ("abuse", "Abuse / rate limiting"),
    "security_finding": ("security_finding", "Security finding"),
    "api_key_expiring": ("api_key_expiring", "API key expiring"),
    "org_suspended": ("org_suspended", "Organization suspended"),
    "feedback": ("feedback", "Customer feedback"),
    "autopatch_pending": ("autopatch_pending", "Autopatch pending"),
    "break_glass": ("break_glass", "Break-glass key used"),
    "support_session": ("support_session", "Support session active"),
    # An authenticator appearing on an operator account, or an enrolment refused for want of an
    # owner's approval. See services/operator_auth.begin_enrolment.
    "mfa_enrolment": ("mfa_enrolment", "Operator MFA enrolment"),
}


def notifications(hooks: Dict[str, Callable[[], Any]], now: Optional[datetime] = None, limit: int = 50) -> Dict[str, Any]:
    """hooks: go_live_gate(), security_findings(), incidents(), abuse(), maintenance(), org_names().

    limit caps the returned items (the portal shows 50); the alert dispatcher asks for all of them."""
    now = now or now_utc()
    items: List[Dict[str, Any]] = []
    c = Collector()

    def item(id_: str, severity: str, kind: str, title: str, detail: str, created_at: Any, route: str) -> None:
        items.append({"id": id_, "severity": severity, "kind": kind, "title": title, "detail": detail,
                      "created_at": ts_iso(created_at), "route": route})

    with Reader() as r:
        names: Dict[str, str] = {}
        c.run("organizations", lambda: names.update({str(x["id"]): x.get("name") or "" for x in
                                                     r.rows("organizations", "SELECT id, name FROM organizations")}))

        def org_label(oid: Any) -> str:
            oid = str(oid or "")
            return f"{names.get(oid) or oid}" if oid else "platform"

        def sla():
            r.require("sla_breaches", "status", "breached_at")
            for x in r.rows("sla_breaches", "SELECT id, organization_id, remediation_id, severity, breached_at, days_overdue "
                                            "FROM sla_breaches WHERE status = 'open' ORDER BY breached_at DESC LIMIT 50"):
                sev = str(x.get("severity") or "").lower()
                item(f"sla_breach:{x['id']}", "critical" if sev in ("critical", "high") else "warn", "sla_breach",
                     f"SLA breached: remediation #{x.get('remediation_id')} ({sev or 'unknown'} severity)",
                     f"{_num(x.get('days_overdue'))} days overdue for {org_label(x.get('organization_id'))}.",
                     x.get("breached_at"), f"#/customers/{quote(str(x.get('organization_id') or ''), safe='')}")
        c.run("sla_breach", sla)

        def feedback():
            r.require("feedback", "status")
            for x in r.rows("feedback", "SELECT id, organization_id, category, rating, message, created_at FROM feedback "
                                        "WHERE status = 'new' ORDER BY created_at DESC LIMIT 50"):
                rating = x.get("rating")
                low = rating is not None and _num(rating) and _num(rating) <= 2
                item(f"feedback:{x['id']}", "warn" if low else "info", "feedback",
                     f"New {x.get('category') or 'customer'} feedback from {org_label(x.get('organization_id'))}",
                     str(x.get("message") or "")[:200], x.get("created_at"), f"#/feedback?id={x['id']}")
        c.run("feedback", feedback)

        def autopatch():
            r.require("platform_autopatches", "status")
            for x in r.rows("platform_autopatches", "SELECT id, title, severity, created_at FROM platform_autopatches "
                                                    "WHERE status = ? ORDER BY created_at DESC LIMIT 50", [PENDING_AUTOPATCH_STATUS]):
                item(f"autopatch:{x['id']}", "warn", "autopatch_pending", f"Autopatch awaiting approval: {x.get('title') or x['id']}",
                     f"Severity {x.get('severity') or 'unknown'}; status needs_review.", x.get("created_at"), f"#/autopatch?id={x['id']}")
        c.run("autopatch_pending", autopatch)

        def failed_spike():
            r.require("platform_auth_events", "event_type", "created_at")
            hour_ago, day_before = now - timedelta(hours=1), now - timedelta(hours=25)
            row = r.one("platform_auth_events",
                        f"SELECT SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS last_hour, "
                        f"SUM(CASE WHEN created_at < ? THEN 1 ELSE 0 END) AS prior "
                        f"FROM platform_auth_events WHERE created_at >= ? AND created_at < ? AND event_type IN {_IN_FAILURE}",
                        [ts_bound("iso", hour_ago), ts_bound("iso", hour_ago), ts_bound("iso", day_before),
                         ts_bound("iso", now + timedelta(seconds=1))])
            last_hour, prior = _num(row.get("last_hour")), _num(row.get("prior"))
            avg = prior / 24.0
            if last_hour >= 10 and last_hour >= 3 * avg:
                hour_label = now.strftime("%Y-%m-%dT%H")
                item(f"failed_login_spike:{hour_label}", "critical", "failed_login_spike",
                     f"Failed-login spike: {last_hour} failures in the last hour",
                     f"Rule: at least 10 failed logins in the last hour and at least 3x the hourly average of the previous 24 hours "
                     f"(average {avg:.1f}/hour from {prior} failures). Source: platform_auth_events login.failure, saml.failure.",
                     now, "#/logins")
        c.run("failed_login_spike", failed_spike)

        def keys():
            r.require("platform_api_keys", "expires_at", "revoked_at")
            for x in r.rows("platform_api_keys", "SELECT id, organization_id, name, prefix, expires_at, created_at FROM platform_api_keys "
                                                 "WHERE (revoked_at IS NULL OR revoked_at = '') AND expires_at > ? AND expires_at <= ? "
                                                 "ORDER BY expires_at ASC LIMIT 50",
                            [ts_bound("iso", now), ts_bound("iso", now + timedelta(days=7))]):
                item(f"api_key_expiring:{x['id']}", "warn", "api_key_expiring", f"API key expires soon: {x.get('name') or x.get('prefix')}",
                     f"Expires {ts_iso(x.get('expires_at'))} ({org_label(x.get('organization_id'))}).", x.get("created_at"),
                     "#/api-keys?id=" + quote(str(x["id"]), safe=""))
        c.run("api_key_expiring", keys)

        def suspended():
            r.require("organizations", "subscription_status")
            for x in r.rows("organizations", "SELECT id, name, updated_at FROM organizations WHERE subscription_status = 'suspended' "
                                             "ORDER BY updated_at DESC LIMIT 50"):
                item(f"org_suspended:{x['id']}", "warn", "org_suspended", f"Organization suspended: {x.get('name') or x['id']}",
                     "Every request from this organization is refused until it is resumed.", x.get("updated_at"),
                     f"#/customers/{quote(str(x['id']), safe='')}")
        c.run("org_suspended", suspended)

        def break_glass():  # shared platform key used in production/staging (services/operator_auth.py)
            r.require("platform_admin_events", "action", "created_at")
            kind = r.ts_kind("platform_admin_events", "created_at")
            for x in r.rows("platform_admin_events", "SELECT id, actor_id, details_json, created_at FROM platform_admin_events "
                                                     "WHERE action = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 20",
                            ["platform.break_glass_used", ts_bound(kind, now - timedelta(hours=24))]):
                details = x.get("details_json")
                if isinstance(details, str):
                    try:
                        details = json.loads(details or "{}")
                    except ValueError:
                        details = {}
                details = details if isinstance(details, dict) else {}
                item(f"break_glass:{x['id']}", "critical", "break_glass", "Break-glass platform key used",
                     f"{details.get('method') or ''} {details.get('path') or ''} in {details.get('environment') or 'production'}"
                     f" from {details.get('ip') or 'unknown address'}. Disable MORROW_ALLOW_BREAK_GLASS_KEY when the emergency is over.",
                     x.get("created_at"), "#/audit")
        c.run("break_glass", break_glass)

        def mfa_enrolment():  # an authenticator appearing on an operator account (operator_auth.py)
            r.require("platform_admin_events", "action", "created_at")
            kind = r.ts_kind("platform_admin_events", "created_at")
            for x in r.rows("platform_admin_events", "SELECT id, action, actor_id, details_json, created_at "
                                                     "FROM platform_admin_events WHERE action IN (?, ?) AND created_at >= ? "
                                                     "ORDER BY created_at DESC LIMIT 20",
                            ["platform.mfa_enrolled", "platform.mfa_enrolment_refused",
                             ts_bound(kind, now - timedelta(days=7))]):
                details = x.get("details_json")
                if isinstance(details, str):
                    try:
                        details = json.loads(details or "{}")
                    except ValueError:
                        details = {}
                details = details if isinstance(details, dict) else {}
                refused = x.get("action") == "platform.mfa_enrolment_refused"
                # Enrolment is the moment an operator account gains a durable second factor. A
                # legitimate onboarding and an intruder making stolen access permanent produce the
                # same row, so both are surfaced rather than left for someone to find in the log.
                item(f"mfa_enrolment:{x['id']}", "critical", "mfa_enrolment",
                     ("MFA enrolment refused: owner approval required" if refused
                      else f"Authenticator enrolled for {details.get('identity') or x.get('actor_id')}"),
                     f"{x.get('actor_id')} from {details.get('ip') or 'unknown address'}"
                     f"{'' if refused else ' — if this was not arranged, reset it and revoke that operator now.'}",
                     x.get("created_at"), "#/audit")
        c.run("mfa_enrolment", mfa_enrolment)

        def support_sessions():  # vendor support "view as customer" sessions in progress
            from services import support_sessions as _support
            for x in _support.list_sessions(active=True, limit=50):
                item(f"support_session:{x['id']}", "warn" if x.get("break_glass") else "info", "support_session",
                     f"Support viewing {org_label(x.get('organization_id'))} as the customer (read-only)",
                     f"{x.get('operator_display') or x.get('operator_id')} · {str(x.get('reason') or '')[:120]} · ends {x.get('expires_at')}",
                     x.get("created_at"), "#/support-sessions?org=" + quote(str(x.get("organization_id") or ""), safe=""))
        c.run("support_session", support_sessions)


    def maintenance():
        state = hooks["maintenance"]() or {}
        if not state.get("enabled"):
            return
        if state.get("overdue"):
            item(f"maintenance_overdue:{state.get('updated_at') or ''}", "critical", "maintenance_overdue",
                 "Maintenance window is overdue", f"Maintenance mode is still on after its end time {state.get('ends_at')}.",
                 state.get("updated_at"), "#/maintenance")
        else:
            item(f"maintenance:{state.get('updated_at') or ''}", "warn", "maintenance", "Maintenance mode is on",
                 str(state.get("message") or "")[:200] + (f" Ends {state.get('ends_at')}." if state.get("ends_at") else ""),
                 state.get("updated_at"), "#/maintenance")
    c.run("maintenance", maintenance)

    def gate():
        result = hooks["go_live_gate"]() or {}
        failed = result.get("failed_required_checks") or []
        warnings = result.get("warnings") or []
        if not failed and not warnings:
            return
        keys_ = sorted(str(x.get("key") or "") for x in failed)
        digest = hashlib.sha256(json.dumps([keys_, [str(w) for w in warnings]]).encode()).hexdigest()[:12]
        labels = ", ".join(str(x.get("label") or x.get("key") or "") for x in failed[:8])
        item(f"go_live_gate:{digest}", "warn", "go_live_blockers",
             f"Go-live gate: {len(failed)} required check(s) failing" + (f", {len(warnings)} warning(s)" if warnings else ""),
             (labels + ("…" if len(failed) > 8 else "")) or "; ".join(str(w) for w in warnings[:3]),
             result.get("generated_at"), "#/readiness")
    c.run("go_live_blockers", gate)

    def findings():
        for x in hooks["security_findings"]() or []:
            sev = str(x.get("severity") or "").lower()
            if str(x.get("status") or "open") != "open" or sev not in ("critical", "high"):
                continue
            item(f"security_finding:{x.get('id')}", "critical" if sev == "critical" else "warn", "security_finding",
                 f"Open {sev} finding: {str(x.get('title') or '')[:120]}",
                 f"{x.get('tool_source') or 'external'} · {org_label_plain(x.get('organization_id'))}", x.get("created_at"),
                 "#/security-truth")
    c.run("security_finding", findings)

    def incidents():
        snap = hooks["incidents"]() or {}
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for x in snap.get("incidents") or []:
            groups.setdefault(str(x.get("category") or "incident"), []).append(x)
        for cat, rows in groups.items():
            sev = "critical" if any(str(x.get("severity")) in ("high", "critical") for x in rows) else "warn"
            item(f"incident:{cat}:{len(rows)}", sev, "incident", f"{len(rows)} {cat.replace('_', ' ')} incident(s) in the live window",
                 str(rows[-1].get("title") or "")[:200], snap.get("generated_at"), "#/incidents")
    c.run("incident", incidents)

    def abuse():
        snap = hooks["abuse"]() or {}
        events = snap.get("rate_limited_events") or []
        if not events:
            return
        latest = max((str(e.get("created_at") or "") for e in events), default="")
        by_source: Dict[str, int] = {}
        for e in events:
            by_source[str(e.get("source") or "rate_limit")] = by_source.get(str(e.get("source") or "rate_limit"), 0) + 1
        item(f"abuse:{latest}", "warn", "abuse", f"{len(events)} rate-limit / abuse signal(s) in the live window",
             ", ".join(f"{k}: {v}" for k, v in sorted(by_source.items())), latest or snap.get("generated_at"), "#/abuse")
    c.run("abuse", abuse)

    items.sort(key=lambda x: x["created_at"] or "", reverse=True)
    counts = {"critical": 0, "warn": 0, "info": 0}
    for x in items:
        counts[x["severity"]] += 1
    counts["total"] = len(items)
    return {"api_version": "v1", "generated_at": iso(now_utc()), "counts": counts, "items": items[:max(1, int(limit))],
            "unavailable": c.unavailable}


def org_label_plain(oid: Any) -> str:
    return str(oid or "") or "platform"


# ── 6) Jobs ──────────────────────────────────────────────────────────────────


def jobs(hooks: Dict[str, Callable[[], Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or now_utc()
    day_ago = now - timedelta(hours=24)
    out: List[Dict[str, Any]] = []

    def job(key: str, label: str, kind: str, status: str, last_run_at: Any = None, next_run_at: Any = None,
            last_error: Optional[str] = None, runs_24h: Optional[int] = None, source: str = "", detail: str = "") -> None:
        out.append({"key": key, "label": label, "kind": kind, "status": status, "last_run_at": ts_iso(last_run_at),
                    "next_run_at": ts_iso(next_run_at), "last_error": last_error or None, "runs_24h": runs_24h,
                    "source": source, "detail": detail})

    def guarded(key: str, label: str, kind: str, source: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except SourceMissing as exc:
            job(key, label, kind, "unknown", source=source, detail=str(exc))
        except Exception as exc:
            job(key, label, kind, "unknown", source=source, detail=f"State could not be read: {exc.__class__.__name__}")

    with Reader() as r:
        def scheduler():
            r.require("scan_schedules", "enabled", "last_run_at", "next_run_at", "last_status", "last_error")
            agg = r.one("scan_schedules",
                        "SELECT COUNT(*) AS total, SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled, "
                        "MAX(last_run_at) AS last_run, SUM(CASE WHEN last_run_at >= ? THEN 1 ELSE 0 END) AS ran_24h FROM scan_schedules",
                        [ts_bound("iso", day_ago)])
            nxt = r.one("scan_schedules", "SELECT MIN(next_run_at) AS n FROM scan_schedules WHERE enabled = 1 AND next_run_at IS NOT NULL "
                                          "AND next_run_at <> ''")
            latest = r.rows("scan_schedules", "SELECT last_status, last_error FROM scan_schedules WHERE last_run_at IS NOT NULL "
                                              "AND last_run_at <> '' ORDER BY last_run_at DESC LIMIT 1")
            errors = r.one("scan_schedules", "SELECT COUNT(*) AS n FROM scan_schedules WHERE enabled = 1 AND last_status = 'error'")
            loop = hooks["scheduler_running"]()
            enabled = _num(agg.get("enabled"))
            if _num(errors.get("n")):
                status = "error"
            elif latest:
                status = "ok"
            else:
                status = "idle"
            detail = f"{enabled} enabled of {_num(agg.get('total'))} schedules; loop " + (
                "running (checks every 5 minutes)" if loop else "not running in this process" if loop is False else "state unknown")
            job("scan_scheduler", "Scheduled scans", "scheduler", status, agg.get("last_run"), nxt.get("n"),
                (latest[0].get("last_error") if latest else None), _num(agg.get("ran_24h")),
                "scan_schedules.last_run_at, next_run_at, last_status, last_error",
                detail + ". runs_24h counts schedules whose latest run is in the last 24h (only the latest run is stored).")
        guarded("scan_scheduler", "Scheduled scans", "scheduler", "scan_schedules", scheduler)

        def validation():
            r.require("validation_jobs", "status", "created_at", "updated_at")
            latest = r.rows("validation_jobs", "SELECT status, stderr, updated_at, finished_at FROM validation_jobs "
                                               "ORDER BY updated_at DESC LIMIT 1")
            agg = r.one("validation_jobs", "SELECT COUNT(*) AS total, SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS runs, "
                                           "SUM(CASE WHEN status IN ('queued','running','pending') THEN 1 ELSE 0 END) AS active "
                                           "FROM validation_jobs", [ts_bound(r.ts_kind("validation_jobs", "created_at"), day_ago)])
            if not latest:
                job("validation_jobs", "Remediation validation", "validation", "idle", runs_24h=0, source="validation_jobs",
                    detail="No validation job has run.")
                return
            st = str(latest[0].get("status") or "").lower()
            status = "error" if st in ("failed", "error") else "ok"
            job("validation_jobs", "Remediation validation", "validation", status, latest[0].get("finished_at") or latest[0].get("updated_at"),
                None, (str(latest[0].get("stderr") or "")[:300] if status == "error" else None), _num(agg.get("runs")),
                "validation_jobs.status, updated_at, finished_at",
                f"Latest status {st or 'unknown'}; {_num(agg.get('active'))} queued or running; {_num(agg.get('total'))} total. Runs on demand.")
        guarded("validation_jobs", "Remediation validation", "validation", "validation_jobs", validation)

        def digest():
            r.require("digest_snapshots", "taken_at")
            kind = r.ts_kind("digest_snapshots", "taken_at")
            agg = r.one("digest_snapshots", "SELECT MAX(taken_at) AS last, SUM(CASE WHEN taken_at >= ? THEN 1 ELSE 0 END) AS runs "
                                            "FROM digest_snapshots", [ts_bound(kind, day_ago)])
            job("digest", "Digest snapshots", "digest", "ok" if agg.get("last") else "idle", agg.get("last"), None, None,
                _num(agg.get("runs")), "digest_snapshots.taken_at",
                "Next run is not scheduled server-side; snapshots are taken when a digest is generated.")
        guarded("digest", "Digest snapshots", "digest", "digest_snapshots", digest)

        def drift():
            r.require("drift_snapshots", "created_at")
            kind = r.ts_kind("drift_snapshots", "created_at")
            agg = r.one("drift_snapshots", "SELECT MAX(created_at) AS last, SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS runs "
                                           "FROM drift_snapshots", [ts_bound(kind, day_ago)])
            job("drift_sentinel", "Drift sentinel snapshots", "scheduler", "ok" if agg.get("last") else "idle", agg.get("last"), None,
                None, _num(agg.get("runs")), "drift_snapshots.created_at", "Snapshots are taken when drift is checked.")
        guarded("drift_sentinel", "Drift sentinel snapshots", "scheduler", "drift_snapshots", drift)

        def retention():
            r.require("platform_admin_events", "action", "created_at")
            kind = r.ts_kind("platform_admin_events", "created_at")
            latest = r.rows("platform_admin_events", "SELECT created_at, reason, details_json FROM platform_admin_events "
                                                     "WHERE action = 'platform.retention_run' ORDER BY created_at DESC LIMIT 1")
            runs = r.one("platform_admin_events", "SELECT COUNT(*) AS n FROM platform_admin_events WHERE action = 'platform.retention_run' "
                                                  "AND created_at >= ?", [ts_bound(kind, day_ago)])
            if not latest:
                job("retention", "Data retention", "retention", "idle", runs_24h=0, source="platform_admin_events action=platform.retention_run",
                    detail="No retention run has been recorded. Runs are started by an operator (POST /platform/retention/run).")
                return
            mode = str(latest[0].get("reason") or "")
            job("retention", "Data retention", "retention", "ok", latest[0].get("created_at"), None, None, _num(runs.get("n")),
                "platform_admin_events action=platform.retention_run",
                f"Last run mode: {mode or 'unknown'}. Runs are operator-started; there is no schedule.")
        guarded("retention", "Data retention", "retention", "platform_admin_events", retention)

        def webhooks():
            parts, failures, deliveries, last, last_err = [], 0, 0, None, None
            if r.has("morrow_webhook_deliveries", "status", "created_at"):
                kind = r.ts_kind("morrow_webhook_deliveries", "created_at")
                agg = r.one("morrow_webhook_deliveries", "SELECT COUNT(*) AS n, SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS f, "
                                                      "MAX(created_at) AS last FROM morrow_webhook_deliveries WHERE created_at >= ?",
                            [ts_bound(kind, day_ago)])
                failures += _num(agg.get("f"))
                deliveries += _num(agg.get("n"))
                last = max(filter(None, [parse_ts(agg.get("last")), last]), default=None)
                err = r.rows("morrow_webhook_deliveries", "SELECT response_body FROM morrow_webhook_deliveries WHERE status = 'failed' "
                                                       "ORDER BY created_at DESC LIMIT 1")
                if err:
                    last_err = str(err[0].get("response_body") or "")[:300] or None
                parts.append("morrow_webhook_deliveries.status")
            if r.has("webhook_events", "status", "created_at", "error_text"):
                kind = r.ts_kind("webhook_events", "created_at")
                agg = r.one("webhook_events", "SELECT COUNT(*) AS n, SUM(CASE WHEN status IN ('failed','dead','dead_letter') THEN 1 ELSE 0 END) AS f, "
                                              "SUM(CASE WHEN status IN ('queued','processing') THEN 1 ELSE 0 END) AS q, "
                                              "MAX(created_at) AS last FROM webhook_events WHERE created_at >= ?", [ts_bound(kind, day_ago)])
                failures += _num(agg.get("f"))
                deliveries += _num(agg.get("n"))
                last = max(filter(None, [parse_ts(agg.get("last")), last]), default=None)
                if not last_err:
                    err = r.rows("webhook_events", "SELECT error_text FROM webhook_events WHERE status IN ('failed','dead','dead_letter') "
                                                   "ORDER BY created_at DESC LIMIT 1")
                    if err:
                        last_err = str(err[0].get("error_text") or "")[:300] or None
                parts.append("webhook_events.status")
            if not parts:
                raise SourceMissing("Neither morrow_webhook_deliveries nor webhook_events exists.")
            status = "error" if failures else ("ok" if deliveries else "idle")
            job("webhook_deliveries", "Webhook deliveries", "webhook", status, last, None, last_err if failures else None, deliveries,
                ", ".join(parts), f"{failures} failed of {deliveries} deliveries in the last 24h.")
        guarded("webhook_deliveries", "Webhook deliveries", "webhook", "morrow_webhook_deliveries, webhook_events", webhooks)

        def usage_rollups():
            from services import usage_rollups as ur
            r.require("platform_usage_rollup_state", "state_key", "state_value")
            state = {str(row["state_key"]): str(row["state_value"]) for row in r.rows(
                "platform_usage_rollup_state", "SELECT state_key, state_value FROM platform_usage_rollup_state "
                                               "WHERE state_key IN ('last_run_at', 'last_success_at', 'last_error', 'last_days_rolled')")}
            extent = ur.rollup_extent(r)
            last_run = state.get("last_run_at")
            error = state.get("last_error") or None
            status = "error" if error else ("ok" if last_run else "idle")
            nxt = (parse_ts(last_run) + timedelta(seconds=ur.interval_seconds())) if last_run and ur.enabled() else None
            job("usage_rollups", "Daily usage rollups", "rollup", status, last_run, nxt,
                f"Last run failed: {error}" if error else None, None, "platform_usage_rollup_state, platform_usage_rollup_days",
                f"{extent['days']} day(s) rolled up ({extent['first_day'] or 'none'} to {extent['last_day'] or 'none'}); "
                f"last pass rolled {state.get('last_days_rolled', '0')} day(s). Runs at start-up and every "
                f"{int(ur.interval_seconds())} s in each API process" + ("" if ur.enabled() else " (disabled: MORROW_USAGE_ROLLUPS_ENABLED=0)")
                + ". runs_24h is not tracked.")
        guarded("usage_rollups", "Daily usage rollups", "rollup", "platform_usage_rollup_state", usage_rollups)

        def analytics_snapshots():
            state = hooks["analytics_snapshots"]()
            ranges = state.get("ranges") or {}
            ages = [v.get("age_seconds") for v in ranges.values() if v.get("age_seconds") is not None]
            built = [key for key, v in ranges.items() if v.get("computed_at")]
            last = max((v.get("computed_at") for v in ranges.values() if v.get("computed_at")), default=None)
            interval = float(state.get("interval_seconds") or 0)
            if not state.get("enabled"):
                status = "idle"
            elif not built:
                status = "idle"
            elif ages and max(ages) > interval * 3:
                status = "error"
            else:
                status = "ok"
            slowest = max((v.get("duration_ms") or 0) for v in ranges.values()) if built else 0
            nxt = (parse_ts(last) + timedelta(seconds=interval)) if last and state.get("enabled") else None
            job("analytics_snapshots", "Operator analytics snapshots", "rollup", status, last, nxt,
                None, None, "platform_analytics_snapshots",
                f"{len(built)} of {len(ranges)} range(s) built ({', '.join(sorted(built)) or 'none'}); "
                f"oldest {int(max(ages)) if ages else 0} s old; slowest computation {int(slowest)} ms. "
                f"Refreshed every {int(interval)} s"
                + ("" if state.get("enabled") else " (disabled: MORROW_ANALYTICS_SNAPSHOTS_ENABLED=0)")
                + f". A range with no snapshot is computed on the request only while the journal holds at most "
                  f"{state.get('inline_max_rows')} rows.")
        guarded("analytics_snapshots", "Operator analytics snapshots", "rollup", "platform_analytics_snapshots",
                analytics_snapshots)

    def journal():
        state = hooks["journal_state"]() or {}
        pending = state.get("pending")
        alive = state.get("writer_alive")
        traffic = state.get("traffic") or {}
        last_ok, last_fail = traffic.get("last_success_at"), traffic.get("last_failure_at")
        if last_fail and (not last_ok or str(last_fail) > str(last_ok)):
            status = "error"
        elif last_ok:
            status = "ok"
        elif alive is None:
            status = "unknown"
        else:
            status = "idle"
        job("traffic_journal", "Request journal writer", "journal", status, last_ok, None,
            (f"Write failed at {last_fail} ({traffic.get('failed_writes', 0)} failed batches since start)" if status == "error" else None),
            None, "services/security_journal in-process writer state",
            f"Queue depth {pending if pending is not None else 'unknown'}; writer thread "
            f"{'running' if alive else 'not started in this process' if alive is False else 'unknown'}; flushes every "
            f"{state.get('flush_interval_seconds', '?')}s. runs_24h is not tracked. State is per API process.")
    guarded("traffic_journal", "Request journal writer", "journal", "services/security_journal", journal)

    def maint_cache():
        state = hooks["maintenance_cache"]() or {}
        loaded = state.get("loaded_at")
        if not loaded:
            job("maintenance_cache", "Maintenance state cache", "cache", "idle", None, None, None, None, "services/announcements._MAINT_CACHE",
                "Not loaded yet in this process.")
            return
        job("maintenance_cache", "Maintenance state cache", "cache", "ok", loaded, state.get("next_refresh_at"), None, None,
            "services/announcements._MAINT_CACHE",
            f"TTL {state.get('ttl_seconds')}s; refreshed on demand by the maintenance guard. Maintenance "
            f"{'ON' if state.get('enabled') else 'off'}. State is per API process.")
    guarded("maintenance_cache", "Maintenance state cache", "cache", "services/announcements", maint_cache)

    def worker():
        info = hooks["worker_state"]() or {}
        job("celery_worker", "Async worker (Celery)", "worker", "unknown", None, None, None, None, "CELERY_BROKER_URL",
            info.get("detail") or "Worker heartbeats are not recorded, so worker health cannot be read from stored state.")
    guarded("celery_worker", "Async worker (Celery)", "worker", "CELERY_BROKER_URL", worker)

    def alert_dispatcher():
        info = hooks["alert_dispatcher"]() or {}
        job("alert_dispatcher", "Alert routing dispatcher", "dispatcher", str(info.get("status") or "unknown"), info.get("last_run_at"),
            info.get("next_run_at"), info.get("last_error"), info.get("runs_24h"), str(info.get("source") or ""), str(info.get("detail") or ""))
    if "alert_dispatcher" in hooks:
        guarded("alert_dispatcher", "Alert routing dispatcher", "dispatcher", "services/alert_routing", alert_dispatcher)

    return {"api_version": "v1", "generated_at": iso(now_utc()), "jobs": out}
