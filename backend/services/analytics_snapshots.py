"""Precomputed operator-analytics snapshots.

The vendor portal's overview aggregates the whole request journal: counts, error rates, exact
percentiles, active users and top lists over 24 hours to 90 days. On a journal of a few million
rows that is tens of seconds to minutes of work, and it was being run *on the request*. Its
in-process cache had a 20-second TTL against a computation that took longer than that, so the
entry was stale before it could ever be served and every request recomputed; the background
warmer then kept a thread looping over four multi-minute aggregations forever, each holding a
pooled database connection (docs/LOAD_TEST_REPORT.md sections 4 and 10).

The dashboard is now served from a stored snapshot instead:

  * one row per (scope, range) in ``platform_analytics_snapshots``, holding the payload the
    overview produced and the instant it was computed;
  * a scheduled refresher (``maintain``) recomputes each range in turn, one at a time, at most
    once per ``MORROW_ANALYTICS_SNAPSHOT_INTERVAL_SECONDS``;
  * a read serves the last stored snapshot and says, in the payload, exactly when it was
    computed -- so the console can show "as of", not "refreshed" (which only ever meant "when
    your browser asked");
  * a cold read -- no snapshot yet -- is cheap by construction. It computes inline only when the
    journal is small enough for that to be quick (every small deployment and every test), and
    otherwise asks the refresher to build one and answers immediately with a well-formed payload
    whose numbers are null and whose ``unavailable`` says the first snapshot is still being
    computed. It never blocks a request behind a multi-minute aggregation.

Nothing about the numbers changes: a snapshot is the output of the same ``platform_analytics``
computation the request used to run, and every field of the response contract is preserved.

The table lives in the feature store (SQLite file or Postgres), so every API replica shares one
snapshot and one refresh schedule rather than each computing its own.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import db_feature_store as store

logger = logging.getLogger(__name__)
UTC = timezone.utc

SCOPE = "overview"
SCHEMA = """
    CREATE TABLE IF NOT EXISTS platform_analytics_snapshots (
        scope TEXT NOT NULL,
        range_key TEXT NOT NULL,
        computed_at TEXT NOT NULL,
        duration_ms REAL NOT NULL DEFAULT 0,
        payload TEXT NOT NULL,
        PRIMARY KEY (scope, range_key)
    );
"""

_lock = threading.RLock()
_ready: set = set()
#: In-process cache of the stored row, so a page that polls does not read the table every time.
_READ_TTL_SECONDS = 5.0
_read_cache: Dict[Any, Any] = {}
_refresh_lock = threading.Lock()
_refresh_requested: Dict[str, float] = {}
_inline_probe: Dict[str, Any] = {}


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def enabled() -> bool:
    return str(os.getenv("MORROW_ANALYTICS_SNAPSHOTS_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def interval_seconds() -> float:
    """How often a range is recomputed. Also the age past which a snapshot reads as stale."""
    try:
        return max(30.0, float(os.getenv("MORROW_ANALYTICS_SNAPSHOT_INTERVAL_SECONDS", "300") or 300))
    except ValueError:
        return 300.0


def inline_max_rows() -> int:
    """The journal size below which a cold read computes inline instead of answering "pending".

    Small deployments (and the test suite) keep the behaviour they had -- an exact answer on the
    first request -- while a journal large enough for the aggregation to take real time never
    blocks a request. 0 disables inline computation entirely.
    """
    try:
        return max(0, int(os.getenv("MORROW_ANALYTICS_INLINE_MAX_ROWS", "200000") or 200000))
    except ValueError:
        return 200000


def _key() -> str:
    from services import usage_rollups
    return usage_rollups._key()


def init_tables() -> None:
    key = _key()
    with _lock:
        if key in _ready:
            return
        with store.feature_conn() as conn:
            present = False
            if store.postgres_enabled():
                row = conn.execute("SELECT to_regclass('public.platform_analytics_snapshots')").fetchone()
                present = bool(row and row[0])
            if not present:
                conn.executescript(SCHEMA)
                conn.commit()
        _ready.add(key)


# ── Storage ──────────────────────────────────────────────────────────────────


def read(range_key: str) -> Optional[Dict[str, Any]]:
    """The stored snapshot for one range, or None. Cached in-process for a few seconds."""
    cache_key = (_key(), range_key)
    now = time.monotonic()
    hit = _read_cache.get(cache_key)
    if hit and hit[0] > now:
        return hit[1]
    try:
        init_tables()
        with store.feature_conn() as conn:
            row = conn.execute(
                "SELECT computed_at, duration_ms, payload FROM platform_analytics_snapshots "
                "WHERE scope = ? AND range_key = ?", (SCOPE, str(range_key))).fetchone()
    except Exception as exc:
        logger.debug("analytics snapshot read failed: %s", exc.__class__.__name__)
        return None
    found = None
    if row:
        try:
            found = {"computed_at": str(row[0]), "duration_ms": float(row[1] or 0),
                     "payload": json.loads(row[2])}
        except Exception:
            found = None
    _read_cache[cache_key] = (now + _READ_TTL_SECONDS, found)
    return found


def write(range_key: str, payload: Dict[str, Any], computed_at: datetime, duration_ms: float) -> None:
    init_tables()
    with store.feature_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO platform_analytics_snapshots "
            "(scope, range_key, computed_at, duration_ms, payload) VALUES (?, ?, ?, ?, ?)",
            (SCOPE, str(range_key), _iso(computed_at), float(duration_ms),
             json.dumps(payload, separators=(",", ":"))))
        conn.commit()
    _read_cache.pop((_key(), range_key), None)


def invalidate() -> None:
    """Drop every stored snapshot. Called by platform_analytics.clear_cache(), which is the
    "the data underneath may have changed" signal (tests, and an operator forcing a refresh)."""
    _read_cache.clear()
    _inline_probe.clear()
    try:
        init_tables()
        with store.feature_conn() as conn:
            conn.execute("DELETE FROM platform_analytics_snapshots WHERE scope = ?", (SCOPE,))
            conn.commit()
    except Exception as exc:
        logger.debug("analytics snapshot invalidate failed: %s", exc.__class__.__name__)


# ── Computing ────────────────────────────────────────────────────────────────


def compute(range_key: str) -> Dict[str, Any]:
    """Run the overview aggregation and store it. Returns the stored snapshot."""
    from services import platform_analytics as pa
    started = time.perf_counter()
    at = _now()
    payload = pa.overview(range_key)
    duration_ms = (time.perf_counter() - started) * 1000.0
    write(range_key, payload, at, duration_ms)
    return {"computed_at": _iso(at), "duration_ms": duration_ms, "payload": payload}


def refresh(range_key: str, force: bool = False) -> Optional[Dict[str, Any]]:
    """Recompute one range unless another process already did it inside the interval.

    Every replica runs the refresher. The advisory lock makes exactly one of them do the work for
    a given range; the others see a fresh snapshot when they re-read and skip it.
    """
    if not enabled():
        return None
    init_tables()
    interval = interval_seconds()
    if not force:
        current = read(range_key)
        if current and _age_seconds(current) < interval:
            return current
    if store.postgres_enabled():
        with store.feature_conn() as conn:
            got = conn.execute("SELECT pg_try_advisory_lock(hashtext(?))",
                               ("pq_analytics_snapshot:" + str(range_key),)).fetchone()
            if not (got and got[0]):
                return None  # another replica is computing this range right now
            try:
                if not force:
                    row = conn.execute(
                        "SELECT computed_at FROM platform_analytics_snapshots WHERE scope = ? AND range_key = ?",
                        (SCOPE, str(range_key))).fetchone()
                    stored = _parse(row[0]) if row else None
                    if stored and (_now() - stored).total_seconds() < interval:
                        return read(range_key)
                return compute(range_key)
            finally:
                try:
                    conn.execute("SELECT pg_advisory_unlock(hashtext(?))",
                                 ("pq_analytics_snapshot:" + str(range_key),))
                    conn.commit()
                except Exception:
                    pass
    return compute(range_key)


def _age_seconds(snapshot: Dict[str, Any]) -> float:
    at = _parse(snapshot.get("computed_at"))
    return 1e9 if at is None else max(0.0, (_now() - at).total_seconds())


def journal_rows_at_most(limit: int) -> int:
    """How big the journal is, answered no more precisely than `limit + 1`.

    The point is to decide whether an inline aggregation would be quick, and asking that question
    must not itself be slow on a multi-million-row table. On Postgres the planner's own estimate
    is exact enough for a yes/no and costs one catalogue lookup; a bounded count on 200,000 rows
    took 485 ms, which is not a question worth that. Elsewhere, and when the estimate is missing
    (a table that has never been analysed reports -1), a count that stops at the limit.
    """
    over = int(limit) + 1
    try:
        with store.feature_conn() as conn:
            if store.postgres_enabled():
                row = conn.execute(
                    "SELECT reltuples FROM pg_class WHERE oid = to_regclass('platform_request_events')"
                ).fetchone()
                estimate = float(row[0]) if row and row[0] is not None else -1.0
                if estimate >= 0:
                    return min(int(estimate), over)
            row = conn.execute(
                "SELECT COUNT(*) FROM (SELECT 1 FROM platform_request_events LIMIT ?) bounded",
                (over,)).fetchone()
        return int((row or [0])[0] or 0)
    except Exception:
        return over  # unknown: assume large and do not compute inline


def inline_ok() -> bool:
    """True when computing an overview on the request is cheap on this deployment."""
    limit = inline_max_rows()
    if limit <= 0:
        return False
    key, now = _key(), time.monotonic()
    hit = _inline_probe.get(key)
    if hit and hit[0] > now:
        return bool(hit[1])
    value = journal_rows_at_most(limit) <= limit
    _inline_probe[key] = (now + 60.0, value)
    return value


def request_refresh(range_key: str) -> bool:
    """Ask for a background refresh of one range. At most one thread, at most one per interval."""
    if not enabled():
        return False
    now = time.monotonic()
    with _lock:
        last = _refresh_requested.get(range_key, 0.0)
        if now - last < min(30.0, interval_seconds()):
            return False
        if not _refresh_lock.acquire(blocking=False):
            return False
        _refresh_requested[range_key] = now

    def work() -> None:
        try:
            refresh(range_key)
        except Exception as exc:
            logger.warning("analytics snapshot refresh failed for %s: %s", range_key, exc.__class__.__name__)
        finally:
            _refresh_lock.release()

    try:
        threading.Thread(target=work, name="analytics-snapshot-refresh", daemon=True).start()
    except Exception:
        _refresh_lock.release()
        return False
    return True


# ── Serving ──────────────────────────────────────────────────────────────────


def _pending_payload(range_key: str) -> Dict[str, Any]:
    """A well-formed overview whose numbers are null, for the first read of a large deployment."""
    from services import platform_analytics as pa
    win = pa.Window(range_key)
    reason = ("The operator analytics are precomputed on a schedule. No snapshot has been built for this "
              "range yet on this database; one is being computed now and will appear within "
              f"{int(interval_seconds())} seconds.")
    kpis = {key: pa.kpi(label, "", None, None) for key, label in pa.OVERVIEW_KPI_LABELS}
    series = {
        "signups": win.series({}, {"organizations": None, "users": None}),
        "active_users": win.series({}, {"value": None}),
        "logins": win.series({}, {"success": None, "failed": None}),
        "scans": win.series({}, {"value": None}),
        "requests": win.series({}, {"total": None, "client_errors": None, "server_errors": None, "rate_limited": None}),
        "latency": win.series({}, {"p50": None, "p95": None}),
        "feedback": win.series({}, {"value": None}),
        "admin_actions": win.series({}, {"value": None}),
    }
    return {
        "api_version": "v1", "generated_at": pa.iso(_now()), "range": win.range, "bucket": win.bucket,
        "kpis": kpis, "series": series,
        "top": {"organizations_by_activity": [], "routes_by_errors": [], "plans": []},
        "sources": {}, "unavailable": [{"metric": "overview", "reason": reason}],
        "coverage": pa._coverage(win, pa.journal_cutoff("auth", win.now), pa.journal_cutoff("traffic", win.now)),
    }


def serve(range_key: str) -> Dict[str, Any]:
    """The overview payload for one range, with the instant its numbers were computed.

    Adds to the response, without changing anything already in it:
      as_of     the instant the numbers were computed (null while the first snapshot is building)
      served_at the instant this response was produced
      snapshot  {state, computed_at, age_seconds, interval_seconds, duration_ms, source}
                state is "fresh", "stale" (serving the last snapshot while a newer one builds) or
                "pending" (no snapshot for this range yet).
    """
    from services import platform_analytics as pa
    interval = interval_seconds()
    snapshot = read(range_key) if enabled() else None
    source = "snapshot"
    state = "fresh"
    if snapshot is not None and _age_seconds(snapshot) < interval:
        pass
    elif inline_ok():
        # Cheap here: compute now so a small deployment keeps an exact, immediate answer.
        source, state = "inline", "fresh"
        if enabled():
            snapshot = refresh(range_key, force=True) or snapshot
        else:
            started, at = time.perf_counter(), _now()
            snapshot = {"computed_at": _iso(at), "duration_ms": (time.perf_counter() - started) * 1000.0,
                        "payload": pa.overview(range_key)}
    else:
        request_refresh(range_key)
        state = "stale" if snapshot is not None else "pending"

    if snapshot is None:
        payload = _pending_payload(range_key)
        meta = {"state": "pending", "computed_at": None, "age_seconds": None,
                "interval_seconds": interval, "duration_ms": None, "source": "pending"}
        return {**payload, "as_of": None, "served_at": pa.iso(_now()), "snapshot": meta}

    payload = dict(snapshot["payload"])
    age = _age_seconds(snapshot)
    meta = {"state": state, "computed_at": snapshot["computed_at"], "age_seconds": round(age, 1),
            "interval_seconds": interval, "duration_ms": round(float(snapshot.get("duration_ms") or 0), 1),
            "source": source}
    if state == "stale":
        note = (f"These numbers were computed {int(age)} seconds ago, which is past the "
                f"{int(interval)}-second refresh interval; a newer snapshot is being computed.")
        payload["unavailable"] = list(payload.get("unavailable") or []) + [
            {"metric": "overview.freshness", "reason": note}]
    return {**payload, "as_of": snapshot["computed_at"], "served_at": pa.iso(_now()), "snapshot": meta}


# ── Scheduling ───────────────────────────────────────────────────────────────


def run_once() -> Dict[str, Any]:
    """Refresh every range whose snapshot is older than the interval, one at a time."""
    from services import platform_analytics as pa
    from services.tenant_scope import platform_scope
    done: List[str] = []
    error = ""
    with platform_scope("analytics snapshots: cross-tenant operator overview"):
        try:
            # Build the analytics indexes here rather than on the first operator request: this is
            # the background thread, and creating them (a covering index over the request journal,
            # trigram indexes for search) is one-off work nobody should wait for.
            pa.ensure_indexes()
        except Exception as exc:
            logger.debug("analytics index preparation skipped: %s", exc.__class__.__name__)
        for range_key in pa.RANGES:
            try:
                current = read(range_key)
                if current and _age_seconds(current) < interval_seconds():
                    continue
                if refresh(range_key) is not None:
                    done.append(range_key)
            except Exception as exc:
                error = exc.__class__.__name__
                logger.error("analytics snapshot refresh failed for %s: %s", range_key, error)
    return {"refreshed": done, "error": error or None}


async def maintain(run_in_threadpool: Callable[..., Any]) -> None:
    """Periodic task for the API lifespan. One range at a time, never more than one at once."""
    # Stagger the first pass so several replicas starting together do not all compute at once.
    await asyncio.sleep(min(15.0, interval_seconds() / 4))
    while True:
        if enabled():
            try:
                await run_in_threadpool(run_once)
            except Exception as exc:  # never let the loop die
                logger.error("analytics snapshot task error: %s", exc.__class__.__name__)
        await asyncio.sleep(max(15.0, interval_seconds() / 4))


def state() -> Dict[str, Any]:
    """What /platform/jobs reports about this job."""
    from services import platform_analytics as pa
    out: Dict[str, Any] = {"enabled": enabled(), "interval_seconds": interval_seconds(),
                           "inline_max_rows": inline_max_rows(), "ranges": {}}
    for range_key in pa.RANGES:
        snapshot = read(range_key)
        out["ranges"][range_key] = {
            "computed_at": snapshot["computed_at"] if snapshot else None,
            "age_seconds": round(_age_seconds(snapshot), 1) if snapshot else None,
            "duration_ms": round(float(snapshot.get("duration_ms") or 0), 1) if snapshot else None,
        }
    return out
