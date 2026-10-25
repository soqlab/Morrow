"""Vendor admin portal: analytics, customer 360, product usage, global search, notifications and
background jobs.

Every endpoint needs a platform admin read role (owner, operator, support, auditor) through the same
guard as routers/platform_admin.py, answers with api_version "v1", generated_at and
Cache-Control: no-store, and never writes: no audit events are recorded for these reads, and results
are cached in-process for a few seconds keyed by (database, endpoint, range, organization).

Aggregation lives in services/platform_analytics.py; see its docstring for the storage model.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from services import analytics_snapshots as _snapshots
from services import platform_analytics as _pa
from services import platform_operators as _operators

READ = _operators.READ_ROLES
OWNER = _operators.OWNER_ROLES

#: In-process TTL for the endpoints that still aggregate on the request (customer 360 and usage).
#: The overview no longer uses it: it is served from a stored snapshot whose own refresh interval
#: is MORROW_ANALYTICS_SNAPSHOT_INTERVAL_SECONDS. A TTL shorter than the computation behind it can
#: never hold an answer, which is what made every overview request recompute.
ANALYTICS_TTL = 20.0
NOTIFICATIONS_TTL = 15.0
JOBS_TTL = 10.0
GATE_TTL = 60.0
FINDINGS_TTL = 30.0
SEARCH_TTL = 20.0


def _no_store(payload: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})


def _range(value: str) -> str:
    key = str(value or _pa.DEFAULT_RANGE).strip().lower()
    if key not in _pa.RANGES:
        raise HTTPException(status_code=400, detail="range must be one of 24h, 7d, 30d, 90d.")
    return key


def create_platform_analytics_router(deps: Any) -> APIRouter:
    """deps: require_platform_admin(request, roles), go_live_gate(request), security_findings(),
    incidents(), abuse(request), default_org_id."""
    router = APIRouter()

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    def prepare() -> None:
        try:
            _pa.ensure_indexes()
        except Exception:
            pass  # an index is an optimisation; reads still work without it

    # ── 1) Overview ──────────────────────────────────────────────────────────

    @router.get("/platform/analytics/overview")
    def platform_analytics_overview(request: Request, range: str = Query(_pa.DEFAULT_RANGE, max_length=8)):  # noqa: A002
        """The last computed snapshot for this range, with the instant it was computed.

        This used to run the whole aggregation on the request, behind a 20-second cache that could
        never hold an answer that took 30-250 seconds to produce. It is now precomputed on a
        schedule (services/analytics_snapshots) and served from storage; a range with no snapshot
        yet is computed inline only while the journal is small enough for that to be quick.
        """
        guard(request, READ)
        key = _range(range)
        prepare()
        payload = _snapshots.serve(key)
        _pa.warm_overviews()  # the other ranges, in the background, at most one per interval
        return _no_store(payload)

    # ── 2) Customer 360 ──────────────────────────────────────────────────────

    @router.get("/platform/analytics/customers/{organization_id}")
    def platform_analytics_customer(organization_id: str, request: Request,
                                    range: str = Query(_pa.DEFAULT_RANGE, max_length=8)):  # noqa: A002
        guard(request, READ)
        key = _range(range)
        oid = str(organization_id or "").strip()
        if not oid or len(oid) > 128:
            raise HTTPException(status_code=404, detail="Customer organization not found.")
        prepare()
        # Keyed by organization: one tenant's cached view is never served for another.
        payload = _pa.cached(("customer", oid, key), ANALYTICS_TTL, lambda: _pa.customer(oid, key))
        if payload is None:
            raise HTTPException(status_code=404, detail="Customer organization not found.")
        return _no_store(payload)

    # ── 3) Usage and adoption ────────────────────────────────────────────────

    @router.get("/platform/analytics/usage")
    def platform_analytics_usage(request: Request, range: str = Query(_pa.DEFAULT_RANGE, max_length=8)):  # noqa: A002
        guard(request, READ)
        key = _range(range)
        prepare()
        return _no_store(_pa.cached(("usage", key), ANALYTICS_TTL, lambda: _pa.usage(key)))

    # ── 4) Global search ─────────────────────────────────────────────────────

    @router.get("/platform/search")
    def platform_search(request: Request, q: str = Query("", max_length=200), limit: int = Query(20, ge=1, le=1000)):
        """Global search over customers, users, API keys, announcements, autopatches and feedback.

        Every predicate is a leading-wildcard LIKE, which no b-tree can serve; on Postgres they are
        backed by trigram indexes (services/platform_analytics.SEARCH_TRIGRAM_COLUMNS). This was
        also the one analytics endpoint with no cache at all, so a console searching as an operator
        types re-scanned every table on every keystroke. It now goes through the same short cache
        as its siblings, keyed by the query, the limit and whether the caller may see operators.
        """
        actor = guard(request, READ)
        text = str(q or "").strip()
        if len(text) < 2:
            raise HTTPException(status_code=400, detail="Search needs at least 2 characters.")
        lim = max(1, min(int(limit), 50))
        is_owner = actor.get("actor_role") in OWNER
        prepare()
        payload = _pa.cached(("search", text.lower(), lim, is_owner), SEARCH_TTL,
                             lambda: _pa.search(text, lim, is_owner, _operators.public_operator_list))
        # A copy: generated_at is when this response was produced, and must not be written into
        # the shared cached object.
        return _no_store({**payload, "generated_at": _pa.iso(_pa.now_utc())})

    # ── 5) Notifications ─────────────────────────────────────────────────────

    def maintenance_state() -> Dict[str, Any]:
        from services import announcements
        return announcements.get_maintenance()

    @router.get("/platform/notifications")
    def platform_notifications(request: Request):
        guard(request, READ)
        hooks = {
            "go_live_gate": lambda: _pa.cached(("go_live_gate",), GATE_TTL, lambda: deps.go_live_gate(request)),
            "security_findings": lambda: _pa.cached(("security_findings",), FINDINGS_TTL, deps.security_findings),
            "incidents": deps.incidents,
            "abuse": lambda: deps.abuse(request),
            "maintenance": maintenance_state,
        }
        return _no_store(_pa.cached(("notifications",), NOTIFICATIONS_TTL, lambda: _pa.notifications(hooks)))

    # ── 6) Background jobs ───────────────────────────────────────────────────

    def journal_state() -> Dict[str, Any]:
        from services import security_journal as sj
        key = sj._key()
        with sj._pending_lock:
            pending = len(sj._pending["rows"]) if sj._pending.get("key") == key else 0
        thread = sj._flusher.get("thread")
        with sj._lock:
            health = {kind: {k: v for k, v in value.items() if k != "last_warning"}
                      for kind, value in sj._health.get(key, {}).items()}
        return {"pending": pending, "writer_alive": bool(thread is not None and thread.is_alive()),
                "traffic": health.get("traffic") or {}, "flush_interval_seconds": sj._FLUSH_INTERVAL_SECONDS}

    def maintenance_cache_state() -> Dict[str, Any]:
        from services import announcements as ann
        cache = ann._MAINT_CACHE
        loaded = float(cache.get("loaded_at") or 0)
        if not loaded or cache.get("state") is None:
            return {}
        try:
            ttl = max(1.0, float(os.getenv("MORROW_MAINTENANCE_CACHE_SECONDS", "5") or 5))
        except ValueError:
            ttl = 5.0
        loaded_wall = datetime.now(timezone.utc) - timedelta(seconds=max(0.0, time.monotonic() - loaded))
        return {"loaded_at": loaded_wall, "next_refresh_at": loaded_wall + timedelta(seconds=ttl), "ttl_seconds": ttl,
                "enabled": bool((cache.get("state") or {}).get("enabled"))}

    def scheduler_running() -> Optional[bool]:
        try:
            from services import scan_scheduler
        except Exception:
            return None
        task = getattr(scan_scheduler, "_LOOP_TASK", None)
        return bool(task is not None and not task.done())

    def worker_state() -> Dict[str, Any]:
        if not os.getenv("CELERY_BROKER_URL"):
            return {"detail": "CELERY_BROKER_URL is not set; no async worker is configured."}
        return {"detail": "A broker is configured, but worker heartbeats are not recorded, so worker health is not "
                          "readable from stored state."}

    @router.get("/platform/jobs")
    def platform_jobs(request: Request):
        guard(request, READ)
        hooks = {"journal_state": journal_state, "maintenance_cache": maintenance_cache_state,
                 "scheduler_running": scheduler_running, "worker_state": worker_state,
                 "analytics_snapshots": _snapshots.state,
                 "alert_dispatcher": lambda: __import__("services.alert_routing", fromlist=["job_state"]).job_state()}
        return _no_store(_pa.cached(("jobs",), JOBS_TTL, lambda: _pa.jobs(hooks)))

    return router
