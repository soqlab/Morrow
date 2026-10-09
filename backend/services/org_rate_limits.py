"""Per-organization rate limits: enforce admin_rate_limits (set from the vendor admin portal).

Two limits per organization, each a sliding window:
  api_calls_per_min  every request identified as that organization (see services/request_identity.py),
                     except exempt routes, within the last 60 seconds
  scans_per_hour     requests to a scan-starting endpoint (SCAN_START_PATTERNS, POST only) in the last hour

Each limit resolves in order: a stored operator override, otherwise the platform default in
PQC_ORG_DEFAULT_API_CALLS_PER_MIN / PQC_ORG_DEFAULT_SCANS_PER_HOUR (unset or 0: organizations with
neither are only subject to the existing per-IP limits). There used to be a billing-plan tier
between the two; the platform is free and that tier is gone, so an override is the only
per-organization limit. Overrides are read from the database at most once every
PQC_ORG_RATE_LIMIT_CACHE_SECONDS (default 15) per process; saving an override clears this process's cache.

Counters live in Redis when REDIS_URL or CELERY_BROKER_URL is set (shared by every replica, a sorted set per
organization and limit, checked and updated by one Lua script so replicas cannot over-admit), otherwise in process
memory. If Redis fails the in-process window is used for REDIS_RETRY_SECONDS before Redis is tried again, so a Redis
outage never blocks requests; during the outage each replica counts on its own.

Exempt: vendor-operator routes (/platform, /vendor-admin), health and status probes, the static UI, API docs,
the public pages, and the /auth namespace (sign-in has its own limits). Anonymous requests are never counted
here; the per-IP limiter covers them.

A request over a limit gets 429 with Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining and a detail that
names the limit; allowed requests from a limited organization carry the same X-RateLimit pair. Each 429 is
added to the in-process rate-limit observations that feed the Incidents & abuse view, and the traffic journal
records it with the organization id.
"""

from __future__ import annotations

import logging
import math
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Optional, Tuple

from fastapi.responses import JSONResponse

from services import request_identity

logger = logging.getLogger(__name__)

API_WINDOW_SECONDS = 60.0
SCAN_WINDOW_SECONDS = 3600.0

#: Scan-starting endpoints (paths after an optional /v1 prefix, POST only).
SCAN_START_PATTERNS = tuple(re.compile(p) for p in (
    r"^/scan$", r"^/scan/ssh$", r"^/scans/synthetic$", r"^/collections/[^/]+/scan$", r"^/scan-schedules/[^/]+/run$",
    r"^/supply-chain/scan$", r"^/secrets-scanner/(vault|aws|azure|env)$", r"^/cicd-gate/scan-(file|diff)$",
    r"^/sast/scan-(file|repo|github)$", r"^/observatory/trigger-scan$", r"^/binary/scan$", r"^/mobile-iot/scan$",
    r"^/dep-scan$", r"^/code/(github-)?crypto-discovery$",
))
EXEMPT_EXACT = frozenset({"/", "/health", "/healthz", "/status", "/robots.txt", "/favicon.ico", "/favicon.svg",
                          "/docs", "/openapi.json", "/redoc"})
EXEMPT_PREFIXES = ("/platform/", "/vendor-admin", "/health/", "/ui/", "/static/", "/auth/")

_clock: Callable[[], float] = time.time
_lock = threading.Lock()
_windows: Dict[Tuple[str, str], Deque[float]] = {}
_overrides: Dict[str, Any] = {"identity": None, "expires_at": 0.0, "rows": {}}
_redis: Dict[str, Any] = {"url": None, "client": None, "warned_at": 0.0, "down_until": 0.0, "script": None, "script_client": None}


def _flag(name: str, default: str) -> bool:
    return str(os.getenv(name, default) or default).strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str) -> int:
    try:
        return max(0, int(os.getenv(name, "0") or 0))
    except ValueError:
        return 0


def enabled() -> bool:
    return _flag("PQC_ORG_RATE_LIMITS_ENABLED", "1")


def cache_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("PQC_ORG_RATE_LIMIT_CACHE_SECONDS", "15") or 15))
    except ValueError:
        return 15.0


def normalize_path(path: str) -> str:
    p = str(path or "/")
    if p == "/v1":
        return "/"
    if p.startswith("/v1/"):
        return p[3:]
    return p


def is_exempt(path: str, is_public: Optional[Callable[[str], bool]] = None) -> bool:
    p = normalize_path(path)
    if p in EXEMPT_EXACT or p.startswith(EXEMPT_PREFIXES) or p == "/platform" or p == "/auth":
        return True
    if is_public is not None:
        try:
            return bool(is_public(p))
        except Exception:
            return False
    return False


def is_scan_start(method: str, path: str) -> bool:
    if str(method or "").upper() != "POST":
        return False
    p = normalize_path(path)
    return any(rx.match(p) for rx in SCAN_START_PATTERNS)


# ── Overrides ────────────────────────────────────────────────────────────────


def _identity() -> str:
    import db_feature_store as store
    try:
        return store.dialect() + ":" + (store._sqlite_path() if not store.postgres_enabled() else "pg")
    except Exception:
        return "unknown"


def overrides_stale() -> bool:
    return _overrides["identity"] != _identity() or _clock() >= float(_overrides["expires_at"] or 0)


def load_overrides() -> Dict[str, Tuple[int, int]]:
    """{org_id: (api_calls_per_min, scans_per_hour)} straight from the database."""
    from db_feature_store import feature_conn
    rows: Dict[str, Tuple[int, int]] = {}
    with feature_conn() as conn:
        for row in conn.execute("SELECT org_id, scans_per_hour, api_calls_per_min FROM admin_rate_limits").fetchall():
            rows[str(row[0])] = (int(row[2] or 0), int(row[1] or 0))
    return rows


def refresh_overrides() -> None:
    try:
        rows = load_overrides()
    except Exception as exc:  # table not created yet, or storage down: enforce defaults only, retry after the TTL
        logger.debug("org rate-limit overrides unavailable: %s", exc.__class__.__name__)
        rows = {}
    with _lock:
        _overrides.update({"identity": _identity(), "expires_at": _clock() + cache_seconds(), "rows": rows})


def invalidate() -> None:
    with _lock:
        _overrides["expires_at"] = 0.0


def stored_override(org_id: str) -> Optional[Tuple[int, int]]:
    try:
        return load_overrides().get(str(org_id))
    except Exception:
        return None


def source_label(limit_source: str) -> str:
    """Human wording for describe()["limit_source"], shared by the admin API note and the portal."""
    if limit_source == "override":
        return "operator override"
    if limit_source == "default":
        return "platform default"
    return "not limited"


def limits_for(org_id: str) -> Tuple[int, int]:
    """(api_calls_per_min, scans_per_hour) in force for an organization; 0 means not limited here.

    Precedence, per limit: an operator override saved in the admin portal, then the platform default
    from PQC_ORG_DEFAULT_*. A billing-plan tier used to sit between them.
    """
    row = (_overrides.get("rows") or {}).get(str(org_id))
    if row is not None:
        return int(row[0] or 0), int(row[1] or 0)
    return _int_env("PQC_ORG_DEFAULT_API_CALLS_PER_MIN"), _int_env("PQC_ORG_DEFAULT_SCANS_PER_HOUR")


def describe(org_id: str) -> Dict[str, Any]:
    """Enforcement state for the admin API (reads the database, not the cache)."""
    row = stored_override(org_id)
    api_default, scan_default = _int_env("PQC_ORG_DEFAULT_API_CALLS_PER_MIN"), _int_env("PQC_ORG_DEFAULT_SCANS_PER_HOUR")
    if row is not None:
        api, scans, source = row[0], row[1], "override"
    else:
        api, scans = api_default, scan_default
        source = "default" if (api_default or scan_default) else "none"
    active = enabled() and bool(api or scans)
    return {"override": row is not None, "enforced": active, "api_calls_per_min_enforced": api if enabled() else 0,
            "scans_per_hour_enforced": scans if enabled() else 0, "backend": "redis" if _redis_url() else "memory",
            "cache_seconds": cache_seconds(), "limit_source": source,
            "limit_source_label": source_label(source)}


# ── Counters ─────────────────────────────────────────────────────────────────


def _redis_url() -> str:
    return str(os.getenv("REDIS_URL") or os.getenv("CELERY_BROKER_URL") or "").strip()


def _redis_client(url: str):
    if _redis["client"] is None or _redis["url"] != url:
        import redis
        _redis["client"] = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
        _redis["url"] = url
        _redis["down_until"] = 0.0
    return _redis["client"]


#: After a Redis error, skip Redis for this long. Without it every request during an outage waits for the
#: connect timeout (1 s against an unreachable host) before falling back.
REDIS_RETRY_SECONDS = 5.0

# Check-then-add in one server-side step. KEYS[1] = the window key; ARGV = now, window, limit, member, ttl.
# Returns {allowed (0/1), count after this call, oldest score as a string ("" when allowed)}. Scores are
# returned as strings because Lua numbers are truncated to integers on the way back to the client.
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  return {0, count, oldest[2] or ARGV[1]}
end
redis.call('ZADD', key, now, ARGV[4])
redis.call('EXPIRE', key, tonumber(ARGV[5]))
return {1, count + 1, ''}
"""


def _hit_memory(kind: str, org: str, limit: int, window: float, now: float) -> Tuple[bool, int, float]:
    with _lock:
        q = _windows.get((kind, org))
        if q is None:
            q = _windows.setdefault((kind, org), deque())
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False, 0, max(0.0, q[0] + window - now)
        q.append(now)
        return True, max(0, limit - len(q)), 0.0


def _hit_redis(client: Any, kind: str, org: str, limit: int, window: float, now: float) -> Tuple[bool, int, float]:
    """One atomic Lua call: expire old entries, and admit (add) only while fewer than `limit` remain.

    Every replica shares the key, and Redis runs the script without interleaving, so concurrent requests can
    never both take the last slot, and a rejected request never occupies a slot, even briefly. The key's TTL
    is the window plus one second, so an idle organization leaves nothing behind.
    """
    key = f"pqc:orglimit:{kind}:{org}"
    member = f"{now:.6f}:{uuid.uuid4().hex[:8]}"
    script = _redis.get("script")
    if script is None or _redis.get("script_client") is not client:
        script = client.register_script(_SLIDING_WINDOW_LUA)
        _redis.update(script=script, script_client=client)
    allowed, count, oldest = script(keys=[key], args=[repr(float(now)), repr(float(window)), int(limit), member, int(math.ceil(window)) + 1])
    count = int(count)
    if not int(allowed):
        first = float(oldest.decode() if isinstance(oldest, bytes) else oldest)
        return False, 0, max(0.0, first + window - now)
    return True, max(0, limit - count), 0.0


def hit(kind: str, org: str, limit: int, window: float) -> Dict[str, Any]:
    now = _clock()
    url = _redis_url()
    if url and time.monotonic() >= float(_redis.get("down_until") or 0):
        try:
            allowed, remaining, retry = _hit_redis(_redis_client(url), kind, org, limit, window, now)
            return {"allowed": allowed, "remaining": remaining, "retry_after": retry, "backend": "redis"}
        except Exception as exc:
            _redis["down_until"] = time.monotonic() + REDIS_RETRY_SECONDS
            if now - float(_redis["warned_at"] or 0) > 60:
                _redis["warned_at"] = now
                logger.warning("organization rate limiter: Redis unavailable (%s); using in-process windows", exc.__class__.__name__)
    allowed, remaining, retry = _hit_memory(kind, org, limit, window, now)
    return {"allowed": allowed, "remaining": remaining, "retry_after": retry, "backend": "memory"}


def reset() -> None:
    """Clear counters and the override cache (tests, and an operator-driven reset)."""
    with _lock:
        _windows.clear()
        _overrides.update({"identity": None, "expires_at": 0.0, "rows": {}})
        _redis["down_until"] = 0.0


# ── Middleware ───────────────────────────────────────────────────────────────


def _attach_route(request: Any) -> str:
    """Record the matching route template on the scope, so the traffic journal logs "/scan-schedules/{id}/run"
    rather than a placeholder for a request answered before routing. Returns the template or the path."""
    try:
        from starlette.routing import Match
        router = getattr(request.scope.get("app"), "router", None)
        raw = str(request.scope.get("path") or "")
        for candidate in dict.fromkeys((raw, normalize_path(raw))):
            probe = {**request.scope, "path": candidate}
            for route in getattr(router, "routes", []):
                match, _ = route.matches(probe)
                if match == Match.FULL:
                    request.scope["route"] = route
                    return str(getattr(route, "path", "") or normalize_path(raw))
    except Exception:
        pass
    return normalize_path(request.url.path)


def _limited(kind: str, org: str, limit: int, result: Dict[str, Any], path: str, observations: Any) -> JSONResponse:
    retry = max(1, int(math.ceil(float(result["retry_after"] or 0))))
    if kind == "api":
        detail = (f"Organization API rate limit exceeded: {limit} requests per minute for organization '{org}'. "
                  f"Retry after {retry} s.")
    else:
        detail = (f"Organization scan limit exceeded: {limit} scans per hour for organization '{org}'. "
                  f"Retry after {retry} s.")
    if observations is not None:
        try:
            observations.append({
                "organization_id": org, "path": path,
                "source": "org_api_calls_per_min" if kind == "api" else "org_scans_per_hour",
                "limit": limit, "backend": result.get("backend"),
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            })
        except Exception:
            pass
    return JSONResponse(status_code=429, content={"detail": detail, "limit": limit, "window_seconds": int(API_WINDOW_SECONDS if kind == "api" else SCAN_WINDOW_SECONDS),
                                                  "retry_after_seconds": retry, "scope": "organization"},
                        headers={"Retry-After": str(retry), "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0",
                                 "X-RateLimit-Scope": "organization-api" if kind == "api" else "organization-scans"})


async def enforce(request: Any, call_next: Callable[[Any], Any], *, auth_mode: str, run_in_threadpool: Callable[..., Any],
                  is_public: Optional[Callable[[str], bool]] = None, observations: Any = None) -> Any:
    if not enabled() or request.method == "OPTIONS" or is_exempt(request.url.path, is_public):
        return await call_next(request)
    identity = request_identity.resolve(request, auth_mode)
    org = str(identity.get("organization_id") or "")
    if not identity.get("authenticated") or not org:
        return await call_next(request)
    if overrides_stale():
        await run_in_threadpool(refresh_overrides)  # never touch the database on the event loop
    api_limit, scan_limit = limits_for(org)
    scan = scan_limit > 0 and is_scan_start(request.method, request.url.path)
    if not api_limit and not scan:
        return await call_next(request)
    use_thread = bool(_redis_url())
    headers: Dict[str, str] = {}
    if api_limit:
        result = await run_in_threadpool(hit, "api", org, api_limit, API_WINDOW_SECONDS) if use_thread else hit("api", org, api_limit, API_WINDOW_SECONDS)
        if not result["allowed"]:
            return _limited("api", org, api_limit, result, _attach_route(request), observations)
        headers = {"X-RateLimit-Limit": str(api_limit), "X-RateLimit-Remaining": str(result["remaining"])}
    if scan:
        result = await run_in_threadpool(hit, "scan", org, scan_limit, SCAN_WINDOW_SECONDS) if use_thread else hit("scan", org, scan_limit, SCAN_WINDOW_SECONDS)
        if not result["allowed"]:
            return _limited("scan", org, scan_limit, result, _attach_route(request), observations)
        headers = {"X-RateLimit-Limit": str(scan_limit), "X-RateLimit-Remaining": str(result["remaining"]),
                   "X-RateLimit-Scope": "organization-scans"}
    response = await call_next(request)
    for name, value in headers.items():
        response.headers.setdefault(name, value)
    return response
