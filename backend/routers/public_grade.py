"""The public quantum-readiness grade API, for soqlab.com and for terminals.

  GET /api/public/grade/{domain}          the graded result (JSON); ?fresh=1 re-checks
  GET /api/public/grade/{domain}.txt      the same, as ~15 plain lines for curl
  GET /api/public/badge/{domain}.svg      a shields-style "quantum-ready | A" badge
  GET /api/public/stats                   aggregate counts only
  GET /api/public/history/{domain}        stored grades for one domain, newest first

Unauthenticated by design (listed in app._auth_public_path) and never unguarded: validation, the
SSRF guard, the opt-out list, per-IP / per-domain / global budgets, the concurrency cap and the
cache all live in services/public_grade.py. Errors are ``{"error", "detail"}`` with 400, 403, 429
(with Retry-After), 503 (switched off) or 504.

CORS is handled here rather than by the application-wide CORSMiddleware, which allows credentials
for the console's own origins: these routes allow only the configured public origins
(``MORROW_PUBLIC_API_CORS_ORIGINS``; default https://soqlab.com, https://www.soqlab.com and
http://localhost:3100), only GET/HEAD, and never credentials.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from services import public_grade as _grade
from services import route_paths as _route_paths

PREFIX = "/api/public"
_RESULT_CACHE = "public, max-age=300"
_BADGE_CACHE = "public, max-age=10800, s-maxage=10800"
_BADGE_UNKNOWN_CACHE = "public, max-age=300"
_DEFAULT_ORIGINS = "https://soqlab.com,https://www.soqlab.com,http://localhost:3100"


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _error_headers(exc: _grade.GradeError) -> dict:
    headers = {"Cache-Control": "no-store"}
    if exc.retry_after:
        headers["Retry-After"] = str(int(max(1, exc.retry_after)))
    return headers


def create_public_grade_router(deps: Any) -> APIRouter:
    """deps: client_ip(request) -> str."""
    router = APIRouter(prefix=PREFIX, tags=["public-grade"])

    def _ip(request: Request) -> str:
        getter = getattr(deps, "client_ip", None)
        if callable(getter):
            try:
                return str(getter(request) or "")
            except Exception:
                pass
        return str(request.client.host if request.client else "")

    # The .txt route is registered first: "/grade/{domain}" would otherwise also match
    # "/grade/example.com.txt" and try to grade a host called example.com.txt.
    @router.get("/grade/{domain}.txt", response_class=PlainTextResponse)
    async def public_grade_text(request: Request, domain: str, fresh: str = ""):
        try:
            result = await run_in_threadpool(_grade.check, domain, _ip(request), _truthy(fresh))
        except _grade.GradeError as exc:
            return PlainTextResponse(f"error: {exc.error}\n{exc.detail}\n", status_code=exc.status_code,
                                     headers=_error_headers(exc))
        return PlainTextResponse(_grade.render_text(result),
                                 headers={"Cache-Control": "no-store" if _truthy(fresh) else _RESULT_CACHE})

    @router.get("/grade/{domain}")
    async def public_grade_json(request: Request, domain: str, fresh: str = ""):
        try:
            result = await run_in_threadpool(_grade.check, domain, _ip(request), _truthy(fresh))
        except _grade.GradeError as exc:
            return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=_error_headers(exc))
        return JSONResponse(result, headers={"Cache-Control": "no-store" if _truthy(fresh) else _RESULT_CACHE})

    def _badge_grade(domain: str, client_ip: str) -> Optional[str]:
        try:
            host = _grade.normalize(domain)
        except _grade.GradeError:
            return None
        try:
            cached = _grade.latest(host, _grade.cache_seconds())
            if cached is not None:
                return str(cached.get("grade") or "") or None
            return str(_grade.check(host, client_ip).get("grade") or "") or None
        except _grade.GradeError as exc:
            if exc.error in ("refused_optout", "refused_target"):
                return None
            # Rate limited, busy or unreachable: an older grade is better than a grey badge.
            try:
                stale = _grade.latest(host)
            except Exception:
                return None
            return (str(stale.get("grade") or "") or None) if stale else None

    @router.get("/badge/{domain}.svg")
    async def public_grade_badge(request: Request, domain: str):
        grade = await run_in_threadpool(_badge_grade, domain, _ip(request))
        return Response(_grade.badge_svg(grade), media_type="image/svg+xml",
                        headers={"Cache-Control": _BADGE_CACHE if grade else _BADGE_UNKNOWN_CACHE})

    @router.get("/stats")
    async def public_grade_stats():
        return JSONResponse(await run_in_threadpool(_grade.stats), headers={"Cache-Control": "public, max-age=300"})

    @router.get("/history/{domain}")
    async def public_grade_history(domain: str, limit: int = 30):
        from services import public_check

        try:
            host = _grade.normalize(domain)
        except _grade.GradeError as exc:
            return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=_error_headers(exc))
        covered = await run_in_threadpool(public_check.opted_out, host)
        if covered:
            exc = _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
            return JSONResponse(exc.as_dict(), status_code=403, headers=_error_headers(exc))
        rows = await run_in_threadpool(_grade.history, host, limit)
        return JSONResponse(rows, headers={"Cache-Control": _RESULT_CACHE})

    return router


def allowed_origins() -> set:
    raw = str(os.getenv("MORROW_PUBLIC_API_CORS_ORIGINS", _DEFAULT_ORIGINS) or _DEFAULT_ORIGINS)
    return {o.strip().rstrip("/") for o in raw.split(",") if o.strip() and o.strip() != "*"}


class PublicApiCorsMiddleware(BaseHTTPMiddleware):
    """CORS for /api/public only: listed origins, GET/HEAD, no credentials.

    Installed outside the application-wide CORSMiddleware so a preflight is answered here, and any
    Access-Control-* header that middleware added (it allows credentials for the console's own
    origins) is replaced on these paths.
    """

    async def dispatch(self, request: Request, call_next):
        if not _route_paths.has_prefix(request.url.path, (PREFIX,)):
            return await call_next(request)
        origin = str(request.headers.get("origin") or "").rstrip("/")
        allowed = bool(origin) and origin in allowed_origins()
        if request.method == "OPTIONS":
            headers = {"Vary": "Origin"}
            wanted = str(request.headers.get("access-control-request-method") or "GET").upper()
            if allowed and wanted in ("GET", "HEAD"):
                headers.update({
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                    "Access-Control-Allow-Headers": "Accept, Content-Type",
                    "Access-Control-Max-Age": "600",
                })
            return Response(status_code=204, headers=headers)
        response = await call_next(request)
        for name in ("access-control-allow-origin", "access-control-allow-credentials",
                     "access-control-expose-headers", "access-control-allow-methods",
                     "access-control-allow-headers"):
            if name in response.headers:
                del response.headers[name]
        if allowed and request.method in ("GET", "HEAD"):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Expose-Headers"] = "Retry-After"
        vary = response.headers.get("vary")
        if not vary:
            response.headers["Vary"] = "Origin"
        elif "origin" not in vary.lower():
            response.headers["Vary"] = vary + ", Origin"
        return response
