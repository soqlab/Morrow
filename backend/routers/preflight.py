"""Pre-flight over HTTP (services/preflight.py holds the probe, the verdict and the guard).

  GET /api/public/preflight/{domain}          public, no account: classical vs post-quantum ClientHello
                                              to the domain on port 443, and the verdict. One probe set
                                              per domain per MORROW_PREFLIGHT_MINUTES, whoever asks; inside
                                              that window the stored answer comes back with "cached": true.
                                              ?stored=1 only reads the newest stored answer (404 if none).
  GET /instrument/preflight/{host}?port=443   signed in (analyst, admin, owner): a host under one of the
                                              organization's verified domains, on the port it names. The
                                              same public-address guard; the organization's own budget.

Errors are ``{"error", "detail"}`` with 400, 403 (opted out, not public, not verified), 404, 429 (with
Retry-After) or 503, like the public grade. /api/public is already outside the auth gate
(app._auth_public_path) and under the public CORS policy (routers/public_grade.PublicApiCorsMiddleware).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from services import preflight as _preflight
from services import public_grade as _grade

_NO_STORE = {"Cache-Control": "no-store"}


def _error(exc: _grade.GradeError) -> JSONResponse:
    headers = dict(_NO_STORE)
    if exc.retry_after:
        headers["Retry-After"] = str(int(max(1, exc.retry_after)))
    return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=headers)


def _ip(deps: Any, request: Request) -> str:
    getter = getattr(deps, "client_ip", None)
    if callable(getter):
        try:
            return str(getter(request) or "")
        except Exception:
            pass
    return str(request.client.host if request.client else "")


def create_preflight_router(deps: Any) -> APIRouter:
    """deps: client_ip(request); for the signed-in route also require_role(request, roles, action,
    resource_type, resource_id), org_id() -> str and audit(request, action, resource_type, resource_id, details)."""
    router = APIRouter(include_in_schema=False)

    @router.get("/api/public/preflight/{domain}")
    async def public_preflight(request: Request, domain: str, stored: str = ""):
        try:
            if str(stored or "").strip().lower() in {"1", "true", "yes"}:
                body = await run_in_threadpool(_preflight.stored, domain)
                if body is None:
                    raise _grade.GradeError(404, "not_checked", "No pre-flight is stored for this domain yet.")
            else:
                body = await run_in_threadpool(_preflight.check, domain, _ip(deps, request))
        except _grade.GradeError as exc:
            return _error(exc)
        # A cached answer may be shared briefly; a new one is the same answer for the whole window.
        return JSONResponse(body, headers={"Cache-Control": "public, max-age=60"})

    @router.get("/instrument/preflight/{host}")
    async def owned_preflight(request: Request, host: str, port: str = "443"):
        require = getattr(deps, "require_role", None)
        if not callable(require):
            return JSONResponse({"error": "unavailable", "detail": "Signed-in pre-flight is not set up here."},
                                status_code=503, headers=_NO_STORE)
        require(request, ["analyst", "admin", "owner"], "run", "preflight", host[:253])
        org = str(deps.org_id() or "")
        try:
            body = await run_in_threadpool(_preflight.check_owned, org, host, port)
        except _grade.GradeError as exc:
            return _error(exc)
        audit = getattr(deps, "audit", None)
        if callable(audit) and not body.get("cached"):
            try:
                audit(request, "preflight.run", "preflight", f"{body['domain']}:{body['port']}",
                      {"verdict": body["verdict"]["id"]})
            except Exception:
                pass
        return JSONResponse(body, headers=_NO_STORE)

    return router
