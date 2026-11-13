"""Vendor check, the change feed and sector reports: their public API and the signed-in vendor lists.

Public (unauthenticated, under /api/public, so app._auth_public_path and the public CORS policy
of routers/public_grade.py apply):

  POST   /api/public/vendors/check              {"domains": "<pasted text or file contents>"}
                                                -> 202 {token, manage_key, report_url, ...}
  GET    /api/public/vendors/report/{token}     the report as JSON (progress while it runs)
  GET    /api/public/vendors/report/{token}.csv the same, as CSV
  DELETE /api/public/vendors/report/{token}     revoke, with header X-Manage-Key
  GET    /api/public/changes[.atom|.rss]        what changed (services/changes.py); ?sector= ?kind=
  GET    /api/public/report                     every sector's headline (services/sector_report.py)
  GET    /api/public/report/{sector}[.csv]      one sector's report

Signed in (the organisation's own lists, under /instrument/vendor-checks; role-checked):

  GET    /instrument/vendor-checks              the organisation's reports and saved lists
  POST   /instrument/vendor-checks              {"domains", "name", "save", "interval_days"}
  GET    /instrument/vendor-checks/{id}         one report
  PATCH  /instrument/vendor-checks/{id}         {"revoke", "new_link", "save", "interval_days", "recheck"}
  DELETE /instrument/vendor-checks/{id}

Every guard lives in the services: the parser and caps, the SSRF guard and budgets of the public
grade, the per-IP / per-organisation / global vendor budgets, the link's expiry and revocation.
The read routes here add a per-IP budget of their own (``MORROW_PUBLIC_REPORTS_IP_PER_MINUTE``,
60) and short cache headers.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

PREFIX = "/api/public"
_NO_STORE = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}
_CACHE = "public, max-age=300"


def _ip_of(deps: Any, request: Request) -> str:
    getter = getattr(deps, "client_ip", None)
    if callable(getter):
        try:
            return str(getter(request) or "")
        except Exception:
            pass
    return str(request.client.host if request.client else "")


def _base(request: Request) -> str:
    from services.public_config import public_base_url

    return (public_base_url() or str(request.base_url)).rstrip("/")


def _read_budget(ip: str) -> Optional[JSONResponse]:
    from services import org_rate_limits, public_check

    try:
        limit = max(1, int(float(os.getenv("MORROW_PUBLIC_REPORTS_IP_PER_MINUTE", "60") or 60)))
    except ValueError:
        limit = 60
    hit = org_rate_limits.hit("public_reports_ip", public_check.hash_ip(ip), limit, 60.0)
    if hit.get("allowed"):
        return None
    retry = str(int(max(1, float(hit.get("retry_after") or 60))))
    return JSONResponse({"error": "rate_limited", "detail": f"More than {limit} requests a minute from your address."},
                        status_code=429, headers={"Retry-After": retry, "Cache-Control": "no-store"})


def _vendor_error(exc: Any) -> JSONResponse:
    headers = dict(_NO_STORE)
    if getattr(exc, "retry_after", None):
        headers["Retry-After"] = str(int(max(1, exc.retry_after)))
    return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=headers)


async def _json_body(request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _is_json(request: Request) -> bool:
    return str(request.headers.get("content-type") or "").split(";")[0].strip().lower() == "application/json"


def create_public_reports_router(deps: Any) -> APIRouter:
    """deps: client_ip(request) -> str."""
    router = APIRouter(prefix=PREFIX, tags=["public-reports"])

    # ── vendor check ──────────────────────────────────────────────────────

    @router.post("/vendors/check")
    async def vendor_check_create(request: Request):
        from services import vendor_check

        # JSON only: a cross-site form post cannot send it without a CORS preflight, which is refused.
        if not _is_json(request):
            return JSONResponse({"error": "bad_request", "detail": "Send JSON: {\"domains\": \"...\"}."},
                                status_code=415, headers=_NO_STORE)
        payload = await _json_body(request)
        try:
            body = await run_in_threadpool(lambda: vendor_check.create(
                payload.get("domains"), client_ip=_ip_of(deps, request), name=str(payload.get("name") or "")))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        return JSONResponse(body, status_code=202, headers=_NO_STORE)

    @router.get("/vendors/report/{token}.csv")
    async def vendor_check_csv(request: Request, token: str):
        from services import vendor_check

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        try:
            report = await run_in_threadpool(vendor_check.read, token, _base(request))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        stamp = str(report.get("finished_at") or report.get("updated_at") or "")[:10]
        return Response(vendor_check.to_csv(report), media_type="text/csv; charset=utf-8",
                        headers=dict(_NO_STORE, **{"Content-Disposition": f'attachment; filename="vendor-check-{stamp}.csv"'}))

    @router.get("/vendors/report/{token}")
    async def vendor_check_read(request: Request, token: str):
        from services import vendor_check

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        try:
            report = await run_in_threadpool(vendor_check.read, token, _base(request))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        return JSONResponse(report, headers=_NO_STORE)

    @router.delete("/vendors/report/{token}")
    async def vendor_check_revoke(request: Request, token: str):
        from services import vendor_check

        try:
            body = await run_in_threadpool(vendor_check.revoke_anonymous, token, str(request.headers.get("x-manage-key") or ""))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        return JSONResponse(body, headers=_NO_STORE)

    # ── what changed ──────────────────────────────────────────────────────

    @router.get("/changes.atom")
    async def changes_atom(request: Request, sector: str = ""):
        from services import changes

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        body = await run_in_threadpool(changes.atom, _base(request), sector[:40])
        return Response(body, media_type="application/atom+xml; charset=utf-8", headers={"Cache-Control": _CACHE})

    @router.get("/changes.rss")
    async def changes_rss(request: Request, sector: str = ""):
        from services import changes

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        body = await run_in_threadpool(changes.rss, _base(request), sector[:40])
        return Response(body, media_type="application/rss+xml; charset=utf-8", headers={"Cache-Control": _CACHE})

    @router.get("/changes")
    async def changes_json(request: Request, sector: str = "", kind: str = "", limit: int = 100):
        from services import changes

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        body = await run_in_threadpool(changes.feed, sector[:40], kind[:20], limit)
        return JSONResponse(body, headers={"Cache-Control": _CACHE})

    # ── sector reports ────────────────────────────────────────────────────

    @router.get("/report")
    async def report_index(request: Request):
        from services import sector_report

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        return JSONResponse(await run_in_threadpool(sector_report.index), headers={"Cache-Control": _CACHE})

    @router.get("/report/{sector}.csv")
    async def report_csv(request: Request, sector: str):
        from services import sector_report

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        try:
            r = await run_in_threadpool(sector_report.report, sector[:40])
        except sector_report.ReportError as exc:
            return JSONResponse({"error": "not_found", "detail": exc.detail}, status_code=exc.status_code)
        stamp = str(r.get("as_of") or r.get("generated_at") or "")[:10]
        return Response(sector_report.to_csv(r), media_type="text/csv; charset=utf-8",
                        headers={"Cache-Control": _CACHE,
                                 "Content-Disposition": f'attachment; filename="morrow-{r["id"]}-{stamp}.csv"'})

    @router.get("/report/{sector}")
    async def report_one(request: Request, sector: str):
        from services import sector_report

        limited = _read_budget(_ip_of(deps, request))
        if limited is not None:
            return limited
        try:
            r = await run_in_threadpool(sector_report.report, sector[:40])
        except sector_report.ReportError as exc:
            return JSONResponse({"error": "not_found", "detail": exc.detail}, status_code=exc.status_code)
        return JSONResponse(r, headers={"Cache-Control": _CACHE})

    return router


def create_vendor_console_router(deps: Any) -> APIRouter:
    """The organisation's own vendor lists.

    deps: require_role(request, roles, action, resource_type, resource_id), org_id() -> str,
    actor_id(request) -> str, audit(request, action, resource_type, resource_id, details), client_ip.
    """
    router = APIRouter(prefix="/instrument/vendor-checks", include_in_schema=False)
    readers = ["viewer", "analyst", "admin", "owner"]
    writers = ["analyst", "admin", "owner"]

    @router.get("")
    def vendor_lists(request: Request):
        from services import vendor_check

        deps.require_role(request, readers, "read", "vendor_check", "*")
        return JSONResponse({"reports": vendor_check.for_org(deps.org_id()),
                             "max_domains": vendor_check.max_domains(True)}, headers=_NO_STORE)

    @router.post("")
    async def vendor_list_create(request: Request):
        from services import vendor_check

        deps.require_role(request, writers, "create", "vendor_check", "*")
        payload = await _json_body(request)
        org = deps.org_id()
        actor = deps.actor_id(request)
        try:
            interval = int(payload.get("interval_days") or 7)
        except (TypeError, ValueError):
            interval = 7
        try:
            body = await run_in_threadpool(lambda: vendor_check.create(
                payload.get("domains"), client_ip=_ip_of(deps, request), org_id=org,
                name=str(payload.get("name") or ""), saved=bool(payload.get("save")), interval_days=interval, actor=actor))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        deps.audit(request, "vendor_check.created", "vendor_check", body["id"], {"domains": body["total"], "saved": body["saved"]})
        return JSONResponse(body, status_code=202, headers=_NO_STORE)

    @router.get("/{report_id}")
    def vendor_list_read(report_id: str, request: Request):
        from services import vendor_check

        deps.require_role(request, readers, "read", "vendor_check", report_id)
        try:
            return JSONResponse(vendor_check.org_report(deps.org_id(), report_id[:64], _base(request)), headers=_NO_STORE)
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)

    @router.patch("/{report_id}")
    async def vendor_list_update(report_id: str, request: Request):
        from services import vendor_check

        deps.require_role(request, writers, "update", "vendor_check", report_id)
        payload = await _json_body(request)

        def _opt_bool(key: str) -> Optional[bool]:
            return None if payload.get(key) is None else bool(payload.get(key))

        try:
            interval = None if payload.get("interval_days") is None else int(payload.get("interval_days"))
        except (TypeError, ValueError):
            interval = None
        try:
            body = await run_in_threadpool(lambda: vendor_check.org_update(
                deps.org_id(), report_id[:64], revoke=_opt_bool("revoke"), new_link=bool(payload.get("new_link")),
                saved=_opt_bool("save"), interval_days=interval, recheck=bool(payload.get("recheck"))))
        except vendor_check.VendorError as exc:
            return _vendor_error(exc)
        deps.audit(request, "vendor_check.updated", "vendor_check", report_id,
                   {k: payload.get(k) for k in ("revoke", "new_link", "save", "interval_days", "recheck") if k in payload})
        return JSONResponse(body, headers=_NO_STORE)

    @router.delete("/{report_id}")
    def vendor_list_delete(report_id: str, request: Request):
        from services import vendor_check

        deps.require_role(request, writers, "delete", "vendor_check", report_id)
        removed = vendor_check.org_delete(deps.org_id(), report_id[:64])
        if removed:
            deps.audit(request, "vendor_check.deleted", "vendor_check", report_id, {})
        return JSONResponse({"removed": removed}, status_code=200 if removed else 404, headers=_NO_STORE)

    return router
