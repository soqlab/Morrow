"""Make it safe over HTTP (services/make_safe.py holds the rules).

Public, unauthenticated, under prefixes the auth gate already lets through (/api/public and /r):

  GET  /api/public/make-safe/recipes              every recipe with its vendor sources and dates
  GET  /api/public/make-safe/{domain}             the fix for a graded host: its stack, the change,
                                                  ?stack=<id> to pick a stack by hand. Reads the stored
                                                  grade and public DNS; never contacts the host
  GET  /api/public/make-safe/{domain}/watch       the re-check session: status, when it may ask again
  POST /api/public/make-safe/{domain}/recheck     {start} one spaced re-check (a fresh public grade);
                                                  429 with Retry-After before the next slot
  POST /api/public/make-safe/{domain}/done/preview {provider, token} what Done would change at the DNS
                                                  provider, read with the person's token; changes nothing
  POST /api/public/make-safe/{domain}/done/apply   {preview_id, token} exactly the previewed change
  POST /api/public/make-safe/{domain}/done/undo    {change_id, token} put the previous state back
  GET  /r/{domain}/proof                          the quantum-safe proof page (stable, public, shareable)
  GET  /r/{domain}/proof.json                     the signed proof envelope

The Done routes read their body by hand, never through a validation model: FastAPI's 422 answer
echoes the offending input, and the input here is an API token. The token is passed to
services/make_safe_done.py for the one call and is never stored, logged or returned.

Every route refuses an opted-out domain. The proof routes read stored grades only: like the rest of
/r, nothing under them can start a check.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from services import make_safe as _safe
from services import make_safe_done as _done_svc
from services import make_safe_page as _page
from services import public_check as _check
from services import public_config as _public_config
from services import public_grade as _grade

_NO_STORE = {"Cache-Control": "no-store"}
#: Plans read DNS; a per-address budget keeps the endpoint from being a free DNS oracle.
PLAN_PER_MINUTE = 20
#: Done calls the DNS provider's API with the person's own token: a few per address, a few per domain.
DONE_PER_IP_10MIN = 20
DONE_PER_DOMAIN_HOUR = 40
DONE_MAX_BODY = 4096


class RecheckBody(BaseModel):
    start: bool = False


def _error(exc: Any) -> JSONResponse:
    headers = dict(_NO_STORE)
    retry = getattr(exc, "retry_after", None)
    if retry:
        headers["Retry-After"] = str(int(max(1, retry)))
    return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=headers)


def create_make_safe_router(deps: Any) -> APIRouter:
    """deps: client_ip(request) -> str."""
    router = APIRouter(include_in_schema=False)

    def _ip(request: Request) -> str:
        getter = getattr(deps, "client_ip", None)
        if callable(getter):
            try:
                return str(getter(request) or "")
            except Exception:
                pass
        return str(request.client.host if request.client else "")

    def _origin(request: Request) -> str:
        return (_public_config.public_base_url() or str(request.base_url)).rstrip("/")

    def _host(domain: str) -> str:
        host = _grade.normalize(domain)
        covered = _check.opted_out(host)
        if covered:
            raise _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
        return host

    @router.get("/api/public/make-safe/recipes")
    def make_safe_recipes():
        return JSONResponse(_safe.recipes(), headers={"Cache-Control": "public, max-age=3600"})

    @router.get("/api/public/make-safe/{domain}")
    async def make_safe_plan(request: Request, domain: str, stack: str = ""):
        try:
            host = _host(domain)
            from services import org_rate_limits

            hit = org_rate_limits.hit("make_safe_plan_ip", _check.hash_ip(_ip(request)), PLAN_PER_MINUTE, 60.0)
            if not hit.get("allowed"):
                raise _grade.GradeError(429, "rate_limited", "Too many requests from your address. Wait a moment.",
                                        retry_after=float(hit.get("retry_after") or 60))
            result = _grade.latest(host)
            if result is None:
                return JSONResponse({"error": "not_graded", "detail": f"{host} has not been graded yet. Open /{host} first."},
                                    status_code=404, headers=_NO_STORE)
            out = await run_in_threadpool(_safe.plan, host, result, str(stack or "")[:40])
        except _grade.GradeError as exc:
            return _error(exc)
        return JSONResponse(out, headers=_NO_STORE)

    @router.get("/api/public/make-safe/{domain}/watch")
    def make_safe_watch(domain: str):
        try:
            host = _host(domain)
        except _grade.GradeError as exc:
            return _error(exc)
        state = _safe.load_state(host)
        return JSONResponse({"domain": host, "watch": _safe.public_state(state) if state else None},
                            headers=_NO_STORE)

    @router.post("/api/public/make-safe/{domain}/recheck")
    async def make_safe_recheck(request: Request, domain: str, body: Optional[RecheckBody] = None):
        try:
            host = _host(domain)
            out = await run_in_threadpool(_safe.recheck, host, _ip(request), bool(body and body.start))
        except (_grade.GradeError, _safe.MakeSafeError) as exc:
            return _error(exc)
        return JSONResponse(out, headers=_NO_STORE)

    async def _done(request: Request, domain: str, action: str):
        from services import org_rate_limits

        try:
            host = _host(domain)
            if not _done_svc.enabled():
                raise _done_svc.DoneError(404, "disabled", "Done is switched off on this server.",
                                          "Follow the step-by-step recipe instead.")
            ip_hash = _check.hash_ip(_ip(request))
            for kind, key, limit, window in (("make_safe_done_ip", ip_hash, DONE_PER_IP_10MIN, 600.0),
                                             ("make_safe_done_domain", host, DONE_PER_DOMAIN_HOUR, 3600.0)):
                hit = org_rate_limits.hit(kind, key, limit, window)
                if not hit.get("allowed"):
                    raise _grade.GradeError(429, "rate_limited", "Too many Done requests. Wait a few minutes.",
                                            retry_after=float(hit.get("retry_after") or 60))
            raw = await request.body()
            if len(raw) > DONE_MAX_BODY:
                raise _done_svc.DoneError(413, "too_large", "That request is too large.", "")
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                body = None
            if not isinstance(body, dict):
                raise _done_svc.DoneError(400, "bad_request", "Send a JSON object.", "")
            token = body.get("token")
            if action == "preview":
                provider = str(body.get("provider") or "cloudflare")
                if provider != "cloudflare":
                    raise _done_svc.DoneError(400, "provider_unsupported", "Done works with Cloudflare for now.",
                                              "Follow the step-by-step recipe instead.")
                out = await run_in_threadpool(_done_svc.preview, host, token, ip_hash)
            elif action == "apply":
                out = await run_in_threadpool(_done_svc.apply, host, body.get("preview_id"), token, ip_hash)
            else:
                out = await run_in_threadpool(_done_svc.undo, host, body.get("change_id"), token, ip_hash)
            del token, body
        except (_grade.GradeError, _safe.MakeSafeError, _done_svc.DoneError) as exc:
            return _error(exc)
        return JSONResponse(out, headers=_NO_STORE)

    @router.post("/api/public/make-safe/{domain}/done/preview")
    async def make_safe_done_preview(request: Request, domain: str):
        return await _done(request, domain, "preview")

    @router.post("/api/public/make-safe/{domain}/done/apply")
    async def make_safe_done_apply(request: Request, domain: str):
        return await _done(request, domain, "apply")

    @router.post("/api/public/make-safe/{domain}/done/undo")
    async def make_safe_done_undo(request: Request, domain: str):
        return await _done(request, domain, "undo")

    def _proof(request: Request, domain: str):
        host = _grade.normalize(domain)
        covered = _check.opted_out(host)
        if covered:
            raise _safe.MakeSafeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
        return host, _safe.proof_envelope(host, _origin(request))

    @router.get("/r/{domain}/proof.json")
    def make_safe_proof_json(request: Request, domain: str):
        try:
            host, envelope = _proof(request, domain)
        except (_grade.GradeError, _safe.MakeSafeError) as exc:
            return _error(exc)
        return JSONResponse(envelope, headers={
            "Cache-Control": "public, max-age=60",
            "Access-Control-Allow-Origin": "*",
            "Content-Disposition": f'inline; filename="{host}-quantum-safe-proof.json"'})

    @router.get("/r/{domain}/proof")
    def make_safe_proof_page(request: Request, domain: str):
        origin = _origin(request)
        try:
            host = _grade.normalize(domain)
        except _grade.GradeError:
            return HTMLResponse(_page.render_missing(str(domain)[:253], origin, "not_a_domain"), status_code=404,
                                headers={**_NO_STORE, "X-Robots-Tag": "noindex, follow"})
        if host != domain:
            from fastapi.responses import RedirectResponse

            return RedirectResponse(f"/r/{host}/proof", status_code=301)
        if _check.opted_out(host):
            return HTMLResponse(_page.render_missing(host, origin, "refused_optout"), status_code=403,
                                headers={**_NO_STORE, "X-Robots-Tag": "noindex, follow"})
        rows = _grade.history_all(host, 1000)
        try:
            envelope = _safe.proof_envelope(host, origin, history=rows)
        except _safe.MakeSafeError as exc:
            if exc.error == "not_safe_yet":
                return HTMLResponse(_page.render_missing(host, origin, exc.error), status_code=404,
                                    headers={"Cache-Control": "public, max-age=60", "X-Robots-Tag": "noindex, follow"})
            # Signing is unavailable: say what the record shows, unsigned, and say that it is unsigned.
            return HTMLResponse(_page.render_unsigned(host, _safe.derive(rows), origin, exc.detail),
                                headers=_NO_STORE)
        return HTMLResponse(_page.render_proof(envelope, origin),
                            headers={"Cache-Control": "public, max-age=60"})

    return router
