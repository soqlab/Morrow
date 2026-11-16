"""Wall mode and display links (services/display_links.py).

  GET    /display-links              admin: the organization's links (never a token or hash) and the choices
  POST   /display-links              admin: a new link; the token is in the returned URL, once
  PATCH  /display-links/{id}         admin: change which number the screen shows
  DELETE /display-links/{id}         admin: revoke it; the screen stops at its next refresh
  GET    /api/public/wall            the screen: X-Display-Token is the only credential, and the only
                                     thing it opens. ETag / If-None-Match; 304 when nothing changed.

Creating, changing and revoking a link each write one audit entry.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from db import current_organization_id
from services import display_links

RequireRole = Callable[..., Dict[str, Any]]
ADMIN = ["admin", "owner"]
TOKEN_HEADER = "x-display-token"

#: Sent with every wall response. no-store: a screen's data never sits in a shared cache.
WALL_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
}


class CreateLink(BaseModel):
    name: str = Field("", max_length=display_links.NAME_MAX)
    metric: str = Field(display_links.DEFAULT_NUMBER, max_length=40)
    expires_in_days: int = Field(0, ge=0, le=365)


class UpdateLink(BaseModel):
    metric: str = Field(..., max_length=40)


def _org(request: Request) -> str:
    return str(getattr(request.state, "org_id", "") or current_organization_id())


def _who(request: Request, actor: Dict[str, Any]) -> str:
    claims = getattr(request.state, "auth_claims", {}) or {}
    label = claims.get("email") if isinstance(claims, dict) else ""
    return str(label or actor.get("actor_id") or "unknown")[:160]


def _audit(actor: Dict[str, Any], action: str, link_id: str, details: Dict[str, Any]) -> None:
    try:
        from db import append_audit_log

        append_audit_log(str(actor.get("actor_id") or ""), str(actor.get("actor_role") or ""), action,
                         "display_link", link_id, decision="allow", details=details)
    except Exception:
        pass


def create_display_links_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter(tags=["Wall mode"])

    def guard(request: Request, action: str, rid: str = "") -> Dict[str, Any]:
        return require_role(request, allowed_roles=ADMIN, action=action, resource_type="display_link",
                            resource_id=rid or _org(request))

    def run(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except display_links.DisplayLinkError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None

    @router.get("/display-links")
    def api_display_links(request: Request):
        guard(request, "display_link.list")
        return JSONResponse({"links": display_links.list_links(_org(request)), **display_links.options()},
                            headers={"Cache-Control": "no-store"})

    @router.post("/display-links")
    def api_display_link_create(body: CreateLink, request: Request):
        actor = guard(request, "display_link.create")
        link = run(display_links.create_link, _org(request), _who(request, actor), body.name, body.metric,
                   body.expires_in_days)
        _audit(actor, "display_link.create", link["id"],
               {"name": link["name"], "metric": link["metric"], "expires_at": link["expires_at"]})
        return JSONResponse(link, headers={"Cache-Control": "no-store"})

    @router.patch("/display-links/{link_id}")
    def api_display_link_update(link_id: str, body: UpdateLink, request: Request):
        actor = guard(request, "display_link.update", link_id)
        link = run(display_links.set_metric, _org(request), link_id, body.metric)
        _audit(actor, "display_link.update", link_id, {"metric": link["metric"]})
        return link

    @router.delete("/display-links/{link_id}")
    def api_display_link_revoke(link_id: str, request: Request):
        actor = guard(request, "display_link.revoke", link_id)
        link = run(display_links.revoke_link, _org(request), link_id, _who(request, actor))
        _audit(actor, "display_link.revoke", link_id, {"name": link["name"]})
        return link

    @router.get("/api/public/wall")
    async def api_wall(request: Request):
        try:
            link = await run_in_threadpool(display_links.resolve, request.headers.get(TOKEN_HEADER, ""))
            body = await run_in_threadpool(display_links.payload_for, link)
        except display_links.DisplayLinkError as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=WALL_HEADERS)
        tag = display_links.etag(body)
        headers = {**WALL_HEADERS, "ETag": tag}
        presented = [t.strip() for t in str(request.headers.get("if-none-match") or "").split(",")]
        if tag in presented or tag.replace('"', "") in presented:
            return Response(status_code=304, headers=headers)
        return JSONResponse(body, headers=headers)

    return router
