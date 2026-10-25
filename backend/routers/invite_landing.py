"""Invitation landing page and its supporting endpoints.

  GET  /invite                                   public page (static/invite.html); the token stays in the fragment
  POST /auth/invite/preview {token}              public, rate limited like the other /auth credential routes
  POST /platform/customers/{org}/invitations/{invite_id}/email   operator write role + reason; emails the
                                                 invited address only, never an arbitrary one
  GET  /platform/invitations/email-status        operator read role; whether invitation email is configured

Acceptance itself stays POST /admin/accept-invite (signed-in identity, email match, atomic claim).
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from services import invite_links as _links
from services import platform_mail as _mail
from services import platform_operators as _operators

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES


class InvitePreviewRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=512)


class InviteEmailRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


def create_invite_landing_router(deps: Any) -> APIRouter:
    """deps: static_dir, limiter, auth_rate, require_platform_admin(request, roles), record_event, org_exists(org_id)."""
    router = APIRouter()

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    @router.get("/invite", include_in_schema=False)
    def public_invite_page():
        path = os.path.join(deps.static_dir, "invite.html")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="invite.html not found")
        # no-store: the page is tiny, and nothing about an invitation should be cached by a proxy.
        return FileResponse(path, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": "no-store, must-revalidate", "X-Robots-Tag": "noindex, nofollow"})

    @router.post("/auth/invite/preview")
    @deps.limiter.limit(deps.auth_rate)
    def auth_invite_preview(request: Request, body: InvitePreviewRequest):
        summary = _links.preview(body.token)
        if summary is None:
            return JSONResponse({"detail": "Invitation not found. Check that the whole link was copied."}, status_code=404,
                                headers={"Cache-Control": "no-store"})
        return JSONResponse(summary, headers={"Cache-Control": "no-store"})

    @router.get("/platform/invitations/email-status")
    def platform_invitation_email_status(request: Request):
        guard(request, READ)
        return JSONResponse({"api_version": "v1", "email_configured": _mail.configured(),
                             "detail": "" if _mail.configured() else "Email isn't configured on this server (set MORROW_SMTP_HOST)."},
                            headers={"Cache-Control": "no-store"})

    @router.post("/platform/customers/{organization_id}/invitations/{invite_id}/email")
    async def platform_email_invitation(organization_id: str, invite_id: str, req: InviteEmailRequest, request: Request):
        guard(request, WRITE)
        if not deps.org_exists(organization_id):
            raise HTTPException(status_code=404, detail="Customer organization not found.")
        if not _mail.configured():
            raise HTTPException(status_code=503, detail="Email isn't configured on this server. Set MORROW_SMTP_HOST and MORROW_SMTP_FROM, "
                                                        "or copy the invite link and send it yourself.")
        invitation = await run_in_threadpool(_links.pending_token, organization_id, invite_id)
        if not invitation:
            raise HTTPException(status_code=404, detail="Pending invitation not found.")
        if invitation["expired"]:
            raise HTTPException(status_code=410, detail="This invitation has expired. Create a new one.")
        try:
            # Emailed, so the origin comes from configuration and never from the Host header.
            link = _links.external_invite_link(invitation["token"])
        except _links.PublicBaseUrlMissing as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        org_name = await run_in_threadpool(_links.organization_name, organization_id)
        message = _links.email_body(link, org_name, invitation["role"], invitation["expires_at"])
        result = await run_in_threadpool(_mail.send_text, [invitation["email"]], message["subject"], message["text"])
        deps.record_event(organization_id, "platform.invitation_emailed", req.reason, {
            "invite_id": invite_id, "email": invitation["email"], "sent": bool(result.get("ok")),
            "error": result.get("error") or ""})
        if not result.get("ok"):
            raise HTTPException(status_code=502, detail=f"The invitation email was not sent: {result.get('error')}")
        return JSONResponse({"ok": True, "invite_id": invite_id, "sent_to": _links.mask_email(invitation["email"])},
                            headers={"Cache-Control": "no-store"})

    return router
