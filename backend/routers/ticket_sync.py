"""Inbound Jira / ServiceNow status sync and its console settings.

The two inbound routes are reachable without a user session (they are listed in app._auth_public_path)
because Jira and ServiceNow cannot present one; each authenticates from its own signature or token
against the secret of the organization named in the URL. Logic lives in services/ticket_sync.py.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from db import current_organization_id
from services import ticket_sync as _ts


class ProviderRequest(BaseModel):
    provider: str = Field(..., pattern="^(jira|servicenow)$")


class PollRequest(ProviderRequest):
    poll_enabled: bool = False


def _raise(exc: _ts.TicketSyncError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None


def create_ticket_sync_router(require_role: Callable[..., Any], broker_ready: Callable[[], bool] = lambda: False) -> APIRouter:
    router = APIRouter(tags=["ticket-sync"])

    async def _inbound(provider: str, organization_id: str, request: Request) -> Dict[str, Any]:
        body = await request.body()
        headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            return await run_in_threadpool(_ts.handle_webhook, provider, organization_id, headers, body, broker_ready)
        except _ts.TicketSyncError as exc:
            _raise(exc)

    @router.post("/integrations/tickets/inbound/jira/{organization_id}")
    async def api_ticket_inbound_jira(organization_id: str, request: Request):
        """Jira Cloud webhook (Issue updated), signed with X-Hub-Signature: sha256=<hmac>."""
        return await _inbound("jira", organization_id, request)

    @router.post("/integrations/tickets/inbound/servicenow/{organization_id}")
    async def api_ticket_inbound_servicenow(organization_id: str, request: Request):
        """ServiceNow business-rule REST message, authenticated by bearer token or X-Morrow-Signature."""
        return await _inbound("servicenow", organization_id, request)

    @router.get("/tickets/sync/settings")
    def api_ticket_sync_settings(request: Request):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="tickets.sync.read",
                     resource_type="integration")
        return _ts.settings_view(current_organization_id(), base_url=str(request.base_url))

    @router.post("/tickets/sync/secret")
    def api_ticket_sync_rotate_secret(req: ProviderRequest, request: Request):
        actor = require_role(request, allowed_roles=["admin"], action="tickets.sync.rotate_secret",
                             resource_type="integration", resource_id=req.provider)
        org_id = current_organization_id()
        try:
            out = _ts.rotate_secret(org_id, req.provider)
        except _ts.TicketSyncError as exc:
            _raise(exc)
        try:
            from db import append_audit_log

            append_audit_log(actor_id=str((actor or {}).get("actor_id") or ""), actor_role=str((actor or {}).get("actor_role") or ""),
                             action="ticket_sync.secret_rotated", resource_type="integration", resource_id=req.provider,
                             decision="allow", reason="inbound ticket sync secret generated",
                             details={"provider": req.provider, "secret_hint": out["secret_hint"]})
        except Exception:
            pass
        url = _ts.public_base_url(str(request.base_url)) + _ts.webhook_path(req.provider, org_id)
        return {**out, "webhook_url": url, "shown_once": True}

    @router.post("/tickets/sync/settings")
    def api_ticket_sync_set_polling(req: PollRequest, request: Request):
        require_role(request, allowed_roles=["admin"], action="tickets.sync.configure",
                     resource_type="integration", resource_id=req.provider)
        out = _ts.set_poll_enabled(current_organization_id(), req.provider, req.poll_enabled)
        return {**out, "polling_available": _ts.poll_globally_enabled()}

    @router.get("/remediations/{remediation_id}/ticket-sync")
    def api_remediation_ticket_sync(remediation_id: int, request: Request):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="remediation.ticket_sync",
                     resource_type="remediation", resource_id=str(remediation_id))
        return _ts.remediation_sync_status(current_organization_id(), int(remediation_id))

    return router
