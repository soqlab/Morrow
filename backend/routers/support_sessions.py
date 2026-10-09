"""Vendor support "view as customer" endpoints. Logic and the enforcement policy live in
services/support_sessions.py; this module is HTTP only.

Platform (x-platform-key):
    POST /platform/customers/{org}/support-sessions      owner, operator, support
    GET  /platform/support-sessions                      any platform read role
    GET  /platform/support-sessions/{id}                 any platform read role (with request journal)
    POST /platform/support-sessions/{id}/revoke          owner, operator, support
Public:
    POST /auth/support-session/exchange                  one-time launch code -> support token
Support token:
    GET  /support-session/current                        banner data for the console
    POST /support-session/end                            the session ends itself
Customer console (normal customer identity):
    GET  /org/support-access                             setting for the active organization
    PUT  /org/support-access                             admin only
    GET  /org/support-access/history                     support sessions (tenant audit log) with every page each
                                                         session requested (path and time, this organization only)
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from services import support_sessions as _support

CREATE_ROLES = set(_support.ALLOWED_CREATE_ROLES)


class SupportSessionCreate(BaseModel):
    reason: str = Field(..., min_length=_support.MIN_REASON, max_length=500)
    minutes: int = Field(_support.DEFAULT_MINUTES, ge=_support.MIN_MINUTES, le=_support.MAX_MINUTES)
    ticket_ref: str = Field("", max_length=80)
    break_glass: bool = False


class SupportSessionRevoke(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class SupportCodeExchange(BaseModel):
    code: str = Field(..., min_length=16, max_length=256)


class SupportAccessUpdate(BaseModel):
    allowed: bool
    reason: str = Field("", max_length=500)


def _raise(exc: _support.SupportSessionError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None


def create_support_sessions_router(deps: Any) -> APIRouter:
    """deps: require_platform_admin(request, roles), require_role(request, roles, action, resource_type, resource_id),
    list_organizations(limit), org_of(request), list_audit_logs(limit, action)."""
    router = APIRouter()

    def org_record(organization_id: str) -> Optional[Dict[str, Any]]:
        oid = str(organization_id or "").strip()
        return next((o for o in deps.list_organizations(limit=2000) if str(o.get("id") or "") == oid), None)

    def support_claims(request: Request) -> Dict[str, Any]:
        claims = getattr(request.state, "auth_claims", {}) or {}
        if claims.get("typ") != _support.TOKEN_TYPE or not getattr(request.state, "support_session_id", ""):
            raise HTTPException(status_code=404, detail="No support session is attached to this request.")
        return claims

    # ── Platform ─────────────────────────────────────────────────────────────

    @router.post("/platform/customers/{organization_id}/support-sessions")
    def platform_create_support_session(organization_id: str, req: SupportSessionCreate, request: Request):
        actor = deps.require_platform_admin(request, CREATE_ROLES)
        role = str(actor.get("actor_role") or "")
        org = org_record(organization_id)
        if not org:
            raise HTTPException(status_code=404, detail="Customer organization not found.")
        status = str(org.get("subscription_status") or "active").lower()
        if status in {"suspended", "archived"} and role != "owner":
            raise HTTPException(
                status_code=403,
                detail=f"Organization is {status}. Only an owner can open a support session for a suspended or archived organization.",
            )
        if req.break_glass:
            raise HTTPException(status_code=403, detail="Support access cannot override customer consent.")
        access = _support.support_access(organization_id)
        break_glass = False
        if not access["allowed"]:
            raise HTTPException(status_code=403, detail="customer has disabled support access")
        _support.finalize_expired(organization_id)
        display = str(actor.get("claimed_user") or actor.get("display_name") or actor.get("email") or actor.get("actor_id") or "")
        try:
            created = _support.create_session(
                organization_id=organization_id, operator_id=str(actor.get("actor_id") or ""), operator_role=role,
                operator_display=display, reason=req.reason, minutes=req.minutes, ticket_ref=req.ticket_ref,
                break_glass=break_glass,
            )
        except _support.SupportSessionError as exc:
            _raise(exc)
        severity = "high" if break_glass else "info"
        extra: Dict[str, Any] = {"organization_status": status}
        if break_glass:
            extra["break_glass_note"] = "Customer had disabled vendor support access; an owner overrode it."
        written = _support.audit(created["row"], "started", reason=req.reason, severity=severity, extra=extra)
        return {
            "api_version": "v1",
            "session": created["session"],
            "launch_url": created["launch_url"],
            "launch_code_expires_in": created["launch_code_expires_in"],
            "audit": written,
            "notice": "Access is read-only, time-limited, logged, and visible to the customer in their audit log.",
        }

    @router.get("/platform/support-sessions")
    def platform_list_support_sessions(request: Request, organization_id: str = Query("", max_length=128),
                                       active: str = Query("", pattern="^(|true|false|1|0)$"),
                                       limit: int = Query(200, ge=1, le=1000)):
        deps.require_platform_admin(request, None)
        _support.finalize_expired()
        flag = None if active == "" else active in {"true", "1"}
        return {"api_version": "v1", "items": _support.list_sessions(organization_id.strip(), flag, limit),
                "limits": {"min_minutes": _support.MIN_MINUTES, "max_minutes": _support.MAX_MINUTES,
                           "launch_code_seconds": _support.CODE_TTL_SECONDS}}

    @router.get("/platform/support-sessions/{session_id}")
    def platform_get_support_session(session_id: str, request: Request, limit: int = Query(200, ge=1, le=1000)):
        deps.require_platform_admin(request, None)
        row = _support.get_session(session_id)
        if not row:
            raise HTTPException(status_code=404, detail="Support session not found.")
        return {"api_version": "v1", "session": _support.public_session(row), "requests": _support.list_requests(session_id, limit)}

    @router.post("/platform/support-sessions/{session_id}/revoke")
    def platform_revoke_support_session(session_id: str, req: SupportSessionRevoke, request: Request):
        actor = deps.require_platform_admin(request, CREATE_ROLES)
        try:
            session = _support.revoke_session(session_id, revoked_by=str(actor.get("actor_id") or ""), reason=req.reason)
        except _support.SupportSessionError as exc:
            _raise(exc)
        return {"ok": True, "session": session}

    # ── Launch code exchange (public: the code is the credential) ─────────────

    @router.post("/auth/support-session/exchange")
    def support_session_exchange(req: SupportCodeExchange):
        try:
            result = _support.exchange_code(req.code)
        except _support.SupportSessionError as exc:
            _raise(exc)
        session = result["session"]
        return {
            "access_token": result["access_token"],
            "token_type": "Bearer",
            "expires_at": session["expires_at"],
            "session": _banner(session),
        }

    # ── Support token ────────────────────────────────────────────────────────

    def _banner(session: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": session["id"], "organization_id": session["organization_id"],
            "operator": session.get("operator_display") or session.get("operator_id"),
            "reason": session.get("reason"), "ticket_ref": session.get("ticket_ref") or "",
            "created_at": session.get("created_at"), "expires_at": session.get("expires_at"),
            "seconds_remaining": session.get("seconds_remaining"), "status": session.get("status"),
            "read_only": True,
        }

    @router.get("/support-session/current")
    def support_session_current(request: Request):
        claims = support_claims(request)
        row = _support.get_session(claims["sid"])
        if not row:
            raise HTTPException(status_code=404, detail="Support session not found.")
        return {"api_version": "v1", "session": _banner(_support.public_session(row))}

    @router.post("/support-session/end")
    def support_session_end(request: Request):
        claims = support_claims(request)
        display = str((claims.get("act") or {}).get("display") or (claims.get("act") or {}).get("operator") or "support")
        try:
            session = _support.revoke_session(claims["sid"], revoked_by=f"{display} (ended from the console)",
                                              reason="Support ended the session from the customer console.")
        except _support.SupportSessionError as exc:
            _raise(exc)
        return {"ok": True, "session": _banner(session)}

    # ── Customer control ─────────────────────────────────────────────────────

    @router.get("/org/support-access")
    def org_support_access(request: Request):
        org = deps.org_of(request)
        deps.require_role(request, ["viewer", "operator", "admin"], "support_access.read", "organization", org)
        return {"api_version": "v1", **_support.support_access(org)}

    @router.put("/org/support-access")
    def org_update_support_access(req: SupportAccessUpdate, request: Request):
        org = deps.org_of(request)
        actor = deps.require_role(request, ["admin"], "support_access.update", "organization", org)
        before = _support.support_access(org)
        result = _support.set_support_access(org, req.allowed, actor["actor_id"])
        if before["allowed"] != result["allowed"]:
            deps.audit(request, action="support_access.enabled" if req.allowed else "support_access.disabled",
                       resource_type="organization", resource_id=org, reason=req.reason,
                       details={"allowed": req.allowed}, actor=actor)
            if not req.allowed:
                # Turning access off also ends any session in progress.
                for session in _support.list_sessions(org, active=True):
                    try:
                        _support.revoke_session(session["id"], revoked_by=f"customer:{actor['actor_id']}",
                                                reason="Customer disabled vendor support access.")
                    except _support.SupportSessionError:
                        pass
        return {"api_version": "v1", **result}

    @router.get("/org/support-access/history")
    def org_support_access_history(request: Request, limit: int = Query(50, ge=1, le=200)):
        org = deps.org_of(request)
        deps.require_role(request, ["viewer", "operator", "admin"], "support_access.history", "organization", org)
        _support.finalize_expired(org)
        entries = []
        for action in ("started", "exchanged", "revoked", "expired"):
            entries.extend(deps.list_audit_logs(limit=500, action=f"support_session.{action}"))
        items = _support.history_from_audit(entries)[:limit]
        # Every request the session made (the platform_support_requests journal, not only the role-checked
        # reads in the tenant audit log), as path and time. Scoped to this organization.
        pages = _support.customer_request_history(org, [i["id"] for i in items])
        for item in items:
            viewed = pages.get(item["id"]) or {"requests": [], "total": 0}
            item["requests"] = viewed["requests"]
            item["requests_total"] = viewed["total"]
            item["requests_truncated"] = viewed["total"] > len(viewed["requests"])
        return {"api_version": "v1", "organization_id": org, "items": items,
                "setting": _support.support_access(org)}

    return router
