from typing import Any, Callable, Dict, Optional
import json
import sys
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import (
    append_audit_log,
    archive_organization,
    current_organization_id,
    delete_organization,
    get_organization_member,
    list_assets,
    list_audit_logs,
    list_organization_members,
    list_organizations,
    list_remediations,
    list_scan_rows,
    list_user_memberships,
    reset_current_organization_id,
    set_current_organization_id,
    upsert_organization,
    upsert_organization_member,
)


RequireRole = Callable[..., Dict[str, Any]]
ActorFromRequest = Callable[[Request], Dict[str, Any]]


class OrganizationUpsertRequest(BaseModel):
    id: str
    name: str
    plan_type: str = "starter"
    subscription_status: str = "active"


class OrganizationMemberRequest(BaseModel):
    user_id: str
    role: str = "viewer"
    display_name: str = ""
    email: str = ""
    status: str = "active"


class OrganizationMemberRoleRequest(BaseModel):
    role: str = "viewer"
    display_name: str = ""
    email: str = ""
    status: str = "active"


def _guard_member_change(request: Request, organization_id: str, actor: Dict[str, Any], user_id: str,
                         action: str, new_role: str = "", existing: Optional[Dict[str, Any]] = None) -> None:
    """Who may change whose role and who may remove whom: services/member_policy.py, enforced in
    app.py (_guard_member_change), which journals and audits a refusal and answers 403."""
    app_module = sys.modules.get("app")
    guard = getattr(app_module, "_guard_member_change", None) if app_module else None
    if guard is None:
        return
    existing = existing or {}
    guard(request, org_id=organization_id, caller_ids=[actor.get("actor_id")],
          target_ids=[user_id, existing.get("email")], target_roles=[existing.get("role")],
          action=action, new_role=new_role, target_label=str(existing.get("email") or ""))


def _apply(request: Request, organization_id: str, actor: Dict[str, Any], user_id: str, kind: str,
           **kwargs: Any) -> Dict[str, Any]:
    """Make an allowed change through services/member_access.py (app._apply_member_change journals and
    audits it): the account and the membership move together, and lowered access revokes tokens."""
    app_module = sys.modules.get("app")
    applier = getattr(app_module, "_apply_member_change", None) if app_module else None
    if applier is not None:
        return applier(request, org_id=organization_id, ids=[user_id], kind=kind,
                       by=str(actor.get("actor_id") or ""), **kwargs)
    from services import member_access

    try:
        return member_access.apply(organization_id, [user_id], kind, actor=str(actor.get("actor_id") or ""), **kwargs)
    except member_access.NotFound:
        raise HTTPException(status_code=404, detail="organization member not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def _change_member(request: Request, organization_id: str, actor: Dict[str, Any], user_id: str,
                   current: Optional[Dict[str, Any]], role: str, status: str, display_name: str,
                   email: str) -> Dict[str, Any]:
    """Apply a POST/PATCH of a member: the role change, then the status change, each through _apply;
    a change of name or email alone is written to the membership as before."""
    role = str(role or "viewer").strip().lower()
    status = str(status or "active").strip().lower()
    if status not in {"active", "disabled"}:
        raise HTTPException(status_code=400, detail="status must be active or disabled")
    profile = {"display_name": display_name or str((current or {}).get("display_name") or ""),
               "email": email or str((current or {}).get("email") or "")}
    was_active = str((current or {}).get("status") or "active").lower() == "active"
    summary: Dict[str, Any] = {}
    if not current or role != str(current.get("role") or "").strip().lower():
        summary = _apply(request, organization_id, actor, user_id, "role", role=role, profile=profile, create=True)
    if status == "disabled" and (was_active or not current):
        summary = _apply(request, organization_id, actor, user_id, "deactivate")
    elif status == "active" and current and not was_active:
        summary = _apply(request, organization_id, actor, user_id, "reactivate")
    if not summary:
        upsert_organization_member(organization_id, user_id, role=role, display_name=profile["display_name"],
                                   email=profile["email"], status=status)
    elif current and (profile["display_name"] != str(current.get("display_name") or "")
                      or profile["email"] != str(current.get("email") or "")):
        fresh = get_organization_member(organization_id, user_id) or {}
        if fresh:
            upsert_organization_member(organization_id, user_id, role=str(fresh.get("role") or role),
                                       display_name=profile["display_name"], email=profile["email"],
                                       status=str(fresh.get("status") or status))
    return summary


def _active_org_id(request: Request) -> str:
    return str(getattr(request.state, "org_id", current_organization_id()) or "").strip()


def _ensure_active_org(request: Request, organization_id: str, actor: Optional[Dict[str, Any]] = None) -> None:
    """Refuse unless the caller is acting for `organization_id`.

    The member routes always called this. Archive, delete and the GDPR export did not, so an
    administrator of any tenant could archive, purge or export any other tenant by naming it in the
    path -- the same "role-checked, not tenant-checked" defect as /admin/orgs/{org_id}/*.
    """
    target = str(organization_id or "").strip()
    if target and _active_org_id(request) == target:
        return
    app_module = sys.modules.get("app")
    checker = getattr(app_module, "_caller_can_act_for_org", None) if app_module else None
    if checker and checker(request, target, actor or {}):
        return
    raise HTTPException(status_code=403, detail="customer admins can manage only their active organization")


def create_organizations_router(require_role: RequireRole, actor_from_request: ActorFromRequest) -> APIRouter:
    router = APIRouter()

    @router.get("/organizations")
    def api_list_organizations(request: Request, limit: int = Query(200, ge=1, le=2000)):
        require_role(
            request,
            allowed_roles=["admin"],
            action="organization.list",
            resource_type="organization",
            resource_id="*",
        )
        return {"items": list_organizations(limit=limit)}

    @router.post("/organizations")
    def api_upsert_organization(request: Request, req: OrganizationUpsertRequest):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.upsert",
            resource_type="organization",
            resource_id=req.id,
        )
        # No id means "create a new organization". Naming an existing one is an update, and an
        # update to a tenant the caller does not belong to renamed it and rewrote its plan and
        # subscription status.
        if str(req.id or "").strip():
            _ensure_active_org(request, req.id, actor)
        return upsert_organization(
            organization_id=req.id,
            name=req.name,
            plan_type=req.plan_type,
            subscription_status=req.subscription_status,
        )

    @router.post("/organizations/{organization_id}/archive")
    def api_archive_organization(organization_id: str, request: Request):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.archive",
            resource_type="organization",
            resource_id=organization_id,
        )
        _ensure_active_org(request, organization_id, actor)
        row = archive_organization(organization_id)
        if not row:
            raise HTTPException(status_code=404, detail="organization not found")
        return {"ok": True, "organization": row}

    @router.delete("/organizations/{organization_id}")
    def api_delete_organization(
        organization_id: str,
        request: Request,
        mode: str = Query("archive", pattern="^(archive|purge)$"),
    ):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.delete",
            resource_type="organization",
            resource_id=organization_id,
        )
        _ensure_active_org(request, organization_id, actor)
        return delete_organization(organization_id, mode=mode)

    @router.get("/organizations/{organization_id}/members")
    def api_list_organization_members(
        organization_id: str,
        request: Request,
        limit: int = Query(500, ge=1, le=2000),
    ):
        require_role(
            request,
            allowed_roles=["admin"],
            action="organization.members.list",
            resource_type="organization",
            resource_id=organization_id,
        )
        _ensure_active_org(request, organization_id)
        return {"items": list_organization_members(organization_id, limit=int(limit))}

    @router.post("/organizations/{organization_id}/members")
    def api_upsert_organization_member(organization_id: str, req: OrganizationMemberRequest, request: Request):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.members.upsert",
            resource_type="organization",
            resource_id=organization_id,
        )
        _ensure_active_org(request, organization_id, actor)
        current = get_organization_member(organization_id, req.user_id)
        # Upserting an existing member may change their role or disable them; adding one grants a role.
        if not current:
            _guard_member_change(request, organization_id, actor, req.user_id, "grant", new_role=req.role)
        else:
            if str(req.role or "").strip().lower() != str(current.get("role") or "").strip().lower():
                _guard_member_change(request, organization_id, actor, req.user_id, "role", new_role=req.role,
                                     existing=current)
            if str(req.status or "active").strip().lower() != "active":
                _guard_member_change(request, organization_id, actor, req.user_id, "remove", existing=current)
        # `seats` is a published plan limit; a directly added member is the other way one is used
        # (the first is an invitation). A no-op unless billing enforcement is on.
        if not current:
            app_module = sys.modules.get("app")
            enforce = getattr(app_module, "_enforce_seat_limit_or_402", None) if app_module else None
            if enforce:
                enforce(organization_id)
        _change_member(request, organization_id, actor, req.user_id, current, req.role, req.status,
                       req.display_name, req.email)
        row = get_organization_member(organization_id, req.user_id)
        append_audit_log(
            actor_id=actor["actor_id"],
            actor_role=actor["actor_role"],
            action="organization.member_upserted",
            resource_type="organization_member",
            resource_id=f"{organization_id}:{req.user_id}",
            decision="allow",
            details={"role": req.role, "status": req.status},
        )
        return {"ok": True, "member": row}

    @router.patch("/organizations/{organization_id}/members/{user_id}")
    def api_update_organization_member(
        organization_id: str,
        user_id: str,
        req: OrganizationMemberRoleRequest,
        request: Request,
    ):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.members.update",
            resource_type="organization_member",
            resource_id=f"{organization_id}:{user_id}",
        )
        _ensure_active_org(request, organization_id)
        existing = get_organization_member(organization_id, user_id)
        if not existing:
            raise HTTPException(status_code=404, detail="organization member not found")
        role_changes = str(req.role or "").strip().lower() != str(existing.get("role") or "").strip().lower()
        disables = str(req.status or "active").strip().lower() != "active"
        if role_changes:
            _guard_member_change(request, organization_id, actor, user_id, "role", new_role=req.role, existing=existing)
        if disables:
            _guard_member_change(request, organization_id, actor, user_id, "remove", existing=existing)
        _change_member(request, organization_id, actor, user_id, existing, req.role, req.status,
                       req.display_name, req.email)
        row = get_organization_member(organization_id, user_id)
        append_audit_log(
            actor_id=actor["actor_id"],
            actor_role=actor["actor_role"],
            action="organization.member_updated",
            resource_type="organization_member",
            resource_id=f"{organization_id}:{user_id}",
            decision="allow",
            details={"role": req.role, "status": req.status},
        )
        return {"ok": True, "member": row}

    @router.delete("/organizations/{organization_id}/members/{user_id}")
    def api_remove_organization_member(organization_id: str, user_id: str, request: Request):
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.members.remove",
            resource_type="organization_member",
            resource_id=f"{organization_id}:{user_id}",
        )
        _ensure_active_org(request, organization_id)
        existing = get_organization_member(organization_id, user_id)
        _guard_member_change(request, organization_id, actor, user_id, "remove", existing=existing)
        if existing:
            summary = _apply(request, organization_id, actor, user_id, "remove")
            result = {"ok": True, "deleted": 1, "organization_id": organization_id, "user_id": user_id,
                      "access_tokens_revoked": summary.get("access_tokens_revoked", False),
                      "refresh_sessions_revoked": summary.get("refresh_sessions_revoked", 0),
                      "api_keys_revoked": summary.get("api_keys_revoked", [])}
        else:
            result = {"ok": True, "deleted": 0, "organization_id": organization_id, "user_id": user_id}
        append_audit_log(
            actor_id=actor["actor_id"],
            actor_role=actor["actor_role"],
            action="organization.member_removed",
            resource_type="organization_member",
            resource_id=f"{organization_id}:{user_id}",
            decision="allow",
            details=result,
        )
        return result

    @router.get("/auth/memberships")
    def api_auth_memberships(request: Request):
        actor = actor_from_request(request)
        return {"items": list_user_memberships(actor["actor_id"], limit=500)}

    @router.get("/organizations/{organization_id}/export")
    def api_gdpr_export_organization(
        organization_id: str,
        request: Request,
        include_scans: bool = Query(True),
        include_assets: bool = Query(True),
        include_remediations: bool = Query(True),
        include_audit: bool = Query(True),
        include_members: bool = Query(True),
    ):
        """GDPR Article 20 — Portable data export for an organization.

        Returns all organization data as a JSON stream suitable for
        Subject Access Requests, data portability, or pre-deletion backup.
        """
        actor = require_role(
            request,
            allowed_roles=["admin"],
            action="organization.gdpr_export",
            resource_type="organization",
            resource_id=organization_id,
        )
        _ensure_active_org(request, organization_id, actor)
        token = set_current_organization_id(organization_id)
        try:
            export: Dict[str, Any] = {
                "export_version": "1.0",
                "organization_id": organization_id,
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "purpose": "GDPR Article 20 - Data Portability / Subject Access Request",
            }
            if include_members:
                export["members"] = list_organization_members(organization_id, limit=5000)
            if include_assets:
                export["assets"] = list_assets(limit=10000)
            if include_scans:
                export["scans"] = list_scan_rows(limit=1000)
            if include_remediations:
                export["remediations"] = list_remediations(limit=5000)
            if include_audit:
                export["audit_logs"] = list_audit_logs(limit=10000)
        finally:
            reset_current_organization_id(token)

        actor = actor_from_request(request)
        append_audit_log(
            actor_id=actor["actor_id"],
            actor_role=actor["actor_role"],
            action="organization.gdpr_export",
            resource_type="organization",
            resource_id=organization_id,
            decision="allow",
            details={"exported_at": export["exported_at"]},
        )

        filename = f"pq-gdpr-export-{organization_id[:8]}-{time.strftime('%Y%m%d')}.json"
        content = json.dumps(export, indent=2, default=str)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return router
