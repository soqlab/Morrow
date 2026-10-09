"""Vendor platform administration: the operator capabilities beyond the core /platform API.

Everything here is guarded by the platform operator credential (see
services/platform_operators.py), never by customer console roles, and every change
records a platform admin event carrying the resolved operator identity.

Role requirements:
    read  (owner, operator, support, auditor): listing, search, exports of audit data
    write (owner, operator): lifecycle, access, keys, sessions, announcements, maintenance
    owner: purge, operator roster

One public route lives here too: GET /announcements/active, which the customer
console reads to render its banner.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from db import (
    archive_organization,
    delete_organization,
    get_connection,
    get_organization_member,
    list_assets,
    list_audit_logs,
    list_organization_members,
    list_organizations,
    list_remediations,
    list_scan_rows,
    remove_organization_member,
    reset_current_organization_id,
    set_current_organization_id,
    upsert_organization,
    upsert_organization_member,
)
from db_postgres import pg_product_conn, postgres_main_db_requested
from services import admin_console as _admin_console
from services import announcements as _announcements
from services import api_keys as _api_keys
from services import auth_issuer as _auth_issuer
from services import platform_access as _access
from services import platform_operators as _operators
from services import session_revocation as _revocation
from services import operator_auth as _operator_auth

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES
OWNER = _operators.OWNER_ROLES

_ORG_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$")
_CSV_RISKY = ("=", "+", "-", "@", "\t", "\r")

FEATURE_FLAG_CATALOG = [
    {"flag_key": "write_path", "label": "Security Truth write-path promotion", "enforced": True},
    {"flag_key": "remediation_candidates", "label": "Remediation candidate generation", "enforced": True},
    {"flag_key": "demo_lab", "label": "Demo lab seeding", "enforced": True},
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── Request models ───────────────────────────────────────────────────────────


class ReasonRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class CustomerCreateRequest(ReasonRequest):
    organization_id: str = Field(..., pattern=_ORG_ID_PATTERN)
    name: str = Field(..., min_length=1, max_length=160)
    plan_type: str = Field("starter", min_length=1, max_length=64)
    subscription_status: str = Field("active", pattern="^(active|trial)$")


class CustomerRenameRequest(ReasonRequest):
    name: str = Field(..., min_length=1, max_length=160)


class CustomerPurgeRequest(ReasonRequest):
    confirm_organization_id: str = Field(..., min_length=1, max_length=128)


class MemberCreateRequest(ReasonRequest):
    user_id: str = Field(..., min_length=1, max_length=200)
    email: str = Field("", max_length=320)
    display_name: str = Field("", max_length=160)
    role: str = Field("viewer", pattern="^(viewer|operator|admin)$")


class MemberRoleRequest(ReasonRequest):
    role: str = Field(..., pattern="^(viewer|operator|admin)$")


class UserStatusRequest(ReasonRequest):
    revoke_sessions: bool = True


class InvitationCreateRequest(ReasonRequest):
    email: str = Field(..., min_length=3, max_length=320)
    role: str = Field("viewer", pattern="^(org_admin|analyst|viewer)$")
    expires_hours: int = Field(72, ge=1, le=720)


class RateLimitRequest(ReasonRequest):
    scans_per_hour: int = Field(..., ge=1, le=100000)
    api_calls_per_min: int = Field(..., ge=1, le=100000)


class SessionRevokeRequest(ReasonRequest):
    organization_id: str = Field("", max_length=128)
    user_id: str = Field("", max_length=200)
    session_id: str = Field("", max_length=64)
    revoke_access_tokens: bool = True


class ApiKeyCreateRequest(ReasonRequest):
    name: str = Field(..., min_length=1, max_length=80)
    scopes: List[str] = Field(..., min_length=1, max_length=3)
    expires_in_days: Optional[int] = Field(90, ge=1, le=730)


class ApiKeyRotateRequest(ReasonRequest):
    expires_in_days: Optional[int] = Field(90, ge=1, le=730)
    grace_seconds: int = Field(0, ge=0, le=86400)


class AnnouncementRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=140)
    body: str = Field("", max_length=2000)
    severity: str = Field("info", pattern="^(info|warn|critical)$")
    audience: str = Field("all", pattern="^(all|orgs)$")
    organization_ids: List[str] = Field(default_factory=list, max_length=500)
    starts_at: Optional[str] = Field(None, max_length=40)
    ends_at: Optional[str] = Field(None, max_length=40)


class MaintenanceRequest(ReasonRequest):
    enabled: bool
    message: str = Field("", max_length=500)
    ends_at: Optional[str] = Field(None, max_length=40)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _operator_sessions_safe() -> List[Dict[str, Any]]:
    """Admin-console (operator SSO) sessions, listed next to customer sessions; revoke via
    POST /platform/operator-sessions/{session_ref}/revoke."""
    try:
        return _operator_auth.list_sessions()
    except Exception:
        return []


def _csv_safe(value: Any) -> str:
    text = "" if value is None else (json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value))
    return "'" + text if text.startswith(_CSV_RISKY) else text


def _csv_response(rows: Iterable[Dict[str, Any]], fields: List[str], filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(fields)
    for row in rows:
        writer.writerow([_csv_safe(row.get(f)) for f in fields])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


def _like_pattern(text: str, contains: bool = True) -> str:
    escaped = str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%" if contains else f"{escaped}%"


def _validate_date(value: str, field: str, end_of_day: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not _DATE_RE.match(text):
        raise HTTPException(status_code=400, detail=f"{field} must be a date (YYYY-MM-DD) or ISO timestamp.")
    if end_of_day and len(text) == 10:
        return text + "T23:59:59Z"
    return text


def create_platform_admin_router(deps: Any) -> APIRouter:
    """deps: require_platform_admin, record_event, ensure_admin_schema, issuer_db, org_status_cache,
    extract_org_id, auth_mode(), default_org_id, legacy_key_enabled(), feature_flags_strict(),
    auth_issuer_enabled()."""
    router = APIRouter()

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    def record(organization_id: str, action: str, reason: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        deps.record_event(organization_id, action, reason=reason, details=details or {})

    def org_row(organization_id: str) -> Optional[Dict[str, Any]]:
        oid = str(organization_id or "").strip()
        return next((o for o in list_organizations(limit=2000) if str(o.get("id") or "") == oid), None)

    def require_org(organization_id: str) -> Dict[str, Any]:
        row = org_row(organization_id)
        if not row:
            raise HTTPException(status_code=404, detail="Customer organization not found.")
        return row

    def invalidate_org_cache() -> None:
        try:
            deps.invalidate_org_cache()
        except Exception:
            pass

    def issuer_call(fn, default):
        try:
            with deps.issuer_db() as conn:
                return fn(conn)
        except Exception:
            return default

    # ── Identity ─────────────────────────────────────────────────────────────

    @router.get("/platform/whoami")
    def platform_whoami(request: Request):
        actor = guard(request)
        ceiling = str(actor.get("ceiling_role") or actor["actor_role"])
        return {
            "api_version": "v1",
            "operator": actor["actor_id"],
            "role": actor["actor_role"],
            "ceiling_role": ceiling,
            "role_bound": bool(actor.get("bound")),
            "credential_source": actor.get("credential_source") or "",
            "claimed_user": actor.get("claimed_user") or "",
            "allowed_roles": _operators.allowed_roles_for(ceiling),
            "can_write": actor["actor_role"] in WRITE,
            "is_owner": actor["actor_role"] in OWNER,
            "named_operators_configured": len(_operators.load_operators()),
            "legacy_key_enabled": bool(deps.legacy_key_enabled()),
            **_operator_auth.whoami_extras(request, actor),
        }

    @router.get("/platform/operators")
    def platform_operators(request: Request):
        guard(request, OWNER)
        return {
            "api_version": "v1",
            "items": _operators.public_operator_list(),
            "configuration_errors": _operators.configuration_errors(),
            "legacy_key": {"enabled": bool(deps.legacy_key_enabled()), "role": _operators.legacy_key_role()},
            "note": "Operators are configured with PQC_PLATFORM_OPERATORS; keys are never stored or shown.",
        }

    # ── Customer lifecycle ───────────────────────────────────────────────────

    @router.post("/platform/customers")
    def platform_create_customer(req: CustomerCreateRequest, request: Request):
        guard(request, WRITE)
        if org_row(req.organization_id):
            raise HTTPException(status_code=409, detail="An organization with that id already exists.")
        row = upsert_organization(req.organization_id, req.name.strip(), plan_type=req.plan_type.strip(),
                                  subscription_status=req.subscription_status)
        invalidate_org_cache()
        record(req.organization_id, "platform.customer_created", req.reason,
               {"name": req.name.strip(), "plan_type": req.plan_type, "subscription_status": req.subscription_status})
        return {"ok": True, "organization": row}

    @router.post("/platform/customers/{organization_id}/rename")
    def platform_rename_customer(organization_id: str, req: CustomerRenameRequest, request: Request):
        guard(request, WRITE)
        current = require_org(organization_id)
        row = upsert_organization(organization_id, req.name.strip(),
                                  plan_type=str(current.get("plan_type") or "starter"),
                                  subscription_status=str(current.get("subscription_status") or "active"))
        record(organization_id, "platform.customer_renamed", req.reason,
               {"from": current.get("name"), "to": req.name.strip()})
        return {"ok": True, "organization": row}

    @router.post("/platform/customers/{organization_id}/archive")
    def platform_archive_customer(organization_id: str, req: ReasonRequest, request: Request):
        guard(request, WRITE)
        require_org(organization_id)
        row = archive_organization(organization_id)
        invalidate_org_cache()
        record(organization_id, "platform.customer_archived", req.reason)
        return {"ok": True, "organization": row}

    @router.post("/platform/customers/{organization_id}/purge")
    def platform_purge_customer(organization_id: str, req: CustomerPurgeRequest, request: Request):
        actor = guard(request, OWNER)
        _operator_auth.require_step_up(actor, "purge an organization")
        require_org(organization_id)
        if req.confirm_organization_id.strip() != organization_id:
            raise HTTPException(status_code=400, detail="Type the organization id exactly to confirm the purge.")
        if organization_id == str(deps.default_org_id):
            raise HTTPException(status_code=409, detail="The default organization cannot be purged.")
        result = delete_organization(organization_id, mode="purge")
        keys_revoked = _api_keys.revoke_organization_keys(organization_id, actor["actor_id"], "organization purged")
        sessions_revoked = issuer_call(lambda conn: _auth_issuer.revoke_refresh_sessions(conn, org_id=organization_id), 0)
        _revocation.revoke("org", organization_id, revoked_by=actor["actor_id"], reason="organization purged")
        invalidate_org_cache()
        record(organization_id, "platform.customer_purged", req.reason, {
            "deleted": result.get("deleted") or {}, "api_keys_revoked": keys_revoked,
            "refresh_sessions_revoked": sessions_revoked,
        })
        return {"ok": True, "organization_id": organization_id, "deleted": result.get("deleted") or {},
                "api_keys_revoked": keys_revoked, "refresh_sessions_revoked": sessions_revoked}

    @router.get("/platform/customers/{organization_id}/export")
    def platform_gdpr_export(organization_id: str, request: Request):
        """GDPR Article 15/20 export of one organization's data, as a JSON download."""
        guard(request, WRITE)
        require_org(organization_id)
        token = set_current_organization_id(organization_id)
        try:
            export: Dict[str, Any] = {
                "export_version": "1.0",
                "organization_id": organization_id,
                "exported_at": _now_iso(),
                "purpose": "GDPR Article 15/20 - Subject Access Request / Data Portability",
                "members": list_organization_members(organization_id, limit=2000),
                "assets": list_assets(limit=10000),
                "scans": list_scan_rows(limit=1000),
                "remediations": list_remediations(limit=5000),
                "audit_logs": list_audit_logs(limit=2000),
            }
        finally:
            reset_current_organization_id(token)
        record(organization_id, "platform.gdpr_export", "", {"exported_at": export["exported_at"]})
        filename = f"pqc-gdpr-export-{organization_id[:24]}-{time.strftime('%Y%m%d')}.json"
        return StreamingResponse(
            iter([json.dumps(export, indent=2, default=str)]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
        )

    # ── Users & access ───────────────────────────────────────────────────────

    def tenant_users(organization_id: str = "", query: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        text = str(query or "").strip().lower()
        rows: Dict[tuple, Dict[str, Any]] = {}

        def entry(org: str, uid: str) -> Dict[str, Any]:
            return rows.setdefault((org, uid), {
                "organization_id": org, "user_id": uid, "email": "", "name": "", "role": "", "status": "active",
                "sources": [], "membership_role": "", "membership_status": "", "account_role": "",
                "account_active": None, "invited_role": "", "last_login_at": None, "created_at": None,
            })

        accounts = issuer_call(lambda conn: _access.password_accounts(conn, organization_id, text, limit), [])
        for account in accounts:
            e = entry(str(account["org_id"]), str(account["id"]))
            e.update(email=account["email"], name=account["full_name"], account_role=account["role"],
                     account_active=account["is_active"], last_login_at=account["last_login_at"],
                     created_at=account["created_at"])
            e["sources"].append("password_account")
        orgs = [organization_id] if organization_id else [str(o.get("id") or "") for o in list_organizations(limit=500)]
        for oid in [o for o in orgs if o]:
            try:
                members = list_organization_members(oid, limit=2000)
            except Exception:
                members = []
            for member in members:
                uid = str(member.get("user_id") or "")
                haystack = f"{uid} {member.get('email') or ''} {member.get('display_name') or ''}".lower()
                if text and text not in haystack:
                    continue
                e = entry(oid, uid)
                e["membership_role"] = str(member.get("role") or "")
                e["membership_status"] = str(member.get("status") or "")
                e["email"] = e["email"] or str(member.get("email") or "")
                e["name"] = e["name"] or str(member.get("display_name") or "")
                e["created_at"] = e["created_at"] or member.get("created_at")
                e["sources"].append("membership")
        try:
            invited = _access.list_invited_users(organization_id)
        except Exception:
            invited = []
        for user in invited:
            haystack = f"{user.get('id') or ''} {user.get('email') or ''}".lower()
            if text and text not in haystack:
                continue
            e = entry(str(user.get("org_id") or ""), str(user.get("email") or user.get("id") or ""))
            e["email"] = e["email"] or str(user.get("email") or "")
            e["invited_role"] = str(user.get("role") or "")
            e["sources"].append("accepted_invitation")
        out = []
        for e in rows.values():
            e["role"] = e["membership_role"] or e["account_role"] or _access.MEMBERSHIP_ROLE_FOR_INVITE.get(e["invited_role"], "")
            if e["membership_status"] == "disabled" or e["account_active"] is False:
                e["status"] = "disabled"
            out.append(e)
        out.sort(key=lambda r: (r["organization_id"], (r["email"] or r["user_id"]).lower()))
        return out[:limit]

    @router.get("/platform/users")
    def platform_users(request: Request, q: str = Query("", max_length=200),
                       organization_id: str = Query("", max_length=128), limit: int = Query(300, ge=1, le=2000)):
        guard(request)
        return {"api_version": "v1", "items": tenant_users(organization_id, q, int(limit)),
                "sources": {"password_account": "built-in sign-in account", "membership": "organization role assignment",
                            "accepted_invitation": "invitation workflow record"}}

    @router.get("/platform/customers/{organization_id}/users")
    def platform_customer_users(organization_id: str, request: Request, q: str = Query("", max_length=200)):
        guard(request)
        require_org(organization_id)
        return {"api_version": "v1", "organization_id": organization_id, "items": tenant_users(organization_id, q, 2000)}

    @router.post("/platform/customers/{organization_id}/members")
    def platform_add_member(organization_id: str, req: MemberCreateRequest, request: Request):
        guard(request, WRITE)
        require_org(organization_id)
        if get_organization_member(organization_id, req.user_id):
            raise HTTPException(status_code=409, detail="That user is already a member; change their role instead.")
        member = upsert_organization_member(organization_id, req.user_id.strip(), role=req.role,
                                            display_name=req.display_name.strip(), email=req.email.strip().lower())
        record(organization_id, "platform.member_added", req.reason, {"user_id": req.user_id, "role": req.role})
        return {"ok": True, "member": member}

    @router.patch("/platform/customers/{organization_id}/members/{user_id}")
    def platform_change_member_role(organization_id: str, user_id: str, req: MemberRoleRequest, request: Request):
        actor = guard(request, WRITE)
        require_org(organization_id)
        member = get_organization_member(organization_id, user_id)
        account_updated = bool(issuer_call(lambda conn: _auth_issuer.update_user_role(conn, user_id, req.role, organization_id), False))
        if member:
            member = upsert_organization_member(organization_id, user_id, role=req.role,
                                                display_name=str(member.get("display_name") or ""),
                                                email=str(member.get("email") or ""),
                                                status=str(member.get("status") or "active"))
        if not member and not account_updated:
            raise HTTPException(status_code=404, detail="No member or sign-in account with that id in this organization.")
        if account_updated:
            # Issued tokens carry the old role claim; cut them off so the next refresh picks up the new role.
            _revocation.revoke("user", user_id, revoked_by=actor["actor_id"], reason="role changed")
        record(organization_id, "platform.member_role_changed", req.reason, {
            "user_id": user_id, "role": req.role, "membership_updated": bool(member), "password_account_updated": account_updated,
        })
        return {"ok": True, "member": member, "password_account_updated": account_updated,
                "access_tokens_reissue_required": account_updated}

    @router.delete("/platform/customers/{organization_id}/members/{user_id}")
    def platform_remove_member(organization_id: str, user_id: str, request: Request,
                               reason: str = Query(..., min_length=3, max_length=500)):
        guard(request, WRITE)
        require_org(organization_id)
        if not get_organization_member(organization_id, user_id):
            raise HTTPException(status_code=404, detail="Organization member not found.")
        result = remove_organization_member(organization_id, user_id)
        record(organization_id, "platform.member_removed", reason, {"user_id": user_id})
        return {"ok": True, "result": result}

    def set_user_status(organization_id: str, user_id: str, active: bool, req: UserStatusRequest, request: Request):
        actor = guard(request, WRITE)
        require_org(organization_id)
        member = get_organization_member(organization_id, user_id)
        account = bool(issuer_call(lambda conn: _auth_issuer.set_user_active(conn, user_id, organization_id, active), False))
        if member:
            member = upsert_organization_member(organization_id, user_id, role=str(member.get("role") or "viewer"),
                                                display_name=str(member.get("display_name") or ""),
                                                email=str(member.get("email") or ""),
                                                status="active" if active else "disabled")
        if not member and not account:
            raise HTTPException(status_code=404, detail="No member or sign-in account with that id in this organization.")
        sessions = 0
        if not active and req.revoke_sessions:
            if account:
                sessions = int(issuer_call(lambda conn: _auth_issuer.revoke_refresh_sessions(conn, user_id=user_id), 0))
            _revocation.revoke("user", user_id, revoked_by=actor["actor_id"], reason="user deactivated")
        action = "platform.user_reactivated" if active else "platform.user_deactivated"
        record(organization_id, action, req.reason, {
            "user_id": user_id, "membership_updated": bool(member), "password_account_updated": account,
            "refresh_sessions_revoked": sessions, "access_tokens_revoked": bool(not active and req.revoke_sessions),
        })
        return {"ok": True, "member": member, "password_account_updated": account,
                "refresh_sessions_revoked": sessions, "access_tokens_revoked": bool(not active and req.revoke_sessions)}

    @router.post("/platform/customers/{organization_id}/users/{user_id}/deactivate")
    def platform_deactivate_user(organization_id: str, user_id: str, req: UserStatusRequest, request: Request):
        return set_user_status(organization_id, user_id, False, req, request)

    @router.post("/platform/customers/{organization_id}/users/{user_id}/reactivate")
    def platform_reactivate_user(organization_id: str, user_id: str, req: UserStatusRequest, request: Request):
        return set_user_status(organization_id, user_id, True, req, request)

    # ── Invitations ──────────────────────────────────────────────────────────

    @router.get("/platform/customers/{organization_id}/invitations")
    def platform_list_invitations(organization_id: str, request: Request, include_accepted: bool = Query(False)):
        guard(request)
        require_org(organization_id)
        return {"api_version": "v1", "organization_id": organization_id,
                "items": _access.list_invitations(organization_id, include_accepted=bool(include_accepted))}

    @router.post("/platform/customers/{organization_id}/invitations")
    def platform_create_invitation(organization_id: str, req: InvitationCreateRequest, request: Request):
        actor = guard(request, WRITE)
        require_org(organization_id)
        try:
            invitation = _access.create_invitation(organization_id, req.email, req.role, actor["actor_id"], req.expires_hours)
        except _access.InvitationError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
        record(organization_id, "platform.invitation_created", req.reason, {
            "invite_id": invitation["invite_id"], "email": invitation["email"], "role": invitation["role"],
        })
        from services import invite_links as _invite_links
        from services import platform_mail as _platform_mail

        invitation["invite_link"] = _invite_links.invite_link(invitation["token"], request)
        # The link carries the token in its fragment and is shown once; the bare token and the
        # accept path are dropped so the credential never appears on its own in a response body.
        invitation.pop("token", None)
        invitation.pop("accept_path", None)
        return {"ok": True, "invitation": invitation, "email_configured": _platform_mail.configured(),
                "note": "The invite link is shown once. Send it to the invitee over a trusted channel (or email it from the "
                        "portal); they must be signed in with the invited email address to accept it."}

    @router.delete("/platform/customers/{organization_id}/invitations/{invite_id}")
    def platform_revoke_invitation(organization_id: str, invite_id: str, request: Request,
                                   reason: str = Query(..., min_length=3, max_length=500)):
        actor = guard(request, WRITE)
        require_org(organization_id)
        if not _access.revoke_invitation(organization_id, invite_id, actor["actor_id"]):
            raise HTTPException(status_code=404, detail="Pending invitation not found.")
        record(organization_id, "platform.invitation_revoked", reason, {"invite_id": invite_id})
        return {"ok": True, "invite_id": invite_id}

    # ── Rate limits ──────────────────────────────────────────────────────────

    def rate_limit_state(organization_id: str) -> Dict[str, Any]:
        from services import org_rate_limits as _org_limits
        state = _org_limits.describe(organization_id)
        if not _org_limits.enabled():
            note = "Per-organization enforcement is switched off (PQC_ORG_RATE_LIMITS_ENABLED=0); values are stored only."
        elif state["override"]:
            note = (f"Enforced per organization (operator override): requests authenticated as this organization over the "
                    f"per-minute limit, and scan starts over the hourly limit, get HTTP 429 with Retry-After. Changes reach "
                    f"every API replica within {int(state['cache_seconds'])} s. Counters: {state['backend']}.")
        elif state["enforced"]:
            note = "No override saved: the platform defaults (PQC_ORG_DEFAULT_*) are enforced for this organization."
        else:
            note = ("No override saved, so no per-organization limit applies; the per-IP limits still do. The values shown are "
                    "the suggested defaults. Save them to enforce them.")
        return {**state, "note": note}

    @router.get("/platform/customers/{organization_id}/rate-limits")
    def platform_get_rate_limits(organization_id: str, request: Request):
        guard(request)
        require_org(organization_id)
        return {"api_version": "v1", **_admin_console.get_rate_limits(organization_id), **rate_limit_state(organization_id)}

    @router.put("/platform/customers/{organization_id}/rate-limits")
    def platform_set_rate_limits(organization_id: str, req: RateLimitRequest, request: Request):
        actor = guard(request, WRITE)
        require_org(organization_id)
        result = _admin_console.set_rate_limits(organization_id, req.scans_per_hour, req.api_calls_per_min, actor=actor["actor_id"])
        record(organization_id, "platform.rate_limits_updated", req.reason,
               {"scans_per_hour": req.scans_per_hour, "api_calls_per_min": req.api_calls_per_min})
        from services import org_rate_limits as _org_limits
        _org_limits.invalidate()  # this replica applies the new values on its next request
        return {"api_version": "v1", **result, **rate_limit_state(organization_id)}

    # ── Feature flags ────────────────────────────────────────────────────────

    @router.get("/platform/feature-flags/catalog")
    def platform_feature_flag_catalog(request: Request):
        guard(request)
        strict = bool(deps.feature_flags_strict())
        return {
            "api_version": "v1",
            "items": FEATURE_FLAG_CATALOG,
            "strict_mode": strict,
            "semantics": ("Strict mode: a feature is off unless its flag is explicitly enabled." if strict else
                          "Kill-switch mode: a feature is on unless its flag is explicitly disabled."),
        }

    @router.delete("/platform/customers/{organization_id}/feature-flags/{flag_key}")
    def platform_delete_feature_flag(organization_id: str, flag_key: str, request: Request,
                                     reason: str = Query(..., min_length=3, max_length=500)):
        guard(request, WRITE)
        require_org(organization_id)
        deps.ensure_admin_schema()
        if postgres_main_db_requested():
            with pg_product_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM platform_feature_flags WHERE organization_id = %s AND flag_key = %s",
                                (organization_id, flag_key))
                    deleted = int(cur.rowcount or 0)
                conn.commit()
        else:
            with closing(get_connection()) as conn:
                cur = conn.execute("DELETE FROM platform_feature_flags WHERE organization_id = ? AND flag_key = ?",
                                   (organization_id, flag_key))
                deleted = int(cur.rowcount or 0)
                conn.commit()
        if not deleted:
            raise HTTPException(status_code=404, detail="Feature flag not set for this organization.")
        record(organization_id, "platform.feature_flag_deleted", reason, {"flag_key": flag_key})
        return {"ok": True, "organization_id": organization_id, "flag_key": flag_key}

    # ── Admin audit trail ────────────────────────────────────────────────────

    def search_admin_events(organization_id: str, action: str, actor: str, q: str, since: str, until: str,
                            limit: int, offset: int) -> Dict[str, Any]:
        deps.ensure_admin_schema()
        pg = postgres_main_db_requested()
        ph = "%s" if pg else "?"
        like = "ILIKE" if pg else "LIKE"
        clauses: List[str] = []
        params: List[Any] = []
        if organization_id:
            clauses.append(f"organization_id = {ph}")
            params.append(organization_id)
        if action:
            clauses.append(f"action {like} {ph} ESCAPE '\\'")
            params.append(_like_pattern(action, contains=False))
        if actor:
            clauses.append(f"actor_id = {ph}")
            params.append(actor)
        if q:
            columns = ("action", "reason", "organization_id", "actor_id", "CAST(details_json AS TEXT)")
            clauses.append("(" + " OR ".join(f"{c} {like} {ph} ESCAPE '\\'" for c in columns) + ")")
            params.extend([_like_pattern(q)] * len(columns))
        if since:
            clauses.append(f"created_at >= {ph}")
            params.append(since)
        if until:
            clauses.append(f"created_at <= {ph}")
            params.append(until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        select = (f"SELECT id, organization_id, action, actor_id, reason, details_json, created_at FROM platform_admin_events "
                  f"{where} ORDER BY created_at DESC, id DESC LIMIT {ph} OFFSET {ph}")
        count_sql = f"SELECT COUNT(*) FROM platform_admin_events {where}"
        if pg:
            from psycopg2.extras import RealDictCursor

            with pg_product_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(count_sql, params)
                    total = int(list(cur.fetchone().values())[0] or 0)
                    cur.execute(select, [*params, limit, offset])
                    raw = [dict(r) for r in cur.fetchall()]
        else:
            with closing(get_connection()) as conn:
                total = int(conn.execute(count_sql, params).fetchone()[0] or 0)
                cursor = conn.execute(select, [*params, limit, offset])
                names = [d[0] for d in cursor.description]
                raw = [dict(zip(names, r)) for r in cursor.fetchall()]
        items = []
        for row in raw:
            details = row.get("details_json")
            if isinstance(details, str):
                try:
                    details = json.loads(details or "{}")
                except ValueError:
                    details = {}
            created = row.get("created_at")
            if isinstance(created, datetime):
                created = created.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            operator = (details or {}).get("operator") if isinstance(details, dict) else None
            items.append({
                "id": row.get("id"), "created_at": created, "organization_id": row.get("organization_id") or "",
                "action": row.get("action") or "", "actor_id": row.get("actor_id") or "", "reason": row.get("reason") or "",
                "operator_role": (operator or {}).get("actor_role", "") if isinstance(operator, dict) else "",
                "details": details if isinstance(details, dict) else {},
            })
        next_offset = offset + len(items) if offset + len(items) < total else None
        return {"api_version": "v1", "items": items, "total": total, "limit": limit, "offset": offset, "next_offset": next_offset}

    @router.get("/platform/admin-events/search")
    def platform_admin_events_search(
        request: Request,
        organization_id: str = Query("", max_length=128),
        action: str = Query("", max_length=120),
        actor: str = Query("", max_length=160),
        q: str = Query("", max_length=200),
        since: str = Query("", max_length=40),
        until: str = Query("", max_length=40),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0, le=1_000_000),
    ):
        guard(request)
        return search_admin_events(organization_id.strip(), action.strip(), actor.strip(), q.strip(),
                                   _validate_date(since, "since"), _validate_date(until, "until", end_of_day=True),
                                   int(limit), int(offset))

    @router.get("/platform/admin-events/export.csv")
    def platform_admin_events_export(
        request: Request,
        organization_id: str = Query("", max_length=128),
        action: str = Query("", max_length=120),
        actor: str = Query("", max_length=160),
        q: str = Query("", max_length=200),
        since: str = Query("", max_length=40),
        until: str = Query("", max_length=40),
        limit: int = Query(5000, ge=1, le=10000),
    ):
        guard(request)
        result = search_admin_events(organization_id.strip(), action.strip(), actor.strip(), q.strip(),
                                     _validate_date(since, "since"), _validate_date(until, "until", end_of_day=True),
                                     int(limit), 0)
        record(organization_id.strip(), "platform.admin_events_exported", "", {"rows": len(result["items"])})
        return _csv_response(result["items"], ["id", "created_at", "organization_id", "action", "actor_id", "operator_role", "reason", "details"],
                             f"pqc-platform-admin-events-{time.strftime('%Y%m%d')}.csv")

    # ── Tenant audit log ─────────────────────────────────────────────────────

    tenant_audit_fields = ["id", "organization_id", "actor_id", "actor_role", "action", "resource_type", "resource_id",
                           "decision", "reason", "details", "prev_hash", "entry_hash", "created_at"]

    def tenant_audit(organization_id: str, limit: int, actor_id: str, action: str, decision: str) -> List[Dict[str, Any]]:
        token = set_current_organization_id(organization_id)
        try:
            return list_audit_logs(limit=limit, actor_id=actor_id, action=action, decision=decision)
        finally:
            reset_current_organization_id(token)

    @router.get("/platform/customers/{organization_id}/audit-logs")
    def platform_tenant_audit_logs(organization_id: str, request: Request, limit: int = Query(200, ge=1, le=2000),
                                   actor_id: str = Query("", max_length=128), action: str = Query("", max_length=128),
                                   decision: str = Query("", max_length=32)):
        guard(request)
        require_org(organization_id)
        return {"api_version": "v1", "organization_id": organization_id,
                "items": tenant_audit(organization_id, int(limit), actor_id.strip(), action.strip(), decision.strip())}

    @router.get("/platform/customers/{organization_id}/audit-logs/export.csv")
    def platform_tenant_audit_export(organization_id: str, request: Request, limit: int = Query(2000, ge=1, le=10000),
                                     actor_id: str = Query("", max_length=128), action: str = Query("", max_length=128),
                                     decision: str = Query("", max_length=32)):
        guard(request)
        require_org(organization_id)
        rows = tenant_audit(organization_id, min(int(limit), 2000), actor_id.strip(), action.strip(), decision.strip())
        record(organization_id, "platform.tenant_audit_exported", "", {"rows": len(rows)})
        return _csv_response(rows, tenant_audit_fields, f"pqc-audit-{organization_id[:24]}-{time.strftime('%Y%m%d')}.csv")

    # ── Sessions ─────────────────────────────────────────────────────────────

    @router.get("/platform/sessions")
    def platform_sessions(request: Request, organization_id: str = Query("", max_length=128),
                          user_id: str = Query("", max_length=200), limit: int = Query(200, ge=1, le=1000)):
        guard(request)
        available = True
        try:
            with deps.issuer_db() as conn:
                items = _auth_issuer.list_refresh_sessions(conn, org_id=organization_id.strip(), user_id=user_id.strip(), limit=int(limit))
        except Exception:
            items, available = [], False
        try:
            revocations = _revocation.list_revocations(limit=50)
        except Exception:
            revocations = []
        return {
            "api_version": "v1",
            "items": items,
            "available": available,
            "issuer_enabled": bool(deps.auth_issuer_enabled()),
            "access_token_ttl_seconds": int(getattr(_auth_issuer, "_TOKEN_TTL", 0) or 0),
            "access_revocations": revocations,
            "operator_sessions": _operator_sessions_safe(),
            "revocation": {
                "refresh_sessions": "deleted immediately; the session can no longer be renewed",
                "access_tokens": "rejected by the request middleware once each replica refreshes its revocation list "
                                 "(PQC_TOKEN_REVOCATION_CACHE_SECONDS, default 10)",
                "external_identity_provider": "sessions issued by an external IdP must also be ended at that IdP",
            },
        }

    @router.post("/platform/sessions/revoke")
    def platform_revoke_sessions(req: SessionRevokeRequest, request: Request):
        actor = guard(request, WRITE)
        org, user, session = req.organization_id.strip(), req.user_id.strip(), req.session_id.strip().lower()
        if not (org or user or session):
            raise HTTPException(status_code=400, detail="Choose a session, a user, or an organization to revoke.")
        if org and not user and not session:
            _operator_auth.require_step_up(actor, "revoke every session in an organization")
        if org:
            require_org(org)
        try:
            with deps.issuer_db() as conn:
                if session:
                    target = next((s for s in _auth_issuer.list_refresh_sessions(conn, org_id=org, user_id=user, limit=1000)
                                   if s["session_id"] == session), None)
                    if not target:
                        raise HTTPException(status_code=404, detail="Active session not found.")
                    revoked = _auth_issuer.revoke_refresh_sessions(conn, session_id=session, org_id=org)
                    user = user or str(target.get("user_id") or "")
                else:
                    revoked = _auth_issuer.revoke_refresh_sessions(conn, user_id=user, org_id="" if user else org)
        except HTTPException:
            raise
        except Exception:
            if session:
                raise HTTPException(status_code=503, detail="Session storage is unavailable.") from None
            revoked = 0
        cutoff = None
        scope = "session" if session else ("user" if user else "organization")
        if req.revoke_access_tokens and scope != "session":
            cutoff = _revocation.revoke("user" if user else "org", user or org, revoked_by=actor["actor_id"], reason=req.reason)
        record(org, "platform.sessions_revoked", req.reason, {
            "scope": scope, "user_id": user, "session_id": session, "refresh_sessions_revoked": revoked,
            "access_tokens_cutoff": cutoff,
        })
        return {
            "ok": True, "scope": scope, "refresh_sessions_revoked": revoked,
            "access_tokens_revoked_before": cutoff,
            "note": ("A single session revoke stops renewal; its current access token expires on its own. "
                     "Revoke the user to cut off access tokens immediately.") if scope == "session" else "",
        }

    # ── API keys ─────────────────────────────────────────────────────────────

    @router.get("/platform/api-keys")
    def platform_list_api_keys(request: Request, organization_id: str = Query("", max_length=128),
                               status: str = Query("", pattern="^(|active|expired|revoked)$")):
        guard(request)
        return {"api_version": "v1", "items": _api_keys.list_keys(organization_id.strip(), status),
                "scopes": {"read": "viewer, GET only", "write": "operator", "admin": "admin"},
                "usage": "Authorization: Bearer pqc_<prefix>_<secret>"}

    @router.get("/platform/customers/{organization_id}/api-keys")
    def platform_customer_api_keys(organization_id: str, request: Request):
        guard(request)
        require_org(organization_id)
        return {"api_version": "v1", "organization_id": organization_id, "items": _api_keys.list_keys(organization_id)}

    @router.post("/platform/customers/{organization_id}/api-keys")
    def platform_create_api_key(organization_id: str, req: ApiKeyCreateRequest, request: Request):
        actor = guard(request, WRITE)
        require_org(organization_id)
        try:
            key, secret = _api_keys.create_key(organization_id, req.name, req.scopes, req.expires_in_days, actor["actor_id"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        record(organization_id, "platform.api_key_created", req.reason,
               {"key_id": key["id"], "prefix": key["prefix"], "scopes": key["scopes"], "expires_at": key["expires_at"]})
        return {"ok": True, "key": key, "secret": secret, "note": "Copy the secret now. It is not stored and cannot be shown again."}

    @router.post("/platform/api-keys/{key_id}/rotate")
    def platform_rotate_api_key(key_id: str, req: ApiKeyRotateRequest, request: Request):
        actor = guard(request, WRITE)
        _operator_auth.require_step_up(actor, "rotate an API key")
        try:
            result = _api_keys.rotate_key(key_id, actor["actor_id"], req.reason, req.expires_in_days, req.grace_seconds)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if not result:
            raise HTTPException(status_code=404, detail="API key not found.")
        key, secret, previous = result
        record(key["organization_id"], "platform.api_key_rotated", req.reason,
               {"key_id": key["id"], "previous_key_id": previous["id"], "grace_seconds": req.grace_seconds})
        return {"ok": True, "key": key, "secret": secret, "previous_key": previous,
                "note": "Copy the new secret now. It is not stored and cannot be shown again."}

    @router.post("/platform/api-keys/{key_id}/revoke")
    def platform_revoke_api_key(key_id: str, req: ReasonRequest, request: Request):
        actor = guard(request, WRITE)
        key = _api_keys.revoke_key(key_id, actor["actor_id"], req.reason)
        if not key:
            raise HTTPException(status_code=404, detail="API key not found.")
        record(key["organization_id"], "platform.api_key_revoked", req.reason, {"key_id": key["id"], "prefix": key["prefix"]})
        return {"ok": True, "key": key}

    # ── Announcements & maintenance ──────────────────────────────────────────

    @router.get("/platform/announcements")
    def platform_list_announcements(request: Request):
        guard(request)
        return {"api_version": "v1", "items": _announcements.list_announcements()}

    @router.post("/platform/announcements")
    def platform_create_announcement(req: AnnouncementRequest, request: Request):
        actor = guard(request, WRITE)
        try:
            item = _announcements.create_announcement(req.model_dump(), actor["actor_id"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        record("", "platform.announcement_created", "", {"announcement_id": item.get("id"), "severity": item.get("severity"),
                                                          "audience": item.get("audience")})
        return {"ok": True, "announcement": item}

    @router.put("/platform/announcements/{announcement_id}")
    def platform_update_announcement(announcement_id: int, req: AnnouncementRequest, request: Request):
        actor = guard(request, WRITE)
        try:
            item = _announcements.update_announcement(int(announcement_id), req.model_dump(), actor["actor_id"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        if not item:
            raise HTTPException(status_code=404, detail="Announcement not found.")
        record("", "platform.announcement_updated", "", {"announcement_id": item.get("id")})
        return {"ok": True, "announcement": item}

    @router.delete("/platform/announcements/{announcement_id}")
    def platform_delete_announcement(announcement_id: int, request: Request,
                                     reason: str = Query(..., min_length=3, max_length=500)):
        guard(request, WRITE)
        if not _announcements.delete_announcement(int(announcement_id)):
            raise HTTPException(status_code=404, detail="Announcement not found.")
        record("", "platform.announcement_deleted", reason, {"announcement_id": int(announcement_id)})
        return {"ok": True, "deleted": int(announcement_id)}

    @router.get("/platform/maintenance")
    def platform_get_maintenance(request: Request):
        guard(request)
        return {"api_version": "v1", **_announcements.get_maintenance(use_cache=False),
                "exempt_prefixes": list(_announcements.EXEMPT_PREFIXES),
                "effect": "While enabled, non-GET customer requests answer 503 with the message and Retry-After."}

    @router.put("/platform/maintenance")
    def platform_set_maintenance(req: MaintenanceRequest, request: Request):
        actor = guard(request, WRITE)
        try:
            state = _announcements.set_maintenance(req.enabled, req.message, req.ends_at or "", actor["actor_id"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        record("", "platform.maintenance_enabled" if req.enabled else "platform.maintenance_disabled", req.reason,
               {"message": state.get("message"), "ends_at": state.get("ends_at")})
        return {"api_version": "v1", **state}

    # ── Public: the console banner ───────────────────────────────────────────

    @router.get("/announcements/active")
    def public_active_announcements(request: Request):
        """Active announcements for the caller, plus maintenance state. Safe without sign-in:
        anonymous callers see only notices addressed to everyone."""
        authenticated = bool(getattr(request.state, "authenticated", False))
        org = ""
        if authenticated or deps.auth_mode() != "jwt":
            org = str(deps.extract_org_id(request) or "")
        available = True
        try:
            items = _announcements.active_for(org, include_targeted=bool(org))
            maintenance = _announcements.public_maintenance_state()
        except Exception:
            items, maintenance, available = [], {"enabled": False, "message": "", "ends_at": ""}, False
        return JSONResponse(
            {"api_version": "v1", "generated_at": _now_iso(), "organization_id": org or None,
             "available": available, "items": items, "maintenance": maintenance},
            headers={"Cache-Control": "no-store"},
        )

    return router


def install_maintenance_guard(app: Any) -> None:
    """Innermost middleware: 503 for customer writes while maintenance mode is on.

    Appended (not inserted) so it runs after authentication, org context, rate limiting and traffic
    monitoring have seen the request, and after the /v1 prefix has been normalised.
    """
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware

    async def dispatch(request, call_next):
        if _announcements.request_is_exempt(request.method, request.url.path):
            return await call_next(request)
        if _announcements.maintenance_cache_stale():
            state = await run_in_threadpool(_announcements.refresh_maintenance_cache)
        else:
            state = _announcements.get_maintenance()
        if not state.get("enabled"):
            return await call_next(request)
        public = _announcements.public_maintenance_state(state)
        return JSONResponse(
            status_code=503,
            content={"detail": public["message"], "maintenance": public},
            headers={"Retry-After": str(_announcements.retry_after_seconds(state)), "Cache-Control": "no-store"},
        )

    app.user_middleware.append(Middleware(BaseHTTPMiddleware, dispatch=dispatch))
