"""Cross-tenant access operations for the platform operator.

Tenant users exist in three places, and the operator needs one view over them:

  * pqc_users            -- built-in password accounts (services/auth_issuer.py)
  * organization_memberships -- per-organization roles that override token roles
  * admin_users / admin_invitations -- the invitation workflow (services/admin_console.py)

This module adds what those modules lack for a safe operator workflow: invitations
identified by a non-secret id instead of their bearer token, revocation, and an
acceptance path that is single-use under concurrency and bound to the signed-in
account whose email the invitation names.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn
from services import tenant_scope as _tenant_scope

logger = logging.getLogger(__name__)

INVITE_ROLES = ("org_admin", "analyst", "viewer")
MEMBERSHIP_ROLE_FOR_INVITE = {"platform_admin": "admin", "org_admin": "admin", "analyst": "operator", "viewer": "viewer"}
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$")


class InvitationError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init() -> None:
    from services import admin_console

    admin_console._init_tables()


def invite_id(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:20]


def _expired(expires_at: str) -> bool:
    try:
        expires = datetime.fromisoformat(str(expires_at))
    except ValueError:
        return True
    if not expires.tzinfo:
        expires = expires.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > expires


def list_invitations(organization_id: str, include_accepted: bool = False) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT token, email, role, invited_by, expires_at, accepted, created_at FROM admin_invitations "
            "WHERE org_id = ? ORDER BY created_at DESC LIMIT 500",
            (str(organization_id or ""),),
        ).fetchall()
    out = []
    for row in rows:
        accepted = bool(int(row["accepted"] or 0))
        if accepted and not include_accepted:
            continue
        out.append({
            "invite_id": invite_id(row["token"]),
            "email": row["email"],
            "role": row["role"],
            "invited_by": row["invited_by"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "status": "accepted" if accepted else ("expired" if _expired(row["expires_at"]) else "pending"),
        })
    return out


def create_invitation(organization_id: str, email: str, role: str, invited_by: str, expires_hours: int = 72) -> Dict[str, Any]:
    from services import admin_console

    address = str(email or "").strip().lower()
    if not _EMAIL_RE.match(address):
        raise InvitationError(400, "Enter a valid email address.")
    if role not in INVITE_ROLES:
        raise InvitationError(400, f"role must be one of: {', '.join(INVITE_ROLES)}")
    hours = int(expires_hours or 72)
    if not 1 <= hours <= 720:
        raise InvitationError(400, "expires_hours must be between 1 and 720.")
    result = admin_console.invite_user(str(organization_id), address, role, str(invited_by or "platform-admin"), hours)
    if not result.get("ok"):
        raise InvitationError(400, str(result.get("error") or "Invitation could not be created."))
    token = str(result["token"])
    return {
        "invite_id": invite_id(token),
        "organization_id": organization_id,
        "email": address,
        "role": role,
        "membership_role": MEMBERSHIP_ROLE_FOR_INVITE[role],
        "expires_at": result.get("expires_at"),
        "token": token,
        "accept_path": "/admin/accept-invite",   # POST {"token": ...}; the token never rides in a URL
    }


def revoke_invitation(organization_id: str, invitation_id: str, actor: str = "") -> bool:
    _init()
    wanted = str(invitation_id or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{20}", wanted):
        return False
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT token, email FROM admin_invitations WHERE org_id = ? AND accepted = 0",
            (str(organization_id),),
        ).fetchall()
        target = None
        for row in rows:
            if hmac.compare_digest(invite_id(row["token"]), wanted):
                target = row
        if not target:
            return False
        cur = conn.execute(
            "DELETE FROM admin_invitations WHERE token = ? AND org_id = ? AND accepted = 0",
            (target["token"], str(organization_id)),
        )
        if int(cur.rowcount or 0) != 1:
            return False
        conn.execute(
            "INSERT INTO admin_audit_log (org_id, actor_email, action, target_type, target_id, detail, ip_address, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(organization_id), str(actor or "platform-admin"), "revoke_invitation", "invitation", wanted,
             f"email={target['email']}", "", _now()),
        )
        conn.commit()
    return True


def accept_invitation_for_user(token: str, *, user_id: str, email: str) -> Dict[str, Any]:
    """Accept an invitation for the signed-in account. Raises InvitationError."""
    raw = str(token or "").strip()
    if not raw or len(raw) > 256:
        raise InvitationError(404, "Invitation not found.")
    identity_email = str(email or "").strip().lower()
    _init()
    # An invitation is looked up by its token, and the tenant it belongs to is not known until the
    # row is read -- by construction: the invitee is not yet a member, so their request carries some
    # other tenant, or none. Under Postgres RLS the policy on admin_invitations would hide the row
    # from them and refuse the admin_users insert, so acceptance is one of the named, audited
    # cross-tenant paths (services/tenant_scope.py, postgres_rls.operator_access_rule case 3, the
    # same reason API-key verification needs it). The block is the whole claim-and-record
    # transaction and nothing else; every entry is journaled.
    with _tenant_scope.platform_scope("invitation acceptance: the tenant is inside the invitation",
                                      actor=str(user_id or "")), feature_conn() as conn:
        inv = conn.execute(
            "SELECT org_id, email, role, expires_at, accepted FROM admin_invitations WHERE token = ?", (raw,)
        ).fetchone()
        if not inv:
            raise InvitationError(404, "Invitation not found.")
        if int(inv["accepted"] or 0):
            raise InvitationError(409, "This invitation has already been used.")
        if _expired(inv["expires_at"]):
            raise InvitationError(410, "This invitation has expired. Ask your administrator for a new one.")
        if not identity_email or not hmac.compare_digest(identity_email, str(inv["email"] or "").strip().lower()):
            raise InvitationError(403, "This invitation was issued to a different email address than the signed-in account.")
        # Claim first: only one concurrent acceptance can move accepted from 0 to 1.
        claimed = conn.execute("UPDATE admin_invitations SET accepted = 1 WHERE token = ? AND accepted = 0", (raw,))
        if int(claimed.rowcount or 0) != 1:
            conn.rollback()
            raise InvitationError(409, "This invitation has already been used.")
        now = _now()
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO admin_users (id, org_id, email, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (secrets.token_hex(8), inv["org_id"], identity_email, inv["role"], "active", now),
                )
        except INTEGRITY_ERRORS:
            conn.execute(
                "UPDATE admin_users SET role = ?, status = 'active' WHERE org_id = ? AND email = ?",
                (inv["role"], inv["org_id"], identity_email),
            )
        conn.execute(
            "INSERT INTO admin_audit_log (org_id, actor_email, action, target_type, target_id, detail, ip_address, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (inv["org_id"], identity_email, "accept_invitation", "user", str(user_id), "", "", now),
        )
        conn.commit()
    membership_role = MEMBERSHIP_ROLE_FOR_INVITE.get(str(inv["role"]), "viewer")
    membership: Optional[Dict[str, Any]] = None
    try:
        from db import upsert_organization_member

        # Same reason as above: the membership row belongs to the invited tenant, which is not the
        # tenant this request resolved to -- that is the whole point of accepting an invitation.
        with _tenant_scope.platform_scope("invitation acceptance: membership in the invited tenant",
                                          actor=str(user_id or "")):
            membership = upsert_organization_member(
                str(inv["org_id"]), str(user_id), role=membership_role, email=identity_email, status="active"
            )
    except Exception as exc:  # the invitation is consumed; report rather than hide a partial result
        logger.warning("[invitations] membership upsert failed: %s", exc.__class__.__name__)
    bound = bind_account_to_organization(str(user_id), str(inv["org_id"]), membership_role, email=identity_email)
    return {
        "ok": True,
        "user_id": str(user_id),
        "org_id": inv["org_id"],
        "email": identity_email,
        "role": inv["role"],
        "membership_role": membership_role,
        "membership_recorded": membership is not None,
        # True when this is a built-in account whose next token will carry the new organization.
        # False for an external IdP identity, where the org claim is the provider's to issue.
        "organization_binding_updated": bound,
        "next_step": (
            "Sign in again (or refresh the access token) to receive a token scoped to this "
            "organization; the token you are holding is still scoped to the previous one."
            if bound else
            "Your identity provider supplies the organization claim; it must place you in this "
            "organization for the membership to take effect."
        ),
    }


def bind_account_to_organization(user_id: str, organization_id: str, membership_role: str = "",
                                 email: str = "") -> bool:
    """Make `organization_id` the tenant the account's next built-in token is scoped to.

    Recording a membership is not enough on its own: with PQC_AUTH_ISSUER_ENABLED=1 the token's
    org claim is read from the account row, so an invitee who accepted an invitation kept operating
    in whichever organization they had registered in. The caller must already have verified that
    the account is entitled to the organization (acceptance of an invitation addressed to it, or an
    active membership); this only moves the claim.

    No built-in account means an external IdP identity, where the claim is the provider's. Returns
    whether the account row moved.
    """
    role = {"admin": "admin", "operator": "operator", "viewer": "viewer"}.get(str(membership_role or ""), "")
    try:
        from contextlib import closing

        from db import get_connection
        from services import auth_issuer

        with closing(get_connection()) as conn:
            return bool(auth_issuer.set_user_organization(conn, str(user_id), str(organization_id), role,
                                                          email=str(email or "")))
    except Exception as exc:
        logger.warning("[invitations] organization binding failed: %s", exc.__class__.__name__)
        return False


def list_invited_users(organization_id: str = "") -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        if organization_id:
            rows = conn.execute(
                "SELECT id, org_id, email, role, status, last_login, created_at FROM admin_users WHERE org_id = ? "
                "ORDER BY created_at DESC LIMIT 2000",
                (str(organization_id),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, org_id, email, role, status, last_login, created_at FROM admin_users ORDER BY created_at DESC LIMIT 2000"
            ).fetchall()
    return [dict(r) for r in rows]


def password_accounts(conn: Any, organization_id: str = "", query: str = "", limit: int = 500) -> List[Dict[str, Any]]:
    """Built-in password accounts, optionally filtered. `conn` is the auth issuer connection."""
    clauses: List[str] = []
    params: List[Any] = []
    if organization_id:
        clauses.append("org_id = ?")
        params.append(str(organization_id))
    text = str(query or "").strip().lower()
    if text:
        clauses.append("(lower(email) LIKE ? OR lower(COALESCE(full_name, '')) LIKE ? OR id = ?)")
        like = "%" + text.replace("%", "").replace("_", "") + "%"
        params.extend([like, like, text])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit or 500), 2000)))
    try:
        rows = conn.execute(
            "SELECT id, email, full_name, role, org_id, is_active, created_at, last_login_at FROM pqc_users"
            + where + " ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    except Exception:
        return []
    return [
        {"id": r[0], "email": r[1], "full_name": r[2] or "", "role": r[3], "org_id": r[4],
         "is_active": bool(r[5]), "created_at": r[6], "last_login_at": r[7]}
        for r in rows
    ]
