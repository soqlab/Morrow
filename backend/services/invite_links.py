"""Invitation links, previews and invitation emails.

Invitations live in admin_invitations (services/admin_console.py), keyed by their bearer token;
services/platform_access.py adds the non-secret invite id (a SHA-256 prefix of the token) and
revocation, which deletes the row and writes a revoke_invitation audit row naming that id.

Link format: {MORROW_PUBLIC_BASE_URL or the request origin}/invite#token=<token>. The token rides in
the URL fragment, which browsers never send to a server or put in a Referer header.

preview() tells the landing page what an invitation is for without revealing anything a token
holder does not already have: organization name, role, the invited address masked (a***@corp.com),
expiry and a status of valid|expired|used|revoked. An unknown token is "not found"; nothing here
takes an arbitrary email address, so it cannot be used to probe accounts.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, Optional

from db_feature_store import feature_conn

ROLE_LABELS = {"org_admin": "Organization admin", "analyst": "Analyst", "viewer": "Viewer", "platform_admin": "Organization admin"}
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,256}$")


def base_url(request: Any = None) -> str:
    from services.public_config import public_base_url

    configured = public_base_url()
    if configured:
        return configured
    if request is None:
        return ""
    try:
        return str(request.base_url).rstrip("/")
    except Exception:
        return ""


def invite_path(token: str) -> str:
    return f"/invite#token={token}"


def invite_link(token: str, request: Any = None) -> str:
    """A link for the console to show. The origin may come from the request.

    Safe here because the operator reads the link in the browser they made the request from: a
    forged Host header would only affect the attacker's own screen.
    """
    return base_url(request) + invite_path(token)


class PublicBaseUrlMissing(RuntimeError):
    """MORROW_PUBLIC_BASE_URL is not configured and the link is about to leave the process."""


def external_invite_link(token: str) -> str:
    """A link that will be EMAILED. The origin must be configured, never taken from the request.

    base_url() falls back to request.base_url, which is the Host header. TrustedHostMiddleware is
    only installed when MORROW_ALLOWED_HOSTS is not '*', so on a default deployment an attacker who can
    reach the API can set Host to a site they control, ask for an invitation to be emailed, and have
    the server send the real invitee a real invitation token pointed at the attacker's origin. A
    link that leaves the process has to come from configuration.
    """
    base = public_base_url_only()
    if not base:
        raise PublicBaseUrlMissing(
            "Set MORROW_PUBLIC_BASE_URL before emailing invitations: the link in the email must come "
            "from configuration, not from the Host header of whoever made the request."
        )
    return base + invite_path(token)


def public_base_url_only() -> str:
    """The configured public origin, with no request fallback."""
    from services.public_config import public_base_url

    return public_base_url()


def mask_email(email: str) -> str:
    address = str(email or "").strip()
    if "@" not in address:
        return "***"
    local, domain = address.rsplit("@", 1)
    return f"{local[:1] or '*'}***@{domain}"


def _digest(value: str) -> bytes:
    return hashlib.sha256(str(value or "").encode("utf-8")).digest()


def organization_name(org_id: str) -> str:
    oid = str(org_id or "")
    try:
        from db import list_organizations

        for org in list_organizations(limit=5000):
            if str(org.get("id") or "") == oid:
                return str(org.get("name") or "").strip() or "your organization"
    except Exception:
        pass
    try:
        with feature_conn() as conn:
            row = conn.execute("SELECT name FROM admin_orgs WHERE id = ?", (oid,)).fetchone()
        if row and str(row[0] or "").strip():
            return str(row[0]).strip()
    except Exception:
        pass
    return "your organization"


def _expired(expires_at: Any) -> bool:
    from services.platform_access import _expired as expired

    return expired(str(expires_at or ""))


def preview(token: str) -> Optional[Dict[str, Any]]:
    """The invitation summary for a token, or None when no invitation ever had that token."""
    raw = str(token or "").strip()
    if not _TOKEN_RE.match(raw):
        return None
    from services import platform_access

    platform_access._init()
    wanted = _digest(raw)
    # The landing page is unauthenticated and the invitee is not yet a member of anything, so this
    # lookup has no tenant of its own -- the tenant is inside the row being looked up. Under
    # Postgres RLS that is one of the audited cross-tenant paths; the summary handed back is masked
    # and reveals nothing a token holder does not already have.
    from services import tenant_scope as _scope

    with _scope.platform_scope("invitation preview: the tenant is inside the invitation"), feature_conn() as conn:
        row = conn.execute(
            "SELECT token, org_id, email, role, expires_at, accepted FROM admin_invitations WHERE token = ?", (raw,)
        ).fetchone()
        # The token is 256 random bits, so the indexed lookup reveals nothing useful; the digest
        # comparison is still constant-time so a near-miss is indistinguishable from a far one.
        if row and hmac.compare_digest(_digest(row["token"]), wanted):
            if int(row["accepted"] or 0):
                status = "used"
            elif _expired(row["expires_at"]):
                status = "expired"
            else:
                status = "valid"
            return {"organization_name": organization_name(row["org_id"]), "role": ROLE_LABELS.get(str(row["role"]), "Viewer"),
                    "invited_email_masked": mask_email(row["email"]), "expires_at": row["expires_at"], "status": status}
        revoked = conn.execute(
            "SELECT org_id, detail FROM admin_audit_log WHERE action = 'revoke_invitation' AND target_type = 'invitation' "
            "AND target_id = ? ORDER BY id DESC LIMIT 1",
            (platform_access.invite_id(raw),),
        ).fetchone()
    if revoked:
        match = re.search(r"email=(\S+)", str(revoked["detail"] or ""))
        return {"organization_name": organization_name(revoked["org_id"]), "role": None,
                "invited_email_masked": mask_email(match.group(1)) if match else None, "expires_at": None, "status": "revoked"}
    return None


def pending_token(organization_id: str, invite_id: str) -> Optional[Dict[str, Any]]:
    """The pending invitation (with its token) for a non-secret invite id, for server-side emailing."""
    wanted = str(invite_id or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{20}", wanted):
        return None
    from services import platform_access

    platform_access._init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT token, email, role, expires_at FROM admin_invitations WHERE org_id = ? AND accepted = 0",
            (str(organization_id),),
        ).fetchall()
    found = None
    for row in rows:
        if hmac.compare_digest(platform_access.invite_id(row["token"]), wanted):
            found = row
    if not found:
        return None
    return {"token": found["token"], "email": found["email"], "role": found["role"], "expires_at": found["expires_at"],
            "expired": _expired(found["expires_at"])}


def email_body(link: str, org_name: str, role: str, expires_at: str) -> Dict[str, str]:
    subject = f"You're invited to {org_name} on Morrow"
    text = (
        f"You have been invited to join {org_name} on Morrow as {ROLE_LABELS.get(role, role)}.\n\n"
        f"Open this link to review and accept the invitation:\n{link}\n\n"
        f"The link works once and expires {expires_at}. Sign in with this email address to accept it.\n"
        "If you did not expect this invitation, you can ignore this message.\n"
    )
    return {"subject": subject, "text": text}
