"""Trial requests: the only way a stranger can ask for an account.

Why this exists
---------------
``/auth/register`` is admin-only on purpose -- it creates accounts, and an unauthenticated caller
once used it to mint an admin. So there is no self-service signup, which left the public site with
no route from "this looks useful" to "I have a login" except the support address.

This closes that gap without opening the one self-service signup would open. An authenticated
account can scan arbitrary hosts, and none of the free checker's guardrails (opt-out before DNS,
per-domain budgets, two connections, port 443 only) apply to the real scanner. Handing that to
anyone who can type an email address would make this a free reconnaissance service. So a request
is a request: it is recorded, it waits, and an operator turns it into an organization and an
invitation by hand, from the admin portal.

What it does not do
-------------------
It creates nothing. ``approve`` is a thin composition of primitives that already exist and are
already audited -- ``db.upsert_organization`` and ``admin_console.invite_user`` -- so a trial
account is indistinguishable from one an operator made directly, and the audit trail is the same.

Spam
----
A honeypot field, a per-IP rate limit on the route, length caps here, and one pending request per
email address. Deliberately no captcha: every public page on this site makes no third-party
request, and a captcha is a third-party request. That is a real trade -- this intake is weaker
against a determined script than a captcha would be -- and the mitigation is that a request grants
nothing until a person approves it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()

#: Deliberately permissive: an address that bounces is the operator's problem to notice, and a
#: regex that rejects a valid address the applicant actually owns is worse than one that accepts a
#: fake they gain nothing from.
_EMAIL_RE = re.compile(r"^[^@\s,;:<>\"]{1,64}@[A-Za-z0-9]([A-Za-z0-9.-]{0,251})\.[A-Za-z]{2,24}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251})\.[A-Za-z]{2,24}$")

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DECLINED = "declined"
STATUS_SPAM = "spam"
STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_DECLINED, STATUS_SPAM)

#: Field caps. A long "what are you trying to do" is useful; a megabyte of it is an attack.
MAX_EMAIL = 254
MAX_NAME = 120
MAX_COMPANY = 160
MAX_DOMAIN = 253
MAX_USE_CASE = 2000


class TrialRequestError(Exception):
    """A refusal with a reason the public page can show verbatim."""

    def __init__(self, status_code: int, detail: str, field: str = ""):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.detail = str(detail)
        self.field = str(field)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _db_identity() -> str:
    return str(os.getenv("PQC_SCANNER_DB", "") or os.getenv("DATABASE_URL", "") or "default")


def init_tables() -> None:
    """This module's own table. Platform-level: a trial request belongs to no organization yet."""
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS trial_requests (
                    id              TEXT PRIMARY KEY,
                    created_at      TEXT NOT NULL,
                    email           TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    company         TEXT NOT NULL DEFAULT '',
                    domain          TEXT NOT NULL DEFAULT '',
                    use_case        TEXT NOT NULL DEFAULT '',
                    requester_ip_hash TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    decided_at      TEXT NOT NULL DEFAULT '',
                    decided_by      TEXT NOT NULL DEFAULT '',
                    note            TEXT NOT NULL DEFAULT '',
                    organization_id TEXT NOT NULL DEFAULT '',
                    invite_id       TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_trial_requests_status
                    ON trial_requests (status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_trial_requests_email
                    ON trial_requests (email, status);
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def hash_ip(value: Any) -> str:
    """A salted hash, never the address.

    Same reasoning as the public checker's check log: enough to tell two requests apart and to
    investigate a flood, not enough to profile anyone. The salt is the checker's, so one
    deployment-wide salt covers both.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    from services import public_check
    return public_check.hash_ip(raw)


def _clean(value: Any, cap: int) -> str:
    text = str(value or "").replace("\x00", "").strip()
    # Collapse the runs of whitespace a paste brings with it, but keep paragraph breaks in the
    # free-text field readable.
    return text[:cap]


def normalize_email(value: Any) -> str:
    email = _clean(value, MAX_EMAIL).lower()
    if not email:
        raise TrialRequestError(400, "An email address is required, so there is somewhere to send "
                                     "the invitation.", "email")
    if not _EMAIL_RE.match(email):
        raise TrialRequestError(400, "That does not look like an email address we can send to.",
                                "email")
    return email


def normalize_domain(value: Any) -> str:
    """Optional. The domain the requester wants to assess, for context on the decision."""
    domain = _clean(value, MAX_DOMAIN).lower()
    if not domain:
        return ""
    domain = domain.split("//")[-1].split("/")[0].split("@")[-1].strip().strip(".")
    if not _HOST_RE.match(domain):
        raise TrialRequestError(400, "That does not look like a domain name. Leave it blank if you "
                                     "would rather not say.", "domain")
    return domain


def submit(email: Any, name: Any = "", company: Any = "", domain: Any = "", use_case: Any = "",
           client_ip: str = "") -> Dict[str, Any]:
    """Record a request. Returns the stored row; raises TrialRequestError on a refusal."""
    init_tables()
    address = normalize_email(email)
    host = normalize_domain(domain)
    row = {
        "id": secrets.token_hex(8),
        "created_at": _now(),
        "email": address,
        "name": _clean(name, MAX_NAME),
        "company": _clean(company, MAX_COMPANY),
        "domain": host,
        "use_case": _clean(use_case, MAX_USE_CASE),
        "requester_ip_hash": hash_ip(client_ip),
        "status": STATUS_PENDING,
    }
    with feature_conn() as conn:
        # One pending request per address. A second submission is not an error the applicant needs
        # to see -- it is usually an impatient reload -- so it returns the request they already
        # have rather than refusing or creating a duplicate for the operator to triage twice.
        existing = conn.execute(
            "SELECT id, created_at, email, status FROM trial_requests "
            "WHERE email = ? AND status = ? ORDER BY created_at DESC LIMIT 1",
            (address, STATUS_PENDING)).fetchone()
        if existing is not None:
            return {"id": existing["id"], "created_at": existing["created_at"],
                    "email": existing["email"], "status": existing["status"], "duplicate": True}
        conn.execute(
            "INSERT INTO trial_requests (id, created_at, email, name, company, domain, use_case, "
            "requester_ip_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["id"], row["created_at"], row["email"], row["name"], row["company"],
             row["domain"], row["use_case"], row["requester_ip_hash"], row["status"]))
        conn.commit()
    logger.info("trial request recorded id=%s domain=%s", row["id"], row["domain"] or "-")
    row["duplicate"] = False
    return row


def _row_to_dict(row: Any) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "email": row["email"],
        "name": row["name"],
        "company": row["company"],
        "domain": row["domain"],
        "use_case": row["use_case"],
        "status": row["status"],
        "decided_at": row["decided_at"],
        "decided_by": row["decided_by"],
        "note": row["note"],
        "organization_id": row["organization_id"],
        "invite_id": row["invite_id"],
    }


def get(request_id: str) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM trial_requests WHERE id = ?",
                           (str(request_id),)).fetchone()
    return _row_to_dict(row) if row is not None else None


def list_requests(status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    init_tables()
    capped = max(1, min(500, int(limit)))
    with feature_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM trial_requests WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (str(status), capped)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM trial_requests ORDER BY "
                # Pending first: this list is a work queue, not an archive.
                "CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC LIMIT ?",
                (capped,)).fetchall()
    return [_row_to_dict(row) for row in rows]


def counts() -> Dict[str, int]:
    """For the badge on the admin navigation."""
    init_tables()
    out = {status: 0 for status in STATUSES}
    try:
        with feature_conn() as conn:
            for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM trial_requests GROUP BY status").fetchall():
                out[str(row["status"])] = int(row["n"] or 0)
    except Exception:
        logger.warning("trial requests: count failed")
    out["total"] = sum(out.get(status, 0) for status in STATUSES)
    return out


def _decide(request_id: str, status: str, operator: str, note: str = "",
            organization_id: str = "", invite_id: str = "") -> Dict[str, Any]:
    init_tables()
    now = _now()
    with feature_conn() as conn:
        cursor = conn.execute(
            "UPDATE trial_requests SET status = ?, decided_at = ?, decided_by = ?, note = ?, "
            "organization_id = ?, invite_id = ? WHERE id = ? AND status = ?",
            (status, now, _clean(operator, 200), _clean(note, 1000), str(organization_id or ""),
             str(invite_id or ""), str(request_id), STATUS_PENDING))
        conn.commit()
    if not cursor.rowcount:
        current = get(request_id)
        if current is None:
            raise TrialRequestError(404, "No trial request with that id.")
        raise TrialRequestError(
            409, f"That request was already {current['status']} "
                 f"{('on ' + current['decided_at']) if current['decided_at'] else ''}".strip() + ".")
    return get(request_id) or {}


def decline(request_id: str, operator: str, note: str = "", spam: bool = False) -> Dict[str, Any]:
    """Declined requests are kept. An address that was declined once and applies again is worth
    seeing in context, and deleting the row would hide that."""
    return _decide(request_id, STATUS_SPAM if spam else STATUS_DECLINED, operator, note)


#: The role a trial owner gets. They administer their own organization and nothing above it --
#: "platform_admin" is this product's operator role and must never be grantable by an intake.
DEFAULT_TRIAL_ROLE = "org_admin"


def trial_caps() -> Tuple[int, int]:
    """(api_calls_per_min, scans_per_hour) applied to a new trial organization. 0 means no cap.

    These are stored as an ordinary operator rate-limit override at approval, which is the only
    per-organization limit there is. A plan-based tier used to sit between the override and the
    platform default and could have carried these caps; it was removed with the billing code when
    the platform became free. Without this, a trial workspace would run at the platform default
    like everything else.

    The override path is already enforced in limits_for() at the top of the precedence order, is
    already audited, and is already visible and editable under Access -> Rate limits. Writing the
    cap there makes the promise on /trial true without touching the rate limiter or changing
    behaviour for self-hosters, who get 0/0 unless they set these.
    """
    def value(name: str, default: int) -> int:
        try:
            return max(0, int(str(os.getenv(name, "") or default).strip()))
        except (TypeError, ValueError):
            return default

    return value("PQC_TRIAL_API_CALLS_PER_MIN", 0), value("PQC_TRIAL_SCANS_PER_HOUR", 0)


def approve(request_id: str, operator: str, organization_name: str = "", plan_type: str = "trial",
            role: str = DEFAULT_TRIAL_ROLE, expires_hours: int = 168,
            note: str = "") -> Dict[str, Any]:
    """Create the organization and a single-use invitation, then mark the request approved.

    Composition only. The organization is created by ``db.upsert_organization`` and the invitation
    by ``admin_console.invite_user``, which is what an operator creating one by hand calls, so this
    produces nothing a trial account has that a normal one does not -- and both write their own
    audit rows.

    The invitation token is returned once and never stored here: the request row keeps only the
    non-secret invite id. The caller sends the link, or emails it through the existing
    ``/platform/customers/{org}/invitations/{invite_id}/email`` route.
    """
    pending = get(request_id)
    if pending is None:
        raise TrialRequestError(404, "No trial request with that id.")
    if pending["status"] != STATUS_PENDING:
        raise TrialRequestError(409, f"That request was already {pending['status']}.")

    import db as _db
    from services import admin_console

    # Validated before anything is created. invite_user reports an unknown role by returning an
    # error, which on its own leaves an organization behind with nobody invited into it --
    # recoverable, but an orphan someone then has to notice.
    wanted_role = str(role or DEFAULT_TRIAL_ROLE).strip()
    if wanted_role == "platform_admin":
        # This is the operator role for the whole platform. No intake path may grant it, however
        # the request was shaped.
        raise TrialRequestError(
            400, "platform_admin is an operator role and cannot be granted from a trial request.",
            "role")
    if wanted_role not in admin_console.VALID_ROLES:
        raise TrialRequestError(
            400, f"{wanted_role!r} is not a role. Valid roles are "
                 f"{', '.join(sorted(r for r in admin_console.VALID_ROLES if r != 'platform_admin'))}.",
            "role")

    name = _clean(organization_name, MAX_COMPANY) or pending["company"] or \
        (pending["domain"] or pending["email"].split("@")[-1])
    organization_id = f"org_{secrets.token_hex(6)}"
    try:
        _db.upsert_organization(organization_id=organization_id, name=name, plan_type=plan_type,
                                subscription_status="trialing")
    except Exception as exc:
        logger.exception("trial approve: creating the organization failed for %s", request_id)
        raise TrialRequestError(500, "The organization could not be created, so nothing was "
                                     "changed. The request is still pending.") from exc

    invitation = admin_console.invite_user(
        org_id=organization_id, email=pending["email"], role=wanted_role,
        invited_by=_clean(operator, 200) or "operator", expires_hours=int(expires_hours))
    if not invitation.get("ok"):
        # The organization exists but nobody was invited into it. Say so rather than reporting
        # success: an empty organization and a pending request is a recoverable state, and a
        # request marked approved with no invitation is not.
        raise TrialRequestError(
            500, f"The organization {organization_id} was created but the invitation failed "
                 f"({invitation.get('error') or 'unknown error'}). The request is still pending; "
                 "invite the address from the Invitations view, or decline and start again.")

    # The caps, before the invitation is used rather than after the first complaint. Written as an
    # operator override because that is the only per-organization limit enforced on a deployment
    # without billing enforcement -- see trial_caps().
    api_per_min, scans_per_hour = trial_caps()
    capped = {"api_calls_per_min": api_per_min, "scans_per_hour": scans_per_hour}
    if api_per_min or scans_per_hour:
        try:
            admin_console.set_rate_limits(
                org_id=organization_id, scans_per_hour=scans_per_hour,
                api_calls_per_min=api_per_min,
                actor=_clean(operator, 200) or "trial-approval")
            # limits_for() reads a cache with a 15-second TTL. The admin portal's own route lets
            # that expire, which is fine for changing a limit; for a cap it is a window in which
            # the new organization is unlimited, so expire it now.
            from services import org_rate_limits
            org_rate_limits.invalidate()
        except Exception:
            # The organization and the invitation both exist and are usable. Report the gap rather
            # than failing the approval: an uncapped trial is a cost problem, a half-approved
            # request is a correctness problem.
            logger.exception("trial approve: applying caps failed for %s", organization_id)
            capped["error"] = "the rate-limit caps were not applied; set them under Access -> Rate limits"

    decided = _decide(request_id, STATUS_APPROVED, operator, note, organization_id,
                      str(invitation.get("invite_id") or ""))
    decided["organization_name"] = name
    decided["plan_type"] = plan_type
    decided["role"] = wanted_role
    decided["caps"] = capped
    decided["invite_token"] = invitation.get("token")       # shown once, never stored
    decided["invite_expires_at"] = invitation.get("expires_at")
    decided["invite_email"] = pending["email"]
    return decided


def prune(days: int = 365) -> int:
    """Drop decided requests older than ``days``. Pending ones are never pruned: an unanswered
    request is work, and work does not expire quietly."""
    init_tables()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))).isoformat()
    with feature_conn() as conn:
        cursor = conn.execute(
            "DELETE FROM trial_requests WHERE status != ? AND decided_at != '' AND decided_at < ?",
            (STATUS_PENDING, cutoff))
        conn.commit()
    return int(cursor.rowcount or 0)


def fingerprint(email: str, ip_hash: str) -> str:
    """A stable id for a submitter, for rate limiting without storing an address."""
    return hashlib.sha256(f"{email}|{ip_hash}".encode("utf-8")).hexdigest()[:32]
