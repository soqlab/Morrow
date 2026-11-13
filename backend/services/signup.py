"""Public sign-up with a passkey: a new organization and its first administrator, and no email.

  GET  /signup                                         public page (static/signup.html)
  POST /auth/passkey/register/begin  {kind: "signup", full_name?, organization?}
  POST /auth/passkey/register/finish {challenge_id, credential}
       -> a session, the new organization, and the account's recovery codes (returned this once)

Nothing is typed except an optional display name and organization name. The account is created
with a passkey (resident key and user verification required, like every passkey here), never a
password, and it has no email address: it signs in with the passkey and recovers with the recovery
codes the sign-up answers with. The person becomes the admin of a new organization of their own.

When it is open. MORROW_PASSKEY_SIGNUP=1 opens it and =0 closes it; unset, it follows
MORROW_PASSKEYS_ONLY (open on a passkeys-only server, closed otherwise). Whatever the flag says, it
stays closed unless passkeys work (MORROW_PUBLIC_BASE_URL) and MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1:
an account anyone can make must not be able to point the scanner at hosts it hasn't proved it
controls (services/domain_verification.py). Public checks on /<domain> are unchanged.

Abuse controls. Completed sign-ups are counted in morrow_signups (a keyed hash of the address,
never the address itself) and refused with 429 above:

  MORROW_SIGNUP_PER_IP_PER_HOUR    default 3     from one address in the last hour
  MORROW_SIGNUP_PER_IP_PER_DAY     default 10    from one address in the last 24 hours
  MORROW_SIGNUP_GLOBAL_PER_HOUR    default 60    from everyone in the last hour
  MORROW_SIGNUP_GLOBAL_PER_DAY     default 500   from everyone in the last 24 hours

0 switches a limit off. The budget is checked when the ceremony starts (a cheap refusal) and again
when it finishes (the one that counts). The routes are also under the per-address auth rate limit
(MORROW_RATE_LIMIT_AUTH). The form carries a field people never see and scripts fill in; a filled
one is refused like any other bad request, without saying why. No third-party CAPTCHA: the page
makes no third-party request.

New organizations get the per-organization caps MORROW_SIGNUP_API_CALLS_PER_MIN and
MORROW_SIGNUP_SCANS_PER_HOUR (falling back to MORROW_TRIAL_API_CALLS_PER_MIN and
MORROW_TRIAL_SCANS_PER_HOUR; 0 or unset means the platform default), written as an ordinary
operator rate-limit override that an operator can change under Access > Rate limits.

The table has no tenant column: a sign-up record belongs to the platform's abuse budget, not to an
organization, like morrow_auth_tickets, and it lives in the same database.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_signups (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL DEFAULT '',
        ip_hash TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    )
"""

MAX_NAME = 120
MAX_ORGANIZATION = 120


class SignupError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def _flag_value(name: str) -> Optional[bool]:
    raw = str(os.getenv(name) or "").strip().lower()
    if not raw:
        return None
    return raw in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(str(os.getenv(name) or default).strip()))
    except (TypeError, ValueError):
        return default


def init_tables(db) -> None:
    db.execute(TABLE)
    db.execute("CREATE INDEX IF NOT EXISTS idx_morrow_signups_created ON morrow_signups (created_at)")
    db.commit()


def requested() -> bool:
    """What the flag asks for: MORROW_PASSKEY_SIGNUP, or MORROW_PASSKEYS_ONLY when it is unset."""
    explicit = _flag_value("MORROW_PASSKEY_SIGNUP")
    if explicit is not None:
        return explicit
    return bool(_flag_value("MORROW_PASSKEYS_ONLY"))


def enabled() -> bool:
    """Sign-up is open: asked for, passkeys work, and scans are limited to verified domains."""
    if not requested():
        return False
    from services import domain_verification, passkeys

    return passkeys.available() and domain_verification.enforcement_enabled()


def limits() -> Dict[str, int]:
    return {
        "per_ip_per_hour": _int_env("MORROW_SIGNUP_PER_IP_PER_HOUR", 3),
        "per_ip_per_day": _int_env("MORROW_SIGNUP_PER_IP_PER_DAY", 10),
        "global_per_hour": _int_env("MORROW_SIGNUP_GLOBAL_PER_HOUR", 60),
        "global_per_day": _int_env("MORROW_SIGNUP_GLOBAL_PER_DAY", 500),
    }


def ip_hash(ip: str) -> str:
    """A keyed hash of the address, so the table alone doesn't list who signed up from where."""
    key = str(os.getenv("MORROW_AUTH_JWT_SECRET") or "morrow-signup").encode("utf-8")
    return hmac.new(key, f"signup-ip:{str(ip or 'unknown').strip().lower()}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _count(db, since: int, hashed: str = "") -> int:
    if hashed:
        row = db.execute("SELECT COUNT(*) FROM morrow_signups WHERE created_at >= ? AND ip_hash = ?", (since, hashed)).fetchone()
    else:
        row = db.execute("SELECT COUNT(*) FROM morrow_signups WHERE created_at >= ?", (since,)).fetchone()
    return int(row[0] or 0) if row else 0


def check_budget(db, ip: str) -> None:
    """Raise SignupError(429) when one more sign-up from this address, or at all, is over a limit."""
    now = int(time.time())
    hashed = ip_hash(ip)
    lim = limits()
    if lim["per_ip_per_hour"] and _count(db, now - 3600, hashed) >= lim["per_ip_per_hour"]:
        raise SignupError(429, "Too many new accounts from your network in the last hour. Try again later.", "signup_ip_hour")
    if lim["per_ip_per_day"] and _count(db, now - 86400, hashed) >= lim["per_ip_per_day"]:
        raise SignupError(429, "Too many new accounts from your network today. Try again tomorrow.", "signup_ip_day")
    if lim["global_per_hour"] and _count(db, now - 3600) >= lim["global_per_hour"]:
        raise SignupError(429, "Morrow is taking a lot of new accounts right now. Try again in an hour.", "signup_global_hour")
    if lim["global_per_day"] and _count(db, now - 86400) >= lim["global_per_day"]:
        raise SignupError(429, "Morrow has taken all the new accounts it can today. Try again tomorrow.", "signup_global_day")


def record(db, user_id: str, ip: str) -> None:
    db.execute("INSERT INTO morrow_signups (id, user_id, ip_hash, created_at) VALUES (?,?,?,?)",
               (secrets.token_hex(12), str(user_id or ""), ip_hash(ip), int(time.time())))
    db.commit()


def clean(text: Any, limit: int) -> str:
    """One line of printable text, collapsed whitespace, at most `limit` characters."""
    value = "".join(ch for ch in str(text or "") if ch.isprintable())
    return " ".join(value.split())[:limit]


def organization_name(full_name: str, organization: str) -> str:
    if organization:
        return organization
    if full_name:
        return f"{full_name}'s organization"[:MAX_ORGANIZATION]
    return "My organization"


def caps() -> Tuple[int, int]:
    """(api_calls_per_min, scans_per_hour) for a new organization; 0 leaves the platform default."""
    def value(primary: str, fallback: str) -> int:
        raw = os.getenv(primary)
        if raw is None or not str(raw).strip():
            raw = os.getenv(fallback)
        try:
            return max(0, int(str(raw or 0).strip()))
        except (TypeError, ValueError):
            return 0

    return (value("MORROW_SIGNUP_API_CALLS_PER_MIN", "MORROW_TRIAL_API_CALLS_PER_MIN"),
            value("MORROW_SIGNUP_SCANS_PER_HOUR", "MORROW_TRIAL_SCANS_PER_HOUR"))


def create_organization(name: str) -> str:
    """A new organization row. Returns its id."""
    import db as _db

    organization_id = f"org_{secrets.token_hex(6)}"
    _db.upsert_organization(organization_id=organization_id, name=name, plan_type="free", subscription_status="active")
    api_per_min, scans_per_hour = caps()
    if api_per_min or scans_per_hour:
        try:
            from services import admin_console, org_rate_limits

            admin_console.set_rate_limits(org_id=organization_id, scans_per_hour=scans_per_hour,
                                          api_calls_per_min=api_per_min, actor="signup")
            org_rate_limits.invalidate()
        except Exception:
            # The account works without the cap; the operator sees the organization and can set one.
            logger.exception("sign-up: rate-limit caps not written for %s", organization_id)
    return organization_id


def add_owner(organization_id: str, user_id: str, display_name: str) -> None:
    """Record the sign-up's account as the organization's admin. The account row already carries
    the organization and the admin role (auth_issuer.create_passkey_user), which is what its tokens read."""
    from services import tenant_scope as _tenant_scope

    try:
        from db import upsert_organization_member

        # The new account has no tenant on its request yet: the organization is the one it just made.
        with _tenant_scope.platform_scope("sign-up: membership in the organization the account created", actor=str(user_id)):
            upsert_organization_member(organization_id, str(user_id), role="admin", display_name=display_name,
                                       email="", status="active")
    except Exception:
        logger.exception("sign-up: membership not recorded for %s", organization_id)
