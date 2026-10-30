"""Password reset for built-in (password) accounts.

  POST /auth/password-reset/request  {email}            always the same answer; emails a link only
                                                         when an active account has that address
  POST /auth/password-reset/confirm  {token, password}   sets the new password and signs the account
                                                         out everywhere
  GET  /reset-password                                   static/reset-password.html

The link is {base}/reset-password#token=<token>: like an invitation, the token rides in the URL
fragment, which browsers never send to a server or in a Referer header. Only its SHA-256 is stored.
A token expires after MORROW_PASSWORD_RESET_TTL_SECONDS (default 30 minutes), works once, and a
newer request for the same account replaces older ones. A weak new password is refused before the
token is claimed, so a typo does not burn the link.

Accounts that sign in through an external identity provider have no password here; their
provider resets it.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from services import auth_issuer

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,256}$")

SCHEMA = """
    CREATE TABLE IF NOT EXISTS morrow_password_resets (
        token_sha256 TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    )
"""


class ResetError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def ttl_seconds() -> int:
    try:
        value = int(str(os.getenv("MORROW_PASSWORD_RESET_TTL_SECONDS") or "1800").strip())
    except ValueError:
        value = 1800
    return max(300, min(value, 86400))


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def init_table(db) -> None:
    db.execute(SCHEMA)
    db.commit()


def create(db, email: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """A new reset token for the active account with this address, or None when there is none."""
    address = str(email or "").strip().lower()
    if not address or len(address) > 320:
        return None
    init_table(db)
    user = auth_issuer.get_user_by_email(db, address)
    if not user or not user.get("is_active"):
        return None
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("DELETE FROM morrow_password_resets WHERE user_id=?", (user["id"],))
    db.execute(
        "INSERT INTO morrow_password_resets (token_sha256, user_id, created_at, expires_at, used_at) "
        "VALUES (?,?,?,?,NULL)",
        (_digest(token), user["id"], now, now + ttl_seconds()),
    )
    db.commit()
    return token, {k: v for k, v in user.items() if k != "password_hash"}


def consume(db, token: str, new_password: str) -> Dict[str, Any]:
    """Set the new password for a valid token. Raises ResetError."""
    raw = str(token or "").strip()
    if not _TOKEN_RE.match(raw):
        raise ResetError(404, "This reset link isn't valid. Request a new one.")
    init_table(db)
    digest = _digest(raw)
    row = db.execute(
        "SELECT user_id, expires_at, used_at FROM morrow_password_resets WHERE token_sha256=?", (digest,)
    ).fetchone()
    if not row:
        raise ResetError(404, "This reset link isn't valid. Request a new one.")
    user_id, expires_at, used_at = row[0], int(row[1] or 0), row[2]
    if used_at:
        raise ResetError(410, "This reset link has already been used. Request a new one if you need to.")
    if expires_at < int(time.time()):
        raise ResetError(410, "This reset link has expired. Request a new one.")
    try:
        auth_issuer._validate_password_strength(str(new_password or ""))
    except ValueError as exc:
        raise ResetError(400, str(exc)) from None
    claimed = db.execute(
        "UPDATE morrow_password_resets SET used_at=? WHERE token_sha256=? AND used_at IS NULL",
        (int(time.time()), digest),
    )
    if int(claimed.rowcount or 0) != 1:
        db.rollback()
        raise ResetError(410, "This reset link has already been used. Request a new one if you need to.")
    user = auth_issuer.get_user_by_id(db, user_id)
    if not user or not user.get("is_active"):
        db.commit()
        raise ResetError(404, "This reset link isn't valid. Request a new one.")
    db.execute("UPDATE morrow_users SET password_hash=? WHERE id=?",
               (auth_issuer._hash_password(new_password), user_id))
    db.commit()
    # Whoever knew the old password is signed out too.
    auth_issuer.revoke_refresh_sessions(db, user_id=user_id)
    return user


def email_body(link: str, email: str) -> Dict[str, str]:
    minutes = ttl_seconds() // 60
    return {
        "subject": "Reset your Morrow password",
        "body": (
            f"Someone asked to reset the password for the Morrow account {email}.\n\n"
            f"To choose a new password, open this link within {minutes} minutes:\n\n{link}\n\n"
            "The link works once. If you didn't ask for this, ignore this email: your password "
            "stays the same.\n"
        ),
    }
