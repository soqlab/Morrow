"""One-time recovery codes: getting back into an account without email.

  GET  /auth/recovery-codes          (signed in)  how many unused codes are left, and when they were made
  POST /auth/recovery-codes          (signed in, recent sign-in)  a new set of codes, shown this once
  POST /auth/recovery-codes/redeem   {code}       public: a short-lived ticket that can only register a passkey

What a code is. RECOVERY_CODE_COUNT (10) codes are made at a time. Each is 16 characters from a
31-character alphabet without look-alikes (no 0/O, 1/I/L), shown as four groups of four: about 79
random bits from `secrets`. The full set is returned once, by the call that makes it, and never again.

What is stored. Only HMAC-SHA256(pepper, code), one row per code. The pepper is a server secret
(MORROW_RECOVERY_CODE_PEPPER, or else a key derived from MORROW_AUTH_JWT_SECRET), so the table alone
is not enough to test guesses offline. There is no per-code salt, on purpose: the codes are uniformly
random with about 79 bits each, so there is no dictionary to precompute, and a deterministic keyed hash is
what lets a code be found without a username (sign-in here asks for none). Rotating the pepper (or
the JWT secret it is derived from, when no pepper is set) makes every outstanding code stop working;
passkeys keep working, and the owner makes a new set.

Use. A code works once: it is claimed atomically (UPDATE ... WHERE used_at IS NULL), so of two
concurrent attempts with the same code exactly one succeeds. A claimed code buys a "recover" ticket
(services/passkeys.issue_ticket) that lives MORROW_RECOVERY_CODE_TICKET_TTL_SECONDS (default 10
minutes) and whose only power is registering a new passkey (kind "recover" in
POST /auth/passkey/register/begin|finish). Registering it signs the account out everywhere else and
can remove the other passkeys, exactly like an emailed recovery link.

Regenerating replaces the whole set in one transaction: the old codes stop working and the new ones
exist in the same commit, so an account never ends up with neither.

The table holds no tenant column: a code belongs to an account, not to an organization, exactly like
morrow_passkeys and morrow_auth_tickets, and it lives in the same database as they do.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, List, Optional

RECOVERY_CODE_COUNT = 10
CODE_LENGTH = 16
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 31 characters: no 0/O, 1/I/L. 31**16 is about 2**79.3.

TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_recovery_codes (
        code_hmac TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        batch_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER
    )
"""


class RecoveryCodeError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def init_tables(db) -> None:
    db.execute(TABLE)
    db.execute("CREATE INDEX IF NOT EXISTS idx_morrow_recovery_codes_user ON morrow_recovery_codes (user_id)")
    db.commit()


def ticket_ttl() -> int:
    try:
        value = int(str(os.getenv("MORROW_RECOVERY_CODE_TICKET_TTL_SECONDS") or 600).strip())
    except ValueError:
        value = 600
    return max(120, min(value, 3600))


def _pepper() -> bytes:
    configured = str(os.getenv("MORROW_RECOVERY_CODE_PEPPER") or "").strip()
    if len(configured) >= 16:
        return configured.encode("utf-8")
    from services import auth_issuer

    secret = str(auth_issuer._SECRET or os.getenv("MORROW_AUTH_JWT_SECRET") or "").strip()
    if not secret:
        raise RecoveryCodeError(503, "Recovery codes aren't available: the server has no signing secret.", "unavailable")
    return hmac.new(secret.encode("utf-8"), b"morrow recovery-code pepper v1", hashlib.sha256).digest()


def normalize(code: Any) -> str:
    """Upper case, without spaces or dashes. "" when it can't be a code."""
    text = "".join(ch for ch in str(code or "").upper() if ch not in " -\t")
    if len(text) != CODE_LENGTH or any(ch not in ALPHABET for ch in text):
        return ""
    return text


def _hmac(normalized: str, pepper: Optional[bytes] = None) -> str:
    return hmac.new(pepper or _pepper(), normalized.encode("ascii"), hashlib.sha256).hexdigest()


def _format(raw: str) -> str:
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def generate(db, user_id: str) -> List[str]:
    """Replace the account's codes with a new set and return it. The only time the codes exist in clear."""
    pepper = _pepper()
    now = int(time.time())
    batch = secrets.token_hex(8)
    codes = ["".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH)) for _ in range(RECOVERY_CODE_COUNT)]
    try:
        db.execute("DELETE FROM morrow_recovery_codes WHERE user_id=?", (str(user_id),))
        for raw in codes:
            db.execute("INSERT INTO morrow_recovery_codes (code_hmac, user_id, batch_id, created_at, used_at) "
                       "VALUES (?,?,?,?,NULL)", (_hmac(raw, pepper), str(user_id), batch, now))
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    return [_format(raw) for raw in codes]


def status(db, user_id: str) -> Dict[str, Any]:
    try:
        row = db.execute(
            "SELECT COUNT(*), SUM(CASE WHEN used_at IS NULL THEN 1 ELSE 0 END), MAX(created_at) "
            "FROM morrow_recovery_codes WHERE user_id=?", (str(user_id),)
        ).fetchone()
    except Exception:
        row = None
    total = int((row or [0])[0] or 0)
    return {"total": total, "remaining": int((row[1] if row else 0) or 0),
            "generated_at": int(row[2]) if row and row[2] else None}


def remaining(db, user_id: str) -> int:
    return status(db, user_id)["remaining"]


def redeem(db, code: Any) -> str:
    """Use up one code. Returns the account id it belongs to; raises RecoveryCodeError (401) otherwise."""
    normalized = normalize(code)
    if not normalized:
        raise RecoveryCodeError(401, "That isn't a valid recovery code. Check it and try again.", "invalid")
    digest = _hmac(normalized)
    row = db.execute("SELECT user_id, used_at FROM morrow_recovery_codes WHERE code_hmac=?", (digest,)).fetchone()
    if not row:
        raise RecoveryCodeError(401, "That isn't a valid recovery code. Check it and try again.", "invalid")
    if row[1]:
        raise RecoveryCodeError(401, "This recovery code has already been used. Each code works once.", "used")
    cur = db.execute("UPDATE morrow_recovery_codes SET used_at=? WHERE code_hmac=? AND used_at IS NULL",
                     (int(time.time()), digest))
    db.commit()
    if int(cur.rowcount or 0) != 1:
        raise RecoveryCodeError(401, "This recovery code has already been used. Each code works once.", "used")
    return str(row[0])
