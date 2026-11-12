"""Passkeys (WebAuthn) for built-in accounts: sign-in without a password.

  POST /auth/passkey/login/begin      {email?}                          options for navigator.credentials.get()
  POST /auth/passkey/login/finish     {challenge_id, credential}        a session, like /auth/login
  POST /auth/passkey/register/begin   {kind, token?, full_name?}        options for navigator.credentials.create()
  POST /auth/passkey/register/finish  {challenge_id, credential, ...}   stores the passkey; see `kind` below
  GET/PATCH/DELETE /auth/passkeys[/{id}]                                the signed-in account's passkeys

Registration `kind` says what the new passkey is for, and what proves the right to register it:

  account  the signed-in account adds one (Bearer token; a recent sign-in when it already has one)
  invite   an invitation creates the invited account (the invitation token)
  join     domain team sign-in creates an account (the emailed join link, services/team_join.py)
  recover  account recovery (the emailed recovery link)
  enroll   a password account, signed in with its password, must add one (MORROW_PASSKEYS_ONLY=1)

Relying party. The RP ID is the host of MORROW_PUBLIC_BASE_URL and the only accepted origin is
that URL's origin (override with MORROW_WEBAUTHN_RP_ID and MORROW_WEBAUTHN_ORIGINS). Without
either, passkeys are unavailable rather than bound to whatever Host header a request carried:
a passkey is bound to its RP ID forever, so it must never come from the request.

Ceremonies. Every challenge is 32 random bytes, stored server side, single use (claimed atomically
before verification, so a failed attempt burns it too), and expires after
MORROW_WEBAUTHN_CHALLENGE_TTL_SECONDS (default 5 minutes). Registration asks for a discoverable
credential (resident key required) and user verification required, and verification requires UV.
Attestation is "none": what is checked is the key, not the make of the authenticator.

Sign counter. The stored count is compared with every assertion (py_webauthn refuses a count that
did not increase when either side is non-zero). A refusal on the count is treated as a possible
cloned authenticator: that passkey is flagged and refused from then on, and the event is
journaled. Its owner removes it and signs in with another passkey or recovers the account by email.
Synced passkeys (iCloud, Google) report 0 every time and never trip this.

Passwords. The first passkey on an account deletes its password (password_hash set to NULL) and from
then on /auth/login refuses it. Accounts that still have a password are asked to add a passkey after
signing in with it; with MORROW_PASSKEYS_ONLY=1 the password sign-in returns no session at all, only
a short-lived single-use enrollment ticket that can do nothing except register a passkey.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

CHALLENGE_TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_webauthn_challenges (
        id TEXT PRIMARY KEY,
        challenge TEXT NOT NULL,
        purpose TEXT NOT NULL,
        user_id TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL DEFAULT '{}',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    )
"""

PASSKEY_TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_passkeys (
        credential_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        transports TEXT NOT NULL DEFAULT '',
        aaguid TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        device_type TEXT NOT NULL DEFAULT '',
        backed_up INTEGER NOT NULL DEFAULT 0,
        clone_suspected INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
    )
"""

#: Single-use emailed or handed-out links: account recovery, domain team join, passkey enrollment.
#: Only the SHA-256 of a ticket is stored.
TICKET_TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_auth_tickets (
        token_sha256 TEXT PRIMARY KEY,
        purpose TEXT NOT NULL,
        user_id TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        org_id TEXT NOT NULL DEFAULT '',
        domain TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    )
"""

TICKET_PURPOSES = {"enroll", "recover", "join"}
REGISTRATION_KINDS = {"account", "invite", "join", "recover", "enroll"}
MAX_PASSKEYS_PER_USER = 20
_TOKEN_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class PasskeyError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


# ── Configuration ──────────────────────────────────────────────────────────────

def _flag(name: str) -> bool:
    return str(os.getenv(name, "0") or "0").strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except ValueError:
        value = default
    return max(low, min(value, high))


def challenge_ttl() -> int:
    return _int_env("MORROW_WEBAUTHN_CHALLENGE_TTL_SECONDS", 300, 60, 900)


def ticket_ttl(purpose: str) -> int:
    if purpose == "enroll":
        return _int_env("MORROW_PASSKEY_ENROLL_TTL_SECONDS", 600, 120, 3600)
    if purpose == "join":
        return _int_env("MORROW_TEAM_JOIN_TTL_SECONDS", 1800, 300, 86400)
    return _int_env("MORROW_ACCOUNT_RECOVERY_TTL_SECONDS", 1800, 300, 86400)


def reauth_seconds() -> int:
    """How recent a sign-in must be to add a passkey to an account that already has one."""
    return _int_env("MORROW_PASSKEY_REAUTH_SECONDS", 600, 60, 86400)


def library_available() -> bool:
    try:
        import webauthn  # noqa: F401
        return True
    except Exception:
        return False


def relying_party() -> Optional[Dict[str, Any]]:
    """{id, name, origins} from configuration only, or None when passkeys can't be offered."""
    from services.public_config import public_base_url

    base = public_base_url()
    rp_id = str(os.getenv("MORROW_WEBAUTHN_RP_ID") or "").strip().lower().rstrip(".")
    origins = [o.strip().rstrip("/") for o in str(os.getenv("MORROW_WEBAUTHN_ORIGINS") or "").split(",") if o.strip()]
    if base:
        parsed = urlparse(base)
        rp_id = rp_id or (parsed.hostname or "")
        origins = origins or [f"{parsed.scheme}://{parsed.netloc}"]
    if not rp_id or not origins:
        return None
    return {"id": rp_id, "name": str(os.getenv("MORROW_WEBAUTHN_RP_NAME") or "Morrow").strip()[:64] or "Morrow",
            "origins": origins}


def available() -> bool:
    return relying_party() is not None and library_available()


def passkeys_only() -> bool:
    """MORROW_PASSKEYS_ONLY=1, and only once passkeys can actually be used (else it would lock everyone out)."""
    return _flag("MORROW_PASSKEYS_ONLY") and available()


def _rp() -> Dict[str, Any]:
    rp = relying_party()
    if rp is None or not library_available():
        raise PasskeyError(503, "Passkeys aren't set up on this server: MORROW_PUBLIC_BASE_URL is not configured.",
                           "passkeys_unavailable")
    return rp


# ── Storage ────────────────────────────────────────────────────────────────────

def init_tables(db) -> None:
    db.execute(CHALLENGE_TABLE)
    db.execute(PASSKEY_TABLE)
    db.execute(TICKET_TABLE)
    db.execute("CREATE INDEX IF NOT EXISTS idx_morrow_passkeys_user ON morrow_passkeys (user_id)")
    db.commit()


def _now() -> int:
    return int(time.time())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    raw = str(text or "")
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _digest(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _valid_token(token: Any) -> bool:
    text = str(token or "")
    return 16 <= len(text) <= 256 and set(text) <= _TOKEN_CHARS


def _row(r: Any) -> Dict[str, Any]:
    return {"id": r[0], "name": r[1] or "", "created_at": r[2], "last_used_at": r[3], "device_type": r[4] or "",
            "backed_up": bool(r[5]), "transports": [t for t in str(r[6] or "").split(",") if t],
            "clone_suspected": bool(r[7])}


_LIST_COLUMNS = "credential_id, name, created_at, last_used_at, device_type, backed_up, transports, clone_suspected"


def list_passkeys(db, user_id: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        f"SELECT {_LIST_COLUMNS} FROM morrow_passkeys WHERE user_id=? ORDER BY created_at",  # nosec B608  # column list is a literal
        (str(user_id),),
    ).fetchall()
    return [_row(r) for r in rows]


def count_passkeys(db, user_id: str) -> int:
    try:
        row = db.execute("SELECT COUNT(*) FROM morrow_passkeys WHERE user_id=?", (str(user_id),)).fetchone()
    except Exception:
        return 0
    return int(row[0] or 0) if row else 0


def rename_passkey(db, user_id: str, credential_id: str, name: str) -> bool:
    clean = " ".join(str(name or "").split())[:60]
    if not clean:
        raise PasskeyError(400, "Give the passkey a name.")
    cur = db.execute("UPDATE morrow_passkeys SET name=? WHERE credential_id=? AND user_id=?",
                     (clean, str(credential_id), str(user_id)))
    db.commit()
    return int(cur.rowcount or 0) > 0


def remove_passkey(db, user_id: str, credential_id: str) -> bool:
    """Delete one passkey. The last one is refused: the account would have no way to sign in."""
    if not db.execute("SELECT 1 FROM morrow_passkeys WHERE credential_id=? AND user_id=?",
                      (str(credential_id), str(user_id))).fetchone():
        return False
    # The count and the delete happen in one statement, so two concurrent removals of the last two
    # passkeys cannot both succeed.
    cur = db.execute(
        "DELETE FROM morrow_passkeys WHERE credential_id=? AND user_id=? "
        "AND (SELECT COUNT(*) FROM morrow_passkeys WHERE user_id=?) > 1",
        (str(credential_id), str(user_id), str(user_id)),
    )
    db.commit()
    if int(cur.rowcount or 0) == 0:
        raise PasskeyError(409, "This is your last passkey. Add another one before removing it, so you can still sign in.",
                           "last_passkey")
    return True


def remove_other_passkeys(db, user_id: str, keep_credential_id: str) -> int:
    cur = db.execute("DELETE FROM morrow_passkeys WHERE user_id=? AND credential_id<>?",
                     (str(user_id), str(keep_credential_id)))
    db.commit()
    return int(cur.rowcount or 0)


def store_credential(db, user_id: str, verified: Dict[str, Any], name: str = "") -> Dict[str, Any]:
    if count_passkeys(db, user_id) >= MAX_PASSKEYS_PER_USER:
        raise PasskeyError(400, f"An account can hold up to {MAX_PASSKEYS_PER_USER} passkeys. Remove one first.")
    now = _now()
    label = " ".join(str(name or "").split())[:60] or default_name(verified)
    try:
        db.execute(
            "INSERT INTO morrow_passkeys (credential_id, user_id, public_key, sign_count, transports, aaguid, name, "
            "device_type, backed_up, clone_suspected, created_at, last_used_at) VALUES (?,?,?,?,?,?,?,?,?,0,?,NULL)",
            (verified["credential_id"], str(user_id), verified["public_key"], int(verified["sign_count"]),
             ",".join(verified.get("transports") or []), verified.get("aaguid") or "", label,
             verified.get("device_type") or "", 1 if verified.get("backed_up") else 0, now),
        )
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        if "unique" in str(exc).lower() or "constraint" in str(exc).lower() or "duplicate" in str(exc).lower():
            raise PasskeyError(409, "This passkey is already registered.") from None
        raise
    return {"id": verified["credential_id"], "name": label, "created_at": now, "last_used_at": None,
            "device_type": verified.get("device_type") or "", "backed_up": bool(verified.get("backed_up")),
            "transports": list(verified.get("transports") or []), "clone_suspected": False}


def default_name(verified: Dict[str, Any]) -> str:
    if verified.get("backed_up") or verified.get("device_type") == "multi_device":
        return "Synced passkey"
    return "Security key or device passkey"


# ── Tickets ────────────────────────────────────────────────────────────────────

def issue_ticket(db, purpose: str, *, user_id: str = "", email: str = "", org_id: str = "", domain: str = "",
                 replace_previous: bool = True) -> str:
    if purpose not in TICKET_PURPOSES:
        raise ValueError("unknown ticket purpose")
    token = secrets.token_urlsafe(32)
    now = _now()
    if replace_previous:
        # A newer link replaces older ones for the same account (or address, before an account exists).
        if user_id:
            db.execute("DELETE FROM morrow_auth_tickets WHERE purpose=? AND user_id=? AND used_at IS NULL", (purpose, user_id))
        elif email:
            db.execute("DELETE FROM morrow_auth_tickets WHERE purpose=? AND email=? AND used_at IS NULL", (purpose, email))
    db.execute(
        "INSERT INTO morrow_auth_tickets (token_sha256, purpose, user_id, email, org_id, domain, created_at, expires_at, used_at) "
        "VALUES (?,?,?,?,?,?,?,?,NULL)",
        (_digest(token), purpose, str(user_id or ""), str(email or "").lower(), str(org_id or ""), str(domain or ""),
         now, now + ticket_ttl(purpose)),
    )
    db.commit()
    return token


_TICKET_WORDS = {"recover": "recovery link", "join": "join link", "enroll": "passkey setup"}


def peek_ticket(db, token: str, purpose: str) -> Dict[str, Any]:
    """The ticket's row if it can still be used. Raises PasskeyError (404 unknown, 410 used or expired)."""
    word = _TICKET_WORDS.get(purpose, "link")
    if not _valid_token(token):
        raise PasskeyError(404, f"This {word} isn't valid. Request a new one.", "ticket_invalid")
    row = db.execute(
        "SELECT user_id, email, org_id, domain, expires_at, used_at FROM morrow_auth_tickets WHERE token_sha256=? AND purpose=?",
        (_digest(token), purpose),
    ).fetchone()
    if not row:
        raise PasskeyError(404, f"This {word} isn't valid. Request a new one.", "ticket_invalid")
    if row[5]:
        raise PasskeyError(410, f"This {word} has already been used. Request a new one if you need to.", "ticket_used")
    if int(row[4] or 0) < _now():
        raise PasskeyError(410, f"This {word} has expired. Request a new one.", "ticket_expired")
    return {"user_id": row[0] or "", "email": row[1] or "", "org_id": row[2] or "", "domain": row[3] or "",
            "expires_at": int(row[4] or 0), "token_sha256": _digest(token)}


def claim_ticket(db, token: str, purpose: str) -> Dict[str, Any]:
    """Mark the ticket used, atomically: of two concurrent claims exactly one succeeds."""
    ticket = peek_ticket(db, token, purpose)
    cur = db.execute(
        "UPDATE morrow_auth_tickets SET used_at=? WHERE token_sha256=? AND purpose=? AND used_at IS NULL AND expires_at>=?",
        (_now(), ticket["token_sha256"], purpose, _now()),
    )
    db.commit()
    if int(cur.rowcount or 0) != 1:
        raise PasskeyError(410, f"This {_TICKET_WORDS.get(purpose, 'link')} has already been used.", "ticket_used")
    return ticket


# ── Challenges ─────────────────────────────────────────────────────────────────

def _new_challenge(db, purpose: str, user_id: str = "", context: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    now = _now()
    # Expired and used challenges are useless; sweep a few each time instead of running a job.
    db.execute("DELETE FROM morrow_webauthn_challenges WHERE expires_at < ? OR used_at IS NOT NULL", (now - 60,))
    challenge = secrets.token_bytes(32)
    handle = secrets.token_urlsafe(24)
    db.execute(
        "INSERT INTO morrow_webauthn_challenges (id, challenge, purpose, user_id, context, created_at, expires_at, used_at) "
        "VALUES (?,?,?,?,?,?,?,NULL)",
        (handle, b64url(challenge), purpose, str(user_id or ""), json.dumps(context or {}, sort_keys=True), now,
         now + challenge_ttl()),
    )
    db.commit()
    return {"id": handle, "challenge": challenge}


def _claim_challenge(db, challenge_id: str, purpose: str) -> Dict[str, Any]:
    handle = str(challenge_id or "")
    if not (16 <= len(handle) <= 64) or not set(handle) <= _TOKEN_CHARS:
        raise PasskeyError(400, "This passkey request isn't valid. Start again.", "challenge_invalid")
    now = _now()
    row = db.execute(
        "SELECT challenge, user_id, context, expires_at, used_at FROM morrow_webauthn_challenges WHERE id=? AND purpose=?",
        (handle, purpose),
    ).fetchone()
    if not row or row[4] or int(row[3] or 0) < now:
        raise PasskeyError(400, "This passkey request has expired or was already used. Start again.", "challenge_expired")
    cur = db.execute(
        "UPDATE morrow_webauthn_challenges SET used_at=? WHERE id=? AND purpose=? AND used_at IS NULL AND expires_at>=?",
        (now, handle, purpose, now),
    )
    db.commit()
    if int(cur.rowcount or 0) != 1:
        raise PasskeyError(400, "This passkey request has expired or was already used. Start again.", "challenge_expired")
    try:
        context = json.loads(row[2] or "{}")
    except ValueError:
        context = {}
    return {"challenge": from_b64url(row[0]), "user_id": row[1] or "", "context": context if isinstance(context, dict) else {}}


# ── Authentication ceremony ────────────────────────────────────────────────────

def _fake_credential_ids(email: str) -> List[bytes]:
    """Stable, made-up credential ids for an address with no passkeys, so the answer for an unknown
    address looks like the answer for a known one (no account enumeration through allowCredentials)."""
    key = str(os.getenv("MORROW_AUTH_JWT_SECRET") or "morrow-passkey-decoy").encode("utf-8")
    return [hmac.new(key, f"passkey-decoy:{email}".encode("utf-8"), hashlib.sha256).digest()]


def begin_login(db, email: str = "") -> Dict[str, Any]:
    """Options for navigator.credentials.get(). Without an email: discoverable credentials (and
    conditional UI). With one: that account's credentials, for authenticators that can't discover."""
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    rp = _rp()
    allow: List[Any] = []
    address = str(email or "").strip().lower()
    if address:
        ids: List[bytes] = []
        row = db.execute("SELECT id FROM morrow_users WHERE email=? AND is_active=1", (address,)).fetchone()
        if row:
            for (cid,) in db.execute("SELECT credential_id FROM morrow_passkeys WHERE user_id=? AND clone_suspected=0",
                                     (row[0],)).fetchall():
                ids.append(from_b64url(cid))
        allow = [PublicKeyCredentialDescriptor(id=i) for i in (ids or _fake_credential_ids(address))]
    created = _new_challenge(db, "login")
    options = generate_authentication_options(
        rp_id=rp["id"], challenge=created["challenge"], timeout=challenge_ttl() * 1000,
        allow_credentials=allow, user_verification=UserVerificationRequirement.REQUIRED,
    )
    return {"challenge_id": created["id"], "options": json.loads(options_to_json(options))}


def _credential_id_of(credential: Any) -> str:
    if not isinstance(credential, dict):
        raise PasskeyError(400, "The passkey response is missing.", "credential_invalid")
    raw = str(credential.get("rawId") or credential.get("id") or "")
    if not raw or len(raw) > 1400:
        raise PasskeyError(400, "The passkey response is missing its credential id.", "credential_invalid")
    try:
        return b64url(from_b64url(raw))
    except Exception:
        raise PasskeyError(400, "The passkey response is malformed.", "credential_invalid") from None


def finish_login(db, challenge_id: str, credential: Any) -> Dict[str, Any]:
    """Verify an assertion. Returns {"user_id", "credential_id"}; raises PasskeyError.

    PasskeyError.code "clone_suspected" means the signature was good but the counter went backwards.
    """
    from webauthn import verify_authentication_response
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    rp = _rp()
    claimed = _claim_challenge(db, challenge_id, "login")
    cred_id = _credential_id_of(credential)
    row = db.execute(
        "SELECT user_id, public_key, sign_count, clone_suspected FROM morrow_passkeys WHERE credential_id=?", (cred_id,)
    ).fetchone()
    if not row:
        raise PasskeyError(401, "This passkey isn't registered here. Use another one, or recover your account.", "unknown_credential")
    user_id, public_key, sign_count, flagged = row[0], row[1], int(row[2] or 0), int(row[3] or 0)
    if flagged:
        raise PasskeyError(401, "This passkey was blocked because it may have been copied. Sign in with another passkey "
                                "or recover your account by email.", "clone_suspected")
    handle = ""
    response = credential.get("response") if isinstance(credential.get("response"), dict) else {}
    if response.get("userHandle"):
        try:
            handle = from_b64url(str(response.get("userHandle"))).decode("utf-8", "replace")
        except Exception:
            handle = "?"
        if handle != user_id:
            raise PasskeyError(401, "This passkey doesn't belong to the account it names.", "user_handle_mismatch")
    try:
        verified = verify_authentication_response(
            credential=credential, expected_challenge=claimed["challenge"], expected_rp_id=rp["id"],
            expected_origin=rp["origins"], credential_public_key=from_b64url(public_key),
            credential_current_sign_count=sign_count, require_user_verification=True,
        )
    except InvalidAuthenticationResponse as exc:
        if "sign count" in str(exc).lower():
            db.execute("UPDATE morrow_passkeys SET clone_suspected=1 WHERE credential_id=?", (cred_id,))
            db.commit()
            raise PasskeyError(401, "This passkey was blocked because it may have been copied. Sign in with another "
                                    "passkey or recover your account by email.", "clone_suspected") from None
        raise PasskeyError(401, "The passkey could not be verified.", "verification_failed") from None
    except Exception:
        raise PasskeyError(401, "The passkey could not be verified.", "verification_failed") from None
    db.execute("UPDATE morrow_passkeys SET sign_count=?, last_used_at=?, backed_up=? WHERE credential_id=?",
               (int(verified.new_sign_count), _now(), 1 if verified.credential_backed_up else 0, cred_id))
    db.commit()
    return {"user_id": user_id, "credential_id": cred_id}


# ── Registration ceremony ──────────────────────────────────────────────────────

def begin_registration(db, *, user_id: str, email: str, display_name: str = "",
                       context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Options for navigator.credentials.create(): discoverable credential, user verification required."""
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    rp = _rp()
    existing = [PublicKeyCredentialDescriptor(id=from_b64url(cid)) for (cid,) in
                db.execute("SELECT credential_id FROM morrow_passkeys WHERE user_id=?", (str(user_id),)).fetchall()]
    created = _new_challenge(db, "register", user_id=user_id, context=context)
    options = generate_registration_options(
        rp_id=rp["id"], rp_name=rp["name"],
        # The user handle is the account's random id, never its email: it is stored on the device
        # and returned with every assertion.
        user_id=str(user_id).encode("utf-8"), user_name=str(email), user_display_name=str(display_name or email),
        challenge=created["challenge"], timeout=challenge_ttl() * 1000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=existing,
    )
    return {"challenge_id": created["id"], "options": json.loads(options_to_json(options))}


def finish_registration(db, challenge_id: str, credential: Any) -> Dict[str, Any]:
    """Verify an attestation. Returns {"user_id", "context", "verified": {...}} without storing anything."""
    from webauthn import verify_registration_response

    rp = _rp()
    claimed = _claim_challenge(db, challenge_id, "register")
    if not isinstance(credential, dict):
        raise PasskeyError(400, "The passkey response is missing.", "credential_invalid")
    try:
        verified = verify_registration_response(
            credential=credential, expected_challenge=claimed["challenge"], expected_rp_id=rp["id"],
            expected_origin=rp["origins"], require_user_verification=True,
        )
    except Exception:
        raise PasskeyError(400, "The new passkey could not be verified. Try again.", "verification_failed") from None
    response = credential.get("response") if isinstance(credential.get("response"), dict) else {}
    transports = [str(t)[:20] for t in (response.get("transports") or []) if isinstance(t, str)][:8]
    device_type = getattr(verified.credential_device_type, "value", str(verified.credential_device_type or ""))
    return {
        "user_id": claimed["user_id"],
        "context": claimed["context"],
        "verified": {
            "credential_id": b64url(verified.credential_id),
            "public_key": b64url(verified.credential_public_key),
            "sign_count": int(verified.sign_count or 0),
            "aaguid": str(verified.aaguid or ""),
            "device_type": str(device_type or ""),
            "backed_up": bool(verified.credential_backed_up),
            "transports": transports,
        },
    }


def ticket_hash(token: str) -> str:
    return _digest(token)
