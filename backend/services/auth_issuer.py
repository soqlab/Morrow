"""Built-in JWT issuer — email/password login when no external IdP is configured.

Activated when MORROW_AUTH_ISSUER_ENABLED=1 (or AUTH_MODE=hosted).
Issues HS256 JWTs signed with MORROW_AUTH_JWT_SECRET.
Falls through gracefully if the env var is absent.
"""
import hashlib
import logging
import os
import time
import uuid
from functools import lru_cache
from typing import Optional

import bcrypt
import jwt

logger = logging.getLogger(__name__)

_SECRET = str(os.getenv("MORROW_AUTH_JWT_SECRET") or "").strip()
_ISSUER = str(os.getenv("MORROW_AUTH_JWT_ISSUER") or "morrow").strip()
_AUDIENCE = str(os.getenv("MORROW_AUTH_JWT_AUDIENCE") or "morrow").strip()
_TOKEN_TTL = int(os.getenv("MORROW_AUTH_TOKEN_TTL_SECONDS") or 86400)  # 24 h default
_REFRESH_TTL = int(os.getenv("MORROW_AUTH_REFRESH_TTL_SECONDS") or 604800)  # 7 d default
_ENABLED = str(os.getenv("MORROW_AUTH_ISSUER_ENABLED") or "1").strip().lower() in {"1", "true", "yes", "on"}

ALGORITHM = "HS256"


# ── Table init ────────────────────────────────────────────────────────────────

def init_tables(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS morrow_users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT NOT NULL DEFAULT 'viewer',
            org_id TEXT NOT NULL DEFAULT 'org-alpha',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS morrow_refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    db.commit()
    _ensure_default_admin(db)


def _ensure_default_admin(db) -> None:
    """Create the bootstrap admin if no users exist yet.

    Account creation (POST /auth/register) requires the admin role, so a fresh deployment needs one
    account to start from. That account's password must never be predictable: a shared literal like
    "changeme123!" is a publicly known credential on every deployment that forgets to override it.
    Bootstrap requires an explicitly supplied secret; credentials must never be emitted into logs.
    """
    count = db.execute("SELECT COUNT(*) FROM morrow_users").fetchone()[0]
    if count > 0:
        return
    default_email = str(os.getenv("MORROW_ADMIN_EMAIL") or "admin@morrow.soqlab.com").strip()
    configured = str(os.getenv("MORROW_ADMIN_PASSWORD") or "").strip()
    if not configured:
        logger.warning("[AuthIssuer] No bootstrap account created: supply MORROW_ADMIN_PASSWORD through a secret manager or configure an external identity provider.")
        return
    _validate_password_strength(configured)
    _create_user(db, default_email, configured, "Platform Admin", "admin", "org-alpha")
    logger.info("[AuthIssuer] Bootstrap admin created from an explicitly configured secret; no credentials logged.")


# ── User management ────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _create_user(db, email: str, password: str, full_name: str, role: str, org_id: str) -> dict:
    uid = str(uuid.uuid4())
    now = int(time.time())
    db.execute(
        "INSERT INTO morrow_users (id, email, password_hash, full_name, role, org_id, is_active, created_at) "
        "VALUES (?,?,?,?,?,?,1,?)",
        (uid, email.lower().strip(), _hash_password(password), full_name, role, org_id, now),
    )
    db.commit()
    return {"id": uid, "email": email, "role": role, "org_id": org_id}


def create_user(db, email: str, password: str, full_name: str = "",
                role: str = "viewer", org_id: str = "org-alpha") -> dict:
    _validate_password_strength(password)
    existing = db.execute("SELECT id FROM morrow_users WHERE email=?", (email.lower().strip(),)).fetchone()
    if existing:
        raise ValueError("Email already registered")
    return _create_user(db, email, password, full_name, role, org_id)


def get_user_by_email(db, email: str) -> Optional[dict]:
    row = db.execute(
        "SELECT id, email, password_hash, full_name, role, org_id, is_active FROM morrow_users WHERE email=?",
        (email.lower().strip(),),
    ).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "password_hash": row[2],
            "full_name": row[3], "role": row[4], "org_id": row[5], "is_active": row[6]}


def get_user_by_id(db, user_id: str) -> Optional[dict]:
    row = db.execute(
        "SELECT id, email, full_name, role, org_id, is_active, created_at, last_login_at FROM morrow_users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "full_name": row[2], "role": row[3],
            "org_id": row[4], "is_active": row[5], "created_at": row[6], "last_login_at": row[7]}


def set_user_organization(db, user_id: str, org_id: str, role: str = "", email: str = "") -> bool:
    """Point a built-in account at the organization its next token will be scoped to.

    A token issued here carries exactly one `org_id`, read from this column, and every tenant
    decision in the app is made against that claim. So a membership recorded elsewhere -- by
    accepting an invitation, say -- changes nothing until this moves too: the invitee kept reading
    and writing the organization they first registered in while their membership said otherwise.
    Callers must have verified the membership first; this function does not authorize anything.

    The account is found by id, or by email when the caller's identity is an address rather than an
    account id (header-auth deployments, and any IdP whose `sub` is an email). Returns False when
    there is no such built-in account, which is the normal case for an identity that comes from an
    external IdP: there the claim is the provider's to set, not ours.
    """
    uid = str(user_id or "").strip()
    org = str(org_id or "").strip()
    address = str(email or (uid if "@" in uid else "")).strip().lower()
    if not org or not (uid or address):
        return False
    where, args = ("id=?", [uid]) if uid else ("email=?", [address])
    if role:
        cur = db.execute(f"UPDATE morrow_users SET org_id=?, role=? WHERE {where}", (org, role, *args))
    else:
        cur = db.execute(f"UPDATE morrow_users SET org_id=? WHERE {where}", (org, *args))
    if cur.rowcount == 0 and address and uid:
        if role:
            cur = db.execute("UPDATE morrow_users SET org_id=?, role=? WHERE email=?", (org, role, address))
        else:
            cur = db.execute("UPDATE morrow_users SET org_id=? WHERE email=?", (org, address))
    db.commit()
    return cur.rowcount > 0


def list_users(db, org_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT id, email, full_name, role, org_id, is_active, created_at, last_login_at "
        "FROM morrow_users WHERE org_id=? ORDER BY created_at DESC",
        (org_id,),
    ).fetchall()
    return [{"id": r[0], "email": r[1], "full_name": r[2], "role": r[3],
             "org_id": r[4], "is_active": bool(r[5]), "created_at": r[6], "last_login_at": r[7]}
            for r in rows]


def update_user_role(db, user_id: str, role: str, org_id: str) -> bool:
    cur = db.execute(
        "UPDATE morrow_users SET role=? WHERE id=? AND org_id=?", (role, user_id, org_id)
    )
    db.commit()
    return cur.rowcount > 0


def deactivate_user(db, user_id: str, org_id: str) -> bool:
    cur = db.execute(
        "UPDATE morrow_users SET is_active=0 WHERE id=? AND org_id=?", (user_id, org_id)
    )
    db.commit()
    return cur.rowcount > 0


def change_password(db, user_id: str, old_password: str, new_password: str) -> bool:
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    row = db.execute("SELECT password_hash FROM morrow_users WHERE id=?", (user_id,)).fetchone()
    if not row or not _verify_password(old_password, row[0]):
        return False
    _validate_password_strength(new_password)
    db.execute("UPDATE morrow_users SET password_hash=? WHERE id=?", (_hash_password(new_password), user_id))
    db.commit()
    return True


def _validate_password_strength(password: str) -> None:
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed bcrypt's 72-byte limit")


# ── JWT issuance ───────────────────────────────────────────────────────────────

def _require_secret() -> str:
    if not _SECRET:
        raise RuntimeError(
            "MORROW_AUTH_JWT_SECRET is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return _SECRET


def issue_access_token(user: dict) -> str:
    secret = _require_secret()
    now = int(time.time())
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "org_id": user["org_id"],
        "name": user.get("full_name") or "",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": now,
        "exp": now + _TOKEN_TTL,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def issue_refresh_token(db, user_id: str) -> str:
    import secrets as _sec
    token = _sec.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    db.execute(
        "INSERT OR REPLACE INTO morrow_refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES (?,?,?,?)",
        (token_hash, user_id, now + _REFRESH_TTL, now),
    )
    db.commit()
    return token


def verify_access_token(token: str) -> dict:
    secret = _require_secret()
    return jwt.decode(token, secret, algorithms=[ALGORITHM], audience=_AUDIENCE, issuer=_ISSUER)


def refresh_access_token(db, refresh_token: str) -> Optional[str]:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    now = int(time.time())
    row = db.execute(
        "SELECT user_id FROM morrow_refresh_tokens WHERE token_hash=? AND expires_at>?",
        (token_hash, now),
    ).fetchone()
    if not row:
        return None
    user = get_user_by_id(db, row[0])
    if not user or not user["is_active"]:
        return None
    return issue_access_token(user)


def revoke_refresh_token(db, refresh_token: str) -> None:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    db.execute("DELETE FROM morrow_refresh_tokens WHERE token_hash=?", (token_hash,))
    db.commit()


def refresh_token_owner(db, refresh_token: str) -> Optional[dict]:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    row = db.execute("SELECT user_id FROM morrow_refresh_tokens WHERE token_hash=? AND expires_at>?", (token_hash, int(time.time()))).fetchone()
    if not row:
        return None
    user = get_user_by_id(db, row[0])
    return user if user and user["is_active"] else None


# ── Operator session management ───────────────────────────────────────────────
# A refresh token row is a session. Its public id is a prefix of the stored SHA-256, which cannot be
# turned back into the token, so listing sessions never exposes anything that can renew one.

SESSION_ID_LENGTH = 24


def list_refresh_sessions(db, org_id: str = "", user_id: str = "", limit: int = 200) -> list[dict]:
    clauses = ["t.expires_at > ?"]
    params: list = [int(time.time())]
    if org_id:
        clauses.append("u.org_id = ?")
        params.append(org_id)
    if user_id:
        clauses.append("t.user_id = ?")
        params.append(user_id)
    params.append(max(1, min(int(limit or 200), 1000)))
    rows = db.execute(
        "SELECT t.token_hash, t.user_id, t.created_at, t.expires_at, u.email, u.org_id, u.role, u.is_active "
        "FROM morrow_refresh_tokens t LEFT JOIN morrow_users u ON u.id = t.user_id WHERE "
        + " AND ".join(clauses) + " ORDER BY t.created_at DESC LIMIT ?",
        tuple(params),
    ).fetchall()
    return [
        {"session_id": r[0][:SESSION_ID_LENGTH], "user_id": r[1], "created_at": r[2], "expires_at": r[3],
         "email": r[4] or "", "org_id": r[5] or "", "role": r[6] or "", "account_active": bool(r[7])}
        for r in rows
    ]


def revoke_refresh_sessions(db, *, session_id: str = "", user_id: str = "", org_id: str = "") -> int:
    """Delete refresh tokens by session id, user, or organization. Returns rows removed."""
    if session_id:
        sid = str(session_id).strip().lower()
        if len(sid) != SESSION_ID_LENGTH or any(c not in "0123456789abcdef" for c in sid):
            return 0
        if org_id:
            cur = db.execute(
                "DELETE FROM morrow_refresh_tokens WHERE token_hash LIKE ? AND user_id IN (SELECT id FROM morrow_users WHERE org_id=?)",
                (sid + "%", org_id),
            )
        else:
            cur = db.execute("DELETE FROM morrow_refresh_tokens WHERE token_hash LIKE ?", (sid + "%",))
    elif user_id:
        cur = db.execute("DELETE FROM morrow_refresh_tokens WHERE user_id=?", (user_id,))
    elif org_id:
        cur = db.execute(
            "DELETE FROM morrow_refresh_tokens WHERE user_id IN (SELECT id FROM morrow_users WHERE org_id=?)", (org_id,)
        )
    else:
        return 0
    db.commit()
    return int(cur.rowcount or 0)


def set_user_active(db, user_id: str, org_id: str, active: bool) -> bool:
    cur = db.execute(
        "UPDATE morrow_users SET is_active=? WHERE id=? AND org_id=?", (1 if active else 0, user_id, org_id)
    )
    db.commit()
    return cur.rowcount > 0


@lru_cache(maxsize=1)
def _dummy_hash():
    return _hash_password("Unused account timing value 719")


# ── Login flow ─────────────────────────────────────────────────────────────────

def login(db, email: str, password: str) -> Optional[dict]:
    """Authenticate and return {access_token, refresh_token, user}. None on failure."""
    if not _ENABLED:
        return None
    user = get_user_by_email(db, email)
    # The same bcrypt work factor is used for absent, inactive, and active accounts.
    valid = _verify_password(password, user["password_hash"] if user else _dummy_hash())
    if not user or not user["is_active"] or not valid:
        return None
    db.execute("UPDATE morrow_users SET last_login_at=? WHERE id=?", (int(time.time()), user["id"]))
    db.commit()
    access_token = issue_access_token(user)
    refresh_token = issue_refresh_token(db, user["id"])
    safe_user = {k: v for k, v in user.items() if k != "password_hash"}
    return {"access_token": access_token, "refresh_token": refresh_token,
            "token_type": "Bearer", "expires_in": _TOKEN_TTL, "user": safe_user}
