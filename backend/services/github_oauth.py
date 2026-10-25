"""
GitHub OAuth integration service.

Handles the OAuth 2.0 flow for per-user GitHub tokens:
  - Redirect user to GitHub authorization page
  - Exchange callback code for access token
  - Encrypt and store token per (org_id, user_id)
  - Retrieve token for AI agent calls
  - Disconnect (delete) token

Env vars required:
  GITHUB_CLIENT_ID      — from GitHub OAuth App settings
  GITHUB_CLIENT_SECRET  — from GitHub OAuth App settings
  GITHUB_CALLBACK_URL   — full callback URL, e.g. https://yourapp.com/auth/github/callback
  MORROW_VAULT_MASTER_KEY  — existing 32-byte base64 key used for Fernet encryption
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import urllib.parse
import urllib.request
import urllib.error
from contextlib import contextmanager
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

from db import DB_PATH

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITHUB_CLIENT_ID = (os.getenv("GITHUB_CLIENT_ID") or "").strip()
GITHUB_CLIENT_SECRET = (os.getenv("GITHUB_CLIENT_SECRET") or "").strip()
GITHUB_CALLBACK_URL = (os.getenv("GITHUB_CALLBACK_URL") or "http://localhost:8000/auth/github/callback").strip()
_SCOPES = "repo,read:org,read:user"

_VAULT_KEY_RAW = (os.getenv("MORROW_VAULT_MASTER_KEY") or "").strip()


def _get_fernet() -> Fernet:
    if not _VAULT_KEY_RAW:
        raise RuntimeError("MORROW_VAULT_MASTER_KEY not set — cannot encrypt GitHub tokens.")
    try:
        raw = base64.b64decode(_VAULT_KEY_RAW)
    except Exception:
        raw = _VAULT_KEY_RAW.encode()
    # Fernet needs exactly 32 bytes → base64url-encode to 44 chars
    key = base64.urlsafe_b64encode(raw[:32].ljust(32, b'\x00'))
    return Fernet(key)


def _encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

@contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_github_tokens_table() -> None:
    with _db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS github_tokens (
                id              TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                user_id         TEXT NOT NULL,
                access_token    TEXT NOT NULL,
                token_type      TEXT DEFAULT 'bearer',
                scope           TEXT,
                github_login    TEXT,
                github_id       INTEGER,
                avatar_url      TEXT,
                connected_at    TEXT NOT NULL,
                UNIQUE(org_id, user_id)
            )
        """)
        c.commit()


def store_token(org_id: str, user_id: str, access_token: str, scope: str,
                github_login: str, github_id: int = 0, avatar_url: str = "") -> None:
    import datetime
    import uuid
    encrypted = _encrypt(access_token)
    now = datetime.datetime.utcnow().isoformat()
    with _db() as c:
        c.execute("""
            INSERT INTO github_tokens
                (id, org_id, user_id, access_token, scope, github_login, github_id, avatar_url, connected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id, user_id) DO UPDATE SET
                access_token=excluded.access_token,
                scope=excluded.scope,
                github_login=excluded.github_login,
                github_id=excluded.github_id,
                avatar_url=excluded.avatar_url,
                connected_at=excluded.connected_at
        """, (str(uuid.uuid4())[:8], org_id, user_id, encrypted, scope, github_login, github_id, avatar_url, now))
        c.commit()


def get_token(org_id: str, user_id: str) -> Optional[str]:
    """Return the decrypted access token, or None if not found."""
    try:
        with _db() as c:
            row = c.execute(
                "SELECT access_token FROM github_tokens WHERE org_id=? AND user_id=?",
                (org_id, user_id)
            ).fetchone()
        if not row:
            return None
        return _decrypt(row["access_token"])
    except InvalidToken:
        return None
    except Exception:
        return None


def get_connection_info(org_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Return connection metadata (no token) for the given user."""
    try:
        with _db() as c:
            row = c.execute(
                "SELECT github_login, github_id, avatar_url, scope, connected_at "
                "FROM github_tokens WHERE org_id=? AND user_id=?",
                (org_id, user_id)
            ).fetchone()
        if not row:
            return None
        return dict(row)
    except Exception:
        return None


def delete_token(org_id: str, user_id: str) -> bool:
    try:
        with _db() as c:
            c.execute("DELETE FROM github_tokens WHERE org_id=? AND user_id=?", (org_id, user_id))
            c.commit()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# OAuth flow helpers
# ---------------------------------------------------------------------------

def get_authorization_url(state: str = "") -> str:
    """Build the GitHub OAuth authorization URL to redirect the user to."""
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_CALLBACK_URL,
        "scope": _SCOPES,
        "state": state or "pq-scout",
    }
    return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)


def exchange_code(code: str) -> Dict[str, Any]:
    """Exchange the OAuth callback code for an access token. Returns token info dict."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise RuntimeError("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set for OAuth.")

    payload = urllib.parse.urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": GITHUB_CALLBACK_URL,
    }).encode()

    req = urllib.request.Request(
        "https://github.com/login/oauth/access_token",
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode())

    if "error" in data:
        raise RuntimeError(f"GitHub OAuth error: {data.get('error_description', data['error'])}")

    access_token = data.get("access_token", "")
    scope = data.get("scope", "")

    # Fetch the GitHub user info
    user_req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pq-scout/1.0",
        },
    )
    with urllib.request.urlopen(user_req, timeout=15) as resp:
        user_info = json.loads(resp.read().decode())

    return {
        "access_token": access_token,
        "scope": scope,
        "github_login": user_info.get("login", ""),
        "github_id": user_info.get("id", 0),
        "avatar_url": user_info.get("avatar_url", ""),
    }


# Initialise table on import
try:
    init_github_tokens_table()
except Exception:
    pass
