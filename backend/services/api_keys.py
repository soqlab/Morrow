"""Per-organization API keys.

Format: ``pq_<12 hex prefix>_<secret>``. Only a salted HMAC-SHA256 of the full key
is stored, next to the public prefix used to find the row. The secret is shown
exactly once, when the key is created or rotated.

A key authenticates as a synthetic actor ("apikey:<id>") inside exactly one
organization. The organization comes from the key, never from x-org-id, so a key
cannot be pointed at another tenant. Scopes map onto the existing roles:

    read  -> viewer   (GET/HEAD/OPTIONS only)
    write -> operator (implies read)
    admin -> admin    (implies write and read)

API keys never authenticate /platform/*, /admin/* or credential-management /auth/*
routes. Verified keys are cached per process for MORROW_API_KEY_CACHE_SECONDS
(default 15): revocation is immediate on the replica that revoked the key and
takes at most that long elsewhere.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from db_feature_store import feature_conn
from services import route_paths as _route_paths

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "pq_"
SCOPES = ("read", "write", "admin")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
BLOCKED_PREFIXES = ("/platform", "/admin", "/vendor-admin")
AUTH_READ_ALLOWED = frozenset({"/auth/context", "/auth/memberships"})
MAX_EXPIRY_DAYS = 730

_TOKEN_RE = re.compile(r"^pq_([0-9a-f]{12})_([A-Za-z0-9_-]{32,128})$")
_LOCK = threading.Lock()
_VERIFY_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}
_LAST_TOUCH: Dict[str, float] = {}

_COLUMNS = (
    "id, organization_id, name, prefix, salt, key_hash, scopes, created_by, created_at, "
    "expires_at, last_used_at, revoked_at, revoked_by, revoke_reason, rotated_from"
)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cache_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("MORROW_API_KEY_CACHE_SECONDS", "15") or 15))
    except ValueError:
        return 15.0


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}"


_TABLES_READY: set = set()


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    _init_tables_uncached()
    _TABLES_READY.add(identity)


def _init_tables_uncached() -> None:
    with feature_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS platform_api_keys (
                id              TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                name            TEXT NOT NULL DEFAULT '',
                prefix          TEXT NOT NULL,
                salt            TEXT NOT NULL,
                key_hash        TEXT NOT NULL,
                scopes          TEXT NOT NULL DEFAULT 'read',
                created_by      TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                expires_at      TEXT NOT NULL DEFAULT '',
                last_used_at    TEXT NOT NULL DEFAULT '',
                revoked_at      TEXT NOT NULL DEFAULT '',
                revoked_by      TEXT NOT NULL DEFAULT '',
                revoke_reason   TEXT NOT NULL DEFAULT '',
                rotated_from    TEXT NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_api_keys_prefix ON platform_api_keys(prefix);
            CREATE INDEX IF NOT EXISTS idx_platform_api_keys_org ON platform_api_keys(organization_id);
            """
        )
        conn.commit()


def normalize_scopes(values: Iterable[Any]) -> List[str]:
    requested = {str(v or "").strip().lower() for v in (values or []) if str(v or "").strip()}
    unknown = requested - set(SCOPES)
    if unknown:
        raise ValueError(f"Unknown scope(s): {', '.join(sorted(unknown))}. Use read, write, admin.")
    if not requested:
        raise ValueError("At least one scope is required.")
    if "admin" in requested:
        requested |= {"write", "read"}
    if "write" in requested:
        requested.add("read")
    return [s for s in SCOPES if s in requested]


def role_for_scopes(scopes: Iterable[str]) -> str:
    scope_set = set(scopes or [])
    if "admin" in scope_set:
        return "admin"
    if "write" in scope_set:
        return "operator"
    return "viewer"


def _hash(salt_hex: str, token: str) -> str:
    return hmac.new(bytes.fromhex(salt_hex), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _status(row: Dict[str, Any], now: Optional[datetime] = None) -> str:
    if str(row.get("revoked_at") or ""):
        return "revoked"
    expires = _parse(row.get("expires_at") or "")
    if expires and expires <= (now or _now()):
        return "expired"
    return "active"


def _public(row: Any) -> Dict[str, Any]:
    item = dict(row)
    scopes = [s for s in str(item.get("scopes") or "").split(",") if s]
    return {
        "id": item.get("id"),
        "organization_id": item.get("organization_id"),
        "name": item.get("name"),
        "prefix": f"{TOKEN_PREFIX}{item.get('prefix')}",
        "scopes": scopes,
        "role": role_for_scopes(scopes),
        "status": _status(item),
        "created_by": item.get("created_by") or "",
        "created_at": item.get("created_at") or "",
        "expires_at": item.get("expires_at") or "",
        "last_used_at": item.get("last_used_at") or "",
        "revoked_at": item.get("revoked_at") or "",
        "revoked_by": item.get("revoked_by") or "",
        "revoke_reason": item.get("revoke_reason") or "",
        "rotated_from": item.get("rotated_from") or "",
    }


def _expiry(expires_in_days: Optional[int]) -> str:
    if expires_in_days is None:
        return ""
    days = int(expires_in_days)
    if not 1 <= days <= MAX_EXPIRY_DAYS:
        raise ValueError(f"expires_in_days must be between 1 and {MAX_EXPIRY_DAYS}, or null for no expiry.")
    return _iso(_now() + timedelta(days=days))


def create_key(
    organization_id: str,
    name: str,
    scopes: Iterable[Any],
    expires_in_days: Optional[int] = 90,
    created_by: str = "",
    rotated_from: str = "",
) -> Tuple[Dict[str, Any], str]:
    org = str(organization_id or "").strip()
    if not org or len(org) > 128:
        raise ValueError("organization_id is required.")
    label = str(name or "").strip()
    if not label or len(label) > 80:
        raise ValueError("name must be 1-80 characters.")
    clean_scopes = normalize_scopes(scopes)
    expires_at = _expiry(expires_in_days)
    init_tables()
    key_id = "key_" + secrets.token_hex(8)
    prefix = secrets.token_hex(6)
    token = f"{TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    salt = secrets.token_hex(16)
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO platform_api_keys (id, organization_id, name, prefix, salt, key_hash, scopes, created_by, "
            "created_at, expires_at, last_used_at, revoked_at, revoked_by, revoke_reason, rotated_from) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?)",
            (key_id, org, label, prefix, salt, _hash(salt, token), ",".join(clean_scopes),
             str(created_by or "")[:160], _iso(_now()), expires_at, str(rotated_from or "")),
        )
        conn.commit()
    return get_key(key_id) or {}, token


def get_key(key_id: str) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(f"SELECT {_COLUMNS} FROM platform_api_keys WHERE id = ?", (str(key_id or ""),)).fetchone()
    return _public(row) if row else None


def list_keys(organization_id: str = "", status: str = "", limit: int = 500) -> List[Dict[str, Any]]:
    init_tables()
    lim = max(1, min(int(limit or 500), 2000))
    with feature_conn() as conn:
        if organization_id:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM platform_api_keys WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
                (str(organization_id), lim),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM platform_api_keys ORDER BY created_at DESC LIMIT ?", (lim,)
            ).fetchall()
    items = [_public(r) for r in rows]
    wanted = str(status or "").strip().lower()
    return [i for i in items if not wanted or i["status"] == wanted]


def _clear_cache() -> None:
    with _LOCK:
        _VERIFY_CACHE.clear()


def revoke_key(key_id: str, revoked_by: str = "", reason: str = "") -> Optional[Dict[str, Any]]:
    current = get_key(key_id)
    if not current:
        return None
    if current["status"] != "revoked":
        with feature_conn() as conn:
            conn.execute(
                "UPDATE platform_api_keys SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
                "WHERE id = ? AND revoked_at = ''",
                (_iso(_now()), str(revoked_by or "")[:160], str(reason or "")[:500], str(key_id)),
            )
            conn.commit()
    _clear_cache()
    return get_key(key_id)


def revoke_organization_keys(organization_id: str, revoked_by: str = "", reason: str = "") -> int:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute(
            "UPDATE platform_api_keys SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
            "WHERE organization_id = ? AND revoked_at = ''",
            (_iso(_now()), str(revoked_by or "")[:160], str(reason or "")[:500], str(organization_id)),
        )
        count = int(cur.rowcount or 0)
        conn.commit()
    _clear_cache()
    return count


def rotate_key(
    key_id: str,
    actor: str = "",
    reason: str = "",
    expires_in_days: Optional[int] = 90,
    grace_seconds: int = 0,
) -> Optional[Tuple[Dict[str, Any], str, Dict[str, Any]]]:
    old = get_key(key_id)
    if not old:
        return None
    if old["status"] != "active":
        raise ValueError(f"Only an active key can be rotated; this key is {old['status']}.")
    grace = max(0, min(int(grace_seconds or 0), 86400))
    new, token = create_key(old["organization_id"], old["name"], old["scopes"], expires_in_days, actor, rotated_from=old["id"])
    if grace:
        grace_end = _now() + timedelta(seconds=grace)
        current_end = _parse(old.get("expires_at") or "")
        end = min(grace_end, current_end) if current_end else grace_end
        with feature_conn() as conn:
            conn.execute(
                "UPDATE platform_api_keys SET expires_at = ?, revoke_reason = ? WHERE id = ?",
                (_iso(end), f"rotated: {str(reason or '')[:480]}", str(key_id)),
            )
            conn.commit()
        _clear_cache()
        previous = get_key(key_id) or old
    else:
        previous = revoke_key(key_id, actor, f"rotated: {str(reason or '')[:480]}") or old
    return new, token, previous


def _touch(key_id: str) -> None:
    now = time.monotonic()
    if now - _LAST_TOUCH.get(key_id, 0.0) < 60:
        return
    _LAST_TOUCH[key_id] = now
    try:
        # Same reason as the verification read: this runs during authentication, before the request
        # has a tenant, so under row-level security a tenant-scoped update would match no row and
        # last_used_at would silently stop advancing -- which is exactly the field an operator uses
        # to find keys that can be retired.
        from services.tenant_scope import platform_scope

        with platform_scope("api-key verification: last_used_at touch"), feature_conn() as conn:
            conn.execute("UPDATE platform_api_keys SET last_used_at = ? WHERE id = ?", (_iso(_now()), key_id))
            conn.commit()
    except Exception as exc:
        logger.debug("[api-keys] last_used update failed: %s", exc.__class__.__name__)


def verify_token(token: str) -> Tuple[Optional[Dict[str, Any]], str, int]:
    """Return (record, error, status). Never logs or stores the token."""
    text = str(token or "").strip()
    match = _TOKEN_RE.match(text)
    if not match:
        return None, "Malformed API key.", 401
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
    identity = _db_identity()
    now = time.monotonic()
    with _LOCK:
        cached = _VERIFY_CACHE.get(fingerprint)
    if cached and cached[0] > now and cached[1] == identity:
        record = dict(cached[2])
    else:
        try:
            # Authentication is the one lookup that cannot be tenant-scoped: the key's organization
            # is the *answer*, so at this point there is no tenant to scope by, and a request
            # carrying only an API key has no other identity. platform_api_keys is covered by the
            # row-level-security plan (every other operation on it -- list, create, rotate, revoke --
            # runs tenant-scoped and is isolated), so this single read takes the audited escape
            # hatch. It is a lookup by public prefix followed by a constant-time HMAC comparison, so
            # widening it to every row grants no ability to guess a key.
            from services.tenant_scope import platform_scope

            init_tables()
            with platform_scope("api-key verification: key lookup precedes tenant identity"):
                with feature_conn() as conn:
                    row = conn.execute(
                        f"SELECT {_COLUMNS} FROM platform_api_keys WHERE prefix = ?", (match.group(1),)
                    ).fetchone()
        except Exception as exc:
            logger.warning("[api-keys] verification storage unavailable: %s", exc.__class__.__name__)
            return None, "API key verification is temporarily unavailable.", 503
        if not row or not hmac.compare_digest(_hash(str(row["salt"]), text), str(row["key_hash"])):
            return None, "Invalid API key.", 401
        record = dict(row)
        record.pop("salt", None)
        record.pop("key_hash", None)
        ttl = _cache_seconds()
        if ttl:
            with _LOCK:
                if len(_VERIFY_CACHE) > 5000:
                    _VERIFY_CACHE.clear()
                _VERIFY_CACHE[fingerprint] = (now + ttl, identity, dict(record))
    status = _status(record)
    if status == "revoked":
        return None, "API key has been revoked.", 401
    if status == "expired":
        return None, "API key has expired.", 401
    _touch(str(record.get("id")))
    return _public({**record, "salt": "", "key_hash": ""}), "", 200


def organization_for_token(token: str) -> str:
    """The organization a valid key belongs to, or "". Used by org-context resolution, which runs
    before authentication, so an API-key request never takes its org from x-org-id."""
    record, _, _ = verify_token(token)
    return str(record["organization_id"]) if record else ""


def blocked_route(path: str) -> bool:
    """True when no organization API key may reach this path, whatever it is spelled like.

    The comparison runs on services/route_paths.guard_path, which collapses every ``/v1`` prefix
    (not just the first -- ``/v1/v1/admin/x`` used to read as the unblocked ``/v1/admin/x`` and then
    route to the real ``/v1/admin/x`` handler), decodes percent-encoded separators, resolves ``.``
    and ``..``, removes duplicate and trailing slashes, and lowercases.
    """
    route = _route_paths.guard_path(path)
    if _route_paths.has_prefix(route, BLOCKED_PREFIXES):
        return True
    return (route == "/auth" or route.startswith("/auth/")) and route not in AUTH_READ_ALLOWED


def claims_for_request(token: str, method: str, path: str) -> Tuple[Optional[Dict[str, Any]], str, int]:
    # The route check comes first: a blocked route is refused whether or not the key is real, so the
    # answer cannot be used to tell a valid key from an invalid one on /admin/* or /platform/*.
    if blocked_route(path):
        return None, "API keys cannot call platform, admin, or credential-management routes.", 403
    record, error, status = verify_token(token)
    if not record:
        return None, error, status
    scopes = set(record.get("scopes") or [])
    if str(method or "GET").upper() not in SAFE_METHODS and not scopes & {"write", "admin"}:
        return None, "This API key is read-only; the write scope is required for this request.", 403
    actor = f"apikey:{record['id']}"
    org = str(record["organization_id"])
    return {
        "sub": actor,
        "user_id": actor,
        "role": record["role"],
        "org_id": org,
        "organization_id": org,
        "scopes": sorted(scopes),
        "api_key_id": record["id"],
        "auth_method": "api_key",
    }, "", 200
