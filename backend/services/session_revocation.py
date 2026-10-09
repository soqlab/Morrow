"""Access-token revocation (denylist by cut-off time).

Refresh tokens are server-side rows and can simply be deleted. Access tokens are
self-contained JWTs, so deleting a refresh token alone leaves every access token
already issued valid until it expires (24 hours with the built-in issuer's default).

Instead of listing every token, a revocation records a cut-off per subject:
"user:<id>" or "org:<id>". A token for that subject whose iat is at or before the
cut-off is rejected by the request auth middleware. The table stays tiny (one row
per revoked subject), and each replica refreshes its in-memory copy every
PQC_TOKEN_REVOCATION_CACHE_SECONDS (default 10), so a revocation takes effect on
every replica within that window.

A storage error keeps the last known list rather than failing every request; the
failure is logged.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_CACHE: Dict[str, Any] = {"loaded_at": 0.0, "db": None, "cutoffs": {}}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _cache_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("PQC_TOKEN_REVOCATION_CACHE_SECONDS", "10") or 10))
    except ValueError:
        return 10.0


def _db_identity() -> str:
    return f"{os.getenv('PQC_FEATURE_STORE_BACKEND', '')}|{os.getenv('PQC_SCANNER_DB', '')}"


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
            CREATE TABLE IF NOT EXISTS platform_token_revocations (
                subject        TEXT PRIMARY KEY,
                revoked_before INTEGER NOT NULL,
                reason         TEXT NOT NULL DEFAULT '',
                revoked_by     TEXT NOT NULL DEFAULT '',
                created_at     TEXT NOT NULL
            );
            """
        )
        conn.commit()


def subject_key(kind: str, identifier: str) -> str:
    kind = str(kind or "").strip().lower()
    if kind not in {"user", "org"}:
        raise ValueError("kind must be user or org")
    ident = str(identifier or "").strip()
    if not ident:
        raise ValueError("identifier is required")
    return f"{kind}:{ident[:200]}"


def revoke(kind: str, identifier: str, *, revoked_by: str = "", reason: str = "") -> int:
    """Reject every access token for the subject issued up to now. Returns the cut-off (epoch)."""
    key = subject_key(kind, identifier)
    cutoff = int(time.time())
    init_tables()
    with feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO platform_token_revocations (subject, revoked_before, reason, revoked_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, cutoff, str(reason or "")[:500], str(revoked_by or "")[:160], _now_iso()),
                )
        except INTEGRITY_ERRORS:
            conn.execute(
                "UPDATE platform_token_revocations SET revoked_before = ?, reason = ?, revoked_by = ?, created_at = ? "
                "WHERE subject = ?",
                (cutoff, str(reason or "")[:500], str(revoked_by or "")[:160], _now_iso(), key),
            )
        conn.commit()
    with _LOCK:
        _CACHE["cutoffs"][key] = cutoff
    return cutoff


def list_revocations(limit: int = 100) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT subject, revoked_before, reason, revoked_by, created_at FROM platform_token_revocations "
            "ORDER BY revoked_before DESC LIMIT ?",
            (max(1, min(int(limit or 100), 500)),),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["revoked_before_iso"] = datetime.fromtimestamp(int(item["revoked_before"]), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        out.append(item)
    return out


def needs_refresh() -> bool:
    return (time.monotonic() - float(_CACHE["loaded_at"] or 0) > _cache_seconds()) or _CACHE["db"] != _db_identity()


def refresh() -> None:
    identity = _db_identity()
    try:
        init_tables()
        with feature_conn() as conn:
            rows = conn.execute("SELECT subject, revoked_before FROM platform_token_revocations").fetchall()
        cutoffs = {str(r[0]): int(r[1]) for r in rows}
    except Exception as exc:  # keep the last known list; never fail every request on a storage blip
        logger.warning("[token-revocation] refresh failed: %s", exc.__class__.__name__)
        if _CACHE["db"] != identity:
            cutoffs = {}
        else:
            with _LOCK:
                _CACHE["loaded_at"] = time.monotonic()
            return
    with _LOCK:
        _CACHE.update(loaded_at=time.monotonic(), db=identity, cutoffs=cutoffs)


def _claim_org(claims: Dict[str, Any]) -> str:
    for key in ("org_id", "organization_id", "org"):
        value = claims.get(key)
        if str(value or "").strip():
            return str(value).strip()
    return ""


def is_revoked(claims: Optional[Dict[str, Any]], org_id: str = "") -> bool:
    """True when the token's subject or organization was revoked at or after it was issued."""
    if not isinstance(claims, dict) or not claims:
        return False
    if needs_refresh():
        refresh()
    cutoffs = _CACHE["cutoffs"]
    if not cutoffs:
        return False
    candidates = []
    sub = str(claims.get("sub") or "").strip()
    if sub:
        candidates.append(f"user:{sub}")
    org = str(org_id or _claim_org(claims)).strip()
    if org:
        candidates.append(f"org:{org}")
    cutoff = max((cutoffs.get(c, 0) for c in candidates), default=0)
    if not cutoff:
        return False
    try:
        issued_at = int(claims.get("iat"))
    except (TypeError, ValueError):
        return True  # no issue time: cannot prove it post-dates the revocation
    return issued_at <= cutoff
