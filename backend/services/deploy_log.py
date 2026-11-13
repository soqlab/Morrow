"""Deploy transparency log: every commit this deployment has run, in order, hash-chained.

Served at GET /api/public/deploys. One row is appended at startup when the running commit
(services/build_info.py) differs from the newest row's commit; a restart of the same commit, or a
server with no known commit, appends nothing. Nothing ever updates or deletes a row.

Each row's ``entry_hash`` is SHA-256 (lowercase hex) over the canonical JSON (sorted keys, no
whitespace, UTF-8; proof_signing.canonical_bytes) of

    {"commit": <sha>, "first_seen": <ISO time>, "prev_hash": <previous entry_hash>, "seq": <int>}

``seq`` starts at 1 and increases by one; the first row's ``prev_hash`` is 64 zeros. A client can
recompute every hash from the JSON the API returns (scripts/verify-deploy.py does), so a row that
is edited, removed or reordered later breaks the chain for everyone who kept an earlier head hash.

What it shows: when this deployment first ran each commit. What it cannot show by itself: the
operator could rewrite the whole table; keep a copy of ``head_hash`` to detect that.

Two replicas starting together both try to write seq N+1; the primary key lets one win and the
other re-reads, sees its commit is already the newest row and stops.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
HASH_RULE = ("entry_hash = sha256(canonical JSON of {commit, first_seen, prev_hash, seq}: sorted keys, "
             "no whitespace, UTF-8); seq starts at 1; the first prev_hash is 64 zeros")

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()
_RECORDED: set = set()


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_tables() -> None:
    """Create public_deploy_log. No organization column: nothing here belongs to a tenant."""
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        from db_feature_store import feature_conn

        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS public_deploy_log (
                    seq         INTEGER PRIMARY KEY,
                    commit_sha  TEXT NOT NULL,
                    first_seen  TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    entry_hash  TEXT NOT NULL
                );
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def entry_hash(seq: int, commit: str, first_seen: str, prev_hash: str) -> str:
    from services.proof_signing import canonical_bytes

    body = {"seq": int(seq), "commit": str(commit), "first_seen": str(first_seen), "prev_hash": str(prev_hash)}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _row(r: Any) -> Dict[str, Any]:
    return {"seq": int(r["seq"]), "commit": str(r["commit_sha"]), "first_seen": str(r["first_seen"]),
            "prev_hash": str(r["prev_hash"]), "entry_hash": str(r["entry_hash"])}


def _last(conn) -> Optional[Dict[str, Any]]:
    r = conn.execute("SELECT seq, commit_sha, first_seen, prev_hash, entry_hash FROM public_deploy_log "
                     "ORDER BY seq DESC LIMIT 1").fetchone()
    return _row(r) if r else None


def record(commit: Optional[str] = None, now: Optional[str] = None, attempts: int = 5) -> Optional[Dict[str, Any]]:
    """Append the running commit if it differs from the newest row. Returns the new row, or None."""
    from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn
    from services import build_info

    sha = commit if commit is not None else build_info.commit()
    if not sha:
        return None
    init_tables()
    for _ in range(max(1, attempts)):
        with feature_conn() as conn:
            last = _last(conn)
            if last and last["commit"] == sha:
                return None
            seq = (last["seq"] + 1) if last else 1
            prev = last["entry_hash"] if last else GENESIS_HASH
            seen = now or _now()
            digest = entry_hash(seq, sha, seen, prev)
            try:
                with atomic(conn):
                    conn.execute("INSERT INTO public_deploy_log (seq, commit_sha, first_seen, prev_hash, entry_hash) "
                                 "VALUES (?, ?, ?, ?, ?)", (seq, sha, seen, prev, digest))
                conn.commit()
            except INTEGRITY_ERRORS:
                try:
                    conn.rollback()
                except Exception:
                    pass
                continue  # another replica took this seq: re-read and decide again
            return {"seq": seq, "commit": sha, "first_seen": seen, "prev_hash": prev, "entry_hash": digest}
    logger.warning("deploy log: gave up appending %s after %d attempts", sha, attempts)
    return None


def record_at_startup() -> Optional[Dict[str, Any]]:
    """record(), at most once per process and database. Never raises: a log failure must not stop startup."""
    identity = _db_identity()
    if identity in _RECORDED:
        return None
    try:
        out = record()
        _RECORDED.add(identity)
        if out:
            logger.info("deploy log: commit %s is entry %d", out["commit"], out["seq"])
        return out
    except Exception as exc:
        logger.warning("deploy log: could not record this deploy (%s)", type(exc).__name__)
        return None


def verify_chain(entries: List[Dict[str, Any]]) -> bool:
    """entries oldest first. The same check scripts/verify-deploy.py makes."""
    prev = GENESIS_HASH
    for index, e in enumerate(entries, start=1):
        try:
            if int(e["seq"]) != index or e["prev_hash"] != prev:
                return False
            if entry_hash(e["seq"], e["commit"], e["first_seen"], e["prev_hash"]) != e["entry_hash"]:
                return False
        except (KeyError, TypeError, ValueError):
            return False
        prev = e["entry_hash"]
    return True


def listing(limit: int = 50) -> Dict[str, Any]:
    from db_feature_store import feature_conn

    init_tables()
    limit = max(1, min(500, int(limit)))
    with feature_conn() as conn:
        rows = [_row(r) for r in conn.execute(
            "SELECT seq, commit_sha, first_seen, prev_hash, entry_hash FROM public_deploy_log ORDER BY seq ASC"
        ).fetchall()]
    return {
        "entries": list(reversed(rows))[:limit],
        "head_hash": rows[-1]["entry_hash"] if rows else None,
        "chain_ok": verify_chain(rows),
        "count": len(rows),
        "genesis_hash": GENESIS_HASH,
        "hash_rule": HASH_RULE,
    }
