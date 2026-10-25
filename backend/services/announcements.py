"""Platform announcements and maintenance mode.

Announcements are operator-authored notices (info / warn / critical) shown to every
customer or to a list of organizations, optionally inside a time window.

Maintenance mode pauses customer writes: while it is on, non-GET requests to
customer routes answer 503 with the operator's message and a Retry-After header.
Reads, /platform, /auth, /health and /status keep working so operators can
still work and customers can still sign in and see the notice. ends_at is the
announced end, reported to clients and used for Retry-After; it does not switch
maintenance off by itself, because an overrunning migration must not reopen writes
halfway through.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

logger = logging.getLogger(__name__)

SEVERITIES = ("info", "warn", "critical")
AUDIENCES = ("all", "orgs")
MAINTENANCE_ID = "global"
DEFAULT_MAINTENANCE_MESSAGE = (
    "Scheduled maintenance is in progress. Changes are paused for a short time; reading data still works."
)
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
EXEMPT_PREFIXES = (
    "/platform", "/auth", "/health", "/healthz", "/status", "/vendor-admin", "/ui",
    "/docs", "/openapi.json", "/redoc", "/favicon.ico", "/favicon.svg", "/announcements",
)

_LOCK = threading.Lock()
_MAINT_CACHE: Dict[str, Any] = {"loaded_at": 0.0, "db": None, "state": None}
_COLUMNS = "id, title, body, severity, audience, organization_ids, starts_at, ends_at, created_by, created_at, updated_by, updated_at"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _timestamp(value: Any, field: str) -> str:
    if value in (None, ""):
        return ""
    parsed = _parse(value)
    if not parsed:
        raise ValueError(f"{field} must be an ISO-8601 timestamp, e.g. 2026-10-01T09:00:00Z.")
    return _iso(parsed)


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}"


_TABLES_READY: set = set()


def init_tables() -> None:
    # list_announcements() runs this on every /announcements/active poll; the DDL only needs to run once
    # per store (the same memo security_journal.init_tables uses).
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    _init_tables_uncached()
    _TABLES_READY.add(identity)


def _init_tables_uncached() -> None:
    with feature_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS platform_announcements (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                title            TEXT NOT NULL,
                body             TEXT NOT NULL DEFAULT '',
                severity         TEXT NOT NULL DEFAULT 'info',
                audience         TEXT NOT NULL DEFAULT 'all',
                organization_ids TEXT NOT NULL DEFAULT '[]',
                starts_at        TEXT NOT NULL DEFAULT '',
                ends_at          TEXT NOT NULL DEFAULT '',
                created_by       TEXT NOT NULL DEFAULT '',
                created_at       TEXT NOT NULL,
                updated_by       TEXT NOT NULL DEFAULT '',
                updated_at       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platform_maintenance (
                id         TEXT PRIMARY KEY,
                enabled    INTEGER NOT NULL DEFAULT 0,
                message    TEXT NOT NULL DEFAULT '',
                ends_at    TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            );
            """
        )
        conn.commit()


# ── Announcements ────────────────────────────────────────────────────────────


def _clean_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = str(payload.get("title") or "").strip()
    if not title or len(title) > 140:
        raise ValueError("title must be 1-140 characters.")
    body = str(payload.get("body") or "").strip()
    if len(body) > 2000:
        raise ValueError("body must be at most 2000 characters.")
    severity = str(payload.get("severity") or "info").strip().lower()
    if severity not in SEVERITIES:
        raise ValueError("severity must be info, warn, or critical.")
    audience = str(payload.get("audience") or "all").strip().lower()
    if audience not in AUDIENCES:
        raise ValueError("audience must be all or orgs.")
    orgs: List[str] = []
    for value in payload.get("organization_ids") or []:
        org = str(value or "").strip()
        if org and len(org) <= 128 and org not in orgs:
            orgs.append(org)
    if audience == "orgs" and not orgs:
        raise ValueError("List at least one organization when the audience is orgs.")
    if len(orgs) > 500:
        raise ValueError("An announcement can target at most 500 organizations.")
    starts_at = _timestamp(payload.get("starts_at"), "starts_at")
    ends_at = _timestamp(payload.get("ends_at"), "ends_at")
    if starts_at and ends_at and _parse(ends_at) <= _parse(starts_at):
        raise ValueError("ends_at must be after starts_at.")
    return {
        "title": title, "body": body, "severity": severity, "audience": audience,
        "organization_ids": orgs if audience == "orgs" else [],
        "starts_at": starts_at, "ends_at": ends_at,
    }


def _state(item: Dict[str, Any], now: Optional[datetime] = None) -> str:
    current = now or _now()
    starts, ends = _parse(item.get("starts_at")), _parse(item.get("ends_at"))
    if starts and starts > current:
        return "scheduled"
    if ends and ends <= current:
        return "expired"
    return "active"


def _row(row: Any) -> Dict[str, Any]:
    item = dict(row)
    try:
        item["organization_ids"] = json.loads(item.get("organization_ids") or "[]")
    except ValueError:
        item["organization_ids"] = []
    item["state"] = _state(item)
    return item


def get_announcement(announcement_id: int) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(f"SELECT {_COLUMNS} FROM platform_announcements WHERE id = ?", (int(announcement_id),)).fetchone()
    return _row(row) if row else None


def list_announcements(limit: int = 200) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM platform_announcements ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit or 200), 500)),),
        ).fetchall()
    return [_row(r) for r in rows]


def create_announcement(payload: Dict[str, Any], actor: str = "") -> Dict[str, Any]:
    clean = _clean_payload(payload)
    init_tables()
    now = _iso(_now())
    with feature_conn() as conn:
        cur = conn.execute(
            "INSERT INTO platform_announcements (title, body, severity, audience, organization_ids, starts_at, ends_at, "
            "created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (clean["title"], clean["body"], clean["severity"], clean["audience"], json.dumps(clean["organization_ids"]),
             clean["starts_at"], clean["ends_at"], str(actor or "")[:160], now, str(actor or "")[:160], now),
        )
        new_id = cur.lastrowid
        conn.commit()
    return get_announcement(int(new_id)) or {}


def update_announcement(announcement_id: int, payload: Dict[str, Any], actor: str = "") -> Optional[Dict[str, Any]]:
    if not get_announcement(announcement_id):
        return None
    clean = _clean_payload(payload)
    with feature_conn() as conn:
        conn.execute(
            "UPDATE platform_announcements SET title = ?, body = ?, severity = ?, audience = ?, organization_ids = ?, "
            "starts_at = ?, ends_at = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (clean["title"], clean["body"], clean["severity"], clean["audience"], json.dumps(clean["organization_ids"]),
             clean["starts_at"], clean["ends_at"], str(actor or "")[:160], _iso(_now()), int(announcement_id)),
        )
        conn.commit()
    return get_announcement(announcement_id)


def delete_announcement(announcement_id: int) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM platform_announcements WHERE id = ?", (int(announcement_id),))
        deleted = int(cur.rowcount or 0)
        conn.commit()
    return deleted > 0


def active_for(organization_id: str = "", include_targeted: bool = True) -> List[Dict[str, Any]]:
    """Announcements a customer should see now: every 'all' notice plus those naming their org."""
    order = {"critical": 0, "warn": 1, "info": 2}
    org = str(organization_id or "").strip()
    out = []
    for item in list_announcements(limit=500):
        if item["state"] != "active":
            continue
        if item["audience"] == "orgs" and not (include_targeted and org and org in item["organization_ids"]):
            continue
        out.append({
            "id": item["id"], "title": item["title"], "body": item["body"], "severity": item["severity"],
            "starts_at": item["starts_at"], "ends_at": item["ends_at"], "updated_at": item["updated_at"],
        })
    out.sort(key=lambda i: (order.get(i["severity"], 3), -int(i["id"])))
    return out


# ── Maintenance mode ─────────────────────────────────────────────────────────


def _default_maintenance() -> Dict[str, Any]:
    return {"enabled": False, "message": "", "ends_at": "", "updated_by": "", "updated_at": ""}


def _decorate(state: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(state)
    ends = _parse(out.get("ends_at"))
    out["overdue"] = bool(out.get("enabled") and ends and ends <= _now())
    if out.get("enabled") and not out.get("message"):
        out["message"] = DEFAULT_MAINTENANCE_MESSAGE
    return out


def load_maintenance() -> Dict[str, Any]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT enabled, message, ends_at, updated_by, updated_at FROM platform_maintenance WHERE id = ?",
            (MAINTENANCE_ID,),
        ).fetchone()
    state = _default_maintenance()
    if row:
        state.update({
            "enabled": bool(int(row["enabled"] or 0)), "message": row["message"] or "", "ends_at": row["ends_at"] or "",
            "updated_by": row["updated_by"] or "", "updated_at": row["updated_at"] or "",
        })
    return _decorate(state)


def maintenance_cache_stale() -> bool:
    try:
        ttl = max(1.0, float(os.getenv("MORROW_MAINTENANCE_CACHE_SECONDS", "5") or 5))
    except ValueError:
        ttl = 5.0
    return _MAINT_CACHE["state"] is None or _MAINT_CACHE["db"] != _db_identity() or (
        time.monotonic() - float(_MAINT_CACHE["loaded_at"] or 0) > ttl
    )


def refresh_maintenance_cache() -> Dict[str, Any]:
    identity = _db_identity()
    try:
        state = load_maintenance()
    except Exception as exc:
        logger.warning("[maintenance] state unavailable: %s", exc.__class__.__name__)
        state = _MAINT_CACHE["state"] if _MAINT_CACHE["db"] == identity and _MAINT_CACHE["state"] else _decorate(_default_maintenance())
    with _LOCK:
        _MAINT_CACHE.update(loaded_at=time.monotonic(), db=identity, state=state)
    return state


def get_maintenance(use_cache: bool = True) -> Dict[str, Any]:
    if not use_cache or maintenance_cache_stale():
        return refresh_maintenance_cache()
    return _decorate(dict(_MAINT_CACHE["state"]))


def set_maintenance(enabled: bool, message: str = "", ends_at: Any = "", updated_by: str = "") -> Dict[str, Any]:
    text = str(message or "").strip()
    if len(text) > 500:
        raise ValueError("message must be at most 500 characters.")
    end = _timestamp(ends_at, "ends_at")
    init_tables()
    now = _iso(_now())
    values = (1 if enabled else 0, text, end, str(updated_by or "")[:160], now)
    with feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO platform_maintenance (id, enabled, message, ends_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (MAINTENANCE_ID, *values),
                )
        except INTEGRITY_ERRORS:
            conn.execute(
                "UPDATE platform_maintenance SET enabled = ?, message = ?, ends_at = ?, updated_by = ?, updated_at = ? WHERE id = ?",
                (*values, MAINTENANCE_ID),
            )
        conn.commit()
    return refresh_maintenance_cache()


def public_maintenance_state(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    current = state or get_maintenance()
    return {"enabled": bool(current.get("enabled")), "message": current.get("message") if current.get("enabled") else "",
            "ends_at": current.get("ends_at") if current.get("enabled") else ""}


def retry_after_seconds(state: Dict[str, Any]) -> int:
    ends = _parse(state.get("ends_at"))
    if ends:
        remaining = int((ends - _now()).total_seconds())
        if remaining > 0:
            return max(30, min(remaining, 3600))
    return 300


def request_is_exempt(method: str, path: str) -> bool:
    if str(method or "GET").upper() in SAFE_METHODS:
        return True
    route = str(path or "/")
    if route == "/v1" or route.startswith("/v1/"):
        route = route[3:] or "/"
    if route == "/ai-control/stop" and str(method).upper() == "POST":
        return True
    return any(route == p or route.startswith(p + "/") for p in EXEMPT_PREFIXES)
