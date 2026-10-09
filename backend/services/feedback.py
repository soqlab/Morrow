"""User feedback capture.

The platform had no way for a user to say anything back to the operator: no bug
report, no request, no rating. Every other signal in the admin console is
inferred from telemetry, which tells you what people did but never why.

Storage goes through db_feature_store so the same code serves SQLite and
Postgres, and the table uses organization_id to match the core convention (see
test_sql_schema_conformance for why both conventions exist and why this file
does not invent a third).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

CATEGORIES = ("bug", "idea", "question", "praise", "other")
STATUSES = ("new", "triaged", "resolved", "declined")

_MAX_MESSAGE = 4000
_MAX_FIELD = 256


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_tables() -> None:
    with feature_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id TEXT NOT NULL DEFAULT '',
                user_id         TEXT NOT NULL DEFAULT '',
                email           TEXT NOT NULL DEFAULT '',
                category        TEXT NOT NULL DEFAULT 'other',
                rating          INTEGER,
                message         TEXT NOT NULL,
                page            TEXT NOT NULL DEFAULT '',
                user_agent      TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'new',
                admin_note      TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_org ON feedback(organization_id);
            CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
            """
        )
        conn.commit()


def _clean(value: Any, limit: int = _MAX_FIELD) -> str:
    return str(value or "").strip()[:limit]


def submit(
    organization_id: str,
    message: str,
    *,
    user_id: str = "",
    email: str = "",
    category: str = "other",
    rating: Optional[int] = None,
    page: str = "",
    user_agent: str = "",
) -> Dict[str, Any]:
    """Record one piece of feedback. Raises ValueError on unusable input."""
    text = str(message or "").strip()
    if not text:
        raise ValueError("Feedback message cannot be empty.")
    text = text[:_MAX_MESSAGE]

    cat = _clean(category).lower() or "other"
    if cat not in CATEGORIES:
        cat = "other"

    score: Optional[int] = None
    if rating is not None and str(rating).strip() != "":
        try:
            score = int(rating)
        except (TypeError, ValueError):
            raise ValueError("Rating must be a whole number between 1 and 5.")
        if not 1 <= score <= 5:
            raise ValueError("Rating must be between 1 and 5.")

    now = _now()
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute(
            "INSERT INTO feedback (organization_id,user_id,email,category,rating,message,"
            "page,user_agent,status,admin_note,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,'new','',?,?)",
            (_clean(organization_id), _clean(user_id), _clean(email), cat, score, text,
             _clean(page, 512), _clean(user_agent, 512), now, now),
        )
        new_id = cur.lastrowid
        conn.commit()
    return {"id": new_id, "category": cat, "rating": score, "status": "new", "created_at": now}


def list_feedback(
    organization_id: str = "",
    *,
    status: str = "",
    category: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Newest first. An empty organization_id lists across every tenant, which is
    what the platform operator needs and what the admin key gates."""
    init_tables()
    clauses, params = [], []
    if organization_id:
        clauses.append("organization_id = ?")
        params.append(organization_id)
    if status:
        clauses.append("status = ?")
        params.append(_clean(status).lower())
    if category:
        clauses.append("category = ?")
        params.append(_clean(category).lower())
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit or 100), 500)))

    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT id,organization_id,user_id,email,category,rating,message,page,"
            "user_agent,status,admin_note,created_at,updated_at FROM feedback"
            + where + " ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [dict(r) for r in rows]


def get_feedback(feedback_id: int, organization_id: str = "") -> Optional[Dict[str, Any]]:
    """One item, in exactly the shape list_feedback returns (message text included).

    A deep link to an item that is older than the page the console loaded cannot otherwise be told
    apart from a deleted one. An empty organization_id reads across every tenant, which is what the
    platform operator needs; passing one scopes the read to that tenant so a mismatch reads as
    "not found" rather than leaking another tenant's item.
    """
    try:
        ident = int(feedback_id)
    except (TypeError, ValueError):
        return None
    init_tables()
    clause, params = "", [ident]
    if organization_id:
        clause, params = " AND organization_id = ?", [ident, organization_id]
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT id,organization_id,user_id,email,category,rating,message,page,"
            "user_agent,status,admin_note,created_at,updated_at FROM feedback WHERE id = ?" + clause,
            tuple(params),
        ).fetchone()
    return dict(row) if row else None


def set_status(feedback_id: int, status: str, admin_note: str = "") -> Optional[Dict[str, Any]]:
    """Move one item through triage. Returns None when it does not exist, so the
    caller can answer 404 rather than pretending it worked."""
    target = _clean(status).lower()
    if target not in STATUSES:
        raise ValueError(f"Status must be one of: {', '.join(STATUSES)}")

    init_tables()
    with feature_conn() as conn:
        existing = conn.execute("SELECT id FROM feedback WHERE id = ?", (int(feedback_id),)).fetchone()
        if not existing:
            return None
        conn.execute(
            "UPDATE feedback SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?",
            (target, _clean(admin_note, 2000), _now(), int(feedback_id)),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id,organization_id,user_id,email,category,rating,message,page,"
            "user_agent,status,admin_note,created_at,updated_at FROM feedback WHERE id = ?",
            (int(feedback_id),),
        ).fetchone()
    return dict(row) if row else None


def summary(organization_id: str = "") -> Dict[str, Any]:
    """Counts the admin panel needs without pulling every row."""
    init_tables()
    where, params = ("", [])
    if organization_id:
        where, params = " WHERE organization_id = ?", [organization_id]

    with feature_conn() as conn:
        total = int((conn.execute(
            "SELECT COUNT(*) FROM feedback" + where, tuple(params)).fetchone() or [0])[0] or 0)
        by_status = {
            str(r[0]): int(r[1])
            for r in conn.execute(
                "SELECT status, COUNT(*) FROM feedback" + where + " GROUP BY status",
                tuple(params)).fetchall()
        }
        by_category = {
            str(r[0]): int(r[1])
            for r in conn.execute(
                "SELECT category, COUNT(*) FROM feedback" + where + " GROUP BY category",
                tuple(params)).fetchall()
        }
        rated = conn.execute(
            "SELECT AVG(rating), COUNT(rating) FROM feedback"
            + (where + " AND" if where else " WHERE") + " rating IS NOT NULL",
            tuple(params),
        ).fetchone()

    average = round(float(rated[0]), 2) if rated and rated[0] is not None else None
    return {
        "total": total,
        "open": int(by_status.get("new", 0)) + int(by_status.get("triaged", 0)),
        "by_status": by_status,
        "by_category": by_category,
        "average_rating": average,
        "rated_count": int(rated[1]) if rated and rated[1] is not None else 0,
    }
