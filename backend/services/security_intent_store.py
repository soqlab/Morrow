from __future__ import annotations

import json
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db import current_organization_id, get_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_intents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            intent_text TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            evaluation_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            published_at TEXT NOT NULL DEFAULT '',
            disabled_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_intents_org_status ON security_intents(organization_id, status, updated_at)"
    )


def _row_to_dict(row) -> Dict[str, Any]:
    data = dict(row)
    try:
        data["evaluation"] = json.loads(data.pop("evaluation_json") or "{}")
    except Exception:
        data["evaluation"] = {}
    return data


def create_security_intent(name: str, intent_text: str, evaluation: Dict[str, Any], created_by: str = "") -> Dict[str, Any]:
    org_id = current_organization_id()
    now = _now()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_table(conn)
        cur = conn.execute(
            """
            INSERT INTO security_intents
                (organization_id, name, intent_text, status, evaluation_json, created_by, created_at, updated_at)
            VALUES (?, ?, ?, 'draft', ?, ?, ?, ?)
            """,
            (org_id, str(name or "Security intent").strip()[:180], str(intent_text or "").strip(), json.dumps(evaluation), str(created_by or "").strip(), now, now),
        )
        row_id = int(cur.lastrowid or 0)
        conn.commit()
        row = conn.execute("SELECT * FROM security_intents WHERE organization_id=? AND id=?", (org_id, row_id)).fetchone()
        return _row_to_dict(row)


def list_security_intents(status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    status = str(status or "").strip().lower()
    limit = max(1, min(int(limit or 200), 1000))
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_table(conn)
        if status:
            rows = conn.execute(
                "SELECT * FROM security_intents WHERE organization_id=? AND status=? ORDER BY updated_at DESC LIMIT ?",
                (org_id, status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM security_intents WHERE organization_id=? ORDER BY updated_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_security_intent(intent_id: int) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_table(conn)
        row = conn.execute(
            "SELECT * FROM security_intents WHERE organization_id=? AND id=?",
            (org_id, int(intent_id)),
        ).fetchone()
        return _row_to_dict(row) if row else None


def set_security_intent_status(intent_id: int, status: str) -> Optional[Dict[str, Any]]:
    org_id = current_organization_id()
    status = str(status or "").strip().lower()
    if status not in {"draft", "published", "disabled"}:
        raise ValueError("invalid security intent status")
    now = _now()
    published_at = now if status == "published" else ""
    disabled_at = now if status == "disabled" else ""
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_table(conn)
        conn.execute(
            """
            UPDATE security_intents
               SET status=?, updated_at=?,
                   published_at=CASE WHEN ? != '' THEN ? ELSE published_at END,
                   disabled_at=CASE WHEN ? != '' THEN ? ELSE disabled_at END
             WHERE organization_id=? AND id=?
            """,
            (status, now, published_at, published_at, disabled_at, disabled_at, org_id, int(intent_id)),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM security_intents WHERE organization_id=? AND id=?", (org_id, int(intent_id))).fetchone()
        return _row_to_dict(row) if row else None


def active_security_intent_bundle() -> Dict[str, Any]:
    intents = list_security_intents(status="published", limit=500)
    controls: List[Dict[str, Any]] = []
    for item in intents:
        for control in (item.get("evaluation") or {}).get("controls") or []:
            controls.append({**control, "security_intent_id": item.get("id"), "security_intent_name": item.get("name")})
    return {
        "api_version": "v1",
        "generated_at": _now(),
        "published_intents": len(intents),
        "controls": controls,
        "intents": intents,
    }
