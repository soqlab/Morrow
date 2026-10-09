"""
Wave 15 — Outbound Webhook System
Register webhook endpoints and deliver events to them with HMAC signing + retry.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

_DDL = [
    """CREATE TABLE IF NOT EXISTS pqc_webhooks (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        events TEXT NOT NULL DEFAULT '["*"]',
        secret TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_triggered_at TEXT,
        total_deliveries INTEGER NOT NULL DEFAULT 0,
        failed_deliveries INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS pqc_webhook_deliveries (
        id TEXT PRIMARY KEY,
        webhook_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        status_code INTEGER,
        response_body TEXT,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        delivered_at TEXT
    )""",
]

ALL_EVENTS = [
    "scan.completed", "scan.failed",
    "finding.critical", "finding.high",
    "remediation.created", "remediation.resolved",
    "sla.breach", "sla.at_risk",
    "canary.tripped", "hndl.alert",
    "policy.violation", "policy.passed",
]


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    # Migrate: add columns that may not exist in pre-Wave-15 webhooks table
    existing = {row[1] for row in conn.execute("PRAGMA table_info(pqc_webhooks)").fetchall()}
    migrations = [
        ("events", "TEXT NOT NULL DEFAULT '[\"*\"]'"),
        ("secret", "TEXT NOT NULL DEFAULT ''"),
        ("last_triggered_at", "TEXT"),
        ("total_deliveries", "INTEGER NOT NULL DEFAULT 0"),
        ("failed_deliveries", "INTEGER NOT NULL DEFAULT 0"),
    ]
    for col, typedef in migrations:
        if col not in existing:
            conn.execute(f"ALTER TABLE pqc_webhooks ADD COLUMN {col} {typedef}")
    conn.commit()


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_webhook(conn: sqlite3.Connection, org_id: str, name: str, url: str,
                   events: List[str], secret: str = "") -> Dict:
    wh_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO pqc_webhooks (id, organization_id, name, url, events, secret, enabled, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
        (wh_id, org_id, name, url, json.dumps(events or ["*"]), secret, now),
    )
    conn.commit()
    return get_webhook(conn, wh_id)


def get_webhook(conn: sqlite3.Connection, wh_id: str) -> Optional[Dict]:
    row = conn.execute(
        """SELECT id, organization_id, name, url, events, secret, enabled,
                  created_at, last_triggered_at, total_deliveries, failed_deliveries
           FROM pqc_webhooks WHERE id=?""",
        (wh_id,),
    ).fetchone()
    if not row:
        return None
    cols = ["id", "organization_id", "name", "url", "events", "secret", "enabled",
            "created_at", "last_triggered_at", "total_deliveries", "failed_deliveries"]
    d = dict(zip(cols, row))
    d["events"] = json.loads(d["events"])
    d["enabled"] = bool(d["enabled"])
    d.pop("secret", None)  # never return secret
    return d


def list_webhooks(conn: sqlite3.Connection, org_id: str) -> List[Dict]:
    rows = conn.execute(
        """SELECT id, organization_id, name, url, events, secret, enabled,
                  created_at, last_triggered_at, total_deliveries, failed_deliveries
           FROM pqc_webhooks WHERE organization_id=? ORDER BY created_at DESC""",
        (org_id,),
    ).fetchall()
    cols = ["id", "organization_id", "name", "url", "events", "secret", "enabled",
            "created_at", "last_triggered_at", "total_deliveries", "failed_deliveries"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        d["events"] = json.loads(d["events"])
        d["enabled"] = bool(d["enabled"])
        d.pop("secret", None)
        result.append(d)
    return result


def update_webhook(conn: sqlite3.Connection, wh_id: str, org_id: str,
                   name: Optional[str] = None, url: Optional[str] = None,
                   events: Optional[List[str]] = None, secret: Optional[str] = None,
                   enabled: Optional[bool] = None) -> Optional[Dict]:
    sets, vals = [], []
    if name is not None:
        sets.append("name=?"); vals.append(name)
    if url is not None:
        sets.append("url=?"); vals.append(url)
    if events is not None:
        sets.append("events=?"); vals.append(json.dumps(events))
    if secret is not None:
        sets.append("secret=?"); vals.append(secret)
    if enabled is not None:
        sets.append("enabled=?"); vals.append(1 if enabled else 0)
    if not sets:
        return get_webhook(conn, wh_id)
    vals.extend([wh_id, org_id])
    conn.execute(f"UPDATE pqc_webhooks SET {','.join(sets)} WHERE id=? AND organization_id=?", vals)
    conn.commit()
    return get_webhook(conn, wh_id)


def delete_webhook(conn: sqlite3.Connection, wh_id: str, org_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM pqc_webhooks WHERE id=? AND organization_id=?", (wh_id, org_id)
    )
    conn.commit()
    return cur.rowcount > 0


# ── Delivery ──────────────────────────────────────────────────────────────────

def _sign(secret: str, body: bytes) -> str:
    if not secret:
        return ""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver_event(conn: sqlite3.Connection, org_id: str, event_type: str, payload: Dict,
                  timeout: int = 10) -> List[Dict]:
    """Deliver event to all matching webhooks. Returns delivery results."""
    import requests as _req

    webhooks = conn.execute(
        "SELECT id, url, events, secret FROM pqc_webhooks WHERE organization_id=? AND enabled=1",
        (org_id,),
    ).fetchall()

    results = []
    for wh_id, url, events_json, secret in webhooks:
        events = json.loads(events_json)
        if "*" not in events and event_type not in events:
            continue

        delivery_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        body_dict = {"id": delivery_id, "event": event_type, "ts": now,
                     "organization_id": org_id, "payload": payload}
        body_bytes = json.dumps(body_dict).encode()
        sig = _sign(secret, body_bytes)

        headers = {"Content-Type": "application/json", "X-PQC-Event": event_type,
                   "X-PQC-Delivery": delivery_id}
        if sig:
            headers["X-PQC-Signature-256"] = sig

        status_code, response_body, status = None, "", "failed"
        try:
            r = _req.post(url, data=body_bytes, headers=headers, timeout=timeout)
            status_code = r.status_code
            response_body = r.text[:500]
            status = "delivered" if r.status_code < 300 else "failed"
        except Exception as e:
            response_body = str(e)[:200]

        delivered_at = datetime.now(timezone.utc).isoformat() if status == "delivered" else None
        try:
            conn.execute(
                """INSERT INTO pqc_webhook_deliveries
                   (id, webhook_id, organization_id, event_type, payload, status, status_code,
                    response_body, attempt_count, created_at, delivered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (delivery_id, wh_id, org_id, event_type, json.dumps(body_dict),
                 status, status_code, response_body, now, delivered_at),
            )
            conn.execute(
                """UPDATE pqc_webhooks SET total_deliveries=total_deliveries+1,
                   failed_deliveries=failed_deliveries+?,
                   last_triggered_at=? WHERE id=?""",
                (0 if status == "delivered" else 1, now, wh_id),
            )
            conn.commit()
        except Exception:
            pass

        results.append({"webhook_id": wh_id, "delivery_id": delivery_id,
                         "status": status, "status_code": status_code})
    return results


def list_deliveries(conn: sqlite3.Connection, wh_id: str, org_id: str, limit: int = 50) -> List[Dict]:
    rows = conn.execute(
        """SELECT id, event_type, status, status_code, response_body, attempt_count,
                  created_at, delivered_at
           FROM pqc_webhook_deliveries WHERE webhook_id=? AND organization_id=?
           ORDER BY created_at DESC LIMIT ?""",
        (wh_id, org_id, limit),
    ).fetchall()
    cols = ["id", "event_type", "status", "status_code", "response_body",
            "attempt_count", "created_at", "delivered_at"]
    return [dict(zip(cols, r)) for r in rows]

