"""Web Push (VAPID) + outbound Slack/Teams webhook notifications."""
import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)


def init_tables(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            user_id TEXT,
            endpoint TEXT NOT NULL UNIQUE,
            sub_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS push_webhook_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS push_notification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            title TEXT,
            status TEXT,
            created_at INTEGER NOT NULL
        )
    """)
    db.commit()


# ── Webhook storage ────────────────────────────────────────────────────────

def upsert_webhook(db, org_id: str, channel: str, url: str) -> dict:
    existing = db.execute(
        "SELECT id FROM push_webhook_configs WHERE org_id=? AND channel=?",
        (org_id, channel),
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE push_webhook_configs SET url=?, enabled=1 WHERE id=?",
            (url, existing[0]),
        )
    else:
        db.execute(
            "INSERT INTO push_webhook_configs (org_id, channel, url, enabled, created_at) VALUES (?,?,?,1,?)",
            (org_id, channel, url, int(time.time())),
        )
    db.commit()
    return {"org_id": org_id, "channel": channel, "url": url, "enabled": True}


def list_webhooks(db, org_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT id, channel, url, enabled, created_at FROM push_webhook_configs WHERE org_id=?",
        (org_id,),
    ).fetchall()
    return [{"id": r[0], "channel": r[1], "url": r[2], "enabled": bool(r[3]), "created_at": r[4]} for r in rows]


def delete_webhook(db, webhook_id: int, org_id: str) -> bool:
    cur = db.execute(
        "DELETE FROM push_webhook_configs WHERE id=? AND org_id=?",
        (webhook_id, org_id),
    )
    db.commit()
    return cur.rowcount > 0


# ── Push subscription storage ──────────────────────────────────────────────

def store_subscription(db, org_id: str, user_id: Optional[str], sub: dict) -> dict:
    endpoint = sub.get("endpoint", "")
    existing = db.execute(
        "SELECT id FROM push_subscriptions WHERE endpoint=?", (endpoint,)
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE push_subscriptions SET sub_json=?, org_id=?, user_id=? WHERE id=?",
            (json.dumps(sub), org_id, user_id, existing[0]),
        )
    else:
        db.execute(
            "INSERT INTO push_subscriptions (org_id, user_id, endpoint, sub_json, created_at) VALUES (?,?,?,?,?)",
            (org_id, user_id, endpoint, json.dumps(sub), int(time.time())),
        )
    db.commit()
    return {"stored": True, "endpoint": endpoint[:60] + "..."}


def list_subscriptions(db, org_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT id, user_id, endpoint, created_at FROM push_subscriptions WHERE org_id=?",
        (org_id,),
    ).fetchall()
    return [{"id": r[0], "user_id": r[1], "endpoint": r[2][:50] + "...", "created_at": r[3]} for r in rows]


# ── Slack / Teams delivery ─────────────────────────────────────────────────

def _post_json(url: str, payload: dict, timeout: int = 8) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def _slack_payload(title: str, body: str, severity: str) -> dict:
    color = {"CRITICAL": "#e53e3e", "HIGH": "#ed8936", "MEDIUM": "#ecc94b"}.get(severity, "#4a5568")
    return {
        "attachments": [{
            "color": color,
            "title": f"[PQC Scanner] {title}",
            "text": body,
            "footer": "PQC Scanner",
            "ts": int(time.time()),
        }]
    }


def _teams_payload(title: str, body: str, severity: str) -> dict:
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": {"CRITICAL": "e53e3e", "HIGH": "ed8936"}.get(severity, "0078D4"),
        "summary": title,
        "sections": [{"activityTitle": f"[PQC Scanner] {title}", "activityText": body}],
    }


def send_alert(db, org_id: str, title: str, body: str, severity: str = "HIGH") -> dict:
    webhooks = db.execute(
        "SELECT id, channel, url FROM push_webhook_configs WHERE org_id=? AND enabled=1",
        (org_id,),
    ).fetchall()
    results = []
    for wh_id, channel, url in webhooks:
        if channel == "slack":
            payload = _slack_payload(title, body, severity)
        elif channel == "teams":
            payload = _teams_payload(title, body, severity)
        else:
            payload = {"title": title, "body": body, "severity": severity}
        status_code, _ = _post_json(url, payload)
        status = "ok" if 200 <= status_code < 300 else f"error_{status_code}"
        db.execute(
            "INSERT INTO push_notification_log (org_id, channel, title, status, created_at) VALUES (?,?,?,?,?)",
            (org_id, channel, title, status, int(time.time())),
        )
        results.append({"channel": channel, "status": status})
    db.commit()
    return {"sent": len(results), "results": results}


def test_webhook(db, webhook_id: int, org_id: str) -> dict:
    row = db.execute(
        "SELECT channel, url FROM push_webhook_configs WHERE id=? AND org_id=?",
        (webhook_id, org_id),
    ).fetchone()
    if not row:
        return {"error": "webhook not found"}
    channel, url = row
    return send_alert(db, org_id, "Test notification", "PQC Scanner webhook test — working correctly.", "LOW")


def notification_log(db, org_id: str, limit: int = 50) -> list[dict]:
    rows = db.execute(
        "SELECT channel, title, status, created_at FROM push_notification_log "
        "WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
        (org_id, limit),
    ).fetchall()
    return [{"channel": r[0], "title": r[1], "status": r[2], "created_at": r[3]} for r in rows]
