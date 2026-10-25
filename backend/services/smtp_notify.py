"""
SMTP Email + Slack Webhook Notifications

Complements alerting.py (Teams / PagerDuty) with email delivery via
smtplib and Slack Block Kit messages via urllib.request.

Config is stored per-organisation in SQLite so each tenant can supply
their own SMTP credentials and Slack webhook URL. Passwords are stored
as-is for now; callers should encrypt at rest before writing.

All network I/O is synchronous. For high-volume use wrap calls in a
thread or task queue.
"""

from __future__ import annotations

import json
import smtplib
import sqlite3
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS notification_configs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id     TEXT UNIQUE NOT NULL,
    smtp_host           TEXT,
    smtp_port           INTEGER DEFAULT 587,
    smtp_user           TEXT,
    smtp_password       TEXT,
    smtp_from           TEXT,
    smtp_to             TEXT DEFAULT '[]',
    smtp_enabled        INTEGER DEFAULT 0,
    slack_webhook_url   TEXT,
    slack_channel       TEXT DEFAULT '#security',
    slack_enabled       INTEGER DEFAULT 0,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL,
    channel         TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    subject         TEXT,
    status          TEXT NOT NULL,
    error           TEXT,
    sent_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_log_org
    ON notification_log(organization_id);
"""


def init_tables(conn: sqlite3.Connection) -> None:
    """Create notification tables if they do not exist."""
    with closing(conn.cursor()) as cur:
        cur.executescript(_DDL)
    conn.commit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(
    conn: sqlite3.Connection,
    org_id: str,
    channel: str,
    event_type: str,
    subject: str,
    status: str,
    error: str = "",
) -> None:
    """Append one row to notification_log."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            INSERT INTO notification_log
                (organization_id, channel, event_type, subject, status, error, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, channel, event_type, subject, status, error, _now()),
        )
    conn.commit()


def _redact_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the config dict with smtp_password redacted."""
    out = dict(cfg)
    if out.get("smtp_password"):
        out["smtp_password"] = "***"
    return out


# ── Config management ─────────────────────────────────────────────────────────

def save_config(
    conn: sqlite3.Connection,
    org_id: str,
    smtp_host: Optional[str] = None,
    smtp_port: int = 587,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    smtp_from: Optional[str] = None,
    smtp_to: Optional[List[str]] = None,
    smtp_enabled: bool = False,
    slack_webhook_url: Optional[str] = None,
    slack_channel: str = "#security",
    slack_enabled: bool = False,
    **_extra: Any,
) -> Dict[str, Any]:
    """
    Upsert notification config for an organisation.

    smtp_to accepts a list of address strings; stored as JSON.
    Returns the saved config (password redacted).
    """
    smtp_to_json = json.dumps(smtp_to or [])
    now = _now()

    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            INSERT INTO notification_configs
                (organization_id, smtp_host, smtp_port, smtp_user, smtp_password,
                 smtp_from, smtp_to, smtp_enabled,
                 slack_webhook_url, slack_channel, slack_enabled, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id) DO UPDATE SET
                smtp_host         = excluded.smtp_host,
                smtp_port         = excluded.smtp_port,
                smtp_user         = excluded.smtp_user,
                smtp_password     = COALESCE(excluded.smtp_password, smtp_password),
                smtp_from         = excluded.smtp_from,
                smtp_to           = excluded.smtp_to,
                smtp_enabled      = excluded.smtp_enabled,
                slack_webhook_url = excluded.slack_webhook_url,
                slack_channel     = excluded.slack_channel,
                slack_enabled     = excluded.slack_enabled,
                updated_at        = excluded.updated_at
            """,
            (
                org_id,
                smtp_host,
                smtp_port,
                smtp_user,
                smtp_password,  # None → preserves existing via COALESCE
                smtp_from,
                smtp_to_json,
                1 if smtp_enabled else 0,
                slack_webhook_url,
                slack_channel,
                1 if slack_enabled else 0,
                now,
            ),
        )
    conn.commit()

    cfg = get_config(conn, org_id)
    return cfg or {}


def get_config(
    conn: sqlite3.Connection,
    org_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Return notification config for an organisation.

    smtp_password is redacted to "***" in the returned dict.
    Returns None if no config exists for this org.
    """
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, smtp_host, smtp_port, smtp_user,
                   smtp_password, smtp_from, smtp_to, smtp_enabled,
                   slack_webhook_url, slack_channel, slack_enabled, updated_at
            FROM notification_configs
            WHERE organization_id = ?
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        cols = [d[0] for d in cur.description]
        cfg = dict(zip(cols, row))

    # Deserialise smtp_to
    try:
        cfg["smtp_to"] = json.loads(cfg.get("smtp_to") or "[]")
    except (json.JSONDecodeError, TypeError):
        cfg["smtp_to"] = []

    # Convert flags to bool
    cfg["smtp_enabled"] = bool(cfg.get("smtp_enabled"))
    cfg["slack_enabled"] = bool(cfg.get("slack_enabled"))

    return _redact_config(cfg)


# ── Email delivery ────────────────────────────────────────────────────────────

def send_email(
    conn: sqlite3.Connection,
    org_id: str,
    subject: str,
    body_html: str,
    event_type: str = "generic",
) -> Dict[str, Any]:
    """
    Send an HTML email via SMTP STARTTLS using the organisation's stored config.

    Logs the result to notification_log regardless of outcome.

    Returns: {"status": "sent"|"failed", "error": str}
    """
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT smtp_host, smtp_port, smtp_user, smtp_password,
                   smtp_from, smtp_to, smtp_enabled
            FROM notification_configs
            WHERE organization_id = ?
            """,
            (org_id,),
        )
        row = cur.fetchone()

    if row is None:
        err = "No notification config found for this organisation"
        _log(conn, org_id, "email", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    (smtp_host, smtp_port, smtp_user, smtp_password,
     smtp_from, smtp_to_raw, smtp_enabled) = row

    if not smtp_enabled:
        err = "SMTP notifications are disabled for this organisation"
        _log(conn, org_id, "email", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    try:
        recipients: List[str] = json.loads(smtp_to_raw or "[]")
    except (json.JSONDecodeError, TypeError):
        recipients = []

    if not recipients:
        err = "No recipient addresses configured"
        _log(conn, org_id, "email", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    if not smtp_host:
        err = "SMTP host is not configured"
        _log(conn, org_id, "email", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    # Build MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from or smtp_user or "noreply@morrow"
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body_html, "html", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, int(smtp_port or 587), timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(msg["From"], recipients, msg.as_string())

        _log(conn, org_id, "email", event_type, subject, "sent")
        return {"status": "sent", "error": ""}

    except smtplib.SMTPAuthenticationError as exc:
        err = f"SMTP authentication failed: {exc}"
    except smtplib.SMTPConnectError as exc:
        err = f"SMTP connection error: {exc}"
    except smtplib.SMTPRecipientsRefused as exc:
        err = f"Recipients refused by server: {exc}"
    except smtplib.SMTPException as exc:
        err = f"SMTP error: {exc}"
    except OSError as exc:
        err = f"Network error sending email: {exc}"

    _log(conn, org_id, "email", event_type, subject, "failed", err)
    return {"status": "failed", "error": err}


# ── Slack delivery ────────────────────────────────────────────────────────────

_SLACK_COLORS = {
    "critical": "danger",
    "high":     "warning",
    "medium":   "#fbbf24",
    "low":      "good",
    "info":     "good",
}


def _build_slack_payload(
    subject: str,
    message: str,
    event_type: str,
    severity: str,
) -> Dict[str, Any]:
    """Construct a Slack Block Kit attachment payload."""
    color = _SLACK_COLORS.get(severity.lower(), "#808080")
    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Morrow Alert",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{subject}*\n{message}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Severity: {severity} | Event: {event_type}",
                            }
                        ],
                    },
                ],
            }
        ]
    }


def send_slack(
    conn: sqlite3.Connection,
    org_id: str,
    message: str,
    event_type: str = "generic",
    severity: str = "info",
    subject: str = "Morrow Notification",
) -> Dict[str, Any]:
    """
    Post a Block Kit message to Slack via the organisation's stored webhook URL.

    Logs the result to notification_log.

    Returns: {"status": "sent"|"failed", "error": str}
    """
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT slack_webhook_url, slack_channel, slack_enabled
            FROM notification_configs
            WHERE organization_id = ?
            """,
            (org_id,),
        )
        row = cur.fetchone()

    if row is None:
        err = "No notification config found for this organisation"
        _log(conn, org_id, "slack", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    webhook_url, _channel, slack_enabled = row

    if not slack_enabled:
        err = "Slack notifications are disabled for this organisation"
        _log(conn, org_id, "slack", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    if not webhook_url:
        err = "Slack webhook URL is not configured"
        _log(conn, org_id, "slack", event_type, subject, "failed", err)
        return {"status": "failed", "error": err}

    payload = _build_slack_payload(subject, message, event_type, severity)
    payload_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if body.strip().lower() != "ok":
                err = f"Unexpected Slack response: {body[:200]}"
                _log(conn, org_id, "slack", event_type, subject, "failed", err)
                return {"status": "failed", "error": err}

        _log(conn, org_id, "slack", event_type, subject, "sent")
        return {"status": "sent", "error": ""}

    except urllib.error.HTTPError as exc:
        err = f"Slack HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        err = f"Slack URL error: {exc.reason}"
    except OSError as exc:
        err = f"Network error posting to Slack: {exc}"

    _log(conn, org_id, "slack", event_type, subject, "failed", err)
    return {"status": "failed", "error": err}


# ── Combined notifier ─────────────────────────────────────────────────────────

def notify_all(
    conn: sqlite3.Connection,
    org_id: str,
    subject: str,
    message: str,
    body_html: str = "",
    event_type: str = "generic",
    severity: str = "info",
) -> Dict[str, Any]:
    """
    Fire email and/or Slack notifications based on what is enabled for the org.

    body_html defaults to a plain-text HTML wrap of `message` if omitted.

    Returns:
        {
            "email": {"status": str, "error": str},
            "slack": {"status": str, "error": str},
        }
    """
    if not body_html:
        body_html = f"<html><body><p>{message}</p></body></html>"

    # Load config once to decide which channels are live
    cfg = get_config(conn, org_id)
    if cfg is None:
        no_config = {"status": "failed", "error": "No notification config for org"}
        return {"email": no_config, "slack": no_config}

    email_result: Dict[str, Any] = {"status": "skipped", "error": ""}
    slack_result: Dict[str, Any] = {"status": "skipped", "error": ""}

    if cfg.get("smtp_enabled"):
        email_result = send_email(
            conn,
            org_id,
            subject=subject,
            body_html=body_html,
            event_type=event_type,
        )

    if cfg.get("slack_enabled"):
        slack_result = send_slack(
            conn,
            org_id,
            message=message,
            event_type=event_type,
            severity=severity,
            subject=subject,
        )

    return {"email": email_result, "slack": slack_result}


# ── Log query ─────────────────────────────────────────────────────────────────

def list_notification_log(
    conn: sqlite3.Connection,
    org_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return recent notification log entries for an organisation."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, channel, event_type, subject,
                   status, error, sent_at
            FROM notification_log
            WHERE organization_id = ?
            ORDER BY sent_at DESC
            LIMIT ?
            """,
            (org_id, limit),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
