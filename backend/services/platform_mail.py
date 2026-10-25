"""Plain-text email from the platform itself (operator alerts, invitation emails).

services/smtp_notify.py sends email for one customer organization with that organization's stored
SMTP settings. Vendor-side mail (alert routing, "Email the invite") has no organization of its own,
so it is configured here:

  MORROW_SMTP_HOST, MORROW_SMTP_PORT (587), MORROW_SMTP_USER, MORROW_SMTP_PASSWORD, MORROW_SMTP_FROM,
  MORROW_SMTP_STARTTLS (1; set 0 only for a local relay on a trusted network)

or, when MORROW_SMTP_HOST is unset and MORROW_PLATFORM_SMTP_ORG_ID names an organization, the SMTP
settings that organization saved through /notifications/config (smtp_notify's notification_configs
row, used only when its smtp_enabled flag is on).

Nothing here logs the password or message bodies.
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s,;<>\"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253})\.[A-Za-z]{2,63}$")


def _truthy(value: str, default: bool = True) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on"}


def settings() -> Optional[Dict[str, Any]]:
    """The SMTP settings in effect, or None when platform email is not configured."""
    host = str(os.getenv("MORROW_SMTP_HOST") or "").strip()
    if host:
        try:
            port = int(str(os.getenv("MORROW_SMTP_PORT") or "587").strip() or 587)
        except ValueError:
            port = 587
        return {
            "source": "env",
            "host": host,
            "port": port,
            "user": str(os.getenv("MORROW_SMTP_USER") or "").strip(),
            "password": str(os.getenv("MORROW_SMTP_PASSWORD") or ""),
            "from": str(os.getenv("MORROW_SMTP_FROM") or os.getenv("MORROW_SMTP_USER") or "").strip(),
            "starttls": _truthy(os.getenv("MORROW_SMTP_STARTTLS", "1")),
        }
    org_id = str(os.getenv("MORROW_PLATFORM_SMTP_ORG_ID") or "").strip()
    if not org_id:
        return None
    try:
        from contextlib import closing

        from db import get_connection

        with closing(get_connection()) as conn:
            row = conn.execute(
                "SELECT smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, smtp_enabled "
                "FROM notification_configs WHERE organization_id = ?",
                (org_id,),
            ).fetchone()
    except Exception:
        return None
    if not row or not int(row[5] or 0) or not str(row[0] or "").strip():
        return None
    return {
        "source": "notification_configs",
        "host": str(row[0]).strip(),
        "port": int(row[1] or 587),
        "user": str(row[2] or ""),
        "password": str(row[3] or ""),
        "from": str(row[4] or row[2] or ""),
        "starttls": True,
    }


def configured() -> bool:
    return settings() is not None


def valid_address(address: str) -> bool:
    return bool(EMAIL_RE.match(str(address or "").strip()))


def send_text(recipients: List[str], subject: str, body: str, timeout: float = 20.0) -> Dict[str, Any]:
    """Send one plain-text message. Returns {"ok", "error"}; never raises."""
    cfg = settings()
    if not cfg:
        return {"ok": False, "error": "Email is not configured: set MORROW_SMTP_HOST (and MORROW_SMTP_FROM)."}
    to = [str(a).strip() for a in recipients or [] if valid_address(a)]
    if not to:
        return {"ok": False, "error": "No valid recipient address."}
    sender = cfg["from"] or "noreply@localhost"
    msg = EmailMessage()
    # Header injection: EmailMessage refuses CR/LF in headers, and the subject is flattened anyway.
    msg["Subject"] = re.sub(r"[\r\n]+", " ", str(subject or ""))[:250]
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=(sender.split("@", 1)[1] if "@" in sender else None))
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(str(body or ""))
    try:
        with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=timeout) as server:
            server.ehlo()
            if cfg["starttls"]:
                server.starttls()
                server.ehlo()
            if cfg["user"] and cfg["password"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(msg, from_addr=sender, to_addrs=to)
        return {"ok": True, "error": ""}
    except smtplib.SMTPAuthenticationError:
        return {"ok": False, "error": "SMTP authentication failed."}
    except smtplib.SMTPRecipientsRefused:
        return {"ok": False, "error": "The SMTP server refused the recipients."}
    except smtplib.SMTPException as exc:
        return {"ok": False, "error": f"SMTP error: {exc.__class__.__name__}"}
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"Could not reach the SMTP server: {exc.__class__.__name__}"}
