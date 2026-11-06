"""Inbound ticket sync: Jira and ServiceNow status changes flow back to the linked remediation.

services/ticketing.py opens a Jira issue or a ServiceNow incident for a remediation and records the
link in ``auto_tickets``. This module is the return path. A ticket being resolved in Jira or
ServiceNow is a claim made by a person, not evidence, so it never closes anything by itself:

* resolved      -> the remediation moves to ``awaiting_verification`` and a rescan of its asset is
                   queued. db.auto_close_merged_remediations closes ``awaiting_verification`` (as it
                   always closed ``merged``) only when a scan of that asset comes back clean. That is
                   the one route to ``verified_closed``.
* reopened      -> a remediation this module moved to ``awaiting_verification`` goes back to the
                   status it had before. A ``verified_closed`` remediation is never downgraded (the
                   same rule update_remediation_status_by_pr_url follows): the reopen is recorded as a
                   conflict on the sync state and in the audit journal for a person to look at.
* closed without a fix (Won't Do, Duplicate, Canceled, Closed Incomplete...) -> recorded, and an
                   ``awaiting_verification`` it caused is undone, but it is never treated as a fix.

Authentication. Every inbound call is authenticated before the body is even parsed:

* Jira Cloud signs the body when the webhook has a secret: ``X-Hub-Signature: sha256=<hex>`` is
  HMAC-SHA256 of the raw UTF-8 body keyed with the secret (Atlassian, "Webhooks", secure admin
  webhooks). The method prefix is checked, so a future change of algorithm fails closed.
* ServiceNow has no native webhook signature. The documented business rule sends either
  ``Authorization: Bearer <token>`` (or ``X-Morrow-Token``) or ``X-Morrow-Signature: sha256=<hmac>``
  (hex, or the base64 that GlideCertificateEncryption.generateMac returns). A presented signature
  must verify; a token is compared as-is. Query-string credentials are never read.

All comparisons are hmac.compare_digest. Secrets are per organization and per provider, generated
here (never chosen by the caller), stored Fernet-sealed with the vault master key, and shown once.

Tenancy. The organization comes from the URL, and that organization's secret is the only one that
can authenticate the call. The handler then runs with the org context variable set to that
organization, so every read and write -- the ticket link lookup, the remediation read and update,
the audit entry, and on Postgres the RLS setting published by services/tenant_scope -- is scoped to
it. A ticket that is not linked to a remediation *in that organization* is refused as unknown, so a
webhook for one tenant cannot name another tenant's ticket or remediation even with a valid secret.

Replay. Each event gets a stable id (Jira changelog id, ServiceNow sys_id + sys_mod_count) that is
recorded under a unique constraint before it is applied: a second delivery is answered as a
duplicate and changes nothing. Events older than MORROW_TICKET_SYNC_MAX_EVENT_AGE_SECONDS, from
further than 10 minutes in the future, or older than the last event already applied to the same
ticket (out-of-order retries) are not applied either.

The ticket tables live in the main SQLite database alongside ticket_configs/auto_tickets (they are
SQLite-only, like the rest of services/ticketing.py); remediations and the audit log go through
db.py, which routes to Postgres when that backend is configured.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PROVIDERS = ("jira", "servicenow")
MAX_BODY_BYTES = 256 * 1024
FUTURE_SKEW_SECONDS = 600
RESCAN_DEBOUNCE_SECONDS = 600
AWAITING = "awaiting_verification"
VERIFIED = "verified_closed"

_ORG_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}:\d{1,5}$")

#: Jira resolutions that close an issue without fixing anything.
JIRA_NOT_FIXED_RESOLUTIONS = {
    "won't do", "won't fix", "wont do", "wont fix", "duplicate", "cannot reproduce",
    "declined", "incomplete", "rejected", "not a bug", "abandoned",
}
#: Status names treated as done when a payload carries no statusCategory (Jira Server/DC plugins).
JIRA_DONE_STATUS_NAMES = {"done", "resolved", "closed", "fixed"}

#: ServiceNow state codes per table: (resolved, closed-without-fix). Everything else is open.
SNOW_STATES: Dict[str, Tuple[set, set]] = {
    "incident": ({"6", "7"}, {"8"}),
    "sc_task": ({"3"}, {"4", "7"}),
    "change_task": ({"3"}, {"4", "7"}),
    "problem": ({"106", "107"}, set()),
}
SNOW_RESOLVED_LABELS = {"resolved", "closed", "closed complete", "complete", "fix applied"}
SNOW_NOT_FIXED_LABELS = {"canceled", "cancelled", "closed incomplete", "closed skipped"}
SNOW_NOT_FIXED_CLOSE_CODES = {
    "not solved (not reproducible)", "not solved (too costly)", "not solved", "duplicate",
    "canceled", "cancelled", "rejected",
}


class TicketSyncError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.detail = str(detail)


# ── Storage ──────────────────────────────────────────────────────────────────

_DDL = [
    """CREATE TABLE IF NOT EXISTS ticket_sync_settings (
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        secret_sealed TEXT NOT NULL DEFAULT '',
        secret_hint TEXT NOT NULL DEFAULT '',
        poll_enabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_event_at TEXT NOT NULL DEFAULT '',
        last_outcome TEXT NOT NULL DEFAULT '',
        last_polled_at TEXT NOT NULL DEFAULT '',
        rejected_auth_count INTEGER NOT NULL DEFAULT 0,
        rejected_unknown_count INTEGER NOT NULL DEFAULT 0,
        last_rejected_at TEXT NOT NULL DEFAULT '',
        last_rejected_reason TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (organization_id, provider)
    )""",
    """CREATE TABLE IF NOT EXISTS ticket_sync_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        event_id TEXT NOT NULL,
        ticket_id TEXT NOT NULL DEFAULT '',
        remediation_id INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'webhook',
        outcome TEXT NOT NULL DEFAULT 'processing',
        received_at TEXT NOT NULL,
        UNIQUE (organization_id, provider, event_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ticket_sync_events_received ON ticket_sync_events(organization_id, received_at)",
    """CREATE TABLE IF NOT EXISTS ticket_sync_state (
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        ticket_id TEXT NOT NULL,
        remediation_id INTEGER NOT NULL DEFAULT 0,
        external_state TEXT NOT NULL DEFAULT '',
        external_status TEXT NOT NULL DEFAULT '',
        last_event_id TEXT NOT NULL DEFAULT '',
        last_event_ts REAL NOT NULL DEFAULT 0,
        last_seq INTEGER NOT NULL DEFAULT -1,
        status_before TEXT NOT NULL DEFAULT '',
        last_outcome TEXT NOT NULL DEFAULT '',
        last_detail TEXT NOT NULL DEFAULT '',
        last_source TEXT NOT NULL DEFAULT '',
        last_synced_at TEXT NOT NULL DEFAULT '',
        rescan_scan_id TEXT NOT NULL DEFAULT '',
        rescan_queued_at REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (organization_id, provider, ticket_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ticket_sync_state_rem ON ticket_sync_state(organization_id, remediation_id)",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _connect() -> sqlite3.Connection:
    import db
    from services import ticketing

    conn = db.get_connection()
    conn.row_factory = sqlite3.Row
    if not db.schema_ensured("ticket_sync_tables"):
        ticketing.init_tables(conn)
        for ddl in _DDL:
            conn.execute(ddl)
        conn.commit()
        db.mark_schema_ensured("ticket_sync_tables")
    return conn


def _max_age_seconds() -> int:
    try:
        return max(300, int(os.getenv("MORROW_TICKET_SYNC_MAX_EVENT_AGE_SECONDS", "259200") or 259200))
    except ValueError:
        return 259200


def _check_provider(provider: str) -> str:
    p = str(provider or "").strip().lower()
    if p not in PROVIDERS:
        raise TicketSyncError(400, "provider must be jira or servicenow")
    return p


# ── Secrets ──────────────────────────────────────────────────────────────────

def _seal(plain: str) -> str:
    try:
        from vault_crypto import encrypt_secret

        return "fernet:" + encrypt_secret(plain)
    except Exception:
        raise TicketSyncError(503, "Ticket sync secrets are stored encrypted. Set MORROW_VAULT_MASTER_KEY "
                                   "(a Fernet key) before generating a webhook secret.") from None


def _unseal(sealed: str) -> str:
    text = str(sealed or "")
    if not text.startswith("fernet:"):
        return ""
    try:
        from vault_crypto import decrypt_secret

        return decrypt_secret(text[len("fernet:"):])
    except Exception:
        logger.warning("ticket sync secret could not be decrypted (vault key changed?)")
        return ""


def rotate_secret(org_id: str, provider: str) -> Dict[str, Any]:
    """Generate (or replace) the org's inbound secret for a provider. The plain value is returned once."""
    provider = _check_provider(provider)
    secret = secrets.token_urlsafe(32)
    sealed = _seal(secret)
    now = _now_iso()
    with closing(_connect()) as conn:
        conn.execute(
            """INSERT INTO ticket_sync_settings (organization_id, provider, secret_sealed, secret_hint, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, provider) DO UPDATE
               SET secret_sealed=excluded.secret_sealed, secret_hint=excluded.secret_hint, updated_at=excluded.updated_at""",
            (org_id, provider, sealed, secret[-4:], now, now),
        )
        conn.commit()
    return {"provider": provider, "secret": secret, "secret_hint": secret[-4:], "rotated_at": now}


def set_poll_enabled(org_id: str, provider: str, enabled: bool) -> Dict[str, Any]:
    provider = _check_provider(provider)
    now = _now_iso()
    with closing(_connect()) as conn:
        conn.execute(
            """INSERT INTO ticket_sync_settings (organization_id, provider, poll_enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, provider) DO UPDATE
               SET poll_enabled=excluded.poll_enabled, updated_at=excluded.updated_at""",
            (org_id, provider, 1 if enabled else 0, now, now),
        )
        conn.commit()
    return {"provider": provider, "poll_enabled": bool(enabled)}


def _settings_row(conn: sqlite3.Connection, org_id: str, provider: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM ticket_sync_settings WHERE organization_id=? AND provider=?", (org_id, provider)
    ).fetchone()


def _note_rejection(org_id: str, provider: str, column: str, reason: str) -> None:
    """Count a refused call on the org's settings row. Never writes the audit chain: the caller is unauthenticated."""
    if column not in ("rejected_auth_count", "rejected_unknown_count"):
        return
    try:
        with closing(_connect()) as conn:
            conn.execute(
                f"""UPDATE ticket_sync_settings SET {column}={column}+1, last_rejected_at=?, last_rejected_reason=?
                    WHERE organization_id=? AND provider=?""",  # nosec B608  # column is allowlisted to two counter names above; values are bound
                (_now_iso(), reason[:200], org_id, provider),
            )
            conn.commit()
    except Exception:
        logger.exception("ticket sync: could not record rejection")


def public_base_url(fallback: str = "") -> str:
    base = str(os.getenv("MORROW_PUBLIC_URL") or os.getenv("MORROW_APP_URL") or fallback or "").strip()
    return base.rstrip("/")


def webhook_path(provider: str, org_id: str) -> str:
    return f"/integrations/tickets/inbound/{provider}/{urllib.parse.quote(org_id, safe='')}"


def _servicenow_business_rule(url: str) -> str:
    return (
        "(function executeRule(current, previous) {\n"
        "  var r = new sn_ws.RESTMessageV2();\n"
        f"  r.setEndpoint('{url}');\n"
        "  r.setHttpMethod('POST');\n"
        "  r.setRequestHeader('Content-Type', 'application/json');\n"
        "  r.setRequestHeader('Authorization', 'Bearer ' + gs.getProperty('morrow.ticket_sync.token'));\n"
        "  r.setRequestBody(JSON.stringify({\n"
        "    table: current.getTableName(), sys_id: current.getUniqueValue(),\n"
        "    number: current.getValue('number'), state: current.getValue('state'),\n"
        "    state_label: current.getDisplayValue('state'), close_code: current.getValue('close_code'),\n"
        "    sys_updated_on: current.getValue('sys_updated_on'), sys_mod_count: current.getValue('sys_mod_count')\n"
        "  }));\n"
        "  r.executeAsync();\n"
        "})(current, previous);"
    )


def settings_view(org_id: str, base_url: str = "") -> Dict[str, Any]:
    """What the console shows: per provider, whether it is armed, the URL to paste, and how to set it up."""
    base = public_base_url(base_url)
    out: List[Dict[str, Any]] = []
    with closing(_connect()) as conn:
        for provider in PROVIDERS:
            row = _settings_row(conn, org_id, provider)
            url = base + webhook_path(provider, org_id)
            if provider == "jira":
                steps = [
                    "Jira settings > System > WebHooks > Create a WebHook.",
                    f"URL: {url}",
                    "Secret: paste the secret generated here (Jira signs each call with X-Hub-Signature).",
                    "Events: Issue > updated. JQL filter: labels = morrow (only Morrow tickets are accepted).",
                ]
            else:
                steps = [
                    "System Properties: add morrow.ticket_sync.token (type password2) holding the secret generated here.",
                    "Business Rule on incident (or sc_task): When = after, Update, condition 'State changes'.",
                    "Script: paste the business rule below. It sends the token as a bearer header, never in the URL.",
                    f"URL: {url}",
                ]
            out.append({
                "provider": provider,
                "webhook_url": url,
                "configured": bool(row and row["secret_sealed"]),
                "secret_hint": ("…" + row["secret_hint"]) if row and row["secret_hint"] else "",
                "poll_enabled": bool(row and row["poll_enabled"]),
                "last_event_at": row["last_event_at"] if row else "",
                "last_outcome": row["last_outcome"] if row else "",
                "last_polled_at": row["last_polled_at"] if row else "",
                "rejected_auth_count": int(row["rejected_auth_count"]) if row else 0,
                "rejected_unknown_count": int(row["rejected_unknown_count"]) if row else 0,
                "last_rejected_at": row["last_rejected_at"] if row else "",
                "last_rejected_reason": row["last_rejected_reason"] if row else "",
                "setup_steps": steps,
                "servicenow_business_rule": _servicenow_business_rule(url) if provider == "servicenow" else "",
            })
    return {"organization_id": org_id, "providers": out,
            "polling_available": poll_globally_enabled(),
            "rule": "A resolved ticket moves the remediation to awaiting verification; only a clean rescan closes it."}


# ── Authentication ───────────────────────────────────────────────────────────

def _hmac_sha256(secret: str, body: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()


def verify_jira(secret: str, body: bytes, headers: Dict[str, str]) -> bool:
    got = str(headers.get("x-hub-signature") or "").strip()
    method, _, signature = got.partition("=")
    if method.strip().lower() != "sha256" or not signature:
        return False
    expected = _hmac_sha256(secret, body).hex()
    return hmac.compare_digest(signature.strip().lower().encode("ascii", "replace"), expected.encode("ascii"))


def verify_servicenow(secret: str, body: bytes, headers: Dict[str, str]) -> bool:
    signature = str(headers.get("x-morrow-signature") or "").strip()
    if signature:
        method, _, value = signature.partition("=")
        if method.strip().lower() != "sha256" or not value:
            return False
        digest = _hmac_sha256(secret, body)
        value = value.strip()
        if hmac.compare_digest(value.lower().encode("ascii", "replace"), digest.hex().encode("ascii")):
            return True
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return False
        return hmac.compare_digest(decoded, digest)
    auth = str(headers.get("authorization") or "").strip()
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else str(headers.get("x-morrow-token") or "").strip()
    if not token:
        return False
    return hmac.compare_digest(token.encode("utf-8"), secret.encode("utf-8"))


# ── Normalizing provider payloads ────────────────────────────────────────────

def _val(value: Any) -> str:
    """ServiceNow sends either plain values or {"value", "display_value"} with sysparm_display_value=all."""
    if isinstance(value, dict):
        value = value.get("value", value.get("display_value", ""))
    return "" if value is None else str(value).strip()


def _display(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("display_value", value.get("value", ""))
    return "" if value is None else str(value).strip()


def _parse_ts(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    if re.fullmatch(r"\d{10,13}", text):
        return _parse_ts(int(text))
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # ServiceNow getValue() is UTC
            return dt.timestamp()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return 0.0


def normalize_jira(payload: Dict[str, Any], headers: Dict[str, str], body: bytes) -> Optional[Dict[str, Any]]:
    """None means "authenticated, but not an event this endpoint acts on"."""
    event = str(payload.get("webhookEvent") or "").strip()
    if event and event != "jira:issue_updated":
        return None
    issue = payload.get("issue") or {}
    if not isinstance(issue, dict) or not (issue.get("key") or issue.get("id")):
        raise TicketSyncError(400, "Jira payload has no issue")
    fields = issue.get("fields") or {}
    status = fields.get("status") or {}
    status_name = str(status.get("name") or "").strip()
    category = str(((status.get("statusCategory") or {}).get("key")) or "").strip().lower()
    resolution = fields.get("resolution") or {}
    resolution_name = str((resolution.get("name") if isinstance(resolution, dict) else resolution) or "").strip()
    done = category == "done" if category else status_name.lower() in JIRA_DONE_STATUS_NAMES
    if done:
        state = "closed_without_fix" if resolution_name.lower() in JIRA_NOT_FIXED_RESOLUTIONS else "resolved"
    else:
        state = "open"
    changelog = payload.get("changelog") or {}
    issue_id = str(issue.get("id") or "")
    if changelog.get("id"):
        event_id = f"jira:{issue_id}:{changelog.get('id')}"
    elif headers.get("x-atlassian-webhook-identifier"):
        event_id = f"jira-hook:{headers.get('x-atlassian-webhook-identifier')}"
    else:
        event_id = "jira-body:" + hashlib.sha256(body).hexdigest()
    return {
        "provider": "jira",
        "keys": [k for k in (str(issue.get("key") or ""), issue_id) if k],
        "ticket_label": str(issue.get("key") or issue_id),
        "external_state": state,
        "external_status": status_name + (f" ({resolution_name})" if resolution_name else ""),
        "event_id": event_id[:200],
        "ts": _parse_ts(payload.get("timestamp")),
        "seq": -1,
    }


def normalize_servicenow(payload: Dict[str, Any], headers: Dict[str, str], body: bytes) -> Optional[Dict[str, Any]]:
    record = payload.get("record") or payload.get("result") or payload
    if isinstance(record, list):
        record = record[0] if record else {}
    if not isinstance(record, dict):
        raise TicketSyncError(400, "ServiceNow payload has no record")
    sys_id = _val(record.get("sys_id"))
    number = _val(record.get("number"))
    if not (sys_id or number):
        raise TicketSyncError(400, "ServiceNow payload has no sys_id or number")
    table = (_val(record.get("table") or record.get("sys_class_name")) or "incident").lower()
    state_code = _val(record.get("state"))
    label = (_val(record.get("state_label")) or _display(record.get("state"))).lower()
    close_code = (_val(record.get("close_code")) or "").lower()
    resolved_codes, not_fixed_codes = SNOW_STATES.get(table, SNOW_STATES["incident"])
    if state_code in not_fixed_codes or label in SNOW_NOT_FIXED_LABELS:
        state = "closed_without_fix"
    elif state_code in resolved_codes or (not state_code.isdigit() and label in SNOW_RESOLVED_LABELS):
        state = "closed_without_fix" if close_code in SNOW_NOT_FIXED_CLOSE_CODES else "resolved"
    else:
        state = "open"
    seq_text = _val(record.get("sys_mod_count"))
    seq = int(seq_text) if seq_text.isdigit() else -1
    if payload.get("event_id"):
        event_id = f"snow-event:{payload.get('event_id')}"
    elif sys_id and seq >= 0:
        event_id = f"snow:{sys_id}:{seq}"
    else:
        event_id = "snow-body:" + hashlib.sha256(body).hexdigest()
    return {
        "provider": "servicenow",
        "keys": [k for k in (number, sys_id) if k],
        "ticket_label": number or sys_id,
        "external_state": state,
        "external_status": (_val(record.get("state_label")) or _display(record.get("state")) or state_code)
                           + (f" ({_val(record.get('close_code'))})" if close_code else ""),
        "event_id": str(event_id)[:200],
        "ts": _parse_ts(record.get("sys_updated_on")),
        "seq": seq,
    }


# ── Applying an event ────────────────────────────────────────────────────────

def _find_link(conn: sqlite3.Connection, org_id: str, provider: str, keys: List[str]) -> Optional[sqlite3.Row]:
    keys = [k for k in keys if k][:4]
    if not keys:
        return None
    marks = ",".join("?" for _ in keys)
    return conn.execute(
        f"""SELECT id, ticket_id, ticket_url, finding_ref, finding_type FROM auto_tickets
            WHERE organization_id=? AND provider=? AND finding_type='remediation'
              AND (ticket_id IN ({marks}) OR (external_id <> '' AND external_id IN ({marks})))
            ORDER BY id DESC LIMIT 1""",  # nosec B608  # only ? placeholder lists are interpolated; keys are bound
        (org_id, provider, *keys, *keys),
    ).fetchone()


def _is_scannable(asset_key: str) -> bool:
    return bool(_HOST_PORT_RE.match(str(asset_key or "")))


def _dispatch_rescan(org_id: str, asset_key: str) -> str:
    """Create a queued scan of one asset and hand it to Celery. Returns the scan id. Tests replace this."""
    import db
    from tasks import run_scan_task

    scan_id = str(uuid.uuid4())
    db.save_scan_row(scan_id=scan_id, status="queued", created_at=datetime.now(timezone.utc),
                     progress={"total": 1, "done": 0, "percent": 0}, error_text="", results=[], summary={})
    res = run_scan_task.delay(scan_id, [asset_key], org_id)
    db.update_scan_job(scan_id, job_id=str(res.id), job_state="PENDING")
    return scan_id


def _queue_rescan(org_id: str, asset_key: str, state: Optional[sqlite3.Row],
                  broker_ready: Callable[[], bool]) -> Dict[str, Any]:
    if not _is_scannable(asset_key):
        return {"queued": False, "reason": "asset is not a host:port endpoint; the next scan that covers it verifies"}
    if state is not None and state["rescan_queued_at"] and time.time() - float(state["rescan_queued_at"]) < RESCAN_DEBOUNCE_SECONDS:
        return {"queued": False, "reason": "a verification rescan was queued recently", "scan_id": state["rescan_scan_id"]}
    try:
        if not broker_ready():
            return {"queued": False, "reason": "task broker unreachable; the next scheduled scan verifies"}
        return {"queued": True, "scan_id": _dispatch_rescan(org_id, asset_key)}
    except Exception as exc:
        logger.warning("ticket sync: rescan dispatch failed: %s", exc)
        return {"queued": False, "reason": "rescan dispatch failed; the next scheduled scan verifies"}


def _decide(current: str, prior_external: str, status_before: str, new_external: str) -> Tuple[str, str, str]:
    """(next remediation status or '', outcome, status_before to keep). Pure, so the rules are testable."""
    if new_external == "resolved":
        if current == VERIFIED:
            return "", "already_verified", status_before
        if current in (AWAITING, "merged"):
            return "", "awaiting_verification", status_before
        return AWAITING, "awaiting_verification", current
    if new_external == "closed_without_fix":
        if current == AWAITING:
            return status_before or "pending", "closed_without_fix", ""
        return "", "closed_without_fix", status_before
    if new_external == "open":
        if current == AWAITING:
            return status_before or "pending", "reopened", ""
        if prior_external in ("resolved", "closed_without_fix"):
            if current == VERIFIED:
                return "", "reopen_conflict_verified_closed", status_before
            return "", "reopened_noted", status_before
        return "", "no_change", status_before
    return "", "no_change", status_before


def apply_event(org_id: str, event: Dict[str, Any], *, source: str = "webhook",
                broker_ready: Callable[[], bool] = lambda: False, check_age: bool = True) -> Dict[str, Any]:
    """Apply one normalized event inside org ``org_id``. Raises TicketSyncError for refusals."""
    import db

    provider = event["provider"]
    now = time.time()
    ts = float(event.get("ts") or 0)
    if check_age:
        if ts <= 0:
            raise TicketSyncError(400, "event has no timestamp")
        if ts < now - _max_age_seconds():
            raise TicketSyncError(400, "event is too old to apply")
        if ts > now + FUTURE_SKEW_SECONDS:
            raise TicketSyncError(400, "event timestamp is in the future")

    token = db.set_current_organization_id(org_id)
    try:
        with closing(_connect()) as conn:
            link = _find_link(conn, org_id, provider, event["keys"])
            if link is None:
                _note_rejection(org_id, provider, "rejected_unknown_count", f"unknown ticket {event['ticket_label'][:64]}")
                raise TicketSyncError(404, "ticket is not linked to a remediation in this organization")
            try:
                remediation_id = int(str(link["finding_ref"]).strip())
            except ValueError:
                raise TicketSyncError(404, "ticket is not linked to a remediation in this organization") from None
            ticket_id = str(link["ticket_id"])
            try:
                conn.execute(
                    """INSERT INTO ticket_sync_events (organization_id, provider, event_id, ticket_id, remediation_id, source, received_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (org_id, provider, event["event_id"], ticket_id, remediation_id, source, _now_iso()),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return {"ok": True, "duplicate": True, "event_id": event["event_id"], "ticket": ticket_id}

            try:
                result = _apply_locked(conn, org_id, provider, ticket_id, remediation_id, link, event, source, broker_ready)
            except BaseException:
                # Leave no dedupe row behind for an event that was not applied, so the sender's retry lands.
                conn.execute("DELETE FROM ticket_sync_events WHERE organization_id=? AND provider=? AND event_id=?",
                             (org_id, provider, event["event_id"]))
                conn.commit()
                raise
            conn.execute("UPDATE ticket_sync_events SET outcome=? WHERE organization_id=? AND provider=? AND event_id=?",
                         (result["outcome"], org_id, provider, event["event_id"]))
            conn.execute(
                """UPDATE ticket_sync_settings SET last_event_at=?, last_outcome=? WHERE organization_id=? AND provider=?""",
                (_now_iso(), result["outcome"], org_id, provider),
            )
            cutoff = datetime.fromtimestamp(now - 2 * _max_age_seconds(), timezone.utc).replace(microsecond=0)
            conn.execute("DELETE FROM ticket_sync_events WHERE organization_id=? AND received_at < ?",
                         (org_id, cutoff.isoformat().replace("+00:00", "Z")))
            conn.commit()
            return result
    finally:
        db.reset_current_organization_id(token)


def _apply_locked(conn: sqlite3.Connection, org_id: str, provider: str, ticket_id: str, remediation_id: int,
                  link: sqlite3.Row, event: Dict[str, Any], source: str,
                  broker_ready: Callable[[], bool]) -> Dict[str, Any]:
    import db

    state = conn.execute(
        "SELECT * FROM ticket_sync_state WHERE organization_id=? AND provider=? AND ticket_id=?",
        (org_id, provider, ticket_id),
    ).fetchone()
    ts = float(event.get("ts") or 0)
    seq = int(event.get("seq") if event.get("seq") is not None else -1)
    base = {"ok": True, "event_id": event["event_id"], "ticket": ticket_id, "remediation_id": remediation_id}
    if state is not None:
        if seq >= 0 and int(state["last_seq"]) >= 0 and seq <= int(state["last_seq"]):
            return {**base, "outcome": "stale", "applied": False}
        if seq < 0 and ts and float(state["last_event_ts"] or 0) and ts < float(state["last_event_ts"]):
            return {**base, "outcome": "stale", "applied": False}

    remediation = db.get_remediation(remediation_id)
    if not remediation:
        raise TicketSyncError(404, "ticket is not linked to a remediation in this organization")
    current = str(remediation.get("status") or "").strip().lower()
    prior_external = str(state["external_state"]) if state is not None else ""
    status_before = str(state["status_before"]) if state is not None else ""
    next_status, outcome, keep_before = _decide(current, prior_external, status_before, event["external_state"])

    label = f"{'Jira' if provider == 'jira' else 'ServiceNow'} {event['ticket_label']}"
    if next_status:
        note = (f"{label} resolved ({event['external_status']}); awaiting a clean verification scan"
                if next_status == AWAITING else f"{label} {outcome.replace('_', ' ')} ({event['external_status']})")
        db.update_remediation_status(remediation_id, next_status, review_note=note[:500])

    rescan: Dict[str, Any] = {}
    if outcome == "awaiting_verification":
        rescan = _queue_rescan(org_id, str(remediation.get("asset_key") or ""), state, broker_ready)

    detail = {"from_status": current, "to_status": next_status or current, "external_state": event["external_state"],
              "external_status": event["external_status"], "rescan": rescan}
    changed = bool(next_status) or event["external_state"] != prior_external or outcome.startswith("reopen")
    conn.execute(
        """INSERT INTO ticket_sync_state (organization_id, provider, ticket_id, remediation_id, external_state,
               external_status, last_event_id, last_event_ts, last_seq, status_before, last_outcome, last_detail,
               last_source, last_synced_at, rescan_scan_id, rescan_queued_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(organization_id, provider, ticket_id) DO UPDATE SET
               remediation_id=excluded.remediation_id, external_state=excluded.external_state,
               external_status=excluded.external_status, last_event_id=excluded.last_event_id,
               last_event_ts=MAX(ticket_sync_state.last_event_ts, excluded.last_event_ts),
               last_seq=MAX(ticket_sync_state.last_seq, excluded.last_seq), status_before=excluded.status_before,
               last_outcome=excluded.last_outcome, last_detail=excluded.last_detail, last_source=excluded.last_source,
               last_synced_at=excluded.last_synced_at,
               rescan_scan_id=CASE WHEN excluded.rescan_scan_id<>'' THEN excluded.rescan_scan_id ELSE ticket_sync_state.rescan_scan_id END,
               rescan_queued_at=CASE WHEN excluded.rescan_queued_at>0 THEN excluded.rescan_queued_at ELSE ticket_sync_state.rescan_queued_at END""",
        (org_id, provider, ticket_id, remediation_id, event["external_state"], event["external_status"][:200],
         event["event_id"], ts, seq, keep_before, outcome, json.dumps(detail, default=str)[:2000], source,
         _now_iso(), str(rescan.get("scan_id") or "") if rescan.get("queued") else "",
         time.time() if rescan.get("queued") else 0),
    )
    conn.commit()

    if changed:
        try:
            db.append_audit_log(
                actor_id=f"{provider}-{source}",
                actor_role="system",
                action=f"ticket_sync.{outcome}",
                resource_type="remediation",
                resource_id=str(remediation_id),
                decision="deny" if outcome == "reopen_conflict_verified_closed" else "allow",
                reason=f"{label} is now {event['external_status'] or event['external_state']}",
                details={"provider": provider, "ticket": ticket_id, "event_id": event["event_id"], "source": source, **detail},
            )
        except Exception:
            logger.exception("ticket sync: audit journal write failed")
    return {**base, "outcome": outcome, "applied": bool(next_status), **detail}


def handle_webhook(provider: str, org_id: str, headers: Dict[str, str], body: bytes,
                   broker_ready: Callable[[], bool] = lambda: False) -> Dict[str, Any]:
    """Authenticate, parse and apply one inbound delivery. ``headers`` keys must be lowercase."""
    provider = _check_provider(provider)
    org_id = str(org_id or "").strip()
    if len(body or b"") > MAX_BODY_BYTES:
        raise TicketSyncError(413, "payload too large")
    if not _ORG_RE.match(org_id):
        raise TicketSyncError(401, "invalid webhook credentials")
    with closing(_connect()) as conn:
        row = _settings_row(conn, org_id, provider)
    secret = _unseal(row["secret_sealed"]) if row is not None else ""
    if not secret:
        raise TicketSyncError(401, "invalid webhook credentials")
    verifier = verify_jira if provider == "jira" else verify_servicenow
    if not verifier(secret, body or b"", headers):
        _note_rejection(org_id, provider, "rejected_auth_count", "signature or token did not verify")
        raise TicketSyncError(401, "invalid webhook credentials")
    try:
        payload = json.loads((body or b"{}").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TicketSyncError(400, "invalid JSON payload") from None
    if not isinstance(payload, dict):
        raise TicketSyncError(400, "invalid JSON payload")
    normalizer = normalize_jira if provider == "jira" else normalize_servicenow
    event = normalizer(payload, headers, body or b"")
    if event is None:
        return {"ok": True, "ignored": True, "reason": "unsupported event"}
    return apply_event(org_id, event, source="webhook", broker_ready=broker_ready)


def remediation_sync_status(org_id: str, remediation_id: int) -> Dict[str, Any]:
    """The console's view of every ticket linked to one remediation, in the caller's org only."""
    with closing(_connect()) as conn:
        links = conn.execute(
            """SELECT a.provider, a.ticket_id, a.ticket_url, a.created_at,
                      s.external_state, s.external_status, s.last_outcome, s.last_synced_at, s.last_source,
                      s.last_detail, s.rescan_scan_id
               FROM auto_tickets a
               LEFT JOIN ticket_sync_state s
                 ON s.organization_id=a.organization_id AND s.provider=a.provider AND s.ticket_id=a.ticket_id
               WHERE a.organization_id=? AND a.finding_type='remediation' AND a.finding_ref=?
               ORDER BY a.id DESC LIMIT 20""",
            (org_id, str(int(remediation_id))),
        ).fetchall()
    items = []
    for r in links:
        items.append({
            "provider": r["provider"], "ticket_id": r["ticket_id"], "ticket_url": r["ticket_url"],
            "linked_at": r["created_at"], "external_state": r["external_state"] or "",
            "external_status": r["external_status"] or "", "last_outcome": r["last_outcome"] or "never synced",
            "last_synced_at": r["last_synced_at"] or "", "last_source": r["last_source"] or "",
            "verification_scan_id": r["rescan_scan_id"] or "",
        })
    return {"remediation_id": int(remediation_id), "tickets": items, "count": len(items)}


# ── Polling fallback (off by default) ────────────────────────────────────────

def poll_globally_enabled() -> bool:
    return str(os.getenv("MORROW_TICKET_SYNC_POLL", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _require_http_url(url: str) -> None:
    if urllib.parse.urlsplit(str(url or "")).scheme.lower() not in ("http", "https"):
        raise TicketSyncError(400, "ticket system URL refused: it must use http or https")


def _check_poll_url(url: str) -> str:
    if str(os.getenv("MORROW_TICKET_SYNC_ALLOW_PRIVATE_HOSTS", "")).strip().lower() in ("1", "true", "yes"):
        _require_http_url(url)
        return url
    from services.alert_routing import AlertRoutingError, validate_webhook_url

    try:
        return validate_webhook_url(url)
    except AlertRoutingError as exc:
        raise TicketSyncError(400, f"ticket system URL refused: {exc}") from None


def _http_get_json(url: str, headers: Dict[str, str], timeout: int = 15) -> Dict[str, Any]:
    _require_http_url(url)
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310  # scheme checked to be http/https just above
        return json.loads(resp.read(MAX_BODY_BYTES).decode("utf-8") or "{}")


def _basic(user: str, secret: str) -> Dict[str, str]:
    cred = base64.b64encode(f"{user}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {cred}", "Accept": "application/json"}


def _poll_jira(cfg: Dict[str, Any], ticket_id: str, fetch: Callable) -> Dict[str, Any]:
    base = _check_poll_url(str(cfg.get("base_url") or "").rstrip("/"))
    url = f"{base}/rest/api/3/issue/{urllib.parse.quote(ticket_id, safe='')}?fields=status,resolution,updated"
    issue = fetch(url, _basic(str(cfg.get("email") or ""), str(cfg.get("api_token") or "")))
    updated = str(((issue or {}).get("fields") or {}).get("updated") or "")
    event = normalize_jira({"webhookEvent": "jira:issue_updated", "issue": issue, "timestamp": _parse_ts(updated)},
                           {}, b"")
    event["event_id"] = f"jira-poll:{issue.get('id') or ticket_id}:{updated}"[:200]
    return event


def _poll_servicenow(cfg: Dict[str, Any], ticket_id: str, external_id: str, fetch: Callable) -> Dict[str, Any]:
    instance = str(cfg.get("instance") or cfg.get("base_url") or "").strip().rstrip("/")
    instance = instance if instance.startswith("http") else f"https://{instance}"
    instance = _check_poll_url(instance)
    table = re.sub(r"[^a-z_]", "", str(cfg.get("table") or "incident").lower()) or "incident"
    fields = "sys_id,number,state,close_code,sys_updated_on,sys_mod_count"
    if external_id:
        url = f"{instance}/api/now/table/{table}/{urllib.parse.quote(external_id, safe='')}?sysparm_fields={fields}"
    else:
        query = urllib.parse.quote(f"number={ticket_id}", safe="")
        url = f"{instance}/api/now/table/{table}?sysparm_query={query}&sysparm_limit=1&sysparm_fields={fields}"
    data = fetch(url, _basic(str(cfg.get("user") or cfg.get("email") or ""),
                             str(cfg.get("password") or cfg.get("api_token") or "")))
    record = (data or {}).get("result") or {}
    if isinstance(record, list):
        record = record[0] if record else {}
    record = {**record, "table": table}
    return normalize_servicenow({"record": record}, {}, json.dumps(record, sort_keys=True).encode())


def poll_org(org_id: str, *, fetch: Callable = _http_get_json, limit: int = 200,
             broker_ready: Callable[[], bool] = lambda: False) -> Dict[str, Any]:
    """Pull the current status of every open linked ticket for providers this org enabled polling for."""
    import db
    from services import ticketing

    stats = {"organization_id": org_id, "checked": 0, "applied": 0, "errors": 0}
    with closing(_connect()) as conn:
        providers = [r["provider"] for r in conn.execute(
            "SELECT provider FROM ticket_sync_settings WHERE organization_id=? AND poll_enabled=1", (org_id,)).fetchall()]
        configs = {p: ticketing.get_config(conn, org_id, p) for p in providers}
        marks = ",".join("?" for _ in providers)
        links = conn.execute(
            f"""SELECT a.provider, a.ticket_id, a.external_id, a.finding_ref FROM auto_tickets a
                WHERE a.organization_id=? AND a.finding_type='remediation' AND a.provider IN ({marks})
                ORDER BY a.id DESC LIMIT ?""",  # nosec B608  # only a ? placeholder list is interpolated; providers are bound
            (org_id, *providers, int(limit)),
        ).fetchall() if providers else []
    token = db.set_current_organization_id(org_id)
    try:
        for link in links:
            cfg = configs.get(link["provider"]) or {}
            if not cfg:
                continue
            try:
                remediation = db.get_remediation(int(link["finding_ref"]))
            except ValueError:
                continue
            if not remediation or str(remediation.get("status") or "").lower() == VERIFIED:
                continue
            stats["checked"] += 1
            try:
                if link["provider"] == "jira":
                    event = _poll_jira(cfg, link["ticket_id"], fetch)
                else:
                    event = _poll_servicenow(cfg, link["ticket_id"], link["external_id"], fetch)
                if event is None:
                    continue
                result = apply_event(org_id, event, source="poll", broker_ready=broker_ready, check_age=False)
                if result.get("applied"):
                    stats["applied"] += 1
            except (TicketSyncError, urllib.error.URLError, OSError, ValueError) as exc:
                stats["errors"] += 1
                logger.warning("ticket sync poll %s %s failed: %s", link["provider"], link["ticket_id"], exc)
    finally:
        db.reset_current_organization_id(token)
    with closing(_connect()) as conn:
        conn.execute("UPDATE ticket_sync_settings SET last_polled_at=? WHERE organization_id=? AND poll_enabled=1",
                     (_now_iso(), org_id))
        conn.commit()
    return stats


def poll_all(*, fetch: Callable = _http_get_json, broker_ready: Callable[[], bool] = lambda: True) -> Dict[str, Any]:
    """Celery beat entry point. Does nothing unless MORROW_TICKET_SYNC_POLL is on."""
    if not poll_globally_enabled():
        return {"skipped": True, "reason": "MORROW_TICKET_SYNC_POLL is off"}
    with closing(_connect()) as conn:
        orgs = [r["organization_id"] for r in conn.execute(
            "SELECT DISTINCT organization_id FROM ticket_sync_settings WHERE poll_enabled=1").fetchall()]
    results = [poll_org(o, fetch=fetch, broker_ready=broker_ready) for o in orgs]
    return {"organizations": len(orgs), "results": results}
