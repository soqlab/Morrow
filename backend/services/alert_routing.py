"""Alert routing: send the platform's operator notifications to the vendor's own on-call channels.

GET /platform/notifications derives items from live state (SLA breaches, failed-login spikes,
maintenance, go-live blockers, incidents, abuse, expiring API keys, feedback, autopatches). This
module delivers those items outside the admin portal.

Storage (feature store: SQLite locally, Postgres when the feature store is on Postgres)
  platform_alert_channels    one row per destination. The target (webhook URL, PagerDuty routing key)
                             is sealed with vault_crypto (Fernet, MORROW_VAULT_MASTER_KEY); email
                             recipient lists are not secrets and are stored as JSON. API responses
                             carry only target_hint.
  platform_alert_ledger      one row per (channel, notification id): first/last sent, send count,
                             open/resolved. This is the dedupe ledger.
  platform_alert_deliveries  every attempt: event, status, HTTP status, error, latency.
  platform_alert_pending_resolves  a PagerDuty resolve that deleting or disabling a channel could not
                             send, with the sealed routing key, until the dispatcher gets it through or
                             gives up after MORROW_ALERT_RESOLVE_MAX_ATTEMPTS tries.
  platform_alert_dispatcher  a single row: the lease that stops two API replicas dispatching the same
                             tick, and the last run's outcome for GET /platform/jobs.

Dispatch (run_once, every MORROW_ALERT_DISPATCH_INTERVAL_SECONDS, default 60)
  * An item matching a channel (min_severity, optional kinds filter, quiet hours) and absent from
    the ledger, or resolved there, is sent ("trigger").
  * An item still open after MORROW_ALERT_RENOTIFY_HOURS (default 24) is sent again ("renotify").
  * An item that disappears is marked resolved; PagerDuty gets a resolve event with
    dedup_key = notification id. Nothing is resolved from a partial snapshot: a source that failed
    to load, or a list truncated by the notifications cap, resolves nothing.
  * Each channel sends at most MORROW_ALERT_RATE_CAP (20) messages per MORROW_ALERT_RATE_WINDOW_MINUTES
    (10). When more are due, the last slot becomes one digest message listing the rest.
  * A failed send is logged and retried on the next tick. run_once never raises.
  * Deleting or disabling a PagerDuty channel resolves every incident it still has open before the
    routing key is discarded; a resolve that fails is queued and retried by later ticks.

Outbound HTTP
  Webhook URLs must be https and every address the host resolves to must be public (no private,
  loopback, link-local, multicast, reserved or unspecified ranges). The check is repeated at send
  time and the connection is pinned to the checked address (TLS still verifies the hostname), so DNS
  rebinding cannot redirect a send inward. Redirects are not followed. PagerDuty uses the fixed
  Events API v2 endpoint through services/alerting.py. Email goes through services/platform_mail.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

logger = logging.getLogger(__name__)

CHANNEL_KINDS = ("slack_webhook", "email", "pagerduty", "generic_webhook")
SECRET_KINDS = frozenset({"slack_webhook", "pagerduty", "generic_webhook"})
SEVERITY_RANK = {"info": 0, "warn": 1, "critical": 2}
# Notification kinds emitted by services/platform_analytics.notifications, and the collector metric
# that produces each (a failed metric must not resolve that kind's items). Derived from the analytics
# catalogue so the emitter, the channel kind filter and the admin portal cannot drift apart.
from services.platform_analytics import NOTIFICATION_KIND_CATALOG  # noqa: E402

NOTIFICATION_KINDS = {kind: metric for kind, (metric, _label) in NOTIFICATION_KIND_CATALOG.items()}
NOTIFICATION_KIND_LABELS = {kind: label for kind, (_metric, label) in NOTIFICATION_KIND_CATALOG.items()}
MAX_CHANNELS = 50
MAX_EMAIL_RECIPIENTS = 20
#: The only TCP port an outbound webhook may name. https is already enforced; without this the
#: guard validated https://8.8.8.8:22/hook and every other port on every public address.
ALLOWED_WEBHOOK_PORTS = frozenset({443})
PD_SEVERITY = {"critical": "critical", "warn": "warning", "info": "info"}
_PD_KEY_RE = re.compile(r"^[A-Za-z0-9]{20,64}$")
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_ID_RE = re.compile(r"^[a-f0-9]{16}$")


class AlertRoutingError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# ── Settings ─────────────────────────────────────────────────────────────────


def _env_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def renotify_hours() -> float:
    return _env_float("MORROW_ALERT_RENOTIFY_HOURS", 24.0, 0.25, 24.0 * 30)


def rate_cap() -> int:
    return int(_env_float("MORROW_ALERT_RATE_CAP", 20, 2, 1000))


def rate_window_minutes() -> float:
    return _env_float("MORROW_ALERT_RATE_WINDOW_MINUTES", 10, 1, 24 * 60)


def interval_seconds() -> float:
    return _env_float("MORROW_ALERT_DISPATCH_INTERVAL_SECONDS", 60, 10, 3600)


def retention_days() -> float:
    return _env_float("MORROW_ALERT_DELIVERY_RETENTION_DAYS", 30, 1, 3650)


def resolve_max_attempts() -> int:
    """How often the dispatcher retries a resolve that a delete or a disable could not send."""
    return int(_env_float("MORROW_ALERT_RESOLVE_MAX_ATTEMPTS", 10, 1, 100))


def dispatch_enabled() -> bool:
    return str(os.getenv("MORROW_ALERT_DISPATCH_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def public_settings() -> Dict[str, Any]:
    return {"renotify_hours": renotify_hours(), "rate_cap": rate_cap(), "rate_window_minutes": rate_window_minutes(),
            "interval_seconds": interval_seconds(), "dispatch_enabled": dispatch_enabled(),
            "delivery_retention_days": retention_days()}


# ── Time ─────────────────────────────────────────────────────────────────────


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ── Tables ───────────────────────────────────────────────────────────────────

_TABLES_READY: set = set()
_TABLES_LOCK = threading.Lock()


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS platform_alert_channels (
                    id             TEXT PRIMARY KEY,
                    kind           TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    target_sealed  TEXT NOT NULL,
                    target_hint    TEXT NOT NULL DEFAULT '',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    min_severity   TEXT NOT NULL DEFAULT 'warn',
                    kinds_json     TEXT NOT NULL DEFAULT '[]',
                    quiet_hours_json TEXT NOT NULL DEFAULT '',
                    created_by     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL,
                    updated_by     TEXT NOT NULL DEFAULT '',
                    updated_at     TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS platform_alert_ledger (
                    channel_id      TEXT NOT NULL,
                    notification_id TEXT NOT NULL,
                    kind            TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    via_digest      INTEGER NOT NULL DEFAULT 0,
                    send_count      INTEGER NOT NULL DEFAULT 0,
                    first_sent_at   TEXT NOT NULL,
                    last_sent_at    TEXT NOT NULL,
                    resolved_at     TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (channel_id, notification_id)
                );
                CREATE TABLE IF NOT EXISTS platform_alert_deliveries (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id      TEXT NOT NULL,
                    channel_name    TEXT NOT NULL DEFAULT '',
                    channel_kind    TEXT NOT NULL DEFAULT '',
                    notification_id TEXT NOT NULL DEFAULT '',
                    event           TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL,
                    http_status     INTEGER,
                    error           TEXT NOT NULL DEFAULT '',
                    latency_ms      INTEGER,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alert_deliveries_channel_created
                    ON platform_alert_deliveries (channel_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_alert_deliveries_created
                    ON platform_alert_deliveries (created_at);
                CREATE TABLE IF NOT EXISTS platform_alert_pending_resolves (
                    channel_id      TEXT NOT NULL,
                    notification_id TEXT NOT NULL,
                    channel_name    TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL DEFAULT '',
                    kind            TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT '',
                    target_sealed   TEXT NOT NULL,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    last_error      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL,
                    next_attempt_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (channel_id, notification_id)
                );
                CREATE TABLE IF NOT EXISTS platform_alert_dispatcher (
                    id               TEXT PRIMARY KEY,
                    holder           TEXT NOT NULL DEFAULT '',
                    lease_expires_at TEXT NOT NULL DEFAULT '',
                    last_run_at      TEXT NOT NULL DEFAULT '',
                    last_status      TEXT NOT NULL DEFAULT '',
                    last_error       TEXT NOT NULL DEFAULT '',
                    last_summary     TEXT NOT NULL DEFAULT '',
                    runs_total       INTEGER NOT NULL DEFAULT 0,
                    updated_at       TEXT NOT NULL DEFAULT ''
                );
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


# ── Secrets ──────────────────────────────────────────────────────────────────


def seal(plain: str) -> str:
    try:
        from vault_crypto import encrypt_secret

        return "fernet:" + encrypt_secret(plain)
    except Exception:
        raise AlertRoutingError(
            503, "Alert channel secrets are stored encrypted. Set MORROW_VAULT_MASTER_KEY (a Fernet key) to configure "
                 "Slack, PagerDuty or webhook channels.") from None


def unseal(sealed: str) -> str:
    text = str(sealed or "")
    if text.startswith("plain:"):
        return text[len("plain:"):]
    if text.startswith("fernet:"):
        from vault_crypto import decrypt_secret

        return decrypt_secret(text[len("fernet:"):])
    raise ValueError("Unknown sealed target format")


def vault_configured() -> bool:
    try:
        seal("probe")
        return True
    except AlertRoutingError:
        return False


# ── Validation ───────────────────────────────────────────────────────────────
#
# The SSRF guard below (ip_is_public / resolve_host / public_addresses /
# validate_webhook_url) is original work written for this project on top of the
# standard library's `ipaddress` and `socket` modules only. It is not derived from
# any third-party SSRF library or published snippet. Two parts are deliberate and
# easy to lose in a refactor:
#
#   * IPv4-mapped and 6to4 addresses are unwrapped before the public/private test,
#     because ::ffff:127.0.0.1 and 2002:7f00:1::/48 both reach loopback while
#     passing a naive is_private check on the outer IPv6 form.
#   * The address that was checked is the address that gets connected to. Checking
#     the hostname and then handing the hostname to the HTTP client re-resolves it,
#     which lets DNS rebinding point the second lookup inward; pinning closes that
#     window. TLS still verifies against the hostname, so pinning does not weaken
#     certificate validation.
#
# Covered by test_alert_routing.py and by test_security_review_findings.py
# (test_the_webhook_ssrf_guard_pins_the_port, finding 14).


def ip_is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or (ip.sixtofour if ip.sixtofour else None)
        if mapped is not None:
            ip = mapped
    return bool(ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                      or ip.is_reserved or ip.is_unspecified))


def resolve_host(host: str, port: int) -> List[str]:
    """Every address the host resolves to (tests replace this; no DNS in the suite)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def public_addresses(host: str, port: int) -> List[str]:
    try:
        addresses = resolve_host(host, port)
    except (OSError, UnicodeError):
        raise AlertRoutingError(400, f"The webhook host {host} does not resolve.") from None
    if not addresses:
        raise AlertRoutingError(400, f"The webhook host {host} does not resolve.")
    blocked = [a for a in addresses if not ip_is_public(a)]
    if blocked:
        raise AlertRoutingError(400, "Webhook URLs must point at a public address; private, loopback, link-local and "
                                     "reserved addresses are refused.")
    return addresses


def validate_webhook_url(url: Any, resolve: bool = True) -> str:
    text = str(url or "").strip()
    if not text or len(text) > 2048 or any(ch in text for ch in "\r\n\t "):
        raise AlertRoutingError(400, "Enter a webhook URL (https, at most 2048 characters).")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise AlertRoutingError(400, "The webhook URL is not a valid URL.") from None
    if parts.scheme.lower() != "https":
        raise AlertRoutingError(400, "Webhook URLs must use https.")
    if not parts.hostname:
        raise AlertRoutingError(400, "The webhook URL has no host.")
    if parts.username or parts.password:
        raise AlertRoutingError(400, "Webhook URLs must not carry credentials before the host.")
    # The port was parsed and then never constrained, so https://8.8.8.8:22/hook validated. The
    # scheme is already pinned to https, and every webhook receiver worth the name listens on 443;
    # leaving the port free turns an outbound webhook into a port scanner of the public internet
    # (and of anything the egress path can reach that a DNS check cannot see), with the connect
    # result readable from the delivery error.
    if port is not None and int(port) not in ALLOWED_WEBHOOK_PORTS:
        raise AlertRoutingError(
            400,
            "Webhook URLs must use port 443. A non-standard port turns an outbound webhook into a "
            "port probe, and no hosted webhook receiver needs one.",
        )
    if resolve:
        public_addresses(parts.hostname, port or 443)
    return text


def parse_emails(value: Any) -> List[str]:
    from services import platform_mail

    raw = value if isinstance(value, list) else re.split(r"[,;\s]+", str(value or ""))
    out: List[str] = []
    for item in raw:
        address = str(item or "").strip().lower()
        if not address:
            continue
        if not platform_mail.valid_address(address):
            raise AlertRoutingError(400, f"'{address[:80]}' is not a valid email address.")
        if address not in out:
            out.append(address)
    if not out:
        raise AlertRoutingError(400, "Enter at least one recipient email address.")
    if len(out) > MAX_EMAIL_RECIPIENTS:
        raise AlertRoutingError(400, f"An email channel takes at most {MAX_EMAIL_RECIPIENTS} recipients.")
    return out


def target_hint(kind: str, plain: str) -> str:
    if kind == "email":
        try:
            return ", ".join(json.loads(plain))
        except (ValueError, TypeError):
            return ""
    if kind == "pagerduty":
        return "routing key …" + plain[-4:]
    try:
        parts = urlsplit(plain)
        tail = plain.rstrip("/")[-4:]
        return f"https://{parts.hostname}/…{tail}"
    except ValueError:
        return "…"


def normalize_target(kind: str, target: Any) -> str:
    if kind == "email":
        return json.dumps(parse_emails(target))
    if kind == "pagerduty":
        key = str(target or "").strip()
        if not _PD_KEY_RE.match(key):
            raise AlertRoutingError(400, "Enter the PagerDuty Events API v2 integration (routing) key: 32 letters and digits.")
        return key
    if isinstance(target, list):
        raise AlertRoutingError(400, "Enter one webhook URL.")
    return validate_webhook_url(target)


def normalize_kinds(kinds: Any) -> List[str]:
    if kinds in (None, "", []):
        return []
    if not isinstance(kinds, list):
        raise AlertRoutingError(400, "kinds must be a list of notification kinds.")
    out = []
    for k in kinds:
        key = str(k or "").strip()
        if key not in NOTIFICATION_KINDS:
            raise AlertRoutingError(400, f"Unknown notification kind '{key[:60]}'. Known: {', '.join(NOTIFICATION_KINDS)}.")
        if key not in out:
            out.append(key)
    return out


def normalize_quiet_hours(value: Any) -> Optional[Dict[str, Any]]:
    if value in (None, "", {}):
        return None
    if not isinstance(value, dict):
        raise AlertRoutingError(400, "quiet_hours must be an object with start, end and timezone.")
    start, end = str(value.get("start") or "").strip(), str(value.get("end") or "").strip()
    if not _HHMM_RE.match(start) or not _HHMM_RE.match(end):
        raise AlertRoutingError(400, "quiet_hours start and end must be HH:MM (24-hour).")
    if start == end:
        raise AlertRoutingError(400, "quiet_hours start and end must differ.")
    tz = str(value.get("timezone") or "UTC").strip() or "UTC"
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(tz)
    except Exception:
        raise AlertRoutingError(400, f"Unknown time zone '{tz[:60]}'. Use an IANA name such as Europe/London or UTC.") from None
    return {"start": start, "end": end, "timezone": tz, "allow_critical": bool(value.get("allow_critical", True))}


def in_quiet_hours(quiet: Optional[Dict[str, Any]], now: datetime) -> bool:
    if not quiet:
        return False
    try:
        from zoneinfo import ZoneInfo

        local = now.astimezone(ZoneInfo(quiet.get("timezone") or "UTC"))
    except Exception:
        local = now
    minutes = local.hour * 60 + local.minute
    sh, sm = (int(x) for x in quiet["start"].split(":"))
    eh, em = (int(x) for x in quiet["end"].split(":"))
    start, end = sh * 60 + sm, eh * 60 + em
    return start <= minutes < end if start < end else (minutes >= start or minutes < end)


# ── Channels ─────────────────────────────────────────────────────────────────

_CHANNEL_COLUMNS = ("id, kind, name, target_sealed, target_hint, enabled, min_severity, kinds_json, quiet_hours_json, "
                    "created_by, created_at, updated_by, updated_at")


def _row_dict(row: Any) -> Dict[str, Any]:
    keys = ["id", "kind", "name", "target_sealed", "target_hint", "enabled", "min_severity", "kinds_json",
            "quiet_hours_json", "created_by", "created_at", "updated_by", "updated_at"]
    out = {k: row[i] for i, k in enumerate(keys)}
    out["enabled"] = bool(int(out["enabled"] or 0))
    try:
        out["kinds"] = json.loads(out.pop("kinds_json") or "[]")
    except ValueError:
        out["kinds"] = []
    try:
        out["quiet_hours"] = json.loads(out.pop("quiet_hours_json") or "null")
    except ValueError:
        out["quiet_hours"] = None
    return out


def public_channel(channel: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": channel["id"], "kind": channel["kind"], "name": channel["name"], "target_hint": channel.get("target_hint") or "",
        "target_encrypted": str(channel.get("target_sealed") or "").startswith("fernet:"),
        "enabled": channel["enabled"], "min_severity": channel["min_severity"], "kinds": channel.get("kinds") or [],
        "quiet_hours": channel.get("quiet_hours"), "created_by": channel.get("created_by") or "",
        "created_at": channel.get("created_at") or "", "updated_by": channel.get("updated_by") or "",
        "updated_at": channel.get("updated_at") or "",
    }


def list_channels(enabled_only: bool = False) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(f"SELECT {_CHANNEL_COLUMNS} FROM platform_alert_channels ORDER BY created_at, id").fetchall()
    channels = [_row_dict(r) for r in rows]
    return [c for c in channels if c["enabled"]] if enabled_only else channels


def get_channel(channel_id: str) -> Optional[Dict[str, Any]]:
    cid = str(channel_id or "").strip().lower()
    if not _ID_RE.match(cid):
        return None
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(f"SELECT {_CHANNEL_COLUMNS} FROM platform_alert_channels WHERE id = ?", (cid,)).fetchone()
    return _row_dict(row) if row else None


def _sealed_for(kind: str, plain: str) -> str:
    return seal(plain) if kind in SECRET_KINDS else "plain:" + plain


def create_channel(data: Dict[str, Any], actor: str) -> Dict[str, Any]:
    kind = str(data.get("kind") or "").strip()
    if kind not in CHANNEL_KINDS:
        raise AlertRoutingError(400, f"kind must be one of: {', '.join(CHANNEL_KINDS)}")
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 80:
        raise AlertRoutingError(400, "Enter a channel name of at most 80 characters.")
    severity = str(data.get("min_severity") or "warn").strip()
    if severity not in SEVERITY_RANK:
        raise AlertRoutingError(400, "min_severity must be critical, warn or info.")
    kinds = normalize_kinds(data.get("kinds"))
    quiet = normalize_quiet_hours(data.get("quiet_hours"))
    plain = normalize_target(kind, data.get("target"))
    sealed = _sealed_for(kind, plain)
    init_tables()
    now = iso(now_utc())
    channel_id = secrets.token_hex(8)
    with feature_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM platform_alert_channels").fetchone()[0]
        if int(count or 0) >= MAX_CHANNELS:
            raise AlertRoutingError(409, f"At most {MAX_CHANNELS} alert channels can be configured.")
        conn.execute(
            "INSERT INTO platform_alert_channels (id, kind, name, target_sealed, target_hint, enabled, min_severity, kinds_json, "
            "quiet_hours_json, created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (channel_id, kind, name, sealed, target_hint(kind, plain), 1 if data.get("enabled", True) else 0, severity,
             json.dumps(kinds), json.dumps(quiet) if quiet else "", str(actor or "")[:160], now, str(actor or "")[:160], now),
        )
        conn.commit()
    return get_channel(channel_id) or {}


def update_channel(channel_id: str, data: Dict[str, Any], actor: str,
                   resolved: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], List[str]]:
    """resolved: filled with the resolve summary when this update disables a PagerDuty channel that still has
    open incidents (nothing would send their resolve while the channel is off)."""
    current = get_channel(channel_id)
    if not current:
        raise AlertRoutingError(404, "Alert channel not found.")
    changed: List[str] = []
    fields: Dict[str, Any] = {}
    if data.get("name") is not None:
        name = str(data["name"]).strip()
        if not name or len(name) > 80:
            raise AlertRoutingError(400, "Enter a channel name of at most 80 characters.")
        fields["name"] = name
    if data.get("enabled") is not None:
        fields["enabled"] = 1 if data["enabled"] else 0
    if data.get("min_severity") is not None:
        if data["min_severity"] not in SEVERITY_RANK:
            raise AlertRoutingError(400, "min_severity must be critical, warn or info.")
        fields["min_severity"] = data["min_severity"]
    if "kinds" in data and data.get("kinds") is not None:
        fields["kinds_json"] = json.dumps(normalize_kinds(data.get("kinds")))
    if "quiet_hours" in data:
        quiet = normalize_quiet_hours(data.get("quiet_hours"))
        fields["quiet_hours_json"] = json.dumps(quiet) if quiet else ""
    target = data.get("target")
    if target not in (None, "", []):
        plain = normalize_target(current["kind"], target)
        fields["target_sealed"] = _sealed_for(current["kind"], plain)
        fields["target_hint"] = target_hint(current["kind"], plain)
    if not fields:
        return current, []
    changed = sorted("target" if k in ("target_sealed", "target_hint") else k.replace("_json", "") for k in fields)
    changed = sorted(set(changed))
    fields["updated_by"] = str(actor or "")[:160]
    fields["updated_at"] = iso(now_utc())
    assignments = ", ".join(f"{k} = ?" for k in fields)
    with feature_conn() as conn:
        conn.execute(f"UPDATE platform_alert_channels SET {assignments} WHERE id = ?", (*fields.values(), current["id"]))
        conn.commit()
    if current["kind"] == "pagerduty" and current["enabled"] and fields.get("enabled") == 0:
        # The channel is off from here on, so its open incidents are resolved now, with the key they were raised
        # with (a target change in the same update applies to later alerts). Failures go to the dispatcher.
        outcome = resolve_open_incidents(current, queue_failures=True)
        if resolved is not None:
            resolved.update(outcome)
        if outcome["failed"]:
            now = iso(now_utc())
            with feature_conn() as conn:
                for entry in outcome["items"]:
                    if not entry["ok"]:
                        conn.execute("UPDATE platform_alert_ledger SET status = 'resolved', resolved_at = ? WHERE channel_id = ? "
                                     "AND notification_id = ?", (now, current["id"], entry["notification_id"]))
                conn.commit()
    return get_channel(current["id"]) or {}, changed


def delete_channel(channel_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Delete a channel. A PagerDuty channel first resolves every incident it still has open (the ledger holds
    them, dedup_key = notification id); a resolve that could not be sent is queued for the dispatcher before the
    routing key is discarded, so the incident is not left open by the deletion."""
    current = get_channel(channel_id)
    if not current:
        raise AlertRoutingError(404, "Alert channel not found.")
    now = now or now_utc()
    with feature_conn() as conn:
        open_items = int(conn.execute("SELECT COUNT(*) FROM platform_alert_ledger WHERE channel_id = ? AND status = 'open'",
                                      (current["id"],)).fetchone()[0] or 0)
        if current["kind"] == "pagerduty" and open_items:
            # Stop a concurrent dispatcher tick from re-notifying while the incidents are being resolved.
            conn.execute("UPDATE platform_alert_channels SET enabled = 0 WHERE id = ?", (current["id"],))
            conn.commit()
    incidents = resolve_open_incidents(current, now, queue_failures=True)
    with feature_conn() as conn:
        conn.execute("DELETE FROM platform_alert_ledger WHERE channel_id = ?", (current["id"],))
        conn.execute("DELETE FROM platform_alert_channels WHERE id = ?", (current["id"],))
        conn.commit()
    return {"channel": current, "open_items": open_items, "incidents": incidents}


# ── Resolving open PagerDuty incidents ───────────────────────────────────────


def _queue_resolve(conn: Any, channel: Dict[str, Any], entry: Dict[str, Any], now: datetime) -> None:
    """Keep what the dispatcher needs to retry one resolve: the sealed routing key and the dedup key."""
    values = (channel["id"], str(entry.get("notification_id") or "")[:300], str(channel.get("name") or "")[:80],
              str(entry.get("title") or "")[:300], str(entry.get("kind") or ""), str(entry.get("severity") or ""),
              str(channel.get("target_sealed") or ""), str(entry.get("error") or "")[:500], iso(now), iso(now))
    try:
        with atomic(conn):
            conn.execute("INSERT INTO platform_alert_pending_resolves (channel_id, notification_id, channel_name, title, kind, "
                         "severity, target_sealed, attempts, last_error, created_at, next_attempt_at) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)", values)
    except INTEGRITY_ERRORS:
        conn.execute("UPDATE platform_alert_pending_resolves SET attempts = attempts + 1, last_error = ?, target_sealed = ?, "
                     "next_attempt_at = ? WHERE channel_id = ? AND notification_id = ?",
                     (str(entry.get("error") or "")[:500], str(channel.get("target_sealed") or ""), iso(now),
                      channel["id"], str(entry.get("notification_id") or "")[:300]))
    conn.commit()


def _drop_pending_resolve(conn: Any, channel_id: str, notification_id: str) -> None:
    conn.execute("DELETE FROM platform_alert_pending_resolves WHERE channel_id = ? AND notification_id = ?",
                 (channel_id, str(notification_id)[:300]))


def pending_resolves(channel_id: str = "") -> List[Dict[str, Any]]:
    init_tables()
    keys = ["channel_id", "notification_id", "channel_name", "title", "kind", "severity", "attempts", "last_error",
            "created_at", "next_attempt_at"]
    sql = ("SELECT channel_id, notification_id, channel_name, title, kind, severity, attempts, last_error, created_at, "
           "next_attempt_at FROM platform_alert_pending_resolves")
    params: List[Any] = []
    if channel_id:
        sql += " WHERE channel_id = ?"
        params.append(channel_id)
    with feature_conn() as conn:
        rows = conn.execute(sql + " ORDER BY created_at, notification_id", params).fetchall()
    return [{k: r[i] for i, k in enumerate(keys)} for r in rows]


def resolve_open_incidents(channel: Dict[str, Any], now: Optional[datetime] = None, queue_failures: bool = False) -> Dict[str, Any]:
    """Send a PagerDuty resolve for every incident this channel triggered and has not resolved yet.

    Each open ledger row is one incident (dedup_key = notification id); rows sent inside a digest share one
    PagerDuty incident whose dedup key is not stored, so they are reported instead of resolved. Successful
    resolves mark the ledger row resolved. With queue_failures the failures are kept in
    platform_alert_pending_resolves, with the sealed routing key, for the dispatcher to retry.
    """
    now = now or now_utc()
    summary: Dict[str, Any] = {"open": 0, "resolved": 0, "failed": 0, "digest_items": 0, "retrying": 0, "items": []}
    if channel.get("kind") != "pagerduty":
        return summary
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT notification_id, kind, severity, title, via_digest FROM platform_alert_ledger "
                            "WHERE channel_id = ? AND status = 'open' ORDER BY first_sent_at, notification_id",
                            (channel["id"],)).fetchall()
    summary["open"] = len(rows)
    summary["digest_items"] = sum(1 for r in rows if int(r[4] or 0))
    unseal_error = ""
    plain = ""
    try:
        plain = unseal(channel["target_sealed"])
    except Exception:
        unseal_error = ("The stored routing key could not be decrypted; check MORROW_VAULT_MASTER_KEY. The resolve is retried "
                        "by the dispatcher.")
    for notification_id, kind, severity, title, via_digest in rows:
        if int(via_digest or 0):
            continue
        item = {"id": notification_id, "kind": kind, "severity": severity, "title": title}
        if unseal_error:
            result: Dict[str, Any] = {"ok": False, "http_status": None, "error": unseal_error, "latency_ms": 0}
        else:
            result = send(channel, plain, "resolve", [item])
        record_delivery(channel, "resolve", "sent" if result["ok"] else "failed", item, result.get("http_status"),
                        result.get("error") or "", result.get("latency_ms"), now)
        entry = {"notification_id": notification_id, "title": title, "kind": kind, "severity": severity,
                 "ok": bool(result["ok"]), "http_status": result.get("http_status"), "error": result.get("error") or ""}
        summary["items"].append(entry)
        with feature_conn() as conn:
            if result["ok"]:
                conn.execute("UPDATE platform_alert_ledger SET status = 'resolved', resolved_at = ? WHERE channel_id = ? "
                             "AND notification_id = ?", (iso(now), channel["id"], notification_id))
                _drop_pending_resolve(conn, channel["id"], notification_id)
                conn.commit()
                summary["resolved"] += 1
            else:
                summary["failed"] += 1
                if queue_failures:
                    _queue_resolve(conn, channel, entry, now)
                    summary["retrying"] += 1
    return summary


def resolve_note(summary: Dict[str, Any]) -> str:
    """One sentence per outcome for the API response and the admin portal."""
    if not summary.get("open"):
        return ""
    parts = []
    if summary.get("resolved"):
        parts.append(f"Resolved {summary['resolved']} open PagerDuty incident(s) raised by this channel.")
    if summary.get("retrying"):
        parts.append(f"{summary['retrying']} could not be resolved just now and are retried by the dispatcher "
                     f"(up to {resolve_max_attempts()} attempts); the delivery log shows every attempt.")
    elif summary.get("failed"):
        parts.append(f"{summary['failed']} could not be resolved; resolve them in PagerDuty.")
    if summary.get("digest_items"):
        parts.append(f"{summary['digest_items']} alert(s) were sent inside a digest message and share one PagerDuty "
                     "incident, which has to be resolved in PagerDuty.")
    return " ".join(parts)


def retry_pending_resolves(now: Optional[datetime] = None, summary: Optional[Dict[str, int]] = None) -> Dict[str, int]:
    """Resend the resolves a delete or a disable could not deliver. Given up on after resolve_max_attempts()
    tries, with the last failure written to the delivery log so an operator can close the incident by hand."""
    now = now or now_utc()
    out = {"retried": 0, "resolved": 0, "failed": 0, "gave_up": 0}
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT channel_id, notification_id, channel_name, title, kind, severity, target_sealed, attempts "
                            "FROM platform_alert_pending_resolves WHERE next_attempt_at <= ? ORDER BY created_at, notification_id",
                            (iso(now),)).fetchall()
    limit = resolve_max_attempts()
    for channel_id, notification_id, channel_name, title, kind, severity, sealed, attempts in rows:
        channel = {"id": channel_id, "name": channel_name, "kind": "pagerduty", "target_sealed": sealed}
        item = {"id": notification_id, "kind": kind, "severity": severity, "title": title}
        out["retried"] += 1
        try:
            plain = unseal(sealed)
            result = send(channel, plain, "resolve", [item])
        except Exception:
            result = {"ok": False, "http_status": None, "error": "The stored routing key could not be decrypted; check "
                                                                 "MORROW_VAULT_MASTER_KEY.", "latency_ms": 0}
        tries = int(attempts or 0) + 1
        done = bool(result["ok"]) or tries >= limit
        error = result.get("error") or ""
        if not result["ok"] and tries >= limit:
            error = (f"{error} Gave up after {tries} attempt(s): resolve this incident in PagerDuty." if error
                     else f"Gave up after {tries} attempt(s): resolve this incident in PagerDuty.")
        record_delivery(channel, "resolve", "sent" if result["ok"] else "failed", item, result.get("http_status"), error,
                        result.get("latency_ms"), now)
        with feature_conn() as conn:
            if done:
                _drop_pending_resolve(conn, channel_id, notification_id)
            else:
                backoff = min(6 * 3600.0, interval_seconds() * (2 ** min(tries, 12)))
                conn.execute("UPDATE platform_alert_pending_resolves SET attempts = ?, last_error = ?, next_attempt_at = ? "
                             "WHERE channel_id = ? AND notification_id = ?",
                             (tries, str(error)[:500], iso(now + timedelta(seconds=backoff)), channel_id, notification_id))
            conn.commit()
        if result["ok"]:
            out["resolved"] += 1
        elif tries >= limit:
            out["gave_up"] += 1
        else:
            out["failed"] += 1
    if summary is not None:
        summary["resolved"] = int(summary.get("resolved", 0)) + out["resolved"]
        summary["failed"] = int(summary.get("failed", 0)) + out["failed"] + out["gave_up"]
    return out


# ── Deliveries ───────────────────────────────────────────────────────────────


def record_delivery(channel: Dict[str, Any], event: str, status: str, notification: Optional[Dict[str, Any]] = None,
                    http_status: Optional[int] = None, error: str = "", latency_ms: Optional[int] = None,
                    now: Optional[datetime] = None, title: str = "") -> None:
    note = notification or {}
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO platform_alert_deliveries (channel_id, channel_name, channel_kind, notification_id, event, severity, title, "
            "status, http_status, error, latency_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (channel["id"], str(channel.get("name") or "")[:80], channel.get("kind") or "", str(note.get("id") or "")[:300], event,
             str(note.get("severity") or ""), str(title or note.get("title") or "")[:300], status,
             int(http_status) if http_status is not None else None, _scrub(error)[:500],
             int(latency_ms) if latency_ms is not None else None, iso(now or now_utc())),
        )
        conn.commit()


def list_deliveries(channel_id: str = "", limit: int = 100, status: str = "", event: str = "") -> List[Dict[str, Any]]:
    init_tables()
    where, params = [], []
    if channel_id:
        where.append("channel_id = ?")
        params.append(channel_id)
    if status:
        where.append("status = ?")
        params.append(status)
    if event:
        where.append("event = ?")
        params.append(event)
    sql = ("SELECT id, channel_id, channel_name, channel_kind, notification_id, event, severity, title, status, http_status, "
           "error, latency_ms, created_at FROM platform_alert_deliveries")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 100), 500)))
    keys = ["id", "channel_id", "channel_name", "channel_kind", "notification_id", "event", "severity", "title", "status",
            "http_status", "error", "latency_ms", "created_at"]
    with feature_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [{k: r[i] for i, k in enumerate(keys)} for r in rows]


_SCRUB_RE = re.compile(r"https?://\S+|[A-Za-z0-9]{32,}")


def _scrub(text: Any) -> str:
    """Errors must not echo a webhook URL or routing key into the delivery log."""
    return _SCRUB_RE.sub("[redacted]", str(text or ""))


# ── Transport ────────────────────────────────────────────────────────────────


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to an address that was checked, while TLS verifies the certificate for the hostname."""

    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:  # pragma: no cover - exercised only against a real network
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def open_connection(host: str, port: int, address: str, timeout: float) -> http.client.HTTPSConnection:
    return _PinnedHTTPSConnection(host, port, address, timeout)


def post_json(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """POST JSON to a validated https webhook. Returns {ok, http_status, error, body}; never raises."""
    try:
        validate_webhook_url(url, resolve=False)
        parts = urlsplit(url)
        port = parts.port or 443
        address = public_addresses(parts.hostname or "", port)[0]
    except AlertRoutingError as exc:
        return {"ok": False, "http_status": None, "error": exc.detail, "body": ""}
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    body = json.dumps(payload, default=str).encode("utf-8")
    conn = None
    try:
        conn = open_connection(parts.hostname or "", port, address, timeout)
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json", "User-Agent": "morrow-alerts/1",
                                                        "Content-Length": str(len(body))})
        resp = conn.getresponse()
        text = resp.read(2048).decode("utf-8", errors="replace")
        ok = 200 <= resp.status < 300
        return {"ok": ok, "http_status": resp.status, "body": text[:300],
                "error": "" if ok else (f"HTTP {resp.status} (redirects are not followed)" if 300 <= resp.status < 400
                                        else f"HTTP {resp.status}")}
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"ok": False, "http_status": None, "error": f"Connection failed: {exc.__class__.__name__}", "body": ""}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _link(base_url: str, route: str) -> str:
    base = str(base_url or "").rstrip("/")
    if not base:
        return ""
    return f"{base}/vendor-admin/{route or '#/notifications'}"


def compose(event: str, items: List[Dict[str, Any]], base_url: str = "", test: bool = False) -> Dict[str, Any]:
    """Subject/text/severity for one message. event: trigger|renotify|digest|test."""
    if test:
        subject = "[TEST] Morrow alert routing test"
        text = ("This is a test message from Morrow alert routing. No action is needed; it confirms this channel "
                "can receive operator alerts.")
        return {"subject": subject, "text": text, "severity": "info", "link": _link(base_url, "#/alert-routing")}
    if event == "digest":
        worst = max((SEVERITY_RANK.get(i.get("severity"), 0) for i in items), default=0)
        severity = next(k for k, v in SEVERITY_RANK.items() if v == worst)
        lines = [f"- [{str(i.get('severity') or '').upper()}] {i.get('title')}" for i in items[:25]]
        if len(items) > 25:
            lines.append(f"- …and {len(items) - 25} more")
        return {"subject": f"Morrow: {len(items)} more alerts (rate limit reached, digest)",
                "text": "This channel reached its message limit, so these alerts are grouped:\n" + "\n".join(lines),
                "severity": severity, "link": _link(base_url, "#/notifications")}
    item = items[0]
    prefix = "Still open: " if event == "renotify" else ""
    return {"subject": f"{prefix}[{str(item.get('severity') or '').upper()}] {item.get('title')}",
            "text": str(item.get("detail") or ""), "severity": item.get("severity") or "info",
            "link": _link(base_url, item.get("route") or "")}


def send(channel: Dict[str, Any], plain: str, event: str, items: List[Dict[str, Any]], base_url: str = "",
         test: bool = False) -> Dict[str, Any]:
    """Deliver one message. Returns {ok, http_status, error, latency_ms}; never raises."""
    started = time.monotonic()
    message = compose(event, items, base_url, test)
    kind = channel["kind"]
    result: Dict[str, Any]
    try:
        if kind == "slack_webhook":
            from services.smtp_notify import _build_slack_payload

            text = message["text"] + (f"\n<{message['link']}|Open in the admin portal>" if message["link"] else "")
            payload = _build_slack_payload(message["subject"], text, "test" if test else event, message["severity"])
            payload["text"] = message["subject"]
            result = post_json(plain, payload)
        elif kind == "generic_webhook":
            payload = {"source": "morrow", "type": "platform.alert", "event": "test" if test else event, "test": bool(test),
                       "subject": message["subject"], "text": message["text"], "severity": message["severity"],
                       "link": message["link"] or None, "sent_at": iso(now_utc()),
                       "notifications": [] if test else [{k: i.get(k) for k in ("id", "severity", "kind", "title", "detail",
                                                                                 "created_at", "route")} for i in items]}
            result = post_json(plain, payload)
        elif kind == "email":
            from services import platform_mail

            body = message["text"] + (f"\n\nOpen in the admin portal: {message['link']}" if message["link"] else "") + \
                "\n\n-- \nSent by Morrow alert routing. Change or mute this channel under Operations > Alert routing."
            sent = platform_mail.send_text(json.loads(plain), "[Morrow] " + message["subject"], body)
            result = {"ok": bool(sent.get("ok")), "http_status": None, "error": sent.get("error") or ""}
        elif kind == "pagerduty":
            from services import alerting

            if event == "resolve":
                pd = alerting.resolve_pagerduty_incident(plain, str(items[0].get("id")))
            else:
                dedup = f"pq-alert-test-{channel['id']}" if test else (
                    "pq-digest-" + hashlib.sha256("|".join(sorted(str(i.get("id")) for i in items)).encode()).hexdigest()[:16]
                    if event == "digest" else str(items[0].get("id")))
                pd = alerting.send_pagerduty_alert(
                    routing_key=plain, summary=message["subject"], severity=PD_SEVERITY.get(message["severity"], "warning"),
                    source="morrow-platform", dedup_key=dedup,
                    details={"detail": message["text"], "event": event, "test": bool(test),
                             "notification_ids": [str(i.get("id")) for i in items]},
                    component="platform", group="operations", class_=("test" if test else str(items[0].get("kind") or event)),
                    links=[{"url": message["link"], "label": "Open in the admin portal"}] if message["link"] else None)
                if test and pd.get("ok"):
                    alerting.resolve_pagerduty_incident(plain, dedup)
            status = pd.get("status")
            result = {"ok": bool(pd.get("ok")), "http_status": int(status) if isinstance(status, int) else None,
                      "error": "" if pd.get("ok") else str(pd.get("error") or "PagerDuty rejected the event")}
        else:
            result = {"ok": False, "http_status": None, "error": f"Unsupported channel kind {kind}"}
    except Exception as exc:  # a sender bug must be logged as a failed attempt, never raised
        result = {"ok": False, "http_status": None, "error": f"Send failed: {exc.__class__.__name__}"}
    result["latency_ms"] = int((time.monotonic() - started) * 1000)
    result["error"] = _scrub(result.get("error"))
    return result


def test_send(channel_id: str, base_url: str = "") -> Dict[str, Any]:
    channel = get_channel(channel_id)
    if not channel:
        raise AlertRoutingError(404, "Alert channel not found.")
    now = now_utc()
    with feature_conn() as conn:
        recent = conn.execute("SELECT COUNT(*) FROM platform_alert_deliveries WHERE channel_id = ? AND event = 'test' AND created_at >= ?",
                              (channel["id"], iso(now - timedelta(minutes=1)))).fetchone()[0]
    if int(recent or 0) >= 5:
        raise AlertRoutingError(429, "At most 5 test messages per minute per channel.")
    try:
        plain = unseal(channel["target_sealed"])
    except Exception:
        result = {"ok": False, "http_status": None, "error": "The stored target could not be decrypted; check MORROW_VAULT_MASTER_KEY or "
                                                             "re-enter the target.", "latency_ms": 0}
    else:
        result = send(channel, plain, "test", [], base_url, test=True)
    record_delivery(channel, "test", "sent" if result["ok"] else "failed", None, result.get("http_status"), result.get("error") or "",
                    result.get("latency_ms"), now, title="[TEST] alert routing test")
    return {"ok": bool(result["ok"]), "http_status": result.get("http_status"), "error": result.get("error") or "",
            "latency_ms": result.get("latency_ms"), "channel": public_channel(channel)}


# ── Dispatcher ───────────────────────────────────────────────────────────────

_STATE_LOCK = threading.Lock()
STATE: Dict[str, Any] = {"last_run_at": None, "last_status": "idle", "last_error": None, "last_summary": {}, "runs": 0,
                         "started_at": None}
_HOLDER = f"{socket.gethostname()[:40]}:{os.getpid()}:{secrets.token_hex(3)}"
_LOOP: Dict[str, Any] = {"task": None}


def _acquire_lease(now: datetime, ttl_seconds: float) -> bool:
    expires = iso(now + timedelta(seconds=ttl_seconds))
    with feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute("INSERT INTO platform_alert_dispatcher (id, holder, lease_expires_at, updated_at) VALUES (?, ?, ?, ?)",
                             ("dispatcher", _HOLDER, expires, iso(now)))
            conn.commit()
            return True
        except INTEGRITY_ERRORS:
            pass
        cur = conn.execute("UPDATE platform_alert_dispatcher SET holder = ?, lease_expires_at = ?, updated_at = ? "
                           "WHERE id = 'dispatcher' AND (holder = ? OR lease_expires_at < ?)",
                           (_HOLDER, expires, iso(now), _HOLDER, iso(now)))
        conn.commit()
        return int(cur.rowcount or 0) == 1


def _save_run(now: datetime, status: str, error: Optional[str], summary: Dict[str, Any]) -> None:
    with _STATE_LOCK:
        STATE.update(last_run_at=iso(now), last_status=status, last_error=error, last_summary=summary, runs=STATE["runs"] + 1)
    try:
        with feature_conn() as conn:
            conn.execute("UPDATE platform_alert_dispatcher SET last_run_at = ?, last_status = ?, last_error = ?, last_summary = ?, "
                         "runs_total = runs_total + 1, updated_at = ? WHERE id = 'dispatcher'",
                         (iso(now), status, str(error or "")[:500], json.dumps(summary)[:2000], iso(now)))
            conn.commit()
    except Exception:
        pass


def _matches(channel: Dict[str, Any], item: Dict[str, Any]) -> bool:
    if SEVERITY_RANK.get(str(item.get("severity")), 0) < SEVERITY_RANK.get(channel.get("min_severity") or "warn", 1):
        return False
    kinds = channel.get("kinds") or []
    return not kinds or str(item.get("kind")) in kinds


def _ledger(conn: Any, channel_id: str) -> Dict[str, Dict[str, Any]]:
    keys = ["notification_id", "kind", "severity", "title", "status", "via_digest", "send_count", "first_sent_at", "last_sent_at"]
    rows = conn.execute("SELECT notification_id, kind, severity, title, status, via_digest, send_count, first_sent_at, last_sent_at "
                        "FROM platform_alert_ledger WHERE channel_id = ?", (channel_id,)).fetchall()
    return {r[0]: {k: r[i] for i, k in enumerate(keys)} for r in rows}


def _mark_sent(conn: Any, channel_id: str, item: Dict[str, Any], now: datetime, via_digest: bool) -> None:
    stamp = iso(now)
    try:
        with atomic(conn):
            conn.execute("INSERT INTO platform_alert_ledger (channel_id, notification_id, kind, severity, title, status, via_digest, "
                         "send_count, first_sent_at, last_sent_at, resolved_at) VALUES (?, ?, ?, ?, ?, 'open', ?, 1, ?, ?, '')",
                         (channel_id, str(item["id"])[:300], str(item.get("kind") or ""), str(item.get("severity") or ""),
                          str(item.get("title") or "")[:300], 1 if via_digest else 0, stamp, stamp))
    except INTEGRITY_ERRORS:
        conn.execute("UPDATE platform_alert_ledger SET status = 'open', via_digest = ?, send_count = send_count + 1, last_sent_at = ?, "
                     "resolved_at = '', severity = ?, title = ? WHERE channel_id = ? AND notification_id = ?",
                     (1 if via_digest else 0, stamp, str(item.get("severity") or ""), str(item.get("title") or "")[:300],
                      channel_id, str(item["id"])[:300]))
    # This incident is open again, so a resolve queued while the channel was disabled must not close it.
    _drop_pending_resolve(conn, channel_id, str(item["id"]))
    conn.commit()


def _sent_in_window(conn: Any, channel_id: str, now: datetime) -> int:
    since = iso(now - timedelta(minutes=rate_window_minutes()))
    row = conn.execute("SELECT COUNT(*) FROM platform_alert_deliveries WHERE channel_id = ? AND created_at >= ? "
                       "AND event IN ('trigger', 'renotify', 'digest')", (channel_id, since)).fetchone()
    return int(row[0] or 0)


def _dispatch_channel(channel: Dict[str, Any], items: List[Dict[str, Any]], current_ids: set, resolvable_kinds: Optional[set],
                      now: datetime, base_url: str, summary: Dict[str, int]) -> None:
    try:
        plain = unseal(channel["target_sealed"])
    except Exception:
        summary["failed"] += 1
        with feature_conn() as conn:
            since = iso(now - timedelta(minutes=rate_window_minutes()))
            seen = conn.execute("SELECT COUNT(*) FROM platform_alert_deliveries WHERE channel_id = ? AND event = 'config_error' "
                                "AND created_at >= ?", (channel["id"], since)).fetchone()[0]
        if not int(seen or 0):
            record_delivery(channel, "config_error", "failed", None, None,
                            "The stored target could not be decrypted; check MORROW_VAULT_MASTER_KEY or re-enter the target.", 0, now)
        return
    renotify_before = iso(now - timedelta(hours=renotify_hours()))
    quiet = in_quiet_hours(channel.get("quiet_hours"), now)
    allow_critical = bool((channel.get("quiet_hours") or {}).get("allow_critical", True))
    with feature_conn() as conn:
        ledger = _ledger(conn, channel["id"])
        used = _sent_in_window(conn, channel["id"], now)
    pending: List[Tuple[Dict[str, Any], str]] = []
    for item in items:
        if not item.get("id") or not _matches(channel, item):
            continue
        if quiet and not (allow_critical and item.get("severity") == "critical"):
            summary["quiet"] += 1
            continue
        row = ledger.get(str(item["id"]))
        if row is None or row["status"] != "open":
            pending.append((item, "trigger"))
        elif str(row["last_sent_at"] or "") <= renotify_before:
            pending.append((item, "renotify"))
    # Most severe first, newest first within a severity: those get the individual messages under the cap.
    pending.sort(key=lambda p: str(p[0].get("created_at") or ""), reverse=True)
    pending.sort(key=lambda p: -SEVERITY_RANK.get(str(p[0].get("severity")), 0))

    remaining = rate_cap() - used
    if pending and remaining <= 0:
        summary["rate_limited"] += len(pending)
        with feature_conn() as conn:
            since = iso(now - timedelta(minutes=rate_window_minutes()))
            seen = conn.execute("SELECT COUNT(*) FROM platform_alert_deliveries WHERE channel_id = ? AND event = 'rate_limited' "
                                "AND created_at >= ?", (channel["id"], since)).fetchone()[0]
        if not int(seen or 0):
            record_delivery(channel, "rate_limited", "suppressed", None, None,
                            f"{len(pending)} alert(s) held: {rate_cap()} messages per {rate_window_minutes():g} minutes reached. "
                            "They are sent when the window frees.", 0, now, title="Rate limit reached")
        pending = []
    individual, digest = (pending, []) if len(pending) <= remaining else (pending[:max(0, remaining - 1)], pending[max(0, remaining - 1):])

    for item, event in individual:
        result = send(channel, plain, event, [item], base_url)
        record_delivery(channel, event, "sent" if result["ok"] else "failed", item, result.get("http_status"), result.get("error") or "",
                        result.get("latency_ms"), now)
        if result["ok"]:
            summary["sent"] += 1
            with feature_conn() as conn:
                _mark_sent(conn, channel["id"], item, now, via_digest=False)
        else:
            summary["failed"] += 1
    if digest:
        batch = [item for item, _ in digest]
        result = send(channel, plain, "digest", batch, base_url)
        record_delivery(channel, "digest", "sent" if result["ok"] else "failed", {"id": f"digest:{len(batch)}", "severity": compose("digest", batch)["severity"]},
                        result.get("http_status"), result.get("error") or "", result.get("latency_ms"), now,
                        title=f"Digest of {len(batch)} alerts")
        if result["ok"]:
            summary["sent"] += 1
            summary["digested"] += len(batch)
            with feature_conn() as conn:
                for item in batch:
                    _mark_sent(conn, channel["id"], item, now, via_digest=True)
        else:
            summary["failed"] += 1

    if resolvable_kinds is None:
        return
    for notification_id, row in ledger.items():
        if row["status"] != "open" or notification_id in current_ids:
            continue
        if NOTIFICATION_KINDS.get(str(row["kind"]), str(row["kind"])) not in resolvable_kinds:
            continue
        item = {"id": notification_id, "kind": row["kind"], "severity": row["severity"], "title": row["title"]}
        if channel["kind"] == "pagerduty" and not int(row["via_digest"] or 0):
            result = send(channel, plain, "resolve", [item], base_url)
            record_delivery(channel, "resolve", "sent" if result["ok"] else "failed", item, result.get("http_status"),
                            result.get("error") or "", result.get("latency_ms"), now)
            if not result["ok"]:
                summary["failed"] += 1
                continue
        summary["resolved"] += 1
        with feature_conn() as conn:
            conn.execute("UPDATE platform_alert_ledger SET status = 'resolved', resolved_at = ? WHERE channel_id = ? AND notification_id = ?",
                         (iso(now), channel["id"], notification_id))
            conn.commit()


def run_once(snapshot: Callable[[], Dict[str, Any]], base_url: str = "", now: Optional[datetime] = None) -> Dict[str, Any]:
    """One dispatch pass. Never raises: every failure is recorded in the run state and the delivery log.

    Runs under the platform scope (services/tenant_scope). The snapshot it dispatches is the vendor's
    fleet-wide alert view, assembled across every customer, and the pass runs on a background task
    with no tenant context; taking the privilege explicitly here keeps it out of the request paths
    and puts every pass in the escape-hatch ledger.
    """
    from services.tenant_scope import platform_scope

    with platform_scope("alert dispatcher: cross-tenant alert pass"):
        return _run_once_unscoped(snapshot, base_url=base_url, now=now)


def _run_once_unscoped(snapshot: Callable[[], Dict[str, Any]], base_url: str = "", now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or now_utc()
    summary = {"channels": 0, "items": 0, "sent": 0, "failed": 0, "resolved": 0, "digested": 0, "rate_limited": 0, "quiet": 0}
    try:
        init_tables()
        channels = list_channels(enabled_only=True)
        summary["channels"] = len(channels)
        if not _acquire_lease(now, max(120.0, interval_seconds() * 3)):
            return {"status": "skipped", "detail": "Another API process holds the dispatcher lease.", **summary}
        # Resolves a delete or a disable could not send: retried here, even when no channel is configured any more.
        try:
            retry_pending_resolves(now, summary)
        except Exception:
            logger.warning("[alert-routing] pending resolve retry failed")
        if not channels:
            _save_run(now, "idle", None, summary)
            return {"status": "idle", **summary}
        data = snapshot() or {}
        items = [i for i in (data.get("items") or []) if isinstance(i, dict) and i.get("id")]
        summary["items"] = len(items)
        current_ids = {str(i["id"]) for i in items}
        unavailable = {str(u.get("metric")) for u in (data.get("unavailable") or []) if isinstance(u, dict)}
        total = int(((data.get("counts") or {}).get("total")) or len(items))
        # Resolve only from a complete snapshot: a failed source or a truncated list is not "cleared".
        resolvable = None if total > len(items) else set(NOTIFICATION_KINDS.values()) - unavailable
        errors = []
        for channel in channels:
            try:
                _dispatch_channel(channel, items, current_ids, resolvable, now, base_url, summary)
            except Exception as exc:
                errors.append(f"{channel.get('name')}: {exc.__class__.__name__}")
                logger.warning("[alert-routing] channel dispatch failed: %s", exc.__class__.__name__)
        try:
            with feature_conn() as conn:
                conn.execute("DELETE FROM platform_alert_deliveries WHERE created_at < ?", (iso(now - timedelta(days=retention_days())),))
                conn.execute("DELETE FROM platform_alert_ledger WHERE status = 'resolved' AND resolved_at < ?",
                             (iso(now - timedelta(days=retention_days())),))
                conn.commit()
        except Exception:
            pass
        status = "error" if errors or summary["failed"] else "ok"
        error = "; ".join(errors) if errors else (f"{summary['failed']} delivery attempt(s) failed; see the delivery log." if summary["failed"] else None)
        _save_run(now, status, error, summary)
        return {"status": status, "error": error, **summary}
    except Exception as exc:
        logger.warning("[alert-routing] dispatch run failed: %s", exc.__class__.__name__)
        try:
            _save_run(now, "error", f"Dispatch run failed: {exc.__class__.__name__}", summary)
        except Exception:
            pass
        return {"status": "error", "error": exc.__class__.__name__, **summary}


def job_state(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Dispatcher status for GET /platform/jobs."""
    now = now or now_utc()
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT last_run_at, last_status, last_error, runs_total, holder, lease_expires_at "
                           "FROM platform_alert_dispatcher WHERE id = 'dispatcher'").fetchone()
        channels = conn.execute("SELECT COUNT(*), SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) FROM platform_alert_channels").fetchone()
        day = conn.execute("SELECT COUNT(*), SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) FROM platform_alert_deliveries "
                           "WHERE created_at >= ? AND event <> 'test'", (iso(now - timedelta(hours=24)),)).fetchone()
        waiting = int(conn.execute("SELECT COUNT(*) FROM platform_alert_pending_resolves").fetchone()[0] or 0)
    task = _LOOP.get("task")
    running = bool(task is not None and not task.done())
    last_run = row[0] if row else None
    status = (row[1] if row and row[1] else "idle") if dispatch_enabled() else "disabled"
    nxt = None
    parsed = _parse(last_run)
    if running and parsed:
        nxt = iso(parsed + timedelta(seconds=interval_seconds()))
    total, enabled = int((channels or [0, 0])[0] or 0), int((channels or [0, 0])[1] or 0)
    sent, failed = int((day or [0, 0])[0] or 0), int((day or [0, 0])[1] or 0)
    detail = (f"{enabled} enabled of {total} channels; every {interval_seconds():g}s; loop "
              f"{'running in this process' if running else 'not running in this process'}"
              f"{'' if dispatch_enabled() else ' (MORROW_ALERT_DISPATCH_ENABLED=0)'}. {sent} attempts and {failed} failures in the last 24h; "
              f"renotify after {renotify_hours():g}h; cap {rate_cap()} per {rate_window_minutes():g} min."
              + (f" {waiting} PagerDuty resolve(s) from a deleted or disabled channel are waiting to be retried."
                 if waiting else ""))
    return {"status": status, "last_run_at": last_run or None, "next_run_at": nxt, "last_error": (row[2] if row and row[2] else None),
            "runs_24h": sent, "running": running, "pending_resolves": waiting,
            "source": "platform_alert_dispatcher, platform_alert_deliveries", "detail": detail}


async def _loop(snapshot: Callable[[], Dict[str, Any]], base_url: Callable[[], str]) -> None:
    from starlette.concurrency import run_in_threadpool

    await asyncio.sleep(min(15.0, interval_seconds()))
    while True:
        try:
            await run_in_threadpool(run_once, snapshot, base_url())
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        await asyncio.sleep(interval_seconds())


def start(snapshot: Callable[[], Dict[str, Any]], base_url: Callable[[], str]) -> Optional[asyncio.Task]:
    if not dispatch_enabled():
        return None
    task = _LOOP.get("task")
    if task is not None and not task.done():
        return task
    _LOOP["task"] = asyncio.get_running_loop().create_task(_loop(snapshot, base_url))
    with _STATE_LOCK:
        STATE["started_at"] = iso(now_utc())
    return _LOOP["task"]


async def stop() -> None:
    task = _LOOP.get("task")
    _LOOP["task"] = None
    if task is None:
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


def iter_kinds() -> Iterable[str]:
    return NOTIFICATION_KINDS.keys()
