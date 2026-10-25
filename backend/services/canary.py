"""
Quantum Canary Network — enterprise-grade implementation.

Cryptographic tripwires that detect the moment Q-Day arrives.
Deploy fake credentials encrypted with deliberately-vulnerable algorithms.
When an attacker decrypts harvested traffic and their tooling tries the
credential, the beacon fires — you know Q-Day has arrived.

Enterprise hardening over the basic version:
  - Bot / crawler UA filtering so web scanners don't create false positives
  - Full hit log (every access, not just first trigger)
  - Geo-IP enrichment on trigger (country / org of origin)
  - Deduplication: Slack alert fires exactly once, not per-hit
  - Credential file export (JSON / .env / YAML) for embedding in real services
  - Audit log integration
  - Incident playbook per tier

Tiers (ordered by expected break date):
  alpha  — RSA-1024  (breaks first — early warning)
  beta   — RSA-2048  (main enterprise alarm)
  gamma  — ECC-256   (elliptic-curve alarm)
  delta  — RSA-4096  (high-security systems)
  omega  — ML-KEM-768 (control — MUST NEVER trigger)
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import string
import urllib.request
import urllib.error
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Tier definitions ──────────────────────────────────────────────────────────

CANARY_TIERS: Dict[str, Dict[str, Any]] = {
    "alpha": {
        "algo": "RSA-1024",
        "label": "Alpha — RSA-1024",
        "color": "#fbbf24",
        "severity": "high",
        "description": "Small-scale quantum computers operational.",
        "urgency": "Accelerate PQC migration — small quantum computers can now break RSA-1024.",
        "playbook": [
            "Activate your PQC migration runbook immediately.",
            "Prioritise RSA-1024 endpoints — rotate keys to ML-KEM-768 or hybrid X25519+ML-KEM.",
            "Notify your CISO and security team within 1 hour.",
            "Assume any RSA-1024-encrypted traffic recorded before this date is readable.",
            "Begin monitoring for Alpha and Beta canary triggers over the next 48 hours.",
        ],
    },
    "beta": {
        "algo": "RSA-2048",
        "label": "Beta — RSA-2048",
        "color": "#f97316",
        "severity": "critical",
        "description": "Q-Day for enterprise traffic — RSA-2048 is broken.",
        "urgency": "EMERGENCY: RSA-2048 broken. All classical TLS traffic recorded since deployment is now readable.",
        "playbook": [
            "Declare a security incident. Convene your incident response team immediately.",
            "Assume ALL RSA-2048 and ECC-256 encrypted traffic recorded in the past 5 years is compromised.",
            "Rotate ALL TLS certificates to ML-KEM-768 hybrid or pure PQC — start with customer-facing endpoints.",
            "Rotate ALL internal service credentials, API keys, and tokens.",
            "Notify affected customers per your breach notification obligation (GDPR: 72 hours).",
            "Engage your cyber insurance provider.",
            "File a report with CISA/NCSC if you are critical infrastructure.",
        ],
    },
    "gamma": {
        "algo": "ECC-256 (P-256)",
        "label": "Gamma — ECC-256",
        "color": "#f97316",
        "severity": "critical",
        "description": "All ECDHE P-256 sessions are exposed.",
        "urgency": "EMERGENCY: Elliptic curve P-256 broken. All ECDHE key exchanges using P-256 are compromised.",
        "playbook": [
            "Declare a security incident alongside Beta tier response.",
            "Assume all ECDHE_P256 TLS sessions are compromised (most HTTPS traffic).",
            "Prioritise rotation of services using ECDSA or ECDH P-256 certificates.",
            "Check for OAuth / JWT tokens signed with ES256 — these are now forgeable.",
            "Rotate all SSH keys using ecdsa-sha2-nistp256.",
        ],
    },
    "delta": {
        "algo": "RSA-4096",
        "label": "Delta — RSA-4096",
        "color": "#ef4444",
        "severity": "critical",
        "description": "Advanced quantum capability — all classical asymmetric crypto broken.",
        "urgency": "EMERGENCY: RSA-4096 broken. All classical asymmetric cryptography is compromised.",
        "playbook": [
            "All classical asymmetric cryptography should be considered broken.",
            "Engage national cybersecurity authority immediately (CISA, NCSC, BSI).",
            "Assume all historical encrypted data, including data stored with RSA-4096, is exposed.",
            "Activate your catastrophic breach response plan.",
            "Verify PQC (ML-KEM, SLH-DSA) systems are still intact — check Omega canary status.",
        ],
    },
    "omega": {
        "algo": "ML-KEM-768 (PQC)",
        "label": "Omega — ML-KEM-768",
        "color": "#a855f7",
        "severity": "critical",
        "description": "Control canary — this MUST NOT trigger.",
        "urgency": "CATASTROPHIC: A NIST-standardised PQC algorithm has been broken. Contact NIST immediately.",
        "playbook": [
            "This canary should never trigger. If it has, treat it as a potential system compromise first.",
            "Verify the trigger is not a false positive (check trigger IP, UA, and timing).",
            "If confirmed genuine: contact NIST and national cybersecurity authority immediately.",
            "Engage cryptographic research community — this would be a historic cryptographic break.",
            "All encrypted data across all algorithm classes should be treated as potentially exposed.",
        ],
    },
}

# ── Known crawler UAs (false-positive suppressors) ────────────────────────────
# These are legitimate web crawlers that should NOT trigger an alert.
# Attacker tooling (curl, python-requests, wget, etc.) is intentionally NOT listed.
_CRAWLER_UA_FRAGMENTS = frozenset([
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "sogou", "exabot", "facebot", "ia_archiver",
    "semrushbot", "ahrefsbot", "dotbot", "mj12bot", "rogerbot",
    "linkdexbot", "bufferbot", "twitterbot", "linkedinbot",
    "facebookexternalhit", "whatsapp", "telegrambot",
])


def _is_crawler(ua: str) -> bool:
    ua_l = ua.lower()
    return any(frag in ua_l for frag in _CRAWLER_UA_FRAGMENTS)


# ── Geo-IP lookup (best-effort, never blocks alert) ───────────────────────────

def _geoip(ip: str) -> Dict[str, str]:
    """Best-effort geo-IP lookup. Returns empty dict on any failure."""
    if not ip or ip in ("127.0.0.1", "::1", "unknown"):
        return {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,org,isp,query"
        req = urllib.request.Request(url, headers={"User-Agent": "PQC-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "fail":
            return {}
        return {
            "country":      data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "org":          data.get("org", ""),
            "isp":          data.get("isp", ""),
        }
    except Exception:
        return {}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("quantum_canaries"):
        return
    _ensure_tables_uncached()
    mark_schema_ensured("quantum_canaries")


def _ensure_tables_uncached() -> None:
    with closing(_db()) as conn:
        # Primary canary table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quantum_canaries (
                id              TEXT PRIMARY KEY,
                tier            TEXT NOT NULL,
                algo_desc       TEXT NOT NULL,
                asset_key       TEXT NOT NULL DEFAULT '',
                org_id          TEXT NOT NULL,
                fake_credential TEXT NOT NULL,
                beacon_token    TEXT NOT NULL UNIQUE,
                deployed_at     TEXT NOT NULL,
                triggered_at    TEXT,
                trigger_ip      TEXT NOT NULL DEFAULT '',
                trigger_ua      TEXT NOT NULL DEFAULT '',
                trigger_geo     TEXT NOT NULL DEFAULT '{}',
                notes           TEXT NOT NULL DEFAULT '',
                slack_alerted   INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Full hit log — every access, including bots and repeat hits
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quantum_canary_hits (
                id           TEXT PRIMARY KEY,
                beacon_token TEXT NOT NULL,
                hit_at       TEXT NOT NULL,
                trigger_ip   TEXT NOT NULL DEFAULT '',
                trigger_ua   TEXT NOT NULL DEFAULT '',
                is_bot       INTEGER NOT NULL DEFAULT 0,
                geo          TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qcanary_org   ON quantum_canaries(org_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qcanary_token ON quantum_canaries(beacon_token)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qchit_token   ON quantum_canary_hits(beacon_token)"
        )
        # Add missing columns to existing tables (safe migration)
        existing = {r[1] for r in conn.execute("PRAGMA table_info(quantum_canaries)").fetchall()}
        for col, defn in [
            ("trigger_geo",   "TEXT NOT NULL DEFAULT '{}'"),
            ("slack_alerted", "INTEGER NOT NULL DEFAULT 0"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE quantum_canaries ADD COLUMN {col} {defn}")
        conn.commit()


# ── Credential generator ──────────────────────────────────────────────────────

def _rand_key(prefix: str = "sk") -> str:
    chars = string.ascii_letters + string.digits
    body = "".join(secrets.choice(chars) for _ in range(36))
    return f"{prefix}-live-{body}"


def _fake_user() -> str:
    user = secrets.choice(["admin", "svc-account", "api", "deploy", "internal-svc", "system"])
    domain = secrets.choice(["corp.internal", "services.net", "internal.corp", "cluster.local"])
    return f"{user}@{domain}"


def _generate_credential(tier: str, beacon_url: str) -> Dict[str, Any]:
    """
    Generate a fake credential that looks real and embeds the beacon URL.
    The beacon URL is set as `token_endpoint` — when automated tooling
    tries to validate/refresh the token, it calls home.
    """
    cred: Dict[str, Any] = {
        "api_key":        _rand_key("sk"),
        "username":       _fake_user(),
        "password":       secrets.token_urlsafe(22),
        "token_endpoint": beacon_url,
        "issued_at":      datetime.now(timezone.utc).isoformat(),
        "expires_in":     86400,
        "scope":          "read write admin",
        "_note":          "Internal service credential — rotate quarterly",
    }
    if tier in ("beta", "delta"):
        cred["db_password"] = secrets.token_urlsafe(18)
        cred["db_host"]     = "db-primary.internal"
        cred["db_port"]     = 5432
        cred["db_user"]     = "app_admin" if tier == "delta" else "app_rw"
    if tier == "gamma":
        cred["oauth_client_id"]     = secrets.token_hex(12)
        cred["oauth_client_secret"] = _rand_key("cs")
        cred["refresh_token"]       = secrets.token_urlsafe(48)
    if tier == "omega":
        cred["_canary_note"] = (
            "ML-KEM-768 control canary. If you decrypted this, "
            "contact your security team immediately."
        )
    return cred


def export_credential(canary: Dict[str, Any], fmt: str = "json") -> str:
    """
    Render canary credential in a format suitable for embedding in real services.
    fmt: 'json' | 'env' | 'yaml'
    """
    cred = canary.get("fake_credential") or {}
    if fmt == "env":
        lines = []
        for k, v in cred.items():
            key = k.upper().replace("-", "_").replace(".", "_")
            lines.append(f'{key}="{v}"')
        return "\n".join(lines)
    if fmt == "yaml":
        lines = []
        for k, v in cred.items():
            safe_v = str(v).replace('"', '\\"')
            lines.append(f'{k}: "{safe_v}"')
        return "\n".join(lines)
    return json.dumps(cred, indent=2)


# ── Core operations ────────────────────────────────────────────────────────────

def deploy_canary(
    tier: str,
    org_id: str,
    app_url: str = "",
    asset_key: str = "",
    notes: str = "",
) -> Dict[str, Any]:
    """Deploy a new quantum canary and return the full record."""
    if tier not in CANARY_TIERS:
        raise ValueError(f"Unknown tier '{tier}'. Valid: {list(CANARY_TIERS)}")

    _ensure_tables()

    canary_id    = secrets.token_urlsafe(18)
    beacon_token = secrets.token_urlsafe(28)
    base         = (app_url or "").rstrip("/")
    beacon_url   = f"{base}/v1/auth/token/{beacon_token}" if base else f"/v1/auth/token/{beacon_token}"

    cred    = _generate_credential(tier, beacon_url)
    info    = CANARY_TIERS[tier]
    now_iso = datetime.now(timezone.utc).isoformat()

    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO quantum_canaries
               (id, tier, algo_desc, asset_key, org_id, fake_credential,
                beacon_token, deployed_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (canary_id, tier, info["algo"], asset_key or "", org_id,
             json.dumps(cred), beacon_token, now_iso, notes or ""),
        )
        conn.commit()

    try:
        from db import write_audit_log
        write_audit_log(
            action="canary.deploy",
            actor=org_id,
            resource_type="canary",
            resource_id=canary_id,
            details={"tier": tier, "algo": info["algo"], "asset_key": asset_key},
        )
    except Exception:
        pass

    return {
        "id": canary_id, "tier": tier, "algo": info["algo"],
        "label": info["label"], "description": info["description"],
        "beacon_token": beacon_token, "beacon_url": beacon_url,
        "asset_key": asset_key, "fake_credential": cred,
        "deployed_at": now_iso, "status": "active",
    }


def list_canaries(org_id: str) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM quantum_canaries WHERE org_id = ? ORDER BY deployed_at DESC",
            (org_id,),
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try:
            d["fake_credential"] = json.loads(d.get("fake_credential") or "{}")
        except Exception:
            d["fake_credential"] = {}
        try:
            d["trigger_geo"] = json.loads(d.get("trigger_geo") or "{}")
        except Exception:
            d["trigger_geo"] = {}
        d["status"] = "triggered" if d.get("triggered_at") else "active"
        out.append(d)
    return out


def get_canary_by_token(beacon_token: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM quantum_canaries WHERE beacon_token = ?",
            (beacon_token,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["fake_credential"] = json.loads(d.get("fake_credential") or "{}")
    except Exception:
        d["fake_credential"] = {}
    try:
        d["trigger_geo"] = json.loads(d.get("trigger_geo") or "{}")
    except Exception:
        d["trigger_geo"] = {}
    d["status"] = "triggered" if d.get("triggered_at") else "active"
    return d


def get_canary_by_id(canary_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM quantum_canaries WHERE id = ? AND org_id = ?",
            (canary_id, org_id),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["fake_credential"] = json.loads(d.get("fake_credential") or "{}")
    except Exception:
        d["fake_credential"] = {}
    try:
        d["trigger_geo"] = json.loads(d.get("trigger_geo") or "{}")
    except Exception:
        d["trigger_geo"] = {}
    d["status"] = "triggered" if d.get("triggered_at") else "active"
    return d


def log_hit(beacon_token: str, ip: str, ua: str) -> bool:
    """
    Record every access to the beacon — bots, crawlers, and real triggers alike.
    Returns True if this is a non-bot hit (should check for first-trigger logic).
    """
    _ensure_tables()
    bot = _is_crawler(ua)
    geo = _geoip(ip) if not bot else {}
    hit_id = secrets.token_urlsafe(12)
    now_iso = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO quantum_canary_hits
               (id, beacon_token, hit_at, trigger_ip, trigger_ua, is_bot, geo)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (hit_id, beacon_token, now_iso, ip or "", ua or "",
             1 if bot else 0, json.dumps(geo)),
        )
        conn.commit()
    return not bot


def trigger_canary(
    beacon_token: str,
    trigger_ip: str = "",
    trigger_ua: str = "",
) -> Optional[Dict[str, Any]]:
    """
    Record the first non-bot trigger on a canary. Idempotent.
    Returns updated canary dict or None if token not found.
    """
    _ensure_tables()
    geo = _geoip(trigger_ip)
    now_iso = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        conn.execute(
            """UPDATE quantum_canaries
               SET triggered_at = ?, trigger_ip = ?, trigger_ua = ?, trigger_geo = ?
               WHERE beacon_token = ? AND triggered_at IS NULL""",
            (now_iso, trigger_ip or "", trigger_ua or "",
             json.dumps(geo), beacon_token),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM quantum_canaries WHERE beacon_token = ?",
            (beacon_token,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["fake_credential"] = json.loads(d.get("fake_credential") or "{}")
    except Exception:
        d["fake_credential"] = {}
    try:
        d["trigger_geo"] = json.loads(d.get("trigger_geo") or "{}")
    except Exception:
        d["trigger_geo"] = {}
    d["status"] = "triggered"
    return d


def mark_slack_alerted(beacon_token: str) -> None:
    """Mark that the Slack alert has been sent for this canary (dedup guard)."""
    with closing(_db()) as conn:
        conn.execute(
            "UPDATE quantum_canaries SET slack_alerted = 1 WHERE beacon_token = ?",
            (beacon_token,),
        )
        conn.commit()


def get_hit_log(beacon_token: str) -> List[Dict[str, Any]]:
    """Return all hits on a canary beacon (audit trail)."""
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, hit_at, trigger_ip, trigger_ua, is_bot, geo
               FROM quantum_canary_hits
               WHERE beacon_token = ?
               ORDER BY hit_at DESC LIMIT 500""",
            (beacon_token,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["geo"] = json.loads(d.get("geo") or "{}")
        except Exception:
            d["geo"] = {}
        d["is_bot"] = bool(d["is_bot"])
        out.append(d)
    return out


def canary_dashboard(org_id: str) -> Dict[str, Any]:
    canaries = list_canaries(org_id)
    tier_summary: Dict[str, Any] = {}
    for tier, info in CANARY_TIERS.items():
        mine = [c for c in canaries if c["tier"] == tier]
        triggered = [c for c in mine if c["status"] == "triggered"]
        tier_summary[tier] = {
            "tier": tier, "algo": info["algo"], "label": info["label"],
            "color": info["color"], "severity": info["severity"],
            "description": info["description"], "urgency": info["urgency"],
            "playbook": info["playbook"],
            "deployed": len(mine), "triggered": len(triggered),
            "latest_trigger": triggered[0]["triggered_at"] if triggered else None,
            "trigger_geo": triggered[0].get("trigger_geo") if triggered else {},
            "trigger_ip": triggered[0].get("trigger_ip") if triggered else "",
            "status": (
                "triggered" if triggered else
                "active"    if mine else
                "undeployed"
            ),
        }

    total_triggered = sum(1 for c in canaries if c["status"] == "triggered")
    return {
        "org_id": org_id,
        "total_deployed": len(canaries),
        "total_triggered": total_triggered,
        "any_triggered": total_triggered > 0,
        "alert_level": "emergency" if total_triggered > 0 else "monitoring",
        "tiers": tier_summary,
    }


def fire_canary_slack_alert(canary: Dict[str, Any]) -> None:
    """
    Send emergency Slack alert. Deduplication: only sends once per canary
    (checked via slack_alerted flag, set after sending).
    """
    if canary.get("slack_alerted"):
        return

    try:
        from db import get_integration_setting
        webhook_url = get_integration_setting("slack_webhook_url", "").strip()
    except Exception:
        webhook_url = ""
    webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    tier    = canary.get("tier", "?")
    info    = CANARY_TIERS.get(tier, {})
    algo    = info.get("algo", canary.get("algo_desc", "?"))
    urgency = info.get("urgency", "A quantum canary has been triggered.")
    geo     = canary.get("trigger_geo") or {}
    location = (
        f"{geo['country']} / {geo['org']}" if geo.get("country") and geo.get("org")
        else geo.get("country") or "unknown location"
    )

    steps = info.get("playbook", [])
    playbook_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps[:4]))

    payload = {
        "text": f"\U0001f6a8 *QUANTUM CANARY TRIGGERED — {algo} HAS BEEN BROKEN*",
        "attachments": [{
            "color": "#EF4444",
            "title": f"Q-Day Alert: {tier.upper()} Canary — {algo}",
            "text": urgency,
            "fields": [
                {"title": "Algorithm",    "value": algo,                                   "short": True},
                {"title": "Triggered At", "value": canary.get("triggered_at", ""),         "short": True},
                {"title": "Trigger IP",   "value": canary.get("trigger_ip", "unknown"),    "short": True},
                {"title": "Location",     "value": location,                               "short": True},
                {"title": "Asset",        "value": canary.get("asset_key") or "org-wide",  "short": True},
            ],
            "footer": "Morrow — Quantum Canary Network",
        }, {
            "color": "#1e293b",
            "title": "Immediate Action Plan",
            "text": playbook_text,
            "footer": "Full playbook in Morrow → Quantum Canary Network",
        }],
    }

    try:
        import urllib.request as _ur
        data = json.dumps(payload).encode()
        req  = _ur.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        _ur.urlopen(req, timeout=8)
        mark_slack_alerted(canary.get("beacon_token", ""))
    except Exception:
        pass
