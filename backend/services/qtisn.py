"""
Quantum Threat Intelligence Signals (Q-TISN) — local signal store

Organizations in THIS deployment can record anonymised canary trigger signals
(tier, jittered timestamp, sector, region) and see threat levels computed from
the signals stored here.

Scope: local only. Signals are not sent to, or received from, any external
network or hub, so counts and threat levels reflect only this deployment's
database. Every response carries network_scope="local" and model_basis.

Threat levels (computed over local signals):
  WATCH   — 1 trigger in the last 24h
  WARNING — 2-4 triggers in a sector within 48h
  ALERT   — 5+ triggers within 24h
  CRITICAL— an omega (PQC control) canary was triggered
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


SECTORS = [
    "financial_services", "healthcare", "government", "critical_infrastructure",
    "technology", "defense", "energy", "telecommunications", "education", "other",
]

REGIONS = ["north_america", "europe", "asia_pacific", "middle_east", "latin_america", "africa"]

NETWORK_SCOPE = "local"
SCOPE_NOTE = (
    "Local signal store: signals are stored in this deployment only and are not shared with or received "
    "from other organizations or any external network."
)


def qtisn_model_basis() -> Dict[str, Any]:
    from services.model_basis import model_basis
    return model_basis(
        kind="model",
        summary=(
            "Threat levels are computed from canary signals stored in this deployment only; they are not "
            "network-wide intelligence."
        ),
        assumptions=[
            "WATCH: 1 signal in 24h; WARNING: 2+ in a sector within 48h or 4+ overall; ALERT: 5+ in 24h or 10+ in 48h; "
            "CRITICAL: any omega-tier signal.",
            "Signal timestamps are jittered by up to ±30 minutes for privacy.",
        ],
        sources=[],
        as_of="2026-09",
    )


def scope_fields() -> Dict[str, Any]:
    return {"network_scope": NETWORK_SCOPE, "scope_note": SCOPE_NOTE}


def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("qtisn"):
        return
    _ensure_tables_uncached()
    mark_schema_ensured("qtisn")


def _ensure_tables_uncached() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS qtisn_signals (
                id              TEXT PRIMARY KEY,
                signal_hash     TEXT NOT NULL,
                tier            TEXT NOT NULL,
                sector          TEXT NOT NULL DEFAULT 'other',
                region          TEXT NOT NULL DEFAULT 'other',
                fired_at        TEXT NOT NULL,
                received_at     TEXT NOT NULL,
                is_local        INTEGER NOT NULL DEFAULT 1,
                org_hash        TEXT NOT NULL DEFAULT '',
                threat_level    TEXT NOT NULL DEFAULT 'watch'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS qtisn_membership (
                org_id          TEXT PRIMARY KEY,
                sector          TEXT NOT NULL DEFAULT 'other',
                region          TEXT NOT NULL DEFAULT 'other',
                joined_at       TEXT NOT NULL,
                share_signals   INTEGER NOT NULL DEFAULT 1,
                receive_alerts  INTEGER NOT NULL DEFAULT 1,
                anonymous_id    TEXT NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qtisn_tier ON qtisn_signals(tier, fired_at)"
        )
        conn.commit()


# ── Membership ────────────────────────────────────────────────────────────────

def join_qtisn(org_id: str, sector: str, region: str) -> Dict[str, Any]:
    """Register org in Q-TISN. Assigns anonymous ID for signal attribution."""
    _ensure_tables()
    anon_id = "ORG-" + hashlib.sha256(org_id.encode()).hexdigest()[:12].upper()
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO qtisn_membership
               (org_id, sector, region, joined_at, share_signals, receive_alerts, anonymous_id)
               VALUES (?, ?, ?, ?, 1, 1, ?)""",
            (org_id, sector, region, now, anon_id),
        )
        conn.commit()
    return {"org_id": org_id, "anonymous_id": anon_id, "sector": sector, "region": region,
            "joined_at": now, "status": "active", **scope_fields()}


def get_membership(org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM qtisn_membership WHERE org_id = ?", (org_id,)
        ).fetchone()
    return dict(row) if row else None


# ── Signal submission ─────────────────────────────────────────────────────────

def submit_signal(
    org_id: str,
    tier: str,
    fired_at: str,
    is_local: bool = True,
) -> Dict[str, Any]:
    """
    Submit an anonymized canary trigger signal to the network.
    fired_at is jittered ±30 minutes for privacy.
    """
    _ensure_tables()
    membership = get_membership(org_id)
    sector = membership.get("sector", "other") if membership else "other"
    region = membership.get("region", "other") if membership else "other"
    org_hash = "ORG-" + hashlib.sha256(org_id.encode()).hexdigest()[:12].upper()

    # Jitter timestamp ±30 minutes
    try:
        dt = datetime.fromisoformat(fired_at.replace("Z", "+00:00"))
        jitter_minutes = secrets.randbelow(61) - 30
        dt_jittered = (dt + timedelta(minutes=jitter_minutes)).isoformat()
    except Exception:
        dt_jittered = datetime.now(timezone.utc).isoformat()

    signal_hash = hashlib.sha256(f"{tier}:{dt_jittered}:{sector}:{region}".encode()).hexdigest()[:20]
    now = datetime.now(timezone.utc).isoformat()

    threat_level = _compute_threat_level(tier, sector, now)

    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR IGNORE INTO qtisn_signals
               (id, signal_hash, tier, sector, region, fired_at,
                received_at, is_local, org_hash, threat_level)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (secrets.token_urlsafe(10), signal_hash, tier, sector, region,
             dt_jittered, now, 1 if is_local else 0, org_hash, threat_level),
        )
        conn.commit()

    return {
        "signal_hash": signal_hash,
        "tier": tier,
        "sector": sector,
        "region": region,
        "fired_at_jittered": dt_jittered,
        "threat_level": threat_level,
        "anonymous_id": org_hash,
        **scope_fields(),
    }


def _compute_threat_level(tier: str, sector: str, now_iso: str) -> str:
    """Compute current threat level based on recent signal history."""
    if tier == "omega":
        return "CRITICAL"

    window_48h = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    window_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    with closing(_db()) as conn:
        # Signals in any sector in last 24h
        count_24h = conn.execute(
            "SELECT COUNT(*) FROM qtisn_signals WHERE fired_at >= ? AND tier != 'omega'",
            (window_24h,),
        ).fetchone()[0]
        # Signals in same sector in last 48h
        count_sector_48h = conn.execute(
            "SELECT COUNT(*) FROM qtisn_signals WHERE sector = ? AND fired_at >= ?",
            (sector, window_48h),
        ).fetchone()[0]
        # Total signals in last 48h
        count_total_48h = conn.execute(
            "SELECT COUNT(*) FROM qtisn_signals WHERE fired_at >= ?",
            (window_48h,),
        ).fetchone()[0]

    if count_24h >= 5 or count_total_48h >= 10:
        return "ALERT"
    if count_sector_48h >= 2 or count_total_48h >= 4:
        return "WARNING"
    return "WATCH"


# ── Network dashboard ─────────────────────────────────────────────────────────

def get_network_dashboard(org_id: str) -> Dict[str, Any]:
    """Current state of the local Q-TISN signal store."""
    _ensure_tables()
    now = datetime.now(timezone.utc)
    w24 = (now - timedelta(hours=24)).isoformat()
    w48 = (now - timedelta(hours=48)).isoformat()
    w7d = (now - timedelta(days=7)).isoformat()

    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        signals_24h = [dict(r) for r in conn.execute(
            "SELECT tier, sector, region, fired_at, threat_level FROM qtisn_signals WHERE fired_at >= ? ORDER BY fired_at DESC",
            (w24,),
        ).fetchall()]
        signals_7d = conn.execute(
            "SELECT COUNT(*) FROM qtisn_signals WHERE fired_at >= ?", (w7d,)
        ).fetchone()[0]
        by_tier = {row["tier"]: row["cnt"] for row in conn.execute(
            "SELECT tier, COUNT(*) as cnt FROM qtisn_signals WHERE fired_at >= ? GROUP BY tier",
            (w48,),
        ).fetchall()}
        by_sector = {row["sector"]: row["cnt"] for row in conn.execute(
            "SELECT sector, COUNT(*) as cnt FROM qtisn_signals WHERE fired_at >= ? GROUP BY sector",
            (w48,),
        ).fetchall()}
        member_count = conn.execute("SELECT COUNT(*) FROM qtisn_membership").fetchone()[0]
        omega_triggered = conn.execute(
            "SELECT COUNT(*) FROM qtisn_signals WHERE tier='omega'"
        ).fetchone()[0]

    # Global threat level
    total_24h = len(signals_24h)
    if omega_triggered:
        global_threat = "CRITICAL"
    elif total_24h >= 5:
        global_threat = "ALERT"
    elif total_24h >= 2:
        global_threat = "WARNING"
    elif total_24h >= 1:
        global_threat = "WATCH"
    else:
        global_threat = "MONITORING"

    threat_colors = {
        "MONITORING": "#63e6be", "WATCH": "#fbbf24",
        "WARNING": "#f97316", "ALERT": "#ef4444", "CRITICAL": "#dc2626",
    }

    membership = get_membership(org_id)

    return {
        # Key name kept for console compatibility; the level covers local signals only.
        "global_threat_level": global_threat,
        "global_threat_color": threat_colors.get(global_threat, "#94a3b8"),
        "local_org_records": member_count,
        "signals_last_24h": total_24h,
        "signals_last_7d": signals_7d,
        "omega_triggered_local": omega_triggered > 0,
        "by_tier_48h": by_tier,
        "by_sector_48h": by_sector,
        "recent_signals": signals_24h[:20],
        "your_membership": membership,
        "network_message": _network_message(global_threat, total_24h),
        **scope_fields(),
        "model_basis": qtisn_model_basis(),
    }


def _network_message(level: str, count_24h: int) -> str:
    if level == "CRITICAL":
        return ("CRITICAL: An omega-tier (PQC control) canary signal is recorded in this deployment. "
                "Investigate the trigger and verify the canary configuration before drawing conclusions.")
    if level == "ALERT":
        return (f"ALERT: {count_24h} canary signals recorded in this deployment in 24 hours. "
                "Investigate the triggers and follow your incident response plan.")
    if level == "WARNING":
        return f"WARNING: {count_24h} canary signal(s) recorded in this deployment. Increase monitoring and investigate."
    if level == "WATCH":
        return "WATCH: One canary signal recorded in this deployment in 24 hours. Continue monitoring."
    return "No canary signals recorded in this deployment in the last 24 hours."


def get_signal_history(org_id: str, days: int = 30) -> List[Dict[str, Any]]:
    _ensure_tables()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT signal_hash, tier, sector, region, fired_at, threat_level
               FROM qtisn_signals WHERE fired_at >= ? ORDER BY fired_at DESC LIMIT 200""",
            (since,),
        ).fetchall()
    return [dict(r) for r in rows]
