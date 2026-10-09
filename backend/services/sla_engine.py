"""
Wave 15 — SLA Enforcement Engine
Tracks remediation SLAs by severity, detects breaches, auto-escalates via telemetry.
"""
from __future__ import annotations
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Default SLA thresholds in days
DEFAULT_SLA = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}

_DDL = [
    """CREATE TABLE IF NOT EXISTS sla_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL UNIQUE,
        critical_days INTEGER NOT NULL DEFAULT 7,
        high_days INTEGER NOT NULL DEFAULT 30,
        medium_days INTEGER NOT NULL DEFAULT 90,
        low_days INTEGER NOT NULL DEFAULT 180,
        info_days INTEGER NOT NULL DEFAULT 365,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sla_breaches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        remediation_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        opened_at TEXT NOT NULL,
        breached_at TEXT NOT NULL,
        days_overdue INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'open',
        notified INTEGER NOT NULL DEFAULT 0,
        UNIQUE(organization_id, remediation_id)
    )""",
]


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    conn.commit()


# ── Config ────────────────────────────────────────────────────────────────────

def get_sla_config(conn: sqlite3.Connection, org_id: str) -> Dict:
    row = conn.execute(
        "SELECT critical_days, high_days, medium_days, low_days, info_days FROM sla_configs WHERE organization_id=?",
        (org_id,),
    ).fetchone()
    if row:
        return {"critical": row[0], "high": row[1], "medium": row[2], "low": row[3], "info": row[4]}
    return dict(DEFAULT_SLA)


def save_sla_config(conn: sqlite3.Connection, org_id: str, config: Dict) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO sla_configs (organization_id, critical_days, high_days, medium_days, low_days, info_days, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(organization_id) DO UPDATE SET
             critical_days=excluded.critical_days, high_days=excluded.high_days,
             medium_days=excluded.medium_days, low_days=excluded.low_days,
             info_days=excluded.info_days, updated_at=excluded.updated_at""",
        (org_id,
         config.get("critical", DEFAULT_SLA["critical"]),
         config.get("high", DEFAULT_SLA["high"]),
         config.get("medium", DEFAULT_SLA["medium"]),
         config.get("low", DEFAULT_SLA["low"]),
         config.get("info", DEFAULT_SLA["info"]),
         now),
    )
    conn.commit()


# ── SLA evaluation ────────────────────────────────────────────────────────────

def _sla_days(config: Dict, severity: str) -> int:
    severity = (severity or "medium").lower()
    return config.get(severity, DEFAULT_SLA.get(severity, 90))


def evaluate_sla_status(conn: sqlite3.Connection, org_id: str) -> Dict:
    """Evaluate all open remediations against SLA thresholds. Returns summary + breach list."""
    config = get_sla_config(conn, org_id)
    now = datetime.now(timezone.utc)

    try:
        # `remediations` has no severity column, so this raised every time and
        # the bare except below reported an empty SLA board -- no breaches, ever.
        # Severity comes from the latest scan of the asset the remediation is
        # against; anything unscanned falls back to the medium default that
        # _sla_days already applies.
        rows = conn.execute(
            """SELECT r.id,
                      (SELECT sr.risk_level FROM scan_results sr
                        WHERE sr.asset_key = r.asset_key
                          AND sr.organization_id = r.organization_id
                        ORDER BY sr.scanned_at DESC LIMIT 1) AS severity,
                      r.created_at, r.status
               FROM remediations r
               WHERE r.organization_id=? AND r.status != 'resolved'""",
            (org_id,),
        ).fetchall()
    except Exception:
        rows = []

    on_track = []
    at_risk = []   # >80% of SLA used
    breached = []

    for row in rows:
        rem_id, severity, created_at_str, status = row
        if not created_at_str:
            continue
        try:
            created = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        sla_days = _sla_days(config, severity or "medium")
        deadline = created + timedelta(days=sla_days)
        age_days = (now - created).days
        pct_used = (age_days / sla_days * 100) if sla_days > 0 else 0
        days_remaining = (deadline - now).days

        entry = {
            "remediation_id": str(rem_id),
            "severity": severity or "medium",
            "created_at": created_at_str,
            "sla_days": sla_days,
            "age_days": age_days,
            "days_remaining": days_remaining,
            "pct_used": round(pct_used, 1),
            "deadline": deadline.isoformat(),
        }

        if days_remaining < 0:
            entry["days_overdue"] = abs(days_remaining)
            breached.append(entry)
            # Upsert breach record
            try:
                conn.execute(
                    """INSERT INTO sla_breaches
                       (organization_id, remediation_id, severity, opened_at, breached_at, days_overdue, status)
                       VALUES (?, ?, ?, ?, ?, ?, 'open')
                       ON CONFLICT(organization_id, remediation_id) DO UPDATE SET
                         days_overdue=excluded.days_overdue""",
                    (org_id, str(rem_id), severity or "medium", created_at_str,
                     deadline.isoformat(), abs(days_remaining)),
                )
            except Exception:
                pass
        elif pct_used >= 80:
            at_risk.append(entry)
        else:
            on_track.append(entry)

    try:
        conn.commit()
    except Exception:
        pass

    return {
        "summary": {
            "on_track": len(on_track),
            "at_risk": len(at_risk),
            "breached": len(breached),
            "total": len(on_track) + len(at_risk) + len(breached),
        },
        "config": config,
        "on_track": on_track,
        "at_risk": at_risk,
        "breached": breached,
    }


def list_breaches(conn: sqlite3.Connection, org_id: str, limit: int = 200) -> List[Dict]:
    try:
        rows = conn.execute(
            """SELECT remediation_id, severity, opened_at, breached_at, days_overdue, status, notified
               FROM sla_breaches WHERE organization_id=? ORDER BY days_overdue DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
        cols = ["remediation_id", "severity", "opened_at", "breached_at",
                "days_overdue", "status", "notified"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception:
        return []
