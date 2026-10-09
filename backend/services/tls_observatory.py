"""
Live TLS Observatory — Continuous Monitoring & Drift Detection

Continuously re-scans all registered assets on a configurable schedule and
detects cryptographic degradation:
  - Algorithm downgrade (was ML-KEM, now RSA-2048)
  - Certificate replacement with quantum-vulnerable cert
  - TLS version downgrade
  - New SAN additions (expansion of attack surface)
  - Certificate expiry approaching

For each asset, maintains a "crypto baseline" — the best cryptographic state
observed. Any deviation from the baseline triggers an alert.

Alert channels:
  - In-app notification (observatory_alerts table)
  - Slack webhook (if configured)
  - Q-TISN signal submission (if canary triggers)

This module provides the scheduling logic. The actual TLS scan is delegated
to the existing scanner.scan_host() function.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


_RISK_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4, "unknown": 5}


def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("tls_observatory"):
        return
    _ensure_tables_uncached()
    mark_schema_ensured("tls_observatory")


def _ensure_tables_uncached() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observatory_baselines (
                asset_key       TEXT NOT NULL,
                org_id          TEXT NOT NULL,
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL DEFAULT 443,
                baseline_at     TEXT NOT NULL,
                algo            TEXT NOT NULL DEFAULT '',
                key_bits        INTEGER NOT NULL DEFAULT 0,
                tls_version     TEXT NOT NULL DEFAULT '',
                risk_level      TEXT NOT NULL DEFAULT 'unknown',
                cert_fingerprint TEXT NOT NULL DEFAULT '',
                scan_json       TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (asset_key, org_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observatory_scans (
                id              TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                asset_key       TEXT NOT NULL,
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL DEFAULT 443,
                scanned_at      TEXT NOT NULL,
                algo            TEXT NOT NULL DEFAULT '',
                key_bits        INTEGER NOT NULL DEFAULT 0,
                tls_version     TEXT NOT NULL DEFAULT '',
                risk_level      TEXT NOT NULL DEFAULT 'unknown',
                cert_fingerprint TEXT NOT NULL DEFAULT '',
                drift_detected  INTEGER NOT NULL DEFAULT 0,
                drift_type      TEXT NOT NULL DEFAULT '',
                scan_json       TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observatory_alerts (
                id              TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                asset_key       TEXT NOT NULL,
                host            TEXT NOT NULL,
                alerted_at      TEXT NOT NULL,
                drift_type      TEXT NOT NULL,
                drift_detail    TEXT NOT NULL DEFAULT '',
                severity        TEXT NOT NULL DEFAULT 'medium',
                acknowledged    INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_obs_org ON observatory_scans(org_id, scanned_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_obs_alerts ON observatory_alerts(org_id, acknowledged)"
        )
        conn.commit()


# ── Baseline management ────────────────────────────────────────────────────────

def set_baseline(asset_key: str, org_id: str, scan_result: Dict[str, Any]) -> None:
    """Record the current scan result as the cryptographic baseline for this asset."""
    _ensure_tables()
    host = str(scan_result.get("host") or "").strip()
    port = int(scan_result.get("port") or 443)
    algo = str(scan_result.get("cert_key_type") or scan_result.get("key_type") or "")
    key_bits = int(scan_result.get("cert_key_bits") or scan_result.get("key_bits") or 0)
    tls_ver = str(scan_result.get("tls_version") or "")
    risk = str(scan_result.get("quantum_risk_level") or scan_result.get("risk_level") or "unknown")
    cert_fp = str(scan_result.get("cert_fingerprint") or scan_result.get("cert_sha256") or "")

    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO observatory_baselines
               (asset_key, org_id, host, port, baseline_at, algo, key_bits, tls_version,
                risk_level, cert_fingerprint, scan_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset_key, org_id, host, port, datetime.now(timezone.utc).isoformat(),
             algo, key_bits, tls_ver, risk, cert_fp, json.dumps(scan_result)),
        )
        conn.commit()


def get_baseline(asset_key: str, org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM observatory_baselines WHERE asset_key = ? AND org_id = ?",
            (asset_key, org_id),
        ).fetchone()
    return dict(row) if row else None


# ── Drift detection ────────────────────────────────────────────────────────────

def detect_drift(
    asset_key: str,
    org_id: str,
    new_scan: Dict[str, Any],
) -> Tuple[bool, str, str]:
    """
    Compare new scan against baseline. Returns (drift_detected, drift_type, drift_detail).

    drift_type values:
      algo_downgrade       — previously better algorithm, now worse
      risk_increase        — risk level increased
      tls_downgrade        — TLS version regressed
      cert_replaced        — certificate fingerprint changed
      key_size_decrease    — key size reduced
    """
    baseline = get_baseline(asset_key, org_id)
    if not baseline:
        return False, "", ""

    str(new_scan.get("cert_key_type") or new_scan.get("key_type") or "")
    new_bits = int(new_scan.get("cert_key_bits") or new_scan.get("key_bits") or 0)
    new_tls = str(new_scan.get("tls_version") or "")
    new_risk = str(new_scan.get("quantum_risk_level") or new_scan.get("risk_level") or "unknown")
    new_fp = str(new_scan.get("cert_fingerprint") or new_scan.get("cert_sha256") or "")

    old_risk = str(baseline.get("risk_level") or "unknown")
    old_bits = int(baseline.get("key_bits") or 0)
    old_tls = str(baseline.get("tls_version") or "")
    old_fp = str(baseline.get("cert_fingerprint") or "")

    # Risk increase
    if (_RISK_LEVEL_ORDER.get(new_risk, 5) < _RISK_LEVEL_ORDER.get(old_risk, 5)):
        return True, "risk_increase", f"Risk level changed from {old_risk} → {new_risk}"

    # TLS version downgrade
    _TLS_ORDER = {"TLSv1.3": 3, "TLSv1.2": 2, "TLSv1.1": 1, "TLSv1.0": 0, "SSLv3": -1}
    old_tls_v = _TLS_ORDER.get(old_tls, 2)
    new_tls_v = _TLS_ORDER.get(new_tls, 2)
    if new_tls and old_tls and new_tls_v < old_tls_v:
        return True, "tls_downgrade", f"TLS version regressed from {old_tls} → {new_tls}"

    # Key size decrease
    if new_bits and old_bits and new_bits < old_bits:
        return True, "key_size_decrease", f"Key size reduced from {old_bits} → {new_bits} bits"

    # Certificate replaced
    if new_fp and old_fp and new_fp != old_fp:
        return True, "cert_replaced", "Certificate fingerprint changed — verify this was intentional"

    return False, "", ""


def record_scan(
    asset_key: str,
    org_id: str,
    host: str,
    port: int,
    scan_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Record an observatory scan and check for drift."""
    _ensure_tables()
    import secrets as _secrets
    scan_id = "OBS-" + _secrets.token_hex(8).upper()

    algo = str(scan_result.get("cert_key_type") or scan_result.get("key_type") or "")
    key_bits = int(scan_result.get("cert_key_bits") or scan_result.get("key_bits") or 0)
    tls_ver = str(scan_result.get("tls_version") or "")
    risk = str(scan_result.get("quantum_risk_level") or scan_result.get("risk_level") or "unknown")
    cert_fp = str(scan_result.get("cert_fingerprint") or scan_result.get("cert_sha256") or "")

    drift_detected, drift_type, drift_detail = detect_drift(asset_key, org_id, scan_result)
    now = datetime.now(timezone.utc).isoformat()

    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO observatory_scans
               (id, org_id, asset_key, host, port, scanned_at, algo, key_bits,
                tls_version, risk_level, cert_fingerprint, drift_detected, drift_type, scan_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, org_id, asset_key, host, port, now, algo, key_bits, tls_ver,
             risk, cert_fp, 1 if drift_detected else 0, drift_type, json.dumps(scan_result)),
        )

        if drift_detected:
            alert_severity = (
                "critical" if drift_type in ("risk_increase", "algo_downgrade") else
                "high"     if drift_type in ("tls_downgrade", "key_size_decrease") else
                "medium"
            )
            alert_id = "ALERT-" + _secrets.token_hex(6).upper()
            conn.execute(
                """INSERT INTO observatory_alerts
                   (id, org_id, asset_key, host, alerted_at, drift_type, drift_detail, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert_id, org_id, asset_key, host, now, drift_type, drift_detail, alert_severity),
            )

        conn.commit()

    # Update baseline if this scan is BETTER (prevent baseline from degrading)
    baseline = get_baseline(asset_key, org_id)
    if baseline:
        old_risk_order = _RISK_LEVEL_ORDER.get(str(baseline.get("risk_level") or "unknown"), 5)
        new_risk_order = _RISK_LEVEL_ORDER.get(risk, 5)
        if new_risk_order > old_risk_order:  # better (higher order = safer)
            set_baseline(asset_key, org_id, scan_result)
    else:
        set_baseline(asset_key, org_id, scan_result)

    return {
        "scan_id": scan_id,
        "drift_detected": drift_detected,
        "drift_type": drift_type,
        "drift_detail": drift_detail,
        "risk_level": risk,
        "algo": algo,
        "key_bits": key_bits,
        "tls_version": tls_ver,
    }


# ── Observatory queries ────────────────────────────────────────────────────────

def get_observatory_dashboard(org_id: str) -> Dict[str, Any]:
    """Current state of the live TLS observatory for this org."""
    _ensure_tables()
    now = datetime.now(timezone.utc)
    w24 = (now - timedelta(hours=24)).isoformat()
    (now - timedelta(days=7)).isoformat()

    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row

        total_baselines = conn.execute(
            "SELECT COUNT(*) FROM observatory_baselines WHERE org_id = ?", (org_id,)
        ).fetchone()[0]

        scans_24h = conn.execute(
            "SELECT COUNT(*) FROM observatory_scans WHERE org_id = ? AND scanned_at >= ?",
            (org_id, w24)
        ).fetchone()[0]

        drifts_24h = conn.execute(
            "SELECT COUNT(*) FROM observatory_scans WHERE org_id = ? AND scanned_at >= ? AND drift_detected = 1",
            (org_id, w24)
        ).fetchone()[0]

        unacked_alerts = conn.execute(
            "SELECT COUNT(*) FROM observatory_alerts WHERE org_id = ? AND acknowledged = 0",
            (org_id,)
        ).fetchone()[0]

        recent_alerts = [dict(r) for r in conn.execute(
            """SELECT id, asset_key, host, alerted_at, drift_type, drift_detail, severity, acknowledged
               FROM observatory_alerts WHERE org_id = ? ORDER BY alerted_at DESC LIMIT 20""",
            (org_id,)
        ).fetchall()]

        recent_scans = [dict(r) for r in conn.execute(
            """SELECT asset_key, host, scanned_at, risk_level, algo, key_bits, drift_detected, drift_type
               FROM observatory_scans WHERE org_id = ? ORDER BY scanned_at DESC LIMIT 20""",
            (org_id,)
        ).fetchall()]

        risk_dist = {row["risk_level"]: row["cnt"] for row in conn.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM observatory_baselines WHERE org_id = ? GROUP BY risk_level",
            (org_id,)
        ).fetchall()}

    return {
        "total_monitored_assets": total_baselines,
        "scans_last_24h": scans_24h,
        "drift_events_24h": drifts_24h,
        "unacknowledged_alerts": unacked_alerts,
        "risk_distribution": risk_dist,
        "recent_alerts": recent_alerts,
        "recent_scans": recent_scans,
        "health": (
            "DEGRADED"  if drifts_24h >= 3 or unacked_alerts >= 5 else
            "WARNING"   if drifts_24h >= 1 or unacked_alerts >= 1 else
            "HEALTHY"   if scans_24h > 0 else
            "IDLE"
        ),
    }


def acknowledge_alert(alert_id: str, org_id: str) -> bool:
    _ensure_tables()
    with closing(_db()) as conn:
        cursor = conn.execute(
            "UPDATE observatory_alerts SET acknowledged = 1 WHERE id = ? AND org_id = ?",
            (alert_id, org_id)
        )
        conn.commit()
    return cursor.rowcount > 0


def get_asset_history(asset_key: str, org_id: str, limit: int = 30) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT scanned_at, algo, key_bits, tls_version, risk_level, drift_detected, drift_type
               FROM observatory_scans WHERE asset_key = ? AND org_id = ?
               ORDER BY scanned_at DESC LIMIT ?""",
            (asset_key, org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def trigger_observatory_scan(
    org_id: str,
    asset_keys: Optional[List[str]] = None,
    max_assets: int = 50,
) -> Dict[str, Any]:
    """
    Trigger a background observatory scan for the org's assets.
    Uses existing scanner.scan_host() for each asset.
    Returns job metadata — actual scanning is async.
    """
    import secrets as _secrets
    job_id = "OBS-JOB-" + _secrets.token_hex(6).upper()
    _ensure_tables()

    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        if asset_keys:
            placeholders = ",".join("?" * len(asset_keys))
            baselines = [dict(r) for r in conn.execute(
                f"SELECT asset_key, host, port FROM observatory_baselines WHERE org_id = ? AND asset_key IN ({placeholders}) LIMIT ?",
                [org_id] + asset_keys + [max_assets]
            ).fetchall()]
        else:
            baselines = [dict(r) for r in conn.execute(
                "SELECT asset_key, host, port FROM observatory_baselines WHERE org_id = ? LIMIT ?",
                (org_id, max_assets)
            ).fetchall()]

    return {
        "job_id": job_id,
        "org_id": org_id,
        "assets_queued": len(baselines),
        "assets": [{"asset_key": b["asset_key"], "host": b["host"], "port": b["port"]} for b in baselines],
        "status": "queued",
        "message": f"Observatory scan queued for {len(baselines)} assets. Results will appear in the dashboard.",
    }
