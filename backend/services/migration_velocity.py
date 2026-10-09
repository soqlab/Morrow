"""
Migration Velocity Tracker

Measures the rate at which an organization is migrating away from
quantum-vulnerable algorithms, and projects a completion date.

Metrics:
  - Weekly assets migrated (rolling 4-week average)
  - Remaining vulnerable assets
  - Projected completion date at current velocity
  - Velocity trend (accelerating / decelerating / steady)
  - Sprint forecast (how many 2-week sprints to completion)

Uses scan history and remediation tables. Pure stdlib.

Everything here is measured from this organization's own scans and
remediations. With no scanned asset there is no migration to have velocity:
the report returns ``available: false`` with a reason and the minimum needed,
and the projection, trend and recommendation are null. An empty workspace is
not a completed migration.
"""

from __future__ import annotations

import math
# `datetime` is called directly here (datetime.now, .fromisoformat, .strptime, and the constructor).
# It was originally imported as `from datetime import datetime, datetime as dt, ...`; the unused
# `dt` alias made an automated unused-import fix drop the plain binding instead, leaving five
# runtime NameErrors. The alias is gone and the name it shadowed is kept.
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

#: Fewest scanned assets before any velocity, projection or verdict is published.
MINIMUM_SCANNED_ASSETS = 1

UNAVAILABLE_REASON = (
    "No scanned assets on record, so there is no migration to measure velocity against. "
    "Run a TLS scan (or import a CBOM/SBOM) and velocity appears once remediations start closing."
)

_MINIMUM_DATA = {
    "scanned_assets": MINIMUM_SCANNED_ASSETS,
    "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
}


def _week_start(d: datetime) -> str:
    """Return ISO date string for Monday of the week containing d."""
    monday = d - timedelta(days=d.weekday())
    return monday.strftime("%Y-%m-%d")


def _unavailable_report(now: datetime) -> Dict[str, Any]:
    """The honest empty-workspace shape: same keys, no projection, no verdict."""
    return {
        "generated_at": now.isoformat(),
        "available": False,
        "reason": UNAVAILABLE_REASON,
        "minimum_data": dict(_MINIMUM_DATA),
        "snapshot": {
            "total_assets": 0,
            "quantum_safe_assets": 0,
            "quantum_vulnerable_assets": 0,
            "progress_pct": None,
        },
        "velocity": {
            "avg_4week_assets_per_week": None,
            "trend": None,
            "trend_pct": None,
            "weekly_history": [],
        },
        "projection": {
            "weeks_to_completion": None,
            "completion_date": None,
            "sprints_to_completion": None,
            "on_track_for_2030": None,
            "velocity_needed_for_2030": None,
            "velocity_gap": None,
            "days_to_2030": (datetime(2030, 1, 1, tzinfo=timezone.utc) - now).days,
        },
        "recommendation": None,
    }


def build_velocity_report(
    scans: List[Dict[str, Any]],
    remediations: List[Dict[str, Any]],
    total_known_assets: int = 0,
) -> Dict[str, Any]:
    """
    Build migration velocity report.

    scans         — list of scan rows (host, port, algorithm, scan_time, risk_level)
    remediations  — list of remediation rows (status, created_at, updated_at, target_host)
    total_known_assets — total asset count (0 = derived from scans)
    """
    now = datetime.now(timezone.utc)

    # ── Current vulnerability snapshot ────────────────────────────────────────
    # Deduplicate by host:port, keep latest scan
    seen: Dict[str, Dict[str, Any]] = {}
    for row in scans:
        key = f"{row.get('host', '')}:{row.get('port', '')}"
        existing = seen.get(key)
        if not existing:
            seen[key] = row
        else:
            # Keep later scan
            try:
                ts_new = row.get("scan_time", "") or ""
                ts_old = existing.get("scan_time", "") or ""
                if ts_new > ts_old:
                    seen[key] = row
            except Exception:
                pass

    total_assets = total_known_assets or len(seen)

    if total_assets < MINIMUM_SCANNED_ASSETS:
        return _unavailable_report(now)

    # "EC" and "ECC" were missing, and scan_results stores the certificate key type as the bare
    # "EC" for every elliptic-curve asset. Because the only two buckets were vulnerable and safe,
    # each of those assets was counted as *migrated*, which inflated the progress percentage.
    vulnerable_algo_names = {
        "RSA", "RSA-2048", "RSA-3072", "RSA-4096",
        "EC", "ECC", "ECDSA", "ECDH", "ECDH-256", "ECDH-384",
        "P-256", "P-384", "P-521", "DH", "DHE", "DSA",
        "ED25519", "ED448", "X25519", "X448", "EDDSA",
        "RC4", "DES", "3DES", "MD5", "SHA-1",
        "TLS-1.0", "TLS-1.1", "SSL-3.0",
    }
    # Post-quantum algorithms. Only an asset positively identified as one of these counts as
    # migrated; everything else is either vulnerable or unknown.
    pqc_safe_prefixes = (
        "ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM",
        "SLH-DSA", "SPHINCS", "FALCON", "NTRU", "BIKE", "HQC", "XMSS", "LMS",
    )

    def classify(algo: str) -> str:
        """vulnerable | migrated | unknown. A blank algorithm is never 'migrated'."""
        a = str(algo or "").upper().strip()
        if not a:
            return "unknown"
        if any(a.startswith(p) for p in pqc_safe_prefixes) or any(p in a for p in pqc_safe_prefixes):
            return "migrated"
        for v in vulnerable_algo_names:
            if a == v or a.startswith(v):
                return "vulnerable"
        return "unknown"

    buckets = {"vulnerable": 0, "migrated": 0, "unknown": 0}
    for r in seen.values():
        buckets[classify(str(r.get("algorithm") or r.get("cipher") or ""))] += 1

    current_vulnerable = buckets["vulnerable"]
    current_unknown = buckets["unknown"] + max(0, total_assets - len(seen))
    # Assets whose algorithm was never observed are not migrated. Counting them as safe is how an
    # estate of unscannable hosts reported itself part-way through its migration.
    current_safe = max(0, total_assets - current_vulnerable - current_unknown)

    # ── Weekly migration velocity from remediation data ───────────────────────
    # A "migrated" asset = a remediation resolved in that week
    weekly_counts: Dict[str, int] = {}
    for rem in remediations:
        status = (rem.get("status") or "").lower()
        if status not in ("resolved", "done", "closed", "completed", "fixed"):
            continue
        ts_str = rem.get("updated_at") or rem.get("resolved_at") or rem.get("created_at")
        if not ts_str:
            continue
        try:
            # Parse ISO timestamp
            ts_str_clean = str(ts_str).replace("Z", "+00:00")
            ts = datetime.fromisoformat(ts_str_clean)
        except Exception:
            try:
                ts = datetime.strptime(str(ts_str)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except Exception:
                continue
        week = _week_start(ts)
        weekly_counts[week] = weekly_counts.get(week, 0) + 1

    # Build 12-week history (fill zeros for weeks with no data)
    weeks_history = []
    for i in range(11, -1, -1):
        week_dt = now - timedelta(weeks=i)
        week_key = _week_start(week_dt)
        weeks_history.append({
            "week_start": week_key,
            "assets_migrated": weekly_counts.get(week_key, 0),
        })

    # Rolling 4-week average velocity
    recent_4 = [w["assets_migrated"] for w in weeks_history[-4:]]
    avg_4week = sum(recent_4) / 4 if recent_4 else 0

    # Trend: compare last 4 weeks vs prior 4 weeks
    prior_4 = [w["assets_migrated"] for w in weeks_history[-8:-4]]
    avg_prior = sum(prior_4) / 4 if prior_4 else 0
    trend: Optional[str]
    trend_pct: Optional[int]
    if avg_4week <= 0 and avg_prior <= 0:
        # Nothing has closed in eight weeks: there is no trend to name.
        trend = None
        trend_pct = None
    elif avg_4week > avg_prior * 1.15:
        trend = "accelerating"
        trend_pct = round((avg_4week / max(avg_prior, 0.01) - 1) * 100)
    elif avg_4week < avg_prior * 0.85:
        trend = "decelerating"
        trend_pct = round((1 - avg_4week / max(avg_prior, 0.01)) * 100)
    else:
        trend = "steady"
        trend_pct = 0

    # ── Projection ────────────────────────────────────────────────────────────
    if avg_4week > 0 and current_vulnerable > 0:
        weeks_to_completion = math.ceil(current_vulnerable / avg_4week)
        completion_date = (now + timedelta(weeks=weeks_to_completion)).strftime("%Y-%m-%d")
        sprints_to_completion = math.ceil(weeks_to_completion / 2)

        # CNSA 2030 deadline feasibility
        cnsa_deadline = datetime(2030, 1, 1, tzinfo=timezone.utc)
        days_to_completion = weeks_to_completion * 7
        completion_dt = now + timedelta(days=days_to_completion)
        on_track_for_2030 = completion_dt <= cnsa_deadline
    elif current_vulnerable == 0:
        weeks_to_completion = 0
        completion_date = now.strftime("%Y-%m-%d")
        sprints_to_completion = 0
        on_track_for_2030 = True
    else:
        # No velocity data — estimate based on team capacity
        weeks_to_completion = None
        completion_date = None
        sprints_to_completion = None
        on_track_for_2030 = False

    # ── Acceleration needed to hit 2030 ──────────────────────────────────────
    days_to_2030 = (datetime(2030, 1, 1, tzinfo=timezone.utc) - now).days
    weeks_to_2030 = days_to_2030 / 7
    needed_velocity = math.ceil(current_vulnerable / max(1, weeks_to_2030)) if current_vulnerable > 0 else 0

    # ── Progress percentage ───────────────────────────────────────────────────
    progress_pct = round((current_safe / max(1, total_assets)) * 100, 1)

    return {
        "generated_at": now.isoformat(),
        "available": True,
        "reason": "",
        "minimum_data": dict(_MINIMUM_DATA),
        "snapshot": {
            "total_assets": total_assets,
            "quantum_safe_assets": current_safe,
            "quantum_vulnerable_assets": current_vulnerable,
            # Assets whose cryptography was never observed. Reported, not folded into either side.
            "quantum_unknown_assets": current_unknown,
            "progress_pct": progress_pct,
        },
        "velocity": {
            "avg_4week_assets_per_week": round(avg_4week, 1),
            "trend": trend,
            "trend_pct": trend_pct,
            "weekly_history": weeks_history,
        },
        "projection": {
            "weeks_to_completion": weeks_to_completion,
            "completion_date": completion_date,
            "sprints_to_completion": sprints_to_completion,
            "on_track_for_2030": on_track_for_2030,
            "velocity_needed_for_2030": needed_velocity,
            "velocity_gap": max(0, needed_velocity - avg_4week),
            "days_to_2030": days_to_2030,
        },
        "recommendation": _recommendation(
            avg_4week, needed_velocity, current_vulnerable, trend
        ),
    }


def _recommendation(
    current_velocity: float,
    needed_velocity: float,
    vulnerable: int,
    trend: Optional[str],
) -> str:
    if vulnerable == 0:
        return "Migration complete — all scanned assets are quantum-safe. Schedule quarterly re-scans to catch regressions."

    gap = needed_velocity - current_velocity
    if gap <= 0:
        return (
            f"Current velocity ({current_velocity:.1f} assets/week) is sufficient to meet the CNSA 2.0 2030 deadline. "
            f"Maintain this pace and ensure new assets are scanned on intake."
        )

    if trend == "decelerating":
        return (
            f"Velocity is decelerating — from prior rate to {current_velocity:.1f} assets/week. "
            f"Need {needed_velocity:.1f}/week for 2030. Re-prioritize sprint backlog; consider automation-assisted remediation."
        )

    return (
        f"Need to increase from {current_velocity:.1f} to {needed_velocity:.1f} assets/week to hit CNSA 2.0 deadline. "
        f"Gap: {gap:.1f} assets/week. "
        f"Consider parallel-track remediation: automate TLS config updates for the {vulnerable} remaining vulnerable endpoints."
    )
