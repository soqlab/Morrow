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

Deadlines: ``projection.milestones`` has one entry per named milestone the organization tracks
(services/migration_milestones: its own list, or the NIST IR 8547 2030 / 2035 defaults, whose
sources are cited there). Each entry says whether the projected completion lands on or before
that milestone, the weekly velocity needed to make it, the gap to the current velocity, the days
left, and the margin between projected completion and the deadline.

The older single-deadline keys (``on_track_for_2030``, ``velocity_needed_for_2030``,
``velocity_gap``, ``days_to_2030``) are still published with their original meaning, measured
against 1 January 2030, for consumers written before milestones existed. New consumers read
``projection.milestones``.

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


#: The one deadline the report knew before milestones were configurable. Kept only so the legacy
#: ``*_2030`` keys keep their original meaning; it is not a default milestone.
LEGACY_DEADLINE = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _deadline(milestone_date: str) -> datetime:
    """A milestone dated D is met by work finished during D: the deadline is the end of that day (UTC)."""
    d = datetime.strptime(str(milestone_date)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return d + timedelta(days=1)


def _resolve_milestones(milestones: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if milestones is None:
        from services.migration_milestones import defaults
        milestones = defaults()
    usable = []
    for m in milestones:
        try:
            _deadline(m.get("date"))
        except (TypeError, ValueError):
            continue
        usable.append(m)
    return sorted(usable, key=lambda m: str(m.get("date")))


def _milestone_base(m: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    deadline = _deadline(m["date"])
    return {
        "id": m.get("id") or "",
        "name": m.get("name") or m["date"],
        "date": str(m["date"])[:10],
        "scope": m.get("scope") or "",
        "source": m.get("source") or "",
        "source_url": m.get("source_url") or "",
        "days_left": (deadline - now).days,
        "passed": deadline <= now,
    }


def _milestone_unmeasured(m: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    return {**_milestone_base(m, now), "status": "not_measured", "on_track": None,
            "velocity_needed": None, "velocity_gap": None,
            "projected_completion_date": None, "projected_margin_days": None}


def _milestone_measured(
    m: Dict[str, Any],
    now: datetime,
    *,
    vulnerable: int,
    avg_velocity: float,
    completion_dt: Optional[datetime],
) -> Dict[str, Any]:
    row = _milestone_base(m, now)
    deadline = _deadline(m["date"])
    margin = (deadline - completion_dt).days if completion_dt is not None else None
    completion = completion_dt.strftime("%Y-%m-%d") if completion_dt is not None else None
    if vulnerable == 0:
        return {**row, "status": "complete", "on_track": True, "velocity_needed": 0, "velocity_gap": 0,
                "projected_completion_date": completion, "projected_margin_days": margin}
    if row["passed"]:
        # The date has gone and vulnerable assets remain: no velocity can meet it any more.
        return {**row, "status": "missed", "on_track": False, "velocity_needed": None, "velocity_gap": None,
                "projected_completion_date": completion, "projected_margin_days": margin}
    weeks_left = (deadline - now).total_seconds() / (7 * 86400)
    needed = math.ceil(vulnerable / max(1, weeks_left))
    gap = round(max(0.0, needed - avg_velocity), 1)
    on_track = completion_dt is not None and completion_dt <= deadline
    status = "on_track" if on_track else ("no_velocity" if completion_dt is None else "behind")
    return {**row, "status": status, "on_track": on_track, "velocity_needed": needed, "velocity_gap": gap,
            "projected_completion_date": completion, "projected_margin_days": margin}


def _week_start(d: datetime) -> str:
    """Return ISO date string for Monday of the week containing d."""
    monday = d - timedelta(days=d.weekday())
    return monday.strftime("%Y-%m-%d")


def _unavailable_report(now: datetime, milestones: List[Dict[str, Any]]) -> Dict[str, Any]:
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
            "milestones": [_milestone_unmeasured(m, now) for m in milestones],
            "next_milestone": _next_milestone_id(milestones, now),
            # Legacy single-deadline keys (see the module docstring).
            "on_track_for_2030": None,
            "velocity_needed_for_2030": None,
            "velocity_gap": None,
            "days_to_2030": (LEGACY_DEADLINE - now).days,
        },
        "recommendation": None,
    }


def _next_milestone_id(milestones: List[Dict[str, Any]], now: datetime) -> Optional[str]:
    upcoming = [m for m in milestones if _deadline(m["date"]) > now]
    return (upcoming[0].get("id") or upcoming[0]["date"]) if upcoming else None


def build_velocity_report(
    scans: List[Dict[str, Any]],
    remediations: List[Dict[str, Any]],
    total_known_assets: int = 0,
    milestones: Optional[List[Dict[str, Any]]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build migration velocity report.

    scans         — list of scan rows (host, port, algorithm, scan_time, risk_level)
    remediations  — list of remediation rows (status, created_at, updated_at, target_host)
    total_known_assets — total asset count (0 = derived from scans)
    milestones    — the organization's deadlines ({name, date, scope, ...}); None = the defaults
                    in services/migration_milestones
    now           — the moment to measure from (tests); defaults to the current time
    """
    now = now or datetime.now(timezone.utc)
    deadlines = _resolve_milestones(milestones)

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
        return _unavailable_report(now, deadlines)

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
    pq_safe_prefixes = (
        "ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM",
        "SLH-DSA", "SPHINCS", "FALCON", "NTRU", "BIKE", "HQC", "XMSS", "LMS",
    )

    def classify(algo: str) -> str:
        """vulnerable | migrated | unknown. A blank algorithm is never 'migrated'."""
        a = str(algo or "").upper().strip()
        if not a:
            return "unknown"
        if any(a.startswith(p) for p in pq_safe_prefixes) or any(p in a for p in pq_safe_prefixes):
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
        if status not in ("resolved", "done", "closed", "completed", "fixed", "verified_closed"):
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
    completion_dt: Optional[datetime]
    if avg_4week > 0 and current_vulnerable > 0:
        weeks_to_completion = math.ceil(current_vulnerable / avg_4week)
        completion_date = (now + timedelta(weeks=weeks_to_completion)).strftime("%Y-%m-%d")
        sprints_to_completion = math.ceil(weeks_to_completion / 2)
        completion_dt = now + timedelta(days=weeks_to_completion * 7)
        on_track_for_2030 = completion_dt <= LEGACY_DEADLINE
    elif current_vulnerable == 0:
        weeks_to_completion = 0
        completion_date = now.strftime("%Y-%m-%d")
        sprints_to_completion = 0
        completion_dt = now
        on_track_for_2030 = True
    else:
        # No completed remediation in four weeks: no rate, so no projected date.
        weeks_to_completion = None
        completion_date = None
        sprints_to_completion = None
        completion_dt = None
        on_track_for_2030 = False

    # ── Each milestone: on track, velocity needed, gap, days left, margin ────
    milestone_rows = [
        _milestone_measured(m, now, vulnerable=current_vulnerable, avg_velocity=avg_4week,
                            completion_dt=completion_dt)
        for m in deadlines
    ]

    # ── Legacy: acceleration needed to hit 1 January 2030 ────────────────────
    days_to_2030 = (LEGACY_DEADLINE - now).days
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
            "milestones": milestone_rows,
            "next_milestone": _next_milestone_id(deadlines, now),
            # Legacy single-deadline keys, measured against 1 January 2030 (see the module docstring).
            "on_track_for_2030": on_track_for_2030,
            "velocity_needed_for_2030": needed_velocity,
            "velocity_gap": max(0, needed_velocity - avg_4week),
            "days_to_2030": days_to_2030,
        },
        "recommendation": _recommendation(
            avg_4week, current_vulnerable, trend, milestone_rows
        ),
    }


def _recommendation(
    current_velocity: float,
    vulnerable: int,
    trend: Optional[str],
    milestones: List[Dict[str, Any]],
) -> str:
    if vulnerable == 0:
        return "Migration complete — all scanned assets are quantum-safe. Schedule quarterly re-scans to catch regressions."

    upcoming = [m for m in milestones if not m["passed"]]
    if not upcoming:
        missed = milestones[-1]["name"] if milestones else "every configured deadline"
        return (
            f"{vulnerable} assets are still quantum-vulnerable and {missed} has passed. "
            f"Add the next deadline you are working to, and prioritize the remaining endpoints by exposure."
        )

    # The nearest milestone still ahead is the one the team has to plan the next sprints against.
    target = upcoming[0]
    needed_velocity = float(target["velocity_needed"] or 0)
    gap = needed_velocity - current_velocity
    if gap <= 0:
        later_behind = [m["name"] for m in upcoming[1:] if m["on_track"] is False]
        tail = f" Later milestones behind: {', '.join(later_behind)}." if later_behind else ""
        return (
            f"Current velocity ({current_velocity:.1f} assets/week) is sufficient to meet {target['name']} "
            f"({target['date']}). Maintain this pace and ensure new assets are scanned on intake.{tail}"
        )

    if trend == "decelerating":
        return (
            f"Velocity is decelerating — from prior rate to {current_velocity:.1f} assets/week. "
            f"Need {needed_velocity:.1f}/week for {target['name']} ({target['date']}). "
            f"Re-prioritize sprint backlog; consider automation-assisted remediation."
        )

    return (
        f"Need to increase from {current_velocity:.1f} to {needed_velocity:.1f} assets/week to meet "
        f"{target['name']} ({target['date']}). Gap: {gap:.1f} assets/week. "
        f"Consider parallel-track remediation: automate TLS config updates for the {vulnerable} remaining vulnerable endpoints."
    )
