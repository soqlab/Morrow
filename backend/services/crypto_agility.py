"""
CryptoFlex Score — Crypto Agility Index

Measures how quickly and completely an organization can respond to a
cryptographic emergency (algorithm break, Q-Day announcement, zero-day).

Five dimensions (each 0-100):

1. Automation Coverage   — % of assets under continuous automated scanning
2. Algorithm Diversity   — Shannon entropy of algorithm distribution (more diversity
                           = no single-point-of-failure if one algo is broken)
3. Deployment Velocity   — Remediation cycle time (days detection → fix); faster = higher score
4. Emergency Readiness   — Coverage of active defenses: CI/CD gate, canary tokens, playbooks
5. HNDL Exposure         — Volume of quantum-vulnerable data in transit (inverted: less = higher score)

Composite CryptoFlex Score: weighted average, 0–100.
Classification:
  0–29  Crypto-Rigid    — emergency response >6 months; catastrophic Q-Day impact
  30–49 Crypto-Aware    — partial automation; 3-6 month response window
  50–69 Crypto-Agile    — meaningful automation; 1-3 month response
  70–89 Crypto-Ready    — near-full automation; <1 month response
  90+   Crypto-Native   — algorithm swap drillable in days

Every dimension is measured from this organization's own scan, remediation and
tooling records. There is no peer, sector or industry comparison: the platform
receives no other organization's posture, so it publishes no percentile,
quartile or "sector average".

The score needs evidence. With no scanned asset on record the report returns
``available: false`` with a reason and the minimum needed, and every score,
classification and recommendation field is null — a workspace with nothing in
it is not "Crypto-Rigid", it is unmeasured.

Pure stdlib — no external dependencies.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from services.model_basis import model_basis as _model_basis

#: Fewest scanned assets before any dimension or composite score is published.
MINIMUM_SCANNED_ASSETS = 1

_UNAVAILABLE_REASON = (
    "No scanned assets on record for this organization, so crypto-agility cannot be measured. "
    "Run a TLS scan (or import a CBOM/SBOM) and the score appears on the next report."
)


# Dimension weights (must sum to 1.0)
_WEIGHTS = {
    "automation_coverage": 0.25,
    "algorithm_diversity":  0.15,
    "deployment_velocity":  0.30,   # strongest predictor of real-world agility
    "emergency_readiness":  0.20,
    "hndl_exposure":        0.10,
}


# ── Dimension calculators ───────────────────────────────────────────────────────

def _score_automation(
    total_assets: int,
    scanned_assets: int,
    scan_frequency_days: Optional[float],
) -> Tuple[Optional[float], Dict[str, Any]]:
    """
    Score based on what fraction of assets are being continuously scanned
    and how often scans run.

    ``scan_frequency_days`` is None until two scans have been recorded — a
    cadence cannot be measured from a single scan. In that case the dimension
    scores on coverage alone and says so, instead of assuming a cadence.
    """
    if total_assets <= 0:
        return None, {
            "coverage_pct": None,
            "scan_frequency_days": None,
            "frequency_score": None,
            "available": False,
            "reason": "No scanned assets, so scanning coverage cannot be measured.",
            "minimum_data": f"at least {MINIMUM_SCANNED_ASSETS} scanned asset",
        }

    coverage_pct = min(100.0, (scanned_assets / total_assets) * 100)

    if scan_frequency_days is None:
        return round(coverage_pct, 1), {
            "coverage_pct": round(coverage_pct, 1),
            "scan_frequency_days": None,
            "frequency_score": None,
            "available": True,
            "note": "Scored on coverage only: a scan cadence needs at least two scans to measure.",
        }

    # Frequency bonus: daily=100, weekly=80, monthly=50, quarterly=20
    if scan_frequency_days <= 1:
        freq_score = 100
    elif scan_frequency_days <= 7:
        freq_score = 80
    elif scan_frequency_days <= 30:
        freq_score = 50
    elif scan_frequency_days <= 90:
        freq_score = 20
    else:
        freq_score = 5

    score = coverage_pct * 0.7 + freq_score * 0.3
    return round(score, 1), {
        "coverage_pct": round(coverage_pct, 1),
        "scan_frequency_days": round(scan_frequency_days, 1),
        "frequency_score": freq_score,
        "available": True,
    }


def _score_diversity(algorithms: List[str]) -> Tuple[Optional[float], Dict[str, Any]]:
    """
    Shannon entropy of algorithm distribution.
    More spread = more agile (no single algorithm is a single point of failure).
    Target: 3+ distinct algorithms in use (mix of PQC + classical during transition).
    Max entropy normalized to 100.
    """
    if not algorithms:
        # No algorithm was recorded on any scan: that is missing evidence, not
        # a measured absence of diversity.
        return None, {
            "unique_algorithms": 0,
            "entropy": None,
            "entropy_max": None,
            "available": False,
            "reason": "No algorithm was recorded on any scan, so algorithm diversity cannot be measured.",
            "minimum_data": "at least 1 scan result carrying an algorithm or cipher",
        }

    counts: Dict[str, int] = {}
    for a in algorithms:
        counts[a] = counts.get(a, 0) + 1

    n = len(algorithms)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    unique = len(counts)
    max_entropy = math.log2(max(unique, 1))
    # Normalize: perfect entropy at 6+ distinct algorithms → score 100
    target_entropy = math.log2(6)
    normalized = min(100.0, (entropy / max(target_entropy, 0.001)) * 100)

    # Penalty if >80% of assets use a single quantum-vulnerable algorithm
    top_algo = max(counts, key=counts.get)
    top_pct = (counts[top_algo] / n) * 100
    if top_pct > 80:
        normalized = max(0, normalized - 30)  # concentration penalty

    return round(normalized, 1), {
        "unique_algorithms": unique,
        "top_algorithm": top_algo,
        "top_algorithm_pct": round(top_pct, 1),
        "shannon_entropy": round(entropy, 3),
        "max_possible_entropy": round(max_entropy, 3),
        "available": True,
    }


def _score_velocity(
    avg_remediation_days: Optional[float],
    open_remediations: int,
    resolved_remediations: int,
) -> Tuple[Optional[float], Dict[str, Any]]:
    """
    Score based on how fast findings are remediated.
    Sub-7-day average = 100; 90+ days = 5.

    With no resolved remediation on record there is nothing to time, so the
    dimension is unmeasured (None) rather than given a default. An empty
    backlog is not evidence of speed.
    """
    if avg_remediation_days is None:
        return None, {
            "avg_days_to_resolve": None,
            "open_count": open_remediations,
            "resolved_count": resolved_remediations,
            "available": False,
            "reason": "No remediation has been resolved yet, so there is no cycle time to measure.",
            "minimum_data": "at least 1 resolved remediation",
            "note": "Insufficient remediation history for velocity measurement",
        }

    # Velocity curve (days → score)
    if avg_remediation_days <= 7:
        score = 100
    elif avg_remediation_days <= 14:
        score = 90
    elif avg_remediation_days <= 30:
        score = 70
    elif avg_remediation_days <= 60:
        score = 45
    elif avg_remediation_days <= 90:
        score = 25
    else:
        score = 10

    # Backlog penalty
    if open_remediations > 50:
        score = max(5, score - 20)
    elif open_remediations > 20:
        score = max(5, score - 10)

    return round(float(score), 1), {
        "avg_days_to_resolve": round(avg_remediation_days, 1),
        "open_count": open_remediations,
        "resolved_count": resolved_remediations,
        "available": True,
    }


def _score_readiness(
    has_cicd_gate: bool,
    canary_token_count: int,
    playbook_count: int,
    alert_rule_count: int,
    has_security_intent: bool,
) -> Tuple[float, Dict[str, Any]]:
    """
    Score based on defensive tooling coverage.
    """
    points = 0
    max_points = 0

    checks = [
        ("CI/CD PQC gate configured", has_cicd_gate, 25),
        ("Canary tokens deployed (5+)", canary_token_count >= 5, 20),
        ("Remediation playbooks (3+)", playbook_count >= 3, 20),
        ("Alert rules configured (3+)", alert_rule_count >= 3, 20),
        ("Security intent published", has_security_intent, 15),
    ]

    details = []
    for label, met, weight in checks:
        max_points += weight
        if met:
            points += weight
        details.append({"check": label, "met": met, "weight": weight})

    score = (points / max_points * 100) if max_points else 0
    return round(score, 1), {"checks": details, "score_raw": f"{points}/{max_points}", "available": True}


def _score_hndl(
    quantum_vulnerable_asset_count: int,
    total_asset_count: int,
    critical_vuln_count: int,
) -> Tuple[Optional[float], Dict[str, Any]]:
    """
    Inverted score: fewer quantum-vulnerable assets = higher score.

    With no scanned asset there is no exposure to invert, so the dimension is
    unmeasured (None) rather than given a mid-scale default.
    """
    if total_asset_count <= 0:
        return None, {
            "vulnerable_pct": None,
            "available": False,
            "reason": "No scanned assets, so quantum-vulnerable exposure cannot be measured.",
            "minimum_data": f"at least {MINIMUM_SCANNED_ASSETS} scanned asset",
            "note": "No scan data",
        }

    vuln_pct = (quantum_vulnerable_asset_count / total_asset_count) * 100
    critical_pct = (critical_vuln_count / total_asset_count) * 100

    # 0% vulnerable = 100; 100% vulnerable = 0
    base = max(0, 100 - vuln_pct)
    # Critical penalty
    penalty = critical_pct * 0.5
    score = max(0, base - penalty)

    return round(score, 1), {
        "vulnerable_pct": round(vuln_pct, 1),
        "critical_pct": round(critical_pct, 1),
        "quantum_vulnerable_count": quantum_vulnerable_asset_count,
        "total_assets": total_asset_count,
        "available": True,
    }


# ── Composite ──────────────────────────────────────────────────────────────────

def _classify(score: float) -> Tuple[str, str]:
    if score >= 90:
        return "Crypto-Native", "Algorithm swap drillable in days"
    if score >= 70:
        return "Crypto-Ready", "Near-full automation; sub-4-week emergency response capable"
    if score >= 50:
        return "Crypto-Agile", "Meaningful automation; 1-3 month emergency response"
    if score >= 30:
        return "Crypto-Aware", "Partial automation; 3-6 month emergency response window"
    return "Crypto-Rigid", "Minimal automation; >6 month response; catastrophic Q-Day exposure"


#: Why no peer figure is served. Kept as one constant so the API, the console
#: and the guide all say the same thing.
NO_PEER_COMPARISON_REASON = (
    "No sector, industry or peer comparison is available: the platform receives no other "
    "organization's posture, so it can publish no percentile, quartile or sector average."
)


def agility_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="model",
        summary=(
            "Every dimension is measured from this organization's own records; the weights and "
            "the score-to-classification bands are the platform's own scoring choices, not a "
            "measured or published benchmark."
        ),
        assumptions=[
            f"{dim} weighted {weight:.0%} of the composite" for dim, weight in _WEIGHTS.items()
        ] + [
            "Dimensions with no evidence are left unmeasured and excluded; the remaining weights are renormalized.",
            f"No composite score is published below {MINIMUM_SCANNED_ASSETS} scanned asset.",
            NO_PEER_COMPARISON_REASON,
        ],
        sources=[],
        as_of="2026-09",
    )


def _unavailable_report(reason: str, dimension_details: Dict[str, Any]) -> Dict[str, Any]:
    """The honest empty-workspace shape: same keys, no invented numbers."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "available": False,
        "reason": reason,
        "minimum_data": {
            "scanned_assets": MINIMUM_SCANNED_ASSETS,
            "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
        },
        "cryptoflex_score": None,
        "classification": None,
        "description": reason,
        "dimensions": {
            dim: {
                "score": None,
                "weight": _WEIGHTS[dim],
                "weighted_contribution": None,
                "available": False,
            }
            for dim in _WEIGHTS
        },
        "dimension_details": dimension_details,
        "measured_dimensions": [],
        "unmeasured_dimensions": sorted(_WEIGHTS),
        "weakest_dimension": None,
        "top_recommendation": None,
        "emergency_response_estimate": None,
        "industry_comparison": {
            "available": False,
            "reason": NO_PEER_COMPARISON_REASON,
            "your_score": None,
        },
        "model_basis": agility_model_basis(),
    }


def build_crypto_agility_report(
    # Asset / scan data
    total_assets: int = 0,
    scanned_assets: int = 0,
    scan_frequency_days: Optional[float] = None,
    algorithms_in_use: Optional[List[str]] = None,
    quantum_vulnerable_count: int = 0,
    critical_vuln_count: int = 0,
    # Remediation data
    avg_remediation_days: Optional[float] = None,
    open_remediations: int = 0,
    resolved_remediations: int = 0,
    # Defensive tooling
    has_cicd_gate: bool = False,
    canary_token_count: int = 0,
    playbook_count: int = 0,
    alert_rule_count: int = 0,
    has_security_intent: bool = False,
) -> Dict[str, Any]:

    algorithms_in_use = algorithms_in_use or []

    auto_score, auto_detail = _score_automation(total_assets, scanned_assets, scan_frequency_days)
    div_score, div_detail = _score_diversity(algorithms_in_use)
    vel_score, vel_detail = _score_velocity(avg_remediation_days, open_remediations, resolved_remediations)
    ready_score, ready_detail = _score_readiness(
        has_cicd_gate, canary_token_count, playbook_count, alert_rule_count, has_security_intent
    )
    hndl_score, hndl_detail = _score_hndl(quantum_vulnerable_count, total_assets, critical_vuln_count)

    dim_scores: Dict[str, Optional[float]] = {
        "automation_coverage": auto_score,
        "algorithm_diversity": div_score,
        "deployment_velocity": vel_score,
        "emergency_readiness": ready_score,
        "hndl_exposure": hndl_score,
    }

    dimension_details = {
        "automation_coverage": auto_detail,
        "algorithm_diversity": div_detail,
        "deployment_velocity": vel_detail,
        "emergency_readiness": ready_detail,
        "hndl_exposure": hndl_detail,
    }

    # Nothing scanned → nothing to score. An empty workspace is unmeasured, not rigid.
    if total_assets < MINIMUM_SCANNED_ASSETS:
        return _unavailable_report(_UNAVAILABLE_REASON, dimension_details)

    measured = {d: s for d, s in dim_scores.items() if s is not None}
    unmeasured = sorted(d for d, s in dim_scores.items() if s is None)

    # Renormalize over the dimensions that actually have evidence, so an
    # unmeasured dimension neither helps nor hurts the composite.
    measured_weight = sum(_WEIGHTS[d] for d in measured)
    composite = round(
        sum(measured[d] * _WEIGHTS[d] for d in measured) / measured_weight, 1
    ) if measured_weight > 0 else None

    if composite is None:
        return _unavailable_report(
            "No crypto-agility dimension could be measured from the evidence on record yet.",
            dimension_details,
        )

    label, description = _classify(composite)

    # Weakest dimension → top recommendation
    weakest_dim = min(measured, key=lambda d: measured[d])
    recommendations = {
        "automation_coverage": "Enroll all network assets in continuous scanning; target sub-24-hour scan cadence.",
        "algorithm_diversity": "Introduce hybrid PQC algorithms (X25519MLKEM768) alongside classical ones to increase crypto diversity.",
        "deployment_velocity": "Integrate auto-remediation triggers; target <7-day mean-time-to-remediate for critical findings.",
        "emergency_readiness": "Deploy CI/CD PQC gate, canary tokens on 5+ endpoints, and publish a security intent.",
        "hndl_exposure": "Prioritize replacing RSA/ECDH key exchange on externally-facing TLS endpoints immediately.",
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "available": True,
        "reason": "",
        "minimum_data": {
            "scanned_assets": MINIMUM_SCANNED_ASSETS,
            "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
        },
        "cryptoflex_score": composite,
        "classification": label,
        "description": description,
        "dimensions": {
            dim: {
                "score": dim_scores[dim],
                "weight": _WEIGHTS[dim],
                "weighted_contribution": (
                    round(dim_scores[dim] * _WEIGHTS[dim] / measured_weight, 1)
                    if dim_scores[dim] is not None else None
                ),
                "available": dim_scores[dim] is not None,
            }
            for dim in dim_scores
        },
        "dimension_details": dimension_details,
        "measured_dimensions": sorted(measured),
        "unmeasured_dimensions": unmeasured,
        "weakest_dimension": weakest_dim,
        "top_recommendation": recommendations[weakest_dim],
        "emergency_response_estimate": _emergency_estimate(composite),
        "industry_comparison": {
            "available": False,
            "reason": NO_PEER_COMPARISON_REASON,
            "your_score": composite,
        },
        "model_basis": agility_model_basis(),
    }


def _emergency_estimate(score: float) -> str:
    if score >= 90:
        return "< 1 week — full algorithm replacement drillable"
    if score >= 70:
        return "2–4 weeks — automated rollout with manual verification"
    if score >= 50:
        return "1–3 months — semi-automated with significant manual steps"
    if score >= 30:
        return "3–6 months — largely manual; significant downtime risk"
    return "> 6 months — high risk of extended outage or data exposure during crypto emergency"
