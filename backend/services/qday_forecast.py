"""
Q-Day Forecasting Engine

Builds the Q-Day forecast report from the Q-Intel model (services/q_intel.py),
which is the single source of Q-Day years and probabilities for the platform.

Everything here is a labelled model: the response carries ``model_basis`` with
the assumptions. No analyst-consensus percentages, vendor survey numbers, or
threat-actor intelligence are provided — the platform has no sourced basis for
them.

Pure stdlib — no numpy, scipy, or external dependencies.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List

from services import q_intel as _q_intel
from services.model_basis import model_basis as _model_basis


# CRQC resource targets used by the illustrative doubling-time trajectory.
_CRQC_LOGICAL_QUBITS_REQUIRED = 4098          # RSA-2048: 2n+2 (Häner et al. 2017)
_CRQC_PHYSICAL_QUBITS_REQUIRED_EST = 1_000_000  # Gidney 2025: "less than a million noisy qubits"
_PHYSICAL_DOUBLING_YEARS = 1.5   # assumption
_LOGICAL_DOUBLING_YEARS = 2.0    # assumption


def _milestones() -> List[Dict[str, Any]]:
    """Public milestones from the Q-Intel seed set, in this module's legacy shape."""
    out = []
    for m in _q_intel.list_seed_milestones():
        out.append({
            "year": int(str(m["date"])[:4]),
            "date": m["date"],
            "entity": m["org"],
            "system": m["system"],
            "qubits": m["qubit_count"],
            "logical": bool(m.get("logical_qubits_eq")),
            "logical_qubits": m.get("logical_qubits_eq") or 0,
            "headline": m["headline"],
            "source_url": m["source_url"],
            "is_seed": True,
        })
    return out


def _years_to_crqc(milestones: List[Dict[str, Any]], reference: Dict[str, Any]) -> Dict[str, Any]:
    """Illustrative doubling-time extrapolation toward CRQC resource targets."""
    current_physical = max((m["qubits"] for m in milestones), default=1)
    current_logical = max((m["logical_qubits"] for m in milestones), default=0) or 1
    base_year = max((m["year"] for m in milestones), default=datetime.now(timezone.utc).year)

    doublings_needed = math.log2(max(1.0, _CRQC_PHYSICAL_QUBITS_REQUIRED_EST / max(1, current_physical)))
    years_physical = doublings_needed * _PHYSICAL_DOUBLING_YEARS
    doublings_logical = math.log2(max(1.0, _CRQC_LOGICAL_QUBITS_REQUIRED / max(1, current_logical)))
    years_logical = doublings_logical * _LOGICAL_DOUBLING_YEARS
    years_blended = (years_physical * 0.4 + years_logical * 0.6)
    return {
        "physical_path_years": round(years_physical, 1),
        "logical_path_years": round(years_logical, 1),
        "blended_estimate_years": round(years_blended, 1),
        "trajectory_base_year": base_year,
        "trajectory_implied_year": base_year + round(years_blended),
        # The platform reference year comes from the Q-Intel model, not this trajectory.
        "estimated_crqc_year": reference.get("expected_year"),
        "confidence": "model",
        "note": (
            "Doubling-time extrapolation shown for comparison only. estimated_crqc_year is the Q-Intel "
            "model's 50% year, which every Q-Day view in the platform uses."
        ),
    }


def _distribution(curve: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for point in curve:
        pct = round(point["probability"] * 100)
        out.append({
            "year": point["year"],
            "cumulative_pct": pct,
            "label": f"Model: {pct}% probability RSA-2048 is breakable by this year",
        })
    return out


def forecast_model_basis(reference: Dict[str, Any]) -> Dict[str, Any]:
    base = _q_intel.model_basis_for()
    return _model_basis(
        kind="model",
        summary=(
            "Q-Day probabilities and years are the Q-Intel model's illustrative projection for RSA-2048; "
            "they are not a prediction or a consensus of analysts, and no threat-actor intelligence is included."
        ),
        assumptions=base["assumptions"] + [
            f"Doubling-time trajectory: physical qubits double every {_PHYSICAL_DOUBLING_YEARS} years toward "
            f"{_CRQC_PHYSICAL_QUBITS_REQUIRED_EST:,} noisy qubits; logical qubits double every "
            f"{_LOGICAL_DOUBLING_YEARS} years toward {_CRQC_LOGICAL_QUBITS_REQUIRED:,}; blended 40/60.",
            "Data longevity windows by sensitivity (low 2y, medium 7y, high 15y, critical 25y) are planning defaults.",
            "Decryption time for harvested traffic is not estimated: it depends on the number of distinct "
            "session keys, not on data volume.",
        ],
        sources=base["sources"],
        as_of=_q_intel.MODEL_AS_OF,
    )


def build_qday_forecast(
    org_scan_count: int = 0,
    hndl_exposure_gb: float = 0.0,
    data_sensitivity: str = "medium",
) -> Dict[str, Any]:
    """
    Build the full Q-Day forecast report.

    org_scan_count       — number of unique assets scanned
    hndl_exposure_gb     — estimated GB of traffic captured by adversaries
    data_sensitivity     — low / medium / high / critical
    """
    now = datetime.now(timezone.utc)
    ms_rows = _q_intel._load_milestones()
    reference = _q_intel.q_day_reference("rsa2048", ms_rows)
    milestones = _milestones()
    crqc = _years_to_crqc(milestones, reference)
    days_until_2030 = (datetime(2030, 1, 1, tzinfo=timezone.utc) - now).days

    # Data longevity risk — how long must data remain secret?
    longevity_risk = {
        "low": {"years": 2, "label": "Short-lived data"},
        "medium": {"years": 7, "label": "Business records / PII"},
        "high": {"years": 15, "label": "IP / trade secrets"},
        "critical": {"years": 25, "label": "National security / long-lived credentials"},
    }.get(data_sensitivity, {"years": 7, "label": "Business records"})

    current_year = now.year
    curve = _q_intel.probability_curve("rsa2048", list(range(current_year, current_year + 21)), ms_rows)
    target_year = current_year + longevity_risk["years"]
    prob = round(_q_intel.get_q_day_probability("rsa2048", target_year) * 100)

    risk_color = "green" if prob < 10 else "yellow" if prob < 30 else "orange" if prob < 60 else "red"

    if prob >= 60:
        urgency = "IMMEDIATE — under this model, Q-Day is more likely than not within your data's confidentiality window"
    elif prob >= 30:
        urgency = "HIGH — start migration now; CNSA 2.0 target dates fall within this window"
    elif prob >= 10:
        urgency = "MEDIUM — begin planning against the CNSA 2.0 target dates"
    else:
        urgency = "LOW — the model places Q-Day beyond this window, but a roadmap is still required"

    hndl_impact = None
    if hndl_exposure_gb > 0:
        hndl_impact = {
            "exposure_gb": hndl_exposure_gb,
            "estimated_decrypt_hours_at_qday": None,
            "note": (
                "Decryption time is not estimated. It depends on how many distinct session keys protect the "
                "captured traffic, not on its volume."
            ),
        }

    return {
        "generated_at": now.isoformat(),
        "crqc_trajectory": crqc,
        "distribution": _distribution(curve),
        "milestones": milestones,
        "threat_actors": [],
        "threat_actors_note": (
            "Threat-actor intelligence is not provided. The platform has no sourced basis for attributing "
            "harvest-now-decrypt-later activity to named actors."
        ),
        "org_context": {
            "scan_count": org_scan_count,
            "data_sensitivity": data_sensitivity,
            "data_longevity_years": longevity_risk["years"],
            "data_longevity_label": longevity_risk["label"],
            "qday_probability_within_window_pct": prob,
            "risk_color": risk_color,
            "urgency": urgency,
        },
        "hndl_exposure": hndl_impact,
        "key_dates": {
            "cnsa_2030_deadline": "2030-01-01",
            "cnsa_2030_days_remaining": days_until_2030,
            "estimated_crqc_year": reference.get("expected_year"),
            "nist_pq_standards_finalized": "2024-08-13",
        },
        "reference_years": reference,
        "recommendation": _recommendation(prob, days_until_2030),
        "model_basis": forecast_model_basis(reference),
    }


def _recommendation(prob: float, days_until_2030: int) -> str:
    if prob >= 60:
        return (
            "Under this model, HNDL risk falls within your data's required confidentiality window. "
            "Prioritize TLS endpoints carrying sensitive long-lived data. "
            "Deploy ML-KEM-768 for key exchange and ML-DSA-65 for signatures."
        )
    if prob >= 30 or days_until_2030 < 1460:
        return (
            "CNSA 2.0 target dates fall within or near your data retention window. "
            "Adopt a phased migration: (1) hybrid TLS with X25519MLKEM768 where your providers support it, "
            "(2) retire RSA < 3072 and classical ECDH on long-lived data paths, "
            "(3) cover FIPS 203/204/205 across remaining systems."
        )
    return (
        "Begin a post-quantum roadmap aligned to the CNSA 2.0 target dates. "
        "Start with a crypto-agility assessment, then pilot ML-KEM-768 on lowest-risk endpoints."
    )


def get_forecast(org_id: str = "", data_sensitivity: str = "medium") -> Dict[str, Any]:
    """Compact forecast used by the AI assistant tool."""
    result = build_qday_forecast(data_sensitivity=data_sensitivity)
    return {
        "organization_id": org_id,
        "estimated_crqc_year": result["key_dates"]["estimated_crqc_year"],
        "reference_years": result["reference_years"],
        "qday_probability_within_window_pct": result["org_context"]["qday_probability_within_window_pct"],
        "data_longevity_years": result["org_context"]["data_longevity_years"],
        "urgency": result["org_context"]["urgency"],
        "recommendation": result["recommendation"],
        "model_basis": result["model_basis"],
    }


def list_milestones() -> List[Dict[str, Any]]:
    return sorted(_milestones(), key=lambda m: m["date"], reverse=True)


def milestones_model_basis() -> Dict[str, Any]:
    return _q_intel.feed_model_basis()


def list_threat_actors() -> List[Dict[str, Any]]:
    """Threat-actor intelligence is not provided (no sourced basis)."""
    return []


def threat_actors_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="reference",
        summary=(
            "Threat-actor intelligence is not provided. Naming actors or attributing harvesting activity "
            "requires sourced intelligence the platform does not have."
        ),
        assumptions=[],
        sources=[],
        as_of=_q_intel.MODEL_AS_OF,
    )
