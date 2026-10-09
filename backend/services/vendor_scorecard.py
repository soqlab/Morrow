"""
Vendor PQC Scorecard

Vendor PQC readiness is shown only from evidence your organization holds:
its own vendor assessments and vendor attestations. The platform does not
publish its own scores for named third-party companies — subjective ratings
of real vendors are not sourced and are not presented.

These functions keep the scorecard API contract (dimensions, weights, tiers)
and return no vendors, with model_basis explaining where scores come from.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.model_basis import model_basis as _model_basis


_CATEGORY_NAMES = {
    "cloud": "Cloud Providers",
    "pki_ca": "PKI / Certificate Authorities",
    "hsm": "Hardware Security Modules",
    "tls_library": "TLS Libraries",
    "secrets_mgmt": "Secrets Management",
    "edr_security": "Security / EDR",
    "network_security": "Network Security",
    "vpn": "VPN / Network Tunneling",
    "developer_tools": "Developer Tools",
    "identity": "Identity / SSO",
    "cdn_security": "CDN / Edge Security",
}

_SCORE_WEIGHTS = {
    "algorithm_support":     0.25,
    "tls_support":           0.25,
    "hsm_support":           0.15,
    "roadmap_clarity":       0.15,
    "standards_participation": 0.10,
    "customer_tooling":      0.10,
}

_DIMENSION_LABELS = {
    "algorithm_support":     "Algorithm Support",
    "tls_support":           "TLS / Key Exchange",
    "hsm_support":           "HSM / KMS Support",
    "roadmap_clarity":       "Roadmap Clarity",
    "standards_participation": "Standards Participation",
    "customer_tooling":      "Customer Tooling",
}


def scorecard_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="reference",
        summary=(
            "No platform-authored vendor scores are shown. Vendor readiness comes only from your organization's "
            "own vendor assessments and attestations."
        ),
        assumptions=[
            "Dimension weights (if you score vendors yourself): " + ", ".join(
                f"{_DIMENSION_LABELS[d]} {w:.0%}" for d, w in _SCORE_WEIGHTS.items()
            ) + ".",
        ],
        sources=[],
        as_of="2026-09",
    )


def get_all_vendors(
    category: Optional[str] = None,
    sort_by: str = "composite",
) -> Dict[str, Any]:
    """No platform-authored vendor scores; see scorecard_model_basis()."""
    return {
        "vendors": [],
        "total": 0,
        "pqc_ready_count": 0,
        "avg_composite_score": None,
        "categories": [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score_dimensions": _DIMENSION_LABELS,
        "model_basis": scorecard_model_basis(),
    }


def get_vendor(vendor_id: str) -> Optional[Dict[str, Any]]:
    """No platform-authored vendor scores exist, so no vendor is found."""
    return None


def compare_vendors(vendor_ids: List[str]) -> Dict[str, Any]:
    return {
        "vendors": [],
        "requested_vendor_ids": list(vendor_ids[:4]),
        "dimensions": list(_DIMENSION_LABELS.items()),
        "best_per_dimension": {},
        "model_basis": scorecard_model_basis(),
    }


def get_scorecard_summary() -> Dict[str, Any]:
    return {
        "total_vendors": 0,
        "pqc_ready": 0,
        "in_progress": 0,
        "early_stage": 0,
        "not_started": 0,
        "avg_composite": None,
        "by_tier": {},
        "avg_by_category": {},
        "top_vendors": [],
        "bottom_vendors": [],
        "model_basis": scorecard_model_basis(),
    }
