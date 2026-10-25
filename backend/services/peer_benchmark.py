"""
Sector Peer Benchmarking — not available

Peer benchmarking needs posture data from other organizations. No such data
source is connected: the platform does not collect or receive other
organizations' scores, and it does not ship survey-derived sector averages.
Rather than show invented percentiles, the benchmark reports that it is
unavailable and returns the organization's own score only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.model_basis import model_basis as _model_basis


_SECTOR_LABELS: Dict[str, str] = {
    "financial_services": "Financial Services",
    "healthcare": "Healthcare",
    "government": "Government / Defense",
    "technology": "Technology",
    "energy_utilities": "Energy & Utilities",
    "retail_ecommerce": "Retail & E-Commerce",
    "telecommunications": "Telecommunications",
    "education_research": "Education & Research",
}

_UNAVAILABLE_REASON = (
    "Peer benchmarking is not available: no data source with other organizations' Post-quantum posture is connected, "
    "so no percentile, quartile, or cross-organization comparison can be computed."
)


def list_sectors() -> List[Dict[str, Any]]:
    return [{"id": k, "label": v} for k, v in _SECTOR_LABELS.items()]


def benchmark_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="reference",
        summary="Only your organization's own score is shown; peer and sector comparisons are not provided.",
        assumptions=[],
        sources=[],
        as_of="2026-09",
    )


def compute_benchmark(
    org_score: float,
    sector: str = "technology",
    maturity_level: Optional[int] = None,
    asset_count: int = 0,
) -> Dict[str, Any]:
    """Return the org's own score and an explicit 'not available' for peer comparison."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "available": False,
        "reason": _UNAVAILABLE_REASON,
        "org_score": round(float(org_score or 0), 1),
        "sector": sector,
        "sector_label": _SECTOR_LABELS.get(sector, sector),
        "model_basis": benchmark_model_basis(),
    }


def compute_portfolio_benchmark(
    orgs: List[Dict[str, Any]],
    sector: str = "technology",
) -> Dict[str, Any]:
    """Aggregate own scores for multiple orgs (e.g. subsidiaries); no peer comparison."""
    scores = [float(o.get("score", 0) or 0) for o in orgs]
    avg = sum(scores) / len(scores) if scores else 0
    return {
        "available": False,
        "reason": _UNAVAILABLE_REASON,
        "sector": sector,
        "org_count": len(orgs),
        "portfolio_avg_score": round(avg, 1),
        "orgs": [{"org_name": o.get("name", f"Org {i+1}"), "org_score": round(float(o.get("score", 0) or 0), 1)}
                 for i, o in enumerate(orgs)],
        "model_basis": benchmark_model_basis(),
    }
