"""
PQC Migration ROI Calculator

A planning model for the financial case for PQC migration:
- Expected breach cost, anchored to the IBM Cost of a Data Breach Report 2024
  where a sector figure was verified, otherwise that report's global average
- Migration investment (engineer-days, tooling, testing) from stated effort assumptions
- Q-Day probability by year from the Q-Intel model (services/q_intel.py)
- Risk-adjusted NPV over configurable time horizons

Every result carries ``model_basis`` listing these assumptions.

Pure stdlib — no numpy, scipy, or external dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.model_basis import model_basis as _model_basis


_BREACH_COST_SOURCE = "IBM Security / Ponemon Institute — Cost of a Data Breach Report 2024 (published 2024-07-30)"
_BREACH_COST_SOURCE_URLS = [
    "https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs",
    "https://www.ibm.com/think/insights/cost-of-a-data-breach-2024-financial-industry",
]
_GLOBAL_AVG_BREACH_COST_USD = 4_880_000   # IBM 2024 global average
_COST_PER_PII_RECORD_USD = 169            # IBM 2024 average cost per customer PII record

# cost_basis: "sector" = IBM 2024 figure for that industry;
#             "global_average" = no verified sector figure, so the global average is used.
# hndl_multiplier and regulatory_fine_pct are planning assumptions, not report figures.
_INDUSTRY_BREACH_COSTS: Dict[str, Dict[str, Any]] = {
    "healthcare": {
        "label": "Healthcare",
        "avg_breach_cost_usd": 9_770_000,
        "cost_basis": "sector",
        "hndl_multiplier": 1.8,
        "regulatory_fine_pct": 0.15,
    },
    "financial_services": {
        "label": "Financial Services",
        "avg_breach_cost_usd": 6_080_000,
        "cost_basis": "sector",
        "hndl_multiplier": 2.1,
        "regulatory_fine_pct": 0.20,
    },
    "technology": {
        "label": "Technology",
        "avg_breach_cost_usd": _GLOBAL_AVG_BREACH_COST_USD,
        "cost_basis": "global_average",
        "hndl_multiplier": 1.6,
        "regulatory_fine_pct": 0.05,
    },
    "government": {
        "label": "Government / Defense",
        "avg_breach_cost_usd": 2_550_000,
        "cost_basis": "sector (public sector)",
        "hndl_multiplier": 3.5,
        "regulatory_fine_pct": 0.0,
    },
    "energy_utilities": {
        "label": "Energy & Utilities",
        "avg_breach_cost_usd": _GLOBAL_AVG_BREACH_COST_USD,
        "cost_basis": "global_average",
        "hndl_multiplier": 2.4,
        "regulatory_fine_pct": 0.10,
    },
    "retail_ecommerce": {
        "label": "Retail & E-Commerce",
        "avg_breach_cost_usd": _GLOBAL_AVG_BREACH_COST_USD,
        "cost_basis": "global_average",
        "hndl_multiplier": 1.3,
        "regulatory_fine_pct": 0.08,
    },
    "telecommunications": {
        "label": "Telecommunications",
        "avg_breach_cost_usd": _GLOBAL_AVG_BREACH_COST_USD,
        "cost_basis": "global_average",
        "hndl_multiplier": 1.9,
        "regulatory_fine_pct": 0.12,
    },
    "education_research": {
        "label": "Education & Research",
        "avg_breach_cost_usd": _GLOBAL_AVG_BREACH_COST_USD,
        "cost_basis": "global_average",
        "hndl_multiplier": 1.5,
        "regulatory_fine_pct": 0.04,
    },
}

_SENSITIVITY_MULTIPLIERS = {"low": 0.5, "medium": 1.0, "high": 1.8, "critical": 3.2}

# Migration effort per asset type (engineer-days) — planning assumptions
_MIGRATION_EFFORT: Dict[str, Dict[str, Any]] = {
    "tls_endpoint": {
        "label": "TLS Endpoint (web / API)",
        "engineer_days": 2.0,
        "complexity": "low",
        "notes": "Library upgrade, config change, cert reissue",
    },
    "ssh_host": {
        "label": "SSH Host Key",
        "engineer_days": 0.5,
        "complexity": "very_low",
        "notes": "Recent OpenSSH releases offer hybrid PQC key exchange; mostly configuration",
    },
    "code_signing": {
        "label": "Code Signing Pipeline",
        "engineer_days": 5.0,
        "complexity": "medium",
        "notes": "CI/CD toolchain, HSM integration, ML-DSA cert",
    },
    "pki_ca": {
        "label": "Internal PKI / CA",
        "engineer_days": 15.0,
        "complexity": "high",
        "notes": "Root CA migration, intermediate CAs, OCSP/CRL",
    },
    "vpn_ipsec": {
        "label": "VPN / IPSec Tunnel",
        "engineer_days": 3.0,
        "complexity": "low-medium",
        "notes": "IKEv2 with ML-KEM KEM support; firmware upgrades",
    },
    "database_encryption": {
        "label": "Database TDE / Column Encryption",
        "engineer_days": 8.0,
        "complexity": "high",
        "notes": "Key rotation, re-encryption of existing data, testing",
    },
    "application_crypto": {
        "label": "Application-Level Crypto",
        "engineer_days": 10.0,
        "complexity": "high",
        "notes": "Custom crypto usage in code; library swap + regression",
    },
}

_ENGINEER_DAY_RATE_USD = 1_200  # default blended loaded rate (caller can override)
_TOOLING_FIXED_USD = 25_000     # HSM, cert mgmt tooling
_TESTING_PCT = 0.20             # testing = 20% of implementation effort
_OVERHEAD_PCT = 0.15            # project management overhead
_ASSET_MIX = {"tls_endpoint": 0.65, "ssh_host": 0.20, "application_crypto": 0.10}


def _discount_factor(rate: float, years: float) -> float:
    """NPV discount factor."""
    return 1.0 / ((1 + rate) ** years)


def _qday_cumulative(year: int) -> float:
    from services.q_intel import get_q_day_probability
    return float(get_q_day_probability("rsa2048", year))


def roi_model_basis(profile: Dict[str, Any], sector: str) -> Dict[str, Any]:
    try:
        from services.q_intel import MODEL_AS_OF as qintel_as_of
    except Exception:
        qintel_as_of = ""
    cost_line = (
        f"Breach cost for {profile['label']}: ${profile['avg_breach_cost_usd']:,} "
        + ("(IBM 2024 sector figure)." if str(profile["cost_basis"]).startswith("sector")
           else "(IBM 2024 global average; no verified sector figure).")
    )
    return _model_basis(
        kind="model",
        summary=(
            "ROI and NPV are a planning model combining a published average breach cost with stated effort and "
            "Q-Day assumptions; they are not a quote, an actuarial estimate, or a measurement of your breach risk."
        ),
        assumptions=[
            cost_line,
            f"HNDL multiplier {profile['hndl_multiplier']} and regulatory fine {profile['regulatory_fine_pct']:.0%} "
            "of breach cost are planning assumptions, not report figures.",
            "Data sensitivity multipliers: " + ", ".join(f"{k} {v}" for k, v in _SENSITIVITY_MULTIPLIERS.items()) + ".",
            f"Record cost ${_COST_PER_PII_RECORD_USD} per record (IBM 2024 customer PII) is added only when records_at_risk is supplied.",
            "Asset mix assumed: 65% TLS endpoints, 20% SSH hosts, 10% application crypto, 5% other (2 engineer-days each).",
            "Engineer-days per asset type: " + ", ".join(f"{k} {v['engineer_days']}" for k, v in _MIGRATION_EFFORT.items()) + ".",
            f"Fixed tooling ${_TOOLING_FIXED_USD:,}; testing {_TESTING_PCT:.0%} and overhead {_OVERHEAD_PCT:.0%} of implementation effort.",
            f"Q-Day probability by year: Q-Intel model for RSA-2048 (as of {qintel_as_of}; see /q-intel/model).",
        ],
        sources=[_BREACH_COST_SOURCE] + _BREACH_COST_SOURCE_URLS,
        as_of="2024-07",
    )


def compute_roi(
    asset_count: int,
    sector: str = "technology",
    records_at_risk: int = 0,
    engineer_day_rate_usd: int = _ENGINEER_DAY_RATE_USD,
    discount_rate: float = 0.10,
    time_horizon_years: int = 10,
    data_sensitivity: str = "medium",
    hndl_interception_pct: float = 10.0,
) -> Dict[str, Any]:
    """
    Compute PQC migration ROI.

    Returns NPV of avoiding a HNDL-then-decrypt breach vs migration cost.
    """
    now = datetime.now(timezone.utc)
    current_year = now.year

    profile = _INDUSTRY_BREACH_COSTS.get(sector, _INDUSTRY_BREACH_COSTS["technology"])
    records_at_risk = max(0, int(records_at_risk or 0))

    # ── Migration cost ────────────────────────────────────────────────────────
    tls_count = max(1, round(asset_count * _ASSET_MIX["tls_endpoint"]))
    ssh_count = max(0, round(asset_count * _ASSET_MIX["ssh_host"]))
    app_count = max(0, round(asset_count * _ASSET_MIX["application_crypto"]))
    other_count = max(0, asset_count - tls_count - ssh_count - app_count)

    impl_days = (
        tls_count * _MIGRATION_EFFORT["tls_endpoint"]["engineer_days"]
        + ssh_count * _MIGRATION_EFFORT["ssh_host"]["engineer_days"]
        + app_count * _MIGRATION_EFFORT["application_crypto"]["engineer_days"]
        + other_count * 2.0
    )
    testing_days = impl_days * _TESTING_PCT
    overhead_days = (impl_days + testing_days) * _OVERHEAD_PCT
    total_days = impl_days + testing_days + overhead_days

    migration_cost = (
        total_days * engineer_day_rate_usd
        + _TOOLING_FIXED_USD
    )

    # ── Expected breach cost (NPV of future risk) ─────────────────────────────
    breach_cost_base = profile["avg_breach_cost_usd"]
    hndl_mult = profile["hndl_multiplier"]
    reg_fine = breach_cost_base * profile["regulatory_fine_pct"]
    record_cost = records_at_risk * _COST_PER_PII_RECORD_USD

    hndl_premium = breach_cost_base * (hndl_interception_pct / 100.0) * hndl_mult

    total_breach_cost = breach_cost_base + reg_fine + record_cost + hndl_premium

    sens_mult = _SENSITIVITY_MULTIPLIERS.get(data_sensitivity, 1.0)
    total_breach_cost *= sens_mult

    # Probability that Q-Day occurs in each future year (marginal), from Q-Intel
    prev_cum = _qday_cumulative(current_year)
    risk_reduction_npv = 0.0
    annual_risk: List[Dict[str, Any]] = []
    for yr in range(current_year + 1, current_year + time_horizon_years + 1):
        cum_this_yr = _qday_cumulative(yr)
        marginal_prob = max(0.0, cum_this_yr - prev_cum)
        prev_cum = max(prev_cum, cum_this_yr)
        years_out = yr - current_year
        pv = marginal_prob * total_breach_cost * _discount_factor(discount_rate, years_out)
        risk_reduction_npv += pv
        annual_risk.append({
            "year": yr,
            "qday_probability_pct": round(cum_this_yr * 100, 1),
            "marginal_risk_pct": round(marginal_prob * 100, 2),
            "expected_loss_pv_usd": round(pv),
        })

    npv = risk_reduction_npv - migration_cost
    roi_pct = round((npv / max(1, migration_cost)) * 100, 1) if migration_cost > 0 else 0.0
    payback_year = None
    cumulative = 0.0
    for row in annual_risk:
        cumulative += row["expected_loss_pv_usd"]
        if cumulative >= migration_cost:
            payback_year = row["year"]
            break

    return {
        "generated_at": now.isoformat(),
        "inputs": {
            "asset_count": asset_count,
            "sector": sector,
            "records_at_risk": records_at_risk,
            "data_sensitivity": data_sensitivity,
            "hndl_interception_pct": hndl_interception_pct,
            "engineer_day_rate_usd": engineer_day_rate_usd,
            "discount_rate_pct": discount_rate * 100,
            "time_horizon_years": time_horizon_years,
        },
        "migration_cost": {
            "implementation_engineer_days": round(impl_days, 1),
            "testing_engineer_days": round(testing_days, 1),
            "total_engineer_days": round(total_days, 1),
            "labor_cost_usd": round(total_days * engineer_day_rate_usd),
            "tooling_cost_usd": _TOOLING_FIXED_USD,
            "total_migration_cost_usd": round(migration_cost),
        },
        "breach_cost_model": {
            "base_breach_cost_usd": round(breach_cost_base),
            "regulatory_fine_usd": round(reg_fine),
            "record_cost_usd": round(record_cost),
            "hndl_premium_usd": round(hndl_premium),
            "sensitivity_multiplier": sens_mult,
            "total_breach_exposure_usd": round(total_breach_cost),
            "sector_avg_breach_usd": profile["avg_breach_cost_usd"],
            "cost_basis": profile["cost_basis"],
            "breach_cost_source": _BREACH_COST_SOURCE,
        },
        "npv_analysis": {
            "risk_reduction_npv_usd": round(risk_reduction_npv),
            "migration_cost_usd": round(migration_cost),
            "net_present_value_usd": round(npv),
            "roi_pct": roi_pct,
            "payback_year": payback_year,
            "positive_roi": npv > 0,
        },
        "annual_risk_profile": annual_risk,
        "effort_breakdown": {
            "tls_endpoints": tls_count,
            "ssh_hosts": ssh_count,
            "application_crypto": app_count,
            "other": other_count,
        },
        "migration_effort_catalog": _MIGRATION_EFFORT,
        "summary": _roi_summary(npv, roi_pct, migration_cost, payback_year),
        "model_basis": roi_model_basis(profile, sector),
    }


def _roi_summary(npv: float, roi_pct: float, cost: float, payback_year: Optional[int]) -> str:
    if npv <= 0:
        return (
            f"Under this model, migration cost (${cost:,.0f}) exceeds the expected risk-reduction NPV within the analysis window. "
            "This typically indicates very short data retention or a sector with low breach cost. "
            "Consider extending the time horizon or increasing data sensitivity."
        )
    py = f"payback by {payback_year}" if payback_year else "payback within analysis window"
    return (
        f"Under this model, PQC migration has a positive NPV of ${npv:,.0f} ({roi_pct:.0f}% ROI), {py}: "
        f"${cost:,.0f} of migration cost against ${npv + cost:,.0f} of modelled, risk-adjusted breach exposure."
    )


def list_sectors() -> List[Dict[str, Any]]:
    return [{"id": k, "label": v["label"], "cost_basis": v["cost_basis"]} for k, v in _INDUSTRY_BREACH_COSTS.items()]


def get_effort_catalog() -> Dict[str, Any]:
    return _MIGRATION_EFFORT
