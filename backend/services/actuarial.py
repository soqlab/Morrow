"""
Quantum Insurance Actuarial Engine

A B2B actuarial module for cyber insurers: given an organization's quantum
posture (from scan data), compute actuarially sound premium components for
quantum breach coverage.

Models:
  Individual risk:   Annual breach probability × Expected loss distribution
  Portfolio risk:    Correlated loss across all insured orgs (using shared CA analysis)
  Tail risk:         99th percentile loss (Value-at-Risk) for the portfolio
  Premium:           Pure premium + expense loading + capital charge

Actuarial basis:
  - Frequency model: Poisson process with rate λ(year) from Q-Intel probability curves
  - Severity model:  Log-normal distribution calibrated to HNDL financial exposure
  - Correlation:     Beta factor based on shared CA dependency (contagion graph)
  - Capital charge:  12% of 99th percentile VaR (planning assumption)

All parameters are planning assumptions. This is not an actuarial opinion or
a rating; every result carries model_basis listing the assumptions.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.model_basis import model_basis as _model_basis


# ── Severity distribution parameters ─────────────────────────────────────────
# Log-normal. μ is set from the organisation's modelled exposure at call time;
# _SEVERITY_MU is only a reference point: ln($4.88M), the IBM Cost of a Data
# Breach Report 2024 global average.
_SEVERITY_MU    = 15.4
_SEVERITY_SIGMA = 1.4    # spread assumption

# Expense loading ratio (admin, claims handling, profit) — assumption
_EXPENSE_RATIO = 0.35

# Capital charge rate — assumption
_CAPITAL_CHARGE_RATE = 0.12

# Per-asset exposure used when an asset carries no exposure_usd — assumption
_DEFAULT_ASSET_EXPOSURE_USD = 200_000

# Quantum correlation factor for portfolio VaR — assumption
_PORTFOLIO_BETA = 0.60


def actuarial_model_basis(portfolio: bool = False) -> Dict[str, Any]:
    assumptions = [
        "Frequency: annual break probability from the Q-Intel model (see /q-intel/model), reduced by 90% of the post-quantum-migrated share.",
        f"Severity: log-normal centred on the modelled exposure, sigma {_SEVERITY_SIGMA} (reduced up to 0.5 by post-quantum share).",
        f"Assets without an exposure figure are counted at ${_DEFAULT_ASSET_EXPOSURE_USD:,} each.",
        f"Premium = (pure premium + {_CAPITAL_CHARGE_RATE:.0%} capital charge on the 99th-percentile loss) / (1 - {_EXPENSE_RATIO:.0%} expense ratio).",
        "Losses are taken net of the retention and capped at the coverage limit.",
    ]
    if portfolio:
        assumptions.append(f"Portfolio correlation beta {_PORTFOLIO_BETA} for simultaneous quantum exposure (assumption).")
    return _model_basis(
        kind="model",
        summary=(
            "Premiums and loss figures are an illustrative model built from planning assumptions; they are not "
            "an actuarial opinion, an insurer's rating, or a price quote."
        ),
        assumptions=assumptions,
        sources=["IBM Security / Ponemon Institute — Cost of a Data Breach Report 2024 (global average $4.88M, reference only)"],
        as_of="2026-09",
    )

# Discount rate for multi-year premium
_DISCOUNT_RATE = 0.05


def _lognormal_mean(mu: float, sigma: float) -> float:
    return math.exp(mu + 0.5 * sigma ** 2)


def _lognormal_var(mu: float, sigma: float, percentile: float = 0.99) -> float:
    """Log-normal Value-at-Risk at given percentile."""
    from statistics import NormalDist
    z = NormalDist().inv_cdf(percentile)
    return math.exp(mu + sigma * z)


def _q_day_prob(algo_class: str, year: int) -> float:
    """Get Q-Day probability from the Q-Intel model (it falls back to its shipped seeds if the DB is unavailable)."""
    from services.q_intel import get_q_day_probability
    return get_q_day_probability(algo_class, year)


def _algo_class_from_scan(scan_assets: List[Dict]) -> str:
    """Determine primary algorithm class from asset list."""
    kt_counts: Dict[str, int] = {}
    for a in scan_assets:
        kt = str(a.get("key_type") or "").lower()
        if "ml-kem" in kt or "kyber" in kt: kt_counts["pq_pure"] = kt_counts.get("pq_pure", 0) + 1
        elif "rsa" in kt:                   kt_counts["rsa2048"]   = kt_counts.get("rsa2048", 0) + 1
        elif "ec" in kt:                    kt_counts["ecc256"]    = kt_counts.get("ecc256", 0) + 1
        else:                               kt_counts["rsa2048"]   = kt_counts.get("rsa2048", 0) + 1
    if not kt_counts: return "rsa2048"
    return max(kt_counts, key=kt_counts.get)


def compute_individual_risk(
    org_id: str,
    scan_assets: List[Dict[str, Any]],
    coverage_years: int = 5,
    coverage_limit_usd: float = 10_000_000.0,
    retention_usd: float = 250_000.0,
) -> Dict[str, Any]:
    """
    Compute actuarial risk metrics for a single organization.

    Returns: {
        annual_breach_probability_by_year,
        expected_loss_usd,
        var_99_usd,
        pure_premium_usd,
        loaded_premium_usd,
        risk_tier,
        coverage_details
    }
    """
    if not scan_assets:
        # No asset on record. The old code counted a floor of one asset and
        # priced a $200k exposure that nobody owns.
        return {
            "org_id": org_id,
            "available": False,
            "reason": (
                "No assets are on record for this organization, so no exposure, loss or premium can "
                "be modelled. Run a TLS scan (or import a CBOM/SBOM) first."
            ),
            "minimum_data": {
                "assets": 1,
                "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
            },
            "risk_tier": None,
            "total_assets_assessed": 0,
            "critical_risk_assets": 0,
            "pq_migrated_pct": None,
            "primary_algo_class": None,
            "estimated_total_exposure_usd": None,
            "estimated_total_exposure_fmt": None,
            "annual_breach_probability_by_year": {},
            "avg_annual_breach_probability": None,
            "mean_loss_severity_usd": None,
            "mean_loss_severity_fmt": None,
            "var_99_usd": None,
            "var_99_fmt": None,
            "pure_premium_annual_usd": None,
            "pure_premium_annual_fmt": None,
            "loaded_premium_annual_usd": None,
            "loaded_premium_annual_fmt": None,
            "coverage_limit_usd": coverage_limit_usd,
            "retention_usd": retention_usd,
            "coverage_years": coverage_years,
            "capital_charge_usd": None,
            "methodology_note": "Not computed: no assets on record.",
            "model_basis": actuarial_model_basis(),
        }

    total_assets = len(scan_assets)
    critical = sum(1 for a in scan_assets if str(a.get("risk_level","")).lower() == "critical")
    high     = sum(1 for a in scan_assets if str(a.get("risk_level","")).lower() == "high")
    pq_count = sum(1 for a in scan_assets
                    if any(x in str(a.get("key_type","")).lower()
                           for x in ("ml-kem","kyber","dilithium","slh")))

    pq_pct = pq_count / total_assets
    algo_class = _algo_class_from_scan(scan_assets)

    # Estimated total HNDL exposure from existing scan data
    total_exposure = sum(
        float(a.get("exposure_usd") or _DEFAULT_ASSET_EXPOSURE_USD) for a in scan_assets
    )
    if not total_exposure:
        total_exposure = total_assets * _DEFAULT_ASSET_EXPOSURE_USD

    # Severity calibration: scale log-normal to actual exposure
    exposure_mu    = math.log(max(total_exposure, 1))
    exposure_sigma = max(_SEVERITY_SIGMA - pq_pct * 0.5, 0.5)  # Post-quantum reduces tail risk

    # Year-by-year breach probability (Poisson arrival with λ = p_break(year))
    start_year = datetime.now(timezone.utc).year
    years = list(range(start_year, start_year + coverage_years))
    annual_probs: Dict[int, float] = {}
    for yr in years:
        p_break = _q_day_prob(algo_class, yr)
        # Adjust for post-quantum migration: partially mitigates break probability
        p_effective = p_break * (1 - pq_pct * 0.90)
        annual_probs[yr] = round(p_effective, 4)

    # Expected loss (severity × frequency, per year)
    mean_severity = _lognormal_mean(exposure_mu, exposure_sigma)
    var_99         = _lognormal_var(exposure_mu, exposure_sigma, 0.99)

    # Net of retention and coverage limit
    mean_severity_net = min(max(mean_severity - retention_usd, 0), coverage_limit_usd)
    var_99_net         = min(max(var_99 - retention_usd, 0), coverage_limit_usd)

    # Average annual probability over coverage period
    avg_annual_prob = sum(annual_probs.values()) / max(len(annual_probs), 1)

    # Pure premium (expected annual loss)
    pure_premium = avg_annual_prob * mean_severity_net

    # Capital charge on 99th percentile
    capital_charge = _CAPITAL_CHARGE_RATE * var_99_net * avg_annual_prob

    # Loaded premium
    loaded_premium = (pure_premium + capital_charge) / (1 - _EXPENSE_RATIO)

    # Risk tier
    risk_tier = (
        "catastrophic" if critical >= 5 or (avg_annual_prob >= 0.30 and not pq_count)
        else "high"    if critical > 0 or avg_annual_prob >= 0.15
        else "medium"  if high > 0 or avg_annual_prob >= 0.05
        else "low"
    )

    def _fmt(v: float) -> str:
        if v >= 1e9: return f"${v/1e9:.2f}B"
        if v >= 1e6: return f"${v/1e6:.2f}M"
        if v >= 1e3: return f"${v/1e3:.0f}K"
        return f"${v:.0f}"

    return {
        "org_id": org_id,
        "available": True,
        "reason": "",
        "minimum_data": {
            "assets": 1,
            "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
        },
        "risk_tier": risk_tier,
        "total_assets_assessed": total_assets,
        "critical_risk_assets": critical,
        "pq_migrated_pct": round(pq_pct * 100, 1),
        "primary_algo_class": algo_class,
        "estimated_total_exposure_usd": round(total_exposure),
        "estimated_total_exposure_fmt": _fmt(total_exposure),
        "annual_breach_probability_by_year": annual_probs,
        "avg_annual_breach_probability": round(avg_annual_prob, 4),
        "mean_loss_severity_usd": round(mean_severity_net),
        "mean_loss_severity_fmt": _fmt(mean_severity_net),
        "var_99_usd": round(var_99_net),
        "var_99_fmt": _fmt(var_99_net),
        "pure_premium_annual_usd": round(pure_premium),
        "pure_premium_annual_fmt": _fmt(pure_premium),
        "loaded_premium_annual_usd": round(loaded_premium),
        "loaded_premium_annual_fmt": _fmt(loaded_premium),
        "coverage_limit_usd": coverage_limit_usd,
        "retention_usd": retention_usd,
        "coverage_years": coverage_years,
        "capital_charge_usd": round(capital_charge),
        "methodology_note": (
            "Frequency: Poisson(λ=Q-Day probability). "
            "Severity: Log-normal calibrated to HNDL exposure. "
            "Premium: Pure + 12% capital charge, 35% expense loading. "
            "Net of retention and coverage limit."
        ),
        "model_basis": actuarial_model_basis(),
    }


def compute_portfolio_risk(
    portfolio: List[Dict[str, Any]],  # list of individual risk results
    coverage_limit_usd: float = 1_000_000_000.0,
) -> Dict[str, Any]:
    """
    Compute portfolio-level aggregate risk for an insurer.
    Accounts for correlation through shared CA infrastructure.

    portfolio: list of outputs from compute_individual_risk()
    """
    if not portfolio:
        return {"error": "Empty portfolio"}

    n = len(portfolio)
    total_pure_premium = sum(p.get("pure_premium_annual_usd", 0) for p in portfolio)
    total_exposure = sum(p.get("estimated_total_exposure_usd", 0) for p in portfolio)
    avg_breach_prob = sum(p.get("avg_annual_breach_probability", 0) for p in portfolio) / n

    # Correlated aggregate VaR — beta factor accounts for shared CA dependencies
    # Beta (correlation): 0.3 typical for cyber (some shared infrastructure)
    # Increases to 0.6 for quantum (shared CAs mean simultaneous exposure)
    beta = _PORTFOLIO_BETA  # quantum-specific correlation factor (assumption)
    individual_vars = [p.get("var_99_usd", 0) for p in portfolio]
    # Portfolio VaR = sqrt(beta × N × mean(VaR²) + (1-beta) × mean(VaR²))
    mean_var = sum(individual_vars) / max(n, 1)
    correlated_var = math.sqrt(beta * n * mean_var**2 + (1 - beta) * sum(v**2 for v in individual_vars))
    correlated_var = min(correlated_var, coverage_limit_usd)

    # Portfolio loaded premium
    portfolio_capital_charge = _CAPITAL_CHARGE_RATE * correlated_var * avg_breach_prob
    portfolio_loaded_premium = (total_pure_premium + portfolio_capital_charge) / (1 - _EXPENSE_RATIO)

    tier_counts = {
        "catastrophic": sum(1 for p in portfolio if p.get("risk_tier") == "catastrophic"),
        "high":         sum(1 for p in portfolio if p.get("risk_tier") == "high"),
        "medium":       sum(1 for p in portfolio if p.get("risk_tier") == "medium"),
        "low":          sum(1 for p in portfolio if p.get("risk_tier") == "low"),
    }

    def _fmt(v: float) -> str:
        if v >= 1e9: return f"${v/1e9:.2f}B"
        if v >= 1e6: return f"${v/1e6:.2f}M"
        if v >= 1e3: return f"${v/1e3:.0f}K"
        return f"${v:.0f}"

    return {
        "portfolio_size": n,
        "total_estimated_exposure_usd": round(total_exposure),
        "total_estimated_exposure_fmt": _fmt(total_exposure),
        "total_pure_premium_usd": round(total_pure_premium),
        "total_pure_premium_fmt": _fmt(total_pure_premium),
        "portfolio_loaded_premium_usd": round(portfolio_loaded_premium),
        "portfolio_loaded_premium_fmt": _fmt(portfolio_loaded_premium),
        "correlated_var_99_usd": round(correlated_var),
        "correlated_var_99_fmt": _fmt(correlated_var),
        "correlation_beta": beta,
        "avg_annual_breach_probability": round(avg_breach_prob, 4),
        "tier_distribution": tier_counts,
        "correlation_note": (
            f"Quantum correlation β={beta} is a modelling assumption. "
            "It is set high because shared CA infrastructure can create simultaneous exposure windows."
        ),
        "capital_charge_usd": round(portfolio_capital_charge),
        "model_basis": actuarial_model_basis(portfolio=True),
    }
