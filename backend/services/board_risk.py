"""Board-level views over the organization's own evidence.

Every figure here is computed from this organization's assets, scans,
remediations and drift records. Nothing is compared against other
organizations: the platform receives no other organization's posture, so it
publishes no sector average, peer percentile or quartile.

A board score needs evidence. With no asset on record the Quantum Risk Index,
the regulatory alignment mapping and the team leaderboard return
``available: false`` with a reason and the minimum needed, and every score and
maturity field is null. "0 of 0 assets covered" is not 100% coverage, and an
empty workspace is not "developing" maturity — it is unmeasured.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional

from services.model_basis import model_basis as _model_basis

#: Fewest assets on record before a board-level score is published.
MINIMUM_ASSETS = 1

QRI_UNAVAILABLE_REASON = (
    "No assets are on record for this organization, so the Quantum Risk Index cannot be computed. "
    "Run a TLS scan (or import a CBOM/SBOM) and the score appears on the next report."
)

_MINIMUM_DATA = {
    "assets": MINIMUM_ASSETS,
    "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
}


def board_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="model",
        summary=(
            "The Quantum Risk Index is computed from this organization's own asset, remediation and "
            "drift records; the component weights and maturity bands are the platform's scoring "
            "choices, not a measured or published benchmark."
        ),
        assumptions=[
            "Inventory coverage 20, open exposure 20, crypto-agility 15, validated execution 20, "
            "blocker control 15, day-2 governance 10 (weights out of 100).",
            f"No score is published below {MINIMUM_ASSETS} asset on record.",
            "No sector, industry or peer comparison is available: the platform receives no other "
            "organization's posture.",
        ],
        sources=[],
        as_of="2026-09",
    )


def _clamp_score(value: float) -> int:
    return max(0, min(100, int(round(value))))


def _ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 1.0
    return max(0.0, min(1.0, numerator / denominator))


def _maturity_label(score: int) -> str:
    if score >= 85:
        return "managed"
    if score >= 70:
        return "progressing"
    if score >= 50:
        return "developing"
    if score >= 30:
        return "early"
    return "unmanaged"


def _component(score: Optional[float], weight: int, label: str, detail: str) -> Dict[str, Any]:
    if score is None:
        return {
            "label": label,
            "score": None,
            "weight": int(weight),
            "weighted_points": None,
            "detail": detail,
            "available": False,
        }
    return {
        "label": label,
        "score": _clamp_score(score),
        "weight": int(weight),
        "weighted_points": round((_clamp_score(score) * int(weight)) / 100.0, 2),
        "detail": detail,
        "available": True,
    }


def build_quantum_risk_index(
    *,
    compliance: Dict[str, Any],
    portfolio: Dict[str, Any],
    metrics: Dict[str, Any],
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a board-level 0-100 quantum-safe maturity score.

    Higher is better. The score is deliberately explainable: every component has a
    weight and a concrete operational signal behind it.
    """
    c_summary = compliance.get("summary") or {}
    p_summary = portfolio.get("summary") or {}
    roi = metrics.get("roi") or {}
    drift = metrics.get("drift_analytics") or {}

    assets_total = int(p_summary.get("assets_total") or c_summary.get("assets_total") or 0)
    assets_with_quantum_data = int(p_summary.get("assets_with_quantum_data") or 0)
    blocked_assets = int(p_summary.get("blocked_assets") or 0)
    actionable_paths = int(p_summary.get("actionable_migration_paths") or 0)
    open_assets = int(c_summary.get("open_assets") or 0)
    remediations_total = int(c_summary.get("remediations_total") or 0)
    validated_passed = int(c_summary.get("validated_passed_total") or 0)
    verified_closed = int(c_summary.get("verified_closed_total") or 0)
    drifted_total = int(c_summary.get("drifted_total") or 0)
    drift_events = int(drift.get("drift_events_total") or 0)

    if assets_total < MINIMUM_ASSETS:
        # Nothing on record. Every ratio below would divide by a floor of 1 and
        # report a perfect score for an empty estate, so no score is published.
        return {
            "available": False,
            "reason": QRI_UNAVAILABLE_REASON,
            "minimum_data": dict(_MINIMUM_DATA),
            "score": None,
            "scale": "0-100",
            "higher_is_better": True,
            "maturity": None,
            "components": [
                _component(None, weight, label, "Not measured: no assets on record.")
                for label, weight in (
                    ("Inventory coverage", 20),
                    ("Open exposure reduction", 20),
                    ("Crypto-agility", 15),
                    ("Validated execution", 20),
                    ("Provider/config blocker control", 15),
                    ("Day-2 governance", 10),
                )
            ],
            "top_risks": [],
            "executive_summary": {
                "assets_total": 0,
                "assets_with_quantum_data": 0,
                "actionable_migration_paths": 0,
                "blocked_assets": 0,
                "open_assets": 0,
                "remediations_total": 0,
                "verified_closed_total": 0,
                "policy_version": (policy or {}).get("version") or "v1",
                "mttr_reduction_percent": None,
            },
            "model_basis": board_model_basis(),
        }

    inventory_score = 100.0 * _ratio(assets_with_quantum_data, assets_total)
    exposure_score = 100.0 * (1.0 - _ratio(open_assets, max(assets_total, 1)))
    agility_score = float(p_summary.get("average_crypto_agility_score") or 0.0)
    # No remediation and no drift event means nothing has been executed or
    # governed yet — unmeasured, not a zero performance.
    execution_score = (
        100.0 * _ratio(validated_passed + verified_closed, remediations_total)
        if remediations_total > 0 else None
    )
    blocker_score = 100.0 * (1.0 - _ratio(blocked_assets, assets_total))
    governance_tracked = max(drift_events, remediations_total)
    governance_score = (
        100.0 * (1.0 - _ratio(drifted_total, governance_tracked))
        if governance_tracked > 0 else None
    )

    components = [
        _component(inventory_score, 20, "Inventory coverage", f"{assets_with_quantum_data}/{assets_total} assets have quantum migration data"),
        _component(exposure_score, 20, "Open exposure reduction", f"{open_assets} assets still have open scan risk"),
        _component(agility_score, 15, "Crypto-agility", f"{agility_score:.0f}% of assets on record are already quantum-safe"),
        _component(execution_score, 20, "Validated execution",
                   f"{validated_passed} passed validations, {verified_closed} verified-closed fixes"
                   if remediations_total > 0 else "Not measured: no remediation has been tracked yet."),
        _component(blocker_score, 15, "Provider/config blocker control", f"{blocked_assets} assets are blocked by provider or configuration constraints"),
        _component(governance_score, 10, "Day-2 governance",
                   f"{drifted_total} active drift items across {governance_tracked} tracked events/items"
                   if governance_tracked > 0 else "Not measured: no remediation or drift event has been tracked yet."),
    ]
    # Renormalize over the components that have evidence, so an unmeasured
    # component neither adds nor removes points.
    measured = [item for item in components if item["weighted_points"] is not None]
    measured_weight = sum(int(item["weight"]) for item in measured)
    qri = (
        _clamp_score(100.0 * sum(float(item["weighted_points"]) for item in measured) / measured_weight)
        if measured_weight > 0 else None
    )

    top_risks: List[Dict[str, Any]] = []
    if open_assets:
        top_risks.append({"kind": "open_exposure", "severity": "high", "message": f"{open_assets} assets still have open findings or risk."})
    if blocked_assets:
        top_risks.append({"kind": "provider_blocker", "severity": "medium", "message": f"{blocked_assets} assets need provider/configuration confirmation before post-quantum rollout."})
    if drifted_total:
        top_risks.append({"kind": "drift", "severity": "high", "message": f"{drifted_total} remediations have active drift."})
    if actionable_paths and remediations_total == 0:
        top_risks.append({"kind": "execution_gap", "severity": "medium", "message": "Actionable migration paths exist but no remediation work is tracked yet."})

    return {
        "available": qri is not None,
        "reason": "" if qri is not None else QRI_UNAVAILABLE_REASON,
        "minimum_data": dict(_MINIMUM_DATA),
        "score": qri,
        "scale": "0-100",
        "higher_is_better": True,
        "maturity": _maturity_label(qri) if qri is not None else None,
        "components": components,
        "top_risks": top_risks[:10],
        "model_basis": board_model_basis(),
        "executive_summary": {
            "assets_total": assets_total,
            "assets_with_quantum_data": assets_with_quantum_data,
            "actionable_migration_paths": actionable_paths,
            "blocked_assets": blocked_assets,
            "open_assets": open_assets,
            "remediations_total": remediations_total,
            "verified_closed_total": verified_closed,
            "policy_version": (policy or {}).get("version") or "v1",
            "mttr_reduction_percent": float(roi.get("mttr_reduction_percent") or 0.0),
        },
    }


REGULATORY_CONTROL_MAP: Dict[str, Dict[str, Any]] = {
    "nist-sp-800-227": {
        "name": "NIST SP 800-227",
        "focus": "post-quantum cryptography transition planning and migration governance",
        "controls": [
            {"id": "inventory", "title": "Cryptographic inventory", "signals": ["assets_with_quantum_data", "asset_evidence"]},
            {"id": "prioritization", "title": "Prioritize long-lived sensitive exposure", "signals": ["hndl_risk_counts", "open_assets"]},
            {"id": "migration", "title": "Migration planning and execution evidence", "signals": ["actionable_migration_paths", "remediations_total", "verified_closed_total"]},
            {"id": "monitoring", "title": "Ongoing monitoring and drift response", "signals": ["drifted_total", "drift_analytics"]},
        ],
    },
    "fips-140-3": {
        "name": "FIPS 140-3",
        "focus": "cryptographic module assurance and evidence management",
        "controls": [
            {"id": "approved_crypto", "title": "Identify cryptographic dependency posture", "signals": ["key_type", "sig_algorithm", "classical_crypto_dependency"]},
            {"id": "change_control", "title": "Validated cryptographic configuration changes", "signals": ["validated_passed_total", "validation_evidence"]},
            {"id": "auditability", "title": "Audit evidence for crypto governance", "signals": ["audit_summary", "evidence_integrity"]},
        ],
    },
    "dora": {
        "name": "DORA",
        "focus": "digital operational resilience, ICT risk management, and third-party/provider dependency tracking",
        "controls": [
            {"id": "ict_risk", "title": "ICT risk identification and treatment", "signals": ["open_assets", "risk_by_asset"]},
            {"id": "resilience_testing", "title": "Validation and testing of remediation actions", "signals": ["validated_total", "validated_passed_total"]},
            {"id": "third_party", "title": "Provider and external dependency visibility", "signals": ["provider_counts", "blocked_assets"]},
            {"id": "incident_drift", "title": "Monitoring, drift, and response evidence", "signals": ["recent_alerts", "drift_analytics"]},
        ],
    },
}


def _status_from_score(score: float) -> str:
    if score >= 85:
        return "aligned"
    if score >= 60:
        return "partially_aligned"
    return "needs_work"


def build_regulatory_alignment(
    *,
    qri: Dict[str, Any],
    compliance: Dict[str, Any],
    portfolio: Dict[str, Any],
    metrics: Dict[str, Any],
) -> Dict[str, Any]:
    c_summary = compliance.get("summary") or {}
    p_summary = portfolio.get("summary") or {}
    drift = (metrics.get("drift_analytics") or {})
    score_by_component: Dict[str, Optional[float]] = {}
    for item in qri.get("components") or []:
        raw = item.get("score")
        score_by_component[str(item.get("label") or "").lower()] = None if raw is None else float(raw)

    inventory = score_by_component.get("inventory coverage")
    exposure = score_by_component.get("open exposure reduction")
    execution = score_by_component.get("validated execution")
    blockers = score_by_component.get("provider/config blocker control")
    governance = score_by_component.get("day-2 governance")
    overall = qri.get("score")
    available = bool(qri.get("available", True)) and overall is not None

    def _weighted(parts: List[tuple]) -> Optional[float]:
        """Weighted mean over the parts that were measured; None if none were."""
        present = [(value, weight) for value, weight in parts if value is not None]
        total_weight = sum(weight for _, weight in present)
        if not available or total_weight <= 0:
            return None
        return sum(value * weight for value, weight in present) / total_weight

    framework_scores: Dict[str, Optional[float]] = {
        "nist-sp-800-227": _weighted([(inventory, 0.30), (exposure, 0.20), (execution, 0.25), (governance, 0.25)]),
        "fips-140-3": _weighted([(inventory, 0.25), (execution, 0.35), (governance, 0.25), (overall, 0.15)]),
        "dora": _weighted([(exposure, 0.25), (execution, 0.25), (blockers, 0.25), (governance, 0.25)]),
    }

    frameworks = []
    for key, meta in REGULATORY_CONTROL_MAP.items():
        raw_score = framework_scores.get(key)
        score = None if raw_score is None else _clamp_score(raw_score)
        controls = []
        for control in meta["controls"]:
            controls.append({
                **control,
                "evidence_examples": [
                    "organization readiness API",
                    "asset/remediation/repository evidence APIs",
                    "validation and audit events",
                ],
            })
        frameworks.append({
            "id": key,
            "name": meta["name"],
            "focus": meta["focus"],
            "alignment_score": score,
            "status": _status_from_score(score) if score is not None else "not_assessed",
            "available": score is not None,
            "reason": "" if score is not None else QRI_UNAVAILABLE_REASON,
            "controls": controls,
        })

    return {
        "available": available,
        "reason": "" if available else QRI_UNAVAILABLE_REASON,
        "minimum_data": dict(_MINIMUM_DATA),
        "model_basis": board_model_basis(),
        "frameworks": frameworks,
        "evidence_summary": {
            "risk_by_asset": c_summary.get("risk_by_asset") or {},
            "hndl_risk_counts": p_summary.get("hndl_risk_counts") or {},
            "provider_counts": p_summary.get("provider_counts") or {},
            "validated_passed_total": int(c_summary.get("validated_passed_total") or 0),
            "verified_closed_total": int(c_summary.get("verified_closed_total") or 0),
            "drift_status_counts": drift.get("drift_status_counts") or c_summary.get("drift_status_counts") or {},
        },
        "disclaimer": "This is an operational readiness mapping, not a certification or legal attestation.",
    }


def build_team_agility_leaderboard(
    *,
    compliance: Dict[str, Any],
    portfolio: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a team-level quantum agility leaderboard.

    This turns the same asset/remediation evidence used by the board report into
    an engineering operating metric. Higher scores mean the team has better
    inventory coverage, less open crypto risk, more validated/verified work, and
    less drift.
    """
    teams: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "team": "unassigned",
            "assets_total": 0,
            "assets_with_quantum_data": 0,
            "open_assets": 0,
            "open_findings_total": 0,
            "risk_weight": 0.0,
            "agility_sum": 0.0,
            "agility_count": 0,
            "remediations_total": 0,
            "validated_passed_total": 0,
            "verified_closed_total": 0,
            "merged_total": 0,
            "drifted_total": 0,
            "top_assets": [],
        }
    )

    asset_team: Dict[str, str] = {}
    risk_weights = {"critical": 12.0, "high": 8.0, "medium": 4.0, "low": 1.5, "none": 0.0, "unknown": 2.0}

    for item in portfolio.get("items") or []:
        asset_key = str(item.get("asset_key") or "").strip()
        team = str(item.get("team") or "").strip() or "unassigned"
        if asset_key:
            asset_team[asset_key] = team
        row = teams[team]
        row["team"] = team
        row["assets_total"] += 1
        if str(item.get("quantum_readiness_level") or "").strip().lower() not in {"", "not_assessed", "unknown"}:
            row["assets_with_quantum_data"] += 1
        try:
            agility = float(item.get("crypto_agility_score") or 0.0)
        except Exception:
            agility = 0.0
        if agility > 0:
            row["agility_sum"] += agility
            row["agility_count"] += 1

    for vuln in compliance.get("vulnerabilities") or []:
        asset_key = str(vuln.get("asset_key") or "").strip()
        team = str(vuln.get("team") or "").strip() or asset_team.get(asset_key) or "unassigned"
        row = teams[team]
        row["team"] = team
        if asset_key and asset_key not in asset_team:
            row["assets_total"] += 1
            asset_team[asset_key] = team
        findings_count = max(1, int(vuln.get("findings_count") or 0))
        risk_level = str(vuln.get("risk_level") or "unknown").strip().lower() or "unknown"
        row["open_assets"] += 1
        row["open_findings_total"] += max(0, int(vuln.get("findings_count") or 0))
        row["risk_weight"] += risk_weights.get(risk_level, risk_weights["unknown"]) * float(findings_count)
        if len(row["top_assets"]) < 5:
            row["top_assets"].append(
                {
                    "asset_key": asset_key,
                    "risk_level": risk_level,
                    "findings_count": int(vuln.get("findings_count") or 0),
                    "repository": str(vuln.get("repository") or "").strip(),
                }
            )

    for rem in compliance.get("remediations") or []:
        asset_key = str(rem.get("asset_key") or "").strip()
        team = asset_team.get(asset_key) or "unassigned"
        row = teams[team]
        row["team"] = team
        row["remediations_total"] += 1
        status = str(rem.get("status") or "").strip().lower()
        if status == "verified_closed":
            row["verified_closed_total"] += 1
        if status == "merged":
            row["merged_total"] += 1
        if str(rem.get("drift_status") or "").strip().lower() == "drifted":
            row["drifted_total"] += 1
        validation = rem.get("validation") if isinstance(rem.get("validation"), dict) else {}
        if str(validation.get("status") or "").strip().lower() == "passed":
            row["validated_passed_total"] += 1

    leaderboard: List[Dict[str, Any]] = []
    for row in teams.values():
        assets_total = int(row["assets_total"] or 0)
        rem_total = int(row["remediations_total"] or 0)
        inventory_score = 100.0 * _ratio(float(row["assets_with_quantum_data"]), float(max(1, assets_total)))
        exposure_score = 100.0 * (1.0 - _ratio(float(row["risk_weight"]), float(max(1, assets_total) * 12.0)))
        agility_count = int(row["agility_count"] or 0)
        # Components without evidence stay unmeasured and drop out of the mean,
        # instead of scoring zero for work that was never tracked.
        execution_score = (
            100.0 * _ratio(float(row["validated_passed_total"] + row["verified_closed_total"]), float(rem_total))
            if rem_total > 0 else None
        )
        agility_score = (float(row["agility_sum"]) / float(agility_count)) if agility_count else None
        drift_score = 100.0 * (1.0 - _ratio(float(row["drifted_total"]), float(rem_total))) if rem_total > 0 else None
        parts = [(inventory_score, 0.20), (exposure_score, 0.25), (execution_score, 0.25),
                 (agility_score, 0.20), (drift_score, 0.10)]
        present = [(v, w) for v, w in parts if v is not None]
        present_weight = sum(w for _, w in present)
        score = _clamp_score(sum(v * w for v, w in present) / present_weight) if present_weight else 0
        leaderboard.append(
            {
                "team": row["team"],
                "score": score,
                "rank_label": _maturity_label(score),
                "assets_total": assets_total,
                "assets_with_quantum_data": int(row["assets_with_quantum_data"] or 0),
                "open_assets": int(row["open_assets"] or 0),
                "open_findings_total": int(row["open_findings_total"] or 0),
                "average_crypto_agility_score": round(agility_score, 1) if agility_score is not None else None,
                "remediations_total": rem_total,
                "validated_passed_total": int(row["validated_passed_total"] or 0),
                "verified_closed_total": int(row["verified_closed_total"] or 0),
                "merged_total": int(row["merged_total"] or 0),
                "drifted_total": int(row["drifted_total"] or 0),
                "components": {
                    "inventory": _clamp_score(inventory_score),
                    "exposure": _clamp_score(exposure_score),
                    "execution": None if execution_score is None else _clamp_score(execution_score),
                    "agility": None if agility_score is None else _clamp_score(agility_score),
                    "drift": None if drift_score is None else _clamp_score(drift_score),
                },
                "top_assets": row["top_assets"],
            }
        )

    leaderboard.sort(key=lambda item: (-int(item["score"]), str(item["team"])))
    for idx, item in enumerate(leaderboard, start=1):
        item["rank"] = idx

    return {
        "available": bool(leaderboard),
        "reason": "" if leaderboard else (
            "No team has any asset or remediation on record yet, so no team score can be computed. "
            "Run a scan and assign asset owners, and the leaderboard fills in."
        ),
        "minimum_data": {
            "teams_with_assets": 1,
            "how_to_get_it": "Run a TLS scan, then tag assets with an owning team.",
        },
        "model_basis": board_model_basis(),
        "teams": leaderboard,
        "summary": {
            "teams_total": len(leaderboard),
            "top_team": leaderboard[0]["team"] if leaderboard else "",
            "lowest_team": leaderboard[-1]["team"] if leaderboard else "",
            "average_score": (
                _clamp_score(sum(float(item["score"]) for item in leaderboard) / float(len(leaderboard)))
                if leaderboard else None
            ),
        },
        "scoring_model": {
            "inventory": 20,
            "exposure": 25,
            "execution": 25,
            "agility": 20,
            "drift": 10,
        },
    }


CRYPTO_WEATHER_SIGNALS: List[Dict[str, Any]] = [
    {
        "id": "tls-legacy-front",
        "title": "Legacy TLS exposure front",
        "severity": "critical",
        "match": "tls_legacy",
        "board_message": "Assets using TLS 1.0/1.1 or SSL-era protocol posture are in the immediate remediation zone.",
    },
    {
        "id": "hndl-pressure-system",
        "title": "Harvest-now-decrypt-later pressure system",
        "severity": "high",
        "match": "hndl_high",
        "board_message": "Long-lived sensitive traffic with high quantum exposure should move first in the migration sequence.",
    },
    {
        "id": "classical-key-dependency",
        "title": "Classical key dependency watch",
        "severity": "medium",
        "match": "classical_dependency",
        "board_message": "RSA/DSA/ECDSA dependencies need an owner, migration path, and validation evidence.",
    },
    {
        "id": "provider-readiness-blocker",
        "title": "Provider readiness blocker",
        "severity": "medium",
        "match": "provider_blocker",
        "board_message": "Unknown or blocked provider posture can delay post-quantum rollout even when engineering is ready.",
    },
    {
        "id": "remediation-drift-watch",
        "title": "Remediation drift watch",
        "severity": "high",
        "match": "drifted_remediation",
        "board_message": "Previously remediated cryptographic controls have drifted and need revalidation.",
    },
]


def _policy_weather_advisories(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = policy.get("crypto_weather_advisories") or policy.get("external_crypto_advisories") or []
    advisories: List[Dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        advisory_id = str(item.get("id") or item.get("name") or "").strip()
        if not advisory_id:
            continue
        advisories.append(
            {
                "id": advisory_id,
                "title": str(item.get("title") or advisory_id).strip(),
                "severity": str(item.get("severity") or "medium").strip().lower(),
                "board_message": str(item.get("board_message") or item.get("description") or "External crypto advisory matched current evidence.").strip(),
                "algorithm_tokens": [str(x or "").strip().lower() for x in (item.get("algorithm_tokens") or item.get("algorithms") or []) if str(x or "").strip()],
                "tls_versions": [str(x or "").strip().lower() for x in (item.get("tls_versions") or []) if str(x or "").strip()],
                "cipher_tokens": [str(x or "").strip().lower() for x in (item.get("cipher_tokens") or item.get("ciphers") or []) if str(x or "").strip()],
                "provider_statuses": [str(x or "").strip().lower() for x in (item.get("provider_statuses") or []) if str(x or "").strip()],
                "source": str(item.get("source") or "policy").strip(),
                "published_at": str(item.get("published_at") or "").strip(),
                "reference_url": str(item.get("reference_url") or item.get("url") or "").strip(),
            }
        )
    return advisories


def _match_policy_advisory(advisory: Dict[str, Any], item: Dict[str, Any]) -> str:
    algorithm = str(item.get("classical_algorithm") or item.get("algorithm") or "").strip().lower()
    tls_version = str(item.get("tls_version") or "").strip().lower()
    cipher = str(item.get("cipher") or item.get("cipher_suite") or "").strip().lower()
    provider_status = str(item.get("provider_pq_support_status") or "unknown").strip().lower()
    if advisory.get("algorithm_tokens") and any(token in algorithm for token in advisory["algorithm_tokens"]):
        return f"algorithm advisory matched {algorithm or 'unknown'}"
    if advisory.get("tls_versions") and tls_version in set(advisory["tls_versions"]):
        return f"TLS advisory matched {tls_version or 'unknown'}"
    if advisory.get("cipher_tokens") and any(token in cipher for token in advisory["cipher_tokens"]):
        return f"cipher advisory matched {cipher or 'unknown'}"
    if advisory.get("provider_statuses") and provider_status in set(advisory["provider_statuses"]):
        return f"provider advisory matched {provider_status or 'unknown'}"
    return ""


def _weather_severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "").lower(), 0)


def build_crypto_weather(
    *,
    compliance: Dict[str, Any],
    portfolio: Dict[str, Any],
    policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Map active crypto advisories to the organization's asset evidence.

    This is intentionally deterministic. It gives the UI a live "storm radar"
    from the platform's current inventory instead of waiting for a static PDF.
    """
    policy = policy or {}
    portfolio_items = [item for item in (portfolio.get("items") or []) if isinstance(item, dict)]
    vulnerabilities = [item for item in (compliance.get("vulnerabilities") or []) if isinstance(item, dict)]
    remediations = [item for item in (compliance.get("remediations") or []) if isinstance(item, dict)]
    vuln_by_asset: Dict[str, Dict[str, Any]] = {
        str(item.get("asset_key") or "").strip(): item
        for item in vulnerabilities
        if str(item.get("asset_key") or "").strip()
    }

    matched: List[Dict[str, Any]] = []
    for signal in [*CRYPTO_WEATHER_SIGNALS, *_policy_weather_advisories(policy)]:
        impacted: List[Dict[str, Any]] = []
        match = signal.get("match") or "policy_advisory"

        if match == "drifted_remediation":
            for rem in remediations:
                if str(rem.get("drift_status") or "").strip().lower() != "drifted":
                    continue
                impacted.append(
                    {
                        "asset_key": str(rem.get("asset_key") or "").strip(),
                        "repository": str(rem.get("repository") or rem.get("repo") or "").strip(),
                        "reason": "drifted remediation",
                        "evidence": {"remediation_id": rem.get("id"), "status": rem.get("status")},
                    }
                )
        else:
            for item in portfolio_items:
                asset_key = str(item.get("asset_key") or "").strip()
                tls_version = str(item.get("tls_version") or "").strip().lower()
                hndl = str(item.get("harvest_now_decrypt_later_risk") or "").strip().lower()
                algorithm = str(item.get("classical_algorithm") or "").strip().lower()
                provider = str(item.get("provider_guess") or "unknown").strip().lower()
                provider_status = str(item.get("provider_pq_support_status") or "unknown").strip().lower()
                classical_dependency = bool(item.get("classical_crypto_dependency"))
                vuln = vuln_by_asset.get(asset_key) or {}

                reason = ""
                if match == "tls_legacy" and tls_version in {"ssl2", "ssl3", "tls1.0", "tlsv1.0", "tls1.1", "tlsv1.1"}:
                    reason = f"legacy protocol {tls_version}"
                elif match == "hndl_high" and hndl in {"high", "critical"}:
                    reason = f"{hndl} HNDL risk"
                elif match == "classical_dependency" and (
                    classical_dependency or any(token in algorithm for token in ("rsa", "dsa", "ecdsa", "ecdh"))
                ):
                    reason = f"classical dependency {algorithm or 'unknown'}"
                elif match == "provider_blocker" and (
                    provider in {"", "unknown"} or provider_status in {"", "unknown", "unsupported", "blocked", "not_supported"}
                ):
                    reason = f"provider posture {provider or 'unknown'} / {provider_status or 'unknown'}"
                elif match == "policy_advisory":
                    reason = _match_policy_advisory(signal, item)

                if reason:
                    impacted.append(
                        {
                            "asset_key": asset_key,
                            "team": str(item.get("team") or vuln.get("team") or "").strip(),
                            "owner": str(item.get("owner") or vuln.get("owner") or "").strip(),
                            "repository": str(vuln.get("repository") or "").strip(),
                            "reason": reason,
                            "evidence": {
                                "tls_version": item.get("tls_version") or "",
                                "hndl_risk": item.get("harvest_now_decrypt_later_risk") or "",
                                "provider": item.get("provider_guess") or "",
                                "provider_pq_support_status": item.get("provider_pq_support_status") or "",
                                "classical_algorithm": item.get("classical_algorithm") or "",
                                "advisory_source": signal.get("source") or "",
                                "advisory_reference_url": signal.get("reference_url") or "",
                            },
                        }
                    )

        if impacted:
            matched.append(
                {
                    "id": signal["id"],
                    "title": signal["title"],
                    "severity": signal["severity"],
                    "board_message": signal["board_message"],
                    "impacted_assets_total": len({str(item.get("asset_key") or "") for item in impacted if str(item.get("asset_key") or "")}),
                    "sample_impacted_assets": impacted[:10],
                }
            )

    matched.sort(key=lambda item: (-_weather_severity_rank(str(item.get("severity") or "")), -int(item.get("impacted_assets_total") or 0), str(item.get("id") or "")))
    critical = sum(1 for item in matched if item.get("severity") == "critical")
    high = sum(1 for item in matched if item.get("severity") == "high")
    total_assets = len({str(item.get("asset_key") or "") for item in portfolio_items if str(item.get("asset_key") or "")})
    impacted_assets = {
        str(asset.get("asset_key") or "")
        for signal in matched
        for asset in signal.get("sample_impacted_assets", [])
        if str(asset.get("asset_key") or "")
    }

    if critical:
        weather_state = "storm"
    elif high:
        weather_state = "watch"
    elif matched:
        weather_state = "advisory"
    else:
        weather_state = "clear"

    return {
        "state": weather_state,
        "summary": {
            "active_signals_total": len(matched),
            "critical_signals_total": critical,
            "high_signals_total": high,
            "assets_total": total_assets,
            "impacted_assets_sampled": len(impacted_assets),
            "policy_version": policy.get("version") or "v1",
            "policy_advisories_total": len(_policy_weather_advisories(policy)),
        },
        "signals": matched,
        "signal_catalog": [*CRYPTO_WEATHER_SIGNALS, *_policy_weather_advisories(policy)],
        "disclaimer": "Signal matching uses current platform evidence and should be triaged before external reporting.",
    }
