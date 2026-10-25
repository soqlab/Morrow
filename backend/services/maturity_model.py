"""
PQC Maturity Model — Cryptographic Quantum Readiness Assessment

A structured 5-level maturity model (CMMI-style) for post-quantum cryptography.
Assesses organizations across 8 domains and produces a composite maturity score,
board-ready maturity certificate, and targeted improvement roadmap.

Maturity Levels:
  1 — Initial:      Ad hoc, no systematic PQC awareness
  2 — Developing:   Inventory started, some awareness, no migration plan
  3 — Defined:      Full inventory, risk classification, migration plan documented
  4 — Managed:      Active migration, metrics tracked, CI/CD gates, supply chain assessed
  5 — Optimizing:   Full PQC deployment, canary monitoring, regulatory compliance, ZK proofs

8 Assessment Domains:
  D1 — Cryptographic Asset Inventory
  D2 — Risk Classification & Prioritization
  D3 — Migration Planning & Governance
  D4 — Technical Implementation
  D5 — Supply Chain & Third-Party Risk
  D6 — Monitoring & Detection
  D7 — Regulatory Compliance
  D8 — Incident Response & Threat Intelligence
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Domain definitions ─────────────────────────────────────────────────────────

_DOMAINS: List[Dict[str, Any]] = [
    {
        "id": "D1",
        "name": "Cryptographic Asset Inventory",
        "weight": 0.15,
        "description": "Discovery and cataloging of all cryptographic assets",
        "levels": {
            1: "No inventory. Cryptographic assets unknown.",
            2: "Manual inventory for some assets. Spreadsheet-based, incomplete.",
            3: "Automated discovery for internet-facing assets. Full catalog with metadata.",
            4: "Continuous scanning. All assets tracked with CBOM. Drift detection active.",
            5: "Real-time inventory with auto-discovery. Supply chain crypto included. API-accessible.",
        },
        "questions": [
            {"q": "Do you have a complete list of all TLS certificates in your environment?", "id": "D1Q1", "levels": {False: 1, "partial": 2, True: 3}},
            {"q": "Is your inventory updated automatically via scanning?", "id": "D1Q2", "levels": {False: 2, True: 4}},
            {"q": "Does your inventory include dependencies and third-party crypto?", "id": "D1Q3", "levels": {False: 3, True: 5}},
        ],
    },
    {
        "id": "D2",
        "name": "Risk Classification & Prioritization",
        "weight": 0.15,
        "description": "Quantum risk assessment and prioritization of cryptographic assets",
        "levels": {
            1: "No risk classification. All assets treated equally.",
            2: "High-level classification. Critical vs non-critical.",
            3: "Algorithm-based risk scoring (RSA-2048 = high, ECC-256 = high). HNDL exposure estimated.",
            4: "Asset-level quantum risk score with business impact weighting. Automated classification.",
            5: "Dynamic risk scoring linked to Q-Day probability model. Dollar-denominated HNDL exposure.",
        },
    },
    {
        "id": "D3",
        "name": "Migration Planning & Governance",
        "weight": 0.15,
        "description": "Structured planning and governance for PQC migration",
        "levels": {
            1: "No migration plan. PQC not on roadmap.",
            2: "PQC migration discussed. No formal plan.",
            3: "Documented migration plan with priorities and owners. Executive sponsor assigned.",
            4: "Funded migration program. Quarterly milestones tracked. Board visibility.",
            5: "Autonomous migration tooling. Config patches auto-generated. GitHub PRs opened by platform.",
        },
    },
    {
        "id": "D4",
        "name": "Technical Implementation",
        "weight": 0.20,
        "description": "Actual deployment of post-quantum cryptographic algorithms",
        "levels": {
            1: "0% PQC deployment. All assets use classical crypto.",
            2: "<25% PQC deployment. Pilots in non-critical systems.",
            3: "25–74% PQC deployment. Critical assets prioritized.",
            4: "75–99% PQC deployment. Hybrid mode (classical + PQC) for critical paths.",
            5: "100% PQC deployment. Hybrid TLS active for all public endpoints.",
        },
    },
    {
        "id": "D5",
        "name": "Supply Chain & Third-Party Risk",
        "weight": 0.10,
        "description": "Assessment of cryptographic risk in software dependencies and vendors",
        "levels": {
            1: "No supply chain crypto assessment.",
            2: "Awareness of key vendors' PQC roadmaps.",
            3: "Dependency scanning (npm/pip/cargo). Critical vendors assessed.",
            4: "Automated supply chain genome scanning in CI/CD. SBOMs generated.",
            5: "Vendor scorecards updated quarterly. Contract requirements for PQC timelines.",
        },
    },
    {
        "id": "D6",
        "name": "Monitoring & Detection",
        "weight": 0.10,
        "description": "Continuous monitoring for quantum threats and crypto degradation",
        "levels": {
            1: "No quantum-specific monitoring.",
            2: "Manual certificate expiry monitoring.",
            3: "Automated TLS scanning. Alerting on cert changes.",
            4: "Quantum canary network deployed. HNDL detection active. Drift alerts.",
            5: "Quantum canary network + Q-TISN participation. Real-time threat intelligence feed.",
        },
    },
    {
        "id": "D7",
        "name": "Regulatory Compliance",
        "weight": 0.10,
        "description": "Alignment with post-quantum regulatory requirements",
        "levels": {
            1: "Unaware of PQC regulatory requirements.",
            2: "Aware of NIST SP 800-208. No compliance actions taken.",
            3: "Gap analysis complete for applicable frameworks. Migration plan references compliance.",
            4: "Compliance filings submitted. Evidence packages maintained. Auditor access configured.",
            5: "ZK Compliance Proofs available. Automated regulatory filing generation. Board attestation.",
        },
    },
    {
        "id": "D8",
        "name": "Incident Response & Threat Intelligence",
        "weight": 0.05,
        "description": "Preparedness for quantum-related cryptographic incidents",
        "levels": {
            1: "No quantum incident response plan.",
            2: "Incident response plan exists but doesn't address quantum scenarios.",
            3: "Quantum incident playbooks written. Canary trigger response procedure defined.",
            4: "Tabletop exercises conducted. Nation-state attribution capability. Q-Day drill completed.",
            5: "Active threat intelligence. Federated threat sharing. Real-time attribution. Actuarial model.",
        },
    },
]

_LEVEL_NAMES = {1: "Initial", 2: "Developing", 3: "Defined", 4: "Managed", 5: "Optimizing"}
_LEVEL_COLORS = {1: "#ef4444", 2: "#f97316", 3: "#fbbf24", 4: "#22c55e", 5: "#a78bfa"}

# ── Auto-scoring from scan data ────────────────────────────────────────────────

def auto_score_from_scan(
    org_id: str,
    scan_summary: Dict[str, Any],
    has_canaries: bool = False,
    has_qtisn: bool = False,
    has_supply_chain: bool = False,
    has_zk_proofs: bool = False,
    has_autopilot: bool = False,
    has_cicd_gate: bool = False,
    has_regulatory_filings: bool = False,
) -> Dict[str, Any]:
    """
    Derive domain scores automatically from scan summary + platform feature usage.
    Returns domain_scores dict (domain_id → 1-5 float score).
    """
    pqc_pct = float(scan_summary.get("pqc_migration_pct", 0) or 0)
    total_assets = int(scan_summary.get("total_assets", 0) or 0)
    critical_count = int(scan_summary.get("critical_risk_count", 0) or 0)
    has_inventory = total_assets > 0
    has_cbom = bool(scan_summary.get("has_cbom"))
    has_migration_plan = bool(scan_summary.get("has_migration_plan"))

    domain_scores: Dict[str, float] = {}

    # D1 — Asset Inventory
    if not has_inventory:
        d1 = 1.0
    elif total_assets < 10:
        d1 = 2.0
    elif total_assets >= 10 and not has_cbom:
        d1 = 3.0
    elif has_cbom and not has_supply_chain:
        d1 = 4.0
    elif has_cbom and has_supply_chain:
        d1 = 5.0
    else:
        d1 = 2.5
    domain_scores["D1"] = d1

    # D2 — Risk Classification
    if critical_count > 0 and not has_inventory:
        d2 = 1.0
    elif total_assets > 0 and not scan_summary.get("risk_classified"):
        d2 = 2.0
    elif total_assets > 0 and scan_summary.get("hndl_exposure_usd"):
        d2 = 4.0 if total_assets > 20 else 3.0
    else:
        d2 = 3.0
    domain_scores["D2"] = d2

    # D3 — Migration Planning
    if has_autopilot and has_migration_plan:
        d3 = 5.0
    elif has_migration_plan:
        d3 = 4.0
    elif pqc_pct > 0:
        d3 = 3.0
    elif has_inventory:
        d3 = 2.0
    else:
        d3 = 1.0
    domain_scores["D3"] = d3

    # D4 — Technical Implementation
    if pqc_pct >= 100:
        d4 = 5.0
    elif pqc_pct >= 75:
        d4 = 4.0
    elif pqc_pct >= 25:
        d4 = 3.0
    elif pqc_pct > 0:
        d4 = 2.0
    else:
        d4 = 1.0
    domain_scores["D4"] = d4

    # D5 — Supply Chain
    if has_supply_chain and has_cicd_gate:
        d5 = 5.0
    elif has_supply_chain:
        d5 = 4.0
    elif has_inventory:
        d5 = 2.5
    else:
        d5 = 1.0
    domain_scores["D5"] = d5

    # D6 — Monitoring & Detection
    if has_canaries and has_qtisn:
        d6 = 5.0
    elif has_canaries:
        d6 = 4.0
    elif total_assets > 0:
        d6 = 3.0
    elif has_inventory:
        d6 = 2.0
    else:
        d6 = 1.0
    domain_scores["D6"] = d6

    # D7 — Regulatory Compliance
    if has_zk_proofs and has_regulatory_filings:
        d7 = 5.0
    elif has_regulatory_filings:
        d7 = 4.0
    elif scan_summary.get("compliance_assessed"):
        d7 = 3.0
    elif has_inventory:
        d7 = 2.0
    else:
        d7 = 1.0
    domain_scores["D7"] = d7

    # D8 — Incident Response
    if has_qtisn and has_canaries:
        d8 = 5.0
    elif has_canaries:
        d8 = 3.5
    elif has_inventory:
        d8 = 2.0
    else:
        d8 = 1.0
    domain_scores["D8"] = d8

    return domain_scores


def compute_maturity(
    org_id: str,
    domain_scores: Dict[str, float],
    org_name: str = "Organization",
) -> Dict[str, Any]:
    """
    Compute full maturity assessment from domain scores.

    domain_scores: {domain_id → float 1.0-5.0}
    """
    # Weighted composite score
    total_weight = 0.0
    weighted_sum = 0.0
    domain_results = []

    for domain in _DOMAINS:
        did = domain["id"]
        score = min(max(float(domain_scores.get(did, 1.0)), 1.0), 5.0)
        weight = domain["weight"]
        weighted_sum += score * weight
        total_weight += weight

        level_int = max(1, min(5, round(score)))
        domain_results.append({
            "domain_id": did,
            "domain_name": domain["name"],
            "score": round(score, 2),
            "level": level_int,
            "level_name": _LEVEL_NAMES[level_int],
            "level_color": _LEVEL_COLORS[level_int],
            "level_description": domain["levels"].get(level_int, ""),
            "weight": weight,
            "weight_pct": f"{weight*100:.0f}%",
            "next_level": domain["levels"].get(level_int + 1, "Already at maximum level") if level_int < 5 else None,
        })

    composite = weighted_sum / max(total_weight, 1.0)
    composite_level = max(1, min(5, round(composite)))

    # Weakest domains (improvement opportunities)
    sorted_by_score = sorted(domain_results, key=lambda d: d["score"])
    weakest = sorted_by_score[:3]

    # Certificate ID
    cert_id = "PQC-MM-" + hashlib.sha256(f"{org_id}:{composite:.2f}:{datetime.now(timezone.utc).date().isoformat()}".encode()).hexdigest()[:12].upper()

    now = datetime.now(timezone.utc)

    return {
        "assessment_id": cert_id,
        "org_id": org_id,
        "org_name": org_name,
        "assessed_at": now.isoformat(),
        "valid_until": f"{now.year + 1}-{now.month:02d}-{now.day:02d}",
        "composite_score": round(composite, 2),
        "composite_level": composite_level,
        "composite_level_name": _LEVEL_NAMES[composite_level],
        "composite_level_color": _LEVEL_COLORS[composite_level],
        "composite_pct": round((composite - 1) / 4 * 100, 1),
        "domain_results": domain_results,
        "weakest_domains": weakest,
        "improvement_roadmap": _generate_roadmap(weakest, composite_level),
        "maturity_summary": _generate_summary(org_name, composite_level, composite),
        "certificate": {
            "id": cert_id,
            "issued_to": org_name,
            "maturity_level": composite_level,
            "maturity_level_name": _LEVEL_NAMES[composite_level],
            "composite_score": round(composite, 2),
            "issued_at": now.isoformat()[:10],
            "valid_until": f"{now.year + 1}-{now.month:02d}-{now.day:02d}",
            "issuer": "Morrow Maturity Assessment Framework",
            "sha256_fingerprint": hashlib.sha256(f"{cert_id}:{composite:.4f}:{now.isoformat()[:10]}".encode()).hexdigest(),
        },
    }


def _generate_roadmap(weakest: List[Dict], current_level: int) -> List[Dict[str, Any]]:
    roadmap = []
    for i, domain in enumerate(weakest, 1):
        next_lvl = domain["level"] + 1
        if next_lvl > 5:
            continue
        roadmap.append({
            "priority": i,
            "domain": domain["domain_name"],
            "current_level": domain["level"],
            "target_level": next_lvl,
            "action": domain["next_level"] or "",
            "estimated_effort": (
                "1-2 weeks" if next_lvl <= 2 else
                "1-3 months" if next_lvl <= 3 else
                "3-6 months" if next_lvl <= 4 else
                "6-12 months"
            ),
            "impact": f"Advances {domain['domain_name']} from {_LEVEL_NAMES[domain['level']]} → {_LEVEL_NAMES[next_lvl]}",
        })
    return roadmap


def _generate_summary(org_name: str, level: int, score: float) -> str:
    summaries = {
        1: f"{org_name} is at the Initial stage of PQC readiness. Immediate action required: begin cryptographic asset discovery and appoint a PQC program owner.",
        2: f"{org_name} has begun its PQC journey but lacks a formal plan. Priority: complete inventory and perform risk classification to advance to Level 3.",
        3: f"{org_name} has a defined PQC program with documented plans and risk classification. Focus: accelerate technical migration — especially critical-risk assets.",
        4: f"{org_name} is actively managing its PQC migration with measurable progress. Excellent work. Next: achieve full deployment and activate threat intelligence sharing.",
        5: f"{org_name} has achieved the highest PQC maturity level. Continuous optimization through Q-TISN participation, ZK compliance proofs, and actuarial modeling is underway.",
    }
    return summaries.get(level, "")


def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("maturity_assessments"):
        return
    _ensure_tables_uncached()
    mark_schema_ensured("maturity_assessments")


def _ensure_tables_uncached() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS maturity_assessments (
                id          TEXT PRIMARY KEY,
                org_id      TEXT NOT NULL,
                org_name    TEXT NOT NULL DEFAULT '',
                assessed_at TEXT NOT NULL,
                composite   REAL NOT NULL,
                level       INTEGER NOT NULL,
                scores_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_maturity_org ON maturity_assessments(org_id, assessed_at)"
        )
        conn.commit()


def save_assessment(result: Dict[str, Any]) -> None:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO maturity_assessments
               (id, org_id, org_name, assessed_at, composite, level, scores_json, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (result["assessment_id"], result["org_id"], result["org_name"],
             result["assessed_at"], result["composite_score"], result["composite_level"],
             json.dumps({d["domain_id"]: d["score"] for d in result["domain_results"]}),
             json.dumps({k: v for k, v in result.items() if k != "certificate"})),
        )
        conn.commit()


def list_assessments(org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, org_name, assessed_at, composite, level
               FROM maturity_assessments WHERE org_id = ?
               ORDER BY assessed_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_assessment(assessment_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        row = conn.execute(
            "SELECT result_json FROM maturity_assessments WHERE id = ? AND org_id = ?",
            (assessment_id, org_id),
        ).fetchone()
    return json.loads(row[0]) if row else None
