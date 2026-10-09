"""
Regulatory Evidence & Readiness Workspace

Tracks post-quantum cryptography migration deadlines across major frameworks
and generates evidence packages, gap analyses, and migration status reports
to support regulatory readiness reviews.

IMPORTANT — Scope accuracy:
  This workspace generates supporting evidence and readiness documentation.
  It does not submit formal regulatory filings or issue compliance certificates.
  Regulatory compliance is determined by a certified auditor or regulator,
  not by this tool. Evidence packages produced here are input to that process.

  Framework-specific notes:
  - NIST SP 800-208 covers stateful hash-based signature schemes (LMS/XMSS),
    not PQC migration broadly. Map controls precisely.
  - DORA, NIS2, ISO 27001, PCI DSS, and SOC 2 do not have specific PQC
    requirements that this tool can automatically "pass" or "fail". Evidence
    is mapped to relevant controls where a reasonable connection exists.
  - No EU "PQC regulatory filing" standard currently exists that can be
    automatically submitted; EU PQC policy proposals are still evolving.

Supported frameworks (evidence mapping only):
  NIST_SP_800_208  — Stateful hash-based signature scheme guidance
  CNSA_2_0         — NSA Commercial National Security Algorithm Suite 2.0
  OMB_M_23_02      — Federal Zero-Trust Architecture mandate (includes PQC)
  NIS2             — EU NIS2 Directive risk management controls
  DORA             — EU Digital Operational Resilience Act ICT risk controls
  FIPS_140_3       — FIPS 140-3 cryptographic module requirements
  PCI_DSS_4        — PCI DSS 4.0 cryptographic controls
  HIPAA_QUANTUM    — HHS proposed quantum-safe PHI protection guidance
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "NIST_SP_800_208": {
        "name": "NIST SP 800-208 / FIPS 203-205",
        "description": "NIST post-quantum cryptography standards — ML-KEM, ML-DSA, SLH-DSA",
        "authority": "NIST",
        "jurisdiction": "US Federal",
        "status": "finalized",
        "effective_date": "2024-08-13",
        "soft_deadline": "2026-01-01",
        "hard_deadline": "2030-01-01",
        "mandatory_for": ["US federal agencies", "federal contractors", "US financial sector"],
        "key_requirements": [
            "Inventory all cryptographic assets using quantum-vulnerable algorithms",
            "Replace RSA and ECC with ML-KEM (FIPS 203) and ML-DSA (FIPS 204)",
            "Submit migration plan by soft deadline",
            "Complete migration to approved PQC algorithms by hard deadline",
        ],
        "filing_url": "https://csrc.nist.gov/projects/post-quantum-cryptography",
        "penalty_usd": 0,
        "penalty_note": "Non-compliance may result in loss of federal contract eligibility",
    },
    "CNSA_2_0": {
        "name": "NSA CNSA 2.0 Suite",
        "description": "Commercial National Security Algorithm Suite 2.0 — mandatory for NSS systems",
        "authority": "NSA CYBERSECURITY",
        "jurisdiction": "US National Security Systems",
        "status": "finalized",
        "effective_date": "2022-09-01",
        "soft_deadline": "2025-01-01",
        "hard_deadline": "2033-01-01",
        "mandatory_for": ["NSS system owners", "Defense contractors (DFARS)", "IC community"],
        "key_requirements": [
            "CNSA 2.0 algorithms only for all new systems by 2025",
            "Firmware/software: prioritize CNSA 2.0 by 2025",
            "Networking equipment: transition complete by 2026",
            "National Security Systems: full transition by 2033",
        ],
        "filing_url": "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF",
        "penalty_usd": 0,
        "penalty_note": "Required for CMMC Level 3 compliance for DoD contractors",
    },
    "OMB_M_23_02": {
        "name": "OMB Memorandum M-23-02",
        "description": "Federal Zero-Trust Strategy — includes post-quantum cryptography requirements",
        "authority": "Office of Management and Budget",
        "jurisdiction": "US Federal Executive Branch",
        "status": "effective",
        "effective_date": "2022-01-26",
        "soft_deadline": "2024-09-30",
        "hard_deadline": "2025-09-30",
        "mandatory_for": ["All US federal civilian agencies (CFO Act agencies)"],
        "key_requirements": [
            "Inventory network traffic encryption status",
            "Identify post-quantum encryption vulnerabilities",
            "Report PQC readiness to CISA and OMB",
        ],
        "filing_url": "https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf",
        "penalty_usd": 0,
        "penalty_note": "OMB mandates; non-compliance jeopardizes agency budget allocations",
    },
    "NIS2": {
        "name": "EU NIS2 Directive",
        "description": "EU Network and Information Security Directive 2 — Article 21 technical measures",
        "authority": "European Commission / National Competent Authorities",
        "jurisdiction": "European Union",
        "status": "effective",
        "effective_date": "2024-10-17",
        "soft_deadline": "2025-04-17",
        "hard_deadline": "2027-10-17",
        "mandatory_for": [
            "Essential entities (energy, transport, banking, health, digital infrastructure)",
            "Important entities (postal, waste, manufacturing, food, chemicals, digital providers)",
        ],
        "key_requirements": [
            "Risk management measures including cryptographic controls",
            "Encryption of data in transit using state-of-the-art algorithms",
            "Incident reporting within 24 hours of significant incident",
            "Supply chain security including cryptographic software dependencies",
        ],
        "filing_url": "https://digital-strategy.ec.europa.eu/en/policies/nis2-directive",
        "penalty_usd": 10_000_000,
        "penalty_note": "Up to €10M or 2% of global annual turnover (essential entities)",
    },
    "DORA": {
        "name": "EU Digital Operational Resilience Act",
        "description": "Financial sector ICT risk management — includes cryptographic controls",
        "authority": "European Supervisory Authorities (EBA, ESMA, EIOPA)",
        "jurisdiction": "European Union — Financial Sector",
        "status": "effective",
        "effective_date": "2025-01-17",
        "soft_deadline": "2025-07-17",
        "hard_deadline": "2027-01-17",
        "mandatory_for": [
            "Banks, investment firms, crypto-asset service providers",
            "Insurance undertakings, payment institutions, e-money institutions",
            "ICT third-party service providers to financial sector",
        ],
        "key_requirements": [
            "ICT risk management framework including encryption risk",
            "Cryptographic controls aligned with state-of-the-art standards",
            "Digital operational resilience testing (penetration testing)",
            "ICT third-party risk management (supply chain cryptography)",
        ],
        "filing_url": "https://www.eba.europa.eu/regulation-and-policy/digital-operational-resilience-act-dora",
        "penalty_usd": 5_000_000,
        "penalty_note": "Up to €5M for financial entities; up to €500K for natural persons",
    },
    "FIPS_140_3": {
        "name": "FIPS 140-3",
        "description": "Cryptographic module security requirements — Level 1-4",
        "authority": "NIST / CMVP",
        "jurisdiction": "US Federal + regulated sectors",
        "status": "effective",
        "effective_date": "2019-09-22",
        "soft_deadline": "2025-09-22",
        "hard_deadline": "2026-09-22",
        "mandatory_for": ["US federal agencies", "Federal contractors handling sensitive data"],
        "key_requirements": [
            "FIPS 140-2 approved modules must migrate to FIPS 140-3",
            "New procurements must use FIPS 140-3 validated modules",
            "PQC algorithm modules subject to upcoming CMVP validation requirements",
        ],
        "filing_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program",
        "penalty_usd": 0,
        "penalty_note": "Non-compliance blocks federal procurement",
    },
    "PCI_DSS_4": {
        "name": "PCI DSS 4.0",
        "description": "Payment Card Industry Data Security Standard — quantum-safe requirements",
        "authority": "PCI Security Standards Council",
        "jurisdiction": "Global — Payment Card Processing",
        "status": "effective",
        "effective_date": "2024-04-01",
        "soft_deadline": "2025-03-31",
        "hard_deadline": "2025-03-31",
        "mandatory_for": [
            "Merchants, payment processors, acquirers, issuers, service providers",
        ],
        "key_requirements": [
            "Requirement 4.2.1: Strong cryptography for all cardholder data transmissions",
            "Requirement 12.3.3: Cryptographic cipher suites reviewed annually",
            "PQC guidance: review and plan migration of cardholder data encryption",
        ],
        "filing_url": "https://www.pcisecuritystandards.org/document_library/",
        "penalty_usd": 100_000,
        "penalty_note": "Fines of $5,000–$100,000/month per card network; breach liability",
    },
}

_ALGORITHM_COMPLIANCE: Dict[str, Dict[str, str]] = {
    # algorithm → per-framework compliance status
    "ML-KEM-768":  {k: "compliant"     for k in _FRAMEWORKS},
    "ML-KEM-1024": {k: "compliant"     for k in _FRAMEWORKS},
    "ML-DSA-65":   {k: "compliant"     for k in _FRAMEWORKS},
    "SLH-DSA":     {k: "compliant"     for k in _FRAMEWORKS},
    "RSA-2048":    {k: "non_compliant" for k in _FRAMEWORKS},
    "RSA-4096":    {k: "non_compliant" for k in _FRAMEWORKS},
    "ECC-256":     {k: "non_compliant" for k in _FRAMEWORKS},
    "ECC-384":     {k: "non_compliant" for k in _FRAMEWORKS},
}


def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS regulatory_filings (
                id              TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                framework       TEXT NOT NULL,
                filing_type     TEXT NOT NULL,
                generated_at    TEXT NOT NULL,
                content_json    TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'draft'
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reg_org ON regulatory_filings(org_id, framework)"
        )
        conn.commit()


# ── Framework information ─────────────────────────────────────────────────────

def list_frameworks() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    out = []
    for fid, f in _FRAMEWORKS.items():
        hard = datetime.fromisoformat(f["hard_deadline"] + "T00:00:00+00:00")
        soft = datetime.fromisoformat(f["soft_deadline"] + "T00:00:00+00:00")
        days_to_hard = max((hard - now).days, 0)
        days_to_soft = max((soft - now).days, 0)
        urgency = (
            "OVERDUE"   if hard < now else
            "CRITICAL"  if days_to_hard <= 180 else
            "HIGH"      if days_to_hard <= 365 else
            "MEDIUM"    if days_to_hard <= 730 else
            "LOW"
        )
        out.append({
            "id": fid, **f,
            "days_to_hard_deadline": days_to_hard,
            "days_to_soft_deadline": days_to_soft,
            "urgency": urgency,
        })
    out.sort(key=lambda x: x["days_to_hard_deadline"])
    return out


def get_framework(framework_id: str) -> Optional[Dict[str, Any]]:
    if framework_id not in _FRAMEWORKS:
        return None
    frameworks = list_frameworks()
    return next((f for f in frameworks if f["id"] == framework_id), None)


# ── Compliance gap analysis ───────────────────────────────────────────────────

def analyze_compliance_gaps(
    org_id: str,
    scan_summary: Dict[str, Any],
    frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Given a scan summary, evaluate which frameworks the org is compliant with,
    which are at risk, and what actions are required.
    """
    target_frameworks = frameworks or list(_FRAMEWORKS.keys())
    pqc_pct = float(scan_summary.get("pqc_migration_pct", 0) or 0)
    critical_count = int(scan_summary.get("critical_risk_count", 0) or 0)
    high_count = int(scan_summary.get("high_risk_count", 0) or 0)
    total_assets = int(scan_summary.get("total_assets", 0) or 1)

    results = []
    now = datetime.now(timezone.utc)

    for fid in target_frameworks:
        if fid not in _FRAMEWORKS:
            continue
        f = _FRAMEWORKS[fid]
        hard = datetime.fromisoformat(f["hard_deadline"] + "T00:00:00+00:00")
        days_to_hard = max((hard - now).days, 0)

        # Compliance score: 0-100
        pqc_score = pqc_pct  # 0-100
        risk_penalty = min((critical_count * 10 + high_count * 3), 40)
        1.0 if days_to_hard > 365 else max(days_to_hard / 365, 0.1)
        compliance_score = max(pqc_score - risk_penalty, 0)

        # Status
        if compliance_score >= 80 and critical_count == 0:
            compliance_status = "compliant"
        elif compliance_score >= 50 or days_to_hard > 730:
            compliance_status = "partial"
        else:
            compliance_status = "non_compliant"

        # Required actions
        actions = []
        if critical_count > 0:
            actions.append(f"Remediate {critical_count} critical-risk cryptographic assets immediately")
        if pqc_pct < 100:
            gap_assets = round(total_assets * (100 - pqc_pct) / 100)
            actions.append(f"Migrate {gap_assets} remaining assets to PQC algorithms (currently {pqc_pct:.0f}%)")
        if fid == "NIST_SP_800_208" and pqc_pct < 100:
            actions.append("Submit cryptographic inventory to NIST FIPS 203-205 compliance tracker")
        if fid in ("NIS2", "DORA"):
            actions.append("Prepare Article 21 technical measures documentation for supervisory authority")
        if fid == "PCI_DSS_4":
            actions.append("Update cipher suite review documentation (Requirement 12.3.3)")

        results.append({
            "framework_id": fid,
            "framework_name": f["name"],
            "compliance_status": compliance_status,
            "compliance_score": round(compliance_score, 1),
            "hard_deadline": f["hard_deadline"],
            "days_to_hard_deadline": days_to_hard,
            "penalty_at_risk_usd": f["penalty_usd"] if compliance_status == "non_compliant" else 0,
            "required_actions": actions,
            "urgency": (
                "OVERDUE"  if hard < now else
                "CRITICAL" if days_to_hard <= 180 else
                "HIGH"     if days_to_hard <= 365 else
                "MEDIUM"   if days_to_hard <= 730 else "LOW"
            ),
        })

    total_penalty_risk = sum(r["penalty_at_risk_usd"] for r in results)
    non_compliant = [r for r in results if r["compliance_status"] == "non_compliant"]
    partial = [r for r in results if r["compliance_status"] == "partial"]
    compliant = [r for r in results if r["compliance_status"] == "compliant"]

    return {
        "org_id": org_id,
        "analyzed_at": now.isoformat(),
        "frameworks_assessed": len(results),
        "compliant_count": len(compliant),
        "partial_count": len(partial),
        "non_compliant_count": len(non_compliant),
        "total_penalty_risk_usd": total_penalty_risk,
        "total_penalty_risk_fmt": f"${total_penalty_risk/1e6:.1f}M" if total_penalty_risk >= 1e6 else f"${total_penalty_risk:,.0f}",
        "framework_results": sorted(results, key=lambda x: (x["compliance_score"], -x["days_to_hard_deadline"])),
        "overall_posture": (
            "CRITICAL" if len(non_compliant) >= 3 or total_penalty_risk > 50_000_000 else
            "AT_RISK"  if len(non_compliant) >= 1 or len(partial) >= 3 else
            "ADEQUATE" if len(partial) >= 1 else "STRONG"
        ),
    }


# ── Filing generator ──────────────────────────────────────────────────────────

def generate_filing(
    org_id: str,
    framework_id: str,
    scan_summary: Dict[str, Any],
    org_name: str = "Organization",
    contact_email: str = "",
) -> Dict[str, Any]:
    """Generate a regulatory filing / evidence package for a given framework."""
    _ensure_tables()

    if framework_id not in _FRAMEWORKS:
        return {"error": f"Unknown framework: {framework_id}"}

    f = _FRAMEWORKS[framework_id]
    gaps = analyze_compliance_gaps(org_id, scan_summary, [framework_id])
    gap_result = gaps["framework_results"][0] if gaps["framework_results"] else {}

    now = datetime.now(timezone.utc)
    filing_id = "REG-" + hashlib.sha256(f"{org_id}:{framework_id}:{now.isoformat()}".encode()).hexdigest()[:12].upper()

    pqc_pct = float(scan_summary.get("pqc_migration_pct", 0) or 0)
    total_assets = int(scan_summary.get("total_assets", 0) or 0)
    critical = int(scan_summary.get("critical_risk_count", 0) or 0)

    filing_content = {
        "filing_id": filing_id,
        "framework": framework_id,
        "framework_name": f["name"],
        "org_id": org_id,
        "org_name": org_name,
        "contact_email": contact_email,
        "generated_at": now.isoformat(),
        "reporting_period": f"{now.year}-01-01 to {now.isoformat()[:10]}",
        "executive_summary": (
            f"{org_name} has assessed its cryptographic posture against {f['name']}. "
            f"Of {total_assets} cryptographic assets inventoried, {pqc_pct:.0f}% have been "
            f"migrated to NIST-approved post-quantum algorithms. "
            f"{critical} critical-risk assets require immediate remediation. "
            f"Compliance score: {gap_result.get('compliance_score', 0):.0f}/100."
        ),
        "cryptographic_inventory_summary": {
            "total_assets_inventoried": total_assets,
            "pqc_migrated_pct": pqc_pct,
            "critical_risk_count": critical,
            "high_risk_count": int(scan_summary.get("high_risk_count", 0) or 0),
            "medium_risk_count": int(scan_summary.get("medium_risk_count", 0) or 0),
            "low_risk_count": int(scan_summary.get("low_risk_count", 0) or 0),
            "algorithms_in_use": scan_summary.get("algorithms_in_use", []),
        },
        "compliance_status": gap_result.get("compliance_status", "unknown"),
        "compliance_score": gap_result.get("compliance_score", 0),
        "required_actions": gap_result.get("required_actions", []),
        "hard_deadline": f["hard_deadline"],
        "days_to_deadline": gap_result.get("days_to_hard_deadline", 0),
        "migration_roadmap": _generate_roadmap(pqc_pct, total_assets, f["hard_deadline"]),
        "attestation": (
            f"This report was generated automatically by PQC Scanner on {now.isoformat()[:10]}. "
            f"The cryptographic inventory was collected via authenticated TLS certificate scanning. "
            f"Contact {contact_email or 'security@' + org_name.lower().replace(' ', '') + '.com'} for questions."
        ),
        "next_steps": [
            f"Review and validate all {total_assets} inventoried cryptographic assets",
            "Prioritize remediation of critical-risk assets (RSA-1024, early ECC)",
            "Procure FIPS 203/204/205 validated cryptographic libraries",
            f"Submit filing to {f['authority']} by {f['soft_deadline']}",
            f"Complete full migration by {f['hard_deadline']}",
        ],
    }

    content_json = json.dumps(filing_content)

    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO regulatory_filings
               (id, org_id, framework, filing_type, generated_at, content_json, status)
               VALUES (?, ?, ?, 'gap_analysis', ?, ?, 'draft')""",
            (filing_id, org_id, framework_id, now.isoformat(), content_json),
        )
        conn.commit()

    return filing_content


def _generate_roadmap(pqc_pct: float, total_assets: int, hard_deadline: str) -> List[Dict[str, Any]]:
    remaining_pct = max(100.0 - pqc_pct, 0)
    remaining_assets = round(total_assets * remaining_pct / 100)
    try:
        deadline = datetime.fromisoformat(hard_deadline + "T00:00:00+00:00")
        months_remaining = max((deadline - datetime.now(timezone.utc)).days / 30, 1)
    except Exception:
        months_remaining = 24

    phases = []
    if remaining_assets > 0:
        phases = [
            {
                "phase": 1,
                "name": "Inventory and Prioritization",
                "duration_months": min(2, months_remaining * 0.15),
                "tasks": [
                    "Complete cryptographic asset inventory",
                    "Prioritize critical and high-risk assets for immediate migration",
                    "Identify dependencies and migration blockers",
                ],
                "milestone": "Signed-off prioritized migration backlog",
            },
            {
                "phase": 2,
                "name": "Critical Asset Migration",
                "duration_months": min(6, months_remaining * 0.30),
                "tasks": [
                    "Migrate all critical-risk RSA/ECC assets to ML-KEM/ML-DSA",
                    "Update TLS configurations across all internet-facing services",
                    "Validate migrations with FIPS-validated testing tools",
                ],
                "milestone": "0 critical-risk assets remaining",
            },
            {
                "phase": 3,
                "name": "Bulk Migration",
                "duration_months": min(12, months_remaining * 0.40),
                "tasks": [
                    f"Migrate remaining {remaining_assets} assets at scale",
                    "Automate PQC deployment via CI/CD pipeline integration",
                    "Update vendor and third-party agreements",
                ],
                "milestone": ">80% of assets migrated",
            },
            {
                "phase": 4,
                "name": "Validation and Compliance",
                "duration_months": min(3, months_remaining * 0.15),
                "tasks": [
                    "Full cryptographic audit of migrated assets",
                    "Generate regulatory compliance evidence package",
                    "Submit attestation to regulatory authority",
                ],
                "milestone": f"Filing submitted by {hard_deadline}",
            },
        ]
    else:
        phases = [{
            "phase": 1,
            "name": "Maintenance and Monitoring",
            "duration_months": 12,
            "tasks": [
                "Ongoing monitoring for algorithm deprecation advisories",
                "Annual cryptographic asset re-assessment",
                "Respond to new NIST guidance as PQC standards evolve",
            ],
            "milestone": "Annual compliance renewal",
        }]
    return phases


def list_filings(org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, framework, filing_type, generated_at, status
               FROM regulatory_filings WHERE org_id = ?
               ORDER BY generated_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_filing(filing_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        row = conn.execute(
            "SELECT content_json FROM regulatory_filings WHERE id = ? AND org_id = ?",
            (filing_id, org_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row[0])
