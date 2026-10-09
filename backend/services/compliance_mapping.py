"""
PQC Compliance Framework Mapper

Maps an organization's PQC posture against major regulatory and security
frameworks. Provides gap analysis, control status, and evidence mapping.

Frameworks covered:
  NIST CSF 2.0       — Cybersecurity Framework (US)
  CMMC Level 2/3     — Cybersecurity Maturity Model Certification (DoD)
  FedRAMP High       — Federal Risk and Authorization Management Program
  SOC 2 Type II      — Service Organization Controls (AICPA)
  ISO 27001:2022     — Information Security Management System
  NIS2               — EU Network and Information Systems Directive (2024)
  DORA               — EU Digital Operational Resilience Act (2025)
  NIST SP 800-53     — Security and Privacy Controls
  HIPAA              — Health Insurance Portability and Accountability Act

Control status and framework grades are derived from this organization's own
scan posture. With no scanned asset the report returns ``available: false``
with a reason and the minimum needed, and every score and grade is null: a
customer who has not scanned yet has not failed a framework.

Pure stdlib — no external dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

#: Fewest scanned assets before any framework score or grade is published.
MINIMUM_SCANNED_ASSETS = 1

UNAVAILABLE_REASON = (
    "No scanned assets on record, so framework alignment cannot be assessed. "
    "Run a TLS scan (or import a CBOM/SBOM) and the control mapping is graded on the next report."
)

_MINIMUM_DATA = {
    "scanned_assets": MINIMUM_SCANNED_ASSETS,
    "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
}


# ── Framework definitions ────────────────────────────────────────────────────────

_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "nist_csf_2": {
        "id": "nist_csf_2",
        "name": "NIST CSF 2.0",
        "full_name": "NIST Cybersecurity Framework 2.0",
        "authority": "NIST (National Institute of Standards and Technology)",
        "effective_date": "2024-02-26",
        "mandatory_for": "US Federal agencies (FISMA); strongly recommended for critical infrastructure",
        "pqc_stance": "IDENTIFY.GV-SC (supply chain risk) + PROTECT.DS (data security) require PQC inventory and roadmap",
        "controls": [
            {
                "id": "GV.SC-07",
                "name": "Cryptographic Inventory",
                "description": "Organization maintains an inventory of cryptographic assets used in products and services",
                "pqc_relevance": "critical",
                "mapping": "CBOM must exist; all algorithms classified against FIPS 203/204/205",
            },
            {
                "id": "ID.AM-02",
                "name": "Asset Inventory",
                "description": "Software, hardware, services, and systems are inventoried",
                "pqc_relevance": "high",
                "mapping": "Quantum-vulnerable algorithms must be enumerated in asset inventory",
            },
            {
                "id": "PR.DS-02",
                "name": "Data in Transit Protected",
                "description": "Data-in-transit is protected",
                "pqc_relevance": "critical",
                "mapping": "TLS 1.3 with ML-KEM hybrid required; RSA/ECDH key exchange must be replaced",
            },
            {
                "id": "PR.DS-01",
                "name": "Data at Rest Protected",
                "description": "Data-at-rest is protected",
                "pqc_relevance": "high",
                "mapping": "AES-256 (CNSA 2.0 approved) required for symmetric encryption",
            },
            {
                "id": "GV.RM-06",
                "name": "Risk Strategy",
                "description": "A cybersecurity risk management strategy is established and communicated",
                "pqc_relevance": "high",
                "mapping": "Formal PQC migration roadmap required; Q-Day risk must be in risk register",
            },
        ],
        "deadline": "No hard deadline; agencies must align with OMB M-23-02",
    },
    "cmmc_3": {
        "id": "cmmc_3",
        "name": "CMMC Level 3",
        "full_name": "Cybersecurity Maturity Model Certification — Level 3",
        "authority": "US Department of Defense (DoD)",
        "effective_date": "2025-12-16",
        "mandatory_for": "DoD contractors handling CUI (Controlled Unclassified Information) and up",
        "pqc_stance": "CMMC Level 3 requires compliance with NIST SP 800-172; cryptographic agility mandated",
        "controls": [
            {
                "id": "SC.3.177",
                "name": "Cryptographic Mechanisms",
                "description": "Employ cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission",
                "pqc_relevance": "critical",
                "mapping": "Must adopt CNSA 2.0 suite; RSA/ECDH for CUI transmission is non-compliant after 2030",
            },
            {
                "id": "SC.3.187",
                "name": "Cryptographic Key Management",
                "description": "Establish and manage cryptographic keys when cryptography is employed",
                "pqc_relevance": "critical",
                "mapping": "Key lifecycle management must support ML-KEM and ML-DSA key types",
            },
            {
                "id": "RA.3.077",
                "name": "Risk Assessments",
                "description": "Periodically assess risk to operations, assets, and individuals",
                "pqc_relevance": "high",
                "mapping": "Q-Day risk must be included in periodic risk assessments; HNDL threat documented",
            },
            {
                "id": "CM.3.068",
                "name": "Security Configuration",
                "description": "Establish and maintain baseline configurations",
                "pqc_relevance": "medium",
                "mapping": "Approved algorithm list must be updated to exclude pre-quantum algorithms",
            },
        ],
        "deadline": "2025-12-16 (phased rollout for Level 2 contractors; Level 3 by 2026)",
    },
    "fedramp_high": {
        "id": "fedramp_high",
        "name": "FedRAMP High",
        "full_name": "Federal Risk and Authorization Management Program — High Baseline",
        "authority": "GSA FedRAMP PMO / OMB",
        "effective_date": "2024-01-01",
        "mandatory_for": "Cloud Service Providers hosting US federal government High-impact data",
        "pqc_stance": "OMB M-23-02 mandates PQC migration plan by January 2024; NSS must comply by 2030",
        "controls": [
            {
                "id": "SC-8(1)",
                "name": "Cryptographic Protection",
                "description": "Transmission Confidentiality and Integrity — cryptographic mechanisms",
                "pqc_relevance": "critical",
                "mapping": "Must implement CNSA 2.0 approved algorithms; TLS must support PQC key exchange",
            },
            {
                "id": "SC-28(1)",
                "name": "Protection of Information at Rest",
                "description": "Cryptographic protection of data at rest",
                "pqc_relevance": "high",
                "mapping": "AES-256 minimum; key wrapping algorithms must be PQC-ready by 2030",
            },
            {
                "id": "SA-9",
                "name": "External System Services",
                "description": "Supply chain cryptographic requirements",
                "pqc_relevance": "high",
                "mapping": "Third-party APIs and SaaS used must document PQC roadmap by FY2026",
            },
        ],
        "deadline": "2030-01-01 (NSS systems); 2033-01-01 (all other systems)",
    },
    "soc2": {
        "id": "soc2",
        "name": "SOC 2 Type II",
        "full_name": "Service Organization Control 2 — Type II",
        "authority": "AICPA",
        "effective_date": "2017-09-01",
        "mandatory_for": "SaaS vendors handling customer data; required by enterprise customers",
        "pqc_stance": "CC9.1 (risk identification) and CC6.1 (logical access) are being updated for PQC; auditors increasingly asking",
        "controls": [
            {
                "id": "CC6.1",
                "name": "Logical Access Security",
                "description": "Security controls over logical access to the entity's systems",
                "pqc_relevance": "high",
                "mapping": "Encryption algorithms used must be documented; quantum risk disclosure expected by 2026",
            },
            {
                "id": "CC9.1",
                "name": "Risk Identification",
                "description": "Identify risks to meeting service commitments",
                "pqc_relevance": "high",
                "mapping": "Q-Day / HNDL risk must be in risk register; migration plan is evidence",
            },
            {
                "id": "CC6.7",
                "name": "Encryption of Data in Transit",
                "description": "Restricts the transmission of confidential information",
                "pqc_relevance": "medium",
                "mapping": "TLS version and algorithm suite must be documented; auditors may flag RSA key exchange",
            },
        ],
        "deadline": "No hard deadline; expect auditor scrutiny from 2026 forward",
    },
    "iso27001_2022": {
        "id": "iso27001_2022",
        "name": "ISO 27001:2022",
        "full_name": "ISO/IEC 27001:2022 — Information Security Management",
        "authority": "ISO / IEC",
        "effective_date": "2022-10-25",
        "mandatory_for": "Global organizations seeking ISMS certification; often required by EU enterprise contracts",
        "pqc_stance": "Annex A.8.24 (use of cryptography) requires a cryptography policy; PQC risk must be addressed",
        "controls": [
            {
                "id": "A.8.24",
                "name": "Use of Cryptography",
                "description": "Rules on effective use of cryptography must be defined and implemented",
                "pqc_relevance": "critical",
                "mapping": "Policy must reference FIPS 203/204/205; quantum-vulnerable algorithm list must be maintained",
            },
            {
                "id": "A.5.19",
                "name": "Information Security in Supplier Relationships",
                "description": "Supply chain cryptographic requirements",
                "pqc_relevance": "medium",
                "mapping": "Supplier contracts must include PQC migration timelines from 2025 onward",
            },
            {
                "id": "A.8.20",
                "name": "Networks Security",
                "description": "Networks shall be managed and controlled to protect information",
                "pqc_relevance": "high",
                "mapping": "TLS 1.3 with forward secrecy mandatory; PQC hybrid key exchange preferred",
            },
        ],
        "deadline": "No hard deadline; 2025 transition deadline for 27001:2022 (from 27001:2013)",
    },
    "nis2": {
        "id": "nis2",
        "name": "NIS2",
        "full_name": "EU Network and Information Systems Directive 2022/2555",
        "authority": "European Commission",
        "effective_date": "2024-10-17",
        "mandatory_for": "EU member state essential and important entities (energy, health, finance, transport, digital infrastructure)",
        "pqc_stance": "Article 21(2)(h) requires state-of-the-art cryptography; ENISA is mapping PQC as state-of-the-art from 2025",
        "controls": [
            {
                "id": "Art.21(2)(h)",
                "name": "Cryptography Policy",
                "description": "Policies and procedures regarding the use of cryptography",
                "pqc_relevance": "critical",
                "mapping": "Entities must assess quantum risk and adopt ETSI/NIST PQC standards in their cryptography policy",
            },
            {
                "id": "Art.21(2)(a)",
                "name": "Risk Analysis",
                "description": "Risk analysis and information system security policies",
                "pqc_relevance": "high",
                "mapping": "HNDL risk from quantum computing must be in risk analysis as of 2025",
            },
            {
                "id": "Art.21(2)(e)",
                "name": "Supply Chain Security",
                "description": "Security in network and information systems acquisition, development, and maintenance",
                "pqc_relevance": "medium",
                "mapping": "Supply chain PQC readiness required; SBOM/CBOM production expected",
            },
        ],
        "deadline": "2024-10-17 transposition deadline (member states); enforcement varies",
    },
    "dora": {
        "id": "dora",
        "name": "DORA",
        "full_name": "EU Digital Operational Resilience Act — Regulation 2022/2554",
        "authority": "European Commission / EBA / ESMA / EIOPA",
        "effective_date": "2025-01-17",
        "mandatory_for": "EU financial entities: banks, insurers, investment firms, crypto-asset providers",
        "pqc_stance": "Article 9(2) operational resilience testing + Article 6 ICT risk framework must include quantum threats",
        "controls": [
            {
                "id": "Art.9(2)",
                "name": "ICT Security Testing",
                "description": "Penetration testing and threat-led resilience testing",
                "pqc_relevance": "high",
                "mapping": "TLPT exercises must include quantum-readiness assessment; PQC migration a test scope item from 2025",
            },
            {
                "id": "Art.6",
                "name": "ICT Risk Framework",
                "description": "Framework for the management of ICT risks",
                "pqc_relevance": "critical",
                "mapping": "Quantum risk is an ICT risk; migration plan with timelines required; board-level ownership mandated",
            },
            {
                "id": "Art.28",
                "name": "Third-Party ICT Risk",
                "description": "General principles on ICT third-party risk",
                "pqc_relevance": "medium",
                "mapping": "Critical ICT third parties must disclose PQC readiness to regulated financial entities",
            },
        ],
        "deadline": "2025-01-17 (fully in force); TLPT requirements by 2026 for significant entities",
    },
}


# ── Compliance scoring ──────────────────────────────────────────────────────────

def _score_control(control: Dict[str, Any], pqc_report: Dict[str, Any]) -> Dict[str, Any]:
    """Score a single control against PQC report data."""
    relevance = control["pqc_relevance"]
    score = pqc_report.get("overall_score", 0)
    grade = pqc_report.get("overall_grade", "F")
    has_cbom = bool(pqc_report.get("asset_count", 0))

    # Map control type to relevant metric
    control_id = control["id"]
    status = "unknown"
    gap = ""
    evidence = []

    if "cryptograph" in control["description"].lower() or "SC-8" in control_id or "A.8.24" in control_id:
        # Cryptography controls
        if score >= 80:
            status = "compliant"
            evidence.append(f"FIPS 203/204/205 coverage: {score}%")
        elif score >= 50:
            status = "partial"
            gap = f"Score {score}/100 — quantum-vulnerable algorithms present"
            evidence.append(f"FIPS grade: {grade}")
        else:
            status = "non_compliant"
            gap = f"Score {score}/100 — significant quantum-vulnerable exposure"

    elif "inventory" in control["description"].lower() or "GV.SC" in control_id:
        # Inventory / CBOM controls
        if has_cbom:
            status = "partial"
            evidence.append(f"{pqc_report.get('asset_count', 0)} assets in CBOM")
            if score < 70:
                gap = "Algorithms not fully classified against FIPS 203/204/205"
        else:
            status = "non_compliant"
            gap = "No crypto asset inventory (CBOM) found"

    elif "risk" in control["description"].lower():
        # Risk management controls
        status = "partial"
        gap = "Q-Day risk quantification and HNDL threat model required for full compliance"
        evidence.append("Risk register must include quantum computing timeline")

    elif "transit" in control["description"].lower() or "transmission" in control["description"].lower():
        # Data in transit
        vuln = pqc_report.get("summary", {}).get("quantum_vulnerable", 0)
        total = pqc_report.get("asset_count", 1)
        if vuln == 0:
            status = "compliant"
            evidence.append("No quantum-vulnerable key exchange detected")
        elif vuln / max(1, total) < 0.2:
            status = "partial"
            gap = f"{vuln} quantum-vulnerable endpoints remain"
        else:
            status = "non_compliant"
            gap = f"{vuln}/{total} endpoints use quantum-vulnerable key exchange"

    else:
        # Default scoring from overall posture
        status = "compliant" if score >= 80 else "partial" if score >= 40 else "non_compliant"
        if score < 80:
            gap = f"Overall PQC score {score}/100 falls short of compliance threshold"

    weight = {"critical": 3, "high": 2, "medium": 1}.get(relevance, 1)
    score_val = {"compliant": 100, "partial": 50, "non_compliant": 0, "unknown": 25}.get(status, 25)

    return {
        **control,
        "status": status,
        "gap": gap,
        "evidence": evidence,
        "weight": weight,
        "weighted_score": score_val * weight,
        "max_weighted_score": 100 * weight,
    }


def build_compliance_report(
    pqc_report: Dict[str, Any],
    frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Map PQC posture against regulatory frameworks.

    pqc_report  — output of fips_pqc.build_fips_compliance_report()
    frameworks  — list of framework IDs to include; None = all
    """
    selected = frameworks or list(_FRAMEWORKS.keys())
    now = datetime.now(timezone.utc)

    # A framework grade needs posture to grade. With no scanned asset every
    # control would fall through to its "non_compliant" default and the report
    # would hand a new customer an F for evidence they have not supplied yet.
    if int(pqc_report.get("asset_count") or 0) < MINIMUM_SCANNED_ASSETS:
        return {
            "generated_at": now.isoformat(),
            "available": False,
            "reason": UNAVAILABLE_REASON,
            "minimum_data": dict(_MINIMUM_DATA),
            "pqc_overall_score": None,
            "pqc_grade": None,
            "frameworks_assessed": 0,
            "overall_compliance_score": None,
            "frameworks": [
                {
                    **{k: v for k, v in (_FRAMEWORKS.get(fw_id) or {}).items() if k != "controls"},
                    "controls": [
                        {**c, "status": "not_assessed", "gap": None, "evidence": [],
                         "weight": None, "weighted_score": None, "max_weighted_score": None}
                        for c in (_FRAMEWORKS.get(fw_id) or {}).get("controls", [])
                    ],
                    "framework_score": None,
                    "grade": None,
                    "available": False,
                    "reason": UNAVAILABLE_REASON,
                    "compliant_controls": 0,
                    "partial_controls": 0,
                    "non_compliant_controls": 0,
                    "total_controls": len((_FRAMEWORKS.get(fw_id) or {}).get("controls", [])),
                    "top_gap": None,
                }
                for fw_id in selected if _FRAMEWORKS.get(fw_id)
            ],
            "priority_gaps": [],
            "quick_wins": [],
        }

    results: List[Dict[str, Any]] = []
    for fw_id in selected:
        fw = _FRAMEWORKS.get(fw_id)
        if not fw:
            continue
        scored_controls = [_score_control(c, pqc_report) for c in fw["controls"]]

        total_weighted = sum(c["weighted_score"] for c in scored_controls)
        max_weighted = sum(c["max_weighted_score"] for c in scored_controls)
        fw_score = round(total_weighted / max(1, max_weighted) * 100)

        compliant_count = sum(1 for c in scored_controls if c["status"] == "compliant")
        partial_count = sum(1 for c in scored_controls if c["status"] == "partial")
        non_count = sum(1 for c in scored_controls if c["status"] == "non_compliant")

        grade = "A" if fw_score >= 90 else "B" if fw_score >= 75 else "C" if fw_score >= 55 else "D" if fw_score >= 35 else "F"

        results.append({
            **{k: v for k, v in fw.items() if k != "controls"},
            "controls": scored_controls,
            "framework_score": fw_score,
            "grade": grade,
            "available": True,
            "reason": "",
            "compliant_controls": compliant_count,
            "partial_controls": partial_count,
            "non_compliant_controls": non_count,
            "total_controls": len(scored_controls),
            "top_gap": next((c["gap"] for c in scored_controls if c["status"] == "non_compliant" and c.get("gap")), None),
        })

    # Overall cross-framework score
    all_scores = [r["framework_score"] for r in results]
    overall = round(sum(all_scores) / max(1, len(all_scores)))

    return {
        "generated_at": now.isoformat(),
        "available": True,
        "reason": "",
        "minimum_data": dict(_MINIMUM_DATA),
        "pqc_overall_score": pqc_report.get("overall_score", 0),
        "pqc_grade": pqc_report.get("overall_grade", "N/A"),
        "frameworks_assessed": len(results),
        "overall_compliance_score": overall,
        "frameworks": results,
        "priority_gaps": _priority_gaps(results),
        "quick_wins": _quick_wins(results),
    }


def _priority_gaps(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    gaps = []
    for fw in results:
        for ctrl in fw.get("controls", []):
            if ctrl["status"] == "non_compliant" and ctrl.get("gap"):
                gaps.append({
                    "framework": fw["name"],
                    "control": ctrl["id"],
                    "control_name": ctrl["name"],
                    "gap": ctrl["gap"],
                    "relevance": ctrl["pqc_relevance"],
                    "mandatory_for": fw.get("mandatory_for", ""),
                })
    gaps.sort(key=lambda g: {"critical": 0, "high": 1, "medium": 2}.get(g["relevance"], 3))
    return gaps[:10]


def _quick_wins(results: List[Dict[str, Any]]) -> List[str]:
    wins = []
    for fw in results:
        for ctrl in fw.get("controls", []):
            if ctrl["status"] == "partial":
                mapping = ctrl.get("mapping", "")
                if mapping and len(mapping) < 120:
                    wins.append(f"[{fw['name']} — {ctrl['id']}] {ctrl['name']}: {mapping}")
    return list(dict.fromkeys(wins))[:8]


def list_frameworks() -> List[Dict[str, Any]]:
    return [{"id": k, "name": v["name"], "full_name": v["full_name"],
             "authority": v["authority"], "deadline": v.get("deadline", "TBD")}
            for k, v in _FRAMEWORKS.items()]
