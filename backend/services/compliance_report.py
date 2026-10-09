"""
Compliance report generator for post-quantum migration frameworks.

Supported frameworks:
  nist-800-208   NIST SP 800-208 Recommendation for Stateful Hash-Based Signature Schemes
  cnsa-2-0       NSA Commercial National Security Algorithm Suite 2.0
  iso-27001      ISO/IEC 27001:2022 Annex A (cryptography controls)
  pci-dss-4      PCI DSS 4.0 requirement 4 (encryption in transit)

Each framework report maps scan findings to specific controls and produces:
  - control_id: the standard control identifier
  - control_name: human-readable name
  - status: pass | fail | partial | not_assessed
  - affected_assets: list of host:port strings
  - evidence: specific finding details
  - remediation: actionable fix
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


FRAMEWORKS = {
    "nist-800-208": "NIST SP 800-208",
    "cnsa-2-0":     "NSA CNSA 2.0",
    "iso-27001":    "ISO/IEC 27001:2022",
    "pci-dss-4":    "PCI DSS 4.0",
}


# ── Control definitions per framework ────────────────────────────────────────

_NIST_800_208_CONTROLS = [
    {
        "id": "SP800-208-SC-13",
        "name": "Cryptographic Protection — Algorithm Selection",
        "description": "Systems must use NIST-approved cryptographic algorithms. RSA and EC are approved for now but must be migrated by 2030.",
        "rule_ids": {"PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT", "SSH_QUANTUM_VULNERABLE_HOST_KEY", "SSH_NO_PQC_KEX"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "SP800-208-SC-8",
        "name": "Transmission Confidentiality and Integrity",
        "description": "Cryptographic mechanisms must protect the confidentiality and integrity of information during transmission.",
        "rule_ids": {"TLS_VERSION_TOO_LOW", "WEAK_CIPHER", "SSH_WEAK_CIPHER", "SSH_CRITICAL_KEX"},
        "fail_severity": {"critical", "high", "medium"},
    },
    {
        "id": "SP800-208-SC-12",
        "name": "Cryptographic Key Establishment and Management",
        "description": "Keys must be established using approved algorithms. Plan for post-quantum key establishment.",
        "rule_ids": {"PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT", "SSH_NO_PQC_KEX"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "SP800-208-IA-7",
        "name": "Cryptographic Module Authentication",
        "description": "Systems shall implement mechanisms that meet CMVP requirements.",
        "rule_ids": {"CERT_SELF_SIGNED", "CERT_HOSTNAME_MISMATCH"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "SP800-208-MA-4",
        "name": "Non-local Maintenance — Encryption",
        "description": "Remote maintenance sessions must use strong cryptography.",
        "rule_ids": {"SSH_CRITICAL_KEX", "SSH_WEAK_CIPHER"},
        "fail_severity": {"critical", "high"},
    },
]

_CNSA_20_CONTROLS = [
    {
        "id": "CNSA2-KE",
        "name": "Key Establishment — ML-KEM Required by 2030",
        "description": "CNSA 2.0 requires ML-KEM-1024 for key establishment. ML-KEM-768 is acceptable for most systems until 2030.",
        "rule_ids": {"PQC_EC_ENDPOINT", "SSH_NO_PQC_KEX", "SSH_QUANTUM_VULNERABLE_HOST_KEY"},
        "fail_severity": {"critical", "high"},
        "deadline": "2030",
    },
    {
        "id": "CNSA2-DS",
        "name": "Digital Signatures — ML-DSA Required by 2030",
        "description": "CNSA 2.0 requires ML-DSA-87 for digital signatures by 2030. RSA and ECDSA must be phased out.",
        "rule_ids": {"PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT"},
        "fail_severity": {"critical", "high"},
        "deadline": "2030",
    },
    {
        "id": "CNSA2-SK",
        "name": "Symmetric Key — AES-256 Required",
        "description": "CNSA 2.0 mandates AES-256. AES-128 is not approved for classified information.",
        "rule_ids": {"WEAK_CIPHER"},
        "fail_severity": {"critical", "high", "medium"},
        "deadline": "Immediate",
    },
    {
        "id": "CNSA2-HASH",
        "name": "Hashing — SHA-384 or SHA-512 Required",
        "description": "CNSA 2.0 requires SHA-384 or SHA-512. SHA-256 and SHA-1 must be phased out.",
        "rule_ids": {"TLS_VERSION_TOO_LOW", "SSH_CRITICAL_KEX"},
        "fail_severity": {"critical", "high"},
        "deadline": "2025",
    },
    {
        "id": "CNSA2-PROT",
        "name": "Protocol Version — TLS 1.3 Required",
        "description": "CNSA 2.0 requires TLS 1.3 for all new systems. TLS 1.2 must be phased out by 2025.",
        "rule_ids": {"TLS_VERSION_TOO_LOW"},
        "fail_severity": {"critical", "high"},
        "deadline": "2025",
    },
]

_ISO_27001_CONTROLS = [
    {
        "id": "A.8.24",
        "name": "Use of Cryptography",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        "rule_ids": {"PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT", "WEAK_CIPHER", "SSH_QUANTUM_VULNERABLE_HOST_KEY"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "A.8.20",
        "name": "Networks Security — Encryption in Transit",
        "description": "Networks and network services shall be secured. Weak protocols must be disabled.",
        "rule_ids": {"TLS_VERSION_TOO_LOW", "SSH_CRITICAL_KEX", "SSH_WEAK_CIPHER"},
        "fail_severity": {"critical", "high", "medium"},
    },
    {
        "id": "A.5.14",
        "name": "Information Transfer",
        "description": "Information transfer rules and procedures shall protect against interception.",
        "rule_ids": {"WEAK_CIPHER", "TLS_VERSION_TOO_LOW"},
        "fail_severity": {"critical", "high", "medium"},
    },
    {
        "id": "A.8.25",
        "name": "Secure Development Lifecycle",
        "description": "Rules for the secure development of software and systems shall be established.",
        "rule_ids": {"CERT_SELF_SIGNED", "CERT_HOSTNAME_MISMATCH"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "A.7.9",
        "name": "Security of Assets Off-Premises",
        "description": "Assets held off-premises shall be protected using cryptographic controls.",
        "rule_ids": {"CERT_EXPIRY_SOON", "OCSP_STAPLING_MISSING"},
        "fail_severity": {"medium", "high", "critical"},
    },
]

_PCI_DSS_4_CONTROLS = [
    {
        "id": "PCI-R4.2.1",
        "name": "Strong Cryptography — TLS 1.2+ Required",
        "description": "PCI DSS 4.0 requires TLS 1.2 or higher for all cardholder data transmission. TLS 1.3 is strongly recommended.",
        "rule_ids": {"TLS_VERSION_TOO_LOW"},
        "fail_severity": {"critical", "high"},
    },
    {
        "id": "PCI-R4.2.1.1",
        "name": "Trusted Certificates for Inbound Connections",
        "description": "Certificates must be valid and from trusted authorities.",
        "rule_ids": {"CERT_SELF_SIGNED", "CERT_HOSTNAME_MISMATCH", "CERT_EXPIRY_SOON"},
        "fail_severity": {"critical", "high", "medium"},
    },
    {
        "id": "PCI-R12.3.3",
        "name": "Cryptographic Review — Annual Algorithm Assessment",
        "description": "All cipher suites must be documented and reviewed annually.",
        "rule_ids": {"WEAK_CIPHER", "PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT"},
        "fail_severity": {"critical", "high", "medium"},
    },
]

_FRAMEWORK_CONTROLS = {
    "nist-800-208": _NIST_800_208_CONTROLS,
    "cnsa-2-0":     _CNSA_20_CONTROLS,
    "iso-27001":    _ISO_27001_CONTROLS,
    "pci-dss-4":    _PCI_DSS_4_CONTROLS,
}


def _collect_findings_index(scan_results: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """Build {rule_id: [enriched_finding, ...]} index from scan results."""
    index: Dict[str, List[Dict]] = {}
    for r in scan_results:
        for f in (r.get("findings") or []):
            rid = f.get("rule_id") or "UNKNOWN"
            entry = {**f, "_host": f"{r.get('host', '')}:{r.get('port', 443)}"}
            index.setdefault(rid, []).append(entry)
    return index


def _evaluate_control(control: Dict[str, Any],
                       findings_index: Dict[str, List[Dict]]) -> Dict[str, Any]:
    matching: List[Dict] = []
    for rid in control["rule_ids"]:
        matching.extend(findings_index.get(rid, []))

    fail_sev = control.get("fail_severity", {"critical", "high"})
    failed = [f for f in matching if f.get("severity") in fail_sev]
    affected = sorted({f["_host"] for f in failed})

    if not matching:
        status = "not_assessed"
    elif failed:
        status = "fail"
    elif matching:
        status = "partial"
    else:
        status = "pass"

    _EVIDENCE_INTERP = {
        "pass":         "evidence_mapped",
        "fail":         "gap_identified",
        "partial":      "partial_evidence",
        "not_assessed": "insufficient_data",
    }

    return {
        "control_id":            control["id"],
        "control_name":          control["name"],
        "description":           control["description"],
        "status":                status,
        "evidence_interpretation": _EVIDENCE_INTERP.get(status, status),
        "affected_assets":       affected,
        "finding_count":         len(failed),
        "evidence": [
            {
                "asset":    f["_host"],
                "rule_id":  f.get("rule_id"),
                "severity": f.get("severity"),
                "title":    f.get("title"),
                "fix":      f.get("fix"),
            }
            for f in failed[:10]
        ],
        **({"deadline": control["deadline"]} if "deadline" in control else {}),
    }


def generate_compliance_report(
    framework: str,
    scan_results: List[Dict[str, Any]],
    org_name: str = "",
    scan_id: str = "",
) -> Dict[str, Any]:
    """
    Generate a compliance report for the given framework.

    framework must be one of: nist-800-208, cnsa-2-0, iso-27001, pci-dss-4
    scan_results is the list of per-host dicts from scanner.scan_host().
    """
    if framework not in _FRAMEWORK_CONTROLS:
        return {"error": f"Unknown framework '{framework}'. Supported: {', '.join(FRAMEWORKS)}"}

    controls_def = _FRAMEWORK_CONTROLS[framework]
    findings_index = _collect_findings_index(scan_results)

    evaluated = [_evaluate_control(c, findings_index) for c in controls_def]

    total   = len(evaluated)
    passing = sum(1 for c in evaluated if c["status"] == "pass")
    failing = sum(1 for c in evaluated if c["status"] == "fail")
    partial = sum(1 for c in evaluated if c["status"] == "partial")
    not_ass = sum(1 for c in evaluated if c["status"] == "not_assessed")

    overall = "compliant" if failing == 0 and partial == 0 else \
              "non-compliant" if failing > 0 else "partial"

    return {
        "framework":     framework,
        "framework_name": FRAMEWORKS[framework],
        "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "org_name":      org_name,
        "scan_id":       scan_id,
        "assets_assessed": len({
            f"{r.get('host')}:{r.get('port', 443)}"
            for r in scan_results if not r.get("error")
        }),
        "overall_status": overall,
        "summary": {
            "total_controls":         total,
            "passing":                passing,
            "failing":                failing,
            "partial":                partial,
            "not_assessed":           not_ass,
            "compliance_percentage":  round(passing / total * 100) if total else 0,
        },
        "controls": evaluated,
    }
