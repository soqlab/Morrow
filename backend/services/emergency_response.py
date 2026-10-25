"""
Crypto Emergency Response Center

Generates a time-boxed, org-specific incident response plan for a cryptographic
emergency: Q-Day announcement, algorithm zero-day break, HNDL exposure disclosure,
or regulatory mandate requiring immediate migration.

Uses live scan data to produce asset-specific tasks ordered by blast radius and
data sensitivity. Outputs a structured playbook with owners, timelines, and
measurable success criteria.

Pure stdlib — no external dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


_EMERGENCY_TYPES: Dict[str, Dict[str, Any]] = {
    "qday": {
        "name": "Q-Day Announcement",
        "description": "A cryptographically-relevant quantum computer (CRQC) has been announced or demonstrated",
        "severity": "critical",
        "color": "#f87171",
        "urgency": "Immediate action required — all RSA/ECDH-protected communications are at risk",
        "response_window_hours": 168,  # 7 days
    },
    "algorithm_break": {
        "name": "Algorithm Zero-Day",
        "description": "A classical cryptanalysis break has been discovered in a widely-used algorithm",
        "severity": "critical",
        "color": "#f87171",
        "urgency": "Rotate keys and replace algorithm within 24-72 hours",
        "response_window_hours": 72,
    },
    "hndl_disclosure": {
        "name": "HNDL Exposure Confirmed",
        "description": "Evidence that adversaries have been harvesting encrypted traffic for future decryption",
        "severity": "high",
        "color": "#fb923c",
        "urgency": "Prioritize migration of highest-sensitivity data channels",
        "response_window_hours": 336,  # 14 days
    },
    "regulatory": {
        "name": "Regulatory Mandate",
        "description": "Emergency post-quantum compliance mandate issued (e.g., CISA emergency directive)",
        "severity": "high",
        "color": "#facc15",
        "urgency": "Compliance required by mandate deadline; non-compliance = sanctions",
        "response_window_hours": 720,  # 30 days
    },
    "canary_trip": {
        "name": "Canary Token Tripped",
        "description": "A crypto canary token has been accessed, indicating active key compromise",
        "severity": "critical",
        "color": "#f87171",
        "urgency": "Active compromise suspected — rotate all associated keys immediately",
        "response_window_hours": 24,
    },
}


def _risk_order(scan: Dict[str, Any]) -> int:
    """Sort key: critical=0, high=1, medium=2, low=3."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        (scan.get("risk_level") or "").lower(), 4
    )


def _vulnerable_algos(scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return deduplicated vulnerable assets sorted by risk."""
    VULN = {"RSA", "RSA-2048", "RSA-3072", "RSA-4096", "ECDSA", "ECDH",
            "ECDH-256", "ECDH-384", "P-256", "P-384", "P-521", "DH", "DHE",
            "ED25519", "X25519", "RC4", "DES", "3DES", "MD5", "SHA-1",
            "TLS-1.0", "TLS-1.1", "SSL-3.0"}

    seen: Dict[str, Dict[str, Any]] = {}
    for row in scans:
        key = f"{row.get('host', '')}:{row.get('port', '')}"
        algo = str(row.get("algorithm") or row.get("cipher") or "").upper().strip()
        is_vuln = any(algo == v.upper() or algo.startswith(v.upper()) for v in VULN)
        if is_vuln:
            existing = seen.get(key)
            if not existing:
                seen[key] = row
            else:
                try:
                    if (row.get("scan_time") or "") > (existing.get("scan_time") or ""):
                        seen[key] = row
                except Exception:
                    pass

    assets = list(seen.values())
    assets.sort(key=_risk_order)
    return assets


def _migrate_action(algo: str) -> str:
    """Return the migration action for an algorithm."""
    a = algo.upper()
    if any(x in a for x in ("RSA", "ECDSA", "ECDH", "DH", "DHE", "P-256", "P-384", "P-521")):
        return "Replace key exchange with X25519MLKEM768; replace certificates with ML-DSA-65"
    if any(x in a for x in ("ED25519", "X25519")):
        return "Upgrade to hybrid: X25519MLKEM768 for KEM, ML-DSA-44 for signatures"
    if any(x in a for x in ("RC4", "DES", "3DES")):
        return "Replace with AES-256-GCM immediately (classically broken — emergency priority)"
    if any(x in a for x in ("MD5", "SHA-1")):
        return "Replace hash with SHA-256/SHA-384; re-sign all certificates"
    if any(x in a for x in ("TLS-1.0", "TLS-1.1", "SSL-3.0")):
        return "Disable immediately; enforce TLS 1.3 only"
    return f"Investigate {algo} — consult NIST SP 800-175B for migration guidance"


def build_emergency_response_plan(
    scans: List[Dict[str, Any]],
    emergency_type: str = "qday",
    declared_by: str = "CISO",
    additional_context: str = "",
) -> Dict[str, Any]:
    """
    Generate a full incident response plan for a cryptographic emergency.

    scans          — current scan rows (host, port, algorithm, risk_level, scan_time)
    emergency_type — one of: qday, algorithm_break, hndl_disclosure, regulatory, canary_trip
    declared_by    — who declared the emergency (for the plan header)
    """
    now = datetime.now(timezone.utc)
    event = _EMERGENCY_TYPES.get(emergency_type, _EMERGENCY_TYPES["qday"])
    vuln_assets = _vulnerable_algos(scans)

    critical_assets = [a for a in vuln_assets if (a.get("risk_level") or "").lower() == "critical"]
    high_assets = [a for a in vuln_assets if (a.get("risk_level") or "").lower() == "high"]
    medium_assets = [a for a in vuln_assets if (a.get("risk_level") or "").lower() == "medium"]
    other_assets = [a for a in vuln_assets if (a.get("risk_level") or "").lower() not in ("critical", "high", "medium")]

    # Build phase timelines
    phases = _build_phases(emergency_type, critical_assets, high_assets, medium_assets, other_assets, now)

    # Immediate actions (T+0h) — always first
    immediate_actions = [
        "Activate War Room — open Morrow War Room and monitor live events",
        f"Declare emergency to: {declared_by}, Legal, Communications, CISO, Board (if Q-Day or regulatory)",
        "Freeze all new deployments that introduce RSA/ECDH cryptography",
        "Increase monitoring frequency on all external TLS endpoints to 15-minute intervals",
        "Brief operations team — do NOT rotate all keys simultaneously (risk of outage)",
    ]
    if emergency_type == "canary_trip":
        immediate_actions.insert(1, "ISOLATE the affected system immediately — assume key compromise")
        immediate_actions.insert(2, "Revoke all certificates associated with the tripped canary token")
    if emergency_type == "hndl_disclosure":
        immediate_actions.append("Document HNDL exposure window dates for breach notification obligations")

    # Communications
    comms = _build_comms(emergency_type, len(vuln_assets), event)

    return {
        "generated_at": now.isoformat(),
        "emergency_type": emergency_type,
        "emergency_name": event["name"],
        "severity": event["severity"],
        "color": event["color"],
        "urgency": event["urgency"],
        "description": event["description"],
        "additional_context": additional_context,
        "declared_by": declared_by,
        "declared_at": now.isoformat(),
        "response_window_hours": event["response_window_hours"],
        "asset_summary": {
            "total_vulnerable": len(vuln_assets),
            "critical": len(critical_assets),
            "high": len(high_assets),
            "medium": len(medium_assets),
            "other": len(other_assets),
            "total_scanned": len(set(f"{s.get('host')}:{s.get('port')}" for s in scans)),
        },
        "immediate_actions": immediate_actions,
        "phases": phases,
        "communications_plan": comms,
        "top_priority_assets": [
            {
                "host": a.get("host", ""),
                "port": a.get("port", ""),
                "algorithm": a.get("algorithm") or a.get("cipher") or "unknown",
                "risk_level": a.get("risk_level", "unknown"),
                "action": _migrate_action(a.get("algorithm") or a.get("cipher") or ""),
            }
            for a in vuln_assets[:15]
        ],
        "success_criteria": _success_criteria(emergency_type, len(vuln_assets)),
        "post_incident": [
            "Conduct a 30-day post-incident review: what slowed migration?",
            "Update CBOM with all algorithm changes made during emergency",
            "File compliance documentation with regulators if required (NIS2, DORA, FedRAMP)",
            "Increase scan cadence to daily for 90 days post-emergency",
            "Publish updated Crypto Agility score to board",
        ],
    }


def _build_phases(
    etype: str,
    critical: List, high: List, medium: List, other: List,
    now: datetime,
) -> List[Dict[str, Any]]:
    phases = [
        {
            "phase": "T+0h",
            "label": "Declare & Contain",
            "deadline": "Within 1 hour",
            "owner": "CISO / Security Lead",
            "tasks": [
                "Activate incident response team and open war room",
                "Freeze crypto-touching deployments",
                f"Confirm {len(critical)} critical-risk assets for immediate action",
                "Enable 15-minute scan cadence on external endpoints",
            ],
            "success": "All stakeholders notified; war room operational",
        },
        {
            "phase": "T+4h",
            "label": "Triage & Prioritize",
            "deadline": "Within 4 hours",
            "owner": "Security Engineering",
            "tasks": [
                f"Generate replacement configs for top {min(5, len(critical))} critical assets using post-quantum Config Generator",
                "Identify which assets carry long-lived sensitive data (HNDL priority)",
                "Assign migration owners per asset (max 3 assets per engineer)",
                "Stand up test environment with X25519MLKEM768 TLS",
            ],
            "success": f"Top {min(5, len(critical))} critical assets have migration configs ready",
        },
        {
            "phase": "T+24h",
            "label": "Critical Asset Migration",
            "deadline": "24 hours",
            "owner": "Engineering Team",
            "tasks": [
                f"Migrate {len(critical)} critical-risk endpoints to X25519MLKEM768",
                "Deploy ML-DSA-65 certificates on externally-facing services",
                "Verify post-quantum negotiation with: openssl s_client -groups X25519MLKEM768",
                "Update canary tokens on migrated endpoints",
                "Scan and confirm migration success via Morrow",
            ],
            "success": f"0 critical-risk assets remain; all {len(critical)} migrated and verified",
        },
        {
            "phase": "T+72h",
            "label": "High Risk Migration",
            "deadline": "72 hours",
            "owner": "Engineering Team",
            "tasks": [
                f"Migrate {len(high)} high-risk endpoints",
                "Update all internal API-to-API communication to use post-quantum",
                "Rotate all certificate authority (CA) keys if algorithm break type",
                "Run compliance scan and update FIPS 203/204/205 report",
            ],
            "success": "0 critical or high-risk assets remain",
        },
        {
            "phase": "T+7d",
            "label": "Full Remediation",
            "deadline": "7 days",
            "owner": "Engineering + DevOps",
            "tasks": [
                f"Migrate {len(medium)} medium-risk and {len(other)} remaining endpoints",
                "Update developer documentation and internal runbooks",
                "CI/CD gate enforcing post-quantum-only algorithms for new deployments",
                "Board update: migration progress, remaining exposure, cost summary",
                "Publish updated CBOM and compliance report",
            ],
            "success": "All scanned assets migrated; FIPS grade A or B achieved",
        },
    ]
    if etype == "canary_trip":
        phases[0]["tasks"].insert(1, "REVOKE all certificates on affected host immediately")
        phases[1]["tasks"].insert(0, "Forensic analysis: which canary was tripped and when?")
    return phases


def _customer_message() -> str:
    from services.public_config import status_page_url
    status_url = status_page_url()
    return (
        "We are proactively upgrading our cryptographic infrastructure. "
        "[Confirm before sending: state whether any customer data was affected, based on your investigation.]"
        + (f" Updates at {status_url}." if status_url else "")
    )


def _build_comms(etype: str, vuln_count: int, event: Dict) -> List[Dict[str, Any]]:
    return [
        {
            "audience": "Executive Team / Board",
            "timing": "T+2h",
            "channel": "Emergency email + verbal briefing",
            "message": f"{event['name']} declared. {vuln_count} vulnerable assets identified. "
                       f"Emergency response plan activated. Full update in 24 hours.",
            "format": "2-minute verbal + 1-page written brief",
        },
        {
            "audience": "Engineering Team",
            "timing": "T+0h",
            "channel": "Slack / Teams war room channel",
            "message": "Crypto emergency declared. Freeze all RSA/ECDH deployments. "
                       "Report to #pq-emergency channel. Migration configs in Morrow.",
            "format": "Instant message + pinned instructions",
        },
        {
            "audience": "Legal / Compliance",
            "timing": "T+4h",
            "channel": "Secure email",
            "message": f"Incident type: {event['name']}. Assessing regulatory notification obligations "
                       f"(NIS2, DORA, FedRAMP, SOC2). Data at risk: classified per data inventory.",
            "format": "Formal incident notification memo",
        },
        {
            "audience": "Customers / Partners (if applicable)",
            "timing": "T+72h",
            "channel": "Email / Status page",
            "message": _customer_message(),
            "format": "Public status update if disclosure required",
        },
    ]


def _success_criteria(etype: str, vuln_count: int) -> List[str]:
    return [
        f"0 quantum-vulnerable assets in production (down from {vuln_count})",
        "All external TLS endpoints negotiate X25519MLKEM768 or stronger",
        "FIPS 203/204/205 compliance report shows grade A or B",
        "Canary tokens re-deployed on all critical endpoints",
        "CI/CD gate blocking any new quantum-vulnerable algorithm deployments",
        "Board sign-off on updated Crypto Agility report (CryptoFlex Score ≥ 70)",
    ]


def list_emergency_types() -> List[Dict[str, Any]]:
    return [{"id": k, **{kk: vv for kk, vv in v.items() if kk != "response_window_hours"}}
            for k, v in _EMERGENCY_TYPES.items()]
