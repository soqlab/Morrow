"""
FIPS 203/204/205 post-quantum Compliance Checker

NIST published three post-quantum standards in August 2024:
  FIPS 203 — ML-KEM   (Module-Lattice Key Encapsulation, aka Kyber)
  FIPS 204 — ML-DSA   (Module-Lattice Digital Signature, aka Dilithium)
  FIPS 205 — SLH-DSA  (Stateless Hash-Based Digital Signature, aka SPHINCS+)

This module classifies each discovered algorithm against those standards,
calculates per-asset compliance, and produces an org-level compliance report.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.model_basis import model_basis as _model_basis


# ── Algorithm classification tables ────────────────────────────────────────────

# Algorithms that satisfy one or more FIPS 203/204/205 standards
_FIPS_COMPLIANT: Dict[str, List[str]] = {
    # FIPS 203 — ML-KEM (key encapsulation)
    "ML-KEM-512":   ["FIPS-203"],
    "ML-KEM-768":   ["FIPS-203"],
    "ML-KEM-1024":  ["FIPS-203"],
    "Kyber512":     ["FIPS-203"],
    "Kyber768":     ["FIPS-203"],
    "Kyber1024":    ["FIPS-203"],
    # Hybrid (key exchange)
    "X25519MLKEM768":   ["FIPS-203"],
    "P256MLKEM768":     ["FIPS-203"],
    "X448MLKEM1024":    ["FIPS-203"],
    # FIPS 204 — ML-DSA (signatures)
    "ML-DSA-44":    ["FIPS-204"],
    "ML-DSA-65":    ["FIPS-204"],
    "ML-DSA-87":    ["FIPS-204"],
    "Dilithium2":   ["FIPS-204"],
    "Dilithium3":   ["FIPS-204"],
    "Dilithium5":   ["FIPS-204"],
    # FIPS 205 — SLH-DSA (signatures)
    "SLH-DSA-SHA2-128s":  ["FIPS-205"],
    "SLH-DSA-SHA2-128f":  ["FIPS-205"],
    "SLH-DSA-SHA2-192s":  ["FIPS-205"],
    "SLH-DSA-SHA2-192f":  ["FIPS-205"],
    "SLH-DSA-SHA2-256s":  ["FIPS-205"],
    "SLH-DSA-SHA2-256f":  ["FIPS-205"],
    "SLH-DSA-SHAKE-128s": ["FIPS-205"],
    "SLH-DSA-SHAKE-128f": ["FIPS-205"],
    "SLH-DSA-SHAKE-192s": ["FIPS-205"],
    "SLH-DSA-SHAKE-192f": ["FIPS-205"],
    "SLH-DSA-SHAKE-256s": ["FIPS-205"],
    "SLH-DSA-SHAKE-256f": ["FIPS-205"],
    "SPHINCS+-SHA2-128s": ["FIPS-205"],
    "SPHINCS+-SHA2-128f": ["FIPS-205"],
    "SPHINCS+-SHAKE-128s":["FIPS-205"],
    "SPHINCS+-SHAKE-256s":["FIPS-205"],
    # Acceptable symmetric (not covered by 203/204/205 but CNSA 2.0 approved)
    "AES-256": ["CNSA-2.0"],
    "SHA-256": ["CNSA-2.0"],
    "SHA-384": ["CNSA-2.0"],
    "SHA-512": ["CNSA-2.0"],
}

# Algorithms that are quantum-vulnerable and must migrate
_QUANTUM_VULNERABLE: Dict[str, Dict[str, Any]] = {
    "RSA": {"risk": "critical", "reason": "Shor's algorithm breaks RSA in polynomial time on a CRQC", "migrate_to": "ML-KEM-768 / ML-DSA-65"},
    "RSA-2048": {"risk": "critical", "reason": "Shor's algorithm breaks RSA in polynomial time", "migrate_to": "ML-KEM-768"},
    "RSA-3072": {"risk": "high", "reason": "Larger key buys marginal time; still broken by Shor", "migrate_to": "ML-KEM-768"},
    "RSA-4096": {"risk": "high", "reason": "Larger key buys marginal time; still broken by Shor", "migrate_to": "ML-KEM-1024"},
    "ECDSA": {"risk": "critical", "reason": "Shor's algorithm breaks ECDLP; all ECC signatures vulnerable", "migrate_to": "ML-DSA-65"},
    "ECDH": {"risk": "critical", "reason": "Shor's algorithm breaks ECDH key exchange", "migrate_to": "ML-KEM-768"},
    "ECDH-256": {"risk": "critical", "reason": "ECDH with P-256 broken by Shor", "migrate_to": "X25519MLKEM768"},
    "ECDH-384": {"risk": "high", "reason": "ECDH with P-384 broken by Shor", "migrate_to": "ML-KEM-1024"},
    "P-256": {"risk": "critical", "reason": "Elliptic curve P-256 vulnerable to Shor's algorithm", "migrate_to": "ML-KEM-768"},
    "P-384": {"risk": "high", "reason": "Elliptic curve P-384 vulnerable to Shor's algorithm", "migrate_to": "ML-KEM-1024"},
    "P-521": {"risk": "high", "reason": "Elliptic curve P-521 vulnerable to Shor's algorithm", "migrate_to": "ML-KEM-1024"},
    "DH": {"risk": "critical", "reason": "Discrete log problem solved by Shor on a CRQC", "migrate_to": "ML-KEM-768"},
    "DHE": {"risk": "critical", "reason": "Discrete log problem solved by Shor on a CRQC", "migrate_to": "ML-KEM-768"},
    "ED25519": {"risk": "high", "reason": "EdDSA over Curve25519 broken by Shor", "migrate_to": "ML-DSA-44"},
    "X25519": {"risk": "high", "reason": "X25519 DH broken by Shor; use hybrid", "migrate_to": "X25519MLKEM768"},
    # scan_results stores the certificate key type, which for elliptic-curve keys is the bare "EC"
    # (43 of 45 rows on the development database). Without these two entries every such asset was
    # classified "unknown" instead of quantum-vulnerable, understating the risk. Last in the table so
    # the specific curves and ECDH variants above still match first.
    "EC": {"risk": "critical", "reason": "Elliptic-curve key; Shor's algorithm breaks ECDLP on a CRQC", "migrate_to": "ML-KEM-768 / ML-DSA-65"},
    "ECC": {"risk": "critical", "reason": "Elliptic-curve key; Shor's algorithm breaks ECDLP on a CRQC", "migrate_to": "ML-KEM-768 / ML-DSA-65"},
}

# Classically broken / deprecated (not post-quantum-specific but flagged)
_DEPRECATED: Dict[str, str] = {
    "RC4": "Classically broken stream cipher",
    "DES": "56-bit key; classically broken",
    "3DES": "Triple DES; Sweet32 vulnerability; deprecated by NIST 2023",
    "MD5": "Collision-broken hash; no integrity guarantee",
    "SHA-1": "Collision-broken; deprecated since 2017",
    "AES-128": "Below CNSA 2.0 minimum of AES-256 for long-lived data",
    "TLS-1.0": "TLS 1.0 deprecated (RFC 8996)",
    "TLS-1.1": "TLS 1.1 deprecated (RFC 8996)",
    "SSL-3.0": "SSL 3.0 broken (POODLE)",
    "EXPORT": "Export-grade crypto; intentionally weak",
    "NULL": "No encryption",
}

# Standards metadata
_STANDARDS = {
    "FIPS-203": {
        "name": "FIPS 203 — ML-KEM",
        "full_name": "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
        "published": "2024-08-13",
        "purpose": "Key encapsulation / key exchange",
        "algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "cnsa_deadline": "2030",
        "requirement": "All key exchange mechanisms must migrate to ML-KEM by 2030 (NSS systems by 2033)",
    },
    "FIPS-204": {
        "name": "FIPS 204 — ML-DSA",
        "full_name": "Module-Lattice-Based Digital Signature Algorithm Standard",
        "published": "2024-08-13",
        "purpose": "Digital signatures / code signing",
        "algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        "cnsa_deadline": "2030",
        "requirement": "All signature schemes must migrate to ML-DSA or SLH-DSA by 2030",
    },
    "FIPS-205": {
        "name": "FIPS 205 — SLH-DSA",
        "full_name": "Stateless Hash-Based Digital Signature Algorithm Standard",
        "published": "2024-08-13",
        "purpose": "Digital signatures (hash-based, stateless)",
        "algorithms": ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
                       "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256s"],
        "cnsa_deadline": "2030",
        "requirement": "Alternative signature standard; stateless hash-based — suitable for code signing",
    },
}


# ── Classification helpers ──────────────────────────────────────────────────────

def _normalise(algorithm: str) -> str:
    return re.sub(r"[_\-\s]+", "-", str(algorithm or "").strip().upper())


def _compliant_verdict(raw: str, standards: List[str]) -> Dict[str, Any]:
    return {
        "algorithm": raw,
        "status": "compliant",
        "standards": list(standards),
        "risk": "low",
        "action": "none",
        "details": f"Compliant with {', '.join(standards)}",
    }


def _vulnerable_verdict(raw: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "algorithm": raw,
        "status": "quantum_vulnerable",
        "standards": [],
        "risk": meta["risk"],
        "action": f"Migrate to {meta['migrate_to']}",
        "details": meta["reason"],
    }


def _deprecated_verdict(raw: str, reason: str) -> Dict[str, Any]:
    return {
        "algorithm": raw,
        "status": "deprecated",
        "standards": [],
        "risk": "high",
        "action": "Remove immediately",
        "details": reason,
    }


def classify_algorithm(algorithm: str) -> Dict[str, Any]:
    """Classify a single algorithm string.

    Exact matches are taken before prefix matches. The tables are ordered dicts and the prefix
    test fires on the first entry that matches, so "RSA-4096" hit the bare "RSA" row and was
    graded `critical` -- the RSA-2048 verdict -- even though "RSA-4096" has its own `high` row
    further down. That made the ordering of these dicts silently load-bearing: moving "EC" above
    "ECDH" would have reclassified every ECDH asset. It is not load-bearing any more.
    """
    raw = str(algorithm or "").strip()
    norm = _normalise(raw)

    for table, build in (
        (_FIPS_COMPLIANT, _compliant_verdict),
        (_QUANTUM_VULNERABLE, _vulnerable_verdict),
        (_DEPRECATED, _deprecated_verdict),
    ):
        for algo, value in table.items():
            if _normalise(algo) == norm:
                return build(raw, value)

    # Check FIPS compliant first (case-insensitive prefix match)
    for algo, standards in _FIPS_COMPLIANT.items():
        if _normalise(algo) == norm or norm.startswith(_normalise(algo)):
            return {
                "algorithm": raw,
                "status": "compliant",
                "standards": standards,
                "risk": "low",
                "action": "none",
                "details": f"Compliant with {', '.join(standards)}",
            }

    # Check quantum-vulnerable
    for algo, meta in _QUANTUM_VULNERABLE.items():
        if _normalise(algo) == norm or norm.startswith(_normalise(algo)):
            return {
                "algorithm": raw,
                "status": "quantum_vulnerable",
                "standards": [],
                "risk": meta["risk"],
                "action": f"Migrate to {meta['migrate_to']}",
                "details": meta["reason"],
            }

    # Check deprecated
    for algo, reason in _DEPRECATED.items():
        if _normalise(algo) == norm or norm.startswith(_normalise(algo)):
            return {
                "algorithm": raw,
                "status": "deprecated",
                "standards": [],
                "risk": "high",
                "action": "Remove immediately",
                "details": reason,
            }

    # Unknown / not classified
    return {
        "algorithm": raw,
        "status": "unknown",
        "standards": [],
        "risk": "medium",
        "action": "Investigate",
        "details": "Algorithm not in FIPS 203/204/205 approved list — manual review required",
    }


# ── Asset compliance ────────────────────────────────────────────────────────────

def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 55: return "C"
    if score >= 35: return "D"
    return "F"


def check_asset_compliance(host: str, port: int, algorithm: str, **kwargs: Any) -> Dict[str, Any]:
    """Return compliance status for a single scanned asset."""
    classification = classify_algorithm(algorithm)
    status = classification["status"]
    score = {"compliant": 100, "unknown": 50, "deprecated": 10, "quantum_vulnerable": 0}.get(status, 40)
    return {
        "host": host,
        "port": port,
        "algorithm": algorithm,
        "classification": classification,
        "compliance_score": score,
        "grade": _grade(score),
        "fips_203_ready": any(s == "FIPS-203" for s in classification["standards"]),
        "fips_204_ready": any(s == "FIPS-204" for s in classification["standards"]),
        "fips_205_ready": any(s == "FIPS-205" for s in classification["standards"]),
        "action_required": status in ("quantum_vulnerable", "deprecated"),
    }


# ── Org-level compliance report ─────────────────────────────────────────────────

def build_fips_compliance_report(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a full FIPS 203/204/205 compliance report from a list of scan rows.

    Each scan row should have at minimum: host, port, algorithm.
    """
    if not scans:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "standards": _STANDARDS,
            "asset_count": 0,
            "overall_grade": "N/A",
            "overall_score": 0,
            "summary": {"compliant": 0, "quantum_vulnerable": 0, "deprecated": 0, "unknown": 0},
            "fips_203_coverage_pct": 0,
            "fips_204_coverage_pct": 0,
            "fips_205_coverage_pct": 0,
            "assets": [],
            "priority_actions": [],
            "message": "No scan data — run a scan first",
        }

    assets: List[Dict[str, Any]] = []
    summary: Dict[str, int] = {"compliant": 0, "quantum_vulnerable": 0, "deprecated": 0, "unknown": 0}
    fips_203_count = fips_204_count = fips_205_count = 0
    total_score = 0

    # Deduplicate by host:port, keep latest algorithm
    seen: Dict[str, Dict[str, Any]] = {}
    for row in scans:
        key = f"{row.get('host','')}:{row.get('port','')}"
        seen[key] = row

    for key, row in seen.items():
        algo = str(row.get("algorithm") or row.get("cipher") or "")
        result = check_asset_compliance(
            host=str(row.get("host", "")),
            port=int(row.get("port") or 0),
            algorithm=algo,
        )
        assets.append(result)
        status = result["classification"]["status"]
        summary[status] = summary.get(status, 0) + 1
        total_score += result["compliance_score"]
        if result["fips_203_ready"]: fips_203_count += 1
        if result["fips_204_ready"]: fips_204_count += 1
        if result["fips_205_ready"]: fips_205_count += 1

    n = len(assets)
    overall_score = round(total_score / n) if n else 0

    # Priority actions: sort quantum_vulnerable and deprecated first
    actions = [
        {
            "asset": f"{a['host']}:{a['port']}",
            "action": a["classification"]["action"],
            "risk": a["classification"]["risk"],
            "algorithm": a["algorithm"],
        }
        for a in assets if a["action_required"]
    ]
    actions.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["risk"], 4))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "standards": _STANDARDS,
        "asset_count": n,
        "overall_grade": _grade(overall_score),
        "overall_score": overall_score,
        "summary": summary,
        "fips_203_coverage_pct": round(fips_203_count / n * 100, 1) if n else 0,
        "fips_204_coverage_pct": round(fips_204_count / n * 100, 1) if n else 0,
        "fips_205_coverage_pct": round(fips_205_count / n * 100, 1) if n else 0,
        "assets": sorted(assets, key=lambda a: a["compliance_score"]),
        "priority_actions": actions[:20],
    }


# ── Migration timeline estimator ────────────────────────────────────────────────

def estimate_migration_timeline(report: Dict[str, Any]) -> Dict[str, Any]:
    """Estimate effort and timeline to reach FIPS 203/204/205 compliance.

    The effort rates below are the platform's own planning assumptions, not
    measured from anyone's migration. With no scanned asset there is nothing to
    plan against, so no sprint count, target or on-track verdict is published.
    """
    n = report.get("asset_count", 0)
    vuln = report.get("summary", {}).get("quantum_vulnerable", 0)
    dep = report.get("summary", {}).get("deprecated", 0)
    score = report.get("overall_score", 0)
    deadline_days = (datetime(2030, 1, 1, tzinfo=timezone.utc) - datetime.now(timezone.utc)).days

    if int(n or 0) < 1:
        return {
            "available": False,
            "reason": (
                "No scanned assets on record, so migration effort cannot be estimated. "
                "Run a TLS scan (or import a CBOM/SBOM) first."
            ),
            "minimum_data": {
                "scanned_assets": 1,
                "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
            },
            "total_effort_engineer_days": None,
            "estimated_sprint_weeks": None,
            "current_score": None,
            "target_score": None,
            "phases": [],
            "cnsa_2030_deadline_days": deadline_days,
            "on_track": None,
            "model_basis": _model_basis(
                kind="model",
                summary=(
                    "Effort and sprint counts are a planning model built from the platform's own "
                    "rates of thumb, not a measured delivery rate for your team."
                ),
                assumptions=[
                    "2 engineer-days per quantum-vulnerable asset.",
                    "0.5 engineer-days per deprecated-algorithm asset.",
                    "0.25 engineer-days per asset for validation and audit.",
                    "1 sprint = 10 engineer-days.",
                    "Deadline: CNSA 2.0 target of 1 January 2030.",
                ],
                sources=[
                    "NSA CNSA 2.0 FAQ (2022) — software/firmware signing and general transition timelines",
                ],
                as_of="2026-09",
            ),
        }

    # Rough effort model: 2 engineer-days per vulnerable asset, 0.5 per deprecated
    effort_days = vuln * 2 + dep * 0.5
    sprint_weeks = max(1, round(effort_days / 10))  # assume 1 sprint = 10 engineer-days

    phases = []
    if dep:
        phases.append({"phase": 1, "name": "Remove deprecated algorithms", "assets": dep,
                       "effort_days": round(dep * 0.5), "priority": "immediate"})
    if vuln:
        phases.append({"phase": 2, "name": "Migrate quantum-vulnerable algorithms",
                       "assets": vuln, "effort_days": round(vuln * 2), "priority": "high"})
    phases.append({"phase": len(phases) + 1, "name": "Validate & audit FIPS compliance",
                   "assets": n, "effort_days": max(1, round(n * 0.25)), "priority": "normal"})

    return {
        "available": True,
        "reason": "",
        "minimum_data": {
            "scanned_assets": 1,
            "how_to_get_it": "Run a TLS scan from the Scans view, or import a CBOM/SBOM.",
        },
        "total_effort_engineer_days": round(effort_days),
        "estimated_sprint_weeks": sprint_weeks,
        "current_score": score,
        "target_score": 95,
        "phases": phases,
        "cnsa_2030_deadline_days": deadline_days,
        "on_track": sprint_weeks <= 52,
        "model_basis": _model_basis(
            kind="model",
            summary=(
                "Effort and sprint counts are a planning model built from the platform's own rates "
                "of thumb applied to your asset counts, not a measured delivery rate for your team."
            ),
            assumptions=[
                "2 engineer-days per quantum-vulnerable asset.",
                "0.5 engineer-days per deprecated-algorithm asset.",
                "0.25 engineer-days per asset for validation and audit.",
                "1 sprint = 10 engineer-days.",
                "Target score of 95/100 is the platform's own completion bar, not a published requirement.",
                "Deadline: CNSA 2.0 target of 1 January 2030.",
            ],
            sources=[
                "NSA CNSA 2.0 FAQ (2022) — software/firmware signing and general transition timelines",
            ],
            as_of="2026-09",
        ),
    }
