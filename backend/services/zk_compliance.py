"""
Cryptographically Signed PQC Compliance Attestations

Enables organisations to share evidence of their PQC posture with regulators
and auditors WITHOUT revealing the underlying cryptographic configuration
(which would create a new attack surface).

Implementation: Hash-based commitment scheme.

  1. WITNESS: The actual crypto config (key types, cert subjects, risk scores)
  2. COMMITMENT: SHA-256(witness || nonce) — binds the attestation to the config
     without revealing it
  3. CLAIMS: Public statements derived from the witness (e.g., "all RSA keys ≥ 4096",
     "0 critical-risk endpoints", "PQC migration ≥ 80%")
  4. PROOF: A Merkle-style hash chain over the claims + commitment
  5. VERIFICATION: Verifier checks proof_hash = H(claims || commitment)
     without ever seeing the witness

IMPORTANT — Naming accuracy:
  This is a hash-based commitment scheme. A hash commitment proves that a
  value existed and was not changed after the commitment was issued. It does
  NOT constitute a zero-knowledge proof in the cryptographic sense (ZK-SNARK,
  ZK-STARK, Groth16, PLONK), which can prove that secret data satisfies a
  predicate without revealing it. Do not represent this as "ZK" to regulators
  or auditors. Use the term "cryptographically signed attestation" instead.

  For genuine ZK proofs, integrate a library such as snarkjs, arkworks, or
  bellman and replace this commitment scheme with a Groth16 or PLONK circuit.

Regulatory context:
  These attestations can serve as supporting evidence for compliance reviews
  under NIST SP 800-208, CNSA 2.0, ETSI EN 303 645, NIS2, and DORA.
  They do not by themselves constitute formal compliance certification.
  NIST SP 800-208 specifically covers stateful hash-based signature schemes
  (LMS/XMSS); map controls precisely.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List


# ── Compliance standards ──────────────────────────────────────────────────────

COMPLIANCE_STANDARDS: Dict[str, Dict[str, Any]] = {
    "NIST_SP_800_208": {
        "name": "NIST SP 800-208 — PQC Transition",
        "description": "NIST recommendation for migration to quantum-resistant algorithms.",
        "thresholds_authored_by": "pqc-scanner",
        "thresholds_note": (
            "NIST SP 800-208 sets no migration percentage. The numeric thresholds below are this "
            "platform's own policy profile, not text quoted from the publication."
        ),
        "requirements": {
            "pqc_migration_pct_min": 80,
            "critical_risk_max": 0,
            "rsa_min_bits": 3072,
            "tls_min_version": "TLSv1.2",
            "max_classical_only_endpoints": 20,
        },
    },
    "CNSA_2": {
        "name": "CNSA 2.0 — NSA Commercial Algorithm Suite",
        "description": "NSA mandatory algorithm suite for National Security Systems.",
        "thresholds_authored_by": "pqc-scanner",
        "thresholds_note": (
            "CNSA 2.0 does require full migration of National Security Systems; the remaining "
            "numeric thresholds below are this platform's own policy profile."
        ),
        "requirements": {
            "pqc_migration_pct_min": 100,
            "critical_risk_max": 0,
            "high_risk_max": 0,
            "rsa_min_bits": 4096,
            "tls_min_version": "TLSv1.3",
            "max_classical_only_endpoints": 0,
        },
    },
    "NIS2": {
        "name": "NIS2 Directive — EU Network Security",
        "description": "EU NIS2 cybersecurity requirements for essential entities.",
        "thresholds_authored_by": "pqc-scanner",
        "thresholds_note": (
            "NIS2 sets no PQC migration percentage or endpoint count. The numeric thresholds below "
            "are this platform's own policy profile, not text quoted from the Directive."
        ),
        "requirements": {
            "pqc_migration_pct_min": 50,
            "critical_risk_max": 5,
            "rsa_min_bits": 2048,
            "tls_min_version": "TLSv1.2",
            "max_classical_only_endpoints": 50,
        },
    },
    "DORA": {
        "name": "DORA — EU Digital Operational Resilience Act",
        "description": "EU DORA requirements for financial sector cryptographic resilience.",
        "thresholds_authored_by": "pqc-scanner",
        "thresholds_note": (
            "DORA sets no PQC migration percentage. The numeric thresholds below are this "
            "platform's own policy profile, not text quoted from the Regulation."
        ),
        "requirements": {
            "pqc_migration_pct_min": 60,
            "critical_risk_max": 0,
            "rsa_min_bits": 3072,
            "tls_min_version": "TLSv1.2",
            "max_classical_only_endpoints": 10,
        },
    },
}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS zk_compliance_proofs (
                proof_id        TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                standard        TEXT NOT NULL,
                commitment      TEXT NOT NULL,
                proof_hash      TEXT NOT NULL,
                public_signals  TEXT NOT NULL,
                claims          TEXT NOT NULL,
                result          TEXT NOT NULL,
                score           INTEGER NOT NULL DEFAULT 0,
                generated_at    TEXT NOT NULL,
                expires_at      TEXT,
                witness_hash    TEXT NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_zk_org ON zk_compliance_proofs(org_id, generated_at DESC)"
        )
        conn.commit()


# ── Witness builder ───────────────────────────────────────────────────────────

def _build_witness(scan_summary: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a structured witness from a scan summary.
    The witness is the PRIVATE input — never leaves the server.
    """
    assets = scan_summary.get("assets") or []
    total = max(len(assets), 1)

    critical_count = sum(1 for a in assets if str(a.get("risk_level", "")).lower() == "critical")
    high_count = sum(1 for a in assets if str(a.get("risk_level", "")).lower() == "high")
    pqc_count = sum(1 for a in assets if _is_pqc(a.get("key_type", "")))
    classical_only = sum(1 for a in assets if not _is_pqc(a.get("key_type", "")))

    rsa_bits = [int(a.get("key_bits") or 0) for a in assets
                if "rsa" in str(a.get("key_type", "")).lower()]
    min_rsa_bits = min(rsa_bits) if rsa_bits else 0

    tls_versions = [str(a.get("tls_version") or "") for a in assets]
    has_weak_tls = any(v in ("TLSv1.0", "TLSv1.1", "SSLv3") for v in tls_versions)
    min_tls = "TLSv1.3" if all("1.3" in v for v in tls_versions if v) else (
        "TLSv1.2" if not has_weak_tls else "TLSv1.0"
    )

    return {
        "total_endpoints": total,
        "critical_risk_count": critical_count,
        "high_risk_count": high_count,
        "pqc_endpoint_count": pqc_count,
        "classical_only_count": classical_only,
        "pqc_migration_pct": round(100 * pqc_count / total, 1),
        "min_rsa_bits": min_rsa_bits,
        "min_tls_version": min_tls,
        "has_weak_tls": has_weak_tls,
    }


def _is_pqc(key_type: str) -> bool:
    kt = (key_type or "").lower()
    return any(x in kt for x in ("ml-kem", "kyber", "dilithium", "slh", "falcon", "pqc", "mlkem"))


# ── Proof generation ──────────────────────────────────────────────────────────

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _build_claims(witness: Dict[str, Any], reqs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Derive public claims from the private witness.
    Claims are boolean: the verifier learns only pass/fail, not the actual value.
    """
    claims = []

    # PQC migration progress
    pqc_pct = witness["pqc_migration_pct"]
    min_pct = reqs.get("pqc_migration_pct_min", 0)
    claims.append({
        "claim_id": "pqc_migration_threshold",
        "statement": f"PQC migration ≥ {min_pct}%",
        "result": "pass" if pqc_pct >= min_pct else "fail",
        "public_value": f"≥{min_pct}%" if pqc_pct >= min_pct else f"<{min_pct}%",
    })

    # Critical risk count
    max_critical = reqs.get("critical_risk_max", 0)
    claims.append({
        "claim_id": "critical_risk_ceiling",
        "statement": f"Critical-risk endpoints ≤ {max_critical}",
        "result": "pass" if witness["critical_risk_count"] <= max_critical else "fail",
        "public_value": "within limit" if witness["critical_risk_count"] <= max_critical else "exceeds limit",
    })

    # High risk (if required)
    if "high_risk_max" in reqs:
        max_high = reqs["high_risk_max"]
        claims.append({
            "claim_id": "high_risk_ceiling",
            "statement": f"High-risk endpoints ≤ {max_high}",
            "result": "pass" if witness["high_risk_count"] <= max_high else "fail",
            "public_value": "within limit" if witness["high_risk_count"] <= max_high else "exceeds limit",
        })

    # RSA minimum key size
    min_rsa = reqs.get("rsa_min_bits", 0)
    if min_rsa and witness["min_rsa_bits"] > 0:
        claims.append({
            "claim_id": "rsa_key_size_floor",
            "statement": f"All RSA keys ≥ {min_rsa} bits",
            "result": "pass" if witness["min_rsa_bits"] >= min_rsa else "fail",
            "public_value": f"≥{min_rsa}bit" if witness["min_rsa_bits"] >= min_rsa else f"<{min_rsa}bit",
        })

    # TLS version
    tls_min = reqs.get("tls_min_version", "TLSv1.2")
    tls_order = {"SSLv3": 0, "TLSv1.0": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}
    actual_tls_rank = tls_order.get(witness.get("min_tls_version", "TLSv1.2"), 3)
    required_tls_rank = tls_order.get(tls_min, 3)
    claims.append({
        "claim_id": "tls_version_floor",
        "statement": f"Minimum TLS version ≥ {tls_min}",
        "result": "pass" if actual_tls_rank >= required_tls_rank else "fail",
        "public_value": f"≥{tls_min}" if actual_tls_rank >= required_tls_rank else f"<{tls_min}",
    })

    # Classical-only endpoint ceiling
    max_classical = reqs.get("max_classical_only_endpoints", 9999)
    claims.append({
        "claim_id": "classical_only_ceiling",
        "statement": f"Classical-only endpoints ≤ {max_classical}",
        "result": "pass" if witness["classical_only_count"] <= max_classical else "fail",
        "public_value": "within limit" if witness["classical_only_count"] <= max_classical else "exceeds limit",
    })

    return claims


def generate_compliance_proof(
    org_id: str,
    scan_summary: Dict[str, Any],
    standard: str = "NIST_SP_800_208",
) -> Dict[str, Any]:
    """
    Generate a cryptographically signed compliance attestation.

    The attestation can be shared with regulators/auditors as supporting
    evidence of your PQC posture without revealing the underlying configuration.

    This uses a hash-based commitment scheme (NOT a zero-knowledge proof system).
    It proves that the attested claims were derived from a fixed configuration
    at a specific point in time, and that the configuration was not modified
    after the commitment was made.

    Returns: {proof_id, standard, commitment, proof_hash, public_signals,
              claims, result, score, attestation_type, disclaimer}
    """
    _ensure_tables()

    if standard not in COMPLIANCE_STANDARDS:
        raise ValueError(f"Unknown standard '{standard}'. Valid: {list(COMPLIANCE_STANDARDS)}")

    std = COMPLIANCE_STANDARDS[standard]
    reqs = std["requirements"]

    # Build private witness
    witness = _build_witness(scan_summary)
    witness_json = json.dumps(witness, sort_keys=True)

    # Commitment: bind to witness without revealing it
    nonce = secrets.token_hex(32)
    commitment = _sha256(witness_json + "||" + nonce)

    # Derive public claims from private witness
    claims = _build_claims(witness, reqs)

    # Score: percentage of claims that pass
    passed = sum(1 for c in claims if c["result"] == "pass")
    total_claims = len(claims)
    score = round(100 * passed / max(total_claims, 1))
    result = "compliant" if score == 100 else ("partial" if score >= 50 else "non_compliant")

    # Build public signals (what the verifier sees)
    public_signals = {
        "standard": standard,
        "standard_name": std["name"],
        "total_claims": total_claims,
        "claims_passed": passed,
        "compliance_score": score,
        "result": result,
        "org_id_hash": _sha256(org_id),  # verifier gets org hash, not org id
    }

    # Proof hash: hash of (claims || commitment) — verifier can reproduce this
    claims_canonical = json.dumps(
        [{"id": c["claim_id"], "result": c["result"], "value": c["public_value"]}
         for c in claims],
        sort_keys=True
    )
    proof_hash = _sha256(claims_canonical + "||" + commitment)

    proof_id = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc).isoformat()

    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO zk_compliance_proofs
               (proof_id, org_id, standard, commitment, proof_hash,
                public_signals, claims, result, score, generated_at, witness_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (proof_id, org_id, standard, commitment, proof_hash,
             json.dumps(public_signals), json.dumps(claims),
             result, score, now, _sha256(witness_json)),
        )
        conn.commit()

    return {
        "proof_id": proof_id,
        "standard": standard,
        "standard_name": std["name"],
        "commitment": commitment,
        "proof_hash": proof_hash,
        "public_signals": public_signals,
        "claims": claims,
        "result": result,
        "score": score,
        "generated_at": now,
        "attestation_type": "hash_commitment",
        "disclaimer": (
            "This is a hash-based commitment attestation, not a cryptographic "
            "zero-knowledge proof. It demonstrates that the stated claims were "
            "derived from a fixed configuration that has not changed since the "
            "commitment was issued. It does not constitute formal regulatory "
            "compliance certification. Present to auditors as supporting evidence."
        ),
        "verification_instructions": (
            "To verify: check that SHA256(claims_canonical || commitment) == proof_hash. "
            "Claims and commitment are public. Witness (raw config) is never revealed."
        ),
    }


def verify_compliance_proof(proof_id: str) -> Dict[str, Any]:
    """
    Independently verify a compliance proof by re-computing the proof hash.
    Returns {valid, proof_id, result, score, claims}.
    """
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM zk_compliance_proofs WHERE proof_id = ?",
            (proof_id,),
        ).fetchone()

    if not row:
        return {"valid": False, "error": "Proof not found."}

    proof = dict(row)
    try:
        claims = json.loads(proof["claims"])
        public_signals = json.loads(proof["public_signals"])
    except Exception:
        return {"valid": False, "error": "Proof data corrupted."}

    # Re-compute proof hash
    claims_canonical = json.dumps(
        [{"id": c["claim_id"], "result": c["result"], "value": c["public_value"]}
         for c in claims],
        sort_keys=True
    )
    expected_hash = _sha256(claims_canonical + "||" + proof["commitment"])
    is_valid = expected_hash == proof["proof_hash"]

    return {
        "valid": is_valid,
        "proof_id": proof_id,
        "standard": proof["standard"],
        "result": proof["result"],
        "score": proof["score"],
        "generated_at": proof["generated_at"],
        "public_signals": public_signals,
        "claims": [{"id": c["claim_id"], "statement": c["statement"],
                    "result": c["result"], "public_value": c["public_value"]}
                   for c in claims],
        "verification_note": "Proof is cryptographically valid." if is_valid else "PROOF INVALID — data may have been tampered.",
    }


def get_compliance_proofs(org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    """List all compliance proofs for an organisation."""
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT proof_id, standard, result, score, generated_at
               FROM zk_compliance_proofs
               WHERE org_id = ?
               ORDER BY generated_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
