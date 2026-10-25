from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db import current_organization_id, get_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secret() -> bytes:
    seed = os.getenv("MORROW_PLATFORM_ADMIN_KEY") or os.getenv("MORROW_VAULT_MASTER_KEY") or "local-dev-secret"
    return hashlib.sha256(str(seed).encode("utf-8")).digest()


def _sign(payload: Dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_secret(), data, hashlib.sha256).hexdigest()


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS crypto_mesh_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            profile_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_crypto_mesh_profiles_org ON crypto_mesh_profiles(organization_id, status, updated_at)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hndl_canary_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            token_id TEXT NOT NULL,
            label TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT '',
            token_hash TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            last_hit_at TEXT NOT NULL DEFAULT '',
            hit_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_hndl_canary_tokens_org_token ON hndl_canary_tokens(organization_id, token_id)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hndl_canary_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            token_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            event_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_private_proofs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            vendor_name TEXT NOT NULL,
            proof_id TEXT NOT NULL,
            claim_json TEXT NOT NULL,
            commitment TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_private_proofs_org_proof ON vendor_private_proofs(organization_id, proof_id)"
    )


def build_crypto_mesh_profile(name: str, intent: str = "", emergency_algorithm: str = "") -> Dict[str, Any]:
    """Build an interoperability-safe crypto agility profile.

    This is a control-plane profile, not a proprietary cryptographic algorithm.
    It targets hybrid standards-compatible rollout through existing proxies/meshes.
    """
    preferred = str(emergency_algorithm or "X25519MLKEM768").strip()
    profile = {
        "api_version": "v1",
        "name": str(name or "Default crypto agility mesh").strip()[:180],
        "intent": str(intent or "Maintain standards-based hybrid post-quantum transport where supported.").strip(),
        "mode": "control-plane",
        "primary_profile": {
            "tls_groups": [preferred, "X25519"],
            "signatures": ["ML-DSA", "SLH-DSA", "ECDSA-P256"],
            "minimum_tls": "1.2",
            "recommended_tls": "1.3",
        },
        "contingency_profiles": [
            {"name": "mlkem_hybrid", "groups": ["X25519MLKEM768", "X25519"], "status": "preferred"},
            {"name": "classical_fallback", "groups": ["X25519"], "status": "break_glass_only"},
            {"name": "future_non_lattice_slot", "groups": ["reserved-non-lattice-kem"], "status": "track_standardization"},
        ],
        "deployment_targets": ["Cloudflare", "Envoy", "Nginx", "Kubernetes ingress", "service mesh"],
        "rollout_plan": [
            "Inventory endpoints and supported key agreement groups.",
            "Enable hybrid ML-KEM-compatible profiles where provider support exists.",
            "Keep classical fallback only for compatibility exceptions.",
            "Publish Security Truth CI policy so unsafe TLS regressions block merge.",
            "Record evidence and rollback state for every profile change.",
        ],
        "created_at": _now(),
    }
    profile["signature"] = _sign(profile)
    return profile


def save_crypto_mesh_profile(name: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    org_id = current_organization_id()
    now = _now()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        cur = conn.execute(
            """
            INSERT INTO crypto_mesh_profiles (organization_id, name, status, profile_json, created_at, updated_at)
            VALUES (?, ?, 'draft', ?, ?, ?)
            """,
            (org_id, str(name or profile.get("name") or "Crypto mesh profile")[:180], json.dumps(profile), now, now),
        )
        row_id = int(cur.lastrowid or 0)
        conn.commit()
        row = conn.execute("SELECT * FROM crypto_mesh_profiles WHERE organization_id=? AND id=?", (org_id, row_id)).fetchone()
        return _mesh_row(row)


def list_crypto_mesh_profiles(limit: int = 100) -> List[Dict[str, Any]]:
    org_id = current_organization_id()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        rows = conn.execute(
            "SELECT * FROM crypto_mesh_profiles WHERE organization_id=? ORDER BY updated_at DESC LIMIT ?",
            (org_id, max(1, min(int(limit or 100), 500))),
        ).fetchall()
        return [_mesh_row(r) for r in rows]


def _mesh_row(row) -> Dict[str, Any]:
    data = dict(row)
    data["profile"] = json.loads(data.pop("profile_json") or "{}")
    return data


def create_hndl_canary_token(label: str, scope: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    org_id = current_organization_id()
    token_id = "hndl_" + secrets.token_urlsafe(18)
    raw_secret = secrets.token_urlsafe(32)
    token_payload = {"org": org_id, "token_id": token_id, "secret": raw_secret}
    signed = base64.urlsafe_b64encode(json.dumps(token_payload, sort_keys=True).encode("utf-8")).decode("ascii").rstrip("=")
    token_hash = hashlib.sha256(signed.encode("utf-8")).hexdigest()
    now = _now()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        conn.execute(
            """
            INSERT INTO hndl_canary_tokens
                (organization_id, token_id, label, scope, token_hash, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, token_id, str(label or "HNDL canary").strip()[:180], str(scope or "").strip()[:300], token_hash, json.dumps(metadata or {}), now),
        )
        conn.commit()
    return {
        "api_version": "v1",
        "token_id": token_id,
        "token": signed,
        "label": label,
        "scope": scope,
        "created_at": now,
        "recommended_use": "Place only in controlled decoy data, test repositories, honey files, or synthetic secrets. Never embed in real customer secrets.",
    }


def record_hndl_canary_hit(token: str, source: str = "", event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    token_hash = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
    org_id = current_organization_id()
    now = _now()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        row = conn.execute(
            "SELECT * FROM hndl_canary_tokens WHERE organization_id=? AND token_hash=?",
            (org_id, token_hash),
        ).fetchone()
        if not row:
            return {"ok": False, "matched": False, "action": "ignore_unknown_token"}
        token_id = str(row["token_id"])
        conn.execute(
            "INSERT INTO hndl_canary_hits (organization_id, token_id, source, event_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, token_id, str(source or "")[:300], json.dumps(event or {}), now),
        )
        conn.execute(
            "UPDATE hndl_canary_tokens SET hit_count=hit_count+1, last_hit_at=? WHERE organization_id=? AND token_id=?",
            (now, org_id, token_id),
        )
        conn.commit()
        return {
            "ok": True,
            "matched": True,
            "token_id": token_id,
            "hit_at": now,
            "automated_response": [
                "Raise HNDL canary alert.",
                "Open root/session key rotation task.",
                "Add event to evidence ledger.",
                "Increase affected asset quantum-risk priority.",
            ],
        }


def list_hndl_canaries(limit: int = 100) -> Dict[str, Any]:
    org_id = current_organization_id()
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        tokens = conn.execute(
            "SELECT token_id, label, scope, metadata_json, created_at, last_hit_at, hit_count FROM hndl_canary_tokens WHERE organization_id=? ORDER BY created_at DESC LIMIT ?",
            (org_id, max(1, min(int(limit or 100), 500))),
        ).fetchall()
        hits = conn.execute(
            "SELECT token_id, source, event_json, created_at FROM hndl_canary_hits WHERE organization_id=? ORDER BY created_at DESC LIMIT ?",
            (org_id, max(1, min(int(limit or 100), 500))),
        ).fetchall()
        return {
            "api_version": "v1",
            "tokens": [{**dict(t), "metadata": json.loads(dict(t).pop("metadata_json") or "{}")} for t in tokens],
            "recent_hits": [{**dict(h), "event": json.loads(dict(h).pop("event_json") or "{}")} for h in hits],
        }


def generate_vendor_private_proof(vendor_name: str, scan_summary: Dict[str, Any], claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    org_id = current_organization_id()
    claims = claims or {}
    public_claim = {
        "vendor_name": str(vendor_name or "vendor").strip()[:180],
        "pq_compliant": bool(claims.get("pq_compliant", scan_summary.get("pq_compliant", False))),
        "legacy_rsa_keys": int(claims.get("legacy_rsa_keys", scan_summary.get("legacy_rsa_keys", 0)) or 0),
        "nist_profile": str(claims.get("nist_profile", scan_summary.get("nist_profile", "ML-KEM/ML-DSA readiness"))),
        "scan_time": str(scan_summary.get("scan_time") or _now()),
    }
    private_commitment_input = {
        "public_claim": public_claim,
        "private_scan_summary": scan_summary,
        "salt": secrets.token_hex(16),
    }
    commitment = hashlib.sha256(json.dumps(private_commitment_input, sort_keys=True).encode("utf-8")).hexdigest()
    proof = {
        "api_version": "v1",
        "proof_type": "hash-commitment-selective-disclosure",
        "proof_id": "proof_" + secrets.token_urlsafe(14),
        "organization_id": org_id,
        "claim": public_claim,
        "commitment": commitment,
        "created_at": _now(),
        "attestation_type": "hash_commitment_signed",
        "note": (
            "Cryptographically signed vendor attestation using HMAC-SHA256 over committed claims. "
            "This is a selective-disclosure commitment scheme, NOT a zero-knowledge proof. "
            "It confirms that the vendor committed to these claims at attestation time and that "
            "the commitment has not been altered. It does not prove the claims are accurate "
            "without access to the underlying data. Present to auditors as supporting evidence. "
            "Upgrade path: replace HMAC with a zkVM/SNARK verifier for genuine ZK semantics."
        ),
    }
    proof["signature"] = _sign({k: v for k, v in proof.items() if k != "signature"})
    with closing(get_connection()) as conn:
        conn.row_factory = __import__("sqlite3").Row
        _ensure_tables(conn)
        conn.execute(
            """
            INSERT INTO vendor_private_proofs
                (organization_id, vendor_name, proof_id, claim_json, commitment, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, public_claim["vendor_name"], proof["proof_id"], json.dumps(public_claim), commitment, proof["signature"], proof["created_at"]),
        )
        conn.commit()
    return proof


def verify_vendor_private_proof(proof: Dict[str, Any]) -> Dict[str, Any]:
    expected = _sign({k: v for k, v in proof.items() if k != "signature"})
    valid = hmac.compare_digest(str(proof.get("signature") or ""), expected)
    claim = proof.get("claim") or {}
    return {
        "api_version": "v1",
        "valid": valid,
        "proof_id": proof.get("proof_id"),
        "claim": claim,
        "decision": "accept" if valid and bool(claim.get("pq_compliant")) and int(claim.get("legacy_rsa_keys") or 0) == 0 else "review",
        "verified_at": _now(),
    }
