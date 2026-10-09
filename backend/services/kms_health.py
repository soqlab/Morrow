"""
Wave 15 — KMS Vault Health
Check AWS KMS, HashiCorp Vault, Azure Key Vault for PQC-readiness:
key algorithm types, rotation policies, compliance posture.
Uses boto3, azure-keyvault-secrets + azure-identity, requests (all in requirements.txt).
"""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List

# Algorithms considered PQC-safe or hybrid-ready
PQC_SAFE_ALGOS = {"KYBER", "DILITHIUM", "FALCON", "SPHINCS", "RSA_4096", "ECC_NIST_P521"}
LEGACY_WEAK = {"RSA_2048", "RSA_1024", "ECC_NIST_P256", "ECC_NIST_P384",
               "HMAC_SHA1", "AES_128", "SYMMETRIC_DEFAULT"}

_DDL = [
    """CREATE TABLE IF NOT EXISTS kms_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '{}',
        keys TEXT NOT NULL DEFAULT '[]',
        risk_level TEXT NOT NULL DEFAULT 'unknown'
    )""",
]


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    conn.commit()


def _save_result(conn: sqlite3.Connection, org_id: str, provider: str,
                 summary: Dict, keys: List, risk_level: str) -> None:
    conn.execute(
        """INSERT INTO kms_scan_results (organization_id, provider, scanned_at, summary, keys, risk_level)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (org_id, provider, datetime.now(timezone.utc).isoformat(),
         json.dumps(summary), json.dumps(keys), risk_level),
    )
    conn.commit()


# ── AWS KMS ───────────────────────────────────────────────────────────────────

def check_aws_kms(conn: sqlite3.Connection, org_id: str,
                  aws_access_key: str, aws_secret_key: str,
                  region: str = "us-east-1") -> Dict:
    try:
        import boto3
        client = boto3.client(
            "kms", region_name=region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
        )
        paginator = client.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                try:
                    meta = client.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    rotation = False
                    try:
                        rotation = client.get_key_rotation_status(
                            KeyId=k["KeyId"])["KeyRotationEnabled"]
                    except Exception:
                        pass
                    algo = meta.get("KeySpec", "UNKNOWN")
                    keys.append({
                        "key_id": meta["KeyId"],
                        "alias": meta.get("Description", ""),
                        "algorithm": algo,
                        "key_usage": meta.get("KeyUsage", ""),
                        "enabled": meta.get("Enabled", False),
                        "rotation_enabled": rotation,
                        "pqc_safe": algo in PQC_SAFE_ALGOS,
                        "legacy_weak": algo in LEGACY_WEAK,
                        "created_at": str(meta.get("CreationDate", "")),
                    })
                except Exception:
                    pass
    except Exception as e:
        return {"error": str(e), "provider": "aws_kms", "keys": [], "summary": {}}

    weak = [k for k in keys if k["legacy_weak"]]
    no_rotation = [k for k in keys if not k["rotation_enabled"] and k["enabled"]]
    risk = "critical" if len(weak) > len(keys) * 0.5 else "high" if weak else "low"
    summary = {
        "total_keys": len(keys),
        "weak_algo_keys": len(weak),
        "no_rotation_keys": len(no_rotation),
        "pqc_safe_keys": len([k for k in keys if k["pqc_safe"]]),
        "region": region,
    }
    _save_result(conn, org_id, "aws_kms", summary, keys, risk)
    return {"provider": "aws_kms", "risk_level": risk, "summary": summary, "keys": keys}


# ── HashiCorp Vault ───────────────────────────────────────────────────────────

def check_hashicorp_vault(conn: sqlite3.Connection, org_id: str,
                          vault_addr: str, vault_token: str,
                          mount: str = "transit") -> Dict:
    try:
        import requests as _req
        headers = {"X-Vault-Token": vault_token}
        base = vault_addr.rstrip("/")

        # List keys in the transit engine
        r = _req.get(f"{base}/v1/{mount}/keys", headers=headers,
                     params={"list": "true"}, timeout=10)
        if r.status_code == 404:
            return {"error": "Transit mount not found", "provider": "vault", "keys": []}
        r.raise_for_status()
        key_names = r.json().get("data", {}).get("keys", [])

        keys = []
        for name in key_names[:50]:
            try:
                kr = _req.get(f"{base}/v1/{mount}/keys/{name}", headers=headers, timeout=10)
                if kr.status_code != 200:
                    continue
                kd = kr.json().get("data", {})
                key_type = kd.get("type", "unknown")
                pqc_safe = "ml-kem" in key_type or "kyber" in key_type or "dilithium" in key_type
                legacy_weak = key_type in ("rsa-2048", "rsa-1024", "ecdsa-p256", "aes128-gcm96")
                keys.append({
                    "name": name,
                    "type": key_type,
                    "rotation_enabled": kd.get("deletion_allowed", False),
                    "min_decryption_version": kd.get("min_decryption_version", 1),
                    "latest_version": kd.get("latest_version", 1),
                    "pqc_safe": pqc_safe,
                    "legacy_weak": legacy_weak,
                    "exportable": kd.get("exportable", False),
                })
            except Exception:
                pass
    except Exception as e:
        return {"error": str(e), "provider": "vault", "keys": [], "summary": {}}

    weak = [k for k in keys if k["legacy_weak"]]
    risk = "critical" if len(weak) > len(keys) * 0.5 else "high" if weak else "low"
    summary = {"total_keys": len(keys), "weak_algo_keys": len(weak),
               "pqc_safe_keys": len([k for k in keys if k["pqc_safe"]]),
               "vault_addr": vault_addr}
    _save_result(conn, org_id, "hashicorp_vault", summary, keys, risk)
    return {"provider": "hashicorp_vault", "risk_level": risk, "summary": summary, "keys": keys}


# ── Azure Key Vault ───────────────────────────────────────────────────────────

def check_azure_keyvault(conn: sqlite3.Connection, org_id: str,
                         vault_url: str, tenant_id: str,
                         client_id: str, client_secret: str) -> Dict:
    try:
        from azure.identity import ClientSecretCredential
        from azure.keyvault.keys import KeyClient

        cred = ClientSecretCredential(tenant_id, client_id, client_secret)
        client = KeyClient(vault_url=vault_url, credential=cred)

        keys = []
        for key_props in client.list_properties_of_keys():
            try:
                key = client.get_key(key_props.name)
                ktype = str(key.key_type) if key.key_type else "unknown"
                pqc_safe = False  # Azure doesn't support PQC keys yet
                legacy_weak = ktype in ("RSA", "EC") and (
                    getattr(key.key, "n", None) is not None and
                    len(getattr(key.key, "n", b"")) < 384
                )
                keys.append({
                    "name": key.name,
                    "type": ktype,
                    "enabled": key_props.enabled,
                    "rotation_enabled": bool(key_props.rotation_policy) if hasattr(key_props, "rotation_policy") else False,
                    "expires_on": str(key_props.expires_on) if key_props.expires_on else None,
                    "pqc_safe": pqc_safe,
                    "legacy_weak": legacy_weak or ktype in ("RSA", "EC"),
                    "key_size": getattr(key.key, "key_size", None),
                })
            except Exception:
                pass
    except Exception as e:
        return {"error": str(e), "provider": "azure_keyvault", "keys": [], "summary": {}}

    weak = [k for k in keys if k["legacy_weak"]]
    risk = "critical" if weak else "medium"
    summary = {"total_keys": len(keys), "weak_algo_keys": len(weak),
               "pqc_safe_keys": 0, "vault_url": vault_url,
               "note": "Azure Key Vault does not yet support PQC key types"}
    _save_result(conn, org_id, "azure_keyvault", summary, keys, risk)
    return {"provider": "azure_keyvault", "risk_level": risk, "summary": summary, "keys": keys}


# ── History ───────────────────────────────────────────────────────────────────

def list_kms_results(conn: sqlite3.Connection, org_id: str, limit: int = 20) -> List[Dict]:
    try:
        rows = conn.execute(
            """SELECT id, provider, scanned_at, summary, risk_level
               FROM kms_scan_results WHERE organization_id=?
               ORDER BY scanned_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
        cols = ["id", "provider", "scanned_at", "summary", "risk_level"]
        result = []
        for row in rows:
            d = dict(zip(cols, row))
            d["summary"] = json.loads(d["summary"])
            result.append(d)
        return result
    except Exception:
        return []
