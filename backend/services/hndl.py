from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from schemas import (
    AwsS3HndlInventoryRequest,
    AzureBlobHndlInventoryRequest,
    GcpStorageHndlInventoryRequest,
    HndlStorageObject,
)
from vault_db import get_credential

def _score_hndl_object(obj: HndlStorageObject) -> Dict[str, Any]:
    encryption = str(obj.encryption or "").lower()
    key_type = str(obj.kms_key_type or "").lower()
    score = 0
    reasons: List[str] = []
    if obj.contains_sensitive_data:
        score += 30
        reasons.append("contains sensitive or regulated data")
    if int(obj.data_lifetime_years or 0) >= 5:
        score += 30
        reasons.append("data remains valuable for 5+ years")
    if int(obj.age_days or 0) >= 365:
        score += 10
        reasons.append("historical backup/data set")
    if "none" in encryption or "unencrypted" in encryption or not encryption:
        score += 30
        reasons.append("missing or unknown encryption")
    elif "sse-s3" in encryption or "provider" in encryption:
        score += 15
        reasons.append("provider-managed encryption needs key/control review")
    if "rsa" in key_type or "legacy" in key_type or "customer-managed-rsa" in key_type:
        score += 20
        reasons.append("legacy/asymmetric key dependency flagged")
    if float(obj.size_gb or 0) >= 100:
        score += 10
        reasons.append("large data volume")
    score = min(score, 100)
    risk = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return {
        "provider": obj.provider,
        "location": obj.location,
        "name": obj.name or obj.location,
        "owner": obj.owner,
        "score": score,
        "risk": risk,
        "reasons": reasons or ["no major HNDL signals in supplied metadata"],
        "next_actions": [
            "confirm data classification and retention period",
            "verify encryption and KMS key policy",
            "rotate or re-encrypt legacy protected backups",
            "attach owner and remediation workflow",
        ],
    }


def _aws_s3_hndl_inventory(req: AwsS3HndlInventoryRequest) -> Dict[str, Any]:
    try:
        import boto3  # type: ignore
    except Exception as exc:
        return {
            "ok": False,
            "mode": "unavailable",
            "error": f"boto3 is not installed in this runtime: {exc}",
            "next_step": "Add boto3 to backend requirements and rebuild the API/worker images.",
            "objects": [],
        }
    session_kwargs: Dict[str, Any] = {"region_name": req.region or "us-east-1"}
    if int(req.credential_id or 0):
        cred = get_credential(int(req.credential_id))
        if not cred:
            raise HTTPException(status_code=404, detail="credential not found")
        secret = str(cred.get("secret") or "")
        try:
            data = json.loads(secret)
        except Exception:
            data = {}
        if data.get("aws_access_key_id") and data.get("aws_secret_access_key"):
            session_kwargs.update({
                "aws_access_key_id": data.get("aws_access_key_id"),
                "aws_secret_access_key": data.get("aws_secret_access_key"),
                "aws_session_token": data.get("aws_session_token"),
            })
        elif secret:
            raise HTTPException(status_code=400, detail="AWS credential secret must be JSON with aws_access_key_id and aws_secret_access_key")
    if bool(req.dry_run):
        return {
            "ok": True,
            "mode": "dry_run",
            "objects": [],
            "next_step": "Set dry_run=false with a valid AWS credential to inventory S3 bucket/object encryption metadata.",
        }
    session = boto3.Session(**{k: v for k, v in session_kwargs.items() if v})
    s3 = session.client("s3")
    errors: List[Dict[str, Any]] = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])[: max(1, min(int(req.max_buckets or 50), 500))]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to list S3 buckets: {exc}")
    patterns = [str(x or "").lower() for x in req.sensitive_name_patterns or []]
    objects: List[HndlStorageObject] = []
    for bucket in buckets:
        bucket_name = str(bucket.get("Name") or "")
        if not bucket_name:
            continue
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name).get("ServerSideEncryptionConfiguration", {})
            rules = enc.get("Rules") or []
            default_enc = (((rules[0] or {}).get("ApplyServerSideEncryptionByDefault") or {}) if rules else {})
            enc_label = str(default_enc.get("SSEAlgorithm") or "unknown")
            kms_key_type = "kms" if default_enc.get("KMSMasterKeyID") else "provider-managed"
        except Exception:
            enc_label = "unknown"
            kms_key_type = "unknown"
        try:
            listed = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max(1, min(int(req.max_objects_per_bucket or 100), 1000))).get("Contents", [])
        except Exception as exc:
            errors.append({"bucket": bucket_name, "operation": "list_objects_v2", "error": str(exc)[:300]})
            listed = []
        for item in listed:
            key = str(item.get("Key") or "")
            size_gb = float(item.get("Size") or 0) / (1024 * 1024 * 1024)
            modified = item.get("LastModified")
            age_days = 0
            try:
                if modified:
                    age_days = max(0, int((datetime.now(timezone.utc) - modified).days))
            except Exception:
                age_days = 0
            name_l = f"{bucket_name}/{key}".lower()
            sensitive = any(p and p in name_l for p in patterns)
            object_enc_label = enc_label
            object_key_type = kms_key_type
            if bool(req.include_object_encryption):
                try:
                    head = s3.head_object(Bucket=bucket_name, Key=key)
                    if head.get("ServerSideEncryption"):
                        object_enc_label = str(head.get("ServerSideEncryption") or enc_label)
                    if head.get("SSEKMSKeyId"):
                        object_key_type = "kms"
                except Exception as exc:
                    errors.append({"bucket": bucket_name, "key": key, "operation": "head_object", "error": str(exc)[:300]})
            objects.append(HndlStorageObject(
                provider="aws",
                location=f"s3://{bucket_name}/{key}",
                name=key,
                encryption=object_enc_label,
                kms_key_type=object_key_type,
                contains_sensitive_data=sensitive,
                data_lifetime_years=10 if sensitive else 1,
                age_days=age_days,
                size_gb=round(size_gb, 4),
                owner="",
            ))
    return {
        "ok": True,
        "mode": "live",
        "objects": objects,
        "buckets_scanned": len(buckets),
        "objects_scanned": len(objects),
        "errors": errors[:100],
        "errors_total": len(errors),
    }


def _gcp_storage_hndl_inventory(req: GcpStorageHndlInventoryRequest) -> Dict[str, Any]:
    try:
        from google.cloud import storage  # type: ignore
        from google.oauth2 import service_account  # type: ignore
    except Exception as exc:
        return {
            "ok": False,
            "mode": "unavailable",
            "error": f"google-cloud-storage is not installed in this runtime: {exc}",
            "next_step": "Add google-cloud-storage to backend requirements and rebuild the API/worker images.",
            "objects": [],
        }
    if bool(req.dry_run):
        return {
            "ok": True,
            "mode": "dry_run",
            "objects": [],
            "next_step": "Set dry_run=false with a valid GCP service-account credential to inventory Cloud Storage metadata.",
        }
    project_id = str(req.project_id or "").strip() or None
    credentials = None
    if int(req.credential_id or 0):
        cred = get_credential(int(req.credential_id))
        if not cred:
            raise HTTPException(status_code=404, detail="credential not found")
        secret = str(cred.get("secret") or "")
        try:
            data = json.loads(secret)
        except Exception:
            data = {}
        if data.get("type") == "service_account":
            credentials = service_account.Credentials.from_service_account_info(data)
            project_id = project_id or data.get("project_id")
        elif secret:
            raise HTTPException(status_code=400, detail="GCP credential secret must be service account JSON")
    try:
        client = storage.Client(project=project_id, credentials=credentials)
        buckets_iter = client.list_buckets(project=project_id) if project_id else client.list_buckets()
        buckets = list(buckets_iter)[: max(1, min(int(req.max_buckets or 50), 500))]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to list GCP Storage buckets: {exc}")
    patterns = [str(x or "").lower() for x in req.sensitive_name_patterns or []]
    errors: List[Dict[str, Any]] = []
    objects: List[HndlStorageObject] = []
    for bucket in buckets:
        bucket_name = str(getattr(bucket, "name", "") or "")
        try:
            default_kms = str(getattr(bucket, "default_kms_key_name", "") or "")
            enc_label = "CMEK" if default_kms else "Google-managed encryption"
            kms_key_type = "kms" if default_kms else "provider-managed"
        except Exception:
            enc_label = "unknown"
            kms_key_type = "unknown"
        try:
            blobs = list(client.list_blobs(bucket, max_results=max(1, min(int(req.max_objects_per_bucket or 100), 1000))))
        except Exception as exc:
            errors.append({"bucket": bucket_name, "operation": "list_blobs", "error": str(exc)[:300]})
            blobs = []
        for blob in blobs:
            key = str(getattr(blob, "name", "") or "")
            size_gb = float(getattr(blob, "size", 0) or 0) / (1024 * 1024 * 1024)
            updated = getattr(blob, "updated", None)
            age_days = 0
            try:
                if updated:
                    age_days = max(0, int((datetime.now(timezone.utc) - updated).days))
            except Exception:
                age_days = 0
            kms_name = str(getattr(blob, "kms_key_name", "") or "")
            object_enc_label = "CMEK" if kms_name else enc_label
            object_key_type = "kms" if kms_name else kms_key_type
            name_l = f"{bucket_name}/{key}".lower()
            sensitive = any(p and p in name_l for p in patterns)
            objects.append(HndlStorageObject(
                provider="gcp",
                location=f"gs://{bucket_name}/{key}",
                name=key,
                encryption=object_enc_label,
                kms_key_type=object_key_type,
                contains_sensitive_data=sensitive,
                data_lifetime_years=10 if sensitive else 1,
                age_days=age_days,
                size_gb=round(size_gb, 4),
                owner="",
            ))
    return {
        "ok": True,
        "mode": "live",
        "project_id": project_id or "",
        "objects": objects,
        "buckets_scanned": len(buckets),
        "objects_scanned": len(objects),
        "errors": errors[:100],
        "errors_total": len(errors),
    }


def _azure_blob_hndl_inventory(req: AzureBlobHndlInventoryRequest) -> Dict[str, Any]:
    try:
        from azure.storage.blob import BlobServiceClient  # type: ignore
    except Exception as exc:
        return {
            "ok": False,
            "mode": "unavailable",
            "error": f"azure-storage-blob is not installed in this runtime: {exc}",
            "next_step": "Add azure-storage-blob to backend requirements and rebuild the API/worker images.",
            "objects": [],
        }
    if bool(req.dry_run):
        return {
            "ok": True,
            "mode": "dry_run",
            "objects": [],
            "next_step": "Set dry_run=false with a valid Azure credential to inventory Blob Storage metadata.",
        }
    account_url = str(req.account_url or "").strip()
    credential: Any = None
    connection_string = ""
    if int(req.credential_id or 0):
        cred = get_credential(int(req.credential_id))
        if not cred:
            raise HTTPException(status_code=404, detail="credential not found")
        secret = str(cred.get("secret") or "")
        try:
            data = json.loads(secret)
        except Exception:
            data = {}
        connection_string = str(data.get("connection_string") or "")
        account_url = account_url or str(data.get("account_url") or "")
        credential = data.get("credential") or data.get("account_key") or data.get("sas_token") or None
        account_name = str(data.get("account_name") or "").strip()
        if not account_url and account_name:
            account_url = f"https://{account_name}.blob.core.windows.net"
        if secret and not (connection_string or account_url):
            raise HTTPException(
                status_code=400,
                detail="Azure credential secret must contain connection_string, or account_url/account_name plus account_key or sas_token",
            )
    try:
        if connection_string:
            client = BlobServiceClient.from_connection_string(connection_string)
        else:
            if not account_url:
                raise HTTPException(status_code=400, detail="account_url is required for live Azure inventory unless credential contains a connection_string")
            client = BlobServiceClient(account_url=account_url, credential=credential)
        containers = list(client.list_containers())[: max(1, min(int(req.max_containers or 50), 500))]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to list Azure Blob containers: {exc}")
    patterns = [str(x or "").lower() for x in req.sensitive_name_patterns or []]
    errors: List[Dict[str, Any]] = []
    objects: List[HndlStorageObject] = []
    for container in containers:
        container_name = str(container.get("name") if isinstance(container, dict) else getattr(container, "name", "") or "")
        if not container_name:
            continue
        try:
            container_client = client.get_container_client(container_name)
            blobs = list(container_client.list_blobs(results_per_page=max(1, min(int(req.max_blobs_per_container or 100), 1000))))[
                : max(1, min(int(req.max_blobs_per_container or 100), 1000))
            ]
        except Exception as exc:
            errors.append({"container": container_name, "operation": "list_blobs", "error": str(exc)[:300]})
            blobs = []
        for blob in blobs:
            key = str(blob.get("name") if isinstance(blob, dict) else getattr(blob, "name", "") or "")
            size_bytes = blob.get("size") if isinstance(blob, dict) else getattr(blob, "size", 0)
            size_gb = float(size_bytes or 0) / (1024 * 1024 * 1024)
            updated = blob.get("last_modified") if isinstance(blob, dict) else getattr(blob, "last_modified", None)
            age_days = 0
            try:
                if updated:
                    age_days = max(0, int((datetime.now(timezone.utc) - updated).days))
            except Exception:
                age_days = 0
            encryption_scope = blob.get("encryption_scope") if isinstance(blob, dict) else getattr(blob, "encryption_scope", None)
            enc_label = "encryption scope" if encryption_scope else "platform-managed encryption"
            key_type = "customer-managed-or-scope" if encryption_scope else "provider-managed"
            name_l = f"{container_name}/{key}".lower()
            sensitive = any(p and p in name_l for p in patterns)
            objects.append(HndlStorageObject(
                provider="azure",
                location=f"azure://{container_name}/{key}",
                name=key,
                encryption=enc_label,
                kms_key_type=key_type,
                contains_sensitive_data=sensitive,
                data_lifetime_years=10 if sensitive else 1,
                age_days=age_days,
                size_gb=round(size_gb, 4),
                owner="",
            ))
    return {
        "ok": True,
        "mode": "live",
        "account_url": account_url,
        "objects": objects,
        "containers_scanned": len(containers),
        "objects_scanned": len(objects),
        "errors": errors[:100],
        "errors_total": len(errors),
    }


# ── TLS/Network Service HNDL Risk Quantification Engine ──────────────────────
#
# Answers: "Given what attackers may have already recorded, what is our
# financial exposure when a cryptographically-relevant quantum computer arrives?"
#
# Model:
#   exposure_usd = data_value_usd_per_year
#                x criticality_multiplier
#                x years_already_recorded   (capped at 5 — attacker harvest window)
#                x p_broken_by_q_day_year   (probability this algorithm is broken)
#
# The probability table and the per-port data profiles below are fixed planning
# assumptions, not measurements. They are returned verbatim in
# model_basis.assumptions (see hndl_model_basis). The default Q-Day year comes
# from the Q-Intel model (services/q_intel.py).


# ── Q-Day probability table ──────────────────────────────────────────────────
# algorithm_class -> {year: probability_broken}
_Q_DAY_PROBS: Dict[str, Dict[int, float]] = {
    "rsa2048":          {2027: 0.01, 2028: 0.03, 2029: 0.07, 2030: 0.15, 2031: 0.28, 2032: 0.45, 2033: 0.65, 2034: 0.80, 2035: 0.92},
    "rsa3072":          {2027: 0.00, 2028: 0.01, 2029: 0.03, 2030: 0.08, 2031: 0.18, 2032: 0.35, 2033: 0.55, 2034: 0.72, 2035: 0.87},
    "rsa4096":          {2027: 0.00, 2028: 0.00, 2029: 0.01, 2030: 0.04, 2031: 0.10, 2032: 0.22, 2033: 0.40, 2034: 0.60, 2035: 0.78},
    "ecc256":           {2027: 0.02, 2028: 0.05, 2029: 0.12, 2030: 0.25, 2031: 0.42, 2032: 0.60, 2033: 0.75, 2034: 0.88, 2035: 0.95},
    "ecc384":           {2027: 0.01, 2028: 0.02, 2029: 0.06, 2030: 0.14, 2031: 0.28, 2032: 0.45, 2033: 0.63, 2034: 0.78, 2035: 0.90},
    "x25519":           {2027: 0.02, 2028: 0.05, 2029: 0.11, 2030: 0.22, 2031: 0.38, 2032: 0.56, 2033: 0.72, 2034: 0.85, 2035: 0.94},
    "dh_classical":     {2027: 0.02, 2028: 0.06, 2029: 0.14, 2030: 0.28, 2031: 0.46, 2032: 0.64, 2033: 0.78, 2034: 0.89, 2035: 0.96},
    "pqc_hybrid":       {2027: 0.00, 2028: 0.00, 2029: 0.00, 2030: 0.00, 2031: 0.00, 2032: 0.00, 2033: 0.01, 2034: 0.01, 2035: 0.02},
    "pqc_pure":         {2027: 0.00, 2028: 0.00, 2029: 0.00, 2030: 0.00, 2031: 0.00, 2032: 0.00, 2033: 0.00, 2034: 0.01, 2035: 0.01},
    "tls10_or_ssl":     {2027: 0.05, 2028: 0.10, 2029: 0.20, 2030: 0.35, 2031: 0.52, 2032: 0.68, 2033: 0.80, 2034: 0.90, 2035: 0.97},
    "unknown_classical":{2027: 0.02, 2028: 0.05, 2029: 0.12, 2030: 0.24, 2031: 0.40, 2032: 0.57, 2033: 0.72, 2034: 0.84, 2035: 0.93},
}

# ── Data sensitivity profiles by port ────────────────────────────────────────
# base_value_usd: estimated annual value of data passing through this service
_DATA_PROFILES: Dict[int, Dict[str, Any]] = {
    443:   {"category": "HTTPS/Web",        "base_value_usd": 200_000,  "lifetime_years": 5,  "criticality": 1.0},
    8443:  {"category": "HTTPS/API",        "base_value_usd": 400_000,  "lifetime_years": 5,  "criticality": 1.2},
    8080:  {"category": "HTTP/API",         "base_value_usd": 150_000,  "lifetime_years": 3,  "criticality": 0.8},
    5432:  {"category": "PostgreSQL",       "base_value_usd": 2_000_000,"lifetime_years": 10, "criticality": 4.0},
    3306:  {"category": "MySQL/MariaDB",    "base_value_usd": 1_500_000,"lifetime_years": 10, "criticality": 3.5},
    1433:  {"category": "SQL Server",       "base_value_usd": 2_000_000,"lifetime_years": 10, "criticality": 4.0},
    27017: {"category": "MongoDB",          "base_value_usd": 1_200_000,"lifetime_years": 7,  "criticality": 3.0},
    6379:  {"category": "Redis",            "base_value_usd": 800_000,  "lifetime_years": 3,  "criticality": 2.5},
    636:   {"category": "LDAPS/Directory",  "base_value_usd": 3_000_000,"lifetime_years": 15, "criticality": 5.0},
    389:   {"category": "LDAP/Directory",   "base_value_usd": 3_000_000,"lifetime_years": 15, "criticality": 5.0},
    993:   {"category": "IMAPS/Email",      "base_value_usd": 1_000_000,"lifetime_years": 7,  "criticality": 2.5},
    995:   {"category": "POP3S/Email",      "base_value_usd": 800_000,  "lifetime_years": 7,  "criticality": 2.0},
    465:   {"category": "SMTPS/Email",      "base_value_usd": 800_000,  "lifetime_years": 7,  "criticality": 2.0},
    22:    {"category": "SSH/Remote",       "base_value_usd": 1_500_000,"lifetime_years": 10, "criticality": 4.0},
    8883:  {"category": "MQTT/IoT",         "base_value_usd": 500_000,  "lifetime_years": 5,  "criticality": 1.5},
    2376:  {"category": "Docker TLS",       "base_value_usd": 1_000_000,"lifetime_years": 5,  "criticality": 3.0},
    6443:  {"category": "Kubernetes API",   "base_value_usd": 2_000_000,"lifetime_years": 7,  "criticality": 4.5},
    2379:  {"category": "etcd",             "base_value_usd": 2_500_000,"lifetime_years": 7,  "criticality": 5.0},
    9200:  {"category": "Elasticsearch",    "base_value_usd": 1_500_000,"lifetime_years": 5,  "criticality": 3.0},
    5601:  {"category": "Kibana/Analytics", "base_value_usd": 500_000,  "lifetime_years": 5,  "criticality": 2.0},
}
_DEFAULT_PROFILE: Dict[str, Any] = {
    "category": "Unknown Service", "base_value_usd": 150_000, "lifetime_years": 5, "criticality": 1.0
}


_HNDL_Q_DAY_YEAR_MIN = 2027
_HNDL_Q_DAY_YEAR_MAX = 2040


def default_q_day_year() -> Dict[str, Any]:
    """Default Q-Day year for HNDL views: the Q-Intel model's RSA-2048 50% year."""
    try:
        from services.q_intel import q_day_reference
        year = q_day_reference("rsa2048").get("expected_year")
        if year is None:
            return {"year": _HNDL_Q_DAY_YEAR_MAX, "source": "q_intel_model_beyond_range"}
        return {"year": max(_HNDL_Q_DAY_YEAR_MIN, min(int(year), _HNDL_Q_DAY_YEAR_MAX)), "source": "q_intel_model"}
    except Exception:
        return {"year": _HNDL_Q_DAY_YEAR_MAX, "source": "fallback_range_max"}


def hndl_model_basis(q_day_year: Optional[int] = None, q_day_year_source: str = "") -> Dict[str, Any]:
    from services.model_basis import model_basis
    assumptions: List[str] = []
    if q_day_year is not None:
        assumptions.append(f"Q-Day year used: {q_day_year} (source: {q_day_year_source or 'request'}).")
    assumptions += [
        "exposure_usd = base_value_usd x criticality x years_recorded x P(algorithm broken by the Q-Day year).",
        "years_recorded is the asset's age in the inventory (0.5-5 years), not observed traffic capture.",
        "Risk tier: critical if exposure >= $2M or P >= 50%; high if >= $500K or P >= 25%; medium if >= $100K or P >= 10%.",
    ]
    for algo, table in _Q_DAY_PROBS.items():
        cells = ", ".join(f"{yr} {p:.0%}" for yr, p in sorted(table.items()))
        assumptions.append(f"P(broken) {algo}: {cells}")
    for port, prof in _DATA_PROFILES.items():
        assumptions.append(
            f"Port {port} {prof['category']}: ${prof['base_value_usd']:,}/yr data value, "
            f"criticality {prof['criticality']}, lifetime {prof['lifetime_years']}y"
        )
    assumptions.append(
        f"Other ports {_DEFAULT_PROFILE['category']}: ${_DEFAULT_PROFILE['base_value_usd']:,}/yr, "
        f"criticality {_DEFAULT_PROFILE['criticality']}, lifetime {_DEFAULT_PROFILE['lifetime_years']}y"
    )
    return model_basis(
        kind="model",
        summary=(
            "Dollar exposure is a planning model built from fixed break probabilities and per-port data values; "
            "it is not a valuation of your data or a measurement of traffic that was actually captured."
        ),
        assumptions=assumptions,
        sources=["Break-probability table and data profiles are internal planning assumptions (no external source)."],
        as_of="2026-09",
    )


#: Returned when nothing about the endpoint's cryptography was observed. It has no probability row
#: on purpose: there is no honest number to multiply a dollar value by for an asset nobody scanned.
UNMEASURED = "unmeasured"


def _classify_algorithm(
    tls_version: str,
    cipher_name: str,
    key_type: str,
    key_bits: int,
    key_exchange: str = "",
) -> str:
    """Map scan result fields to an algorithm class for Q-Day probability lookup.

    Two things this must not do, both of which it used to. It must not report a key size it was
    not given -- every RSA asset came out as ``rsa2048`` and every EC asset as ``ecc256``, so
    RSA-4096 and P-521 endpoints were priced at the Q-Day probability of the weakest key in their
    family. And it must not classify an asset that was never scanned at all: with no TLS version,
    no cipher and no key it fell through to ``unknown_classical`` and got a dollar figure.

    ``key_exchange`` is the negotiated TLS 1.3 group (see scanner._probe_tls13_key_exchange_group).
    It is the only field that can reach the ``pqc_hybrid`` and ``pqc_pure`` buckets, because a
    TLS 1.3 suite name such as TLS_AES_256_GCM_SHA384 never names the key exchange.
    """
    tv = str(tls_version or "").lower()
    cn = str(cipher_name or "").lower()
    kt = str(key_type or "").lower()
    kx = str(key_exchange or "").lower().replace("_", "").replace("-", "")
    try:
        kb = int(key_bits or 0)
    except (TypeError, ValueError):
        kb = 0

    if not tv and not cn and not kt and not kx:
        return UNMEASURED

    # The negotiated group, where the scanner could observe it, decides the key exchange outright.
    if kx:
        pqc = any(x in kx for x in ("mlkem", "kyber", "ntru", "bike", "hqc", "frodo"))
        if pqc:
            hybrid = any(x in kx for x in ("x25519", "x448", "p256", "p384", "p521", "secp"))
            return "pqc_hybrid" if hybrid else "pqc_pure"

    if "1.0" in tv or "ssl" in tv:
        return "tls10_or_ssl"
    if any(x in cn for x in ("kyber", "mlkem", "ml-kem", "ntru", "bike", "hqc")):
        if any(x in cn for x in ("x25519", "p256", "p384")):
            return "pqc_hybrid"
        return "pqc_pure"
    if any(x in cn for x in ("dilithium", "mldsa", "falcon", "sphincs")):
        return "pqc_pure"
    if "rsa" in kt or "rsa" in cn:
        if kb >= 4096:
            return "rsa4096"
        if kb >= 3072:
            return "rsa3072"
        if kb:
            return "rsa2048"
        # RSA of an unobserved size. It is classical and Shor breaks it, but which of the three
        # RSA curves applies is not known, so use the generic classical curve rather than assert
        # the 2048-bit one.
        return "unknown_classical"
    if any(x in kt for x in ("ec", "ecdsa", "ecdh")):
        if kb >= 384:
            return "ecc384"
        if kb:
            return "ecc256"
        return "unknown_classical"
    if "x25519" in cn or "25519" in kt:
        return "x25519"
    if "dhe" in cn or "dh_" in cn:
        return "dh_classical"
    return "unknown_classical"


def _interpolate_prob(algo_class: str, q_day_year: int) -> float:
    """Return probability that algo_class is broken by q_day_year (linear interpolation)."""
    table = _Q_DAY_PROBS.get(algo_class, _Q_DAY_PROBS["unknown_classical"])
    years = sorted(table.keys())
    if q_day_year <= years[0]:
        return table[years[0]]
    if q_day_year >= years[-1]:
        return table[years[-1]]
    for i in range(len(years) - 1):
        y0, y1 = years[i], years[i + 1]
        if y0 <= q_day_year <= y1:
            frac = (q_day_year - y0) / (y1 - y0)
            return table[y0] + frac * (table[y1] - table[y0])
    return 0.0


def score_tls_endpoint_hndl(
    host: str,
    port: int,
    tls_version: str,
    cipher_name: str,
    key_type: str,
    key_bits: int,
    q_day_year: Optional[int] = None,
    first_scan_days_ago: int = 365,
    key_exchange: str = "",
) -> Dict[str, Any]:
    """Calculate HNDL financial exposure for a single TLS/SSH endpoint.

    An endpoint whose cryptography was never observed returns ``exposure_usd: None`` and risk tier
    ``unmeasured``. Returning a number there would price an asset nobody scanned, using an
    algorithm nobody saw -- and the number would land in the org total as if it were evidence.
    """
    if q_day_year is None:
        q_day_year = default_q_day_year()["year"]
    algo_class = _classify_algorithm(tls_version, cipher_name, key_type, key_bits, key_exchange)
    profile = _DATA_PROFILES.get(int(port or 443), _DEFAULT_PROFILE)
    if algo_class == UNMEASURED:
        return {
            "host": host,
            "port": port,
            "algo_class": UNMEASURED,
            "p_broken": None,
            "data_category": profile["category"],
            "data_lifetime_years": profile["lifetime_years"],
            "criticality_multiplier": profile["criticality"],
            "years_recorded": None,
            "exposure_usd": None,
            "risk_tier": UNMEASURED,
            "rationale": (
                "No cryptography has been observed on this endpoint, so its harvest-now exposure "
                "cannot be estimated. Scan it to obtain a figure."
            ),
        }
    p_broken = round(_interpolate_prob(algo_class, q_day_year), 4)
    years_recorded = min(max(float(first_scan_days_ago or 365) / 365.0, 0.5), 5.0)
    exposure_usd = round(
        profile["base_value_usd"] * profile["criticality"] * years_recorded * p_broken, 2
    )

    if exposure_usd >= 2_000_000 or p_broken >= 0.50:
        risk_tier = "critical"
    elif exposure_usd >= 500_000 or p_broken >= 0.25:
        risk_tier = "high"
    elif exposure_usd >= 100_000 or p_broken >= 0.10:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    return {
        "host": host,
        "port": port,
        "algo_class": algo_class,
        "p_broken": p_broken,
        "data_category": profile["category"],
        "data_lifetime_years": profile["lifetime_years"],
        "criticality_multiplier": profile["criticality"],
        "years_recorded": round(years_recorded, 2),
        "exposure_usd": exposure_usd,
        "risk_tier": risk_tier,
        "rationale": (
            f"Algorithm: {algo_class.replace('_', ' ')} | "
            f"P(broken by {q_day_year}): {p_broken:.0%} | "
            f"Data: {profile['category']} | "
            f"Harvest window: {years_recorded:.1f} yr"
        ),
    }


def compute_org_hndl_dashboard(
    assets: List[Dict[str, Any]],
    q_day_year: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Aggregate HNDL exposure across all org assets.

    Each asset dict should contain: host, port, tls_version, cipher_name,
    key_type, key_bits, first_scan_days_ago (optional).
    q_day_year defaults to the Q-Intel model's RSA-2048 50% year.
    """
    if q_day_year is None:
        resolved = default_q_day_year()
        q_day_year, q_day_year_source = resolved["year"], resolved["source"]
    else:
        q_day_year_source = "request"
    scored: List[Dict[str, Any]] = []
    for a in assets:
        host = str(a.get("host") or a.get("asset_key") or "")
        port = int(a.get("port") or 443)
        result = score_tls_endpoint_hndl(
            host=host,
            port=port,
            tls_version=str(a.get("tls_version") or ""),
            cipher_name=str(a.get("cipher_name") or a.get("cipher") or ""),
            key_type=str(a.get("key_type") or a.get("cert_key_type") or ""),
            key_bits=int(a.get("key_bits") or a.get("cert_key_bits") or 0),
            q_day_year=q_day_year,
            first_scan_days_ago=int(a.get("first_scan_days_ago") or 365),
            key_exchange=str(a.get("key_exchange") or a.get("negotiated_group") or ""),
        )
        result["asset_key"] = a.get("asset_key") or f"{host}:{port}"
        result["owner"] = a.get("owner") or ""
        result["environment"] = a.get("environment") or ""
        scored.append(result)

    scored.sort(key=lambda x: (x["exposure_usd"] is not None, x["exposure_usd"] or 0.0), reverse=True)
    # Unmeasured assets contribute no dollars, because there is no observation to price. They are
    # counted separately instead of being folded in at a default algorithm, which is what made the
    # estate total look like a measurement of the whole inventory.
    measured = [x for x in scored if x["exposure_usd"] is not None]
    unmeasured = [x for x in scored if x["exposure_usd"] is None]
    total_exposure = sum(x["exposure_usd"] for x in measured)
    tier_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, UNMEASURED: 0}
    algo_counts: Dict[str, int] = {}
    for x in scored:
        tier_counts[x["risk_tier"]] = tier_counts.get(x["risk_tier"], 0) + 1
        algo_counts[x["algo_class"]] = algo_counts.get(x["algo_class"], 0) + 1

    return {
        "q_day_year": q_day_year,
        "q_day_year_source": q_day_year_source,
        "total_exposure_usd": round(total_exposure, 2),
        "asset_count": len(scored),
        "measured_asset_count": len(measured),
        "unmeasured_asset_count": len(unmeasured),
        "exposure_basis": (
            f"Exposure is summed over the {len(measured)} asset(s) whose cryptography was observed; "
            f"{len(unmeasured)} asset(s) have never been scanned and are excluded rather than "
            "priced at an assumed algorithm."
        ),
        "risk_tier_counts": tier_counts,
        "top_algo_classes": dict(sorted(algo_counts.items(), key=lambda i: i[1], reverse=True)),
        "priority_queue": scored[:50],
        "model_basis": hndl_model_basis(q_day_year, q_day_year_source),
    }


def compute_hndl_timeline(
    assets: List[Dict[str, Any]],
    years: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Compute total HNDL exposure across multiple Q-Day years for timeline chart."""
    if not years:
        years = [2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035]
    result = []
    for y in years:
        dash = compute_org_hndl_dashboard(assets, q_day_year=y)
        result.append({
            "year": y,
            "total_exposure_usd": dash["total_exposure_usd"],
            "critical_count": dash["risk_tier_counts"].get("critical", 0),
            "high_count": dash["risk_tier_counts"].get("high", 0),
        })
    return result
