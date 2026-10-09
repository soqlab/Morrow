from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class HndlStorageObject(BaseModel):
    provider: str = "aws"
    location: str
    name: str = ""
    encryption: str = ""
    kms_key_type: str = ""
    contains_sensitive_data: bool = False
    data_lifetime_years: int = 0
    age_days: int = 0
    size_gb: float = 0.0
    owner: str = ""


class HndlAuditRequest(BaseModel):
    objects: List[HndlStorageObject] = Field(default_factory=list)


class AwsS3HndlInventoryRequest(BaseModel):
    credential_id: int = 0
    region: str = "us-east-1"
    max_buckets: int = 50
    max_objects_per_bucket: int = 100
    sensitive_name_patterns: List[str] = Field(default_factory=lambda: ["backup", "db", "database", "patient", "customer", "pii", "phi", "archive"])
    dry_run: bool = True
    include_object_encryption: bool = False


class GcpStorageHndlInventoryRequest(BaseModel):
    credential_id: int = 0
    project_id: str = ""
    max_buckets: int = 50
    max_objects_per_bucket: int = 100
    sensitive_name_patterns: List[str] = Field(default_factory=lambda: ["backup", "db", "database", "patient", "customer", "pii", "phi", "archive"])
    dry_run: bool = True


class AzureBlobHndlInventoryRequest(BaseModel):
    credential_id: int = 0
    account_url: str = ""
    max_containers: int = 50
    max_blobs_per_container: int = 100
    sensitive_name_patterns: List[str] = Field(default_factory=lambda: ["backup", "db", "database", "patient", "customer", "pii", "phi", "archive"])
    dry_run: bool = True


class RuntimeTrafficRecord(BaseModel):
    source: str = ""
    provider: str = ""
    url: str = ""
    host: str = ""
    hostname: str = ""
    port: int = 0
    protocol: str = ""
    method: str = ""
    path: str = ""
    server_name: str = ""
    tls_version: str = ""
    cipher: str = ""
    status_code: int = 0
    count: int = 1
    observed_count: int = 0
    timestamp: str = ""
    observed_at: str = ""
    metadata: dict = Field(default_factory=dict)


class RuntimeTrafficImportRequest(BaseModel):
    source: str = Field("manual", max_length=64)
    provider: str = Field("unknown", max_length=64)
    log_format: str = Field("auto", max_length=32)
    raw_logs: List[str] = Field(default_factory=list, max_length=10000)
    records: List[RuntimeTrafficRecord] = Field(default_factory=list, max_length=10000)
    create_assets: bool = True
    default_owner: str = Field("", max_length=256)
    default_team: str = Field("", max_length=256)
    default_environment: str = Field("", max_length=64)
    default_criticality: str = Field("", max_length=64)
    default_confidentiality_lifetime: str = Field("", max_length=64)
    tags: List[str] = Field(default_factory=lambda: ["runtime-observed"], max_length=50)
