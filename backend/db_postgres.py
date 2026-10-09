from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, List, Optional, Sequence

import psycopg2
from psycopg2.extras import Json, RealDictCursor, execute_values

from scan_observation import scan_result_observation


DEFAULT_ORG_ID = (
    os.environ.get("PQC_DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001").strip()
    or "00000000-0000-0000-0000-000000000001"
)
_SCHEMA_READY_LOCK = threading.Lock()
_SCHEMA_READY: set[str] = set()
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: Sequence[str]
    conflict_target: Sequence[str] = field(default_factory=tuple)
    update_columns: Sequence[str] = field(default_factory=tuple)
    json_defaults: Dict[str, Any] = field(default_factory=dict)
    timestamp_columns: Sequence[str] = field(default_factory=tuple)
    integer_columns: Sequence[str] = field(default_factory=tuple)
    sequence_column: str = ""


CORE_TABLE_SPECS: List[TableSpec] = [
    TableSpec(
        name="organizations",
        columns=("id", "name", "plan_type", "subscription_status", "created_at", "updated_at"),
        conflict_target=("id",),
        update_columns=("name", "plan_type", "subscription_status", "updated_at"),
        timestamp_columns=("created_at", "updated_at"),
    ),
    TableSpec(
        name="repositories",
        columns=("id", "organization_id", "name", "html_url", "created_at", "updated_at"),
        conflict_target=("organization_id", "name"),
        update_columns=("html_url", "updated_at"),
        timestamp_columns=("created_at", "updated_at"),
        sequence_column="id",
    ),
    TableSpec(
        name="validation_jobs",
        columns=(
            "id",
            "organization_id",
            "remediation_id",
            "validator_type",
            "status",
            "git_ref",
            "job_id",
            "stdout",
            "stderr",
            "exit_code",
            "details_json",
            "created_at",
            "updated_at",
            "finished_at",
        ),
        conflict_target=("id",),
        update_columns=(
            "organization_id",
            "remediation_id",
            "validator_type",
            "status",
            "git_ref",
            "job_id",
            "stdout",
            "stderr",
            "exit_code",
            "details_json",
            "created_at",
            "updated_at",
            "finished_at",
        ),
        json_defaults={"details_json": {}},
        integer_columns=("remediation_id", "exit_code"),
        timestamp_columns=("created_at", "updated_at", "finished_at"),
        sequence_column="id",
    ),
    TableSpec(
        name="assets",
        columns=(
            "organization_id",
            "asset_key",
            "owner",
            "team",
            "environment",
            "criticality",
            "confidentiality_lifetime",
            "notes",
            "metadata_json",
            "repository_id",
            "updated_at",
        ),
        conflict_target=("organization_id", "asset_key"),
        update_columns=(
            "owner",
            "team",
            "environment",
            "criticality",
            "confidentiality_lifetime",
            "notes",
            "metadata_json",
            "repository_id",
            "updated_at",
        ),
        json_defaults={"metadata_json": {}},
        integer_columns=("repository_id",),
        timestamp_columns=("updated_at",),
    ),
    TableSpec(
        name="asset_tags",
        columns=("organization_id", "asset_key", "tag"),
        conflict_target=("organization_id", "asset_key", "tag"),
    ),
    TableSpec(
        name="baselines",
        columns=("organization_id", "asset_key", "baseline_scan_id", "set_at"),
        conflict_target=("organization_id", "asset_key"),
        update_columns=("baseline_scan_id", "set_at"),
        timestamp_columns=("set_at",),
    ),
    TableSpec(
        name="scans",
        columns=(
            "id",
            "organization_id",
            "status",
            "created_at",
            "progress_json",
            "error_text",
            "results_json",
            "summary_json",
            "job_id",
            "job_state",
            "job_started_at",
            "job_finished_at",
        ),
        conflict_target=("id",),
        update_columns=(
            "status",
            "organization_id",
            "created_at",
            "progress_json",
            "error_text",
            "results_json",
            "summary_json",
            "job_id",
            "job_state",
            "job_started_at",
            "job_finished_at",
        ),
        json_defaults={
            "progress_json": {},
            "results_json": [],
            "summary_json": {},
        },
        timestamp_columns=("created_at", "job_started_at", "job_finished_at"),
    ),
    TableSpec(
        name="scan_results",
        columns=(
            "id",
            "organization_id",
            "asset_key",
            "scan_id",
            "scanned_at",
            "risk_level",
            "quantum_score",
            "findings_count",
            "pqc_relevance",
            "tls_version",
            "key_type",
            "sig_algorithm",
            "owner",
            "team",
            "environment",
            "criticality",
            "key_bits",
            "key_curve",
            "cipher_name",
            "scan_status",
            "key_exchange",
        ),
        conflict_target=("id",),
        update_columns=(
            "organization_id",
            "asset_key",
            "scan_id",
            "scanned_at",
            "risk_level",
            "quantum_score",
            "findings_count",
            "pqc_relevance",
            "tls_version",
            "key_type",
            "sig_algorithm",
            "owner",
            "team",
            "environment",
            "criticality",
        ),
        integer_columns=("id", "findings_count"),
        timestamp_columns=("scanned_at",),
        sequence_column="id",
    ),
    TableSpec(
        name="remediations",
        columns=(
            "id",
            "organization_id",
            "asset_key",
            "repo_id",
            "vulnerability",
            "file_path",
            "original_content",
            "suggested_fix",
            "suggested_content",
            "status",
            "pr_url",
            "pr_branch",
            "pr_base_branch",
            "github_credential_id",
            "branch_cleanup_status",
            "branch_cleanup_at",
            "branch_cleanup_error",
            "branch_cleanup_attempts",
            "review_note",
            "merged_at",
            "verification_scan_id",
            "closed_at",
            "parent_remediation_id",
            "origin_kind",
            "drift_followup_remediation_id",
            "drift_status",
            "last_drift_checked_at",
            "drift_detected_at",
            "drift_acknowledged_at",
            "drift_acknowledged_by",
            "drift_ack_note",
            "drift_details_json",
            "created_at",
            "updated_at",
        ),
        conflict_target=("id",),
        update_columns=(
            "organization_id",
            "asset_key",
            "repo_id",
            "vulnerability",
            "file_path",
            "original_content",
            "suggested_fix",
            "suggested_content",
            "status",
            "pr_url",
            "pr_branch",
            "pr_base_branch",
            "github_credential_id",
            "branch_cleanup_status",
            "branch_cleanup_at",
            "branch_cleanup_error",
            "branch_cleanup_attempts",
            "review_note",
            "merged_at",
            "verification_scan_id",
            "closed_at",
            "parent_remediation_id",
            "origin_kind",
            "drift_followup_remediation_id",
            "drift_status",
            "last_drift_checked_at",
            "drift_detected_at",
            "drift_acknowledged_at",
            "drift_acknowledged_by",
            "drift_ack_note",
            "drift_details_json",
            "created_at",
            "updated_at",
        ),
        json_defaults={"drift_details_json": {}},
        integer_columns=("id", "repo_id", "github_credential_id", "branch_cleanup_attempts", "parent_remediation_id", "drift_followup_remediation_id"),
        timestamp_columns=("merged_at", "closed_at", "branch_cleanup_at", "last_drift_checked_at", "drift_detected_at", "drift_acknowledged_at", "created_at", "updated_at"),
        sequence_column="id",
    ),
    TableSpec(
        name="audit_logs",
        columns=(
            "id",
            "organization_id",
            "actor_id",
            "actor_role",
            "action",
            "resource_type",
            "resource_id",
            "decision",
            "reason",
            "details_json",
            "prev_hash",
            "entry_hash",
            "created_at",
        ),
        conflict_target=("id",),
        json_defaults={"details_json": {}},
        integer_columns=("id",),
        timestamp_columns=("created_at",),
        sequence_column="id",
    ),
    TableSpec(
        name="github_installations",
        columns=(
            "id",
            "organization_id",
            "installation_id",
            "account_login",
            "account_type",
            "target_type",
            "permissions_json",
            "repositories_count",
            "suspended_at",
            "created_at",
            "updated_at",
        ),
        conflict_target=("organization_id", "installation_id"),
        update_columns=(
            "account_login",
            "account_type",
            "target_type",
            "permissions_json",
            "repositories_count",
            "suspended_at",
            "updated_at",
        ),
        json_defaults={"permissions_json": {}},
        integer_columns=("id", "installation_id", "repositories_count"),
        timestamp_columns=("suspended_at", "created_at", "updated_at"),
        sequence_column="id",
    ),
    TableSpec(
        name="webhooks",
        columns=("id", "name", "url", "secret", "credential_id", "events_json", "enabled", "created_at", "updated_at"),
        conflict_target=("id",),
        update_columns=("name", "url", "secret", "credential_id", "events_json", "enabled", "created_at", "updated_at"),
        json_defaults={"events_json": []},
        integer_columns=("id", "credential_id", "enabled"),
        sequence_column="id",
    ),
    TableSpec(
        name="webhook_events",
        columns=(
            "id",
            "webhook_id",
            "created_at",
            "event_type",
            "dedupe_key",
            "payload_json",
            "status",
            "http_status",
            "error_text",
            "response_excerpt",
            "attempts",
            "last_attempt_at",
            "next_attempt_at",
            "claimed_at",
            "claimed_by",
        ),
        conflict_target=("id",),
        update_columns=(
            "webhook_id",
            "created_at",
            "event_type",
            "dedupe_key",
            "payload_json",
            "status",
            "http_status",
            "error_text",
            "response_excerpt",
            "attempts",
            "last_attempt_at",
            "next_attempt_at",
            "claimed_at",
            "claimed_by",
        ),
        json_defaults={"payload_json": {}},
        integer_columns=("id", "webhook_id", "http_status", "attempts"),
        sequence_column="id",
    ),
    TableSpec(
        name="collections",
        columns=("id", "name", "targets_text", "created_at", "updated_at"),
        conflict_target=("id",),
        update_columns=("name", "targets_text", "created_at", "updated_at"),
        sequence_column="id",
    ),
    TableSpec(
        name="schedules",
        columns=(
            "id",
            "collection_id",
            "enabled",
            "interval_minutes",
            "created_at",
            "updated_at",
            "last_run_at",
            "next_run_at",
            "last_scan_id",
        ),
        conflict_target=("id",),
        update_columns=(
            "collection_id",
            "enabled",
            "interval_minutes",
            "created_at",
            "updated_at",
            "last_run_at",
            "next_run_at",
            "last_scan_id",
        ),
        integer_columns=("id", "collection_id", "enabled", "interval_minutes"),
        sequence_column="id",
    ),
    TableSpec(
        name="integrations_settings",
        columns=("key", "value"),
        conflict_target=("key",),
        update_columns=("value",),
    ),
    TableSpec(
        name="event_rules",
        columns=(
            "id",
            "name",
            "enabled",
            "webhook_ids_json",
            "event_types_json",
            "min_severity",
            "rule_ids_json",
            "quantum_score_min",
            "environments_json",
            "teams_json",
            "criticalities_json",
            "tags_json",
            "cooldown_minutes",
            "fire_mode",
            "created_at",
            "updated_at",
        ),
        conflict_target=("id",),
        update_columns=(
            "name",
            "enabled",
            "webhook_ids_json",
            "event_types_json",
            "min_severity",
            "rule_ids_json",
            "quantum_score_min",
            "environments_json",
            "teams_json",
            "criticalities_json",
            "tags_json",
            "cooldown_minutes",
            "fire_mode",
            "created_at",
            "updated_at",
        ),
        json_defaults={
            "webhook_ids_json": [],
            "event_types_json": [],
            "rule_ids_json": [],
            "environments_json": [],
            "teams_json": [],
            "criticalities_json": [],
            "tags_json": [],
        },
        integer_columns=("id", "enabled", "cooldown_minutes"),
        sequence_column="id",
    ),
    TableSpec(
        name="event_rule_fires",
        columns=("rule_id", "fingerprint", "last_fired_at"),
        conflict_target=("rule_id", "fingerprint"),
        update_columns=("last_fired_at",),
        integer_columns=("rule_id",),
    ),
]


POSTGRES_CORE_SCHEMA_SQL: Sequence[str] = (
    """
    CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        plan_type TEXT NOT NULL DEFAULT 'starter',
        subscription_status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name)",
    """
    CREATE TABLE IF NOT EXISTS repositories (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        name TEXT NOT NULL,
        html_url TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE(organization_id, name)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_repositories_org ON repositories(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_repositories_name ON repositories(name)",
    """
    CREATE TABLE IF NOT EXISTS assets (
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT '',
        team TEXT NOT NULL DEFAULT '',
        environment TEXT NOT NULL DEFAULT '',
        criticality TEXT NOT NULL DEFAULT '',
        confidentiality_lifetime TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        repository_id BIGINT NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY(organization_id, asset_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner)",
    "CREATE INDEX IF NOT EXISTS idx_assets_team ON assets(team)",
    "CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment)",
    "CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets(criticality)",
    """
    CREATE TABLE IF NOT EXISTS asset_tags (
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL,
        tag TEXT NOT NULL,
        PRIMARY KEY(organization_id, asset_key, tag)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asset_tags_org ON asset_tags(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags(tag)",
    """
    CREATE TABLE IF NOT EXISTS baselines (
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL,
        baseline_scan_id TEXT NOT NULL,
        set_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY(organization_id, asset_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_baselines_org ON baselines(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines(baseline_scan_id)",
    """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        progress_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        error_text TEXT NOT NULL DEFAULT '',
        results_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        job_id TEXT NOT NULL DEFAULT '',
        job_state TEXT NOT NULL DEFAULT '',
        job_started_at TIMESTAMPTZ NULL,
        job_finished_at TIMESTAMPTZ NULL
    )
    """,
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE scans SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id)",
    # pg_list_scan_rows is "WHERE organization_id = %s ORDER BY created_at DESC LIMIT %s"; the
    # single-column index above leaves Postgres to sort every one of the tenant's scans on every
    # GET /scans. services/platform_analytics.py already creates this index, but only once an
    # operator opens an analytics page -- the customer-facing path must not depend on that.
    "CREATE INDEX IF NOT EXISTS idx_scans_org_created ON scans(organization_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS scan_results (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        scanned_at TIMESTAMPTZ NOT NULL,
        risk_level TEXT NOT NULL,
        quantum_score DOUBLE PRECISION NOT NULL DEFAULT 0,
        findings_count INTEGER NOT NULL DEFAULT 0,
        pqc_relevance TEXT NOT NULL DEFAULT '',
        tls_version TEXT NOT NULL DEFAULT '',
        key_type TEXT NOT NULL DEFAULT '',
        sig_algorithm TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL DEFAULT '',
        team TEXT NOT NULL DEFAULT '',
        environment TEXT NOT NULL DEFAULT '',
        criticality TEXT NOT NULL DEFAULT '',
        key_bits INTEGER,
        key_curve TEXT,
        cipher_name TEXT,
        scan_status TEXT,
        key_exchange TEXT
    )
    """,
    # Observed key facts. Added after the table shipped, so existing deployments get them here --
    # ensure_postgres_core_schema() runs this list on every start, which is how every other column
    # added to this schema has reached an already-populated database. NULLable on purpose: NULL
    # means the scan did not observe a key size, which is not the same as a zero-bit key.
    "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS key_bits INTEGER",
    "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS key_curve TEXT",
    "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS cipher_name TEXT",
    "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS scan_status TEXT",
    "ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS key_exchange TEXT",
    # Backfill only what the stored key_type fixes on its own; RSA and bare "EC" stay NULL rather
    # than being guessed at 2048 / P-256.
    "UPDATE scan_results SET key_bits=256, key_curve='Curve25519' WHERE key_bits IS NULL AND LOWER(TRIM(key_type)) IN ('ed25519','x25519')",
    "UPDATE scan_results SET key_bits=448, key_curve='Curve448' WHERE key_bits IS NULL AND LOWER(TRIM(key_type))='ed448'",
    "UPDATE scan_results SET key_bits=448, key_curve='Curve448' WHERE key_bits IS NULL AND LOWER(TRIM(key_type))='x448'",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_org ON scan_results(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_asset ON scan_results(asset_key, scanned_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)",
    # Every reporting read is "this tenant, newest first" or "this tenant, newest per asset":
    # pg_list_scan_results_since (behind /executive-dashboard, /board-risk, /heatmap and
    # /crypto-agility) and pg_latest_scan_results_for_assets. idx_scan_results_asset is keyed on
    # asset_key first, so it cannot serve either, and the org-only index leaves a sort over the
    # whole tenant. This one orders within the tenant.
    "CREATE INDEX IF NOT EXISTS idx_scan_results_org_scanned ON scan_results(organization_id, scanned_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_org_asset_scanned "
    "ON scan_results(organization_id, asset_key, scanned_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS remediations (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL,
        repo_id BIGINT NOT NULL DEFAULT 0,
        vulnerability TEXT NOT NULL DEFAULT '',
        file_path TEXT NOT NULL DEFAULT '',
        original_content TEXT NOT NULL DEFAULT '',
        suggested_fix TEXT NOT NULL DEFAULT '',
        suggested_content TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        pr_url TEXT NOT NULL DEFAULT '',
        pr_branch TEXT NOT NULL DEFAULT '',
        pr_base_branch TEXT NOT NULL DEFAULT '',
        github_credential_id BIGINT NOT NULL DEFAULT 0,
        branch_cleanup_status TEXT NOT NULL DEFAULT '',
        branch_cleanup_at TIMESTAMPTZ NULL,
        branch_cleanup_error TEXT NOT NULL DEFAULT '',
        branch_cleanup_attempts INTEGER NOT NULL DEFAULT 0,
        review_note TEXT NOT NULL DEFAULT '',
        merged_at TIMESTAMPTZ NULL,
        verification_scan_id TEXT NOT NULL DEFAULT '',
        closed_at TIMESTAMPTZ NULL,
        parent_remediation_id BIGINT NOT NULL DEFAULT 0,
        origin_kind TEXT NOT NULL DEFAULT '',
        drift_followup_remediation_id BIGINT NOT NULL DEFAULT 0,
        drift_status TEXT NOT NULL DEFAULT '',
        last_drift_checked_at TIMESTAMPTZ NULL,
        drift_detected_at TIMESTAMPTZ NULL,
        drift_acknowledged_at TIMESTAMPTZ NULL,
        drift_acknowledged_by TEXT NOT NULL DEFAULT '',
        drift_ack_note TEXT NOT NULL DEFAULT '',
        drift_details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )
    """,
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS parent_remediation_id BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS pr_branch TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS pr_base_branch TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS github_credential_id BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS branch_cleanup_status TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS branch_cleanup_at TIMESTAMPTZ NULL",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS branch_cleanup_error TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS branch_cleanup_attempts INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS origin_kind TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_followup_remediation_id BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_status TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS last_drift_checked_at TIMESTAMPTZ NULL",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_detected_at TIMESTAMPTZ NULL",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_acknowledged_at TIMESTAMPTZ NULL",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_acknowledged_by TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_ack_note TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediations ADD COLUMN IF NOT EXISTS drift_details_json JSONB NOT NULL DEFAULT '{}'::jsonb",
    "CREATE INDEX IF NOT EXISTS idx_remediations_org ON remediations(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_repo_id ON remediations(repo_id)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_asset_key ON remediations(asset_key)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_branch_cleanup ON remediations(branch_cleanup_status)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_parent_id ON remediations(parent_remediation_id)",
    "CREATE INDEX IF NOT EXISTS idx_remediations_drift_status ON remediations(drift_status)",
    """
    CREATE TABLE IF NOT EXISTS migration_tasks (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        asset_key TEXT NOT NULL DEFAULT '',
        repository_name TEXT NOT NULL DEFAULT '',
        repo_id BIGINT NOT NULL DEFAULT 0,
        file_path TEXT NOT NULL DEFAULT '',
        rule_id TEXT NOT NULL DEFAULT '',
        legacy_dependency TEXT NOT NULL DEFAULT '',
        migration_target TEXT NOT NULL DEFAULT '',
        safety_class TEXT NOT NULL DEFAULT 'migration_task',
        confidence TEXT NOT NULL DEFAULT 'medium',
        safety_reason TEXT NOT NULL DEFAULT '',
        recommended_workflow TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        source TEXT NOT NULL DEFAULT 'repo_crypto_discovery',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_migration_tasks_org ON migration_tasks(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_migration_tasks_status ON migration_tasks(status)",
    "CREATE INDEX IF NOT EXISTS idx_migration_tasks_repo_id ON migration_tasks(repo_id)",
    "CREATE INDEX IF NOT EXISTS idx_migration_tasks_asset_key ON migration_tasks(asset_key)",
    "CREATE INDEX IF NOT EXISTS idx_migration_tasks_repository_name ON migration_tasks(repository_name)",
    """
    CREATE TABLE IF NOT EXISTS validation_jobs (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        remediation_id BIGINT NOT NULL,
        validator_type TEXT NOT NULL DEFAULT 'auto',
        status TEXT NOT NULL DEFAULT 'queued',
        git_ref TEXT NOT NULL DEFAULT '',
        job_id TEXT NOT NULL DEFAULT '',
        stdout TEXT NOT NULL DEFAULT '',
        stderr TEXT NOT NULL DEFAULT '',
        exit_code INTEGER NOT NULL DEFAULT -1,
        details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        finished_at TIMESTAMPTZ NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_validation_jobs_org ON validation_jobs(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_validation_jobs_remediation_id ON validation_jobs(remediation_id)",
    "CREATE INDEX IF NOT EXISTS idx_validation_jobs_status ON validation_jobs(status)",
    "CREATE INDEX IF NOT EXISTS idx_validation_jobs_job_id ON validation_jobs(job_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        actor_id TEXT NOT NULL DEFAULT '',
        actor_role TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL DEFAULT '',
        resource_type TEXT NOT NULL DEFAULT '',
        resource_id TEXT NOT NULL DEFAULT '',
        decision TEXT NOT NULL DEFAULT 'allow',
        reason TEXT NOT NULL DEFAULT '',
        details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        prev_hash TEXT NOT NULL DEFAULT '',
        entry_hash TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id)",
    # pg_append_audit_log reads the chain head with "WHERE organization_id = %s ORDER BY id DESC
    # LIMIT 1", and that runs on the success path of every authorized request. With only the
    # org-only index Postgres collects and sorts the whole tenant's log to find one row, so the
    # cost of every read grows with the size of the audit log the reads themselves are writing.
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id_desc ON audit_logs(organization_id, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_decision ON audit_logs(decision)",
    """
    CREATE OR REPLACE FUNCTION prevent_audit_logs_mutation() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_logs is immutable';
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs",
    """
    CREATE TRIGGER trg_audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_logs_mutation()
    """,
    "DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs",
    """
    CREATE TRIGGER trg_audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_logs_mutation()
    """,
    """
    CREATE TABLE IF NOT EXISTS flight_recorder_events (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        actor_type TEXT NOT NULL DEFAULT 'human',
        actor_id TEXT NOT NULL DEFAULT '',
        actor_role TEXT NOT NULL DEFAULT '',
        intent TEXT NOT NULL DEFAULT '',
        resource_type TEXT NOT NULL DEFAULT '',
        resource_id TEXT NOT NULL DEFAULT '',
        policy_version TEXT NOT NULL DEFAULT '',
        decision TEXT NOT NULL DEFAULT 'allowed',
        outcome TEXT NOT NULL DEFAULT 'pending',
        reason TEXT NOT NULL DEFAULT '',
        evidence_refs_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_flight_events_org ON flight_recorder_events(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_flight_events_created_at ON flight_recorder_events(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_flight_events_intent ON flight_recorder_events(intent)",
    "CREATE INDEX IF NOT EXISTS idx_flight_events_resource ON flight_recorder_events(resource_type, resource_id)",
    "CREATE INDEX IF NOT EXISTS idx_flight_events_decision ON flight_recorder_events(decision)",
    """
    CREATE TABLE IF NOT EXISTS github_installations (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL,
        installation_id BIGINT NOT NULL,
        account_login TEXT NOT NULL DEFAULT '',
        account_type TEXT NOT NULL DEFAULT '',
        target_type TEXT NOT NULL DEFAULT '',
        permissions_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        repositories_count INTEGER NOT NULL DEFAULT 0,
        suspended_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE(organization_id, installation_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_github_installations_org ON github_installations(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_github_installations_installation_id ON github_installations(installation_id)",
    """
    CREATE TABLE IF NOT EXISTS webhooks (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT NOT NULL DEFAULT '',
        credential_id BIGINT NULL,
        events_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
        timeout_seconds INTEGER NOT NULL DEFAULT 10
    )
    """,
    "ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE webhooks SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "ALTER TABLE webhooks DROP CONSTRAINT IF EXISTS webhooks_name_key",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_org_name_unique ON webhooks(organization_id, name)",
    "CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_webhooks_name ON webhooks(name)",
    "ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER NOT NULL DEFAULT 60",
    "ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS timeout_seconds INTEGER NOT NULL DEFAULT 10",
    """
    CREATE TABLE IF NOT EXISTS webhook_events (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        webhook_id BIGINT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        dedupe_key TEXT NOT NULL,
        payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'queued',
        http_status INTEGER NOT NULL DEFAULT 0,
        error_text TEXT NOT NULL DEFAULT '',
        response_excerpt TEXT NOT NULL DEFAULT '',
        attempts INTEGER NOT NULL DEFAULT 0,
        last_attempt_at TEXT NOT NULL DEFAULT '',
        next_attempt_at TEXT NOT NULL DEFAULT '',
        claimed_at TEXT NOT NULL DEFAULT '',
        claimed_by TEXT NOT NULL DEFAULT '',
        UNIQUE(organization_id, webhook_id, dedupe_key)
    )
    """,
    "ALTER TABLE webhook_events ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE webhook_events SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_events_org_webhook_dedupe_unique ON webhook_events(organization_id, webhook_id, dedupe_key)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_events_org ON webhook_events(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook ON webhook_events(webhook_id)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status)",
    """
    CREATE TABLE IF NOT EXISTS collections (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        targets_text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(organization_id, name)
    )
    """,
    "ALTER TABLE collections ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE collections SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(organization_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_collections_org_name_unique ON collections(organization_id, name)",
    "CREATE INDEX IF NOT EXISTS idx_collections_name ON collections(name)",
    """
    CREATE TABLE IF NOT EXISTS schedules (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        collection_id BIGINT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
        enabled INTEGER NOT NULL DEFAULT 1,
        interval_minutes INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_run_at TEXT NOT NULL DEFAULT '',
        next_run_at TEXT NOT NULL DEFAULT '',
        last_scan_id TEXT NOT NULL DEFAULT ''
    )
    """,
    "ALTER TABLE schedules ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE schedules SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE INDEX IF NOT EXISTS idx_schedules_org ON schedules(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run_at)",
    "CREATE INDEX IF NOT EXISTS idx_schedules_collection ON schedules(collection_id)",
    """
    CREATE TABLE IF NOT EXISTS integrations_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS event_rules (
        id BIGSERIAL PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        webhook_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        event_types_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        min_severity TEXT NOT NULL DEFAULT '',
        rule_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        quantum_score_min DOUBLE PRECISION NOT NULL DEFAULT -1,
        environments_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        teams_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        criticalities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        cooldown_minutes INTEGER NOT NULL DEFAULT 0,
        fire_mode TEXT NOT NULL DEFAULT 'always',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "ALTER TABLE event_rules ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE event_rules SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE INDEX IF NOT EXISTS idx_event_rules_org ON event_rules(organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_event_rules_enabled ON event_rules(enabled)",
    """
    CREATE TABLE IF NOT EXISTS event_rule_fires (
        organization_id TEXT NOT NULL DEFAULT '',
        rule_id BIGINT NOT NULL REFERENCES event_rules(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        last_fired_at TEXT NOT NULL,
        PRIMARY KEY(organization_id, rule_id, fingerprint)
    )
    """,
    "ALTER TABLE event_rule_fires ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''",
    f"UPDATE event_rule_fires SET organization_id='{DEFAULT_ORG_ID}' WHERE organization_id=''",
    "CREATE INDEX IF NOT EXISTS idx_event_rule_fires_rule ON event_rule_fires(rule_id)",
)


def product_database_url() -> str:
    return str(os.getenv("PQC_PRODUCT_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()


def postgres_main_db_requested() -> bool:
    return str(os.getenv("PQC_MAIN_DB_BACKEND") or "").strip().lower() == "postgres"


_pool_lock = threading.Lock()
_pools: dict = {}  # dsn_key → ThreadedConnectionPool

_POOL_MIN = int(os.environ.get("PQC_PG_POOL_MIN", "2"))
_POOL_MAX = int(os.environ.get("PQC_PG_POOL_MAX", "20"))
#: How long a caller waits for a pooled connection before giving up. psycopg2's pool never queues
#: (see _getconn_waiting), so without this every request that arrives while the pool is full fails.
_POOL_ACQUIRE_TIMEOUT = max(0.0, float(os.environ.get("PQC_PG_POOL_ACQUIRE_TIMEOUT", "15") or 15))


def _get_pool(url: str):
    """Return a ThreadedConnectionPool for the given DSN, creating it once."""
    from psycopg2 import pool as pg_pool
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    if key not in _pools:
        with _pool_lock:
            if key not in _pools:
                _pools[key] = pg_pool.ThreadedConnectionPool(_POOL_MIN, _POOL_MAX, url)
                logger.info("[PG Pool] created pool min=%d max=%d", _POOL_MIN, _POOL_MAX)
    return _pools[key]


def close_pools() -> None:
    """Close and forget every pooled connection.

    Needed wherever the DSN or the connecting role changes underneath a running process -- tests that
    move between an owner role and the runtime role, and a reconfigure that repoints the product
    database. Without it the old pool keeps handing out connections authenticated as the previous
    role, which for row-level security means the new configuration is not the one being exercised.
    """
    with _pool_lock:
        for pool in list(_pools.values()):
            try:
                pool.closeall()
            except Exception:
                pass
        _pools.clear()


def _getconn_waiting(pool, timeout: float = None):
    """Borrow a connection, waiting for one to come back rather than failing immediately.

    psycopg2's ThreadedConnectionPool.getconn() raises PoolError("connection pool exhausted")
    the instant maxconn connections are checked out -- it has no queue and no wait. Under a
    burst that turned every request arriving while the pool was full into a 500, with no
    backpressure: a load test at 50 concurrent readers produced 500s on /assets, /scans and
    /fix-next while Postgres itself was idle. Worse, callers that wrap their query in a broad
    `except Exception` (reporting paths do, to tolerate a missing table) read the exhaustion as
    "no rows" and reported an empty, zero-risk posture with a 200.

    A pool that is momentarily full is a wait, not a failure. Callers that wait longer than
    PQC_PG_POOL_ACQUIRE_TIMEOUT still get the PoolError, which app.py answers with 503 and a
    Retry-After so a client backs off instead of hammering.
    """
    from psycopg2.pool import PoolError

    limit = _POOL_ACQUIRE_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + limit
    delay = 0.005
    while True:
        try:
            return pool.getconn()
        except PoolError as exc:
            # Only exhaustion is retryable; a closed pool must fail at once.
            if "exhausted" not in str(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 0.1)


class _PooledConn:
    """Context manager that borrows a connection from the pool and returns it on exit."""
    def __init__(self, url: str):
        self._pool = _get_pool(url)
        self._conn = None

    def __enter__(self):
        self._conn = _getconn_waiting(self._pool)
        self._conn.autocommit = False
        self._apply_org_setting(self._conn)
        return self._conn

    @staticmethod
    def _apply_org_setting(conn) -> None:
        """Publish the caller's tenant (and privilege) to Postgres for this checkout.

        services/postgres_rls.py generates policies that read app.current_organization_id, and its
        operator steps say to enable FORCE ROW LEVEL SECURITY. Nothing set that variable, so
        following those instructions made every policy evaluate against NULL and the product would
        have returned zero rows everywhere — the plan reported "ready" while enabling it would have
        broken the deployment.

        Setting it here, at the single point where every Postgres transaction begins, makes RLS a
        genuine backstop behind the per-query organization_id filters. services/tenant_scope.py owns
        the decision and the reasoning (why session scope rather than SET LOCAL, why the value is
        written on every borrow even when no tenant is resolved, and how the cross-tenant escape
        hatch is opened and audited).
        """
        from services.tenant_scope import apply_to_connection

        apply_to_connection(conn)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            if exc_type:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
            else:
                try:
                    self._conn.commit()
                except Exception:
                    pass
            # Clear the tenant before the connection goes back to the pool, so an idle connection
            # never carries the last borrower's tenant or privilege. The next borrow sets its own
            # values regardless; this is the belt to that set of braces, and it is what makes
            # "a pooled connection cannot leak the previous tenant" a property of the pool rather
            # than a property of every future caller remembering to overwrite it.
            try:
                from services.tenant_scope import reset_on_release

                reset_on_release(self._conn)
            except Exception:
                pass
            self._pool.putconn(self._conn)
            self._conn = None


def pg_product_conn(dsn: Optional[str] = None):
    url = str(dsn or product_database_url()).strip()
    if not url:
        raise RuntimeError("PQC_PRODUCT_DATABASE_URL or DATABASE_URL is required for Postgres cutover")
    return _PooledConn(url)


def _dsn_key(dsn: Optional[str] = None) -> str:
    return str(dsn or product_database_url()).strip()


#: Tables the application cannot serve without. Used to decide whether a role that lacks DDL
#: rights is a correctly-provisioned least-privilege runtime role or a genuine misconfiguration.
_CORE_REQUIRED_TABLES: Sequence[str] = (
    "organizations",
    "assets",
    "scans",
    "scan_results",
    "remediations",
    "audit_logs",
)


def _missing_core_tables(conn) -> List[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public' AND tablename = ANY(%s)
            """,
            (list(_CORE_REQUIRED_TABLES),),
        )
        present = {str(row[0]) for row in cur.fetchall()}
    return [t for t in _CORE_REQUIRED_TABLES if t not in present]


def ensure_postgres_core_schema(dsn: Optional[str] = None) -> None:
    """Create/upgrade the Postgres core schema, tolerating a role without DDL rights.

    Row-level security is only meaningful if the runtime role is not a superuser and has no
    BYPASSRLS -- and such a role is normally not granted CREATE on the schema either. This function
    used to run its DDL unconditionally, so a correctly-provisioned least-privilege role made the
    application fail to start with a raw `permission denied for schema public` traceback. The
    documented hardening step and the ability to boot were mutually exclusive.

    Now: if the DDL is refused but the core tables already exist, migrations are skipped and the
    app serves normally (run them separately with an owner/migration role, e.g. AUTO_MIGRATE=1 on a
    one-off container). If the DDL is refused and the schema is genuinely absent, that is fatal, but
    it fails with an actionable message instead of a privilege traceback.
    """
    key = _dsn_key(dsn)
    if not key:
        raise RuntimeError("PQC_PRODUCT_DATABASE_URL or DATABASE_URL is required for Postgres cutover")
    if key in _SCHEMA_READY:
        return
    with _SCHEMA_READY_LOCK:
        if key in _SCHEMA_READY:
            return
        with pg_product_conn(key) as conn:
            try:
                with conn.cursor() as cur:
                    for stmt in POSTGRES_CORE_SCHEMA_SQL:
                        cur.execute(stmt)
            except psycopg2.errors.InsufficientPrivilege:
                conn.rollback()
                missing = _missing_core_tables(conn)
                if missing:
                    raise RuntimeError(
                        "Postgres role %r cannot create the core schema (permission denied) and "
                        "these required tables do not exist: %s. Run migrations once with an "
                        "owner/migration role (AUTO_MIGRATE=1, or python -c \"import db; "
                        "db.init_db()\" using the owner DSN), then start the app with the "
                        "least-privilege role." % (_dsn_role(key), ", ".join(missing))
                    ) from None
                logger.info(
                    "Postgres role %r lacks DDL privileges; skipping schema migrations. The core "
                    "schema is already present, which is the expected state for a least-privilege "
                    "runtime role under row-level security. Apply migrations with an "
                    "owner/migration role.",
                    _dsn_role(key),
                )
        _SCHEMA_READY.add(key)


def _dsn_role(dsn: str) -> str:
    """Extract the username from a DSN for log/error messages, without exposing the password."""
    try:
        from urllib.parse import urlparse
        return urlparse(dsn).username or "?"
    except Exception:
        return "?"


#: Features that create their Postgres tables on first use rather than at startup, registered so a
#: migration run can create all of them up front with an owner role. Without this, the only way to
#: materialise those tables is to hit the corresponding endpoint while connected as a role that has
#: DDL rights -- which is precisely the role a hardened deployment must not use at runtime.
_DEFERRED_SCHEMA_HOOKS: List[tuple] = []


def register_deferred_schema(name: str, fn) -> None:
    """Register a lazily-applied Postgres schema so `apply_deferred_schemas()` can pre-create it."""
    name = str(name)
    # Application reloads must not multiply DDL work or retain stale callbacks.
    for index, (registered_name, _) in enumerate(_DEFERRED_SCHEMA_HOOKS):
        if registered_name == name:
            _DEFERRED_SCHEMA_HOOKS[index] = (name, fn)
            return
    _DEFERRED_SCHEMA_HOOKS.append((name, fn))


def apply_deferred_schemas() -> Dict[str, Any]:
    """Apply every registered deferred schema. Intended to run once with an owner/migration role.

    Import the application first so all hooks are registered:
        python -c "import app, db_postgres, json; print(json.dumps(db_postgres.apply_deferred_schemas()))"

    Returns what succeeded and what did not rather than raising, so one unavailable feature does not
    abort the rest of the migration.
    """
    applied: List[str] = []
    failed: List[Dict[str, str]] = []
    for name, fn in list(_DEFERRED_SCHEMA_HOOKS):
        try:
            fn()
            applied.append(name)
        except Exception as exc:
            # Connection errors can echo a DSN or an env value (e.g. the vault hook); never log secrets.
            from services.env_file import redact_secrets

            message = redact_secrets(exc)
            logger.warning("deferred schema %s failed: %s", name, message)
            failed.append({"name": name, "error": message})
    return {"applied": applied, "failed": failed, "count": len(_DEFERRED_SCHEMA_HOOKS)}


@contextlib.contextmanager
def tolerate_missing_ddl_privilege(conn, required_tables: Sequence[str], feature: str):
    """Allow request-time `CREATE TABLE IF NOT EXISTS` to fail when the role has no DDL rights.

    Several features create their tables lazily on first use rather than at startup. Under a
    least-privilege runtime role -- the one row-level security requires -- Postgres refuses the
    statement with `permission denied for schema public` even when the table already exists, because
    it checks the privilege before honouring IF NOT EXISTS. That turned a dozen endpoints into 500s
    on exactly the configuration the hardening guide tells operators to use.

    Wrap such a block in this: if the tables are already there, the refusal is expected and
    harmless. If they are genuinely absent the error propagates, because then the feature really
    cannot work and silently returning an empty result would hide a broken deployment.
    """
    try:
        yield
    except psycopg2.errors.InsufficientPrivilege:
        try:
            conn.rollback()
        except Exception:
            pass
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY(%s)",
                (list(required_tables),),
            )
            present = {str(row[0]) for row in cur.fetchall()}
        missing = [t for t in required_tables if t not in present]
        if missing:
            raise
        logger.debug(
            "%s: role lacks DDL privileges but its tables already exist; skipping lazy migration",
            feature,
        )


def _json_obj(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _fetchall_dicts(cur) -> List[Dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


def _iso_utc(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        else:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat().replace("+00:00", "Z")
    return str(value)


def _row_to_repo_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    out["created_at"] = _iso_utc(out.get("created_at"))
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    return out


def ensure_postgres_default_org(dsn: Optional[str] = None, name: str = "Default Organization") -> Dict[str, Any]:
    return pg_upsert_organization(DEFAULT_ORG_ID, name=name, dsn=dsn)


def pg_upsert_organization(
    organization_id: str,
    name: str,
    plan_type: str = "starter",
    subscription_status: str = "active",
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO organizations (id, name, plan_type, subscription_status, created_at, updated_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    plan_type = EXCLUDED.plan_type,
                    subscription_status = EXCLUDED.subscription_status,
                    updated_at = NOW()
                RETURNING id, name, plan_type, subscription_status, created_at, updated_at
                """,
                (
                    str(organization_id or "").strip(),
                    str(name or "").strip(),
                    str(plan_type or "starter").strip(),
                    str(subscription_status or "active").strip(),
                ),
            )
            return dict(cur.fetchone())


def pg_list_organizations(limit: int = 200, dsn: Optional[str] = None, *, offset: int = 0) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, plan_type, subscription_status, created_at, updated_at
                FROM organizations
                ORDER BY updated_at DESC,id
                LIMIT %s OFFSET %s
                """,
                (max(1, min(int(limit or 200), 2000)), max(0, int(offset))),
            )
            return _fetchall_dicts(cur)


def pg_archive_organization(org_id: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    oid = str(org_id or "").strip()
    if not oid:
        return None
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE organizations
                SET subscription_status = 'archived', updated_at = NOW()
                WHERE id = %s
                RETURNING id, name, plan_type, subscription_status, created_at, updated_at
                """,
                (oid,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def pg_delete_organization(org_id: str, mode: str = "archive", dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    oid = str(org_id or "").strip()
    if not oid:
        raise ValueError("organization_id is required")
    if str(mode or "archive").strip().lower() != "purge":
        return {"ok": True, "mode": "archive", "organization": pg_archive_organization(oid, dsn=dsn)}

    tables = [
        "event_rule_fires",
        "event_rules",
        "webhook_events",
        "webhooks",
        "validation_jobs",
        "migration_tasks",
        "remediations",
        "scan_results",
        "baselines",
        "asset_tags",
        "assets",
        "repositories",
        "github_installations",
        "credentials",
        "audit_logs",
        "schedules",
        "collections",
        "scans",
    ]
    counts: Dict[str, int] = {}
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            for table in tables:
                cur.execute(
                    """
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = %s
                      AND column_name = 'organization_id'
                    """,
                    (table,),
                )
                if not cur.fetchone():
                    continue
                cur.execute(f"DELETE FROM {table} WHERE organization_id = %s", (oid,))
                counts[table] = int(cur.rowcount or 0)
            cur.execute("DELETE FROM organizations WHERE id = %s", (oid,))
            counts["organizations"] = int(cur.rowcount or 0)
    return {"ok": True, "mode": "purge", "organization_id": oid, "deleted": counts}


def pg_upsert_repository(org_id: str, name: str, html_url: str, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO repositories (organization_id, name, html_url, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
                ON CONFLICT (organization_id, name) DO UPDATE SET
                    html_url = EXCLUDED.html_url,
                    updated_at = NOW()
                RETURNING id, name, html_url, created_at, updated_at
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(name or "").strip(), str(html_url or "").strip()),
            )
            return _row_to_repo_dict(cur.fetchone()) or {"name": name, "html_url": html_url}


def pg_list_repositories(org_id: str, limit: int = 2000, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, html_url, created_at, updated_at
                FROM repositories
                WHERE organization_id = %s
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, max(1, min(int(limit or 2000), 5000))),
            )
            return [_row_to_repo_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_get_repository_by_name(org_id: str, name: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, html_url, created_at, updated_at
                FROM repositories
                WHERE organization_id = %s AND name = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(name or "").strip()),
            )
            return _row_to_repo_dict(cur.fetchone())


def pg_get_repository_by_id(org_id: str, repo_id: int, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, html_url, created_at, updated_at
                FROM repositories
                WHERE organization_id = %s AND id = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, int(repo_id)),
            )
            return _row_to_repo_dict(cur.fetchone())


def _row_to_installation_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    try:
        out["installation_id"] = int(out.get("installation_id") or 0)
    except Exception:
        out["installation_id"] = 0
    try:
        out["repositories_count"] = int(out.get("repositories_count") or 0)
    except Exception:
        out["repositories_count"] = 0
    out["permissions"] = _json_obj(out.pop("permissions_json", {}))
    out["suspended_at"] = _iso_utc(out.get("suspended_at"))
    out["created_at"] = _iso_utc(out.get("created_at"))
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    return out


def pg_upsert_github_installation(
    org_id: str,
    installation_id: int,
    account_login: str,
    account_type: str = "",
    target_type: str = "",
    permissions: Optional[Dict[str, Any]] = None,
    repositories_count: int = 0,
    suspended_at: str = "",
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO github_installations (
                    organization_id, installation_id, account_login, account_type, target_type,
                    permissions_json, repositories_count, suspended_at, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NULLIF(%s, '')::timestamptz, NOW(), NOW())
                ON CONFLICT (organization_id, installation_id) DO UPDATE SET
                    account_login = EXCLUDED.account_login,
                    account_type = EXCLUDED.account_type,
                    target_type = EXCLUDED.target_type,
                    permissions_json = EXCLUDED.permissions_json,
                    repositories_count = EXCLUDED.repositories_count,
                    suspended_at = EXCLUDED.suspended_at,
                    updated_at = NOW()
                RETURNING id, installation_id, account_login, account_type, target_type,
                          permissions_json, repositories_count, suspended_at, created_at, updated_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    int(installation_id),
                    str(account_login or "").strip(),
                    str(account_type or "").strip(),
                    str(target_type or "").strip(),
                    Json(permissions or {}),
                    int(repositories_count or 0),
                    str(suspended_at or "").strip(),
                ),
            )
            return _row_to_installation_dict(cur.fetchone()) or {"installation_id": int(installation_id)}


def pg_list_github_installations(org_id: str, limit: int = 2000, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, installation_id, account_login, account_type, target_type, permissions_json,
                       repositories_count, suspended_at, created_at, updated_at
                FROM github_installations
                WHERE organization_id = %s
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, max(1, min(int(limit or 2000), 5000))),
            )
            return [_row_to_installation_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_get_github_installation(org_id: str, installation_id: int, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, installation_id, account_login, account_type, target_type, permissions_json,
                       repositories_count, suspended_at, created_at, updated_at
                FROM github_installations
                WHERE organization_id = %s AND installation_id = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, int(installation_id)),
            )
            return _row_to_installation_dict(cur.fetchone())


def _row_to_asset_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["repository_id"] = int(out.get("repository_id") or 0)
    except Exception:
        out["repository_id"] = 0
    out["metadata"] = _json_obj(out.pop("metadata_json", {}))
    out["repository_name"] = str(out.get("repository_name") or "")
    out["repository_html_url"] = str(out.get("repository_html_url") or "")
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    tags = out.get("tags") or []
    out["tags"] = [str(t) for t in tags if str(t or "").strip()]
    return out


def pg_get_asset(org_id: str, asset_key_str: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT a.asset_key, a.owner, a.team, a.environment, a.criticality, a.confidentiality_lifetime,
                       a.notes, a.metadata_json, a.repository_id, a.updated_at,
                       COALESCE(r.name, '') AS repository_name,
                       COALESCE(r.html_url, '') AS repository_html_url,
                       ARRAY(
                           SELECT t.tag
                           FROM asset_tags t
                           WHERE t.organization_id = a.organization_id AND t.asset_key = a.asset_key
                           ORDER BY t.tag
                       ) AS tags
                FROM assets a
                LEFT JOIN repositories r
                  ON r.organization_id = a.organization_id AND r.id = a.repository_id
                WHERE a.organization_id = %s AND a.asset_key = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )
            return _row_to_asset_dict(cur.fetchone())


def pg_upsert_asset(
    org_id: str,
    asset_key_str: str,
    owner: str = "",
    team: str = "",
    environment: str = "",
    criticality: str = "",
    confidentiality_lifetime: str = "",
    notes: str = "",
    tags: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    repository_id: Optional[int] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    existing = pg_get_asset(org_id, asset_key_str, dsn=dsn) or {}
    if repository_id is None:
        try:
            repository_id = int(existing.get("repository_id") or 0)
        except Exception:
            repository_id = 0
    if metadata is None or metadata == {}:
        metadata = existing.get("metadata") or {}
    clean_tags = sorted({str(t or "").strip() for t in (tags or []) if str(t or "").strip()})
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    organization_id, asset_key, owner, team, environment, criticality,
                    confidentiality_lifetime, notes, metadata_json, repository_id, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (organization_id, asset_key) DO UPDATE SET
                    owner = EXCLUDED.owner,
                    team = EXCLUDED.team,
                    environment = EXCLUDED.environment,
                    criticality = EXCLUDED.criticality,
                    confidentiality_lifetime = EXCLUDED.confidentiality_lifetime,
                    notes = EXCLUDED.notes,
                    metadata_json = EXCLUDED.metadata_json,
                    repository_id = EXCLUDED.repository_id,
                    updated_at = NOW()
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(asset_key_str or "").strip(),
                    str(owner or "").strip(),
                    str(team or "").strip(),
                    str(environment or "").strip(),
                    str(criticality or "").strip(),
                    str(confidentiality_lifetime or "").strip(),
                    str(notes or "").strip(),
                    Json(metadata or {}),
                    int(repository_id or 0),
                ),
            )
            cur.execute(
                "DELETE FROM asset_tags WHERE organization_id = %s AND asset_key = %s",
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )
            if clean_tags:
                execute_values(
                    cur,
                    "INSERT INTO asset_tags (organization_id, asset_key, tag) VALUES %s ON CONFLICT DO NOTHING",
                    [(str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip(), tag) for tag in clean_tags],
                )
        conn.commit()
    return pg_get_asset(org_id, asset_key_str, dsn=dsn) or {"asset_key": asset_key_str}


def pg_register_scanned_asset(org_id: str, asset_key_str: str, dsn: Optional[str] = None) -> None:
    """Create the inventory row for a scanned endpoint without touching customer-owned fields.

    pg_upsert_asset() overwrites owner/team/environment/criticality with its defaults, so using it
    from the scan path would erase the ownership a customer entered every time the endpoint was
    re-scanned. DO NOTHING on conflict also guarantees one asset row per host and port.
    """
    ensure_postgres_core_schema(dsn)
    ak = str(asset_key_str or "").strip()
    if not ak:
        return
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    organization_id, asset_key, owner, team, environment, criticality,
                    confidentiality_lifetime, notes, metadata_json, repository_id, updated_at
                ) VALUES (%s, %s, '', '', '', '', '', '', '{}'::jsonb, 0, NOW())
                ON CONFLICT (organization_id, asset_key) DO NOTHING
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, ak),
            )
        conn.commit()


def pg_list_assets(
    org_id: str,
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 2000,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    joins = ""
    clauses = ["a.organization_id = %s"]
    if tag:
        joins += " JOIN asset_tags tf ON tf.organization_id = a.organization_id AND tf.asset_key = a.asset_key"
        clauses.append("tf.tag = %s")
        params.append(str(tag))
    if owner not in (None, ""):
        clauses.append("a.owner = %s")
        params.append(owner)
    if team not in (None, ""):
        clauses.append("a.team = %s")
        params.append(team)
    if environment not in (None, ""):
        clauses.append("a.environment = %s")
        params.append(environment)
    if criticality not in (None, ""):
        clauses.append("a.criticality = %s")
        params.append(criticality)
    params.append(max(1, min(int(limit or 2000), 5000)))
    sql = f"""
        SELECT a.asset_key, a.owner, a.team, a.environment, a.criticality, a.confidentiality_lifetime,
               a.notes, a.metadata_json, a.repository_id, a.updated_at,
               COALESCE(r.name, '') AS repository_name,
               COALESCE(r.html_url, '') AS repository_html_url,
               ARRAY(
                   SELECT t.tag
                   FROM asset_tags t
                   WHERE t.organization_id = a.organization_id AND t.asset_key = a.asset_key
                   ORDER BY t.tag
               ) AS tags
        FROM assets a
        LEFT JOIN repositories r
          ON r.organization_id = a.organization_id AND r.id = a.repository_id
        {joins}
        WHERE {' AND '.join(clauses)}
        ORDER BY a.updated_at DESC
        LIMIT %s
    """
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_asset_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_list_tags(org_id: str, limit: int = 2000, dsn: Optional[str] = None) -> List[str]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT tag
                FROM asset_tags
                WHERE organization_id = %s
                ORDER BY tag
                LIMIT %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, max(1, min(int(limit or 2000), 5000))),
            )
            return [str(r[0]) for r in cur.fetchall()]


def pg_list_assets_by_repository(org_id: str, repo_id: int, limit: int = 5000, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT a.asset_key, a.owner, a.team, a.environment, a.criticality, a.confidentiality_lifetime,
                       a.notes, a.metadata_json, a.repository_id, a.updated_at,
                       COALESCE(r.name, '') AS repository_name,
                       COALESCE(r.html_url, '') AS repository_html_url,
                       ARRAY(
                           SELECT t.tag
                           FROM asset_tags t
                           WHERE t.organization_id = a.organization_id AND t.asset_key = a.asset_key
                           ORDER BY t.tag
                       ) AS tags
                FROM assets a
                LEFT JOIN repositories r
                  ON r.organization_id = a.organization_id AND r.id = a.repository_id
                WHERE a.organization_id = %s AND a.repository_id = %s
                ORDER BY a.updated_at DESC
                LIMIT %s
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    int(repo_id),
                    max(1, min(int(limit or 5000), 10000)),
                ),
            )
            return [_row_to_asset_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_link_asset_repository(org_id: str, asset_key_str: str, repository_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets
                SET repository_id = %s, updated_at = NOW()
                WHERE organization_id = %s AND asset_key = %s
                """,
                (int(repository_id or 0), str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )


def pg_set_asset_metadata(org_id: str, asset_key_str: str, metadata: Dict[str, Any], dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets
                SET metadata_json = %s, updated_at = NOW()
                WHERE organization_id = %s AND asset_key = %s
                """,
                (Json(metadata or {}), str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )


def pg_latest_scan_result_for_asset(org_id: str, asset_key_str: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       key_bits, key_curve, cipher_name, scan_status, key_exchange
                FROM scan_results
                WHERE organization_id = %s AND asset_key = %s
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )
            row = cur.fetchone()
            if not row:
                return None
            out = dict(row)
            out["scanned_at"] = _iso_utc(out.get("scanned_at"))
            try:
                out["findings_count"] = int(out.get("findings_count") or 0)
            except Exception:
                out["findings_count"] = 0
            return out


def pg_latest_scan_results_for_assets(
    org_id: str, asset_keys: Sequence[str], dsn: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """{asset_key: newest scan_results row} for many assets, in one query.

    The per-asset pg_latest_scan_result_for_asset above is correct but is called in a loop by the
    HNDL dashboard and timeline, once per asset. At 1000 assets that is 1000 sequential round
    trips, each borrowing a pooled connection, and GET /hndl/dashboard took over a minute on a
    tenant of that size while Postgres was idle between round trips. DISTINCT ON does the same
    work in one statement.
    """
    keys = [str(k).strip() for k in (asset_keys or []) if str(k or "").strip()]
    if not keys:
        return {}
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (asset_key)
                       asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       key_bits, key_curve, cipher_name, scan_status, key_exchange
                FROM scan_results
                WHERE organization_id = %s AND asset_key = ANY(%s)
                ORDER BY asset_key, scanned_at DESC
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, keys),
            )
            rows = _fetchall_dicts(cur)
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        item["scanned_at"] = _iso_utc(item.get("scanned_at"))
        try:
            item["findings_count"] = int(item.get("findings_count") or 0)
        except Exception:
            item["findings_count"] = 0
        out[str(item.get("asset_key") or "")] = item
    return out


def _like_contains(text: str) -> str:
    """A `LIKE ... ESCAPE '\\'` "contains" pattern in which the caller's %, _ and \\ stay literal."""
    escaped = str(text or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def pg_count_assets(org_id: str, dsn: Optional[str] = None) -> int:
    """How many assets this organization has, without listing them."""
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM assets WHERE organization_id = %s",
                        (str(org_id or "").strip() or DEFAULT_ORG_ID,))
            row = cur.fetchone()
    return int((row or [0])[0] or 0)


def pg_recent_scan_result_times(org_id: str, limit: int = 2000, dsn: Optional[str] = None) -> List[str]:
    """The newest scan_results.scanned_at values for one tenant, newest first, as ISO text."""
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT scanned_at FROM scan_results WHERE organization_id = %s "
                "ORDER BY scanned_at DESC LIMIT %s",
                (str(org_id or "").strip() or DEFAULT_ORG_ID, max(1, min(int(limit or 2000), 20000))),
            )
            rows = cur.fetchall()
    return [_iso_utc(r[0]) for r in rows if r and r[0]]


#: The columns the per-asset reporting facts are built from (see db._SCAN_FACT_COLUMNS).
_SCAN_FACT_COLUMNS = (
    "asset_key", "scan_id", "scanned_at", "risk_level", "quantum_score", "findings_count",
    "pqc_relevance", "tls_version", "key_type", "sig_algorithm",
    "owner", "team", "environment", "criticality",
    "key_bits", "key_curve", "cipher_name", "scan_status", "key_exchange",
)


def pg_latest_scan_facts_for_org(org_id: str, limit: int = 5000, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    """The newest scan_results row per asset for one tenant, newest scan first, in one statement.

    The caller used to read every scan result the tenant had ever recorded (up to 50,000 rows),
    de-duplicate to one row per asset in Python and sort them there, with the caller's own limit
    applied afterwards. DISTINCT ON does the de-duplication in the database and the outer LIMIT
    bounds the rows that ever become Python objects.
    """
    columns = ", ".join(_SCAN_FACT_COLUMNS)
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT {columns} FROM (
                    SELECT DISTINCT ON (asset_key) {columns}, id
                    FROM scan_results
                    WHERE organization_id = %s
                    ORDER BY asset_key, scanned_at DESC, id DESC
                ) newest
                ORDER BY scanned_at DESC
                LIMIT %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, max(1, min(int(limit or 5000), 50000))),
            )
            return [_row_to_scan_result_dict(r) or {} for r in _fetchall_dicts(cur)]


def _row_to_scan_row_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    out["id"] = str(out.get("id") or "")
    out["status"] = str(out.get("status") or "")
    out["created_at"] = _parse_iso_datetime(_iso_utc(out.get("created_at")))
    progress = _normalize_json_value(out.pop("progress_json", {}), {})
    results = _normalize_json_value(out.pop("results_json", []), [])
    summary = _normalize_json_value(out.pop("summary_json", {}), {})
    out["progress"] = progress if isinstance(progress, dict) else {}
    out["results"] = results if isinstance(results, list) else []
    out["summary"] = summary if isinstance(summary, dict) else {}
    out["error"] = str(out.pop("error_text", "") or "")
    out["job_id"] = str(out.get("job_id") or "")
    out["job_state"] = str(out.get("job_state") or "")
    out["job_started_at"] = _iso_utc(out.get("job_started_at"))
    out["job_finished_at"] = _iso_utc(out.get("job_finished_at"))
    return out


def pg_save_scan_row(
    org_id: str,
    scan_id: str,
    status: str,
    created_at: datetime,
    progress: Dict[str, Any],
    error_text: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (id, organization_id, status, created_at, progress_json, error_text, results_json, summary_json)
                VALUES (%s, %s, %s, %s::timestamptz, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    organization_id = EXCLUDED.organization_id,
                    status = EXCLUDED.status,
                    created_at = EXCLUDED.created_at,
                    progress_json = EXCLUDED.progress_json,
                    error_text = EXCLUDED.error_text,
                    results_json = EXCLUDED.results_json,
                    summary_json = EXCLUDED.summary_json
                """,
                (
                    str(scan_id or "").strip(),
                    str(org_id or "").strip(),
                    str(status or "").strip(),
                    _iso_utc(created_at),
                    Json(progress or {}),
                    str(error_text or ""),
                    Json(results or []),
                    Json(summary or {}),
                ),
            )


def _insert_scan_stub(
    cur,
    org_id: str,
    scan_id: str,
    *,
    status: str = "queued",
    progress: Optional[Dict[str, Any]] = None,
    error_text: str = "",
    results: Optional[List[Dict[str, Any]]] = None,
    summary: Optional[Dict[str, Any]] = None,
    job_id: str = "",
    job_state: str = "",
    job_started_at: Any = None,
    job_finished_at: Any = None,
    created_at: Any = None,
) -> None:
    cur.execute(
        """
        INSERT INTO scans (
            id, organization_id, status, created_at, progress_json, error_text, results_json, summary_json,
            job_id, job_state, job_started_at, job_finished_at
        )
        VALUES (%s, %s, %s, %s::timestamptz, %s, %s, %s, %s, %s, %s, %s::timestamptz, %s::timestamptz)
        ON CONFLICT (id) DO NOTHING
        """,
        (
            str(scan_id or "").strip(),
            str(org_id or "").strip(),
            str(status or "").strip() or "queued",
            _iso_utc(created_at) or _iso_utc(datetime.now(timezone.utc)),
            Json(progress or {}),
            str(error_text or ""),
            Json(results or []),
            Json(summary or {}),
            str(job_id or ""),
            str(job_state or ""),
            _iso_utc(job_started_at) or None,
            _iso_utc(job_finished_at) or None,
        ),
    )


def pg_update_scan_progress(
    org_id: str,
    scan_id: str,
    progress: Dict[str, Any],
    status: str = "running",
    error_text: str = "",
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s, progress_json = %s, error_text = %s
                WHERE organization_id = %s AND id = %s
                """,
                (
                    str(status or "").strip() or "running",
                    Json(progress or {}),
                    str(error_text or ""),
                    str(org_id or "").strip(),
                    str(scan_id or "").strip(),
                ),
            )
            if cur.rowcount == 0:
                logger.warning("scan row missing during progress update; inserting stub row for %s", scan_id)
                _insert_scan_stub(
                    cur,
                    org_id,
                    scan_id,
                    status=status or "running",
                    progress=progress,
                    error_text=error_text,
                )


def pg_save_scan_results(
    org_id: str,
    scan_id: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    status: str = "completed",
    error_text: str = "",
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s, error_text = %s, results_json = %s, summary_json = %s
                WHERE organization_id = %s AND id = %s
                """,
                (
                    str(status or "").strip() or "completed",
                    str(error_text or ""),
                    Json(results or []),
                    Json(summary or {}),
                    str(org_id or "").strip(),
                    str(scan_id or "").strip(),
                ),
            )
            if cur.rowcount == 0:
                logger.warning("scan row missing during results save; inserting stub row for %s", scan_id)
                _insert_scan_stub(
                    cur,
                    org_id,
                    scan_id,
                    status=status or "completed",
                    error_text=error_text,
                    results=results,
                    summary=summary,
                )


def pg_load_scan_row(org_id: str, scan_id: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, status, created_at, progress_json, error_text, results_json, summary_json,
                       job_id, job_state, job_started_at, job_finished_at
                FROM scans
                WHERE organization_id = %s AND id = %s
                """,
                (str(org_id or "").strip(), str(scan_id or "").strip()),
            )
            return _row_to_scan_row_dict(cur.fetchone())


def pg_count_scans(org_id: str, dsn: Optional[str] = None) -> int:
    """How many scans this organization has. Callers used to fetch up to 1000 rows and len() them."""
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM scans WHERE organization_id = %s",
                        (str(org_id or "").strip() or DEFAULT_ORG_ID,))
            row = cur.fetchone()
    return int((row or [0])[0] or 0)


def pg_list_scan_rows(org_id: str, limit: int = 20, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                -- results_json is deliberately absent: the loop below pops "results" from every
                -- row, so selecting it transferred and JSON-parsed one full result blob per scan
                -- to emit none of them. On a tenant with large scans that was the bulk of the
                -- cost of GET /scans.
                SELECT id, status, created_at, progress_json, error_text, summary_json,
                       job_id, job_state, job_started_at, job_finished_at
                FROM scans
                WHERE organization_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (str(org_id or "").strip(), max(1, min(int(limit or 20), 1000))),
            )
            rows = _fetchall_dicts(cur)
    out: List[Dict[str, Any]] = []
    for row in rows:
        item = _row_to_scan_row_dict(row) or {}
        item["created_at"] = _iso_utc(row.get("created_at"))
        item.pop("results", None)
        out.append(item)
    return out


def pg_update_scan_job(
    org_id: str,
    scan_id: str,
    job_id: str = "",
    job_state: str = "",
    started_at_iso: str = "",
    finished_at_iso: str = "",
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    sets: List[str] = []
    vals: List[Any] = []
    if job_id != "":
        sets.append("job_id = %s")
        vals.append(str(job_id))
    if job_state != "":
        sets.append("job_state = %s")
        vals.append(str(job_state))
    if started_at_iso != "":
        sets.append("job_started_at = %s::timestamptz")
        vals.append(str(started_at_iso))
    if finished_at_iso != "":
        sets.append("job_finished_at = %s::timestamptz")
        vals.append(str(finished_at_iso))
    if not sets:
        return
    vals.extend([str(org_id or "").strip(), str(scan_id or "").strip()])
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE scans SET {', '.join(sets)} WHERE organization_id = %s AND id = %s", vals)
            if cur.rowcount == 0:
                logger.warning("scan row missing during job update; inserting stub row for %s", scan_id)
                _insert_scan_stub(
                    cur,
                    org_id,
                    scan_id,
                    status="queued",
                    job_id=job_id,
                    job_state=job_state,
                    job_started_at=started_at_iso,
                    job_finished_at=finished_at_iso,
                )


def pg_set_baseline(
    org_id: str,
    asset_key_str: str,
    baseline_scan_id: str,
    set_at: Optional[datetime] = None,
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    when = set_at or datetime.now(timezone.utc)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO baselines (organization_id, asset_key, baseline_scan_id, set_at)
                VALUES (%s, %s, %s, %s::timestamptz)
                ON CONFLICT (organization_id, asset_key) DO UPDATE SET
                    baseline_scan_id = EXCLUDED.baseline_scan_id,
                    set_at = EXCLUDED.set_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(asset_key_str or "").strip(),
                    str(baseline_scan_id or "").strip(),
                    _iso_utc(when),
                ),
            )


def pg_get_baseline(org_id: str, asset_key_str: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT asset_key, baseline_scan_id, set_at
                FROM baselines
                WHERE organization_id = %s AND asset_key = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, str(asset_key_str or "").strip()),
            )
            row = cur.fetchone()
    if not row:
        return None
    out = dict(row)
    out["set_at"] = _iso_utc(out.get("set_at"))
    return out


def pg_list_baselines(org_id: str, limit: int = 500, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT asset_key, baseline_scan_id, set_at
                FROM baselines
                WHERE organization_id = %s
                ORDER BY set_at DESC
                LIMIT %s
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    max(1, min(int(limit or 500), 5000)),
                ),
            )
            rows = _fetchall_dicts(cur)
    out: List[Dict[str, Any]] = []
    for row in rows:
        row["set_at"] = _iso_utc(row.get("set_at"))
        out.append(row)
    return out


def _row_to_scan_result_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    out["asset_key"] = str(out.get("asset_key") or "")
    out["scan_id"] = str(out.get("scan_id") or "")
    out["scanned_at"] = _iso_utc(out.get("scanned_at"))
    out["risk_level"] = str(out.get("risk_level") or "")
    try:
        out["quantum_score"] = float(out.get("quantum_score") or 0.0)
    except Exception:
        out["quantum_score"] = 0.0
    try:
        out["findings_count"] = int(out.get("findings_count") or 0)
    except Exception:
        out["findings_count"] = 0
    for key in (
        "pqc_relevance",
        "tls_version",
        "key_type",
        "sig_algorithm",
        "owner",
        "team",
        "environment",
        "criticality",
        "repository_name",
        "repository_html_url",
    ):
        if key in out:
            out[key] = str(out.get(key) or "")
    if "repository_id" in out:
        try:
            out["repository_id"] = int(out.get("repository_id") or 0)
        except Exception:
            out["repository_id"] = 0
    return out


def pg_save_scan_asset_summaries(
    org_id: str,
    scan_id: str,
    scanned_at_iso: str,
    results: List[Dict[str, Any]],
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    org = str(org_id or "").strip() or DEFAULT_ORG_ID
    scanned_at = str(scanned_at_iso or "").strip() or _pg_now_iso()
    rows_to_insert: List[tuple[Any, ...]] = []
    asset_keys = []
    for item in results or []:
        host = str(item.get("host") or item.get("hostname") or "").strip()
        if not host:
            continue
        try:
            port = int(item.get("port") or 443)
        except Exception:
            port = 443
        asset_keys.append(f"{host}:{port}")
    asset_map: Dict[str, Dict[str, Any]] = {}
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if asset_keys:
                cur.execute(
                    """
                    SELECT asset_key, owner, team, environment, criticality
                    FROM assets
                    WHERE organization_id = %s AND asset_key = ANY(%s)
                    """,
                    (org, list(dict.fromkeys(asset_keys))),
                )
                asset_map = {str(r["asset_key"]): dict(r) for r in _fetchall_dicts(cur)}

                # A scanned endpoint is an asset. Nothing in the scan path registered one, so
                # /assets stayed empty after a scan and the HNDL dashboard reported $0 exposure
                # over zero assets. DO NOTHING on conflict: a re-scan must not overwrite the
                # owner, environment or criticality the customer set, and must not create a
                # second row for the same host and port.
                execute_values(
                    cur,
                    """
                    INSERT INTO assets (
                        organization_id, asset_key, owner, team, environment, criticality,
                        confidentiality_lifetime, notes, metadata_json, repository_id, updated_at
                    ) VALUES %s
                    ON CONFLICT (organization_id, asset_key) DO NOTHING
                    """,
                    [(org, ak) for ak in dict.fromkeys(asset_keys)],
                    template="(%s,%s,'','','','','','','{}'::jsonb,0,NOW())",
                )

            for item in results or []:
                host = str(item.get("host") or item.get("hostname") or "").strip()
                if not host:
                    continue
                try:
                    port = int(item.get("port") or 443)
                except Exception:
                    port = 443
                asset_key_str = f"{host}:{port}"
                findings = item.get("findings") or []
                asset_row = asset_map.get(asset_key_str) or {}
                observed = scan_result_observation(item)
                rows_to_insert.append(
                    (
                        org,
                        asset_key_str,
                        str(scan_id or "").strip(),
                        scanned_at,
                        str(item.get("risk") or item.get("risk_level") or "unknown"),
                        float(item.get("quantum_risk_score") or item.get("quantum_score") or item.get("score") or 0.0),
                        len(findings) if isinstance(findings, list) else 0,
                        str(item.get("pqc_relevance") or ""),
                        str(item.get("tls_version") or ""),
                        str(item.get("key_type") or ""),
                        str(item.get("sig_algorithm") or ""),
                        str(asset_row.get("owner") or ""),
                        str(asset_row.get("team") or ""),
                        str(asset_row.get("environment") or ""),
                        str(asset_row.get("criticality") or ""),
                        observed["key_bits"],
                        observed["key_curve"],
                        observed["cipher_name"],
                        observed["scan_status"],
                        observed["key_exchange"],
                    )
                )
            if rows_to_insert:
                execute_values(
                    cur,
                    """
                    INSERT INTO scan_results (
                        organization_id, asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                        pqc_relevance, tls_version, key_type, sig_algorithm,
                        owner, team, environment, criticality,
                        key_bits, key_curve, cipher_name, scan_status, key_exchange
                    ) VALUES %s
                    """,
                    rows_to_insert,
                    template="(%s,%s,%s,%s::timestamptz,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                )


def pg_get_asset_history(org_id: str, asset_key_str: str, limit: int = 50, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT scanned_at, scan_id, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       owner, team, environment, criticality,
                       key_bits, key_curve, cipher_name, scan_status, key_exchange
                FROM scan_results
                WHERE organization_id = %s AND asset_key = %s
                ORDER BY scanned_at DESC
                LIMIT %s
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(asset_key_str or "").strip(),
                    max(1, min(int(limit or 50), 200)),
                ),
            )
            return [_row_to_scan_result_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_list_scan_results(
    org_id: str,
    scan_id: str,
    owner: str = "",
    team: str = "",
    environment: str = "",
    criticality: str = "",
    limit: int = 5000,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    clauses = ["sr.organization_id = %s", "sr.scan_id = %s"]
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID, str(scan_id or "").strip()]
    owner = str(owner or "").strip()
    team = str(team or "").strip()
    environment = str(environment or "").strip()
    criticality = str(criticality or "").strip()
    if owner:
        clauses.append("sr.owner = %s")
        params.append(owner)
    if team:
        clauses.append("sr.team = %s")
        params.append(team)
    if environment:
        clauses.append("sr.environment = %s")
        params.append(environment)
    if criticality:
        clauses.append("sr.criticality = %s")
        params.append(criticality)
    params.append(max(1, min(int(limit or 5000), 20000)))
    where = " AND ".join(clauses)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT sr.asset_key, sr.scan_id, sr.scanned_at, sr.risk_level, sr.quantum_score, sr.findings_count,
                       sr.pqc_relevance, sr.tls_version, sr.key_type, sr.sig_algorithm,
                       sr.owner, sr.team, sr.environment, sr.criticality,
                       sr.key_bits, sr.key_curve, sr.cipher_name, sr.scan_status, sr.key_exchange,
                       COALESCE(a.repository_id, 0) AS repository_id,
                       COALESCE(r.name, '') AS repository_name,
                       COALESCE(r.html_url, '') AS repository_html_url
                FROM scan_results sr
                LEFT JOIN assets a
                  ON a.organization_id = sr.organization_id AND a.asset_key = sr.asset_key
                LEFT JOIN repositories r
                  ON r.organization_id = sr.organization_id AND r.id = a.repository_id
                WHERE {where}
                ORDER BY sr.quantum_score DESC, sr.findings_count DESC
                LIMIT %s
                """,
                params,
            )
            return [_row_to_scan_result_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_list_scan_results_since(
    org_id: str,
    since_iso: str,
    limit: int = 200000,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       owner, team, environment, criticality,
                       key_bits, key_curve, cipher_name, scan_status, key_exchange
                FROM scan_results
                WHERE organization_id = %s AND scanned_at >= %s::timestamptz
                ORDER BY scanned_at ASC
                LIMIT %s
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(since_iso or "").strip(),
                    max(1, min(int(limit or 200000), 400000)),
                ),
            )
            return [_row_to_scan_result_dict(r) or {} for r in _fetchall_dicts(cur)]


def _row_to_validation_job_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    try:
        out["remediation_id"] = int(out.get("remediation_id") or 0)
    except Exception:
        out["remediation_id"] = 0
    try:
        raw_exit_code = out.get("exit_code")
        out["exit_code"] = -1 if raw_exit_code in (None, "") else int(raw_exit_code)
    except Exception:
        out["exit_code"] = -1
    out["details"] = out.pop("details_json", {}) or {}
    out["created_at"] = _iso_utc(out.get("created_at"))
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    out["finished_at"] = _iso_utc(out.get("finished_at"))
    return out


def pg_create_validation_job(
    org_id: str,
    remediation_id: int,
    validator_type: str = "auto",
    git_ref: str = "",
    status: str = "queued",
    job_id: str = "",
    details: Optional[Dict[str, Any]] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO validation_jobs (
                    organization_id, remediation_id, validator_type, status, git_ref, job_id,
                    stdout, stderr, exit_code, details_json, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, '', '', -1, %s, NOW(), NOW())
                RETURNING id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                          stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    int(remediation_id),
                    str(validator_type or "auto").strip().lower() or "auto",
                    str(status or "queued").strip().lower() or "queued",
                    str(git_ref or "").strip(),
                    str(job_id or "").strip(),
                    Json(details or {}),
                ),
            )
            return _row_to_validation_job_dict(cur.fetchone()) or {"remediation_id": int(remediation_id)}


def pg_get_validation_job(org_id: str, validation_job_id: int, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
                       stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
                FROM validation_jobs
                WHERE organization_id = %s AND id = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, int(validation_job_id)),
            )
            return _row_to_validation_job_dict(cur.fetchone())


def pg_list_validation_jobs(
    org_id: str,
    remediation_id: Optional[int] = None,
    status: str = "",
    limit: int = 200,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    clauses = ["organization_id = %s"]
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    if remediation_id is not None:
        clauses.append("remediation_id = %s")
        params.append(int(remediation_id))
    if str(status or "").strip():
        clauses.append("status = %s")
        params.append(str(status or "").strip().lower())
    params.append(max(1, min(int(limit or 200), 2000)))
    sql = f"""
        SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
               stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
        FROM validation_jobs
        WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
    """
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_validation_job_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_get_latest_validation_job_for_remediation(
    org_id: str,
    remediation_id: int,
    passed_only: bool = False,
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    sql = """
        SELECT id, organization_id, remediation_id, validator_type, status, git_ref, job_id,
               stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at
        FROM validation_jobs
        WHERE organization_id = %s AND remediation_id = %s
    """
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID, int(remediation_id)]
    if passed_only:
        sql += " AND status = 'passed'"
    sql += " ORDER BY created_at DESC, id DESC LIMIT 1"
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return _row_to_validation_job_dict(cur.fetchone())


def pg_update_validation_job(
    org_id: str,
    validation_job_id: int,
    *,
    status: Optional[str] = None,
    validator_type: Optional[str] = None,
    git_ref: Optional[str] = None,
    job_id: Optional[str] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    exit_code: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    finished: Optional[bool] = None,
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    sets: List[str] = ["updated_at = NOW()"]
    params: List[Any] = []
    if status is not None:
        sets.append("status = %s")
        params.append(str(status or "").strip().lower())
    if validator_type is not None:
        sets.append("validator_type = %s")
        params.append(str(validator_type or "").strip().lower() or "auto")
    if git_ref is not None:
        sets.append("git_ref = %s")
        params.append(str(git_ref or "").strip())
    if job_id is not None:
        sets.append("job_id = %s")
        params.append(str(job_id or "").strip())
    if stdout is not None:
        sets.append("stdout = %s")
        params.append(str(stdout or ""))
    if stderr is not None:
        sets.append("stderr = %s")
        params.append(str(stderr or ""))
    if exit_code is not None:
        sets.append("exit_code = %s")
        params.append(int(exit_code))
    if details is not None:
        sets.append("details_json = %s")
        params.append(Json(details or {}))
    if finished is True:
        sets.append("finished_at = NOW()")
    elif finished is False:
        sets.append("finished_at = NULL")
    if len(sets) == 1:
        return pg_get_validation_job(org_id, validation_job_id, dsn=dsn)
    params.extend([str(org_id or "").strip() or DEFAULT_ORG_ID, int(validation_job_id)])
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE validation_jobs SET {', '.join(sets)} WHERE organization_id = %s AND id = %s",
                params,
            )
    return pg_get_validation_job(org_id, validation_job_id, dsn=dsn)


def _row_to_remediation_dict(row: Optional[Dict[str, Any]], dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    try:
        out["repo_id"] = int(out.get("repo_id") or 0)
    except Exception:
        out["repo_id"] = 0
    try:
        out["github_credential_id"] = int(out.get("github_credential_id") or 0)
    except Exception:
        out["github_credential_id"] = 0
    try:
        out["branch_cleanup_attempts"] = int(out.get("branch_cleanup_attempts") or 0)
    except Exception:
        out["branch_cleanup_attempts"] = 0
    try:
        out["parent_remediation_id"] = int(out.get("parent_remediation_id") or 0)
    except Exception:
        out["parent_remediation_id"] = 0
    try:
        out["drift_followup_remediation_id"] = int(out.get("drift_followup_remediation_id") or 0)
    except Exception:
        out["drift_followup_remediation_id"] = 0
    out["origin_kind"] = str(out.get("origin_kind") or "").strip().lower()
    repo = pg_get_repository_by_id(str(out.get("organization_id") or DEFAULT_ORG_ID), out["repo_id"], dsn=dsn) if out["repo_id"] else None
    out["repository_name"] = (repo or {}).get("name", "")
    out["repository_html_url"] = (repo or {}).get("html_url", "")
    out["drift_status"] = str(out.get("drift_status") or "").strip().lower()
    out["drift_details"] = _normalize_json_value(out.pop("drift_details_json", {}), {})
    out["merged_at"] = _iso_utc(out.get("merged_at"))
    out["closed_at"] = _iso_utc(out.get("closed_at"))
    out["branch_cleanup_at"] = _iso_utc(out.get("branch_cleanup_at"))
    out["last_drift_checked_at"] = _iso_utc(out.get("last_drift_checked_at"))
    out["drift_detected_at"] = _iso_utc(out.get("drift_detected_at"))
    out["drift_acknowledged_at"] = _iso_utc(out.get("drift_acknowledged_at"))
    out["drift_acknowledged_by"] = str(out.get("drift_acknowledged_by") or "").strip()
    out["drift_ack_note"] = str(out.get("drift_ack_note") or "").strip()
    out["created_at"] = _iso_utc(out.get("created_at"))
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    return out


def pg_create_remediation(
    org_id: str,
    asset_key_str: str,
    repo_id: int,
    file_path: str,
    vulnerability: str,
    suggested_fix: str,
    original_content: str = "",
    suggested_content: str = "",
    status: str = "pending",
    review_note: str = "",
    parent_remediation_id: int = 0,
    origin_kind: str = "",
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO remediations (
                    organization_id, asset_key, repo_id, vulnerability, file_path, original_content,
                    suggested_fix, suggested_content, status, pr_url, review_note,
                    verification_scan_id, parent_remediation_id, origin_kind, drift_followup_remediation_id,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, '', %s, '', %s, %s, 0, NOW(), NOW())
                RETURNING id, organization_id, asset_key, repo_id, vulnerability, file_path, original_content,
                          suggested_fix, suggested_content, status, pr_url, pr_branch, pr_base_branch,
                          github_credential_id, branch_cleanup_status, branch_cleanup_at,
                          branch_cleanup_error, branch_cleanup_attempts, review_note, merged_at,
                          verification_scan_id, closed_at, parent_remediation_id, origin_kind, drift_followup_remediation_id,
                          drift_status, last_drift_checked_at, drift_detected_at, drift_acknowledged_at,
                          drift_acknowledged_by, drift_ack_note, drift_details_json, created_at, updated_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(asset_key_str or "").strip(),
                    int(repo_id or 0),
                    str(vulnerability or "").strip(),
                    str(file_path or "").strip(),
                    str(original_content or ""),
                    str(suggested_fix or ""),
                    str(suggested_content or ""),
                    str(status or "pending").strip().lower() or "pending",
                    str(review_note or ""),
                    int(parent_remediation_id or 0),
                    str(origin_kind or "").strip().lower(),
                ),
            )
            return _row_to_remediation_dict(cur.fetchone(), dsn=dsn) or {"asset_key": asset_key_str}


def pg_get_remediation(org_id: str, remediation_id: int, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, organization_id, asset_key, repo_id, vulnerability, file_path, original_content,
                       suggested_fix, suggested_content, status, pr_url, pr_branch, pr_base_branch,
                       github_credential_id, branch_cleanup_status, branch_cleanup_at,
                       branch_cleanup_error, branch_cleanup_attempts, review_note, merged_at,
                       verification_scan_id, closed_at, parent_remediation_id, origin_kind, drift_followup_remediation_id,
                       drift_status, last_drift_checked_at, drift_detected_at,
                       drift_acknowledged_at, drift_acknowledged_by, drift_ack_note, drift_details_json, created_at, updated_at
                FROM remediations
                WHERE organization_id = %s AND id = %s
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID, int(remediation_id)),
            )
            return _row_to_remediation_dict(cur.fetchone(), dsn=dsn)


def pg_list_remediations(
    org_id: str,
    status: str = "",
    repo_id: Optional[int] = None,
    asset_key_str: str = "",
    drift_status: str = "",
    parent_remediation_id: Optional[int] = None,
    origin_kind: str = "",
    text_query: str = "",
    limit: int = 200,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    clauses = ["organization_id = %s"]
    if str(status or "").strip():
        clauses.append("status = %s")
        params.append(str(status or "").strip().lower())
    if repo_id is not None:
        clauses.append("repo_id = %s")
        params.append(int(repo_id))
    if str(asset_key_str or "").strip():
        clauses.append("asset_key = %s")
        params.append(str(asset_key_str or "").strip())
    if str(drift_status or "").strip():
        clauses.append("drift_status = %s")
        params.append(str(drift_status or "").strip().lower())
    if parent_remediation_id is not None:
        clauses.append("parent_remediation_id = %s")
        params.append(int(parent_remediation_id))
    if str(origin_kind or "").strip():
        clauses.append("origin_kind = %s")
        params.append(str(origin_kind or "").strip().lower())
    text_query = str(text_query or "").strip().lower()
    if text_query:
        # Free-text filter for the in-app search. LIKE on a lowered column, with the wildcards
        # supplied here so a '%' or '_' the operator types stays literal.
        pattern = _like_contains(text_query)
        clauses.append(
            "(LOWER(vulnerability) LIKE %s ESCAPE '\\' OR LOWER(suggested_fix) LIKE %s ESCAPE '\\' "
            "OR LOWER(asset_key) LIKE %s ESCAPE '\\' OR LOWER(status) LIKE %s ESCAPE '\\')"
        )
        params.extend([pattern] * 4)
    params.append(max(1, min(int(limit or 200), 2000)))
    sql = f"""
        SELECT id, organization_id, asset_key, repo_id, vulnerability, file_path, original_content,
               suggested_fix, suggested_content, status, pr_url, pr_branch, pr_base_branch,
               github_credential_id, branch_cleanup_status, branch_cleanup_at,
               branch_cleanup_error, branch_cleanup_attempts, review_note, merged_at,
               verification_scan_id, closed_at, parent_remediation_id, origin_kind, drift_followup_remediation_id,
               drift_status, last_drift_checked_at, drift_detected_at,
               drift_acknowledged_at, drift_acknowledged_by, drift_ack_note, drift_details_json, created_at, updated_at
        FROM remediations
        WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
    """
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_remediation_dict(r, dsn=dsn) or {} for r in _fetchall_dicts(cur)]


def _row_to_migration_task_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    for key in ("id", "repo_id"):
        try:
            out[key] = int(out.get(key) or 0)
        except Exception:
            out[key] = 0
    out["status"] = str(out.get("status") or "open").strip().lower() or "open"
    out["safety_class"] = str(out.get("safety_class") or "migration_task").strip().lower()
    out["confidence"] = str(out.get("confidence") or "medium").strip().lower()
    out["created_at"] = _iso_utc(out.get("created_at"))
    out["updated_at"] = _iso_utc(out.get("updated_at"))
    return out


def pg_create_migration_task(
    org_id: str,
    asset_key_str: str = "",
    repository_name: str = "",
    repo_id: int = 0,
    file_path: str = "",
    rule_id: str = "",
    legacy_dependency: str = "",
    migration_target: str = "",
    safety_class: str = "migration_task",
    confidence: str = "medium",
    safety_reason: str = "",
    recommended_workflow: str = "",
    status: str = "open",
    source: str = "repo_crypto_discovery",
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO migration_tasks (
                    organization_id, asset_key, repository_name, repo_id, file_path, rule_id,
                    legacy_dependency, migration_target, safety_class, confidence, safety_reason,
                    recommended_workflow, status, source, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                RETURNING id, organization_id, asset_key, repository_name, repo_id, file_path, rule_id,
                          legacy_dependency, migration_target, safety_class, confidence, safety_reason,
                          recommended_workflow, status, source, created_at, updated_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(asset_key_str or "").strip(),
                    str(repository_name or "").strip(),
                    int(repo_id or 0),
                    str(file_path or "").strip(),
                    str(rule_id or "").strip(),
                    str(legacy_dependency or "").strip(),
                    str(migration_target or "").strip(),
                    str(safety_class or "migration_task").strip().lower() or "migration_task",
                    str(confidence or "medium").strip().lower() or "medium",
                    str(safety_reason or "").strip(),
                    str(recommended_workflow or "").strip(),
                    str(status or "open").strip().lower() or "open",
                    str(source or "repo_crypto_discovery").strip().lower() or "repo_crypto_discovery",
                ),
            )
            return _row_to_migration_task_dict(cur.fetchone()) or {}


def pg_list_migration_tasks(
    org_id: str,
    status: str = "",
    asset_key_str: str = "",
    repository_name: str = "",
    limit: int = 200,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    clauses = ["organization_id = %s"]
    if str(status or "").strip():
        clauses.append("status = %s")
        params.append(str(status or "").strip().lower())
    if str(asset_key_str or "").strip():
        clauses.append("asset_key = %s")
        params.append(str(asset_key_str or "").strip())
    if str(repository_name or "").strip():
        clauses.append("repository_name = %s")
        params.append(str(repository_name or "").strip())
    params.append(max(1, min(int(limit or 200), 2000)))
    sql = f"""
        SELECT id, organization_id, asset_key, repository_name, repo_id, file_path, rule_id,
               legacy_dependency, migration_target, safety_class, confidence, safety_reason,
               recommended_workflow, status, source, created_at, updated_at
        FROM migration_tasks
        WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
    """
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_migration_task_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_update_migration_task_status(
    org_id: str,
    task_id: int,
    status: str,
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    clean = str(status or "open").strip().lower() or "open"
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE migration_tasks
                SET status = %s, updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                RETURNING id, organization_id, asset_key, repository_name, repo_id, file_path, rule_id,
                          legacy_dependency, migration_target, safety_class, confidence, safety_reason,
                          recommended_workflow, status, source, created_at, updated_at
                """,
                (clean, str(org_id or "").strip() or DEFAULT_ORG_ID, int(task_id)),
            )
            return _row_to_migration_task_dict(cur.fetchone())


def pg_update_remediation_status(
    org_id: str,
    remediation_id: int,
    status: str,
    review_note: str = "",
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET status = %s, review_note = %s, updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (
                    str(status or "pending").strip().lower() or "pending",
                    str(review_note or ""),
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    int(remediation_id),
                ),
            )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_set_remediation_pr(
    org_id: str,
    remediation_id: int,
    pr_url: str,
    status: str = "pr_created",
    branch: str = "",
    base_branch: str = "",
    github_credential_id: int = 0,
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET pr_url = %s,
                    pr_branch = %s,
                    pr_base_branch = %s,
                    github_credential_id = %s,
                    branch_cleanup_status = '',
                    branch_cleanup_at = NULL,
                    branch_cleanup_error = '',
                    branch_cleanup_attempts = 0,
                    status = %s,
                    updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (
                    str(pr_url or "").strip(),
                    str(branch or "").strip(),
                    str(base_branch or "").strip(),
                    int(github_credential_id or 0),
                    str(status or "pr_created").strip().lower(),
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    int(remediation_id),
                ),
            )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_update_remediation_branch_cleanup(
    org_id: str,
    remediation_id: int,
    status: str,
    error: str = "",
    cleanup_at_iso: str = "",
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    cleanup_at = str(cleanup_at_iso or "").strip()
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            if cleanup_at:
                cur.execute(
                    """
                    UPDATE remediations
                    SET branch_cleanup_status = %s,
                        branch_cleanup_at = %s::timestamptz,
                        branch_cleanup_error = %s,
                        branch_cleanup_attempts = branch_cleanup_attempts + 1,
                        updated_at = NOW()
                    WHERE organization_id = %s AND id = %s
                    """,
                    (
                        str(status or "").strip().lower(),
                        cleanup_at,
                        str(error or "")[:2000],
                        str(org_id or "").strip() or DEFAULT_ORG_ID,
                        int(remediation_id),
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE remediations
                    SET branch_cleanup_status = %s,
                        branch_cleanup_at = NOW(),
                        branch_cleanup_error = %s,
                        branch_cleanup_attempts = branch_cleanup_attempts + 1,
                        updated_at = NOW()
                    WHERE organization_id = %s AND id = %s
                    """,
                    (
                        str(status or "").strip().lower(),
                        str(error or "")[:2000],
                        str(org_id or "").strip() or DEFAULT_ORG_ID,
                        int(remediation_id),
                    ),
                )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_mark_remediation_merged(
    org_id: str,
    remediation_id: int,
    merged_at_iso: str = "",
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    merged_at = str(merged_at_iso or "").strip()
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET status = 'merged',
                    merged_at = COALESCE(NULLIF(%s, '')::timestamptz, NOW()),
                    drift_acknowledged_at = NULL,
                    drift_acknowledged_by = '',
                    drift_ack_note = '',
                    drift_status = '',
                    last_drift_checked_at = NULL,
                    drift_detected_at = NULL,
                    drift_details_json = '{}'::jsonb,
                    updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (merged_at, str(org_id or "").strip() or DEFAULT_ORG_ID, int(remediation_id)),
            )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_mark_remediation_merged_by_pr_url(
    pr_url: str,
    merged_at_iso: str = "",
    organization_id: Optional[str] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(organization_id or "").strip()
    pr_url = str(pr_url or "").strip()
    if not pr_url:
        return {"matched": 0, "updated": 0, "already_merged": 0, "remediation_ids": []}
    matched = 0
    updated = 0
    already_merged = 0
    remediation_ids: List[int] = []
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if org_id:
                cur.execute(
                    "SELECT id, status, organization_id FROM remediations WHERE organization_id = %s AND pr_url = %s",
                    (org_id, pr_url),
                )
            else:
                cur.execute(
                    "SELECT id, status, organization_id FROM remediations WHERE pr_url = %s",
                    (pr_url,),
                )
            rows = _fetchall_dicts(cur)
            matched = len(rows)
            for row in rows:
                rid = int(row.get("id") or 0)
                remediation_ids.append(rid)
                status = str(row.get("status") or "").strip().lower()
                row_org_id = str(row.get("organization_id") or DEFAULT_ORG_ID)
                if status in ("merged", "verified_closed"):
                    already_merged += 1
                    continue
                cur.execute(
                    """
                    UPDATE remediations
                    SET status = 'merged',
                        merged_at = COALESCE(NULLIF(%s, '')::timestamptz, NOW()),
                        drift_acknowledged_at = NULL,
                        drift_acknowledged_by = '',
                        drift_ack_note = '',
                        drift_status = '',
                        last_drift_checked_at = NULL,
                        drift_detected_at = NULL,
                        drift_details_json = '{}'::jsonb,
                        updated_at = NOW()
                    WHERE organization_id = %s AND id = %s
                    """,
                    (str(merged_at_iso or "").strip(), row_org_id, rid),
                )
                updated += 1
    return {
        "matched": matched,
        "updated": updated,
        "already_merged": already_merged,
        "remediation_ids": remediation_ids,
    }


def pg_update_remediation_status_by_pr_url(
    pr_url: str,
    status: str,
    review_note: str = "",
    organization_id: Optional[str] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(organization_id or "").strip()
    pr_url = str(pr_url or "").strip()
    next_status = str(status or "").strip().lower()
    if not pr_url or not next_status:
        return {"matched": 0, "updated": 0, "already": 0, "remediation_ids": []}
    matched = 0
    updated = 0
    already = 0
    remediation_ids: List[int] = []
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if org_id:
                cur.execute(
                    "SELECT id, status, organization_id FROM remediations WHERE organization_id = %s AND pr_url = %s",
                    (org_id, pr_url),
                )
            else:
                cur.execute("SELECT id, status, organization_id FROM remediations WHERE pr_url = %s", (pr_url,))
            rows = _fetchall_dicts(cur)
            matched = len(rows)
            for row in rows:
                rid = int(row.get("id") or 0)
                remediation_ids.append(rid)
                current_status = str(row.get("status") or "").strip().lower()
                row_org_id = str(row.get("organization_id") or DEFAULT_ORG_ID)
                if current_status == next_status:
                    already += 1
                    continue
                if current_status == "verified_closed" and next_status not in {"verified_closed"}:
                    already += 1
                    continue
                cur.execute(
                    """
                    UPDATE remediations
                    SET status = %s,
                        review_note = CASE WHEN %s = '' THEN review_note ELSE %s END,
                        updated_at = NOW()
                    WHERE organization_id = %s AND id = %s
                    """,
                    (next_status, str(review_note or ""), str(review_note or ""), row_org_id, rid),
                )
                updated += 1
    return {"matched": matched, "updated": updated, "already": already, "remediation_ids": remediation_ids}


def pg_update_remediation_drift_state(
    org_id: str,
    remediation_id: int,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    checked_at_iso: str = "",
    detected_at_iso: str = "",
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    drift_status = str(status or "").strip().lower()
    checked_at = str(checked_at_iso or "").strip()
    detected_at = str(detected_at_iso or "").strip()
    if drift_status == "drifted" and not detected_at:
        detected_at = checked_at or _pg_now_iso()
    if drift_status != "drifted":
        detected_at = ""
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET drift_status = %s,
                    last_drift_checked_at = COALESCE(NULLIF(%s, '')::timestamptz, NOW()),
                    drift_detected_at = NULLIF(%s, '')::timestamptz,
                    drift_details_json = %s,
                    updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (
                    drift_status,
                    checked_at,
                    detected_at,
                    Json(details or {}),
                    org_id,
                    int(remediation_id),
                ),
            )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_set_remediation_drift_followup(
    org_id: str,
    parent_remediation_id: int,
    followup_remediation_id: int,
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET drift_followup_remediation_id = %s,
                    updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (int(followup_remediation_id or 0), org_id, int(parent_remediation_id)),
            )
    return pg_get_remediation(org_id, parent_remediation_id, dsn=dsn)


def pg_acknowledge_remediation_drift(
    org_id: str,
    remediation_id: int,
    actor_id: str,
    note: str = "",
    dsn: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE remediations
                SET drift_acknowledged_at = NOW(),
                    drift_acknowledged_by = %s,
                    drift_ack_note = %s,
                    updated_at = NOW()
                WHERE organization_id = %s AND id = %s
                """,
                (
                    str(actor_id or "").strip(),
                    str(note or ""),
                    org_id,
                    int(remediation_id),
                ),
            )
    return pg_get_remediation(org_id, remediation_id, dsn=dsn)


def pg_auto_close_merged_remediations(
    org_id: str,
    scan_id: str,
    results: List[Dict[str, Any]],
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    closed = 0
    assets_checked = 0
    scan_id = str(scan_id or "")
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            for item in results or []:
                host = str(item.get("host") or item.get("hostname") or "").strip()
                if not host:
                    continue
                port = int(item.get("port") or 443)
                asset_key_str = f"{host}:{port}"
                assets_checked += 1
                risk = str(item.get("risk") or item.get("risk_level") or item.get("quantum_risk_level") or "").strip().lower()
                findings = item.get("findings") or []
                findings_count = len(findings) if isinstance(findings, list) else int(item.get("findings_count") or 0)
                passed = findings_count == 0 or risk in ("none", "ok", "pass", "info", "low")
                if not passed:
                    continue
                cur.execute(
                    """
                    SELECT COUNT(1)
                    FROM remediations
                    WHERE organization_id = %s AND asset_key = %s AND status = 'merged'
                    """,
                    (str(org_id or "").strip() or DEFAULT_ORG_ID, asset_key_str),
                )
                row = cur.fetchone()
                to_close = int((row or [0])[0] or 0)
                if to_close <= 0:
                    continue
                cur.execute(
                    """
                    UPDATE remediations
                    SET status = 'verified_closed',
                        verification_scan_id = %s,
                        closed_at = NOW(),
                        updated_at = NOW()
                    WHERE organization_id = %s AND asset_key = %s AND status = 'merged'
                    """,
                    (scan_id, str(org_id or "").strip() or DEFAULT_ORG_ID, asset_key_str),
                )
                closed += to_close
    return {"scan_id": scan_id, "assets_checked": assets_checked, "closed": closed}


def _compute_audit_entry_hash(
    prev_hash: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    decision: str,
    reason: str,
    details_json: str,
    created_at: str,
) -> str:
    payload = "|".join(
        [
            str(prev_hash or ""),
            str(actor_id or ""),
            str(actor_role or ""),
            str(action or ""),
            str(resource_type or ""),
            str(resource_id or ""),
            str(decision or ""),
            str(reason or ""),
            str(details_json or "{}"),
            str(created_at or ""),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def pg_append_audit_log(
    org_id: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str = "",
    decision: str = "allow",
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    created_at = _iso_utc(datetime.now(timezone.utc))
    details_json = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # The chain is a read-modify-write: read the newest entry_hash, hash it into this
            # entry, insert. Two concurrent requests for the same tenant used to read the same
            # prev_hash and fork the chain, so verification failed on a perfectly honest log. The
            # advisory lock serializes appends per tenant across every replica, and is released
            # when this transaction commits.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                        ("pqc_audit_chain:" + (str(org_id or "").strip() or DEFAULT_ORG_ID),))
            cur.execute(
                """
                SELECT entry_hash
                FROM audit_logs
                WHERE organization_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (str(org_id or "").strip() or DEFAULT_ORG_ID,),
            )
            prev = cur.fetchone()
            prev_hash = str((prev or {}).get("entry_hash") or "")
            entry_hash = _compute_audit_entry_hash(
                prev_hash=prev_hash,
                actor_id=actor_id,
                actor_role=actor_role,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                decision=decision,
                reason=reason,
                details_json=details_json,
                created_at=created_at,
            )
            cur.execute(
                """
                INSERT INTO audit_logs (
                    organization_id, actor_id, actor_role, action, resource_type, resource_id, decision,
                    reason, details_json, prev_hash, entry_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, organization_id, actor_id, actor_role, action, resource_type, resource_id,
                          decision, reason, details_json, prev_hash, entry_hash, created_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(actor_id or "").strip(),
                    str(actor_role or "").strip().lower(),
                    str(action or "").strip(),
                    str(resource_type or "").strip(),
                    str(resource_id or "").strip(),
                    str(decision or "allow").strip().lower(),
                    str(reason or "").strip(),
                    Json(details or {}),
                    prev_hash,
                    entry_hash,
                    created_at,
                ),
            )
            row = dict(cur.fetchone() or {})
    if not row:
        return {"id": 0}
    row["details_json"] = json.dumps(_json_obj(row.get("details_json")), separators=(",", ":"), sort_keys=True)
    row["created_at"] = _iso_utc(row.get("created_at"))
    try:
        row["id"] = int(row.get("id") or 0)
    except Exception:
        row["id"] = 0
    return row


def pg_list_audit_logs(
    org_id: str,
    limit: int = 200,
    actor_id: str = "",
    action: str = "",
    decision: str = "",
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    clauses = ["organization_id = %s"]
    if str(actor_id or "").strip():
        clauses.append("actor_id = %s")
        params.append(str(actor_id or "").strip())
    if str(action or "").strip():
        clauses.append("action = %s")
        params.append(str(action or "").strip())
    if str(decision or "").strip():
        clauses.append("decision = %s")
        params.append(str(decision or "").strip().lower())
    params.append(max(1, min(int(limit or 200), 2000)))
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT id, organization_id, actor_id, actor_role, action, resource_type, resource_id,
                       decision, reason, details_json, prev_hash, entry_hash, created_at
                FROM audit_logs
                WHERE {' AND '.join(clauses)}
                ORDER BY id DESC
                LIMIT %s
                """,
                params,
            )
            rows = _fetchall_dicts(cur)
    out: List[Dict[str, Any]] = []
    for row in rows:
        row["details_json"] = json.dumps(_json_obj(row.get("details_json")), separators=(",", ":"), sort_keys=True)
        row["created_at"] = _iso_utc(row.get("created_at"))
        try:
            row["id"] = int(row.get("id") or 0)
        except Exception:
            row["id"] = 0
        out.append(row)
    return out


def _normalize_flight_event(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row or {})
    out["evidence_refs_json"] = json.dumps(_json_obj(out.get("evidence_refs_json")), separators=(",", ":"), sort_keys=True)
    out["details_json"] = json.dumps(_json_obj(out.get("details_json")), separators=(",", ":"), sort_keys=True)
    out["created_at"] = _iso_utc(out.get("created_at"))
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    return out


def pg_append_flight_recorder_event(
    org_id: str,
    *,
    actor_type: str,
    actor_id: str,
    actor_role: str,
    intent: str,
    resource_type: str,
    resource_id: str = "",
    policy_version: str = "",
    decision: str = "allowed",
    outcome: str = "pending",
    reason: str = "",
    evidence_refs: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    created_at = _iso_utc(datetime.now(timezone.utc))
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO flight_recorder_events (
                    organization_id, actor_type, actor_id, actor_role, intent, resource_type, resource_id,
                    policy_version, decision, outcome, reason, evidence_refs_json, details_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, organization_id, actor_type, actor_id, actor_role, intent, resource_type,
                          resource_id, policy_version, decision, outcome, reason, evidence_refs_json,
                          details_json, created_at
                """,
                (
                    str(org_id or "").strip() or DEFAULT_ORG_ID,
                    str(actor_type or "human").strip().lower() or "human",
                    str(actor_id or "").strip(),
                    str(actor_role or "").strip().lower(),
                    str(intent or "").strip(),
                    str(resource_type or "").strip(),
                    str(resource_id or "").strip(),
                    str(policy_version or "").strip(),
                    str(decision or "allowed").strip().lower(),
                    str(outcome or "pending").strip().lower(),
                    str(reason or "").strip(),
                    Json(evidence_refs or {}),
                    Json(details or {}),
                    created_at,
                ),
            )
            row = dict(cur.fetchone() or {})
    if not row:
        return {"id": 0}
    normalized = _normalize_flight_event(row)
    normalized["evidence_refs"] = _json_obj(normalized.pop("evidence_refs_json", "{}"))
    normalized["details"] = _json_obj(normalized.pop("details_json", "{}"))
    return normalized


def pg_list_flight_recorder_events(
    org_id: str,
    *,
    limit: int = 200,
    intent: str = "",
    resource_type: str = "",
    resource_id: str = "",
    decision: str = "",
    actor_id: str = "",
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    params: List[Any] = [str(org_id or "").strip() or DEFAULT_ORG_ID]
    clauses = ["organization_id = %s"]
    filters = {
        "intent": str(intent or "").strip(),
        "resource_type": str(resource_type or "").strip(),
        "resource_id": str(resource_id or "").strip(),
        "decision": str(decision or "").strip().lower(),
        "actor_id": str(actor_id or "").strip(),
    }
    for key, value in filters.items():
        if value:
            clauses.append(f"{key} = %s")
            params.append(value)
    params.append(max(1, min(int(limit or 200), 2000)))
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT id, organization_id, actor_type, actor_id, actor_role, intent, resource_type,
                       resource_id, policy_version, decision, outcome, reason, evidence_refs_json,
                       details_json, created_at
                FROM flight_recorder_events
                WHERE {' AND '.join(clauses)}
                ORDER BY id DESC
                LIMIT %s
                """,
                params,
            )
            rows = _fetchall_dicts(cur)
    out: List[Dict[str, Any]] = []
    for row in rows:
        normalized = _normalize_flight_event(row)
        normalized["evidence_refs"] = _json_obj(normalized.pop("evidence_refs_json", "{}"))
        normalized["details"] = _json_obj(normalized.pop("details_json", "{}"))
        out.append(normalized)
    return out


def _pg_now_iso() -> str:
    return _iso_utc(datetime.now(timezone.utc))


def _row_to_webhook_dict(row: Optional[Dict[str, Any]], include_secret: bool = False) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    cred = out.get("credential_id")
    try:
        out["credential_id"] = int(cred) if cred is not None else None
    except Exception:
        out["credential_id"] = None
    out["events"] = _normalize_json_value(out.pop("events_json", []), [])
    out["enabled"] = bool(int(out.get("enabled") or 0))
    out["created_at"] = str(out.get("created_at") or "")
    out["updated_at"] = str(out.get("updated_at") or "")
    try:
        out["rate_limit_per_minute"] = int(out.get("rate_limit_per_minute") or 60)
    except Exception:
        out["rate_limit_per_minute"] = 60
    try:
        out["timeout_seconds"] = int(out.get("timeout_seconds") or 10)
    except Exception:
        out["timeout_seconds"] = 10
    out["secret"] = str(out.get("secret") or "") if include_secret else ""
    return out


def _row_to_webhook_event_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    for key in ("id", "webhook_id", "http_status", "attempts"):
        try:
            out[key] = int(out.get(key) or 0)
        except Exception:
            out[key] = 0
    out["payload"] = _normalize_json_value(out.pop("payload_json", {}), {})
    for key in ("created_at", "last_attempt_at", "next_attempt_at", "claimed_at", "claimed_by"):
        out[key] = str(out.get(key) or "")
    out["status"] = str(out.get("status") or "")
    out["error_text"] = str(out.get("error_text") or "")
    out["response_excerpt"] = str(out.get("response_excerpt") or "")
    out["event_type"] = str(out.get("event_type") or "")
    out["dedupe_key"] = str(out.get("dedupe_key") or "")
    return out


def pg_list_webhooks(org_id: str, limit: int = 200, include_secret: bool = False, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at,
                    rate_limit_per_minute, timeout_seconds
                FROM webhooks
                WHERE organization_id = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (str(org_id or "").strip(), max(1, min(int(limit or 200), 500))),
            )
            return [_row_to_webhook_dict(r, include_secret=include_secret) or {} for r in _fetchall_dicts(cur)]


def pg_list_webhooks_public(org_id: str, limit: int = 200, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in pg_list_webhooks(org_id, limit=limit, include_secret=True, dsn=dsn):
        secret = str(row.pop("secret", "") or "")
        row["has_secret"] = bool(secret)
        row["secret_masked"] = "********" if secret else ""
        row["secret"] = None
        out.append(row)
    return out


def pg_upsert_webhook(
    org_id: str,
    name: str,
    url: str,
    secret: str = "",
    credential_id: Optional[int] = None,
    events: Optional[List[str]] = None,
    enabled: bool = True,
    webhook_id: Optional[int] = None,
    rate_limit_per_minute: int = 60,
    timeout_seconds: int = 10,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    name = str(name or "").strip()
    url = str(url or "").strip()
    if not name:
        raise ValueError("name is required")
    if not url:
        raise ValueError("url is required")
    ev = ["*"] if events is None else [str(x) for x in (events or [])]
    try:
        rate_limit_per_minute = max(1, int(rate_limit_per_minute or 60))
    except Exception:
        rate_limit_per_minute = 60
    try:
        timeout_seconds = max(1, int(timeout_seconds or 10))
    except Exception:
        timeout_seconds = 10
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if webhook_id:
                cur.execute(
                    """
                    UPDATE webhooks
                    SET name=%s, url=%s, secret=%s, credential_id=%s, events_json=%s, enabled=%s, updated_at=%s,
                        rate_limit_per_minute=%s, timeout_seconds=%s
                    WHERE organization_id=%s AND id=%s
                    RETURNING id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at,
                        rate_limit_per_minute, timeout_seconds
                    """,
                    (
                        name,
                        url,
                        str(secret or ""),
                        int(credential_id) if credential_id is not None else None,
                        Json(ev),
                        1 if enabled else 0,
                        now,
                        rate_limit_per_minute,
                        timeout_seconds,
                        str(org_id or "").strip(),
                        int(webhook_id),
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO webhooks(organization_id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at, rate_limit_per_minute, timeout_seconds)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(organization_id, name) DO UPDATE SET
                        url=EXCLUDED.url,
                        secret=EXCLUDED.secret,
                        credential_id=EXCLUDED.credential_id,
                        events_json=EXCLUDED.events_json,
                        enabled=EXCLUDED.enabled,
                        updated_at=EXCLUDED.updated_at,
                        rate_limit_per_minute=EXCLUDED.rate_limit_per_minute,
                        timeout_seconds=EXCLUDED.timeout_seconds
                    RETURNING id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at,
                        rate_limit_per_minute, timeout_seconds
                    """,
                    (
                        str(org_id or "").strip(),
                        name,
                        url,
                        str(secret or ""),
                        int(credential_id) if credential_id is not None else None,
                        Json(ev),
                        1 if enabled else 0,
                        now,
                        now,
                        rate_limit_per_minute,
                        timeout_seconds,
                    ),
                )
            row = cur.fetchone()
    if not row:
        raise RuntimeError("failed to upsert webhook")
    return _row_to_webhook_dict(row, include_secret=True) or {"name": name, "url": url}


def pg_delete_webhook(org_id: str, webhook_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM webhooks WHERE organization_id=%s AND id=%s", (str(org_id or "").strip(), int(webhook_id)))


def pg_get_webhook_public(org_id: str, webhook_id: int, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at,
                    rate_limit_per_minute, timeout_seconds
                FROM webhooks
                WHERE organization_id=%s AND id=%s
                """,
                (str(org_id or "").strip(), int(webhook_id)),
            )
            row = cur.fetchone()
    if not row:
        return None
    out = _row_to_webhook_dict(row, include_secret=True) or {}
    secret = str(out.pop("secret", "") or "")
    out["has_secret"] = bool(secret)
    out["secret_masked"] = "********" if secret else ""
    out["secret"] = None
    return out


def pg_rotate_webhook_secret(org_id: str, webhook_id: int, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    new_secret = os.urandom(32).hex()
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE webhooks
                SET secret=%s, updated_at=%s
                WHERE organization_id=%s AND id=%s
                RETURNING id, name, url, secret, credential_id, events_json, enabled, created_at, updated_at
                """,
                (new_secret, now, str(org_id or "").strip(), int(webhook_id)),
            )
            row = cur.fetchone()
    if not row:
        return {"ok": True}
    out = _row_to_webhook_dict(row, include_secret=True) or {}
    secret = str(out.pop("secret", "") or "")
    out["has_secret"] = bool(secret)
    out["secret_masked"] = "********" if secret else ""
    out["secret"] = None
    return out


def pg_record_webhook_event(
    org_id: str,
    webhook_id: int,
    event_type: str,
    dedupe_key: str,
    payload: Dict[str, Any],
    status: str = "queued",
    http_status: int = 0,
    error_text: str = "",
    max_attempts: int = 5,
    dsn: Optional[str] = None,
) -> Optional[int]:
    ensure_postgres_core_schema(dsn)
    payload_obj = payload or {}
    payload_json = Json(payload_obj)
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, status, attempts
                FROM webhook_events
                WHERE organization_id=%s AND webhook_id=%s AND dedupe_key=%s
                """,
                (str(org_id or "").strip(), int(webhook_id), str(dedupe_key)),
            )
            existing = cur.fetchone()
            if existing:
                existing_status = str(existing.get("status") or "")
                attempts = int(existing.get("attempts") or 0)
                if existing_status == "sent" or attempts >= int(max_attempts):
                    return None
                cur.execute(
                    """
                    UPDATE webhook_events
                    SET payload_json=%s, status=%s, http_status=%s, error_text=%s,
                        next_attempt_at='', response_excerpt=''
                    WHERE id=%s
                    """,
                    (payload_json, str(status), int(http_status), str(error_text or ""), int(existing["id"])),
                )
                return int(existing["id"])

            cur.execute(
                """
                INSERT INTO webhook_events(
                    organization_id, webhook_id, created_at, event_type, dedupe_key, payload_json, status,
                    http_status, error_text, response_excerpt, attempts, last_attempt_at,
                    next_attempt_at, claimed_at, claimed_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, '', 0, '', '', '', '')
                RETURNING id
                """,
                (
                    str(org_id or "").strip(),
                    int(webhook_id),
                    now,
                    str(event_type or ""),
                    str(dedupe_key),
                    payload_json,
                    str(status or "queued"),
                    int(http_status),
                    str(error_text or ""),
                ),
            )
            row = cur.fetchone()
            return int((row or {}).get("id") or 0) or None


def pg_bump_webhook_attempt(org_id: str, event_row_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE webhook_events
                SET attempts = attempts + 1, last_attempt_at=%s
                WHERE organization_id=%s AND id=%s
                """,
                (_pg_now_iso(), str(org_id or "").strip(), int(event_row_id)),
            )


def pg_update_webhook_event(
    org_id: str,
    event_row_id: int,
    status: str,
    http_status: int = 0,
    error_text: str = "",
    response_excerpt: str = "",
    next_attempt_at: str = "",
    dsn: Optional[str] = None,
) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE webhook_events
                SET status=%s,
                    http_status=%s,
                    error_text=%s,
                    response_excerpt=%s,
                    next_attempt_at=%s
                WHERE organization_id=%s AND id=%s
                """,
                (
                    str(status),
                    int(http_status),
                    str(error_text or ""),
                    str(response_excerpt or ""),
                    str(next_attempt_at or ""),
                    str(org_id or "").strip(),
                    int(event_row_id),
                ),
            )


def pg_list_webhook_events(org_id: str, limit: int = 50, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, webhook_id, created_at, event_type, dedupe_key, status, http_status,
                       error_text, response_excerpt, attempts, last_attempt_at, next_attempt_at,
                       payload_json, claimed_at, claimed_by
                FROM webhook_events
                WHERE organization_id=%s
                ORDER BY id DESC
                LIMIT %s
                """,
                (str(org_id or "").strip(), max(1, min(int(limit or 50), 500))),
            )
            return [_row_to_webhook_event_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_list_pending_webhook_events(org_id: str, limit: int = 100, max_attempts: int = 5, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, webhook_id, created_at, event_type, dedupe_key, status, http_status,
                       error_text, response_excerpt, attempts, last_attempt_at, next_attempt_at,
                       payload_json, claimed_at, claimed_by
                FROM webhook_events
                WHERE organization_id=%s
                  AND status IN ('queued', 'failed', '')
                  AND attempts < %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (str(org_id or "").strip(), int(max_attempts), max(1, min(int(limit or 100), 500))),
            )
            return [_row_to_webhook_event_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_list_due_webhook_events(
    org_id: str,
    limit: int = 100,
    max_attempts: int = 5,
    now_iso: Optional[str] = None,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    current = str(now_iso or _pg_now_iso())
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, webhook_id, created_at, event_type, dedupe_key, status, http_status,
                       error_text, response_excerpt, attempts, last_attempt_at, next_attempt_at,
                       payload_json, claimed_at, claimed_by
                FROM webhook_events
                WHERE organization_id=%s
                  AND status IN ('queued', 'failed', '')
                  AND attempts < %s
                  AND (next_attempt_at = '' OR next_attempt_at <= %s)
                ORDER BY id ASC
                LIMIT %s
                """,
                (str(org_id or "").strip(), int(max_attempts), current, max(1, min(int(limit or 100), 500))),
            )
            return [_row_to_webhook_event_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_claim_due_webhook_events(
    org_id: str,
    limit: int = 100,
    max_attempts: int = 5,
    now_iso: Optional[str] = None,
    worker_id: Optional[str] = None,
    lease_seconds: int = 600,
    dsn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    current = str(now_iso or _pg_now_iso())
    worker = str(worker_id or f"{socket.gethostname()}:{os.getpid()}")
    stale_before = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - max(1, int(lease_seconds))))
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE webhook_events
                SET status='queued', claimed_at='', claimed_by=''
                WHERE status='processing'
                  AND organization_id=%s
                  AND claimed_at != ''
                  AND substr(claimed_at, 1, 20) < %s
                """,
                (str(org_id or "").strip(), stale_before),
            )
            cur.execute(
                """
                WITH due AS (
                    SELECT id
                    FROM webhook_events
                    WHERE organization_id=%s
                      AND status IN ('queued', 'failed')
                      AND COALESCE(attempts, 0) < %s
                      AND (COALESCE(next_attempt_at, '') = '' OR COALESCE(next_attempt_at, '') <= %s)
                    ORDER BY id ASC
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE webhook_events w
                SET status='processing', claimed_at=%s, claimed_by=%s
                FROM due
                WHERE w.id = due.id
                RETURNING w.id, w.webhook_id, w.created_at, w.event_type, w.dedupe_key, w.status,
                          w.http_status, w.error_text, w.response_excerpt, w.attempts,
                          w.last_attempt_at, w.next_attempt_at, w.payload_json, w.claimed_at, w.claimed_by
                """,
                (
                    str(org_id or "").strip(),
                    int(max_attempts),
                    current,
                    max(1, min(int(limit or 100), 500)),
                    current,
                    worker,
                ),
            )
            return [_row_to_webhook_event_dict(r) or {} for r in _fetchall_dicts(cur)]


def _parse_iso_datetime(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.utcfromtimestamp(0)
    s = str(dt_str).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return datetime.utcfromtimestamp(0)


def _row_to_collection_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    try:
        out["id"] = int(out.get("id") or 0)
    except Exception:
        out["id"] = 0
    return out


def pg_upsert_collection(org_id: str, name: str, targets_text: str, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    name = str(name or "").strip()
    targets_text = str(targets_text or "").strip()
    if not name:
        raise ValueError("collection name is required")
    if not targets_text:
        raise ValueError("targets_text is required")
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO collections(organization_id, name, targets_text, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT(organization_id, name) DO UPDATE SET
                    targets_text=EXCLUDED.targets_text,
                    updated_at=EXCLUDED.updated_at
                RETURNING id, organization_id, name, targets_text, created_at, updated_at
                """,
                (org_id, name, targets_text, now, now),
            )
            return _row_to_collection_dict(cur.fetchone()) or {"name": name, "targets_text": targets_text}


def pg_list_collections(org_id: str, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, organization_id, name, targets_text, created_at, updated_at FROM collections WHERE organization_id=%s ORDER BY name ASC",
                (org_id,),
            )
            return [_row_to_collection_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_get_collection(org_id: str, collection_id: int, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, organization_id, name, targets_text, created_at, updated_at FROM collections WHERE organization_id=%s AND id=%s",
                (org_id, int(collection_id)),
            )
            row = cur.fetchone()
    if not row:
        raise KeyError("collection not found")
    return _row_to_collection_dict(row) or {"id": int(collection_id)}


def pg_delete_collection(org_id: str, collection_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM collections WHERE organization_id=%s AND id=%s", (org_id, int(collection_id)))


def _row_to_schedule_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    out = dict(row)
    for key in ("id", "collection_id", "enabled", "interval_minutes"):
        try:
            out[key] = int(out.get(key) or 0)
        except Exception:
            out[key] = 0
    out["enabled"] = bool(out["enabled"])
    for key in ("created_at", "updated_at", "last_run_at", "next_run_at", "last_scan_id", "collection_name"):
        if key in out:
            out[key] = str(out.get(key) or "")
    return out


def pg_create_schedule(org_id: str, collection_id: int, interval_minutes: int, enabled: bool = True, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    interval_minutes = int(interval_minutes)
    if interval_minutes <= 0:
        raise ValueError("interval_minutes must be > 0")
    now = _pg_now_iso()
    next_dt = _parse_iso_datetime(now) + timedelta(minutes=interval_minutes)
    next_run = next_dt.isoformat() + ("Z" if not next_dt.isoformat().endswith("Z") else "")
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM collections WHERE organization_id=%s AND id=%s", (org_id, int(collection_id)))
            if not cur.fetchone():
                raise KeyError("collection not found")
            cur.execute(
                """
                INSERT INTO schedules(organization_id, collection_id, enabled, interval_minutes, created_at, updated_at, last_run_at, next_run_at, last_scan_id)
                VALUES (%s, %s, %s, %s, %s, %s, '', %s, '')
                RETURNING id
                """,
                (org_id, int(collection_id), 1 if enabled else 0, interval_minutes, now, now, next_run),
            )
            row = cur.fetchone()
    return pg_get_schedule(org_id, int((row or {}).get("id") or 0), dsn=dsn)


def pg_list_schedules(org_id: str, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT s.id, s.organization_id, s.collection_id, c.name AS collection_name, s.enabled, s.interval_minutes,
                       s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
                FROM schedules s
                JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
                WHERE s.organization_id = %s
                ORDER BY s.id DESC
                """,
                (org_id,),
            )
            return [_row_to_schedule_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_get_schedule(org_id: str, schedule_id: int, dsn: Optional[str] = None) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT s.id, s.organization_id, s.collection_id, c.name AS collection_name, s.enabled, s.interval_minutes,
                       s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
                FROM schedules s
                JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
                WHERE s.organization_id = %s AND s.id = %s
                """,
                (org_id, int(schedule_id)),
            )
            row = cur.fetchone()
    if not row:
        raise KeyError("schedule not found")
    return _row_to_schedule_dict(row) or {"id": int(schedule_id)}


def pg_update_schedule(
    org_id: str,
    schedule_id: int,
    interval_minutes: Optional[int] = None,
    enabled: Optional[bool] = None,
    dsn: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT interval_minutes, enabled FROM schedules WHERE organization_id=%s AND id=%s", (org_id, int(schedule_id)))
            row = cur.fetchone()
            if not row:
                raise KeyError("schedule not found")
            new_interval = int(interval_minutes) if interval_minutes is not None else int(row.get("interval_minutes") or 0)
            if new_interval <= 0:
                raise ValueError("interval_minutes must be > 0")
            new_enabled = 1 if enabled else 0 if enabled is not None else int(row.get("enabled") or 0)
            next_dt = _parse_iso_datetime(now) + timedelta(minutes=new_interval)
            next_run = next_dt.isoformat() + ("Z" if not next_dt.isoformat().endswith("Z") else "")
            cur.execute(
                """
                UPDATE schedules
                SET enabled=%s, interval_minutes=%s, updated_at=%s, next_run_at=%s
                WHERE organization_id=%s AND id=%s
                """,
                (new_enabled, new_interval, now, next_run, org_id, int(schedule_id)),
            )
    return pg_get_schedule(org_id, int(schedule_id), dsn=dsn)


def pg_delete_schedule(org_id: str, schedule_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM schedules WHERE organization_id=%s AND id=%s", (org_id, int(schedule_id)))


def pg_due_schedules(org_id: str, now_iso: str, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT s.id, s.organization_id, s.collection_id, c.name AS collection_name, s.enabled, s.interval_minutes,
                       s.last_run_at, s.next_run_at, s.last_scan_id
                FROM schedules s
                JOIN collections c ON c.id = s.collection_id AND c.organization_id = s.organization_id
                WHERE s.organization_id=%s AND s.enabled=1 AND s.next_run_at <> '' AND s.next_run_at <= %s
                ORDER BY s.next_run_at ASC
                """,
                (org_id, str(now_iso or "")),
            )
            return [_row_to_schedule_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_mark_schedule_ran(org_id: str, schedule_id: int, run_at_iso: str, interval_minutes: int, last_scan_id: str, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    org_id = str(org_id or "").strip() or DEFAULT_ORG_ID
    run_dt = _parse_iso_datetime(str(run_at_iso or ""))
    next_dt = run_dt + timedelta(minutes=int(interval_minutes))
    next_run = next_dt.isoformat() + ("Z" if not next_dt.isoformat().endswith("Z") else "")
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE schedules
                SET last_run_at=%s, next_run_at=%s, last_scan_id=%s, updated_at=%s
                WHERE organization_id=%s AND id=%s
                """,
                (str(run_at_iso or ""), next_run, str(last_scan_id or ""), _pg_now_iso(), org_id, int(schedule_id)),
            )


def pg_get_integration_setting(key: str, default: str = "", dsn: Optional[str] = None) -> str:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM integrations_settings WHERE key=%s", (str(key or ""),))
            row = cur.fetchone()
            return str(row[0]) if row else str(default)


def pg_set_integration_setting(key: str, value: str, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO integrations_settings(key, value) VALUES(%s, %s)
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value
                """,
                (str(key or ""), str(value)),
            )


def _json_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    try:
        obj = json.loads(s)
        if isinstance(obj, list):
            return [str(x) for x in obj if str(x).strip()]
    except Exception:
        pass
    return [x.strip() for x in s.split(",") if x.strip()]


def _row_to_event_rule_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    d = dict(row)
    for key in ("id", "enabled", "cooldown_minutes"):
        if key in d:
            try:
                d[key] = int(d.get(key) or 0)
            except Exception:
                d[key] = 0
    d["enabled"] = bool(int(d.get("enabled") or 0))
    for k in ("webhook_ids_json", "event_types_json", "rule_ids_json", "environments_json", "teams_json", "criticalities_json", "tags_json"):
        if k in d:
            d[k[:-5]] = _normalize_json_value(d.get(k), [])
            d.pop(k, None)
    return d


def pg_get_event_rule_fire(org_id: str, rule_id: int, fingerprint: str, dsn: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT rule_id, fingerprint, last_fired_at FROM event_rule_fires WHERE organization_id=%s AND rule_id=%s AND fingerprint=%s",
                (str(org_id or "").strip(), int(rule_id), str(fingerprint)),
            )
            row = cur.fetchone()
    return dict(row) if row else None


def pg_upsert_event_rule_fire(org_id: str, rule_id: int, fingerprint: str, fired_at_iso: str, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO event_rule_fires(organization_id, rule_id, fingerprint, last_fired_at) VALUES (%s, %s, %s, %s)
                ON CONFLICT(organization_id, rule_id, fingerprint) DO UPDATE SET last_fired_at=EXCLUDED.last_fired_at
                """,
                (str(org_id or "").strip(), int(rule_id), str(fingerprint), str(fired_at_iso)),
            )


def pg_should_fire_event_rule(
    org_id: str,
    rule_id: int,
    fingerprint: str,
    cooldown_minutes: int,
    fire_mode: str,
    dsn: Optional[str] = None,
) -> bool:
    mode = str(fire_mode or "always").strip().lower()
    if mode == "always":
        return True
    now = datetime.now(timezone.utc)
    rec = pg_get_event_rule_fire(org_id, int(rule_id), str(fingerprint), dsn=dsn)
    if not rec:
        pg_upsert_event_rule_fire(org_id, int(rule_id), str(fingerprint), now.isoformat().replace("+00:00", "Z"), dsn=dsn)
        return True
    cd = int(cooldown_minutes or 0)
    if cd <= 0:
        return False
    last = _parse_iso_datetime(str(rec.get("last_fired_at") or "")).replace(tzinfo=timezone.utc)
    if (now - last).total_seconds() >= cd * 60:
        pg_upsert_event_rule_fire(org_id, int(rule_id), str(fingerprint), now.isoformat().replace("+00:00", "Z"), dsn=dsn)
        return True
    return False


def pg_list_event_rules(org_id: str, limit: int = 200, dsn: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, name, enabled, webhook_ids_json, event_types_json,
                       min_severity, rule_ids_json, quantum_score_min,
                       environments_json, teams_json, criticalities_json, tags_json,
                       cooldown_minutes, fire_mode, created_at, updated_at
                FROM event_rules
                WHERE organization_id=%s
                ORDER BY id DESC
                LIMIT %s
                """,
                (str(org_id or "").strip(), max(1, min(int(limit or 200), 1000))),
            )
            return [_row_to_event_rule_dict(r) or {} for r in _fetchall_dicts(cur)]


def pg_upsert_event_rule(
    *,
    org_id: str,
    name: str,
    webhook_ids: List[int],
    event_types: List[str],
    enabled: bool = True,
    min_severity: str = "",
    rule_ids: Optional[List[str]] = None,
    quantum_score_min: float = -1,
    environments: Optional[List[str]] = None,
    teams: Optional[List[str]] = None,
    criticalities: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    cooldown_minutes: int = 0,
    rule_id: Optional[int] = None,
    dsn: Optional[str] = None,
    **_extra: Any,
) -> Dict[str, Any]:
    ensure_postgres_core_schema(dsn)
    name = str(name or "").strip()
    if not name:
        raise ValueError("rule name is required")
    webhook_ids = [int(x) for x in (webhook_ids or [])]
    if not webhook_ids:
        raise ValueError("select at least one destination webhook")
    event_types = ["*"] if event_types is None else _json_list(event_types)
    min_severity = str(min_severity or "").strip().lower()
    if min_severity and min_severity not in ("low", "medium", "high", "critical"):
        raise ValueError("min_severity must be one of: low, medium, high, critical")
    rule_ids = _json_list(rule_ids)
    environments = _json_list(environments)
    teams = _json_list(teams)
    criticalities = _json_list(criticalities)
    tags = _json_list(tags)
    try:
        quantum_score_min = float(quantum_score_min)
    except Exception:
        quantum_score_min = -1
    try:
        cooldown_minutes = int(cooldown_minutes or 0)
    except Exception:
        cooldown_minutes = 0
    cooldown_minutes = max(0, min(60 * 24 * 30, cooldown_minutes))
    now = _pg_now_iso()
    with pg_product_conn(dsn) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if rule_id is not None:
                cur.execute(
                    """
                    UPDATE event_rules
                    SET name=%s, enabled=%s, webhook_ids_json=%s, event_types_json=%s,
                        min_severity=%s, rule_ids_json=%s, quantum_score_min=%s,
                        environments_json=%s, teams_json=%s, criticalities_json=%s, tags_json=%s,
                        cooldown_minutes=%s, fire_mode=%s, updated_at=%s
                    WHERE organization_id=%s AND id=%s
                    RETURNING id, name, enabled, webhook_ids_json, event_types_json,
                              min_severity, rule_ids_json, quantum_score_min,
                              environments_json, teams_json, criticalities_json, tags_json,
                              cooldown_minutes, fire_mode, created_at, updated_at
                    """,
                    (
                        name,
                        1 if enabled else 0,
                        Json(webhook_ids),
                        Json(event_types),
                        min_severity,
                        Json(rule_ids),
                        float(quantum_score_min),
                        Json(environments),
                        Json(teams),
                        Json(criticalities),
                        Json(tags),
                        int(cooldown_minutes),
                        str(_extra.get("fire_mode") or "always").strip().lower() or "always",
                        now,
                        str(org_id or "").strip(),
                        int(rule_id),
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO event_rules(
                        organization_id, name, enabled, webhook_ids_json, event_types_json,
                        min_severity, rule_ids_json, quantum_score_min,
                        environments_json, teams_json, criticalities_json, tags_json,
                        cooldown_minutes, fire_mode, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, name, enabled, webhook_ids_json, event_types_json,
                              min_severity, rule_ids_json, quantum_score_min,
                              environments_json, teams_json, criticalities_json, tags_json,
                              cooldown_minutes, fire_mode, created_at, updated_at
                    """,
                    (
                        str(org_id or "").strip(),
                        name,
                        1 if enabled else 0,
                        Json(webhook_ids),
                        Json(event_types),
                        min_severity,
                        Json(rule_ids),
                        float(quantum_score_min),
                        Json(environments),
                        Json(teams),
                        Json(criticalities),
                        Json(tags),
                        int(cooldown_minutes),
                        str(_extra.get("fire_mode") or "always").strip().lower() or "always",
                        now,
                        now,
                    ),
                )
            row = cur.fetchone()
    return _row_to_event_rule_dict(row) or {"name": name}


def pg_delete_event_rule(org_id: str, rule_id: int, dsn: Optional[str] = None) -> None:
    ensure_postgres_core_schema(dsn)
    with pg_product_conn(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM event_rules WHERE organization_id=%s AND id=%s", (str(org_id or "").strip(), int(rule_id)))
            cur.execute("DELETE FROM event_rule_fires WHERE organization_id=%s AND rule_id=%s", (str(org_id or "").strip(), int(rule_id)))

def _sqlite_table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return []
    return [str(r[1]) for r in rows]


def _normalize_json_value(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return json.loads(text)
        except Exception:
            return default
    return default


def _normalize_row(spec: TableSpec, row: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(row)
    if "organization_id" in spec.columns:
        data["organization_id"] = str(data.get("organization_id") or "").strip() or DEFAULT_ORG_ID

    for col in spec.integer_columns:
        if col not in data:
            continue
        raw = data.get(col)
        if raw in (None, ""):
            data[col] = 0
            continue
        try:
            data[col] = int(raw)
        except Exception:
            data[col] = 0

    for col, default in spec.json_defaults.items():
        if col in data:
            data[col] = _normalize_json_value(data.get(col), default)

    for col in spec.timestamp_columns:
        if col not in data:
            continue
        raw = data.get(col)
        if raw in (None, ""):
            data[col] = None
        else:
            data[col] = str(raw)

    return data


def _build_upsert_sql(spec: TableSpec) -> str:
    cols = ", ".join(spec.columns)
    if spec.conflict_target:
        target = ", ".join(spec.conflict_target)
        if spec.update_columns:
            updates = ", ".join(f"{col}=EXCLUDED.{col}" for col in spec.update_columns)
            conflict_clause = f"ON CONFLICT ({target}) DO UPDATE SET {updates}"
        else:
            conflict_clause = f"ON CONFLICT ({target}) DO NOTHING"
    else:
        conflict_clause = ""
    return f"INSERT INTO {spec.name} ({cols}) VALUES %s {conflict_clause}"


def _reset_sequence(cur, table: str, column: str) -> None:
    cur.execute(
        f"""
        SELECT setval(
            pg_get_serial_sequence(%s, %s),
            GREATEST(COALESCE((SELECT MAX({column}) FROM {table}), 0), 1),
            true
        )
        """,
        (table, column),
    )


def migrate_sqlite_core_to_postgres(
    sqlite_path: str,
    dsn: Optional[str] = None,
    batch_size: int = 500,
) -> Dict[str, Any]:
    sqlite_path = str(sqlite_path or "").strip()
    if not sqlite_path:
        raise ValueError("sqlite_path is required")
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")

    ensure_postgres_core_schema(dsn)

    stats: Dict[str, Any] = {"sqlite_path": sqlite_path, "tables": {}, "copied": 0}
    with sqlite3.connect(sqlite_path) as src, pg_product_conn(dsn) as dest:
        src.row_factory = sqlite3.Row
        with dest.cursor() as cur:
            for spec in CORE_TABLE_SPECS:
                sqlite_cols = _sqlite_table_columns(src, spec.name)
                cols = [c for c in spec.columns if c in sqlite_cols]
                if not cols:
                    stats["tables"][spec.name] = {"copied": 0, "skipped": True}
                    continue

                rows = src.execute(f"SELECT {', '.join(cols)} FROM {spec.name}").fetchall()
                if not rows:
                    stats["tables"][spec.name] = {"copied": 0, "skipped": False}
                    continue

                ordered_rows: List[Sequence[Any]] = []
                for row in rows:
                    normalized = _normalize_row(spec, {col: row[col] for col in cols})
                    ordered_rows.append(tuple(normalized.get(col) for col in cols))

                sql = _build_upsert_sql(TableSpec(
                    name=spec.name,
                    columns=tuple(cols),
                    conflict_target=tuple(c for c in spec.conflict_target if c in cols),
                    update_columns=tuple(c for c in spec.update_columns if c in cols),
                ))

                for start in range(0, len(ordered_rows), batch_size):
                    chunk = ordered_rows[start : start + batch_size]
                    execute_values(cur, sql, chunk)

                if spec.sequence_column:
                    _reset_sequence(cur, spec.name, spec.sequence_column)

                stats["tables"][spec.name] = {"copied": len(ordered_rows), "skipped": False}
                stats["copied"] += len(ordered_rows)

    return stats
