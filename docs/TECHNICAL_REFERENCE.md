# PQC Scanner Technical Reference

This document is the codebase-level technical reference for the current repository state.

It complements:

- `docs/USER_GUIDE.md`
- `docs/TRY_IT_ON_YOUR_MACHINE.md`
- `docs/TRY_IT_IN_THE_CLOUD.md`

Primary source files:

- `backend/app.py`
- `backend/db.py`
- `backend/db_postgres.py`
- `backend/tasks.py`
- `backend/scanner.py`
- `backend/policy.py`
- `backend/migration.py`
- `backend/remediation_validation.py`
- `backend/remediation_drift.py`
- `backend/events.py`
- `backend/integrations/github.py`
- `backend/integrations/github_app.py`
- `backend/integrations/gcp.py`
- `backend/vault_db.py`
- `backend/vault_crypto.py`
- `backend/static/index.html`
- `infra/gcp/cloudrun/`

## 1. System summary

PQC Scanner is an end-to-end remediation loop, not only a TLS scanner.

It does all of the following:

- scans public endpoints for TLS, certificate, and PQC-readiness posture
- stores current and historical scan results
- tracks asset ownership and business metadata
- links assets to repositories
- creates migration guidance and prioritization views
- generates AI remediation suggestions
- validates candidate fixes before PR creation
- opens PRs in GitHub
- tracks merged PRs through GitHub webhook events
- verifies closure using later scan evidence
- checks for drift after merge
- emits webhook notifications
- records audit events
- exposes organization-level compliance reporting

The main workflow is:

1. detect
2. classify
3. link to code ownership
4. suggest fix
5. validate fix
6. create PR
7. mark merged
8. verify closed
9. monitor for drift

## 2. Runtime architecture

### 2.1 Components

The runtime has three application roles:

- API
  - FastAPI service
  - serves both JSON API and static UI
- worker
  - Celery worker
  - runs scans, validation, sync, correlation, and drift tasks
- beat
  - Celery beat scheduler

The container entrypoint is in `backend/entrypoint.sh` and switches behavior using `APP_COMPONENT`.

### 2.2 Storage and queues

The system uses:

- PostgreSQL
  - primary runtime database in current compose and cloud setups
- Redis
  - Celery broker and result backend
- in-memory API cache
  - `_SCANS` in `backend/app.py`
  - only for short-lived scan acceleration

Legacy SQLite support still exists in `backend/db.py`, but current production-like runtime is Postgres-backed.

### 2.3 Frontend

The frontend is a static HTML/JavaScript UI in:

- `backend/static/index.html`

FastAPI mounts it at:

- `/ui/`

Root `/` redirects to `/ui/`.

There is no separate frontend build pipeline in the current implementation.

### 2.4 Deployment targets

Local/container deployment:

- `backend/compose.yml`

Cloud deployment:

- `infra/gcp/cloudrun/`
- `infra/gcp/modules/private-cloud/`
- `infra/gcp/private-cloud-demo/`
- `scripts/setup-enterprise.sh`

The cloud stack provisions:

- Artifact Registry
- VPC and subnet
- Cloud SQL Postgres
- Memorystore Redis
- Secret Manager
- Cloud Run API
- Cloud Run worker pools

The private-cloud module packages the same stack for customer-owned VPC deployments. It supports a two-phase bootstrap where the customer first creates the private infrastructure and Artifact Registry, then builds/pushes the backend image, adds required secrets, deploys runtime services, and runs Alembic migrations through a one-off Cloud Run Job.

## 3. Execution model

### 3.1 Synchronous scan

Endpoint:

- `POST /scan`

Behavior:

- runs targets inline
- returns results and summary immediately
- does not create the full queued scan lifecycle

Use case:

- quick testing
- simple UI smoke flows

### 3.2 Asynchronous durable scan

Endpoint:

- `POST /scans`

Behavior:

- validates target list
- creates a durable scan row
- enqueues Celery task `pqc.run_scan_task`
- worker updates progress and stores results
- results are fetched later via `/scans/{scan_id}` and `/scans/{scan_id}/results`

This is the main durable scan path.

### 3.3 Synthetic scan

Endpoint:

- `POST /scans/synthetic`

Behavior:

- admin-only
- seeds synthetic results directly into storage
- useful for tests, demos, and verification workflows
- can auto-close merged remediations if the synthetic result proves closure

### 3.4 Scheduler authority

Two scheduling paths exist:

- legacy in-process scheduler in `backend/app.py`
- Celery beat scheduler in the deployed runtime

Important detail:

- when `WORKER_ROLE` is set, the in-process scheduler is disabled
- in Docker and Cloud Run, Celery beat is the intended scheduler authority

## 4. Feature inventory

### 4.1 Scanner

Implemented in:

- `backend/scanner.py`

The scanner collects:

- TLS handshake details
- certificate issuer and subject
- SAN coverage
- key type and key detail
- signature algorithm
- TLS version support
- accepted TLS 1.2 ciphers
- weak cipher acceptance
- ALPN
- OCSP stapling metadata
- OCSP/CRL reachability
- chain completeness and confidence
- verification failures and reasons

Important output fields include:

- `risk_level`
- `quantum_risk_level`
- `quantum_risk_score`
- `pqc_relevance`
- `pqc_recommendation`

### 4.2 Policy engine

Implemented in:

- `backend/policy.py`

The policy layer turns scanner facts into:

- findings
- severity
- risk level
- risk score
- PQC relevance
- aggregate summaries

Rule areas include:

- expired and expiring certs
- certificate verification failures
- incomplete chains
- hostname mismatch
- legacy TLS support
- weak ciphers
- lack of TLS 1.3
- RSA key exchange
- RSA and ECDSA certificate presence as migration signals

### 4.3 Migration planning

Implemented in:

- `backend/migration.py`

It maps finding rule IDs to ordered migration steps with:

- step title
- why it matters
- affected assets
- evidence samples

Exposed by:

- `GET /scans/{scan_id}/migration-plan`

### 4.4 Baselines and diffs

Features:

- set explicit per-asset baseline
- set baselines from an entire scan
- compare current scan against baseline
- compute per-asset new, resolved, and unchanged findings
- show top regressions and improvements

Core implementation lives in:

- `backend/app.py`
- `backend/db.py`
- `backend/db_postgres.py`

### 4.5 Asset inventory

Assets add business context on top of scan targets.

Fields include:

- `asset_key`
- `owner`
- `team`
- `environment`
- `criticality`
- `confidentiality_lifetime`
- `notes`
- `tags`
- `metadata`
- `repository_id`

Important behavior:

- `GET /assets/{asset_key}` auto-creates a blank asset if missing
- asset history comes from persisted `scan_results`
- assets can be manually linked to repositories

### 4.6 Collections and schedules

Collections:

- saved target sets using `targets_text`

Schedules:

- interval-based recurring scans
- store interval in minutes
- can be run immediately with `run-now`

### 4.7 Fix-next prioritization

Endpoint:

- `GET /fix-next`

Purpose:

- rank assets from a scan by priority score
- combine findings and asset metadata into a triage queue

### 4.8 Metrics and dashboard data

Endpoints:

- `GET /metrics/scan/{scan_id}/overview`
- `GET /metrics/trends`
- `GET /org/compliance-report`
- `GET /org/{organization_id}/metrics`
- `GET /org/{organization_id}/drift-analytics`

Aggregates include:

- open assets
- risk distribution
- remediation throughput
- validation pass rates
- verified closure rates
- drift counts
- developer-hours-saved estimate
- engineering-hours-saved per 100 remediations
- MTTR reduction estimate versus configured manual baseline
- manual non-compliant changes reverted through drift follow-up remediations
- compliance readiness score

### 4.9 Multi-tenancy

The product has an organization model implemented in the application and data layer.

Key pieces:

- request org context middleware in `backend/app.py`
- org-aware storage functions in `backend/db.py` and `backend/db_postgres.py`

Important current detail:

- tenancy is app-scoped
- database Row-Level Security is not implemented

### 4.10 Auth and RBAC

Auth modes:

- `headers`
  - local/manual mode using `x-user-id`, `x-user-role`, `x-org-id`
- `jwt`
  - hosted mode using verified bearer tokens

Public routes:

- `/`
- `/ui/*`
- `/health`
- `/auth/config`

`/auth/context` exposes effective session details.

Roles:

- `viewer`
- `operator`
- `admin`

Role enforcement is applied on selected routes using `_require_role`, with audit logging on both allow and deny outcomes.

### 4.11 Vault and credentials

Implemented in:

- `backend/vault_db.py`
- `backend/vault_crypto.py`

Secrets are:

- encrypted at rest using Fernet
- stored in Postgres table `credentials`

Current uses include:

- GitHub PATs
- GitHub App private keys
- GCP service account JSON
- Cloudflare API tokens
- webhook secrets

Important current detail:

- credentials are org-scoped by `organization_id`
- credential names are unique per organization, not globally

### 4.12 GitHub PAT integration

Implemented in:

- `backend/integrations/github.py`

Primary use:

- repository sync using a PAT-style credential

### 4.13 GitHub App integration

Implemented in:

- `backend/integrations/github_app.py`

Capabilities:

- build GitHub App JWT
- fetch installation access token
- resolve installation for repo
- mint repo-scoped token
- sync installations
- sync installation repositories

This is the preferred model for remediation, validation, and PR creation.

### 4.14 GCP sync

Implemented in:

- `backend/integrations/gcp.py`

Purpose:

- sync assets from Google Cloud using a vault-stored service account

### 4.15 Repository correlation

Implemented as Celery task:

- `pqc.correlate_assets`

Purpose:

- heuristically link assets to repositories by searching repository content for asset identifiers

Important nuance:

- correlation is heuristic, not guaranteed
- manual repository linkage remains a valid fallback

### 4.16 Remediation suggestion

Endpoint:

- `POST /remediations/suggest`

Flow:

1. resolve repository
2. resolve GitHub token
3. fetch current file from GitHub
4. build LLM prompt
5. call OpenAI
6. accept either a unified diff or full replacement content
7. apply diff if needed
8. strip wrapper text
9. run guardrails
10. persist remediation

Current guardrails explicitly block suggestions touching:

- IAM
- firewall
- security group resources

### 4.17 Validation

Implemented in:

- `backend/remediation_validation.py`

Capabilities:

- download repository archive
- apply proposed file content in temp workspace
- detect validator type
- run generic or Terraform validation

Sandbox model:

- validation runs in a Python `tempfile.TemporaryDirectory`
- the GitHub repository is downloaded as an archive into that temporary workspace
- archive extraction rejects unsafe paths and zip path traversal
- `file_path` is normalized and rejected if it contains path traversal
- the proposed `suggested_content` is written into the temporary repository copy
- validator commands run with a timeout and captured stdout/stderr/exit code
- validator subprocesses run with a minimal scrubbed environment instead of inheriting application secrets
- the temporary workspace is deleted after the validation function exits
- the latest passed validation is required before PR creation unless an admin uses `allow_unvalidated`

Security boundary note:

- default mode is an ephemeral validation workspace inside the API/worker container
- optional Docker mode runs Terraform validation in a separate per-job container with `--network none`, dropped Linux capabilities, no-new-privileges, CPU/memory limits, and a scrubbed environment
- Docker mode is enabled with `PQC_VALIDATION_ISOLATION_MODE=docker` and requires Docker access plus `PQC_VALIDATION_DOCKER_IMAGE`
- Docker mode is stronger than the default workspace mode, but it is still not a micro-VM or kernel-level hostile-code boundary

Current validator types:

- `auto`
- `terraform`
- `generic`

Terraform validation runs:

- `terraform fmt -check`
- `terraform init -backend=false`
- `terraform validate`

### 4.18 PR creation

Endpoint:

- `POST /remediations/{id}/create-pr`

Behavior:

- remediation must be approved
- remediation normally must have a passed validation
- admin can override with `allow_unvalidated`
- branch is created
- file is updated
- PR is opened
- remediation moves to `pr_created`
- branch, base branch, and GitHub credential metadata are stored for later branch cleanup
- PR body can include a link back to the remediation dashboard when `PQC_APP_BASE_URL` or `PQC_PUBLIC_APP_URL` is set

Current branch naming pattern:

- `{branch_prefix}-{remediation_id}-{timestamp}-{suffix}`

The timestamp and suffix make normal PR retries collision-resistant while preserving readable branch names.

After a remediation reaches `verified_closed`, `pqc.cleanup_remediation_branches` can delete the remediation branch from GitHub. The cleanup skips protected/default branches and records cleanup status, timestamp, error text, and attempt count on the remediation.

### 4.19 Merge tracking and verified closure

Merge tracking happens by:

- manual mark-merged endpoint
- GitHub webhook receiver

Webhook endpoint:

- `POST /integrations/github/webhook`

Behavior:

- optionally verifies `X-Hub-Signature-256`
- handles merged close, closed-without-merge, reopened, and synchronized pull request events
- matches PR URL to remediation
- marks remediation merged, pr_closed, pr_created, or pr_updated
- emits merge event

GitHub PR lifecycle history and status/check publish attempts are also stored for audit and troubleshooting. They are exposed by `GET /integrations/github/pr-events` and `GET /integrations/github/status-publishes`.

Verified closure is driven by later scan evidence and stored as:

- `verification_scan_id`
- `closed_at`
- remediation status `verified_closed`

### 4.20 Drift detection

Implemented in:

- `backend/remediation_drift.py`

Capabilities:

- fetch current file from GitHub
- reconstruct expected post-fix content
- compare current vs expected content
- compute hashes and unified diff
- set drift state:
  - `clean`
  - `drifted`
  - `check_failed`
- auto-create follow-up remediation
- allow acknowledgement
- allow revalidation

### 4.21 Notifications and event rules

Implemented in:

- `backend/events.py`

Capabilities:

- outbound webhook registration
- delivery queue
- HMAC signing
- retry with backoff
- rules with filters and cooldown logic

Built-in event types include:

- `scan.completed`
- `scan.failed`
- `cert.expired`
- `cert.expiring_soon`
- `pqc.not_ready`
- `scan.regression`
- `validation.failed`
- `remediation.merged`
- `remediation.drifted`
- `remediation.drift_followup_created`
- `remediation.drift_acknowledged`

### 4.22 Cloudflare integration

Capabilities currently present:

- connect existing Cloudflare credential from vault
- rotate token
- verify token
- list zones
- store simple policy
- preview desired zone settings
- toggle enforcement
- mock apply
- apply policy to real zone
- inspect and clear Cloudflare audit state

Important note:

- this is a parallel integration feature set
- parts of it are explicitly dry-run friendly

### 4.23 Compliance gate

Endpoint:

- `GET /api/v1/compliance/gate?repo=owner/repo`
- `POST /integrations/ci/status-check`

Current logic:

- load assets linked to repo
- inspect latest scan posture for each linked asset
- return `FAIL` only if one or more linked assets are currently `critical`
- status-check mode can also inspect changed IaC snippets and fail the merge gate on general security policy violations
- status-check mode can optionally publish the resulting success/failure state back to GitHub as either a commit status or Check Run when a GitHub credential id and commit SHA are supplied

Medium/high findings do not fail the gate unless represented as `critical`.

### 4.23.1 General IaC security prototype

Implemented in:

- `backend/iac_security.py`

Current prototype rules:

- `IAC_OPEN_SSH_TO_INTERNET`
  - detects Terraform security group ingress that exposes SSH to a public CIDR
- `IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED`
  - detects incomplete S3 public access block controls

The remediation validation sandbox includes this policy check after generic/Terraform validation. This demonstrates that the same golden loop can validate non-crypto infrastructure fixes, not only PQC/TLS migrations.

### 4.23.2 MCP interface

Endpoint:

- `POST /mcp`

This is a lightweight JSON-RPC MCP-style interface for IDE assistants and external AIs. It supports:

- `tools/list`
- `tools/call` for `check_iac_compliance`
- `tools/call` for `check_repo_enforcement`

The goal is to let an external assistant ask whether a Terraform snippet or repository is compliant with the current organization policy before code is merged.

### 4.24 Audit logging

Audit records include:

- actor
- role
- action
- resource
- decision
- reason
- details JSON
- hash-chain fields

Postgres adds triggers to reject update/delete on `audit_logs`.

### 4.25 Observability and health

Runtime observability includes:

- structured JSON request logs with `organization_id`, method, path, status code, and latency
- optional Sentry exception capture through `SENTRY_DSN`
- Cloud Logging-compatible exception logs when Sentry is not configured
- `/health/deep` for Postgres and Redis connectivity checks
- optional deep `/health` behavior with `PQC_HEALTH_DEEP=1`

### 4.26 Organization lifecycle

Organization lifecycle controls include:

- admin archive endpoint that marks an organization subscription as `archived`
- admin delete endpoint that defaults to archive mode
- explicit purge mode for controlled deletion of org-scoped repositories, scans, remediations, webhooks, event rules, audit logs, collections, schedules, credentials, and related records

## 5. Code map

- `backend/app.py`
  - FastAPI app, middleware, orchestration, endpoints
- `backend/scanner.py`
  - raw TLS/certificate scanning
- `backend/policy.py`
  - finding generation and risk scoring
- `backend/migration.py`
  - migration-plan generation
- `backend/tasks.py`
  - Celery app and background tasks
- `backend/remediation_validation.py`
  - validator execution
- `backend/remediation_drift.py`
  - post-merge drift logic
- `backend/services/hndl.py`
  - HNDL object scoring and AWS/GCP/Azure storage inventory helpers
- `backend/services/repo_discovery.py`
  - generic repository ownership scoring and crypto/config discovery logic
- `backend/services/remediation_workflow.py`
  - remediation guardrails, next-action helpers, queue grouping, PR readiness checks, branch naming, PR title/body generation, and candidate content resolution
- `backend/services/github_pr.py`
  - GitHub API wrappers for branch creation, file updates, repository metadata, and pull request creation
- `backend/schemas.py`
  - shared request/data models extracted from the main FastAPI app
- `backend/idempotency.py`
  - Idempotency-Key handling for retry-safe write actions
- `backend/events.py`
  - outbound notifications and rules
- `backend/db.py`
  - legacy SQLite and dispatch layer
- `backend/db_postgres.py`
  - Postgres storage and schema
- `backend/vault_db.py`
  - encrypted credential storage
- `backend/vault_crypto.py`
  - Fernet encryption/decryption
- `backend/integrations/github.py`
  - PAT sync
- `backend/integrations/github_app.py`
  - GitHub App token minting and sync
- `backend/integrations/gcp.py`
  - GCP sync
- `backend/static/index.html`
  - static UI

## 6. Non-obvious implementation details

### 6.1 Org-scoped versus global tables

Org-scoped data includes:

- organizations
- repositories
- assets
- asset_tags
- baselines
- scan_results
- remediations
- validation_jobs
- audit_logs
- github_installations
- collections
- schedules
- scans
- webhooks
- webhook_events
- event_rules
- event_rule_fires

Global/shared tables currently include:

- integrations_settings

### 6.2 Scans are org-scoped

Top-level scans rows and scan_results carry organization context so scan audit trails and reporting can be tied to the owning tenant.

### 6.3 Credentials are org-scoped

Vault credentials carry `organization_id`. List, reveal, rotate, and token resolution paths only return credentials in the active organization context.

### 6.4 Collections and schedules are org-scoped

Collections and schedules carry `organization_id`; list/get/update/delete operations resolve through the active organization context.

### 6.5 The UI is intentionally thin

The UI mostly:

- calls backend endpoints
- stores API base
- stores bearer token
- reads `/auth/config`
- reads `/auth/context`

Most business logic is backend-side.

### 6.6 Vendor vs customer visibility

Customer-visible data is scoped to the active organization:

- dashboard and compliance report
- ROI metrics and drift analytics
- scans, scan results, assets, collections, and schedules
- repositories, remediations, validation jobs, PR URLs, verified closure, and drift state
- outbound webhooks, webhook delivery events, event rules, and audit logs
- CI gate and MCP compliance answers for the active organization

Vendor/operator-only visibility exists outside the normal customer UI:

- organization list, archive, and purge APIs
- Cloud Run logs and health
- Cloud SQL operational access and backups
- Secret Manager metadata and runtime secret wiring
- Terraform state and deployment outputs
- cross-tenant database inspection for support, if the vendor has database credentials

There is no polished cross-tenant vendor console yet. Vendor operations are currently done through admin APIs, cloud console, Terraform, logs, or direct database inspection.

### 6.7 Hosted auth is functional but transitional

The hosted auth bridge works with bearer tokens and current JWT config, but a full browser-native code+PKCE flow would still be a natural hardening step.

## 7. Testing map

Important tests:

- `backend/test_compliance_gate.py`
- `backend/test_sprint12_remediations.py`
- `backend/test_sprint13_rbac_audit_guardrails.py`
- `backend/test_sprint14_multitenancy.py`
- `backend/test_sprint14_github_app_bridge.py`
- `backend/test_sprint14_schema_migrations.py`
- `backend/test_sprint18_compliance_report.py`
- `backend/test_sprint19_drift_notifications.py`
- `backend/test_sprint20_drift_response.py`
- `backend/test_postgres_runtime_switch.py`
- `backend/test_postgres_cutover_utils.py`
- `backend/test_saas_auth_jwt.py`

Coverage areas:

- compliance gate
- remediation lifecycle
- RBAC and audit
- multi-tenancy
- GitHub App flows
- schema migration
- compliance report
- drift notifications and follow-up remediation
- Postgres cutover/runtime dispatch
- JWT auth

## 8. Current technical debt

- `backend/app.py` is large and mixes concerns
- FastAPI startup/shutdown uses lifespan handlers
- runtime timestamp generation uses timezone-aware UTC helpers; legacy stored rows may still contain older naive strings
- some shared tables weaken tenancy hardening
- repository correlation is heuristic
- remediation PR branches use unique suffixes to avoid normal retry collisions

## 9. Supporting technical docs

Use these alongside this file:

- `docs/API_REFERENCE.md`
- `docs/DATA_MODEL_AND_OPERATIONS.md`

### Runtime traffic inventory

A runtime traffic import layer now exists alongside active scanning and static repository discovery.

Implementation files:

- `backend/services/runtime_observations.py`
- `backend/db.py`
- `backend/app.py`

Storage:

- `runtime_traffic_observations`

Purpose:

- ingest CDN, load balancer, ingress, or service-mesh observations
- normalize observed hosts into `host:port` asset keys
- create/update asset metadata with runtime evidence
- expose machine-readable runtime observations and runtime-observed assets

This is not packet capture. It is a safer enterprise ingestion path for production telemetry.

### GitHub App diagnostics

GitHub App enterprise hardening added safe setup and repository-access diagnostics.

Implementation:

- `integrations/github_app.py`
  - `github_app_credential_status`
  - `diagnose_github_repo_access`
- `backend/app.py`
  - `GET /integrations/github-app/status`
  - `POST /integrations/github-app/repo-diagnostics`

The diagnostic path does not return installation tokens. It reports readiness, missing setup steps, installation id, token expiry metadata, and optional repository metadata reachability.

### Organization memberships and tenant admin

Organization membership storage was added to support production tenant administration.

Storage:

- `organization_memberships`

Core functions:

- `upsert_organization_member`
- `get_organization_member`
- `list_organization_members`
- `list_user_memberships`
- `remove_organization_member`

Runtime behavior:

- `_actor_from_request` resolves the actor from JWT/header first.
- If the actor has an active membership in the active organization, the membership role overrides the claimed/header role.
- Tenant member-management endpoints require admin role and reject cross-org management attempts.

### Validation sandbox profile and evidence

Validation hardening added explicit sandbox profile and evidence package helpers.

Implementation:

- `remediation_validation.validation_sandbox_profile`
- `remediation_validation.validation_evidence_package`
- `GET /validation/sandbox-profile`
- `GET /validation-jobs/{validation_job_id}/evidence`

Command execution now records timeout metadata and applies configured stdout/stderr truncation limits. The validation evidence package exposes secret scrubbing, path traversal checks, archive extraction checks, timeout enforcement, and output capture status.

Backend architecture cleanup update:

- Validation-related API routes were extracted out of the large application file into `backend/routers/validation.py`.
- The existing public paths did not change:
  - `GET /remediations/{remediation_id}/validations`
  - `GET /validation-jobs/{validation_job_id}`
  - `GET /validation/sandbox-profile`
  - `GET /validation-jobs/{validation_job_id}/evidence`
- `backend/app.py` now wires the validation router through `app.include_router(...)`.
- This is the first safe router extraction step toward splitting `backend/app.py` into smaller maintainable modules without changing behavior.

Backend architecture cleanup update:

- GitHub App enterprise routes were extracted into `backend/routers/github_app.py`.
- Existing route URLs stayed unchanged:
  - `GET /integrations/github-app/installations`
  - `GET /integrations/github-app/status`
  - `POST /integrations/github-app/sync-installations`
  - `POST /integrations/github-app/sync-repositories`
  - `POST /integrations/github-app/repo-diagnostics`
- The router preserves existing test seams and behavior while reducing `backend/app.py` size.

### Organization router extraction

Organization and tenant membership API handlers have been moved out of `backend/app.py` into `backend/routers/organizations.py`.

URLs remain unchanged:

- `GET /organizations`
- `POST /organizations`
- `POST /organizations/{organization_id}/archive`
- `DELETE /organizations/{organization_id}`
- `GET /organizations/{organization_id}/members`
- `POST /organizations/{organization_id}/members`
- `PATCH /organizations/{organization_id}/members/{user_id}`
- `DELETE /organizations/{organization_id}/members/{user_id}`
- `GET /auth/memberships`

This keeps tenant administration and membership RBAC behavior intact while reducing the size of the main application module.

### Remediation and PR workflow router extraction

Remediation workflow handlers have been moved out of `backend/app.py` into `backend/routers/remediations.py`.

URLs remain unchanged:

- `GET /remediations`
- `GET /remediations/{remediation_id}`
- `POST /remediations/suggest`
- `POST /remediations/{remediation_id}/approve`
- `POST /remediations/{remediation_id}/reject`
- `POST /remediations/{remediation_id}/validate`
- `POST /remediations/{remediation_id}/create-pr`
- `POST /remediations/drift/check`
- `POST /remediations/branches/cleanup`
- `GET /remediations/branches/cleanup/status`
- `POST /remediations/{remediation_id}/branch/cleanup`
- `POST /remediations/{remediation_id}/drift/acknowledge`
- `POST /remediations/{remediation_id}/drift/revalidate`
- `POST /remediations/{remediation_id}/mark-merged`

The router keeps the existing validation, GitHub PR creation, drift, branch cleanup, and review status behavior while isolating the enterprise remediation workflow from the main application module.

### Evidence and reporting router extraction

Evidence and organization reporting API handlers have been moved out of `backend/app.py` into `backend/routers/evidence.py`.

URLs remain unchanged:

- `GET /org/compliance-report`
- `GET /org/{organization_id}/metrics`
- `GET /org/{organization_id}/drift-analytics`
- `GET /org/{organization_id}/quantum-migrations`
- `GET /org/{organization_id}/readiness`
- `GET /v1/org/{organization_id}/readiness`
- `GET /assets/{asset_key}/evidence`
- `GET /v1/assets/{asset_key}/evidence`
- `GET /evidence/assets/{asset_key}`
- `GET /v1/evidence/assets/{asset_key}`
- `GET /evidence/remediations/{remediation_id}`
- `GET /v1/evidence/remediations/{remediation_id}`
- `GET /evidence/repos/{owner/repo}`
- `GET /v1/evidence/repos/{owner/repo}`
- `GET /repos/{owner/repo}/gate`
- `GET /v1/repos/{owner/repo}/gate`

This prepares the backend for board-level risk metrics, regulatory mapping, and audit-ready evidence APIs while preserving existing endpoint contracts.

### Quantum Risk Index and regulatory alignment

Board-level risk APIs were added on top of the evidence/reporting layer.

New endpoints:

- `GET /org/{organization_id}/qri`
- `GET /v1/org/{organization_id}/qri`
- `GET /org/{organization_id}/regulatory-alignment`
- `GET /v1/org/{organization_id}/regulatory-alignment`

The Quantum Risk Index is a 0-100 maturity score where higher is better. It is composed from explainable weighted signals:

- inventory coverage
- open exposure reduction
- crypto-agility
- validated execution
- provider/config blocker control
- Day-2 governance

Regulatory alignment currently maps platform evidence to operational control areas for:

- NIST SP 800-227
- FIPS 140-3
- DORA

The regulatory mapping is an operational readiness mapping, not a certification or legal attestation.

### GitHub PR blocking enforcement update

The repository CI/status-check gate now returns a stronger PR blocking payload.

Updated endpoint:

- `POST /integrations/ci/status-check`

The response now includes:

- `blocking`
- `merge_gate`
- `required_check_context`
- `enforcement_mode`
- `fix_suggestions`
- enriched violation objects with `id`, `blocking`, and `fix_suggestion`

The GitHub check-run output now includes concrete fix guidance for each blocking violation.

Policy-as-code also supports default banned crypto enforcement through `banned_crypto_rules`. The initial default rule blocks RSA-2048 signals for EU/EU-like regions when `fail_ci_on_banned_crypto` is enabled.

This moves the platform closer to active governance: the platform does not only report crypto risk, it can publish a failing GitHub status/check that branch protection can use to block merges.

### Certificate lifecycle and Shadow IT governance

Crypto-governance APIs were added for certificate expiration monitoring and unmanaged runtime endpoint discovery.

New service:

- `backend/services/crypto_governance.py`

New router:

- `backend/routers/governance.py`

New endpoints:

- `GET /governance/certificates`
- `GET /v1/governance/certificates`
- `GET /governance/shadow-it`
- `GET /v1/governance/shadow-it`

Certificate lifecycle reports classify assets as:

- `expired`
- `expiring_soon`
- `healthy`
- `unknown`

Shadow IT reports compare runtime-observed endpoints with inventory, ownership, repository linkage, and scan evidence. Runtime endpoints with missing inventory, owner, repo, or scan evidence are returned as unmanaged/unknown runtime endpoints.

### Remediation Feed / PR-Canvas backend

A work-feed API was added to support the later "actionable PR-canvas" UI.

New service:

- `backend/services/remediation_feed.py`

New router:

- `backend/routers/workfeed.py`

New endpoints:

- `GET /work/remediation-feed`
- `GET /v1/work/remediation-feed`

The feed converts remediations and migration tasks into action cards with:

- board column (`candidates`, `validate`, `pull_request`, `verified_drift`, `migration_tasks`, `closed`)
- priority and risk label
- next action (`approve`, `validate`, `create_pr`, `track_pr`, `drift_check`, `plan_migration`)
- action URL
- validation status
- safe-to-apply and blocker metadata

This is the backend foundation for a live remediation feed where the UI can show what should be processed next instead of forcing users to read static reports.

### Remediation Feed UI panel

The existing Remediation Queue modal now consumes the work-feed API:

- `GET /v1/work/remediation-feed`

The UI groups backend action cards into operational columns:

- candidates
- review
- validate
- pull request
- verified / drift
- migration tasks

Cards show the next safe action, validation state, risk label, blocker metadata, and links into existing remediation, evidence, PR, drift, and migration-task workflows. This is intentionally functional first; final command-center graphics can be redesigned later without changing the backend contract.

### Board-level dashboard widgets

The dashboard now includes a board-level risk posture section that calls the enterprise APIs already added:

- `GET /v1/org/{organization_id}/qri`
- `GET /v1/org/{organization_id}/regulatory-alignment`
- `GET /v1/governance/certificates`
- `GET /v1/governance/shadow-it`
- `GET /v1/work/remediation-feed`

The widget summarizes Quantum Risk Index, regulatory alignment, work queue state, certificate alerts, and shadow IT exposure. This is a functional CISO/board layer before the later command-center visual redesign.

### Policy management UI

The Policies modal is now an editable organization policy surface instead of a read-only viewer.

Added controls:

- load organization policy
- save organization policy
- evaluate current policy across assets
- add the default RSA-2048 EU banned-crypto rule to the editor

The policy editor writes to:

- `PUT /v1/org/{organization_id}/policy`

The saved policy is used by asset evidence decisions, organization reports, board risk widgets, and the PR merge gate.

### Runtime traffic log ingestion

Runtime traffic import now accepts raw log lines in addition to structured records.

Updated endpoint:

- `POST /v1/runtime/traffic/import`

New request fields:

- `log_format`
- `raw_logs`

The parser supports auto-detection for JSON-style edge/access logs and text lines containing URLs/hosts. It extracts host, port, path, method, TLS version, cipher, status code, source, and provider, then stores the result in runtime observations and optionally creates/updates runtime-observed assets.

This reduces the static-analysis blind spot by allowing Cloudflare Logpush, Envoy/access-log, ALB-like, and generic HTTP log evidence to feed shadow-IT and board-risk views.

### Runtime traffic UI panel

The operator console now includes a Runtime Traffic panel.

New UI actions:

- import raw Cloudflare/Envoy/ALB/generic access logs
- refresh runtime-observed assets
- load Shadow IT findings derived from runtime observations

The panel calls:

- `POST /v1/runtime/traffic/import`
- `GET /v1/runtime/assets`
- `GET /v1/governance/shadow-it`

This makes network/runtime evidence visible in the product UI and feeds the board-risk and shadow-IT dashboards.

### GitHub App diagnostics UI

The GitHub connection area now exposes GitHub App diagnostics controls.

New UI actions:

- GitHub App status
- sync GitHub App installations
- sync GitHub App repositories for an installation id
- diagnose repo access for `owner/repo`

The panel calls:

- `GET /integrations/github-app/status`
- `POST /integrations/github-app/sync-installations`
- `POST /integrations/github-app/sync-repositories`
- `POST /integrations/github-app/repo-diagnostics`

This gives operators a visible readiness check before running live repo scanning, validation, and PR creation flows.

### PR readiness API

The remediation workflow now has a pre-flight readiness endpoint before operators attempt a live GitHub PR.

Endpoints:

- `GET /remediations/{remediation_id}/pr-readiness`
- `GET /v1/remediations/{remediation_id}/pr-readiness`

Query parameters:

- `github_credential_id`
- `check_live_repo`

The response returns `ready`, `phase`, `next_action`, blockers, warnings, remediation summary, latest validation summary, GitHub diagnostic details, and the next API calls for validation or PR creation.

This makes the PR flow safer: the platform can tell an operator exactly whether the remediation is approved, validated, linked to a valid repo, has a target file and suggested content, has a GitHub credential, and optionally has live GitHub repo access before attempting branch/commit/PR mutation.

### PR readiness in the Remediation Queue

The Remediation Queue now exposes the PR readiness pre-flight directly on eligible remediation cards.

UI behavior:

- approved or validated cards show a `PR Readiness` action
- `Create PR` runs the readiness check first
- blocked PRs surface concrete blockers instead of attempting GitHub mutation
- successful readiness opens the JSON diagnostic for operator review

This keeps the live PR path explicit and auditable: operators can see whether validation, repo linkage, credentials, and optional GitHub App access are ready before creating a branch, commit, and pull request.

### End-to-end readiness checklist

The platform now exposes an aggregated final-flow readiness checklist.

Endpoints:

- `GET /readiness/e2e`
- `GET /v1/readiness/e2e`

The checklist mirrors the full test plan from startup through the final money flow: auth, RBAC, multi-tenancy, GitHub App sync, scans, asset/repo correlation, compliance gate, remediation suggestion, approval, validation, PR creation, merge webhook, verify-close, drift, notifications, compliance report, dashboard, persistence, and negative security tests.

The Dashboard loads this checklist as `Final end-to-end readiness checklist`, showing readiness percentage, blocked items, warnings, and the highest-priority blockers. This gives operators one place to see what still blocks the final live enterprise demo.

The checklist now includes action controls:

- `Do next` on each visible checklist item
- `Run top blocker` for the first blocked item
- direct jumps to GitHub App status, scan start, asset onboarding, correlation, remediation queue, integrations/webhooks, audit logs, and compliance report JSON

These controls turn the readiness checklist into an operator runner instead of a passive report.

### End-to-end readiness handoff export

The readiness checklist can now produce a compact handoff artifact for demo/release coordination.

Endpoints:

- `GET /readiness/e2e/export?format=markdown`
- `GET /readiness/e2e/export?format=json`
- `GET /v1/readiness/e2e/export?format=markdown`
- `GET /v1/readiness/e2e/export?format=json`

The Markdown export summarizes readiness percentage, ready/warning/blocked counts, source counts, blockers, warnings, and the next blocker to resolve. The JSON export returns the same compact handoff shape without the full item list.

The Dashboard includes `Open blocker handoff` and `Copy Markdown handoff` controls for sharing the current state before a live demo or release checkpoint.
