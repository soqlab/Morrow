# PQC Scanner Data Model and Operations

This file covers:

- persistent data model
- runtime configuration
- local and cloud deployment details
- operations and maintenance notes
- testing and troubleshooting map

## 1. Storage model

The system uses three storage classes:

- PostgreSQL
  - main application database
  - current runtime target in compose and cloud
- Redis
  - Celery broker and result backend
- in-memory API cache
  - short-lived `_SCANS` map in `backend/app.py`

Legacy SQLite code still exists in `backend/db.py`, but current production-like runtime is Postgres-backed.

## 2. Main PostgreSQL tables

### 2.1 `organizations`

Purpose:

- tenant records

Fields:

- `id`
- `name`
- `plan_type`
- `subscription_status`
- `created_at`
- `updated_at`

### 2.2 `repositories`

Purpose:

- GitHub repositories linked into the platform

Fields:

- `id`
- `organization_id`
- `name`
- `html_url`
- `created_at`
- `updated_at`

Constraint:

- unique per `(organization_id, name)`

### 2.3 `assets`

Purpose:

- tracked endpoints plus ownership metadata

Fields:

- `organization_id`
- `asset_key`
- `owner`
- `team`
- `environment`
- `criticality`
- `confidentiality_lifetime`
- `notes`
- `metadata_json`
- `repository_id`
- `updated_at`

Primary key:

- `(organization_id, asset_key)`

### 2.4 `asset_tags`

Purpose:

- normalized tags per asset

Fields:

- `organization_id`
- `asset_key`
- `tag`

### 2.5 `baselines`

Purpose:

- baseline scan ID per asset

Fields:

- `organization_id`
- `asset_key`
- `baseline_scan_id`
- `set_at`

### 2.6 `scans`

Purpose:

- top-level durable scan rows

Fields:

- `id`
- `organization_id`
- `status`
- `created_at`
- `progress_json`
- `error_text`
- `results_json`
- `summary_json`
- `job_id`
- `job_state`
- `job_started_at`
- `job_finished_at`

Important note:

- scoped by `organization_id`; scan audit trails are tenant-owned.

### 2.7 `scan_results`

Purpose:

- historical per-asset scan snapshots for trends and asset history

Fields:

- `id`
- `organization_id`
- `asset_key`
- `scan_id`
- `scanned_at`
- `risk_level`
- `quantum_score`
- `findings_count`
- `pqc_relevance`
- `tls_version`
- `key_type`
- `sig_algorithm`
- `owner`
- `team`
- `environment`
- `criticality`

### 2.8 `remediations`

Purpose:

- fix workflow records

Fields:

- `id`
- `organization_id`
- `asset_key`
- `repo_id`
- `vulnerability`
- `file_path`
- `original_content`
- `suggested_fix`
- `suggested_content`
- `status`
- `pr_url`
- `pr_branch`
- `pr_base_branch`
- `github_credential_id`
- `branch_cleanup_status`
- `branch_cleanup_at`
- `branch_cleanup_error`
- `branch_cleanup_attempts`
- `review_note`
- `merged_at`
- `verification_scan_id`
- `closed_at`
- `parent_remediation_id`
- `origin_kind`
- `drift_followup_remediation_id`
- `drift_status`
- `last_drift_checked_at`
- `drift_detected_at`
- `drift_acknowledged_at`
- `drift_acknowledged_by`
- `drift_ack_note`
- `drift_details_json`
- `created_at`
- `updated_at`

### 2.9 `validation_jobs`

Purpose:

- validation execution history

Fields:

- `id`
- `organization_id`
- `remediation_id`
- `validator_type`
- `status`
- `git_ref`
- `job_id`
- `stdout`
- `stderr`
- `exit_code`
- `details_json`
- `created_at`
- `updated_at`
- `finished_at`

### 2.10 `audit_logs`

Purpose:

- governance trail

Fields:

- `id`
- `organization_id`
- `actor_id`
- `actor_role`
- `action`
- `resource_type`
- `resource_id`
- `decision`
- `reason`
- `details_json`
- `prev_hash`
- `entry_hash`
- `created_at`

Postgres hardening:

- update/delete triggers reject mutation

### 2.11 `github_installations`

Purpose:

- synced GitHub App installation metadata

Fields:

- `id`
- `organization_id`
- `installation_id`
- `account_login`
- `account_type`
- `target_type`
- `permissions_json`
- `repositories_count`
- `suspended_at`
- `created_at`
- `updated_at`

### 2.12 `webhooks`

Purpose:

- outbound notification destinations

Fields:

- `id`
- `organization_id`
- `name`
- `url`
- `secret`
- `credential_id`
- `events_json`
- `enabled`
- `created_at`
- `updated_at`

Important note:

- scoped by `organization_id`; event delivery only targets webhooks in the active organization.

### 2.13 `webhook_events`

Purpose:

- delivery queue and delivery history

Fields:

- `id`
- `organization_id`
- `webhook_id`
- `created_at`
- `event_type`
- `dedupe_key`
- `payload_json`
- `status`
- `http_status`
- `error_text`
- `response_excerpt`
- `attempts`
- `last_attempt_at`
- `next_attempt_at`
- `claimed_at`
- `claimed_by`

### 2.14 `collections`

Purpose:

- saved target groups

Fields:

- `id`
- `organization_id`
- `name`
- `targets_text`
- `created_at`
- `updated_at`

Constraint:

- unique per `(organization_id, name)` in Postgres-backed deployments

### 2.15 `schedules`

Purpose:

- recurring collection scans

Fields:

- `id`
- `organization_id`
- `collection_id`
- `enabled`
- `interval_minutes`
- `created_at`
- `updated_at`
- `last_run_at`
- `next_run_at`
- `last_scan_id`

Important note:

- scoped by `organization_id` and linked to an org-scoped collection

### 2.16 `integrations_settings`

Purpose:

- generic key/value settings store

Fields:

- `key`
- `value`

### 2.17 `event_rules`

Purpose:

- notification matching and routing rules

Key fields in current schema include:

- `id`
- `organization_id`
- `name`
- `enabled`
- `webhook_ids_json`
- `event_types_json`
- `min_severity`
- `rule_ids_json`
- `environments_json`
- `teams_json`
- `criticalities_json`
- `tags_json`
- `cooldown_minutes`
- `quantum_score_min`
- `fire_mode`
- timestamps

### 2.18 `event_rule_fires`

Purpose:

- rule fire dedupe and cooldown tracking

Fields:

- `organization_id`
- `rule_id`
- `fingerprint`
- `last_fired_at`

## 3. Vault schema

Vault credentials are stored in:

- `credentials`

Fields:

- `id`
- `organization_id`
- `name`
- `provider`
- `secret_enc`
- `meta_json`
- `created_at`
- `updated_at`
- `last_rotated_at`

Secrets are encrypted using:

- `PQC_VAULT_MASTER_KEY`

## 4. Org-scoped vs global data

Org-scoped:

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
- credentials
- collections
- schedules
- scans
- webhooks
- webhook_events
- event_rules
- event_rule_fires

Global/shared in current schema:

- integrations_settings

This is one of the most important current architecture facts.

## 4.1 Vendor vs customer visibility

In hosted/SaaS mode, tenant visibility is controlled by:

- `organization_id` on stored data
- JWT organization claims or local `x-org-id` headers
- role checks for `viewer`, `operator`, and `admin`
- org-scoped database access functions

Customer users can see data for their active organization only:

- their assets
- their scans and scan results
- their repositories
- their remediations, validation jobs, PR links, verified-closed state, and drift state
- their collections and schedules
- their outbound webhooks, webhook delivery events, and event rules
- their audit logs
- their compliance report, ROI metrics, drift analytics, CI gate result, and MCP compliance responses

Customer users cannot see other organizations' data through normal API/UI flows when auth is configured with tenant-specific organization claims.

Vendor/operator visibility is different:

- through cloud/provider access, the vendor can inspect infrastructure logs, Cloud Run service health, Secret Manager metadata, Cloud SQL backups, Terraform state, and deployment status
- through admin API endpoints, the vendor can list organizations, archive organizations, purge organizations, inspect audit logs, and perform operational setup
- through direct database access, the vendor can inspect all tenant data in the hosted database for support and incident response

Current UI note:

- the customer UI exposes the active organization's dashboard, scans, assets, remediations, compliance report, ROI cards, and CI gate checks
- there is not yet a separate polished vendor console for cross-tenant management
- vendor-only operations currently happen through admin APIs, cloud console, logs, Terraform outputs, or direct database inspection

Security caveat:

- application-level tenant scoping is implemented
- database Row-Level Security is still a recommended future hardening step for stronger shared-SaaS isolation

## 5. Runtime environment variables

### 5.1 Database and backend selection

- `PQC_MAIN_DB_BACKEND`
- `PQC_PRODUCT_DATABASE_URL`
- `DATABASE_URL`
- `PQC_SCANNER_DB`

### 5.2 Vault

- `PQC_VAULT_MASTER_KEY`

### 5.3 Auth

- `PQC_AUTH_MODE`
- `PQC_AUTH_REQUIRED`
- `PQC_AUTH_PROVIDER_NAME`
- `PQC_AUTH_LOGIN_URL`
- `PQC_AUTH_LOGOUT_URL`
- `PQC_AUTH_TOKEN_HELP`
- `PQC_AUTH_JWT_ISSUER`
- `PQC_AUTH_JWT_AUDIENCE`
- `PQC_AUTH_JWT_JWKS_URL`
- `PQC_AUTH_JWT_SECRET`
- `PQC_AUTH_USER_ID_CLAIM`
- `PQC_AUTH_ROLE_CLAIM`
- `PQC_AUTH_ORG_ID_CLAIM`
- `PQC_AUTH_CLOCK_SKEW_SECONDS`
- `PQC_AUTH_JWT_ALGORITHMS`

### 5.4 Defaults and request limits

- `PQC_DEFAULT_ROLE`
- `PQC_DEFAULT_ORG_ID`
- `PQC_API_KEY`
- `PQC_RATE_LIMIT_WINDOW_SECONDS`
- `PQC_RATE_LIMIT_MAX_REQUESTS`

### 5.5 AI

- `OPENAI_API_KEY`
- `OPENAI_MODEL`

### 5.6 GitHub webhook

- `GITHUB_WEBHOOK_SECRET`

### 5.7 Celery and Redis

- `REDIS_PASSWORD`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`

### 5.8 Runtime behavior

- `APP_COMPONENT`
- `WORKER_ROLE`
- `ENABLE_INPROCESS_SCHEDULER`
- `PER_TARGET_TIMEOUT`
- `HOST`
- `PORT`
- `CELERY_LOGLEVEL`
- `CELERY_CONCURRENCY`
- `BEAT_SCHEDULE_PATH`

### 5.9 Background sync and drift tuning

- `GITHUB_SYNC_CREDENTIAL_ID`
- `GITHUB_SYNC_ORG`
- `GITHUB_SYNC_VISIBILITY`
- `CORRELATE_ASSET_LIMIT`
- `GCP_SYNC_CREDENTIAL_ID`
- `GCP_SYNC_PROJECT_ID`
- `PQC_WEBHOOK_DRAIN_LIMIT`
- `PQC_WEBHOOK_MAX_ATTEMPTS`
- `PQC_WEBHOOK_LEASE_SECONDS`
- `PQC_DRIFT_CHECK_LIMIT`
- `PQC_GITHUB_DRIFT_CREDENTIAL_ID`
- `PQC_BRANCH_CLEANUP_LIMIT`
- `CORRELATE_DEEP_SCAN`
- `CORRELATE_DEEP_SCAN_MAX_FILES`
- `CORRELATE_DEEP_SCAN_MAX_DEPTH`
- `CORRELATE_DEEP_SCAN_MAX_KB`

### 5.10 Validation isolation

- `PQC_VALIDATION_ISOLATION_MODE`
  - `workspace` by default
  - `docker` to run Terraform validation in a per-job Docker container
- `PQC_VALIDATION_DOCKER_IMAGE`
  - Docker image used for isolated Terraform validation
  - default: `ghcr.io/opentofu/opentofu:1.8.6`
- `PQC_VALIDATION_DOCKER_CPUS`
  - CPU limit for the validation container
- `PQC_VALIDATION_DOCKER_MEMORY`
  - memory limit for the validation container

### 5.11 Observability

- `PQC_STRUCTURED_LOGS`
  - defaults to enabled; emits JSON logs for Cloud Logging
- `PQC_LOG_LEVEL`
  - root log level for API and worker logs
- `SENTRY_DSN`
  - optional Sentry DSN for exception capture
- `SENTRY_TRACES_SAMPLE_RATE`
  - optional Sentry tracing sample rate
- `PQC_ENVIRONMENT`
  - environment label attached to Sentry events
- `PQC_HEALTH_DEEP`
  - if enabled, `/health` also verifies Postgres and Redis; `/health/deep` always performs deep checks
- `PQC_APP_BASE_URL` / `PQC_PUBLIC_APP_URL`
  - public UI base URL used for GitHub PR link-back metadata

## 6. Local Docker deployment

`backend/compose.yml` starts:

- `redis`
- `postgres`
- `webhook_sink`
- `api`
- `worker`
- `beat`

Important defaults:

- Postgres exposed on host `5433`
- API exposed on host `8000`
- webhook sink exposed on `9001`

All application services use:

- Postgres as main DB
- Redis for Celery
- vault key from env
- OpenAI config from env

## 7. Container image behavior

`backend/Dockerfile`:

- base image: `python:3.11-slim`
- installs Terraform into the image
- installs Python requirements
- copies source into `/app`
- uses `entrypoint.sh`

Technical consequence:

- default Terraform validation runs inside the same runtime image with a temporary workspace and scrubbed environment
- optional Docker isolation runs Terraform validation in a separate per-job container with network disabled and resource limits

## 8. Cloud deployment

Terraform under `infra/gcp/cloudrun/` provisions:

- required GCP APIs
- Artifact Registry repo
- private VPC and subnet
- private service networking
- Cloud SQL Postgres
- Memorystore Redis
- runtime service account
- Secret Manager secrets
- Cloud Run API
- Cloud Run worker pools

### 8.0 Private-cloud / VPC package

Enterprise private-cloud packaging lives in:

- `infra/gcp/modules/private-cloud/`
  - reusable customer-owned GCP module
  - provisions Artifact Registry, VPC, private service networking, Cloud SQL Postgres, Memorystore Redis, Secret Manager, Cloud Run API, Celery worker pool, and Celery beat worker pool
- `infra/gcp/private-cloud-demo/`
  - thin investor/customer demo root module that wraps the reusable module
- `scripts/setup-enterprise.sh`
  - two-phase bootstrap script for clean customer projects

The bootstrap script:

1. applies Terraform with `deploy_runtime=false`
2. builds and pushes the backend image into the customer's private Artifact Registry
3. writes required Secret Manager versions
4. applies Terraform with `deploy_runtime=true`
5. runs Alembic migrations using a one-off Cloud Run Job inside the VPC

This deployment keeps Postgres, Redis, secrets, runtime identities, and container images inside the customer-controlled project. It is the preferred packaging model for banks, government contractors, healthcare systems, and other customers with strict data sovereignty requirements.

### 8.1 Two-phase deploy model

Current flow:

1. `deploy_runtime = false`
   - create infra and secret containers
2. add missing secret versions manually
3. set `deploy_runtime = true`
4. apply again to deploy runtime

Manual secrets still required after first apply:

- OpenAI API key
- vault master key

Generated automatically:

- database URL
- Celery broker URL
- Celery result backend
- GitHub webhook secret

### 8.2 Terraform auth variables

Terraform wires hosted auth config into Cloud Run using variables such as:

- `auth_mode`
- `auth_required`
- `auth_provider_name`
- `auth_login_url`
- `auth_logout_url`
- `auth_jwt_issuer`
- `auth_jwt_audience`
- `auth_jwt_jwks_url`
- `auth_jwt_algorithms`
- `auth_user_id_claim`
- `auth_role_claim`
- `auth_org_id_claim`

## 9. Operations

### 9.1 Minimum health checks

- GET /health for the default liveness check
- GET /health/deep or PQC_HEALTH_DEEP=1 for Postgres and Redis probing
- `GET /auth/config`
- UI load on `/ui/`

For background runtime:

- verify worker is running
- verify beat is running
- verify Redis reachable
- verify Postgres reachable

### 9.2 Common admin tasks

- sync GitHub App installations
- sync repositories
- rotate vault credentials
- review failed validation jobs
- review drifted remediations
- clean up verified-closed remediation branches
- review ROI metrics and MTTR reduction evidence
- review CI/CD enforcement gate failures
- archive or purge inactive organizations
- retry webhook deliveries
- review audit logs

### 9.3 Backup targets

Critical backup targets:

- Postgres database
- Secret Manager values
- Terraform state

Redis is operational state, not the main system of record.

### 9.4 Logging and troubleshooting surfaces

- API logs
- worker logs
- beat logs
- audit logs
- webhook event records
- validation job stdout/stderr
- structured JSON request logs with `organization_id`
- optional Sentry events when `SENTRY_DSN` is configured

### 9.5 Hosted auth reset

Most common hosted auth issue:

- expired browser token

Current browser-side reset:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

## 10. Testing and verification

### 10.1 Main regression suites

Recommended grouped run:

- `backend/test_compliance_gate.py`
- `backend/test_sprint12_remediations.py`
- `backend/test_sprint13_rbac_audit_guardrails.py`
- `backend/test_sprint14_multitenancy.py`
- `backend/test_sprint14_github_app_bridge.py`
- `backend/test_sprint14_schema_migrations.py`
- `backend/test_sprint18_compliance_report.py`
- `backend/test_sprint19_drift_notifications.py`
- `backend/test_sprint20_drift_response.py`
- `backend/test_postgres_cutover_utils.py`
- `backend/test_postgres_runtime_switch.py`
- `backend/test_saas_auth_jwt.py`

### 10.2 Key manual flows

- login
- scan
- asset metadata
- collection and schedule
- GitHub App sync
- repository sync
- remediation suggestion
- validation
- PR creation
- merge webhook
- verified closure
- automatic branch cleanup after verified closure
- drift detection
- ROI metrics
- CI/CD status-check enforcement
- general IaC security check
- MCP compliance check from an IDE assistant
- compliance report

### 10.3 ROI and enforcement evidence

The investor-facing metrics endpoint is:

- `GET /org/{organization_id}/metrics`

It reports:

- engineering hours saved total
- engineering hours saved per 100 remediations
- target attainment against 200 hours per 100 remediations
- MTTR reduction versus `PQC_ROI_MANUAL_MTTR_HOURS`
- drift events caught
- drift follow-ups created
- manual non-compliant changes reverted

The CI/CD enforcement endpoint is:

- `POST /integrations/ci/status-check`

It returns a status-check shaped response with:

- `state = success`
- `state = failure`
- merge-blocking policy violations

The general IaC security prototype is:

- `POST /iac/security/check`

Current rules detect open SSH ingress and incomplete S3 public access block settings.

The lightweight MCP interface is:

- `POST /mcp`

It lets external IDE assistants call `check_iac_compliance` or `check_repo_enforcement`.

## 11. Current operational caveats

- hosted auth works but is not yet a full browser-native OIDC client
- correlation may not always auto-link assets
- compliance gate currently fails only on `critical` linked assets

## 12. Obvious future hardening areas

- keep lifespan startup/shutdown coverage in regression tests
- normalize any legacy naive timestamp rows during future data migrations
- consider database RLS for stronger shared-SaaS isolation
- split `backend/app.py` into routers/services
- improve correlation behavior for GitHub App-only environments
- move hosted auth from token-in-URL bridge toward full code+PKCE
