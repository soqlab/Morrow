# Morrow API Reference

This file is the grouped route inventory for `backend/app.py`. Selected write endpoints accept `Idempotency-Key` or `X-Idempotency-Key` headers to prevent duplicate side effects during retries. Current protected flows include remediation suggestion, validation, PR creation, CI status/check publishing, GitHub crypto discovery when creating records, autonomous remediation candidates, and cloud HNDL inventory.

It is not a generated OpenAPI dump. It is the maintainers' reference:

- method and path
- purpose
- main request fields
- important behavior notes

All API routes also accept the `/v1` prefix through compatibility middleware, for example `/v1/health` and `/v1/remediations`.

## 1. UI and health

- `GET /`
  - redirects to `/ui/`

- `GET /ui/*`
  - static frontend served from `backend/static/index.html`

- `GET /health`
  - health probe
  - returns `{"status":"ok"}`

- `GET /health/deep`
  - deep health probe
  - verifies Postgres and Redis connectivity

## 2. Auth and session context

- `GET /auth/config`
  - public
  - returns hosted auth mode/config for the UI
  - fields include:
    - `mode`
    - `required`
    - `provider_name`
    - `login_url`
    - `logout_url`
    - `token_help`
    - `bearer_token_supported`
    - `manual_actor_supported`

- `GET /auth/context`
  - returns effective session context
  - fields include:
    - `authenticated`
    - `auth_mode`
    - `organization_id`
    - `actor_id`
    - `actor_role`
    - `auth_error`

## 3. Organizations

- `GET /organizations`
  - admin-only
  - list organizations

- `POST /organizations`
  - admin-only
  - upsert organization
  - request:
    - `id`
    - `name`
    - `plan_type`
    - `subscription_status`

- `POST /organizations/{organization_id}/archive`
  - admin-only
  - marks an organization as archived

- `DELETE /organizations/{organization_id}`
  - admin-only
  - query:
    - `mode` (`archive|purge`, defaults to `archive`)
  - archive mode marks inactive; purge mode deletes org-scoped data

## 4. Compliance reporting

- `GET /org/compliance-report`
  - operator/admin
  - query:
    - `format` (`json` only)
    - `remediation_limit`
    - `asset_limit`
    - `audit_limit`
    - `include_audit`
  - returns organization summary, vulnerabilities, remediations, audit summary, recent alerts

- `GET /org/{organization_id}/metrics`
  - operator/admin
  - returns ROI metrics, engineering-hours-saved estimate, MTTR reduction, and drift analytics

- `GET /org/{organization_id}/drift-analytics`
  - operator/admin
  - returns day-2 governance metrics for drift events and reverted non-compliant changes

## 5. Scan execution

- `POST /scan`
  - legacy synchronous scan
  - request:
    - `targets: [string]`
  - response:
    - `count`
    - `results`
    - `summary`

- `POST /scans`
  - queued durable scan
  - request:
    - `targets: [string]`
  - response:
    - `job_id`
    - `id`
    - `status`
    - `created_at`
    - `progress`

- `POST /scans/synthetic`
  - admin-only
  - inject synthetic results
  - request:
    - `scan_id`
    - `created_at`
    - `results`
    - `auto_close_merged`

- `GET /scans/{scan_id}`
  - get durable scan status/progress

- `GET /scans/{scan_id}/results`
  - get scan with results and summary

- `GET /scans`
  - list recent scan rows
  - query:
    - `limit`

## 6. Baselines and diffs

- `GET /baselines`
  - list baselines

- `POST /baselines`
  - set explicit baseline for one asset
  - request:
    - `host`
    - `port`
    - `baseline_scan_id`

- `POST /baselines/from-scan/{scan_id}`
  - set baselines for all assets in a scan

- `GET /scans/{scan_id}/diff`
  - compare scan to explicit `baseline_scan_id` or stored per-asset baselines

## 7. Assets and inventory

- `GET /assets`
  - list assets
  - query filters:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `tag`
    - `limit`

- `GET /assets/{asset_key}`
  - get asset
  - auto-creates a blank asset record if absent

- `PUT /assets/{asset_key}`
  - upsert/update asset metadata
  - request:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `confidentiality_lifetime`
    - `tags`
    - `notes`
    - `metadata`
    - `repository_id`

- `GET /assets/{asset_key}/history`
  - historical scan snapshots for the asset

- `GET /tags`
  - list distinct tags

## 8. Repositories

- `GET /repositories`
  - list repositories

- `GET /repositories/{name}`
  - get repository by `owner/repo`

## 9. Migration planning and exports

- `GET /scans/{scan_id}/migration-plan`
  - ordered migration steps from current findings

- `GET /scans/{scan_id}/export.csv`
  - export scan results as CSV

## 10. Prioritization and metrics

- `GET /fix-next`
  - prioritized asset list from a scan
  - query:
    - `scan_id`
    - `limit`
    - `min_severity`
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `tag`

- `GET /metrics/scan/{scan_id}/overview`
  - scan overview metrics
  - query:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `top_n`

- `GET /metrics/trends`
  - time-series rollup
  - query:
    - `days`
    - `group_by` (`team|environment|owner|criticality`)
    - `metric` (`avg_score|avg_findings|assets_with_findings`)
    - `top_groups`

## 11. Collections and schedules

- `GET /collections`
  - list collections

- `POST /collections`
  - create/update collection
  - request:
    - `name`
    - `targets_text`

- `GET /collections/{collection_id}`
  - get collection

- `DELETE /collections/{collection_id}`
  - delete collection

- `POST /collections/{collection_id}/scan`
  - start scan from collection targets

- `GET /schedules`
  - list schedules

- `POST /schedules`
  - create schedule
  - request:
    - `collection_id`
    - `interval_minutes`
    - `enabled`

- `GET /schedules/{schedule_id}`
  - get schedule

- `PUT /schedules/{schedule_id}`
  - update schedule
  - request:
    - `interval_minutes`
    - `enabled`

- `DELETE /schedules/{schedule_id}`
  - delete schedule

- `POST /schedules/{schedule_id}/run-now`
  - immediate schedule execution

## 12. Jobs

- `GET /jobs/{job_id}`
  - query Celery result state and metadata

## 13. Integrations: GCP and GitHub

- `POST /integrations/gcp/sync`
  - sync GCP assets
  - request:
    - `credential_id`
    - `project_id`
    - `async_mode`

- `POST /integrations/github/sync`
  - sync GitHub repositories using PAT-style credential
  - request:
    - `credential_id`
    - `org`
    - `visibility`
    - `async_mode`

- `POST /integrations/github/connect-token`
  - simple UI-oriented GitHub connection flow
  - verifies a pasted GitHub token, stores it encrypted as an org-scoped Vault credential, and optionally syncs repositories
  - request:
    - `token`
    - `org`
    - `visibility`
    - `credential_name`
    - `sync_now`
  - response includes:
    - `credential_id`
    - `verified_as`
    - `sync`
  - plaintext token is never returned

- `GET /integrations/github-app/installations`
  - list synced GitHub App installations

- `POST /integrations/github-app/sync-installations`
  - sync GitHub App installations
  - request:
    - `credential_id`
    - `async_mode`

- `POST /integrations/github-app/sync-repositories`
  - sync repositories for one installation
  - request:
    - `credential_id`
    - `installation_id`
    - `async_mode`

- `POST /integrations/correlate-assets`
  - repository correlation job
  - request:
    - `credential_id`
    - `asset_limit`
    - `async_mode`

## 14. Integrations: webhooks and rules

- `POST /integrations/webhooks`
  - create/update outbound webhook
  - request:
    - `id`
    - `name`
    - `url`
    - `secret`
    - `credential_id`
    - `events`
    - `enabled`

- `GET /integrations/webhooks`
  - list configured outbound webhooks

- `DELETE /integrations/webhooks/{webhook_id}`
  - delete outbound webhook

- `POST /integrations/webhooks/{webhook_id}/test`
  - send signed test ping

- `GET /integrations/webhook-events`
  - list queued/sent/failed delivery records

- `POST /integrations/webhook-events/retry`
  - force retry pass for pending/failed deliveries

- `GET /integrations/settings`
  - get integration settings
  - includes generic settings and Cloudflare connector state

- `PUT /integrations/settings`
  - update settings
  - currently supports:
    - `cert_expiring_soon_days`
    - `record_suppressed_events`
    - `cloudflare_credential_id`

- `GET /integrations/rules`
  - list event rules

- `POST /integrations/rules`
  - create/update event rule
  - request can include:
    - `name`
    - `enabled`
    - `webhook_ids`
    - `event_types`
    - `min_severity`
    - `rule_ids`
    - `quantum_score_min`
    - `environments`
    - `teams`
    - `criticalities`
    - `tags`
    - `cooldown_minutes`

- `DELETE /integrations/rules/{rule_id}`
  - delete event rule

- `POST /integrations/rules/test`
  - test rules against a scan-derived event set

## 15. Vault credentials

Vault credential operations are scoped to the active organization context. The same credential name may exist in different organizations.

- `POST /vault/credentials`
  - admin-only
  - create vault credential

- `GET /vault/credentials`
  - operator/admin
  - list credentials without plaintext secret

- `GET /vault/credentials/{cred_id}`
  - operator/admin
  - get one credential without plaintext secret by default

- `GET /vault/credentials/{cred_id}/reveal`
  - operator/admin
  - reveal decrypted secret
  - sensitive endpoint

- `POST /vault/credentials/{cred_id}/rotate`
  - admin-only
  - rotate credential secret in place

## 16. Cloudflare integration

- `POST /integrations/cloudflare/connect`
  - connect existing vault credential to Cloudflare connector
  - request:
    - `credential_id`

- `POST /integrations/cloudflare/rotate`
  - rotate connected Cloudflare token
  - request:
    - `secret`
    - `credential_id` (optional)
    - `reason`

- `GET /integrations/cloudflare/status`
  - connector status summary

- `POST /integrations/cloudflare/verify`
  - verify token using Cloudflare `/user/tokens/verify`

- `GET /integrations/cloudflare/zones`
  - list zones

- `GET /integrations/cloudflare/my-ip`
  - return caller IP for allow-list help

- `GET /integrations/cloudflare/summary`
  - combined connection/verify/zones summary

- `GET /integrations/cloudflare/policy`
  - get current Cloudflare policy profile

- `POST /integrations/cloudflare/policy`
  - set current policy profile
  - request:
    - `min_tls`
    - `force_https`

- `GET /integrations/cloudflare/policy-preview`
  - preview desired zone settings from policy

- `GET /integrations/cloudflare/audit`
  - inspect last apply audit fields

- `GET /integrations/cloudflare/enforcement`
  - get enforcement toggle

- `POST /integrations/cloudflare/enforcement`
  - set enforcement toggle
  - request:
    - `enabled`

- `POST /integrations/cloudflare/audit/clear`
  - clear Cloudflare apply audit state

- `POST /integrations/cloudflare/zones/mock/apply-policy`
  - dry-run/mock policy apply without real zone
  - request:
    - `current_always_use_https`
    - `current_min_tls_version`
    - `policy_override`

- `POST /integrations/cloudflare/zones/{zone_id}/apply-policy`
  - apply policy to real zone
  - query:
    - `dry_run` (`0|1`)

## 17. Compliance gate

- `GET /api/v1/compliance/gate`
  - query:
    - `repo`
  - returns PASS/FAIL based on linked critical assets

- `POST /integrations/ci/status-check`
  - operator/admin
  - GitHub/GitLab-compatible merge/status-check response
  - evaluates linked asset policy and changed IaC snippets
  - can optionally publish a GitHub commit status or GitHub Check Run when `publish_to_github=true`
  - request:
    - `repo`
    - `ref`
    - `provider`
    - `require_verified_closed`
    - `changed_files`
    - `github_credential_id`
    - `publish_to_github`
    - `publish_mode` (`status` or `check_run`)
    - `target_url`

- `POST /v1/guardrails/evaluate-change`
  - viewer/operator/admin
  - also supports external `x-tool-api-key` with `guardrails:evaluate` scope
  - "Security Truth" API for AI coding agents and external tools
  - evaluates proposed repository/IaC changes before merge
  - returns normalized allow/warn/block decision, policy violations, fix suggestions, required actions, and `evidence_id`
  - request:
    - `repo`
    - `ref`
    - `branch`
    - `provider`
    - `actor_type`
    - `actor_id`
    - `tool_source` such as `cipherlens`, `cursor`, `gemini`, `snyk`, `wiz`, or `mcp`
    - `intent`
    - `mode`
    - `changed_files`
    - `proposed_diff`
    - `metadata`
    - `require_verified_closed`
  - response:
    - `decision`: `allow`, `warn`, or `block`
    - `blocking`
    - `evidence_id`
    - `violations`
    - `fix_suggestions`
    - `required_actions`

- `POST /v1/integrations/findings/ingest`
  - operator/admin
  - also supports external `x-tool-api-key` with `findings:write` scope
  - ingests and persists normalized findings from Wiz/Snyk/custom tools into audit/evidence flow
  - request:
    - `tool_source`
    - `integration_type`
    - `findings`
    - `metadata`
  - response includes:
    - `batch_id`
    - `persisted`
    - `finding_ids`
    - `counts_by_severity`

- `GET /v1/integrations/findings`
  - viewer/operator/admin
  - also supports external `x-tool-api-key` with `findings:read` scope
  - lists persisted external findings for the current organization
  - query:
    - `limit`
    - `severity`
    - `status`
    - `tool_source`

- `GET /v1/integrations/findings/{finding_id}`
  - viewer/operator/admin
  - also supports external `x-tool-api-key` with `findings:read` scope
  - returns one persisted external finding and source evidence

- `POST /v1/integrations/findings/{finding_id}/write-path`
  - operator/admin
  - also supports external `x-tool-api-key` with `write_path:request` scope
  - promotes a finding into a guarded write-path fix request and marks it `fix_requested`
  - request:
    - `dry_run`
    - `create_remediation`
    - `desired_outcome`
    - `changed_files`
    - `proposed_diff`
    - `metadata`

- `POST /v1/write-path/fix-requests`
  - operator/admin
  - also supports external `x-tool-api-key` with `write_path:request` scope
  - creates a governed fix-request envelope and evaluates proposed changes through guardrails before any write-path workflow
  - request:
    - `tool_source`
    - `finding_id`
    - `repo`
    - `asset_key`
    - `desired_outcome`
    - `changed_files`
    - `proposed_diff`
    - `dry_run`
    - `metadata`

- `GET /platform/security-truth`
  - platform admin only; requires `x-platform-key`
  - returns vendor/admin metrics for external findings, open high/critical items, blocked write-path changes, and recent guardrail events

- `POST /platform/security-truth/findings/{finding_id}/write-path`
  - platform admin only; requires `x-platform-key`
  - promotes an external finding into a guarded write-path request for the finding's owning organization
  - blocked when the owning organization has feature flag `write_path=false` or strict feature mode is enabled without `write_path=true`

- `GET /platform/admin-mode`
  - platform admin only; requires `x-platform-key`
  - returns vendor/admin runtime mode, key posture, CSP state, feature-flag strictness, and warnings

- `GET /platform/retention/policy`
  - platform admin only; requires `x-platform-key`
  - returns default retention windows and notes that `audit_logs` are immutable evidence

- `POST /platform/retention/run`
  - platform admin only; requires `x-platform-key`
  - defaults to dry-run; counts or deletes aged rows from operational tables
  - request:
    - `dry_run`
    - `scans_days`
    - `scan_results_days`
    - `validation_jobs_days`
    - `webhook_events_days`
    - `login_events_days`
    - `platform_admin_events_days`
    - `limit`

- `GET /platform/customers/{organization_id}/feature-flags`
  - platform admin only; requires `x-platform-key`
  - lists feature flags for one customer organization

- `PUT /platform/customers/{organization_id}/feature-flags`
  - platform admin only; requires `x-platform-key`
  - upserts one feature flag
  - request:
    - `flag_key`
    - `enabled`
    - `reason`

- `POST /iac/security/check`
  - operator/admin
  - checks Terraform/IaC text for general security policy violations
  - current prototype rules:
    - public SSH ingress
    - incomplete S3 public access block

- `POST /mcp`
  - operator/admin
  - lightweight JSON-RPC MCP-style endpoint for IDE/AI assistants
  - supports:
    - `tools/list`
    - `tools/call` with `check_iac_compliance`
    - `tools/call` with `check_repo_enforcement`
    - `tools/call` with `evaluate_change_guardrails`

## 18. Remediations

- `GET /remediations`
  - viewer/operator/admin
  - query:
    - `status`
    - `repo_id`
    - `asset_key_str`
    - `drift_status`
    - `parent_remediation_id`
    - `origin_kind`
    - `limit`

- `GET /remediations/{remediation_id}`
  - viewer/operator/admin
  - get remediation record

- `GET /remediations/{remediation_id}/validations`
  - viewer/operator/admin
  - list validation jobs for one remediation

- `GET /validation-jobs/{validation_job_id}`
  - viewer/operator/admin
  - get validation job

- `POST /remediations/suggest`
  - operator/admin
  - request:
    - `asset_key`
    - `repository_id` or `repository`
    - `file_path`
    - `vulnerability`
    - `github_credential_id`
    - `ref`

- `POST /remediations/{remediation_id}/approve`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/reject`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/validate`
  - operator/admin
  - request:
    - `github_credential_id`
    - `ref`
    - `validator_type`
    - `async_mode`
    - `timeout_seconds`

- `POST /remediations/{remediation_id}/create-pr`
  - operator/admin
  - request:
    - `github_credential_id`
    - `branch_prefix`
    - `base_branch`
    - `title`
    - `body`
    - `allow_unvalidated`

- `POST /remediations/drift/check`
  - operator/admin
  - request:
    - `remediation_id`
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/branches/cleanup`
  - admin-only
  - deletes recorded remediation branches after verified closure
  - request:
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/{remediation_id}/drift/acknowledge`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/drift/revalidate`
  - operator/admin
  - request:
    - `github_credential_id`
    - `async_mode`

- `POST /remediations/{remediation_id}/mark-merged`
  - operator/admin
  - request:
    - `merged_at`

- `GET /remediations/branches/cleanup/status`
  - viewer/operator/admin
  - lists verified-closed remediation branch cleanup state
  - query:
    - `status`
    - `limit`

- `POST /remediations/branches/cleanup`
  - admin-only
  - bulk branch cleanup for verified-closed remediations
  - request:
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/{remediation_id}/branch/cleanup`
  - admin-only
  - cleanup one remediation branch
  - request:
    - `github_credential_id`

## 19. Audit

- `GET /audit/logs`
  - operator/admin
  - query:
    - `limit`
    - `actor_id`
    - `action`
    - `decision`

- `GET /audit/logs/export.csv`
  - operator/admin
  - exports filtered audit logs as CSV

## 20. Inbound GitHub webhook

- `POST /integrations/github/webhook`
  - GitHub webhook receiver
  - verifies `X-Hub-Signature-256` if `GITHUB_WEBHOOK_SECRET` is configured
  - handles `pull_request` close/merge, close-without-merge, reopen, and synchronize events
  - marks matching remediation(s) by PR URL as merged, pr_closed, pr_created, or pr_updated

- `GET /integrations/github/pr-events`
  - viewer/operator/admin
  - list recorded PR lifecycle webhook events
  - query:
    - `pr_url`
    - `limit`

- `GET /integrations/github/status-publishes`
  - viewer/operator/admin
  - list GitHub commit status / Check Run publish attempts
  - query:
    - `repo`
    - `limit`

## 21. Machine-to-machine v1 control plane

- `GET /v1/org/{organization_id}/readiness`
  - viewer/operator/admin
  - returns organization quantum readiness, ROI, drift analytics, active policy, and top next actions

- `GET /v1/assets/{asset_key}/evidence`
  - viewer/operator/admin
  - returns one asset evidence package with latest scan, quantum readiness, policy decision, remediations, validations, and evidence hash

- `GET /v1/evidence/assets/{asset_key}`
  - alias for asset evidence

- `GET /v1/evidence/remediations/{remediation_id}`
  - viewer/operator/admin
  - returns remediation evidence package with validation jobs and linked asset evidence

- `GET /v1/evidence/repos/{owner/repo}`
  - viewer/operator/admin
  - returns repository evidence package, linked asset evidence, remediations, and gate decision

- `GET /v1/repos/{owner/repo}/gate`
  - viewer/operator/admin
  - machine-readable CI/CD gate decision for a repository

- `GET /v1/org/{organization_id}/policy`
  - viewer/operator/admin
  - returns active policy-as-code for the organization

- `PUT /v1/org/{organization_id}/policy`
  - admin-only
  - updates active policy-as-code
  - request:
    - `policy`

- `POST /v1/repositories/discover-ownership`
  - operator/admin
  - scores likely asset-to-repository ownership mappings
  - request:
    - `asset_keys`
    - `repository_names`
    - `link_high_confidence`
    - `high_confidence_threshold`

- `GET /v1/providers/capabilities`
  - viewer/operator/admin
  - returns provider PQC/hybrid TLS capability guidance for Cloudflare, AWS, Google, Azure, Fastly, Akamai, self-managed TLS, and unknown providers

- `GET /v1/providers/{provider}/playbook`
  - viewer/operator/admin
  - returns provider-specific migration playbook with fix-now actions, blocked/verify actions, and evidence expectations

- `POST /v1/remediation-candidates`
  - operator/admin
  - returns autonomous remediation candidates for high-risk assets
  - request:
    - `asset_keys`
    - `create_records`
    - `limit`

- `POST /v1/policy/evaluate`
  - operator/admin
  - evaluates assets against active policy-as-code and can optionally emit policy warning/block events
  - request:
    - `asset_keys`
    - `emit_events`
    - `limit`

### Runtime traffic inventory endpoints

- `POST /v1/runtime/traffic/import`
  - imports runtime observations from CDN/load-balancer/service-mesh/ingress logs or exported telemetry
  - supports `Idempotency-Key`
  - normalizes records into asset keys and can auto-create/update assets

- `GET /v1/runtime/traffic/observations`
  - lists stored runtime observations
  - filters: `asset_key`, `source`, `limit`

- `GET /v1/runtime/assets`
  - returns assets observed from runtime telemetry with sources, providers, protocols, TLS versions, counts, and first/last seen timestamps

Runtime import is intended for log/telemetry ingestion, not packet capture. It provides production evidence while avoiding invasive traffic interception.

### GitHub App enterprise diagnostics

- `GET /integrations/github-app/status?credential_id=123`
  - returns safe GitHub App setup status, synced installations, missing setup steps, and next action guidance
  - does not expose private keys or tokens

- `POST /integrations/github-app/repo-diagnostics`
  - request body: `{ "credential_id": 123, "repository": "owner/repo", "check_live_repo": false }`
  - verifies repository format, credential readiness, repo-scoped token resolution, and optionally live repository metadata access
  - returns `safe_to_attempt_pr` when the PR workflow has enough GitHub access to proceed

Use these before validation/PR creation to explain exactly what is missing in an enterprise GitHub App setup.

### Organization membership APIs

- `GET /organizations/{organization_id}/members`
  - lists users in an organization
  - admin only

- `POST /organizations/{organization_id}/members`
  - creates or updates a member
  - body: `{ "user_id": "user", "role": "viewer|operator|admin", "display_name": "", "email": "", "status": "active|disabled" }`
  - admin only

- `PATCH /organizations/{organization_id}/members/{user_id}`
  - updates member role/profile/status
  - admin only

- `DELETE /organizations/{organization_id}/members/{user_id}`
  - removes a member
  - admin only

- `GET /auth/memberships`
  - lists memberships for the current actor

`/auth/context` now includes the active membership and allowed action summary. Active membership role overrides header/JWT role for that organization.

### Validation sandbox evidence APIs

- `GET /validation/sandbox-profile`
  - returns current validation sandbox policy and security boundary
  - includes isolation mode, network posture, timeout/output limits, Docker settings, secret scrubbing, and traversal protections

- `GET /validation-jobs/{validation_job_id}/evidence`
  - returns machine-readable evidence for one validation job
  - includes sandbox profile, command list, IaC policy result, status, exit code, and validation evidence flags

Validation output is captured with truncation limits, and command timeout metadata is recorded.

