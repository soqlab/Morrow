# Security Operations Runbook

## Production Gates

Use `/platform/readiness` from the vendor admin portal. Enterprise launch is blocked until all checks pass.

Also run:

- `/platform/admin-mode` to confirm production mode, CSP, feature-flag strictness, and admin-key posture.
- `/platform/go-live-gate` to get the machine-readable final release decision.
- `scripts/verify-cloud-deployment.ps1` against the deployed domain to verify health endpoints and browser security headers.

## Retention Operations

Retention is deliberately conservative:

- `/platform/retention/policy` returns the default policy and confirms that audit logs are immutable.
- `/platform/retention/run` defaults to `dry_run=true`; archive the dry-run output before deleting anything.
- Audit logs are not deleted by the retention job because they are evidence records.
- Run retention after backups are confirmed healthy.

Recommended cadence during pilot: dry-run weekly, delete monthly after review.

## Feature Flag Operations

Use customer-level feature flags to disable risky workflows without shipping code:

- `write_path` controls Security Truth write-path promotion.
- `remediation_candidates` controls autonomous remediation candidate creation.
- `github_pr_creation` controls GitHub PR creation from remediations.
- `demo_lab` controls Demo Lab seeding.

Default behavior is backwards-compatible unless `PQC_FEATURE_FLAGS_STRICT=1` is enabled. For production enterprise pilots, enable strict mode only after each customer has explicit flags configured.

## Incident Response

1. Triage severity and affected tenant(s).
2. Preserve logs and database snapshots.
3. Rotate relevant secrets if credential exposure is possible.
4. Disable affected integrations or suspend affected tenant if needed.
5. Notify customer contacts according to contract and legal guidance.
6. Record timeline, root cause, containment, and corrective actions.

## Secret Rotation

- Rotate `PQC_PLATFORM_ADMIN_KEY` after any operator offboarding or suspected exposure.
- Rotate GitHub webhook secrets on integration compromise.
- Rotate `PQC_VAULT_MASTER_KEY` only with a tested re-encryption plan.
- Rotate OpenAI/API provider keys through Secret Manager and restart services.

## Security Review Cadence

- Dependency scan before every release.
- Container image scan before every release.
- Secret scan before every release.
- External penetration test before enterprise GA and after major auth/data-plane changes.

## Audit Review

Review vendor admin events weekly during pilot:

- customer suspension/resume
- plan/status edits
- admin notes changes
- feature flag changes
- retention dry-run/delete events
- failed platform admin attempts from logs
