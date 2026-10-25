# Security Review Checklist

Run before any paid pilot, production deployment, or major write-path release.

## Application Security

- [ ] Header auth disabled in production.
- [ ] JWT/SAML issuer, audience, JWKS, org claim, and role claim verified.
- [ ] Viewer/operator/admin permissions tested.
- [ ] Platform admin route is not linked from customer UI.
- [ ] `/platform/*` requires platform admin auth.
- [ ] Assistant prompt-injection guardrail tests pass.
- [ ] Write-path requests require guardrails and audit.

## Data Security

- [ ] Managed Postgres configured.
- [ ] RLS applied and forced.
- [ ] App DB role is non-superuser and does not have `BYPASSRLS`.
- [ ] `verify_rls.py` output archived.
- [ ] Backups configured.
- [ ] Restore drill completed.

## Secrets

- [ ] No production secrets in `.env`, source code, docs, test fixtures, or videos.
- [ ] Cloud secret manager configured.
- [ ] GitHub App private key stored securely.
- [ ] `MORROW_VAULT_MASTER_KEY` rotated from local/demo value.
- [ ] Webhook secrets configured and verified.

## CI / Supply Chain

- [ ] Unit tests pass.
- [ ] Alembic migrations pass.
- [ ] Ruff check passes.
- [ ] Bandit scan reviewed.
- [ ] pip-audit reviewed.
- [ ] Secret scan reviewed.
- [ ] Runtime artifacts are not tracked.
- [ ] `scripts/check-go-live-gate.ps1` returns `go_live_allowed=true` in production.
- [ ] `scripts/load-smoke.ps1` passes against staging with no 5xx errors.

## Infrastructure

- [ ] HTTPS custom domain configured.
- [ ] CORS allowlist configured.
- [ ] Rate limits enabled.
- [ ] Logs/metrics/errors configured.
- [ ] Alerts configured for auth failures, write-path denial spikes, worker failure, and database errors.

## Customer Pilot

- [ ] Pilot scope approved in writing.
- [ ] One real repo end-to-end remediation loop completed.
- [ ] Audit/evidence export reviewed with customer.
- [ ] Known limitations documented.
