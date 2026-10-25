# Production Hardening Checklist

Use this before moving from controlled pilot to production enterprise deployment.

## Identity

- [ ] Auth0 or hosted JWT configured.
- [ ] Issuer/audience validation enforced.
- [ ] Header/dev auth disabled in production.
- [ ] Viewer/operator/admin roles tested.
- [ ] Org claim mapping tested.

## Database

- [ ] Postgres is the primary product DB.
- [ ] Backup schedule configured.
- [ ] Restore test completed.
- [ ] Migration rollback procedure written.
- [ ] Postgres RLS applied in staging.
- [ ] RLS isolation tests pass.
- [ ] App DB role has no `BYPASSRLS`.

## Secrets

- [ ] `MORROW_VAULT_MASTER_KEY` stored in cloud secret manager.
- [ ] GitHub App private key stored in Vault/secret manager.
- [ ] Webhook secrets stored in Vault.
- [ ] Secret reveal restricted to admin.
- [ ] Secret rotation procedure tested.
- [ ] Logs checked for secret leakage.

## GitHub App

- [ ] App installed only on approved pilot repos.
- [ ] Repository sync works.
- [ ] Token minting works.
- [ ] Branch/commit/PR creation works.
- [ ] Required check context is documented: `morrow/security-policy`.
- [ ] Branch protection behavior verified.

## Runtime Services

- [ ] API service health endpoint monitored.
- [ ] Worker service monitored.
- [ ] Beat/scheduler monitored.
- [ ] Redis monitored.
- [ ] Failed job alerts configured.
- [ ] Webhook delivery retry queue monitored.

## Network And Deployment

- [ ] HTTPS enforced.
- [ ] CORS locked to approved origins.
- [ ] Cloud Run/service account permissions minimized.
- [ ] Public endpoints reviewed.
- [ ] Admin endpoints restricted.
- [ ] Rate limits reviewed.

## Evidence And Compliance

- [ ] Compliance report reviewed with customer.
- [ ] Audit log export path documented.
- [ ] Data deletion/export process documented.
- [ ] Disclaimers reviewed: readiness mapping, not certification.
- [ ] Pilot scope documented.

## Go/No-Go

Do not move to production if any of these are incomplete:

- Real login does not work.
- GitHub App flow cannot create/check PRs.
- Backup/restore has not been tested.
- RLS/tenant isolation has not been verified.
- Secrets appear in logs or API responses.
- No owner exists for operational alerts.
