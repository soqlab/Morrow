# Production Readiness Checklist

Status: pre-production until every required item is complete.

## Required Before Enterprise / Paid Pilot

- [ ] Deploy API, worker, and beat to Cloud Run or equivalent managed runtime.
- [ ] Preserve runtime hardening in deployment: no-new-privileges, dropped Linux capabilities where supported, non-root runtime user, and bounded logs.
- [ ] Use managed Postgres, not local SQLite.
- [ ] Use managed Redis for Celery broker/result backend.
- [ ] Store `OPENAI_API_KEY`, `MORROW_VAULT_MASTER_KEY`, database URL, Redis URL, and `MORROW_PLATFORM_ADMIN_KEY` in a cloud secret manager.
- [ ] Configure `MORROW_AUTH_MODE=jwt`.
- [ ] Configure `MORROW_AUTH_REQUIRED=1`.
- [ ] Configure `MORROW_DEFAULT_ROLE=viewer`.
- [ ] Configure JWT issuer, audience, JWKS URL, role claim, and org claim.
- [ ] Replace local/header auth with Auth0/SAML/hosted identity provider.
- [ ] Enable MFA for vendor/admin users in the identity provider.
- [ ] Configure `MORROW_ALLOWED_HOSTS` with exact app/admin/API hostnames; do not use `*`.
- [ ] Configure `MORROW_CORS_ORIGINS` with exact browser origins; keep `MORROW_CORS_ALLOW_ALL=0`.
- [ ] Apply and verify Postgres RLS policies for tenant tables.
- [ ] Confirm the application database role does not have `BYPASSRLS`.
- [ ] Run `python verify_rls.py` from `backend/` against the production/staging database and keep the JSON output as deployment evidence.
- [ ] Configure HTTPS custom domain for customer app.
- [ ] Keep `/vendor-admin/` unlinked from customer UI and protect `/platform/*` with platform admin auth.
- [ ] Verify `/vendor-admin/traffic.html` works with `x-platform-key` and stores no bodies, query strings, cookies, or authorization headers.
- [ ] Verify platform admin roles: `owner`/`operator` can write, `support`/`auditor` remain read-only.
- [ ] Verify `/platform/traffic/export.ndjson` and `/platform/traffic/otel` can be ingested by SIEM/OpenTelemetry.
- [ ] Set `MORROW_TRAFFIC_PERSIST_TO_DB=1` in production.
- [ ] Keep traffic/IP monitoring behind SSO/VPN or an identity-aware proxy; set `MORROW_TRUST_PROXY_HEADERS=1` only behind a trusted proxy.
- [ ] Review `/platform/state/coverage`; keep `MORROW_API_REPLICA_COUNT=1` until auxiliary SQLite tables are empty/archived and endpoint-level migration is complete.
- [ ] Set `MORROW_AIRLOCK_SIGNING_KEY` and `MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE=1` before accepting customer collector evidence.
- [ ] Confirm `MORROW_ALLOW_PLATFORM_KEY_QUERY=0`; admin keys must only be accepted via `x-platform-key`.
- [ ] Confirm `MORROW_CSP_ENABLED=1` and archive response headers from `/status`.
- [ ] Review `/platform/admin-mode` from the vendor admin portal and resolve every warning.
- [ ] Confirm production startup guard passes without `MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP=1`.
- [ ] Treat `MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP=1` as break-glass only; never leave it enabled for normal production service.
- [ ] Review `/platform/retention/policy`; run `/platform/retention/run` first in dry-run mode and archive output.
- [ ] Configure feature flags for controlled rollouts of risky flows:
  - `write_path`
  - `remediation_candidates`
  - `github_pr_creation`
  - `demo_lab`
- [ ] Run the full checklist in `docs/pq-full-test-plan.pdf`.
- [ ] Review and update `docs/THREAT_MODEL.md`.
- [ ] Complete `docs/SECURITY_REVIEW_CHECKLIST.md`.
- [ ] Follow the customer onboarding runbook for the first controlled buyer pilot.
- [ ] Review [`docs/DATA_BOUNDARY_AND_PRIVACY.md`](DATA_BOUNDARY_AND_PRIVACY.md) and the
      commercial pack: market launch pack, controlled pilot offer, pricing and packaging,
      support and incident response, and the DPA template.
      (All of the commercial documents named above are maintained privately rather than in
      this repository -- they are vendor-confidential. See docs/OPEN_SOURCE_READINESS.md.)
- [ ] Have counsel approve `/privacy`, `/terms`, and the DPA template before paid customer use.
- [ ] Confirm `/launch`, `/trust-passport-demo`, `/enterprise-admin`, `/security`, and `/support` contain current buyer-safe claims and contact details.
- [ ] Run the launch collateral check and archive the output:

```powershell
.\scripts\launch-collateral-check.ps1 -BaseUrl https://YOUR-PRODUCTION-DOMAIN
```

- [ ] Run the production handoff report and archive the output:

```powershell
.\scripts\prod-handoff.ps1 -EnvFile .env.prod -BaseUrl https://YOUR-PRODUCTION-DOMAIN
```

- [ ] Exercise backup and restore for Postgres. The drill dumps the database, restores it into a
      scratch database, compares the two, then drops the scratch copy — pass the owner DSN, since a
      least-privilege runtime role cannot create the scratch database, and without a DSN the
      Postgres half is skipped entirely:

```powershell
.\scripts\backup-restore-drill.ps1 -Dsn "postgresql://OWNER:PASSWORD@HOST:5432/DBNAME"
```
- [ ] Configure production logs, metrics, alerts, and error reporting.
- [ ] Run the automated go-live gate and archive output:

```powershell
.\scripts\check-go-live-gate.ps1 -BaseUrl https://YOUR-PRODUCTION-DOMAIN -Json
```

- [ ] Run cloud deployment verification and archive output:

```powershell
.\scripts\verify-cloud-deployment.ps1 -BaseUrl https://YOUR-PRODUCTION-DOMAIN -PlatformKey $env:MORROW_PLATFORM_ADMIN_KEY -ExpectHsts
```

- [ ] Generate and archive a release evidence bundle:

```powershell
.\scripts\release-evidence-bundle.ps1 -BaseUrl https://YOUR-PRODUCTION-DOMAIN -PlatformKey $env:MORROW_PLATFORM_ADMIN_KEY -RunBrowserSmoke -ExpectHsts
```

- [ ] Run a basic load smoke test against staging:

```powershell
.\scripts\load-smoke.ps1 -BaseUrl https://YOUR-STAGING-DOMAIN -Requests 100 -Concurrency 10
```

- [ ] Run an external security review / penetration test before enterprise GA.

## Local Hardening Already Applied

- Vendor admin key added to local `.env` if it was missing.
- `MORROW_AUTH_REQUIRED=1` added locally if it was missing.
- `MORROW_DEFAULT_ROLE=viewer` added locally if it was missing.
- Production env template added at `backend/.env.production.example`.

## Manual Inputs Still Required

- Auth0/SAML tenant details.
- Production domain names.
- Cloud project and secret manager setup.
- GitHub App production installation.
- Counsel approval for public legal pages, DPA template, support process, and customer-facing terms.
