# Production Deployment Runbook

This runbook is for a production-like Cloud Run deployment of PQC Scanner.

## 1. Preflight

- Confirm `backend/.env.production.example` has been copied into your cloud secret/deployment variables.
- Confirm `PQC_AUTH_MODE=jwt`, `PQC_AUTH_REQUIRED=1`, and `PQC_DEFAULT_ROLE=viewer`.
- Confirm Auth0/SAML/JWT issuer, audience, JWKS URL, role claim, and org claim are configured.
- Confirm `PQC_PLATFORM_ADMIN_KEY` is stored in Secret Manager, not source control. In production it is a
  break-glass credential only; operators sign in with SSO (see section 5a).
- Confirm managed Postgres and Redis are available.

## 1a. Integration Self-Test

`scripts/prod-preflight.ps1` reads the environment file and tells you whether the settings look right.
It cannot tell you whether the accounts behind them work. `scripts/check-integrations.py` does: it
loads `backend/.env` the way the app is started with it (byte-order-mark tolerant, and a variable
already exported wins), then reports every integration as **CONFIGURED**, **MISSING** or **ERROR**
with a one-line fix.

```powershell
.\scripts\check-integrations.ps1                   # everything, including outbound probes
.\scripts\check-integrations.ps1 -Offline          # configuration only, no network at all
.\scripts\check-integrations.ps1 -SendTest         # also send ONE labelled alert test message
.\scripts\check-integrations.ps1 -CheckAi          # also spend one cheap AI provider call
.\scripts\check-integrations.ps1 -Json             # same result, machine-readable
python scripts/check-integrations.py --offline     # the same tool without PowerShell
```

What it covers, and what a failure there actually means:

| Area | Checked | Why it matters |
| --- | --- | --- |
| `auth` | `PQC_AUTH_JWT_SECRET` present and at least 32 characters | Support sessions and issued tokens are signed with it. A short one is guessable; a missing one means nobody can hold a session. |
| `vault` | `PQC_VAULT_MASTER_KEY` is a valid Fernet key and round-trips a probe value | It seals customer scanner credentials, operator MFA secrets and recovery codes, alert channel targets and gateway site secrets. A changed key makes all of them unreadable. |
| `sso` | Issuer reachable, discovery document valid and self-consistent, client id and secret present, redirect URI consistent with `PQC_PUBLIC_BASE_URL`, operator roster parsed, MFA policy and break-glass flag | A redirect URI that does not match the public URL is refused by the IdP at sign-in, not at configuration time. |
| `alerts` | Channels read from the database: kind, enabled state, and whether the sealed target still decrypts | A channel whose target no longer decrypts is silently dead: the incident is raised and nothing leaves the building. |
| `redis` | Reachable, and whether rate limits and counters are shared across replicas | Without Redis each replica enforces its own limits, so the effective limit is multiplied by the replica count. |
| `postgres` | Reachable, the app role is `NOSUPERUSER NOBYPASSRLS`, and whether row-level security is applied | A role with `BYPASSRLS` makes every tenant isolation policy decorative. |
| `ai` | Which provider CipherLens will use (`ANTHROPIC_API_KEY`, else `OPENAI_API_KEY`), validated with `--check-ai` | Otherwise the first customer question is where you find out the key was revoked. |
| `deployment` | `PQC_ENVIRONMENT`, `PQC_PUBLIC_BASE_URL`, and the public contact (`PQC_STATUS_PAGE_URL`, `PQC_SMTP_FROM`) | Generated evidence, incident templates and the SSO redirect all point at the public base URL. |

Rules it keeps, so it is safe to run against production and to paste the output into a ticket:

- **Nothing reaches a customer.** The only outbound write is the alert test message, it needs
  `--send-test`, it is labelled `[TEST]`, and `--offline` overrides it.
- **No secret is printed.** Values whose leading marker is public by design are shown the way their
  own dashboard shows them (`sk_live_...4h2p`); everything else is reported as `set, N characters`.
  Database and Redis URLs are never echoed at all.
- Every outbound call has a short timeout, and `--offline` skips all of them.

Exit codes, for a pipeline:

- `0` nothing is broken and nothing required is missing.
- `1` something that is configured is failing — a rejected key, an unreachable service. Fix these first.
- `2` a required production setting is missing. Expected on a laptop that is not going live yet.

## 2. Build And Push Image

```powershell
cd backend
docker build -t REGION-docker.pkg.dev/PROJECT/pqc-containers/backend:VERSION .
docker push REGION-docker.pkg.dev/PROJECT/pqc-containers/backend:VERSION
```

## 3. Provision Infrastructure

```powershell
cd infra/gcp/cloudrun
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

First apply may create secret containers only. Add secret versions, set `deploy_runtime=true`, then apply again.

## 4. Apply Database Hardening

- Run migrations, then create the deferred tables once with the owner role, so the isolation plan has
  something to protect:
  `python -c "import app, db_postgres, json; print(json.dumps(db_postgres.apply_deferred_schemas()))"`
- In the container this is `APP_COMPONENT=migrate` (see `backend/entrypoint.sh`). Off the container —
  a VM, or a staging rehearsal — run the same three steps in the same order, from `backend/`, with
  the **owner** DSN in the environment. Alembic's `0001_baseline` is only a stamp, so running it
  first against an empty database fails with `relation "collections" does not exist`:

  ```powershell
  .venv\Scripts\python.exe -c "import db; db.init_db()"
  .venv\Scripts\alembic.exe -c alembic.ini upgrade head
  .venv\Scripts\python.exe -c "import json, app, db_postgres; print(json.dumps(db_postgres.apply_deferred_schemas()))"
  ```

  The third step must report `"failed": []`. Once the runtime role is hardened it has no DDL
  rights, so anything missed here can never be created at runtime.
- Apply row-level security (section 4a).
- Run tenant-isolation tests against staging: `PQC_TEST_PG_DSN=<staging-owner-dsn> python -m pytest -q backend/test_postgres_rls.py`.

### 4a. Row-level security: the tenant boundary

Until this is applied, tenant isolation rests entirely on `WHERE organization_id = ?` appearing in
every query. That is a convention, not a boundary: one missing clause in one new endpoint is a
cross-tenant read, and nothing in the database would stop it. Row-level security makes the database
refuse, so a missing clause returns too few rows instead of someone else's.

**Create the runtime role first, and create it `NOSUPERUSER NOBYPASSRLS`.** This is the part that is
easy to get wrong and impossible to notice: Postgres exempts superusers and `BYPASSRLS` roles from
*every* policy, on every table, silently. Apply the whole plan over such a role and every check
passes, every policy is listed by `\d+`, and nothing whatsoever is enforced. Managed-Postgres default
users (RDS `postgres`, Cloud SQL `postgres`, Supabase `postgres`) are usually superusers, so a
deployment that simply points `PQC_PRODUCT_DATABASE_URL` at the account the provider handed over has
no isolation at all. The application must connect as a role created for it:

```sql
CREATE ROLE pqc_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '…';
```

Keep the owner/migration role for DDL only, and point `PQC_PRODUCT_DATABASE_URL` / `DATABASE_URL` at
`pqc_app`. The generated SQL refuses to run at all if the role it is given is a superuser or holds
`BYPASSRLS`, rather than appearing to succeed.

Then apply the plan, with the **owner** DSN (only the owner can `ALTER TABLE … ENABLE ROW LEVEL
SECURITY`):

```powershell
# 1. Preview. This is the default: the script changes nothing without --apply.
python scripts/apply-postgres-rls.py --dsn $OWNER_DSN

# 2. Apply, then verify through the runtime role's own eyes.
python scripts/apply-postgres-rls.py --dsn $OWNER_DSN --apply --verify-dsn $APP_DSN
```

`--create-role` will create or repair `pqc_app` for you, taking the password from
`$PQC_APP_DB_PASSWORD` so it never reaches shell history. `--verify-dsn` matters: verifying with the
owner role always reports the role check as failing, because that role is a superuser — the answer
you want is the one the application sees.

What the migration does, per org-scoped table: grants the runtime role baseline DML (RLS restricts,
it never grants), then creates the isolation policy, then `ENABLE` and `FORCE ROW LEVEL SECURITY` —
in that order, because a table left with FORCE and no policy returns zero rows to everyone. Tables
absent from the schema are skipped with a `NOTICE` instead of aborting the run and leaving the rest
unprotected. It is idempotent and runs in a single transaction, so **re-run it after every migration
that adds a tenant table**; the verify step is what tells you whether the new table was picked up.

`GET /platform/rls-plan` and `GET /admin/postgres-rls/plan` return the same SQL, plus the operator
rule below, for review outside the deploy host. `GET /admin/postgres-rls/verify` reports the live
state at any time.

#### How the tenant reaches the database

The application publishes two session settings on **every** connection checkout, and clears them on
release (`backend/services/tenant_scope.py`):

| Setting | Meaning |
| --- | --- |
| `app.current_organization_id` | The tenant this connection may read and write. Empty or unset matches **no** row — including rows whose `organization_id` is itself empty. |
| `app.platform_scope` | `'on'` only inside an explicitly privileged, cross-tenant code path. |

Operators never set these by hand. They are written on checkout so a pooled connection cannot serve
tenant B while still carrying tenant A, and cleared on release so an idle pooled connection carries
no tenant at all. All of it is a no-op on SQLite.

#### The operator rule

**Cross-tenant access is allowed only while `app.platform_scope = 'on'`, and exactly three things may
turn it on:**

1. A `/platform/*` or `/vendor-admin` request that has **already** authenticated against the platform
   credential or an operator SSO session, and whose role has already been accepted for that
   operation. It is set in `app._require_platform_admin` after those checks, never before, so an
   unauthenticated request never reaches a connection with the hatch open.
2. A named background writer that spans tenants by design: the security-journal flusher, the usage
   rollups, and the alert dispatcher.
3. API-key verification, which has to find the key row before any tenant is known — the key's
   organization is the answer it returns. Every other operation on API keys is tenant-scoped.

Every entry is recorded: an INFO log line (`[PQC RLS] cross-tenant scope entered: reason=… actor=…`)
plus a bounded in-process ledger, on top of the existing operator audit trail in
`platform_admin_events` for case 1.

The escape hatch is a session flag in the policy text rather than `BYPASSRLS` on the role
deliberately. `BYPASSRLS` exempts a role from every policy on every statement forever, with no record
that the exemption was ever used. A flag has to be turned on by a named code path, is off again the
moment that path returns, is visible in `\d+ <table>`, and can be counted.

#### Not covered, and why

Six tables carry an `organization_id` but get no isolation policy, because they are the vendor's own
records rather than the customer's: `platform_admin_events`, `platform_customer_notes`,
`platform_feature_flags`, `platform_autopatches`, `platform_auth_events`, `platform_request_events`.
No customer request path reads or writes any of them. The list is explicit in
`backend/services/postgres_rls.py` so that a tenant table someone genuinely forgot still shows up as
a failure instead of hiding among them — the verifier reports any org-scoped table in the live schema
that is on neither list.

`organizations` is also outside the plan, for a different reason: it is the tenant *registry* rather
than any tenant's data, and paths that run inside ordinary customer requests read it across tenants
on purpose — notably the suspension cache, which builds a process-wide snapshot of every
organization's status and would silently stop enforcing suspension for everyone else if it could only
see the requesting tenant. What that leaves exposed is the tenant roster (id, display name, plan,
status), reachable only through authenticated endpoints that already filter to the caller's
memberships.

SQLite-backed features are outside all of this: SQLite has no row-level security, so those tables are
isolated by query filters only. The list is in `docker-compose.prod.yml`.

## 5. Verify Runtime

- Open `/health` and confirm no production-blocking warnings except expected environment notes.
- Open `/vendor-admin/` and sign in with **Sign in with SSO** (or a named operator key) plus your authenticator
  code. In production the shared platform key is refused unless break-glass is on.
- Open **Security › Launch readiness** (or `/platform/readiness` and `/platform/go-live-gate`) and fix every
  failed check, including **Operator SSO**, **Operator MFA required** and **Shared key is break-glass only**.
- `scripts/check-go-live-gate.ps1` falls back to `PQC_PLATFORM_ADMIN_KEY` from `backend\.env`, and in
  production that credential is **refused** (`break_glass_disabled`). Pass a named operator key
  instead, and verify MFA for it once first, or every call answers 401 `mfa_enrolment_required`:

  ```powershell
  # one-time, per operator key: POST /platform/mfa/enroll/start, then /platform/mfa/enroll/confirm
  .\scripts\check-go-live-gate.ps1 -BaseUrl https://<host> -PlatformKey $OPERATOR_KEY
  ```

  `/platform/whoami`, `/platform/auth-config` and the `/platform/mfa/*` routes are the only ones a
  key may use before MFA elevation.
- Run the checklist in `docs/pqc-full-test-plan.pdf`.

## 5a. Operator Console Production Settings

Every variable below has a commented section in `.env.prod.example`. The operator procedures are in
[OPERATOR_CONSOLE_GUIDE.md](OPERATOR_CONSOLE_GUIDE.md); IdP details are in "Operator SSO, MFA and
break-glass" in [COMPLETE_DOCUMENTATION.md](COMPLETE_DOCUMENTATION.md).

**Operator SSO and MFA (required by the go-live gate)**

- `PQC_ENVIRONMENT=production` (or `staging`): MFA defaults on and the shared key is refused.
- `PQC_ADMIN_OIDC_ISSUER`, `PQC_ADMIN_OIDC_CLIENT_ID`, `PQC_ADMIN_OIDC_CLIENT_SECRET` (empty for a public PKCE
  client), and `PQC_ADMIN_OPERATOR_ROLES` (`email=role` roster) or `PQC_ADMIN_OIDC_ALLOWED_DOMAINS`.
- Register the redirect URI `https://<console host>/vendor-admin/sso/callback` (or set
  `PQC_ADMIN_OIDC_REDIRECT_URI`); `PQC_PUBLIC_BASE_URL` must be the public URL.
- Do not set `PQC_ADMIN_REQUIRE_MFA=0`.
- Test SSO sign-in, a denied non-roster account, MFA enrolment and a step-up prompt against the real identity
  provider in staging. This has only been tested with a mocked provider.

**Break-glass off**

- Leave `PQC_ALLOW_BREAK_GLASS_KEY` unset. Keep `PQC_PLATFORM_ADMIN_KEY` in the secret manager for emergencies
  only; lower `PQC_PLATFORM_ADMIN_KEY_ROLE` once named operators exist. If break-glass is used, remove the flag,
  restart and rotate the shared key afterwards.

**Secrets that new features depend on**

- `PQC_AUTH_JWT_SECRET`: required for vendor support sessions (without it, starting one answers 503).
- `PQC_VAULT_MASTER_KEY`: required for operator MFA secrets and for Slack, PagerDuty and webhook alert channel
  targets (those channel types cannot be saved without it).
- `PQC_USAGE_ACTOR_SALT`: set a long random value and keep it stable, so rotating the vault or JWT key does not
  reset distinct-user counts.

**Alert dispatcher**

- Runs inside each API process every 60 seconds by default (`PQC_ALERT_DISPATCH_ENABLED=1`,
  `PQC_ALERT_DISPATCH_INTERVAL_SECONDS`); only one server dispatches at a time.
- For email channels and "Email the invite": `PQC_SMTP_HOST`, `PQC_SMTP_PORT`, `PQC_SMTP_USER`,
  `PQC_SMTP_PASSWORD`, `PQC_SMTP_FROM`, `PQC_SMTP_STARTTLS` (or `PQC_PLATFORM_SMTP_ORG_ID`).
- After deploy, add a channel in **Operations › Alert routing**, press **Send test**, and check the
  **Alert routing dispatcher** row in **Operations › Background jobs**.

**Redis for shared rate limits (required with more than one API replica)**

- Set `REDIS_URL` (or `CELERY_BROKER_URL`) whenever more than one API replica runs. Every replica then shares
  the per-organization limits (`admin_rate_limits` and plan limits), the per-organization request cap
  (`PQC_RATE_LIMIT_MAX_REQUESTS`) and the per-IP limits (`PQC_RATE_LIMIT_*`). Without it each replica counts
  separately and N replicas allow up to N times every limit.
- A Redis outage falls back to per-replica counting and does not block requests; each replica retries Redis
  after 5 seconds.
- The other short-lived caches do not need Redis: each replica re-reads token revocations (10 s,
  `PQC_TOKEN_REVOCATION_CACHE_SECONDS`), API key verifications (15 s, `PQC_API_KEY_CACHE_SECONDS`), support
  sessions (at most 5 s), operator sessions (5 s in the middleware, checked in full on every console route) and
  maintenance mode (5 s) from Postgres. A revocation takes effect at once on the replica that handled it and
  within that window everywhere else. The alert dispatcher lease is a Postgres row, so one replica dispatches.

**Verify against Postgres and Redis**

The default test run uses SQLite and in-process counters. Before a release that touches SQL or rate limiting,
run the gated suites against disposable servers (the Postgres role needs `CREATEDB`; the tests create and drop
their own database, and use Redis DB index 1):

```bash
cd backend
PQC_TEST_PG_DSN=postgresql://pqc:pqctest@127.0.0.1:55432/pqc_test PQC_TEST_REDIS_URL=redis://127.0.0.1:56379/1 \
  .venv/Scripts/python.exe -m pytest -q test_postgres_integration.py test_redis_integration.py test_sql_schema_conformance.py
```

Start the servers with `docker run -d --name pqc-test-pg -e POSTGRES_USER=pqc -e POSTGRES_PASSWORD=pqctest -e
POSTGRES_DB=pqc_test -p 55432:5432 postgres:16-alpine` and `docker run -d --name pqc-test-redis -p 56379:6379
redis:7-alpine`. Without the variables those tests are skipped.

**Vault key rotation**

- `scripts/rotate-vault-master-key.py` re-encrypts integration credentials, gateway site keys, operator MFA
  secrets, GitHub tokens and alert channel targets (Slack, PagerDuty and webhook). Rehearse without `--apply`,
  then apply in a maintenance window with a backup. Afterwards press **Send test** on one alert channel.
- Set `PQC_EVIDENCE_SIGNING_KEY` before rotating so existing evidence keeps verifying.

## 6. Rollback

- Keep the previous Cloud Run revision available.
- If deployment fails, route traffic back to the previous revision.
- Restore DB only if a migration caused data corruption and rollback SQL cannot safely recover.
