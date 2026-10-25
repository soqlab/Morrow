# Morrow User Guide

This guide explains how to use Morrow as an operator, security lead, or administrator.

It covers:

- login and access
- first-time setup
- scanning
- assets, ownership, and environment metadata
- collections and schedules
- repository sync and linking
- remediations
- validation, pull requests, and verification
- drift detection
- webhooks and notifications
- dashboard and compliance reporting
- deployment and runtime configuration
- Quantum Airlock, Trust Passport, and enterprise admin pages
- CAM/API transparent proxy deployment
- Autonomous Security Mesh
- common troubleshooting steps

## 1. What the product does

Morrow is a workflow platform for external crypto and TLS risk.

At a high level it does this:

1. scans internet-facing assets
2. stores the results and keeps history
3. links assets to the repository that owns the fix
4. creates an AI-assisted remediation suggestion
5. validates the suggested change before opening a PR
6. opens the PR in GitHub
7. verifies the issue is actually closed after merge
8. keeps monitoring for drift later

The product is strongest when used as a continuous loop, not a one-off scan tool.

## 2. User roles

The app uses three main roles.

- `viewer`
  - can read dashboards, assets, scans, reports, and remediation state
  - cannot change data or trigger write actions

- `operator`
  - can scan, classify assets, create remediations, validate, approve, and run most day-to-day operations

- `admin`
  - can manage credentials, organizations, auth-sensitive actions, synthetic verification scans, and operational setup

## 3. How to access the app

### Hosted / SaaS mode

Open the application URL in a browser and log in through the configured identity provider.

Example hosted URLs:

- app UI: `https://YOUR_DEPLOYED_HOST/ui/`
- machine-readable org report: `https://YOUR_DEPLOYED_HOST/org/compliance-report?format=json`

### Local Docker mode

From `backend/`:

```powershell
docker compose up -d
```

Then open:

- UI: `http://localhost:8000/ui/`

### Public and admin pages

Useful routes:

- public launch page: `/launch`
- Trust Passport demo: `/trust-passport-demo`
- Enterprise Admin overview: `/enterprise-admin`
- vendor operations portal: `/vendor-admin/`
- platform traffic monitor: `/vendor-admin/traffic.html`
- security boundary: `/security`
- support and incident process: `/support`

The vendor operations portal is separate from the customer console and requires the platform admin
key. Do not expose it to customer users as a normal navigation item.
The traffic monitor also requires the platform admin key and stores only request metadata: no
bodies, query values, cookies, authorization headers, API keys, or uploads.
- health check: `http://localhost:8000/health`

### Local Python mode

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Then open:

- UI: `http://localhost:8000/ui/`

## 4. Login and session handling

The platform supports two auth patterns:

- `headers` mode
  - mainly for local development and tests
  - the UI can simulate actor/role headers

- `jwt` mode
  - for hosted environments
  - the UI uses a real bearer token from the identity provider

### If you see `jwt token is expired`

Clear the stored token in the browser and log in again.

In the browser console:

```javascript
localStorage.removeItem("morrow_auth_bearer_token");
location.reload();
```

Then click `Login` again.

## 5. First-time setup checklist

Use this order for a clean first setup.

### Step 1: confirm the organization context

In a multi-tenant deployment, every asset, repo, remediation, and report belongs to an organization.

If you are in a new environment, confirm:

- your organization exists
- your token or local actor context resolves to the correct `org_id`

### Step 2: add credentials to the vault

Credentials are stored through the vault API and used by GitHub, webhooks, and optional connectors.

Supported patterns include:

- `github_app`
- `github`
- `webhook`
- `generic`

Example API call:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/vault/credentials" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin"} `
  -ContentType "application/json" `
  -Body '{"name":"github-app-main","provider":"github_app","secret":"<secret or key material>","meta":{}}'
```

Important:

- normal credential listing hides the raw secret
- only admins should use reveal or rotate actions

### Step 3: sync GitHub App installations

If you use a GitHub App credential, sync installations first:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/github-app/sync-installations" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"async_mode":false}'
```

Then list installations:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/integrations/github-app/installations" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Step 4: sync repositories for an installation

Use the returned `installation_id`:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/github-app/sync-repositories" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"installation_id":112874196,"async_mode":false}'
```

Then confirm repositories exist:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/repositories" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Step 5: set up webhook destinations if needed

Create outbound webhooks for alerts such as:

- `validation.failed`
- `remediation.merged`
- `remediation.drifted`
- `remediation.drift_followup_created`

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"name":"ops-channel","url":"https://example.com/webhook","secret":"shared-secret","events":["validation.failed","remediation.merged"],"enabled":true}'
```

## 6. The main screens and what they are for

### Dashboard

Use it to answer:

- how much risk exists now
- how much is being fixed
- how many remediations are verified closed
- how many items drifted later

The dashboard is the best opening screen for demos and the best daily posture view for operators and security leads.

### Assets

Use it to:

- open a specific asset
- assign owner, team, environment, and criticality
- attach tags
- inspect scan history
- confirm repository linkage

### Repositories

Use it to:

- confirm GitHub sync worked
- inspect which repos exist in the platform
- cross-check repo-to-asset linkage

### Collections

Use it to save reusable scan target groups.

### Schedules

Use it to run recurring scans from collections.

### Remediations

Use it to:

- create suggestions
- review content
- approve or reject
- validate
- create PRs
- inspect verified closure
- inspect drift and follow-up work

### Integrations / webhooks

Use it to:

- manage outbound notifications
- test webhook delivery
- inspect webhook delivery failures

### Compliance report

Use it to:

- generate machine-readable evidence
- inspect summary metrics
- review remediation and drift state
- feed dashboards or external systems

## 7. Running a scan

There are two scan styles:

- synchronous scan: `POST /scan`
- asynchronous scan: `POST /scans`

The UI typically uses a simple scan workflow. For automation and persistence testing, the async path is the more complete flow.

### One-time scan (simple)

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scan" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"targets":["www.cloudflare.com:443"]}'
```

This returns scan results directly.

### Persistent async scan

Create the scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scans" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"targets":["www.cloudflare.com:443"]}'
```

Poll status:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/scans/<scan_id>" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

Fetch stored results:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/scans/<scan_id>/results" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### What scan results mean

Important fields include:

- `host`
- `port`
- `risk_level`
- `tls_version`
- `key_type`
- `sig_algorithm`
- `findings`
- `pq_recommendation`
- `quantum_risk_score`

Use scans to establish current exposure and to build historical trends.

## 8. Managing assets

An asset is the operational object that ties scan results to ownership and downstream workflow.

### Open or create an asset record

If an asset is not yet classified, opening it creates a blank metadata record.

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### Recommended asset fields

Set these consistently:

- `owner`
  - accountable individual or group
  - example: `web-team`

- `team`
  - delivery team responsible
  - example: `platform`

- `environment`
  - use a fixed vocabulary
  - recommended:
    - `prod`
    - `staging`
    - `dev`

- `criticality`
  - recommended:
    - `low`
    - `medium`
    - `high`

- `tags`
  - example:
    - `internet`
    - `tls`
    - `customer-facing`

### Update asset metadata

Example:

```powershell
Invoke-RestMethod -Method Put -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"owner":"web-team","team":"platform","environment":"prod","criticality":"high","tags":["internet","tls"]}'
```

### Asset history

Asset history shows how risk changed over time.

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443/history" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 9. Collections

A collection is a saved group of targets.

Use collections when:

- you want repeatable scans
- you want to schedule recurring checks
- you want to separate environments or customers

### Create a collection

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/collections" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"name":"Cloudflare Demo","targets_text":"www.cloudflare.com:443"}'
```

### Run a collection

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/collections/1/scan" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 10. Schedules

A schedule runs a collection automatically on an interval.

### Create a schedule

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/schedules" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"collection_id":1,"interval_minutes":1440,"enabled":true}'
```

### Schedule fields

- `collection_id`
  - the collection being monitored

- `interval_minutes`
  - scan frequency

- `enabled`
  - whether the schedule is active

### Run a schedule immediately

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/schedules/1/run-now" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 11. Repository linkage and correlation

Repository linkage is the bridge from asset risk to code ownership.

### Automatic correlation

The platform supports a correlation pass that searches repo content for asset hints.

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/correlate-assets" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"asset_limit":500,"async_mode":false}'
```

### Manual repository linkage

If correlation does not link an asset automatically, set the repository manually on the asset.

Example:

```powershell
Invoke-RestMethod -Method Put -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"owner":"web-team","team":"platform","environment":"prod","criticality":"high","tags":["internet","tls"],"repository_id":1}'
```

This is a valid operational fallback and often the fastest path for demos or early deployments.

## 12. Compliance gate

The compliance gate answers:

- does this repository have linked critical assets?

### Run the gate

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/compliance/gate?repo=yasseennandally/hello-world" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"}
```

### How to read the result

- `status = PASS`
  - no linked critical asset currently fails the gate

- `status = FAIL`
  - one or more linked critical assets still carry critical posture

Use the compliance gate to move from "scan result" to "release / policy decision".

## 13. Creating a remediation

A remediation is a proposed code fix tied to:

- an asset
- a repository
- a file
- a vulnerability description

### Create a suggestion

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/suggest" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"asset_key":"www.cloudflare.com:443","repository_id":1,"file_path":"demo_asset_match.tf","vulnerability":"Critical TLS exposure for a production internet-facing asset. Update this infrastructure to improve post-quantum crypto agility and remove weak TLS posture assumptions.","github_credential_id":15}'
```

### What the remediation stores

- `original_content`
- `suggested_content`
- `suggested_fix`
- lifecycle status
- later PR, merge, verify, and drift metadata

### Guardrails

The remediation layer blocks certain unsafe change classes, including:

- IAM changes
- firewall changes
- AWS security group changes

If a suggestion request contains forbidden classes, the API returns a guardrail error instead of creating a remediation.

## 14. Approval and rejection

After suggestion, a remediation should be reviewed.

### Approve

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/approve" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"looks good"}'
```

### Reject

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/reject" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"needs a different approach"}'
```

## 15. Validation sandbox

Validation is the safety gate between AI output and GitHub PR creation.

The sandbox is a temporary validation workspace used for a proposed remediation.

It does not edit the real GitHub repository. The worker downloads a copy of the repository, writes the suggested file into a temporary directory, runs validation commands there, stores the result, and then the temporary workspace is discarded.

Current behavior:

- `.tf`, `.tfvars`, and `.hcl` files use the Terraform validator
- other files use a generic content sanity validator
- commands run with a timeout
- command execution uses a scrubbed environment so application secrets are not passed into validation subprocesses
- repository archive extraction rejects unsafe paths before files are unpacked
- output is stored in a validation job
- PR creation is blocked unless the latest validation passed, unless an admin explicitly overrides it

Important limitation:

- default mode is a validation workspace, not a separate high-security VM or micro-VM isolation boundary

Optional Docker isolation can run Terraform validation in a separate per-job container with network disabled, dropped capabilities, and CPU/memory limits. This is stronger than default workspace mode, but still should not be treated as a micro-VM hostile-code boundary.

Set `MORROW_VALIDATION_ISOLATION_MODE=docker` and configure `MORROW_VALIDATION_DOCKER_IMAGE` if your runtime has Docker access and you want this stricter mode.

For Terraform, the platform runs:

- `terraform fmt`
- `terraform init -backend=false`
- `terraform validate`

### Run validation

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/validate" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"validator_type":"auto","async_mode":false,"timeout_seconds":180}'
```

### How to read validation output

- `status = passed`
  - the proposed content is valid for the selected validator

- `status = failed`
  - the change is blocked from PR creation unless an admin overrides

Important fields:

- `validator_type`
- `exit_code`
- `stdout`
- `stderr`
- `details.commands`

## 16. Creating a pull request

After a remediation is approved and validation has passed, create the PR.

### Create PR

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/create-pr" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"branch_prefix":"fix/pq-remediation","allow_unvalidated":false}'
```

### Notes

- branch names include the remediation id, timestamp, and unique suffix to avoid retry collisions
- if GitHub still reports a branch collision, retry the create PR action
- normal operators should not set `allow_unvalidated=true`
- admins can override validation if policy allows it

## 17. Merge and verification

### Merge

Once the PR is merged, the platform can mark the remediation as merged:

- automatically through the GitHub webhook
- or manually through the API

Manual example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/mark-merged" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"merged_at":"2026-05-09T11:53:37Z"}'
```

### Verify closure

After merge, the platform expects a later scan to confirm the issue is actually closed.

If the next relevant result is clean enough, the remediation moves to:

- `verified_closed`

For demos or controlled verification, admins can use the synthetic scan path:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scans/synthetic" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"scan_id":"verify-close-demo","results":[{"host":"www.cloudflare.com","port":443,"risk_level":"low","findings":[]}],"auto_close_merged":true}'
```

## 18. Drift detection

Drift means the repo content later diverged from the expected fixed state.

### Run drift check

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/drift/check" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"remediation_id":1,"github_credential_id":15,"async_mode":false}'
```

### Drift states

- `clean`
  - repo content still matches expected fixed content

- `drifted`
  - repo content diverged and needs attention

- `check_failed`
  - the drift check could not complete

### Acknowledge drift

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/drift/acknowledge" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"accepted temporarily"}'
```

### Revalidate drift

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/drift/revalidate" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"async_mode":false}'
```

### Drift follow-up remediations

When drift is detected, the system can auto-create a follow-up remediation with:

- `origin_kind = drift_followup`
- `parent_remediation_id` pointing back to the original item

## 19. Dashboard and compliance report

### Dashboard

The dashboard is the best summary screen.

Use it to watch:

- current open assets
- remediation pipeline state
- validation coverage
- verified closures
- drift totals
- recent alerts

### Compliance report

Machine-readable report:

```text
/org/compliance-report?format=json
```

The report includes:

- organization metadata
- summary counts
- vulnerabilities / asset posture
- remediation lifecycle state
- validation status
- merged and verified-close timestamps
- drift status
- recent alerts and audit summary

This is the best artifact for audits, dashboards, and API consumers.

## 20. Outbound webhooks and notifications

Use outbound webhooks to push events into Slack-compatible, Discord-compatible, or generic endpoints.

### Create a webhook

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"name":"ops","url":"http://webhook_sink:9001/hook","secret":"shared-secret","events":["validation.failed","remediation.merged","remediation.drifted","remediation.drift_followup_created"],"enabled":true}'
```

### Test it

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks/1/test" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Inspect delivery history

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/integrations/webhook-events?limit=20" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

Use this to troubleshoot:

- delivery failures
- retry scheduling
- event payloads

## 21. Optional Cloudflare connector

The app includes Cloudflare connector settings and dry-run policy support.

Use it if you want to:

- attach a Cloudflare credential
- inspect zones
- verify token access
- preview or dry-run policy application

This is optional and not required for the core post-quantum remediation workflow.

## 22. Deployment and configuration reference

This section covers the main runtime settings you are likely to change.

### Core runtime

| Variable | Meaning |
|---|---|
| `MORROW_MAIN_DB_BACKEND` | Main app database backend. Use `postgres` for shared/cloud mode or local SQLite flow when appropriate. |
| `MORROW_PRODUCT_DATABASE_URL` | Main Postgres connection string for app data. |
| `DATABASE_URL` | General database URL used by some integrations and older paths. |
| `CELERY_BROKER_URL` | Redis broker for background jobs. |
| `CELERY_RESULT_BACKEND` | Redis result backend for background tasks. |
| `MORROW_VAULT_MASTER_KEY` | Encryption root for stored vault secrets. |
| `OPENAI_API_KEY` | Required for remediation suggestion generation. |
| `OPENAI_MODEL` | Optional override for the model used in remediation generation. |
| `MORROW_API_KEY` | Optional API key protection for scan routes and docs. |
| `MORROW_DEFAULT_ORG_ID` | Default organization id in non-hosted or simplified local setups. |
| `MORROW_DEFAULT_ROLE` | Default role when using local header mode. |

### Auth

| Variable | Meaning |
|---|---|
| `MORROW_AUTH_MODE` | `headers` for local/dev, `jwt` for hosted auth. |
| `MORROW_AUTH_REQUIRED` | Force authenticated access when true. |
| `MORROW_AUTH_PROVIDER_NAME` | Label shown in the UI, such as `Auth0`. |
| `MORROW_AUTH_LOGIN_URL` | Hosted login URL used by the UI. |
| `MORROW_AUTH_LOGOUT_URL` | Hosted logout URL used by the UI. |
| `MORROW_AUTH_TOKEN_HELP` | Helper text shown in the UI. |
| `MORROW_AUTH_JWT_ISSUER` | Expected JWT issuer. |
| `MORROW_AUTH_JWT_AUDIENCE` | Expected JWT audience. |
| `MORROW_AUTH_JWT_JWKS_URL` | JWKS endpoint for RS256 token verification. |
| `MORROW_AUTH_JWT_SECRET` | Shared secret if using HS256 instead of JWKS. |
| `MORROW_AUTH_USER_ID_CLAIM` | User id claim name, usually `sub`. |
| `MORROW_AUTH_ROLE_CLAIM` | Role claim name. |
| `MORROW_AUTH_ORG_ID_CLAIM` | Organization id claim name. |
| `MORROW_AUTH_JWT_ALGORITHMS` | Allowed JWT algorithms. |
| `MORROW_AUTH_CLOCK_SKEW_SECONDS` | JWT clock skew tolerance. |

### Scan / API limits

| Variable | Meaning |
|---|---|
| `MORROW_RATE_LIMIT_WINDOW_SECONDS` | Rate-limit window length. |
| `MORROW_RATE_LIMIT_MAX_REQUESTS` | Max requests allowed in that window. |
| `PER_TARGET_TIMEOUT` | Target-level scan timeout. |

### Local Docker defaults

The local Docker stack is configured in `backend/compose.yml`.

It expects:

- Postgres
- Redis
- API
- worker
- beat

If you change Dockerfile dependencies, rebuild the images:

```powershell
docker compose build api worker beat
docker compose up -d --force-recreate api worker beat
```

## 23. Recommended naming standards

Use a fixed vocabulary for the metadata fields so reports stay clean.

### Environment

Recommended values:

- `prod`
- `staging`
- `dev`

### Criticality

Recommended values:

- `low`
- `medium`
- `high`

### Team

Use real delivery team names only.

Examples:

- `platform`
- `backend`
- `network`
- `security`

### Owner

Use one of:

- a real accountable person
- a real owning group

Do not mix many naming styles for the same responsibility.

## 24. Troubleshooting

### `jwt token is expired`

Clear the stored UI token and log in again:

```javascript
localStorage.removeItem("morrow_auth_bearer_token");
location.reload();
```

### Local validation says Terraform is not installed

Your local containers are stale. Rebuild them:

```powershell
docker compose build api worker beat
docker compose up -d --force-recreate api worker beat
```

### Asset is scanned but not visible in `/assets`

Scan history and asset inventory are different concepts.

Open the asset directly or classify it explicitly:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### Automatic correlation did not link the repo

Run repo sync again, then either:

- retry correlation
- or manually set `repository_id` on the asset

Manual linkage is an acceptable operational workflow.

### PR creation fails with a GitHub branch conflict

Branch names are generated with a unique suffix. If GitHub still reports a collision, retry the create PR action.

### Validation fails before PR creation

Read:

- `exit_code`
- `stderr`
- `details.commands`

Fix the proposed content or reject the remediation.

### Webhooks are queued but not delivered

Inspect:

- `/integrations/webhook-events`

Check:

- destination URL
- DNS reachability
- shared secret
- retry state

## 25. Suggested operating routine

Use this loop daily or per release window:

1. check the dashboard
2. review new alerts
3. scan key collections
4. classify new assets
5. confirm repository links
6. run compliance gate on important repos
7. create or review remediations
8. validate fixes
9. create PRs
10. verify closure after merge
11. review drift and follow-up work

## 26. Demo-friendly workflow

If you need to demonstrate the product, use this sequence:

1. dashboard
2. collection
3. scan
4. asset metadata
5. repository linkage
6. schedule
7. remediation suggestion
8. validation
9. PR
10. verified closure
11. drift
12. compliance report

This keeps the narrative clean:

- detect
- own
- fix
- validate
- prove
- monitor

## 27. Validation sandbox profile

The validation sandbox is the environment where remediation suggestions are tested before a pull request is created.

### How it works

When you click Validate on a remediation candidate, the platform:

1. Downloads the target repository files from GitHub
2. Applies the suggested code change to a temporary workspace
3. Runs a syntax and security check on the modified files
4. Returns a pass/fail result with stdout evidence

### Sandbox modes

| Mode | Description | Use when |
|---|---|---|
| `workspace` | Temporary folder inside the worker container | Default. Safe for most cases. |
| `docker` | Isolated Docker container with `--network none` | Recommended for production. Requires Docker on the worker host. |

### Configuration

Set these environment variables in your `.env` file:

```
MORROW_VALIDATION_ISOLATION_MODE=workspace   # or: docker
MORROW_VALIDATION_DOCKER_IMAGE=ghcr.io/opentofu/opentofu:1.8.6
MORROW_VALIDATION_DOCKER_CPUS=1
MORROW_VALIDATION_DOCKER_MEMORY=512m
MORROW_VALIDATION_TIMEOUT_MAX_SECONDS=900
```

To check what your current sandbox profile looks like, call:

```
GET /validation/sandbox-profile
```

This returns the active isolation mode, Docker availability, timeout, and security boundary description.

### Viewing validation evidence

For any completed validation job, call:

```
GET /validation-jobs/{job_id}/evidence
```

This returns the full evidence package: sandbox profile, exit code, stdout excerpt, file diff, and timestamps. The evidence package is included in the compliance report.

## 28. Bulk asset import via CSV

To import a large number of assets without entering them one by one:

1. Prepare a CSV file with these columns:
   - `host` (required) — hostname or IP address
   - `port` (optional, default 443)
   - `owner` (optional)
   - `team` (optional)
   - `environment` (optional — e.g., production, staging)
   - `criticality` (optional — e.g., critical, high, medium, low)
   - `tags` (optional — comma-separated list)

2. In the Asset Editor, click **Import CSV** and select your file.

3. The platform imports each row, skips rows without a host, and returns a summary of imported, skipped, and errored rows.

You can also call the API directly:

```
POST /assets/import-csv
Content-Type: multipart/form-data
file: <your CSV file>
```

## 29. Secret backend configuration

Morrow supports three secret backends for storing webhook secrets and credentials:

| Backend | Env var value | Description |
|---|---|---|
| Local vault (default) | `MORROW_SECRET_BACKEND=vault` | Fernet encryption + PostgreSQL |
| AWS Secrets Manager | `MORROW_SECRET_BACKEND=aws` | Requires `AWS_REGION` and IAM permissions |
| Azure Key Vault | `MORROW_SECRET_BACKEND=azure` | Requires `AZURE_KEY_VAULT_URL` and service principal |

To check the active backend: `GET /integrations/secret-backend`

### AWS Secrets Manager

Set `MORROW_SECRET_BACKEND=aws` and ensure the worker has IAM access to Secrets Manager:

```
AWS_REGION=us-east-1
# In ECS/EC2, use task role instead of keys:
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

Install: `pip install boto3`

### Azure Key Vault

Set `MORROW_SECRET_BACKEND=azure`:

```
AZURE_KEY_VAULT_URL=https://your-vault.vault.azure.net
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
AZURE_TENANT_ID=...
```

Install: `pip install azure-keyvault-secrets azure-identity`

## 30. Jira integration

Morrow integrates with Jira in two ways:

### Option 1: Direct Jira REST API

Call `POST /integrations/jira/create-issue` with:

```json
{
  "jira_url": "https://your-org.atlassian.net",
  "project_key": "SEC",
  "email": "your@email.com",
  "api_token": "your-jira-api-token",
  "asset_key": "example.com:443",
  "finding_ids": ["MORROW_RSA_ENDPOINT"],
  "summary": "[post-quantum] RSA endpoint detected",
  "issue_type": "Bug"
}
```

### Option 2: Jira Automation Webhook

Get the webhook template: `GET /integrations/jira/template`

This returns step-by-step instructions for connecting Morrow events to Jira Automation triggers.

## 31. CAM/API transparent proxy

Use **Strategic capability layer -> Automated cryptographic agility middleware -> Build CAM** to
generate the no-code traffic protection package.

What the button does:

- calls `POST /crypto-mesh/middleware-plan`
- returns a ZIP with Envoy ingress/egress configs, iptables transparent capture, rollback scripts,
  Docker Compose and Kubernetes manifests
- includes a telemetry agent that posts runtime handshake proof without packet payloads

How to deploy it:

1. Download the ZIP from the result drawer.
2. Extract it beside the customer's compose or Kubernetes deployment files.
3. Run `./install-transparent.sh validate`.
4. Deploy the CAM ingress gateway.
5. Inject the CAM egress sidecar or route traffic through a node/egress gateway.
6. Run `./verify-transparent.sh`.

Important limit: this requires no customer application code changes, but it does require network
routing, sidecar injection, or gateway deployment. It does not rewrite app-layer crypto hidden
inside payloads.

## 32. Autonomous Security Mesh

Use **Overview -> Strategic capability layer -> Autonomous predictive security mesh -> Open mesh**,
or open **API Explorer -> Autonomous Mesh**.
Start with `GET /autonomous-mesh/capability-truth`; it tells you which parts are active,
which are deployment packages, which need credentials, and which are blocked.

The mesh exposes these production-shaped controls:

- passive eBPF crypto sniffer package for customer-approved Linux hosts
- entropy binary hunting for stripped or obfuscated crypto libraries
- multi-hop contagion graph for CA/KMS/service trust blast radius
- dynamic Q-Day countdown from Q-Intel milestones
- multi-variant PR body generation for developer choice
- canary-driven traffic shifting artifacts with rollback thresholds
- HSM/TPM virtualization and collector package
- HSM/KMS quantum-drift enforcement from customer-submitted hardware/cloud KMS observations
- crypto-anomaly detection and SIEM/XDR package generation for Splunk, Datadog, Sentinel and Sigma
- continuous compliance proof without raw asset identifiers
- insurance underwriting export and signed proof-of-agility bundle

Important limits:

- eBPF and HSM collectors run inside the customer boundary after customer review.
- canary rollout artifacts do not write to live providers unless credentials and change approval are
  supplied later
- continuous compliance proof is a hash-commitment attestation, not a formal ZK-SNARK
  proof
- it does not fix application-layer crypto inside request bodies
- empty/sample inputs are rejected for risk claims; provide real nodes, edges, upstreams, or assets
- HSM/KMS support is never hard-coded as a provider claim; run collectors or submit observations
- crypto-anomaly detection uses metadata only, not packet payloads or plaintext
- underwriter proof bundles expose aggregate scores and hashes, not raw asset identifiers
