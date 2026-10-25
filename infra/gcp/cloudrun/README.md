# GCP Cloud Run production deploy

This folder prepares the current backend for a two-phase GCP deploy:

1. Provision Artifact Registry, VPC, Cloud SQL, Redis, service accounts, and Secret Manager containers.
2. Populate the missing runtime secrets manually, then deploy the Cloud Run API service plus Celery worker pools.

## What this does

- `backend/Dockerfile` now has a runtime entrypoint that can boot:
  - FastAPI API (`APP_COMPONENT=api`)
  - Celery worker (`APP_COMPONENT=worker`)
  - Celery beat (`APP_COMPONENT=beat`)
- Terraform provisions:
  - Artifact Registry Docker repo
  - private VPC + subnet
  - private service networking
  - Cloud SQL PostgreSQL
  - Memorystore Redis
  - Secret Manager secrets
  - Cloud Run API service
  - Cloud Run worker pools for `worker` and `beat`

## What still requires owner input

- production domain and DNS cutover
- hosted auth issuer, audience, JWKS URL, role claim, and org claim
- OpenAI production API key
- Sentry project/DSN and incident contacts
- legal/security sign-off and backup restore evidence

## Prerequisites

- `gcloud` installed and authenticated
- Terraform installed locally
- Billing enabled on the project

## 1. Build and push the container

From the repo root:

```powershell
gcloud auth configure-docker europe-west1-docker.pkg.dev
gcloud builds submit backend --tag europe-west1-docker.pkg.dev/YOUR_PROJECT_ID/pqc-containers/backend:latest
```

Adjust the region/repository in both the command and `terraform.tfvars`.

## 2. Create your tfvars file

```powershell
cd C:\Users\Samsung\Desktop\morrow\infra\gcp\cloudrun
Copy-Item terraform.tfvars.example terraform.tfvars
```

Fill in at least:

- `project_id`
- `region`
- `image`
- `auth_jwt_issuer`
- `auth_jwt_audience`
- `auth_jwt_jwks_url`
- `cors_origins`
- `sentry_dsn`

Keep `deploy_runtime = false` for the first apply.

## 3. First Terraform apply: infra only

```powershell
terraform init
terraform plan
terraform apply
```

This creates the Secret Manager secret containers. Terraform also auto-generates the database URL,
Redis URLs, GitHub webhook signing secret, platform admin key, and token signing secret. You still
need to add your OpenAI key and Fernet vault key manually.

Terraform state is stored remotely in GCS using:

- bucket: `pqc-scanner-2026-tfstate`
- prefix: `cloudrun`

That backend is declared in `infra/gcp/cloudrun/backend.tf`.

## 4. Add the missing runtime secrets manually

Generate a Fernet-compatible vault key:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then add secret versions:

```powershell
gcloud secrets versions add pq-morrow-vault-master-key --data-file=-
gcloud secrets versions add pq-openai-api-key --data-file=-
```

Paste the generated Fernet key for the first command, and your OpenAI key for the second command. The secret names use the default `name_prefix = "pq"` from `terraform.tfvars.example`; adjust if you changed the prefix. The GitHub webhook secret is generated automatically as `${name_prefix}-github-webhook-secret`.

## 5. Second Terraform apply: deploy runtime

Set this in `terraform.tfvars`:

```hcl
deploy_runtime = true
```

Then apply again:

```powershell
terraform plan
terraform apply
```

Terraform refuses `deploy_runtime = true` when JWT metadata, CORS origins, Sentry, or hardened auth
settings are missing.

## 6. What you get back

- `api_url`: public HTTPS endpoint from Cloud Run
- `github_webhook_url`: GitHub App callback URL (`${api_url}/integrations/github/webhook`)
- `worker_pool_name`: worker pool for Celery workers
- `beat_pool_name`: worker pool for Celery beat

## 7. Verify the live deployment

```powershell
$api = terraform output -raw api_url
$platformKey = gcloud secrets versions access latest --secret morrow-platform-admin-key
..\..\..\scripts\verify-cloud-deployment.ps1 -BaseUrl $api -PlatformKey $platformKey
..\..\..\scripts\go-live-report.ps1 -BaseUrl $api -PlatformKey $platformKey
```

Do not send this URL to a buyer until both commands pass and the manual exit criteria in the
go-live report have been completed.

## GitHub App webhook cutover

Once `deploy_runtime = true` is applied:

1. Read the generated webhook secret:

```powershell
gcloud secrets versions access latest --secret pq-github-webhook-secret
```

2. In GitHub App settings:
   - set the payload URL to the `github_webhook_url` Terraform output
   - set the webhook secret to the value from Secret Manager
   - subscribe to at least the `Pull request` event

The backend route is `POST /integrations/github/webhook`. It verifies `X-Hub-Signature-256` when `GITHUB_WEBHOOK_SECRET` is present.

## Operational notes

- Cloud Run worker pools are currently a preview feature. Google documents them as the right primitive for continuous non-HTTP background processing, but they require manual instance counts and do not autoscale on queue depth by default.
- Redis traffic is private-IP only, but TLS is not enabled here because the current Celery configuration does not yet use `rediss://`.
- Cloud Run direct VPC egress is used so API and worker pools can reach Redis and Cloud SQL without a serverless VPC connector.
- Do not keep `terraform.tfstate`, `terraform.tfvars`, or `tfplan` in Git. The repo `.gitignore` now excludes them.

## Sources

- Cloud Run worker pools: https://cloud.google.com/run/docs/overview/what-is-cloud-run
- Worker pool Terraform/resource patterns: https://cloud.google.com/run/docs/deploy-worker-pools
- Worker pool manual scaling: https://cloud.google.com/run/docs/configuring/workerpools/manual-scaling
- Direct VPC egress with Terraform: https://cloud.google.com/run/docs/configuring/vpc-direct-vpc
- Secret Manager integration for Cloud Run: https://cloud.google.com/run/docs/configuring/services/secrets
