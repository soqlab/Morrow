# PQC Scanner Private Cloud Demo

This is the investor/customer demo root module for proving that PQC Scanner can run inside a customer-owned GCP perimeter.

It wraps `../modules/private-cloud` and keeps all state/configuration outside application code.

## Fast path

From the repository root:

```bash
export OPENAI_API_KEY="..."
scripts/setup-enterprise.sh --project CUSTOMER_PROJECT_ID --region europe-west1 --prefix pqc-ent
```

The script performs the two-phase deployment:

1. creates VPC, private services, Cloud SQL, Redis, Artifact Registry, and secrets
2. builds and pushes the backend image into the customer's private Artifact Registry
3. adds Secret Manager versions
4. deploys API, worker, and beat
5. executes Alembic migrations through a one-off Cloud Run Job inside the VPC

## Manual flow

```bash
cd infra/gcp/private-cloud-demo
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var="deploy_runtime=false"

gcloud auth configure-docker europe-west1-docker.pkg.dev
gcloud builds submit ../../../backend \
  --tag europe-west1-docker.pkg.dev/PROJECT_ID/pqc-ent-containers/backend:latest

printf '%s' "$PQC_VAULT_MASTER_KEY" | gcloud secrets versions add pqc-ent-pqc-vault-master-key --data-file=-
printf '%s' "$OPENAI_API_KEY" | gcloud secrets versions add pqc-ent-openai-api-key --data-file=-

terraform apply -var="deploy_runtime=true"
```

## Data sovereignty statement

The deployed database, Redis queue, secrets, runtime service account, and container images live in the customer project. The app connects to Cloud SQL and Redis over private networking. This is the deployment shape for banks, healthcare systems, government contractors, and other customers that cannot accept a shared SaaS data plane.
