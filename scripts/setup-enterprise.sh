#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/setup-enterprise.sh --project PROJECT_ID [options]

Bootstraps a customer-owned private-cloud GCP deployment:
  1. Terraform apply with deploy_runtime=false to create VPC, Artifact Registry, Cloud SQL, Redis, and secrets.
  2. Build and push the backend image into the customer Artifact Registry.
  3. Populate required Secret Manager versions.
  4. Terraform apply with deploy_runtime=true to deploy API, worker, and beat.
  5. Run Alembic migrations through a one-off Cloud Run Job inside the VPC.

Options:
  --project ID          Required GCP project ID.
  --region REGION      Default: europe-west1.
  --prefix PREFIX      Default: pq-ent.
  --image-tag TAG      Default: latest.
  --tf-dir PATH        Default: infra/gcp/private-cloud-demo.
  --skip-build         Do not build/push the Docker image.
  --skip-secrets       Do not add Secret Manager versions.
  --skip-migrate       Do not create/execute the migration job.
  -h, --help           Show this help.

Environment:
  OPENAI_API_KEY          Required unless --skip-secrets is used.
  MORROW_VAULT_MASTER_KEY    Optional. If absent, a Fernet-compatible key is generated.
USAGE
}

PROJECT_ID=""
REGION="europe-west1"
NAME_PREFIX="pq-ent"
IMAGE_TAG="latest"
TF_DIR="infra/gcp/private-cloud-demo"
SKIP_BUILD=0
SKIP_SECRETS=0
SKIP_MIGRATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT_ID="${2:-}"; shift 2 ;;
    --region) REGION="${2:-}"; shift 2 ;;
    --prefix) NAME_PREFIX="${2:-}"; shift 2 ;;
    --image-tag) IMAGE_TAG="${2:-}"; shift 2 ;;
    --tf-dir) TF_DIR="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-secrets) SKIP_SECRETS=1; shift ;;
    --skip-migrate) SKIP_MIGRATE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$PROJECT_ID" ]]; then
  echo "--project is required" >&2
  usage
  exit 2
fi

for bin in gcloud terraform; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing required command: $bin" >&2
    exit 1
  fi
done

if [[ ! -d "$TF_DIR" ]]; then
  echo "Terraform directory not found: $TF_DIR" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_ABS="$(cd "$TF_DIR" && pwd)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${NAME_PREFIX}-containers/backend:${IMAGE_TAG}"

terraform_apply() {
  local deploy_runtime="$1"
  terraform -chdir="$TF_ABS" apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="name_prefix=${NAME_PREFIX}" \
    -var="image_tag=${IMAGE_TAG}" \
    -var="deploy_runtime=${deploy_runtime}"
}

secret_exists() {
  gcloud secrets describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1
}

add_secret_version() {
  local secret_name="$1"
  local value="$2"
  if ! secret_exists "$secret_name"; then
    echo "Secret does not exist yet: $secret_name" >&2
    exit 1
  fi
  printf '%s' "$value" | gcloud secrets versions add "$secret_name" \
    --project "$PROJECT_ID" \
    --data-file=- >/dev/null
}

generate_fernet_key() {
  python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
}

echo "[1/5] Terraform infra apply: VPC, private services, Artifact Registry, secrets"
terraform -chdir="$TF_ABS" init
terraform_apply false

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "[2/5] Build and push private image: $IMAGE"
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
  gcloud builds submit "$ROOT_DIR/backend" \
    --project "$PROJECT_ID" \
    --tag "$IMAGE"
else
  echo "[2/5] Skipping image build/push"
fi

if [[ "$SKIP_SECRETS" -eq 0 ]]; then
  echo "[3/5] Populate required Secret Manager versions"
  if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "OPENAI_API_KEY is required unless --skip-secrets is used" >&2
    exit 1
  fi
  VAULT_KEY="${MORROW_VAULT_MASTER_KEY:-$(generate_fernet_key)}"
  add_secret_version "${NAME_PREFIX}-morrow-vault-master-key" "$VAULT_KEY"
  add_secret_version "${NAME_PREFIX}-openai-api-key" "$OPENAI_API_KEY"
else
  echo "[3/5] Skipping Secret Manager population"
fi

echo "[4/5] Terraform runtime apply: API, worker, beat"
terraform_apply true

if [[ "$SKIP_MIGRATE" -eq 0 ]]; then
  echo "[5/5] Run Alembic migration job inside the private VPC"
  RUNTIME_SA="${NAME_PREFIX}-runtime@${PROJECT_ID}.iam.gserviceaccount.com"
  JOB_NAME="${NAME_PREFIX}-migrate"
  NETWORK="${NAME_PREFIX}-net"
  SUBNET="${NAME_PREFIX}-serverless"
  gcloud run jobs deploy "$JOB_NAME" \
    --project "$PROJECT_ID" \
    --region "$REGION" \
    --image "$IMAGE" \
    --service-account "$RUNTIME_SA" \
    --set-env-vars "APP_COMPONENT=migrate,MORROW_MAIN_DB_BACKEND=postgres" \
    --set-secrets "MORROW_PRODUCT_DATABASE_URL=${NAME_PREFIX}-database-url:latest,DATABASE_URL=${NAME_PREFIX}-database-url:latest,MORROW_VAULT_MASTER_KEY=${NAME_PREFIX}-morrow-vault-master-key:latest,OPENAI_API_KEY=${NAME_PREFIX}-openai-api-key:latest,CELERY_BROKER_URL=${NAME_PREFIX}-celery-broker-url:latest,CELERY_RESULT_BACKEND=${NAME_PREFIX}-celery-result-backend:latest" \
    --network "$NETWORK" \
    --subnet "$SUBNET" \
    --vpc-egress private-ranges-only \
    --quiet
  gcloud run jobs execute "$JOB_NAME" --project "$PROJECT_ID" --region "$REGION" --wait
else
  echo "[5/5] Skipping migrations"
fi

echo "Enterprise private-cloud deployment complete."
terraform -chdir="$TF_ABS" output
