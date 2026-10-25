# Morrow Private Cloud Module

This module packages the customer-owned GCP deployment for enterprise/private-cloud installs.

It provisions the full runtime stack inside a customer project:

- Artifact Registry private Docker repository
- dedicated VPC and serverless subnet
- private service networking range
- private-IP Cloud SQL PostgreSQL
- private-IP Memorystore Redis with AUTH
- Secret Manager secret containers
- runtime service account and IAM bindings
- Cloud Run API service
- Cloud Run worker pool for Celery workers
- Cloud Run worker pool for Celery beat

## Security boundary

Application data stays in the customer-controlled GCP project. Postgres and Redis use private addresses reachable through the deployed VPC path. Container images are pulled from the customer's Artifact Registry repository.

Cloud Run still exposes the API through Google-managed Cloud Run HTTPS unless the caller sets stricter ingress and front-door networking in the root module.

## Two-phase deployment

The module supports a two-phase flow:

1. `deploy_runtime = false`
   - create network, database, Redis, Artifact Registry, and Secret Manager containers
   - build/push the backend image to the created private registry
   - add secret versions for `openai-api-key` and `pqc-vault-master-key`
2. `deploy_runtime = true`
   - deploy API, worker, and beat using the private image and private dependencies

The helper script `scripts/setup-enterprise.sh` automates this flow for demo environments.

## Required inputs

- `project_id`
- `region`
- `name_prefix`
- `image`

## Important outputs

- `artifact_registry_repository`
- `api_url`
- `github_webhook_url`
- `cloud_sql_private_ip`
- `redis_host`
- `runtime_secret_names`
