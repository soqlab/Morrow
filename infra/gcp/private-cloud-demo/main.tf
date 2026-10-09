locals {
  artifact_repository = "${var.region}-docker.pkg.dev/${var.project_id}/${var.name_prefix}-containers"
  image               = "${local.artifact_repository}/backend:${var.image_tag}"
}

module "pqc_private_cloud" {
  source = "../modules/private-cloud"

  project_id        = var.project_id
  region            = var.region
  name_prefix       = var.name_prefix
  image             = local.image
  deploy_runtime    = var.deploy_runtime
  openai_model      = var.openai_model
  auth_mode         = var.auth_mode
  auth_required     = var.auth_required
  auth_jwt_issuer   = var.auth_jwt_issuer
  auth_jwt_audience = var.auth_jwt_audience
  auth_jwt_jwks_url = var.auth_jwt_jwks_url

  # Private-cloud default: Cloud Run is reachable through Google-managed HTTPS,
  # while Postgres and Redis remain private-IP only inside the customer VPC.
  api_ingress               = "INGRESS_TRAFFIC_ALL"
  allow_unauthenticated_api = true

  labels = {
    deployment_model = "private-cloud"
    data_boundary    = "customer-vpc"
  }
}
