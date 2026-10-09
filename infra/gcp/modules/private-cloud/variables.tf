variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Google Cloud region for Cloud Run, Cloud SQL, and Redis."
  type        = string
  default     = "europe-west1"
}

variable "name_prefix" {
  description = "Short prefix for all deployed resources."
  type        = string
  default     = "pqc"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must start with a letter, end with a letter or number, and stay short enough for Cloud Run/SQL resource names."
  }
}

variable "image" {
  description = "Artifact Registry image URL for the backend container."
  type        = string
}

variable "deploy_runtime" {
  description = "If true, deploy Cloud Run API + worker pools. Keep false for the first apply until manual secrets are populated."
  type        = bool
  default     = false
}

variable "allow_unauthenticated_api" {
  description = "Allow public HTTPS access to the API service."
  type        = bool
  default     = true
}

variable "api_ingress" {
  description = "Cloud Run ingress setting for the API service."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "api_min_instances" {
  description = "Minimum Cloud Run API instances."
  type        = number
  default     = 0
}

variable "api_max_instances" {
  description = "Maximum Cloud Run API instances."
  type        = number
  default     = 2
}

variable "api_cpu" {
  description = "API CPU limit."
  type        = string
  default     = "1"
}

variable "api_memory" {
  description = "API memory limit."
  type        = string
  default     = "1Gi"
}

variable "worker_cpu" {
  description = "Worker pool CPU limit."
  type        = string
  default     = "1"
}

variable "worker_memory" {
  description = "Worker pool memory limit."
  type        = string
  default     = "1Gi"
}

variable "worker_instance_count" {
  description = "Manual instance count for the Celery worker pool."
  type        = number
  default     = 1
}

variable "beat_instance_count" {
  description = "Manual instance count for the Celery beat worker pool."
  type        = number
  default     = 1
}

variable "cloud_sql_database_version" {
  description = "Cloud SQL PostgreSQL version."
  type        = string
  default     = "POSTGRES_16"
}

variable "cloud_sql_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-1-3840"
}

variable "cloud_sql_disk_size_gb" {
  description = "Cloud SQL disk size in GB."
  type        = number
  default     = 20
}

variable "cloud_sql_availability_type" {
  description = "Cloud SQL availability type."
  type        = string
  default     = "ZONAL"
}

variable "redis_tier" {
  description = "Memorystore Redis tier."
  type        = string
  default     = "BASIC"
}

variable "redis_memory_size_gb" {
  description = "Memorystore Redis memory size in GB."
  type        = number
  default     = 1
}

variable "redis_version" {
  description = "Memorystore Redis version."
  type        = string
  default     = "REDIS_7_2"
}

variable "serverless_subnet_cidr" {
  description = "Subnet CIDR used by Cloud Run direct VPC egress."
  type        = string
  default     = "10.20.0.0/24"
}

variable "private_service_range_prefix_length" {
  description = "Prefix length for the private service networking range."
  type        = number
  default     = 16
}

variable "openai_model" {
  description = "OpenAI model name exposed to the runtime."
  type        = string
  default     = "gpt-4.1-mini"
}

variable "per_target_timeout" {
  description = "Per-target timeout exposed to scan workers."
  type        = number
  default     = 20
}

variable "auth_mode" {
  description = "Runtime auth mode for the API service."
  type        = string
  default     = "headers"
}

variable "auth_required" {
  description = "Require authenticated JWTs for non-public API routes."
  type        = bool
  default     = false
}

variable "auth_provider_name" {
  description = "Friendly auth provider name shown in the UI."
  type        = string
  default     = "Hosted JWT"
}

variable "auth_login_url" {
  description = "Hosted login URL used by the UI."
  type        = string
  default     = ""
}

variable "auth_logout_url" {
  description = "Hosted logout URL used by the UI."
  type        = string
  default     = ""
}

variable "auth_token_help" {
  description = "Optional helper text shown near the bearer token field."
  type        = string
  default     = ""
}

variable "auth_jwt_issuer" {
  description = "Expected JWT issuer."
  type        = string
  default     = ""
}

variable "auth_jwt_audience" {
  description = "Expected JWT audience."
  type        = string
  default     = ""
}

variable "auth_jwt_jwks_url" {
  description = "JWKS URL for verifying RS256 tokens."
  type        = string
  default     = ""
}

variable "auth_jwt_algorithms" {
  description = "Comma-separated JWT algorithms accepted by the runtime."
  type        = string
  default     = "RS256,HS256"
}

variable "auth_user_id_claim" {
  description = "JWT claim path used for the user id."
  type        = string
  default     = "sub"
}

variable "auth_role_claim" {
  description = "JWT claim path used for the app role."
  type        = string
  default     = "role"
}

variable "auth_org_id_claim" {
  description = "JWT claim path used for the organization id."
  type        = string
  default     = ""
}

variable "labels" {
  description = "Additional labels applied to GCP resources."
  type        = map(string)
  default     = {}
}
