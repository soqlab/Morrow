variable "project_id" {
  description = "Customer-owned Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Deployment region."
  type        = string
  default     = "europe-west1"
}

variable "name_prefix" {
  description = "Short resource prefix."
  type        = string
  default     = "pq-ent"
}

variable "image_tag" {
  description = "Backend image tag to deploy from the private Artifact Registry."
  type        = string
  default     = "latest"
}

variable "deploy_runtime" {
  description = "Deploy API, worker, and beat after the image/secrets exist."
  type        = bool
  default     = false
}

variable "openai_model" {
  description = "OpenAI model used by remediation suggestions."
  type        = string
  default     = "gpt-4.1-mini"
}

variable "auth_mode" {
  description = "Auth mode. Use jwt for enterprise SSO."
  type        = string
  default     = "headers"
}

variable "auth_required" {
  description = "Require auth for non-public API routes."
  type        = bool
  default     = false
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
  description = "JWKS URL for RS256 token verification."
  type        = string
  default     = ""
}
