output "artifact_registry_repository" {
  description = "Customer private Artifact Registry repository."
  value       = module.pqc_private_cloud.artifact_registry_repository
}

output "backend_image" {
  description = "Backend image URL expected by runtime services."
  value       = local.image
}

output "api_url" {
  description = "Cloud Run API URL."
  value       = module.pqc_private_cloud.api_url
}

output "github_webhook_url" {
  description = "GitHub App webhook receiver URL."
  value       = module.pqc_private_cloud.github_webhook_url
}

output "runtime_secret_names" {
  description = "Runtime Secret Manager secret names."
  value       = module.pqc_private_cloud.runtime_secret_names
}

output "cloud_sql_private_ip" {
  description = "Private Cloud SQL address."
  value       = module.pqc_private_cloud.cloud_sql_private_ip
}

output "redis_host" {
  description = "Private Redis address."
  value       = module.pqc_private_cloud.redis_host
}
