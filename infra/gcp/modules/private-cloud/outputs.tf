output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository for backend images."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.containers.repository_id}"
}

output "api_url" {
  description = "Cloud Run HTTPS URL for the API service."
  value       = try(google_cloud_run_v2_service.api[0].uri, null)
}

output "github_webhook_url" {
  description = "GitHub App webhook receiver URL on Cloud Run."
  value       = try("${google_cloud_run_v2_service.api[0].uri}/integrations/github/webhook", null)
}

output "worker_pool_name" {
  description = "Cloud Run worker pool name for Celery workers."
  value       = try(google_cloud_run_v2_worker_pool.worker[0].name, null)
}

output "beat_pool_name" {
  description = "Cloud Run worker pool name for Celery beat."
  value       = try(google_cloud_run_v2_worker_pool.beat[0].name, null)
}

output "cloud_sql_private_ip" {
  description = "Private IP address for the Cloud SQL instance."
  value       = google_sql_database_instance.vault.private_ip_address
}

output "redis_host" {
  description = "Internal Redis host."
  value       = google_redis_instance.cache.host
}

output "runtime_secret_names" {
  description = "Secret Manager secret names used by runtime services."
  value = {
    openai_api_key        = google_secret_manager_secret.runtime["openai-api-key"].secret_id
    pqc_vault_master_key  = google_secret_manager_secret.runtime["pqc-vault-master-key"].secret_id
    github_webhook_secret = google_secret_manager_secret.runtime["github-webhook-secret"].secret_id
  }
}

output "deployment_model" {
  description = "Deployment model summary."
  value       = "customer-owned-private-cloud"
}
