locals {
  labels = merge(
    {
      app        = "morrow"
      managed_by = "terraform"
    },
    var.labels,
  )

  api_service_name   = "${var.name_prefix}-api"
  worker_pool_name   = "${var.name_prefix}-worker"
  beat_pool_name     = "${var.name_prefix}-beat"
  runtime_sa_id      = "${var.name_prefix}-runtime"
  artifact_repo_name = "${var.name_prefix}-containers"
  network_name       = "${var.name_prefix}-net"
  subnet_name        = "${var.name_prefix}-serverless"
  sql_instance_name  = "${var.name_prefix}-sql"
  sql_database_name  = "pq"
  sql_user_name      = "pq"
  redis_name         = "${var.name_prefix}-redis"

  secret_ids = {
    "database-url"          = "${var.name_prefix}-database-url"
    "celery-broker-url"     = "${var.name_prefix}-celery-broker-url"
    "celery-result-backend" = "${var.name_prefix}-celery-result-backend"
    "morrow-vault-master-key"  = "${var.name_prefix}-morrow-vault-master-key"
    "openai-api-key"        = "${var.name_prefix}-openai-api-key"
    "github-webhook-secret" = "${var.name_prefix}-github-webhook-secret"
  }

  database_url = format(
    "postgresql://%s:%s@%s:5432/%s",
    local.sql_user_name,
    urlencode(random_password.cloud_sql_password.result),
    google_sql_database_instance.vault.private_ip_address,
    google_sql_database.app.name,
  )

  celery_broker_url = format(
    "redis://:%s@%s:%s/0",
    urlencode(google_redis_instance.cache.auth_string),
    google_redis_instance.cache.host,
    google_redis_instance.cache.port,
  )

  celery_result_backend = format(
    "redis://:%s@%s:%s/1",
    urlencode(google_redis_instance.cache.auth_string),
    google_redis_instance.cache.host,
    google_redis_instance.cache.port,
  )
}

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_project_service" "required" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "redis.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  repository_id = local.artifact_repo_name
  description   = "Post-quantum backend container images"
  format        = "DOCKER"
  labels        = local.labels

  depends_on = [google_project_service.required]
}

resource "google_artifact_registry_repository_iam_member" "cloud_run_reader" {
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:service-${data.google_project.current.number}@serverless-robot-prod.iam.gserviceaccount.com"
}

resource "google_compute_network" "platform" {
  name                    = local.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "serverless" {
  name                     = local.subnet_name
  ip_cidr_range            = var.serverless_subnet_cidr
  region                   = var.region
  network                  = google_compute_network.platform.id
  private_ip_google_access = true
}

resource "google_compute_global_address" "private_service_range" {
  name          = "${var.name_prefix}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_service_range_prefix_length
  network       = google_compute_network.platform.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.platform.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]

  depends_on = [google_project_service.required]
}

resource "random_password" "cloud_sql_password" {
  length  = 32
  special = false
}

resource "random_password" "github_webhook_secret" {
  length  = 48
  special = false
}

resource "google_sql_database_instance" "vault" {
  name                = local.sql_instance_name
  region              = var.region
  database_version    = var.cloud_sql_database_version
  deletion_protection = true

  settings {
    edition           = "ENTERPRISE"
    tier              = var.cloud_sql_tier
    availability_type = var.cloud_sql_availability_type
    disk_type         = "PD_SSD"
    disk_size         = var.cloud_sql_disk_size_gb
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.platform.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled = true
    }
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_sql_database" "app" {
  name     = local.sql_database_name
  instance = google_sql_database_instance.vault.name
}

resource "google_sql_user" "app" {
  name     = local.sql_user_name
  instance = google_sql_database_instance.vault.name
  password = random_password.cloud_sql_password.result
}

resource "google_redis_instance" "cache" {
  name               = local.redis_name
  region             = var.region
  tier               = var.redis_tier
  memory_size_gb     = var.redis_memory_size_gb
  redis_version      = var.redis_version
  authorized_network = google_compute_network.platform.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  auth_enabled       = true
  labels             = local.labels

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_service_account" "runtime" {
  account_id   = local.runtime_sa_id
  display_name = "Post-quantum runtime identity"
}

resource "google_project_iam_member" "runtime_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret" "runtime" {
  for_each = local.secret_ids

  secret_id = each.value
  labels    = local.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "runtime_access" {
  for_each = google_secret_manager_secret.runtime

  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret_version" "generated" {
  for_each = {
    "database-url"          = local.database_url
    "celery-broker-url"     = local.celery_broker_url
    "celery-result-backend" = local.celery_result_backend
    "github-webhook-secret" = random_password.github_webhook_secret.result
  }

  secret      = google_secret_manager_secret.runtime[each.key].id
  secret_data = each.value
}

resource "google_cloud_run_v2_service" "api" {
  count = var.deploy_runtime ? 1 : 0

  name                = local.api_service_name
  location            = var.region
  ingress             = var.api_ingress
  deletion_protection = false
  labels              = local.labels

  template {
    service_account = google_service_account.runtime.email

    scaling {
      min_instance_count = var.api_min_instances
      max_instance_count = var.api_max_instances
    }

    containers {
      image = var.image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.api_cpu
          memory = var.api_memory
        }
      }

      env {
        name  = "APP_COMPONENT"
        value = "api"
      }

      env {
        name  = "MORROW_MAIN_DB_BACKEND"
        value = "postgres"
      }

      env {
        name  = "ENABLE_INPROCESS_SCHEDULER"
        value = "0"
      }

      env {
        name  = "WORKER_ROLE"
        value = "api"
      }

      env {
        name  = "OPENAI_MODEL"
        value = var.openai_model
      }

      env {
        name  = "MORROW_AUTH_MODE"
        value = var.auth_mode
      }

      env {
        name  = "MORROW_AUTH_REQUIRED"
        value = var.auth_required ? "1" : "0"
      }

      env {
        name  = "MORROW_AUTH_PROVIDER_NAME"
        value = var.auth_provider_name
      }

      env {
        name  = "MORROW_AUTH_LOGIN_URL"
        value = var.auth_login_url
      }

      env {
        name  = "MORROW_AUTH_LOGOUT_URL"
        value = var.auth_logout_url
      }

      env {
        name  = "MORROW_AUTH_TOKEN_HELP"
        value = var.auth_token_help
      }

      env {
        name  = "MORROW_AUTH_JWT_ISSUER"
        value = var.auth_jwt_issuer
      }

      env {
        name  = "MORROW_AUTH_JWT_AUDIENCE"
        value = var.auth_jwt_audience
      }

      env {
        name  = "MORROW_AUTH_JWT_JWKS_URL"
        value = var.auth_jwt_jwks_url
      }

      env {
        name  = "MORROW_AUTH_JWT_ALGORITHMS"
        value = var.auth_jwt_algorithms
      }

      env {
        name  = "MORROW_AUTH_USER_ID_CLAIM"
        value = var.auth_user_id_claim
      }

      env {
        name  = "MORROW_AUTH_ROLE_CLAIM"
        value = var.auth_role_claim
      }

      env {
        name  = "MORROW_AUTH_ORG_ID_CLAIM"
        value = var.auth_org_id_claim
      }

      env {
        name  = "PER_TARGET_TIMEOUT"
        value = tostring(var.per_target_timeout)
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_PRODUCT_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_VAULT_MASTER_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["morrow-vault-master-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "OPENAI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["openai-api-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_BROKER_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-broker-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_RESULT_BACKEND"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-result-backend"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "GITHUB_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["github-webhook-secret"].secret_id
            version = "latest"
          }
        }
      }
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"

      network_interfaces {
        network    = google_compute_network.platform.name
        subnetwork = google_compute_subnetwork.serverless.name
        tags       = ["${var.name_prefix}-runtime"]
      }
    }
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.cloud_run_reader,
    google_project_iam_member.runtime_cloudsql_client,
    google_secret_manager_secret_iam_member.runtime_access,
    google_secret_manager_secret_version.generated,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  count = var.deploy_runtime && var.allow_unauthenticated_api ? 1 : 0

  location = google_cloud_run_v2_service.api[0].location
  name     = google_cloud_run_v2_service.api[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_worker_pool" "worker" {
  provider = google-beta
  count    = var.deploy_runtime ? 1 : 0

  name         = local.worker_pool_name
  location     = var.region
  launch_stage = "BETA"
  labels       = local.labels

  template {
    service_account = google_service_account.runtime.email
    containers {
      image = var.image

      resources {
        limits = {
          cpu    = var.worker_cpu
          memory = var.worker_memory
        }
      }

      env {
        name  = "APP_COMPONENT"
        value = "worker"
      }

      env {
        name  = "MORROW_MAIN_DB_BACKEND"
        value = "postgres"
      }

      env {
        name  = "WORKER_ROLE"
        value = "worker"
      }

      env {
        name  = "OPENAI_MODEL"
        value = var.openai_model
      }

      env {
        name  = "PER_TARGET_TIMEOUT"
        value = tostring(var.per_target_timeout)
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_PRODUCT_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_VAULT_MASTER_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["morrow-vault-master-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "OPENAI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["openai-api-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_BROKER_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-broker-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_RESULT_BACKEND"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-result-backend"].secret_id
            version = "latest"
          }
        }
      }
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"

      network_interfaces {
        network    = google_compute_network.platform.name
        subnetwork = google_compute_subnetwork.serverless.name
        tags       = ["${var.name_prefix}-runtime"]
      }
    }
  }

  scaling {
    scaling_mode          = "MANUAL"
    manual_instance_count = var.worker_instance_count
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.cloud_run_reader,
    google_project_iam_member.runtime_cloudsql_client,
    google_secret_manager_secret_iam_member.runtime_access,
    google_secret_manager_secret_version.generated,
  ]
}

resource "google_cloud_run_v2_worker_pool" "beat" {
  provider = google-beta
  count    = var.deploy_runtime ? 1 : 0

  name         = local.beat_pool_name
  location     = var.region
  launch_stage = "BETA"
  labels       = local.labels

  template {
    service_account = google_service_account.runtime.email
    containers {
      image = var.image

      resources {
        limits = {
          cpu    = var.worker_cpu
          memory = var.worker_memory
        }
      }

      env {
        name  = "APP_COMPONENT"
        value = "beat"
      }

      env {
        name  = "MORROW_MAIN_DB_BACKEND"
        value = "postgres"
      }

      env {
        name  = "WORKER_ROLE"
        value = "beat"
      }

      env {
        name  = "OPENAI_MODEL"
        value = var.openai_model
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_PRODUCT_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["database-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "MORROW_VAULT_MASTER_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["morrow-vault-master-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "OPENAI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["openai-api-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_BROKER_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-broker-url"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CELERY_RESULT_BACKEND"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.runtime["celery-result-backend"].secret_id
            version = "latest"
          }
        }
      }
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"

      network_interfaces {
        network    = google_compute_network.platform.name
        subnetwork = google_compute_subnetwork.serverless.name
        tags       = ["${var.name_prefix}-runtime"]
      }
    }
  }

  scaling {
    scaling_mode          = "MANUAL"
    manual_instance_count = var.beat_instance_count
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.cloud_run_reader,
    google_project_iam_member.runtime_cloudsql_client,
    google_secret_manager_secret_iam_member.runtime_access,
    google_secret_manager_secret_version.generated,
  ]
}

