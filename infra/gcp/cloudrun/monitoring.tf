locals {
  api_service_id = var.deploy_runtime ? google_cloud_run_v2_service.api[0].name : local.api_service_name
  alert_channels = var.alert_notification_channels
}

# ---------------------------------------------------------------------------
# Uptime check — external HTTP ping to /healthz every 60 s
# ---------------------------------------------------------------------------

resource "google_monitoring_uptime_check_config" "api_healthz" {
  count = var.deploy_runtime && var.enable_monitoring ? 1 : 0

  display_name = "${var.name_prefix} API healthz"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/healthz"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.api_hostname
    }
  }
}

# ---------------------------------------------------------------------------
# Alert: API availability < 99% over 5 min
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "api_availability" {
  count = var.deploy_runtime && var.enable_monitoring ? 1 : 0

  display_name = "${var.name_prefix} API availability"
  combiner     = "OR"

  conditions {
    display_name = "Uptime check failing"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_FRACTION_TRUE"
        group_by_fields    = ["resource.label.host"]
      }
    }
  }

  notification_channels = local.alert_channels
  severity              = "CRITICAL"

  alert_strategy {
    auto_close = "1800s"
  }
}

# ---------------------------------------------------------------------------
# Alert: Cloud Run request error rate > 1% over 5 min
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "api_error_rate" {
  count = var.deploy_runtime && var.enable_monitoring ? 1 : 0

  display_name = "${var.name_prefix} API 5xx error rate"
  combiner     = "OR"

  conditions {
    display_name = "5xx responses > 1%"
    condition_threshold {
      filter = join(" AND ", [
        "metric.type=\"run.googleapis.com/request_count\"",
        "resource.type=\"cloud_run_revision\"",
        "resource.label.service_name=\"${local.api_service_name}\"",
        "metric.label.response_code_class=\"5xx\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01
      duration        = "300s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  notification_channels = local.alert_channels
  severity              = "ERROR"

  alert_strategy {
    auto_close = "1800s"
  }
}

# ---------------------------------------------------------------------------
# Alert: Cloud Run p99 request latency > 5 s over 5 min
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "api_latency" {
  count = var.deploy_runtime && var.enable_monitoring ? 1 : 0

  display_name = "${var.name_prefix} API p99 latency"
  combiner     = "OR"

  conditions {
    display_name = "p99 latency > 5000 ms"
    condition_threshold {
      filter = join(" AND ", [
        "metric.type=\"run.googleapis.com/request_latencies\"",
        "resource.type=\"cloud_run_revision\"",
        "resource.label.service_name=\"${local.api_service_name}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 5000
      duration        = "300s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_PERCENTILE_99"
        cross_series_reducer = "REDUCE_MAX"
      }
    }
  }

  notification_channels = local.alert_channels
  severity              = "WARNING"

  alert_strategy {
    auto_close = "3600s"
  }
}

# ---------------------------------------------------------------------------
# Alert: Cloud SQL disk utilisation > 85%
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "cloudsql_disk" {
  count = var.deploy_runtime && var.enable_monitoring ? 1 : 0

  display_name = "${var.name_prefix} Cloud SQL disk utilisation"
  combiner     = "OR"

  conditions {
    display_name = "Disk utilisation > 85%"
    condition_threshold {
      filter = join(" AND ", [
        "metric.type=\"cloudsql.googleapis.com/database/disk/utilization\"",
        "resource.type=\"cloudsql_database\"",
        "resource.label.database_id=\"${var.project_id}:${local.sql_instance_name}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = local.alert_channels
  severity              = "WARNING"

  alert_strategy {
    auto_close = "3600s"
  }
}
