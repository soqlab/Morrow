terraform {
  backend "gcs" {
    bucket = "pqc-scanner-2026-tfstate"
    prefix = "cloudrun"
  }
}
