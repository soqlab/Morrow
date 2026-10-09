# Changelog

All notable changes to PQC Scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `/v1` versioned prefix for all sub-routers; unversioned paths remain for backward compatibility
- `X-API-Version: 1` response header on every API response
- `/healthz` lightweight liveness endpoint (Kubernetes / Cloud Run probe compatible)
- HTTP security headers middleware: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`
- OpenTelemetry distributed tracing — activated by `OTEL_EXPORTER_OTLP_ENDPOINT`
- SAML 2.0 SSO support (`python3-saml`)
- Azure Key Vault secret backend (`azure-keyvault-secrets`, `azure-identity`)
- `robots.txt` — disallows indexing of all API and platform paths
- Terms of Service and Privacy Policy placeholder pages (`/ui/terms.html`, `/ui/privacy.html`)
- Cloud Monitoring alert policies for availability, error rate, latency, and Cloud SQL disk (Terraform)
- Cloud Run startup and liveness probes (Terraform)
- Terraform validation: `deploy_runtime=true` with insecure auth defaults now fails at plan time
- CI/CD GitHub Actions: test pipeline (PR gate) and deploy pipeline (GCP Cloud Run)
- Non-root container user (`appuser`, UID 1001)
- Docker Compose healthchecks on Redis and Postgres; dependent services wait for `service_healthy`
- Redis password injected at runtime via `--requirepass`; hardcoded placeholder removed from `redis.conf`
- GCP Secret Manager secrets for `PQC_PLATFORM_ADMIN_KEY` and `PQC_AUTH_JWT_SECRET`
- Redis TLS in transit (`transit_encryption_mode = SERVER_AUTHENTICATION`) on GCP Memorystore
- Runtime startup warnings for: missing Redis password, missing Sentry DSN, insecure auth mode
- `SECURITY.md` responsible disclosure policy

### Changed
- `redis.conf` no longer contains a hardcoded `requirepass` value
- `.env.production.example` extended with `REDIS_PASSWORD`, `OTEL_*`, `SENTRY_DSN`, `PQC_SECRET_BACKEND`

---

## [0.6.0] — 2026-05-01

### Added
- Platform admin readiness endpoint (`/platform/readiness`)
- Subscription status enforcement — suspended organisations return 403
- Audit log IP address and request ID columns (migration 0005)
- SAML ACS handler and SP metadata endpoint
- Cloud secret backends: AWS Secrets Manager, Azure Key Vault

## [0.5.0] — 2026-04-01

### Added
- Vendor attestation invite and submission flow
- HNDL (Harvest Now, Decrypt Later) risk scoring
- GitHub App bridge for multi-installation enterprise repos
- Postgres Row-Level Security plan generator

## [0.4.0] — 2026-03-01

### Added
- Celery-backed async scan queue with Redis broker
- Remediation drift detection and auto-close on PR merge
- Circuit breaker and compliance gate endpoints
- Flight recorder event log

## [0.3.0] — 2026-02-01

### Added
- Multi-tenant organisations with RBAC membership
- Postgres primary database with Alembic migrations
- Structured JSON logging with secret masking
- Sentry error capture integration

## [0.2.0] — 2026-01-01

### Added
- Collections, schedules, and asset tagging
- Webhook event delivery with HMAC signatures
- GitHub repository discovery and asset correlation

## [0.1.0] — 2025-12-01

### Added
- Initial TLS endpoint scanner with PQC finding detection
- Risk scoring and migration plan generation
- FastAPI REST API with SQLite persistence
