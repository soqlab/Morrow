# Changelog

All notable changes to Morrow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Crypto kill switch (`/crypto-switch/...`, `/ui/crypto-switch.html`): an admin declares "X is broken, switch to Y"; Morrow plans every affected asset by priority with a per-stack change (nginx, Apache, Envoy, HAProxy, OpenSSL, Go, Java), refuses fallbacks weaker than org policy, opens approved batches as pull requests, and marks assets switched only after a rescan observes Y. Dry run by default; every step audited
- Gradual post-quantum rollout (`/pq-rollouts/...`): staged 1/10/50/100% weighted-routing configs for Envoy, Istio, nginx and HAProxy, health gates on handshake failure and HTTP error rate from the customer's Prometheus, immediate rollback config/PR and alert on a failed gate
- Passive TLS discovery: continuous ingest of nginx, Envoy, HAProxy, AWS ALB and Zeek logs from Fluent Bit / Vector / Logstash (`POST /v1/runtime/passive/ingest`, per-org hashed ingest tokens, size and rate limits). Extracts host, port, TLS version, cipher and key-exchange group (including X25519MLKEM768), dedupes per (host, port, group, cipher), classifies with the scanner's rules and merges into the inventory with source `passive`. See docs/PASSIVE_DISCOVERY.md
- IKEv2 / IPsec VPN scanner (`backend/ike_scanner.py`, `POST /v1/scan/ike`, Scanners › VPN (IKEv2)): unauthenticated IKE_SA_INIT probing over UDP 500 or 4500 (NAT-T) that reports the accepted encryption, PRF, integrity and key-exchange transforms, RFC 9370 additional key exchanges and ML-KEM (IANA KE IDs 35-37), whether post-quantum key exchange is required or only optional, and whether IKEv1 is still accepted. Paced, capped, stateless on the responder, and refused for hosts outside the organization's verified domains
- CBOM import for CBOMkit output (`POST /v1/cbom/import`, CBOM › Import CBOMkit CBOM): CycloneDX 1.6 documents are validated against the vendored schema, their algorithm, protocol, certificate and related-crypto-material assets, evidence occurrences and dependencies are recorded, and each asset is merged into a new org-scoped, deduplicated crypto inventory (`GET /v1/crypto-inventory`) that SBOM imports now feed too
- Upload size limits for SBOM and CBOM imports (`MORROW_BOM_IMPORT_MAX_BYTES`, default 10 MiB; `MORROW_BOM_IMPORT_MAX_COMPONENTS`, default 20000)
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
- GCP Secret Manager secrets for `MORROW_PLATFORM_ADMIN_KEY` and `MORROW_AUTH_JWT_SECRET`
- Redis TLS in transit (`transit_encryption_mode = SERVER_AUTHENTICATION`) on GCP Memorystore
- Runtime startup warnings for: missing Redis password, missing Sentry DSN, insecure auth mode
- `SECURITY.md` responsible disclosure policy

### Changed
- `redis.conf` no longer contains a hardcoded `requirepass` value
- `.env.production.example` extended with `REDIS_PASSWORD`, `OTEL_*`, `SENTRY_DSN`, `MORROW_SECRET_BACKEND`

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
- Initial TLS endpoint scanner with post-quantum finding detection
- Risk scoring and migration plan generation
- FastAPI REST API with SQLite persistence
