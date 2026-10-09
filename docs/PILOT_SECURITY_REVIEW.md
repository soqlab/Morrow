# Pilot Security Review

This document gives concise answers for early customer security review. It is not a SOC2 report or legal certification.

## Product Boundary

PQC Scanner is a cryptographic observability and governance platform. It discovers TLS/PQC posture, links assets to repositories, manages remediation workflow, validates changes, and records evidence.

## Current Deployment Model

Recommended pilot deployment:

- Cloud Run or equivalent container runtime.
- Postgres for product data.
- Redis for async job queue.
- GitHub App for repository integration.
- Auth0 or hosted JWT for authentication.

## Authentication

Supported:

- Auth0/JWT-based auth.
- Header-based local/dev mode for controlled local testing.
- Viewer/operator/admin role model.

Before paid pilot:

- Disable unauthenticated production access.
- Configure real issuer/audience validation.
- Confirm role/org claims are present.

## Authorization

The platform enforces role-based access control:

- Viewer: read dashboards/assets/evidence/reports.
- Operator: normal workflow operations.
- Admin: sensitive actions, credentials, org policy, RLS plan.

## Multi-Tenancy

Current model:

- Organization-scoped tables and queries.
- JWT/header org context.
- Regression tests for org isolation.

Hardening path:

- Apply Postgres RLS in staging/production.
- Use generated RLS plan from `/v1/admin/postgres-rls/plan`.
- Ensure application DB role does not have `BYPASSRLS`.

## Secrets

Secrets are stored through the Vault credential flow and encrypted before storage.

Covered:

- GitHub/webhook credentials should not be returned in list responses.
- Credential reveal is admin-only.
- Rotation endpoint exists.

Before paid pilot:

- Verify master key management in production secret manager.
- Define rotation schedule.
- Confirm no secrets appear in logs.

## GitHub Access

GitHub App is preferred over long-lived personal tokens.

The app can:

- Sync installations/repositories.
- Mint repo-scoped tokens.
- Create branches/commits/PRs when approved.
- Publish required checks/statuses for circuit breaker enforcement.

Before paid pilot:

- Restrict installation to pilot repository/repositories.
- Confirm branch protection behavior.
- Confirm PR creation is operator/admin controlled.

## Validation Sandbox

The validation sandbox validates remediation content and IaC policy checks. It is not currently positioned as hostile-code containment.

Pilot guidance:

- Use controlled repositories.
- Do not allow arbitrary untrusted customer code execution without additional isolation review.
- Treat sandbox as validation workspace, not malware sandbox.

## Audit And Evidence

The platform records:

- RBAC/audit events.
- Flight-recorder intent/outcome events.
- Validation evidence.
- Remediation state transitions.
- PR/check publication events.
- Compliance report evidence.

## Data Retention

To define per pilot:

- asset inventory retention
- scan result retention
- webhook event retention
- validation stdout/stderr retention
- deletion/export request process

## Known Gaps Before Enterprise Production

- SOC2/ISO certification not complete.
- External penetration test not complete.
- Postgres RLS generated but must be applied and verified in staging/production.
- Full backup/restore procedure must be exercised.
- Production observability/SLOs must be finalized.

## Safe Pilot Statement

Recommended customer-facing statement:

> This pilot evaluates cryptographic observability, governance, and remediation workflow on a limited set of assets and repositories. It is not a certification of compliance, and production enforcement controls will remain explicitly scoped and approved.
