# PQC Scanner Threat Model

Status: living document for controlled enterprise pilots. Review before every production deployment and after any write-path feature change.

## 1. System Boundaries

PQC Scanner is a multi-tenant governance platform for quantum-readiness discovery, evidence, remediation workflow, and guarded write-path actions.

Primary trust boundaries:

- Customer browser to API.
- API to Postgres.
- API/worker to Redis/Celery.
- API/worker to GitHub App.
- API to identity provider.
- API to external scanners and AI agents through Security Truth APIs.
- Vendor admin portal to `/platform/*`.

## 2. High-Value Assets

- Tenant-scoped scan, asset, remediation, audit, evidence, and findings data.
- GitHub App private key and installation tokens.
- Vault master key and stored customer credentials.
- Auth0/SAML signing and claim configuration.
- Platform admin key.
- Guardrail evidence and audit logs.
- Proposed remediation diffs and validation logs.

## 3. Principal Threats

| Threat | Impact | Required Control |
| --- | --- | --- |
| Tenant data leakage | Critical | Postgres RLS, org claim enforcement, multi-tenant tests |
| Forged role/org headers in production | Critical | `PQC_AUTH_MODE=jwt`, `PQC_AUTH_REQUIRED=1`, no header auth |
| Compromised platform admin key | Critical | Store in Secret Manager, rotate, monitor `/platform/*` logs |
| Malicious write-path request | Critical | Guardrails, human approval, validation sandbox, audit |
| GitHub token leakage | Critical | GitHub App short-lived tokens, secret scrubbing, vault isolation |
| Prompt injection against AI assistant | High | constrained assistant scope, server-side intent validation |
| External scanner flooding findings | High | tool API scopes, rate limits, pagination, audit |
| Validation sandbox escape | High | path traversal checks, network isolation, timeouts, output truncation |
| Public CORS or weak auth in prod | High | readiness checks, locked CORS, production env gate |
| Evidence tampering | Medium | audit hash chain, evidence hash/signature metadata |

## 4. Write-Path Security Invariants

The platform must never directly apply or merge a code change without all of the following:

- authenticated actor or scoped external tool key;
- organization context;
- guardrail evaluation;
- persisted audit event;
- human approval for remediation execution;
- validation evidence before PR creation;
- GitHub PR/check evidence before merge;
- post-merge verification and drift monitoring.

## 5. Multi-Tenant Isolation Requirements

Required for production:

- Use managed Postgres, not SQLite.
- Enable RLS on tenant tables.
- Force RLS where appropriate.
- Use a non-superuser app role.
- Confirm app role does not have `BYPASSRLS`.
- Run `backend/verify_rls.py` before pilot and after migrations.
- Keep `/platform/*` separate from customer routes and key-protected.

## 6. Security Truth API Requirements

External tools and agents must use scoped keys:

- `guardrails:evaluate` for read-only policy checks.
- `findings:write` for ingestion.
- `findings:read` for finding retrieval.
- `write_path:request` for governed fix requests.

Do not issue wildcard `*` keys to third parties unless it is a short-lived internal emergency key.

## 7. Incident Response Triggers

Escalate immediately if any of these occur:

- cross-tenant data access;
- unauthorized `/platform/*` request success;
- guardrail bypass;
- unexpected GitHub PR or branch creation;
- leaked secret in logs or validation output;
- production auth running in header mode;
- RLS verification failure.

## 8. Pre-GA Security Exit Criteria

- Threat model reviewed and signed off.
- RLS verification passes and output is archived.
- CI security workflow passes.
- Backup/restore drill completed.
- One full pilot write-path loop completed on a real repo.
- External security review or penetration test completed.
