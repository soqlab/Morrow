# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately in one of two ways:

1. **GitHub private vulnerability reporting** — preferred. Go to the
   [Security tab](https://github.com/yasseennandally/pqc_scanner/security/advisories/new) and open a
   draft advisory. This keeps the report, the discussion and the eventual CVE in one place.
2. **Email** — **contact@soqlab.com**, with `SECURITY` in the subject line.

Please include:

- What the vulnerability is and what an attacker gains from it.
- Steps to reproduce, or a proof of concept. A failing request is ideal.
- The affected component, file or endpoint, and the commit or version you tested.
- Any suggested mitigation, if you have one.

If you need to send something sensitive, say so in your first message and we will arrange an
encrypted channel.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement that the report was received | 2 business days |
| Initial triage, severity assessment, and whether it is in scope | 5 business days |
| Fix or documented mitigation — critical and high | 30 days |
| Fix or documented mitigation — medium and low | 90 days |
| Public disclosure | Coordinated with you, after a fix is available |

This is a project maintained by one person, not a vendor with a security team on rota. If a deadline
is going to slip you will be told, with a reason, rather than left without a reply. If you get no
acknowledgement within the window above, please chase — it means the message was missed, not
ignored.

## Credit

Reporters are credited in the advisory and the changelog unless they ask not to be. There is no bug
bounty — this is an unfunded open-source project, so the only thing on offer is credit and a prompt
fix.

## In scope

- `backend/` — the FastAPI application, API endpoints, scanners, services.
- Authentication and authorisation: JWT/JWKS verification, SAML, the built-in issuer, RBAC role
  enforcement, operator sessions and MFA.
- **Multi-tenant isolation** — any path by which one organisation can read or write another's data.
  This is the highest-value class of bug in this codebase; please look here.
- Secret handling: the vault sealing layer, credential storage, anything that could log or return a
  secret.
- The SSRF guard on outbound requests, and request-forgery or injection in the scanners.
- `backend/static/` and `backend/static_admin/` — stored or reflected XSS in either console.
- `gateway/` — the Go WAF and reverse proxy.
- `infra/` — Terraform that provisions something insecurely by default.
- Supply-chain issues in how this project builds or ships, including the Docker images.

## Out of scope

Reports in these categories will be closed as intended behaviour or wrong venue. Please read this
list before testing — most of it exists because the insecure thing is deliberate, documented and
warned about at runtime.

- **The default local configuration.** `docker compose up` and an unconfigured server run with
  `PQC_AUTH_MODE=headers` and `PQC_DEFAULT_ROLE=admin`, which means any caller can claim any role via
  a request header and anonymous requests are admin. This is intentional so the quick start works
  without setup. The server logs a warning about both on every start, `GET /health/deep` reports
  them, and the README says not to expose it. "Anyone can become admin by setting `x-user-role`" is
  not a vulnerability in this mode; it is the mode.
- Anything requiring `PQC_ENVIRONMENT` to be something other than `production` in order to work. A
  production deployment refuses to start without external SSO, managed Postgres and Redis, a vault
  key and explicit allowed hosts.
- Third-party dependency CVEs with no project-specific exploit path. Report those upstream; open a
  normal issue here if a version bump is needed.
- Missing hardening that is already documented as absent, such as the lack of a security
  certification or a third-party penetration test.
- Denial of service through resource exhaustion on an endpoint whose scale ceiling is already
  documented, or by sending unbounded input to a local-only deployment.
- Self-XSS, missing security headers with no demonstrated impact, clickjacking on a page with no
  state-changing action, and reports consisting only of an automated scanner's output.
- Social engineering, physical access, and attacks on the maintainer's own accounts or
  infrastructure rather than this code.

## Supported versions

| Version | Supported |
|---|---|
| Latest `main` | Yes |
| Tagged releases | Latest only |
| Anything older | No — please upgrade before reporting |

## What the platform does to protect itself

Not a certification claim, just what is implemented, so you know where to look:

- JWT verification against a JWKS endpoint with RS256; HS256 is refused in production unless
  explicitly overridden. Optional SAML 2.0 SSO.
- Role-based access control, with a separate operator portal whose roles (owner / operator / support
  / auditor) are bound to the credential rather than requested per call.
- Postgres row-level security for tenant isolation, with a non-superuser application role.
  `GET /admin/postgres-rls/verify` reports whether it is genuinely active rather than assuming it.
- Integration credentials sealed with Fernet under `PQC_VAULT_MASTER_KEY` before storage. Without a
  key, features that store credentials refuse to save rather than writing plaintext.
- An SSRF guard on outbound requests: HTTPS only, every resolved address must be public, IPv4-mapped
  and 6to4 forms unwrapped before the check, the connection pinned to the address that was checked so
  DNS rebinding cannot redirect it inward, and redirects not followed.
- Rate limiting per organisation and per IP, backed by Redis so it holds across replicas.
- Structured JSON logging with secret masking, and an append-only audit journal recording the acting
  operator for every administrative write.
- Optional integration with AWS Secrets Manager, Azure Key Vault and GCP Secret Manager.
- HTTP security headers including HSTS, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy` and a configurable CSP.

### Known gaps

Stated plainly, because finding these again is not a good use of your time:

- There is **no security certification** — no SOC 2, no ISO 27001, and no third-party penetration
  test has been performed.
- The customer console at `/ui/` is served with a CSP that permits inline script. Tightening it
  requires restructuring a large single-file SPA and is tracked.
- Some analytics endpoints have documented scale ceilings on large estates.

If you find something in those areas that is worse than described, that is still worth reporting.
