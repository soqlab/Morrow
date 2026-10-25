# Security logging and administrator visibility

Updated 2026-09-13. This documents implemented scope, not a security certification or launch approval.

## Where to look

- `/vendor-admin/#activity`: authentication outcomes, filterable by event type. The screen reports storage status, retention and process-observed write failures.
- `/vendor-admin/traffic.html`: recent request buffer or retained database history, with exact IP and literal route-prefix filters. Summary counters cover this process only, even when the event table shows archive history.
- `/platform/auth-events` (also `/platform/logins`): authentication journal. Customer-specific `/platform/customers/{organization_id}/logins` contains successful sign-ins only.
- `/platform/logging/health`: authenticated storage health and process-observed write failures. Counters reset on restart; retained records do not.
- Traffic NDJSON and OTLP-shaped JSON exports accept `source=recent|archive`, `source_ip` and `path_prefix`. Maximum export size is 5,000 matching events; this is not a continuous SIEM delivery integration or a full archive export.

All journal APIs require the platform key. A customer JWT is not a platform administrator credential. Auditor/support permissions do not authorize clearing the traffic buffer. Public HTML shells may load without authentication, but they contain no customer log data until an authorized API request succeeds. Protect the vendor surface behind your SSO/VPN and use role-scoped platform credentials; do not distribute the owner key to customers.

## What is actually recorded

- Built-in password sign-in success, incorrect credentials, invalid requests, authentication service errors and rate limiting.
- SAML callback success/failure, refresh success/failure, supplied refresh-token revocation and rejected access tokens.
- Verified user/org/role on successful authentication. Failed passwords do not acquire an identity from the attempted email or caller-supplied headers. Where a vault/JWT secret is configured, a keyed reference to the attempted email supports correlation without retaining the email itself.
- Requests handled by this API: source IP, HTTP method, route template, response status, duration and verified identity where available. Unknown/rejected-before-routing paths are replaced with a constant. The database stores a browser category, not the full user-agent string. The bounded recent buffer retains a truncated user-agent string.
- Existing action-audit records remain separate. Generic successful mutation audits no longer include query strings. Explicit role authorization fails closed in production if its audit write fails. Generic post-response auditing remains best-effort and cannot retroactively undo completed operations.

Normal authenticated requests no longer manufacture hourly "login" entries. Login counts and customer last-login fields use the new journal, within its retention window. A missing sign-in record means **not observed**, not necessarily that someone never used the product. External OIDC/JWKS authentication does not expose upstream IdP sign-in failures to this API: inspect/export the IdP's own logs as well.

This is **not everything a visitor does**. It does not record keystrokes, field contents, session replay, client-only tab changes, requests served entirely by a CDN, or traffic that never reaches this API. A source IP may belong to a proxy or shared network, not a uniquely identified person. Do not market this as covert visitor surveillance or tamper-proof evidence.

## Storage and retention

The new `platform_auth_events` and `platform_request_events` tables use `MORROW_FEATURE_STORE_BACKEND`: local SQLite, or PostgreSQL after migrating that feature store. They are deliberately cross-tenant platform-admin tables, not customer-readable tenant tables. Migration owners create the tables/indexes; runtime accounts need SELECT/INSERT/DELETE, not DDL permission after migration.

| Setting | Default | Enforced range |
| --- | --- | --- |
| `MORROW_TRAFFIC_PERSIST_TO_DB` | `1` | Boolean; explicitly disabled archives return an error, not a misleading empty history |
| `MORROW_AUTH_LOG_RETENTION_DAYS` | `90` | 1-365 days |
| `MORROW_TRAFFIC_RETENTION_DAYS` | `7` | 1-30 days |

All journal reads enforce expiry immediately. The lifespan task removes up to 5,000 expired rows per table every minute. If the service is stopped or deletion capacity is exceeded, physical cleanup lags; monitor storage growth. Clearing the recent traffic buffer does not erase the database archive. Backups, exported SIEM copies, historical `login_events`, and existing action-audit tables have their own retention policies; this task does not retroactively sanitize or delete them.

Traffic persistence is awaited off the event loop, without an unbounded delivery queue. It still adds database work and needs deployment-specific load testing, capacity planning and retention monitoring. It is not a high-volume immutable logging pipeline. A traffic write failure does not break customer requests; it increments health failure counters and emits a sanitized, rate-limited error. The gap is not silently presented as complete history.

## Credential and failure behavior

- No bootstrap user is silently generated. On an empty built-in auth database, supply `MORROW_ADMIN_PASSWORD` through a secret manager, or configure an external IdP. Bootstrap credentials are never printed. Existing accounts are not reset by changing that setting.
- Built-in passwords use bcrypt with the same cost for absent and known accounts. Passwords over 72 UTF-8 bytes are rejected rather than truncated. This reduces one enumeration signal; it is not a proof of constant-time end-to-end HTTP behavior.
- Password login and refresh return no credentials if the required success audit cannot be committed. An unreturned new refresh token is revoked. Logout still revokes the supplied refresh token if logging fails and reports `audit_recorded=false`.
- **Logout does not revoke already-issued access JWTs.** They remain valid until expiry. Built-in refresh tokens remain reusable until revoked/expired; built-in MFA and session-wide JWT revocation are not implemented by this change. Use your enterprise IdP/session policy for those requirements.
- The existing built-in user/refresh-token store is SQLite-backed even if the journal is on PostgreSQL. Do not treat this as a horizontally scalable hosted identity service. Production SSO configuration and session-lifecycle validation remain required.
- The SAML assertion consumer returns credentials in a `Cache-Control: no-store` JSON response, never in a redirect query string. This changes the previous callback contract. Validate your real IdP and approved browser callback integration before enabling SAML; mocked validator tests are not SAML interoperability proof.
- Default Uvicorn access logs omit the raw request target altogether; protected traffic logs retain safe route templates. Configure equivalent redaction on ingress/CDN/SIEM/exception-reporting systems separately. Previously logged bootstrap passwords/tokens must be rotated by the operator; old log copies cannot be assumed clean.

## Operator verification

1. Apply migrations with the migration role, then start with the restricted runtime role. Inspect `/platform/logging/health` using a header-carried platform credential; never put it in a URL.
2. Exercise a successful and rejected login on a dedicated test account in staging. Confirm distinct event types, trusted identity, no credential/query leakage and accurate UTC timestamps.
3. Refresh and log out that session. Confirm refresh stops working; verify the separate access-token expiry/IdP revocation policy.
4. Generate requests, select retained database history and restart the service. Confirm those requests survive. Inspect storage failure counters and backup/restore behavior.
5. Validate trusted-proxy configuration and client IP handling behind the actual ingress. Never enable forwarding-header trust on an Internet-reachable untrusted backend.
6. Review the go-live gate and complete independent security review, session/SSO, backup/restore, load and incident-response acceptance. A passing journal check is not approval for all other platform features.

The readiness journal check executes zero-row INSERT statements to test permission without fabricating login/traffic records. This does not prove disk durability, crash recovery, backups or audit completeness. Inspect actual write history and perform operational drills.

Design references: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) and [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
