# Auth And Access Policy

## Decision

Do not make login optional for customer dashboards, scans, assets, admin, or traffic/IP monitoring.

No-login is allowed only for:

- Public marketing and legal pages: `/launch`, `/security`, `/privacy`, `/terms`, `/support`.
- Auth bootstrap and credential exchange: `/auth/config`, `/auth/login`, `/auth/refresh`, `/auth/logout`.
- Non-sensitive proof demos: `/trust-passport-demo`.
- Future signed read-only proof links, if they are scoped, expiring, and contain no raw asset/IP inventory.

## Required Login

These surfaces require authenticated users or platform admin credentials:

- Customer console: `/`, `/scan`, `/scans`, `/assets`, `/repositories`, `/remediations`.
- Customer organization data: `/org/*`.
- Customer admin/API administration: `/admin/*`.
- Vendor operations: `/platform/*`.
- Traffic/IP monitoring: `/platform/traffic/*`.

## Admin Pages

The static vendor admin shell may be reachable at `/vendor-admin/` and `/vendor-admin/traffic.html` so operators can load the page before entering a key. The page shell is not the security boundary.

The security boundary is the API:

- All `/platform/*` endpoints require `x-platform-key`.
- Platform admin requests may include `x-platform-admin-role`.
- `owner` can perform all platform operations, including state migration and destructive controls.
- `operator` can perform day-to-day write operations.
- `support` and `auditor` are read-only.
- Production must set `MORROW_PLATFORM_ADMIN_KEY` to a high-entropy value.
- Production must keep `MORROW_ALLOW_PLATFORM_KEY_QUERY=0`.
- Production should place vendor admin routes behind SSO, VPN, or an identity-aware proxy.

## Traffic Data Boundary

The traffic monitor stores:

- Source IP.
- Path without query string.
- HTTP method.
- Status code and status family.
- Duration.
- Organization id.
- Actor id/role when already available.
- User agent and referrer path.

The traffic monitor does not store:

- Request bodies.
- Query string values.
- Cookies.
- Authorization headers.
- API keys.
- Uploaded files.

By default, traffic data is an in-memory ring buffer and disappears on restart. For production retention, export to SIEM/OpenTelemetry with a formal retention policy.

## Proxy Header Rule

`MORROW_TRUST_PROXY_HEADERS=0` is the safe default. Turn on `MORROW_TRUST_PROXY_HEADERS=1` only when the app is behind a trusted reverse proxy such as Cloudflare, nginx, or a cloud load balancer that strips untrusted forwarding headers.
