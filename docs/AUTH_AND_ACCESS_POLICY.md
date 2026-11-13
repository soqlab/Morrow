# Auth And Access Policy

## Decision

Do not make login optional for customer dashboards, scans, assets, admin, or traffic/IP monitoring.

No-login is allowed only for:

- Public marketing and legal pages: `/launch`, `/security`, `/privacy`, `/terms`, `/support`.
- Auth bootstrap and credential exchange: `/auth/config`, `/auth/login`, `/auth/refresh`, `/auth/logout`.
- Passkey ceremonies, each authenticated by its own payload (a stored single-use challenge plus a signature, and for registration an invitation, emailed link or Bearer token): `/auth/passkey/login/begin|finish`, `/auth/passkey/register/begin|finish`.
- Account recovery and team sign-in links: `/reset-password`, `/auth/password-reset/request|confirm`, `/join`, `/auth/team-join/request|preview`.
- Recovery without email: `/auth/recovery-codes/redeem` (the one-time code in the body is the credential; it buys only a short-lived ticket that can register a passkey).
- Non-sensitive proof demos: `/trust-passport-demo`.
- Future signed read-only proof links, if they are scoped, expiring, and contain no raw asset/IP inventory.

## Passkeys (built-in sign-in)

The built-in issuer (MORROW_AUTH_ISSUER_ENABLED=1, HS256) signs people in with passkeys
(`backend/services/passkeys.py`, py_webauthn). Production mode still requires an external RS256
identity provider; none of this changes that check.

- Relying party: the host of `MORROW_PUBLIC_BASE_URL`, origin that URL's origin (overrides:
  `MORROW_WEBAUTHN_RP_ID`, `MORROW_WEBAUTHN_ORIGINS`). Never the request's Host header. Without
  one, passkeys are not offered and `MORROW_PASSKEYS_ONLY` has no effect (it would lock everyone out).
- Registration asks for a discoverable credential with user verification required; attestation
  `none`. Sign-in offers discoverable credentials (and browser autofill); an email field lists that
  account's credentials for authenticators that can't discover (an unknown address gets stable decoy
  ids, so the answer doesn't reveal whether an account exists).
- Challenges are 32 random bytes, stored server side, single use (claimed before verification),
  and expire after `MORROW_WEBAUTHN_CHALLENGE_TTL_SECONDS` (default 300).
- Sign counter: a counter that does not increase (when either side is non-zero) blocks that passkey
  (`clone_suspected`) and journals `passkey.clone_suspected`. Synced passkeys report 0 and never trip it.
- The first passkey on an account sets its `password_hash` to NULL; `/auth/login` refuses any
  account that has a passkey. Adding another passkey to an account that already has one needs a
  sign-in within `MORROW_PASSKEY_REAUTH_SECONDS` (default 600), so a stolen access token can't plant one.
- Users list, rename and remove their passkeys (`GET/PATCH/DELETE /auth/passkeys`); the last one
  can't be removed.
- Accounts that still have a password: signing in with it returns `passkey_enrollment_required`,
  and the console makes adding a passkey the next, non-skippable step.
- `MORROW_PASSKEYS_ONLY=1` (set on hosted Morrow): a password sign-in returns no session, only a
  single-use enrollment ticket (`MORROW_PASSKEY_ENROLL_TTL_SECONDS`, default 600) that can do nothing
  but register a passkey; `/auth/register`, `/auth/invite/register`, `/auth/change-password` and
  `/auth/password-reset/confirm` answer 403. "Forgot password" emails an account-recovery link
  (`/reset-password#recover=…`, `MORROW_ACCOUNT_RECOVERY_TTL_SECONDS`, default 1800, single use, a
  newer link replaces older ones) that registers a new passkey, optionally removes the others, and
  signs the account out everywhere. Passkey accounts get the recovery link whether or not the flag is set.
- Schema: `morrow_passkeys`, `morrow_webauthn_challenges`, `morrow_auth_tickets` are created by
  `auth_issuer.init_tables`, which also makes `morrow_users.password_hash` nullable (SQLite: one
  table rebuild in a write transaction, indexes recreated; Postgres: `DROP NOT NULL`). Existing rows
  and passwords are kept.
- The operator portal (`/vendor-admin`, operator key + TOTP) is unchanged.

## Sign-in without email

- **No username.** The console shows one "Sign in with a passkey" button. `login/begin` is called
  without an email, so `allowCredentials` is empty and the browser offers this site's discoverable
  passkeys (every passkey is registered with `residentKey: required`, `userVerification: required`).
  No `transports` are ever sent in `allowCredentials`/`excludeCredentials` and no authenticator
  attachment is requested, so the browser may also offer a security key or a phone by QR code
  (hybrid). The old email fallback (`login/begin {email}`) still works for authenticators that can't
  discover credentials; the console no longer asks for it. Password sign-in stays behind
  "Sign in with a password" for accounts that still have one (the bootstrap admin from
  `MORROW_ADMIN_EMAIL`/`MORROW_ADMIN_PASSWORD` included), unchanged under `MORROW_PASSKEYS_ONLY`.
- **Email is optional.** `morrow_users.email` is nullable (still UNIQUE; NULLs are distinct). An admin
  creates an account with only a display name (and optionally an email) with `POST /auth/accounts`
  (console: Users › Set up account). The answer carries a single-use setup link
  (`/reset-password#setup=…`, `MORROW_ACCOUNT_SETUP_TTL_SECONDS`, default 259200 = 3 days, a newer
  link replaces older ones) that the admin hands over; nothing is emailed. Opening it creates the
  account's first passkey (`register` kind `setup`) and signs in. `POST /auth/accounts/{id}/setup-link`
  issues a new link, only for an account in the admin's organization that has neither a passkey nor a
  password, so a setup link can never take over an account someone already uses. Invitations and
  domain team join still carry an email: team join must prove a work mailbox on the domain, exactly
  as before. An account without an email can't accept email-addressed invitations.
- **Recovery codes** (`backend/services/recovery_codes.py`). `POST /auth/recovery-codes` (signed in,
  within `MORROW_PASSKEY_REAUTH_SECONDS`) returns 10 codes once (16 characters from a 31-character
  alphabet, about 79 bits each). Only `HMAC-SHA256(pepper, code)` is stored in `morrow_recovery_codes`;
  the pepper is `MORROW_RECOVERY_CODE_PEPPER` (16+ characters) or, when unset, derived from
  `MORROW_AUTH_JWT_SECRET`. Rotating it invalidates outstanding codes (passkeys keep working; make a
  new set). A deterministic keyed hash, not a per-code salt, is what lets a code be found without a
  username. Each code works once (claimed atomically); making a new set replaces the old one in the
  same transaction, so an account never has neither. `POST /auth/recovery-codes/redeem {code}` is rate
  limited like every auth endpoint and journaled (`recovery_code.used` / `recovery_code.refused`,
  method `recovery_code`); it returns a `recover` ticket (`MORROW_RECOVERY_CODE_TICKET_TTL_SECONDS`,
  default 600) that is not a session and can only register a passkey, exactly like an emailed
  recovery link: it signs the account out everywhere else and can remove the other passkeys.
  `GET /auth/recovery-codes` reports how many are left.
- **Emailed recovery is per account** (`morrow_users.email_recovery`, default 1). Existing accounts
  keep emailed recovery (lost-passkey links and password resets) exactly as before, so nobody is
  locked out by the upgrade; new accounts with an email get it too. The owner switches it off with
  `PUT /auth/email-recovery {enabled}` (signed in recently) only while they hold unused recovery codes;
  an account without an email can't switch it on. When it is off, `/auth/password-reset/request`
  sends nothing and answers exactly as for an unknown address.
- **Never locked out.** The last passkey still can't be removed; recovery codes are not counted as
  a way to sign in. Passwords that exist keep working until the account adds a passkey.
- Schema: `auth_issuer.init_tables` migrates `morrow_users` once (SQLite: one table rebuild inside a
  write transaction with its indexes recreated; Postgres: `ALTER COLUMN … DROP NOT NULL` and
  `ADD COLUMN IF NOT EXISTS email_recovery`), keeping every row, password and address, and creates
  `morrow_recovery_codes`. Like the other passkey tables it is keyed by account, has no tenant
  column and lives in the main database, so it is not in the Postgres RLS plan.

## Domain team sign-in

An organization admin can let anyone with a verified mailbox at one of the organization's verified
domains join it (`backend/services/team_join.py`, `GET /domain-join`, `PUT /domain-join/{domain}`,
page `/ui/domains.html`). The person enters a work email at `/join`, opens the emailed single-use
link (`MORROW_TEAM_JOIN_TTL_SECONDS`, default 1800) and creates a passkey; the account joins as
`viewer`.

- Refused: free-mail domains (built-in list plus `MORROW_FREE_MAIL_DOMAINS`), domains the
  organization hasn't verified, and subdomain addresses through a parent domain (exact match only).
- The `_morrow-verify` TXT record is looked up live when the admin enables it, when a link is
  requested and when the account is created; a missing record refuses the join (journaled
  `team_join.refused`) without using up the link.
- A domain verified by two organizations: the first to verify wins. Another organization can't
  enable team sign-in for it, and a join resolves only when exactly one organization has it enabled.
- The link request answers the same whether or not the domain admits people; an address that
  already has an account gets no link.
- Every join is recorded in the tenant audit log (`domains.team_join.joined`), the organization's
  admin audit log (`domain_join`), the authentication journal (`team_join.joined`) and
  `org_domain_joins`, which the admin page lists. Enabling and disabling are audited too.

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
