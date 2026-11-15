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
  `/auth/password-reset/confirm` answer 403. Nothing that signs anyone in or gets anyone back in is
  emailed: `/auth/password-reset/request` and `/auth/team-join/request` answer 410 and send nothing,
  and `/auth/config` reports `password_reset_enabled` and `team_join_enabled` false. Recovery is a
  recovery code or a recovery link an admin hands over; joining is an invite link an admin hands over
  (next section). With the flag off, "forgot password" emails an account-recovery link
  (`/reset-password#recover=…`, `MORROW_ACCOUNT_RECOVERY_TTL_SECONDS`, default 1800, single use, a
  newer link replaces older ones) that registers a new passkey, optionally removes the others, and
  signs the account out everywhere, and domain team sign-in emails its join links, as before.
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

## Public sign-up, invite links and recovery links (no email)

- **Sign-up** (`backend/services/signup.py`, page `/signup`). `register/begin` with kind `signup`
  takes only an optional `full_name` and `organization`; `register/finish` creates a new organization
  (`org_<12 hex>`), its account with role `admin` and no email or password, and the passkey, and
  answers with a session, the organization and 10 recovery codes (made by `recovery_codes.generate`,
  shown this once). Open when `MORROW_PASSKEY_SIGNUP=1` (unset: follows `MORROW_PASSKEYS_ONLY`), and
  only while passkeys work and `MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1`, so a new organization scans
  only domains it verifies by DNS; public checks are unchanged. Budgets on completed sign-ups, counted
  in `morrow_signups` by a keyed hash of the address: `MORROW_SIGNUP_PER_IP_PER_HOUR` (3),
  `MORROW_SIGNUP_PER_IP_PER_DAY` (10), `MORROW_SIGNUP_GLOBAL_PER_HOUR` (60),
  `MORROW_SIGNUP_GLOBAL_PER_DAY` (500), 0 = off; checked at begin and again at finish (429). A field
  hidden from people refuses scripts (400). New organizations get the rate-limit override
  `MORROW_SIGNUP_API_CALLS_PER_MIN` / `MORROW_SIGNUP_SCANS_PER_HOUR`. `/signup?watch=<domain>` watches
  the domain right after and returns to `/<domain>`; `/signup?claim=<domain>` starts its DNS claim.
  Journaled: `signup.completed`, `signup.refused`, `signup.rate_limited`; audited `auth.signup.completed`.
- **Invite links** (`POST/GET /auth/invite-links`, `DELETE /auth/invite-links/{id}`, admin; console:
  Users & access › Invite link). A single-use link (`/join#invite=…`,
  `MORROW_INVITE_LINK_TTL_SECONDS`, default 604800 = 7 days, several may be open at once, revocable)
  that the admin hands over; nothing is sent. `POST /auth/invite-links/preview` (public) shows the
  organization and role; register kind `team` creates a `viewer` account without email in that
  organization. Works with or without `MORROW_PASSKEYS_ONLY`; the domain join-policy rows are kept.
- **Recovery links** (`POST /auth/accounts/{id}/recovery-link`, admin of the same organization;
  console: Users & access › Recovery link). For a member who lost every passkey and recovery code: a
  single-use `recover` link (`/reset-password#recover=…`, `MORROW_ACCOUNT_RECOVERY_TTL_SECONDS`)
  that registers a new passkey, signs the account out everywhere else and can remove its other
  passkeys. Journaled `account_recovery.issued`, audited `auth.account_recovery.issued`. An account
  that was never set up gets a setup link instead.
  A recovery link is a way into the account, so an admin may issue one only for a member who is not
  an admin. One for an admin, or for the organization's owner, needs the owner: the account that
  signed up and created the organization, recorded once in `morrow_org_owners` and not moved by a
  role change or a deactivation. Nobody issues one for their own account (that is what recovery
  codes are for). A refusal is journaled `account_recovery.refused` and audited with decision
  `deny`. The owner's own way back in, and an admin's in an organization with no recorded owner
  (made by an operator, or before owners were recorded), is a platform operator:
  `POST /platform/accounts/{id}/recovery-link` (operator role, MFA step-up, platform admin log).
- `morrow_signups` and `morrow_org_owners`, like the other auth tables, have no tenant column and
  live in the main database, so they are not in the Postgres RLS plan.

## Sign in with SOQLAB (one passkey for Morrow and Q-Lab)

`services/soqlab_id.py`. Off unless `MORROW_SOQLAB_ID_ISSUER` (https://id.soqlab.com),
`MORROW_SOQLAB_ID_CLIENT_ID`, `MORROW_SOQLAB_ID_CLIENT_SECRET` and `MORROW_SOQLAB_ID_LINK_KEY` (Morrow's
EC P-256 private key, PEM, `
` escapes allowed) are all set and `MORROW_PUBLIC_BASE_URL` is too.
While off, every `/auth/soqlab/*` route answers 404 and `/auth/config` reports
`soqlab_id_enabled: false`, so the console, `/signup` and `/reset-password` look exactly as before.
The redirect URI to register at the service is `<MORROW_PUBLIC_BASE_URL>/auth/soqlab/callback`.

- OpenID Connect code flow with PKCE S256, `client_secret_basic` at `/token`. The issuer comes only
  from configuration; discovery, keys, `/token` and `/unlink` are fetched only from its own origin
  (https, no redirects, 5 s, 64 KB), cached for an hour. ID tokens: ES256 only, `iss`, `aud`/`azp`,
  `exp`, `iat`, `nonce`, `amr` containing `passkey`, and `link_ticket` (below). The redirect back must
  carry `iss` (RFC 9207).
- No cookies. `POST /auth/soqlab/start` stores a round trip (`morrow_soqlab_flows`: SHA-256 of
  `state`, PKCE verifier, nonce, 10 minutes, single use) and answers with a random `flow` secret the
  page keeps in sessionStorage. `GET /auth/soqlab/callback` sends the browser back to the page that
  started (`/ui/`, `/signup` or `/reset-password`); that page posts `{code, state, iss, flow}` to
  `POST /auth/soqlab/callback`, which claims the round trip once, exchanges the code and acts.
- The service gives Morrow a pairwise `sub` (different per product; no name, no email).
  `morrow_soqlab_links` maps it to a Morrow account; sign-in then issues Morrow's normal tokens
  (`auth_issuer.start_session`), journaled with method `soqlab`. A `sub` with no link is refused.
- Linking (`purpose: link`) needs a sign-in within `MORROW_PASSKEY_REAUTH_SECONDS` and the same
  account's Bearer token on the way back. Morrow signs a link ticket (ES256 with the link key, 5
  minutes, single-use `jti`, `sub` = the Morrow account id) and the browser goes to
  `<issuer>/link?ticket=…`; the ID token that comes back must carry `link_ticket` = that `jti`.
  A sign-in round trip whose ID token carries a `link_ticket` is refused.
- Sign-up (`purpose: signup`, same rules and budgets as a passkey sign-up) is a link ticket for a
  freshly allocated account id: the account, its organization and its recovery codes are created
  when SOQLAB comes back. Recovery (`purpose: recover`, a recovery ticket from a recovery code or a
  recovery link) links a new SOQLAB passkey to that account only, signs it out everywhere and can
  remove its Morrow passkeys.
- `GET /auth/soqlab/link` reports whether the account is linked (never the `sub`);
  `DELETE /auth/soqlab/link` deletes the link, then asks the service to forget it (`POST /unlink`).
  Unlinking is refused while SOQLAB is the account's only way in.
- Morrow's own passkeys keep working ("Use my older Morrow passkey"). After a sign-in with one, the
  console offers a SOQLAB passkey once per browser.
- Neither table has a tenant column (a link belongs to an account), like `morrow_passkeys`, so
  neither is in `ORG_SCOPED_TABLES`.

## The organization's owner: roles and removals

Rules in `services/member_policy.py`, enforced on every route that changes a member's role or removes
one: `PUT /auth/users/{id}/role`, `POST /auth/users/{id}/deactivate`, `POST|PATCH|DELETE
/organizations/{id}/members[/{user}]`, `PUT /admin/users/role`, `DELETE /admin/users` and
`POST /admin/orgs/{id}/invite`.

- In an organization with a recorded owner, only the owner may change an admin's role, make someone
  an admin (by a role change, by adding a member or by an invitation with an admin role) or
  remove/deactivate an admin. Other admins keep managing members who are not admins (viewer,
  operator, analyst). An invite-joined admin is an admin like any other.
- Nobody changes their own role. The owner can't be demoted or removed from inside the organization
  at all, so it never ends up without one: the owner first hands ownership to another active admin
  with `POST /auth/organization/owner/transfer {"user_id"}`. That needs a recent sign-in
  (`MORROW_PASSKEY_REAUTH_SECONDS`, as for adding a passkey; 401 "sign in again" otherwise). The
  previous owner stays an admin, which the new owner can then change. Journaled
  `org_owner.transferred`, audited `auth.org_owner.transferred`.
- An organization without a recorded owner (made before owners were recorded, or by a platform
  operator) keeps the earlier rules for managing admins, except that nobody changes their own role.
  A platform operator records or replaces its owner with `PUT /platform/customers/{id}/owner
  {"user_id", "reason"}` (operator role, MFA step-up; the account must be an active admin of the
  organization). Journaled `org_owner.set`, audited `auth.org_owner.set`, platform admin log
  `platform.org_owner_set`.
- Platform operators change or remove an admin or the owner through `/platform/customers/{id}/members`
  and `/platform/customers/{id}/users/{user}/deactivate`, with an MFA step-up whenever the change
  touches an admin or the owner or makes someone an admin.
- A refusal answers 403 with a plain sentence, is journaled `member_change.refused` (or
  `org_owner.refused`) and audited with decision `deny` and the reason (`owner_required`,
  `owner_protected`, `own_role`). Someone in another organization gets 404, as before.
- `GET /auth/users` also returns `owner_id` and `you`; the console marks the owner, disables the
  buttons the caller can't use with a one-line reason and offers "Make owner" to the owner.

## Role changes, deactivation and removal take effect at once

One function, `services/member_access.py` `apply()`, makes every change to what a person may do in an
organization: `PUT /auth/users/{id}/role`, `POST /auth/users/{id}/deactivate`, `POST|PATCH|DELETE
/organizations/{id}/members[/{user}]`, `PUT /admin/users/role`, `DELETE /admin/users`,
`POST|PATCH|DELETE /platform/customers/{id}/members[/{user}]` and
`/platform/customers/{id}/users/{user}/deactivate|reactivate`. The rules above decide whether a change
is allowed; this decides how it is made.

- **One authoritative record.** A person's role and status in an organization is their membership
  (`organization_memberships`). The built-in account (`morrow_users`) carries the role and active flag
  for the organization it is bound to, which its tokens are minted from, and is written in the same
  transaction as the membership (with the membership in Postgres: the account write is held until the
  membership commits, and the membership is put back if the account can't be committed). The
  invitation record (`admin_users`) follows. Authorization reads the records, not the token's role
  claim: the membership when there is one, else the account's own role; an inactive account or a
  disabled membership has no role. Ownership transfer and `PUT /platform/customers/{id}/owner` check
  the same thing.
- **Demotion, deactivation, removal: the very next request.** When access goes down, every access
  token the person holds is revoked (a per-user "valid after" time in `platform_token_revocations`,
  checked on every request, cached for `MORROW_TOKEN_REVOCATION_CACHE_SECONDS`, default 10, and applied
  at once on the replica that made the change). A demoted person keeps their refresh session, whose
  next token carries the new role; a deactivated or removed person's refresh sessions are deleted. The
  organization API keys they created whose scope is above their new role are revoked (`admin` keys on
  a demotion to operator; every key when they lose access). `POST /platform/customers/{id}/users/{user}/deactivate`
  revokes tokens whatever `revoke_sessions` says.
- **Promotion: the next request.** Nothing is revoked. The token the person holds still says the old
  role, but every check reads the records, so the new role applies straight away; it shows in the token
  after the next refresh or sign-in.
- **Removing or deactivating someone in the organization their account is bound to** moves the account
  to another organization where they are an active member, or deactivates it when there is none: an
  account can't keep minting tokens for an organization it no longer belongs to. Adding them back as a
  member gives the account its access back.
- **Same-second sign-in.** Built-in tokens carry `iat_ms`, and a revocation records its time to the
  millisecond, so a token minted just after a revocation is not caught by it. Tokens without `iat_ms`
  (other identity providers) keep the whole-second rule.
- **The last admin.** Nobody deactivates or removes themselves when no other active admin would be
  left (403 `last_admin`, journaled `member_change.refused`); this matters in an organization without
  a recorded owner, where it was possible.
- **Records.** Each change is journaled `member_change.applied` and audited
  `auth.member.<role|deactivate|reactivate|remove>` with what was revoked; operator changes also go to
  the platform admin log.
- **Startup reconciliation.** Once per start, idempotently, every account is compared with its
  membership in the organization it is bound to. A missing membership is recorded from the account;
  a disagreement is resolved toward the lesser access (the lower role, disabled if either says so),
  and the tokens of anyone whose access went down are revoked. Each fix is logged with the
  organization and account id only.

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
