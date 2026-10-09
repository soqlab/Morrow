# Operator Console Guide

For vendor operators: the staff who run Airlock Command for customers. Customers never see this console or this guide.

The operator console lives at `/vendor-admin/`. It is deliberately not linked from the public website. Your deployment team publishes its address behind your SSO or VPN gateway. The same guide is shown in the customer console as the operator-only **Administrator Guide**, which only appears when the tab carries an accepted platform key.

What this guide does not claim: SSO was tested against a mocked identity provider and has not been run end to end against a real Okta, Entra ID or Google Workspace account. Section 21 lists what to configure and test before you rely on it.

## 1. Signing in

The console shows a full-page sign-in until you are connected. What you see depends on how the server is configured.

### Sign in with SSO (production default)

1. Open `/vendor-admin/`. When SSO is configured, the screen shows **Sign in with SSO**. The key sign-in is folded underneath.
2. Press **Sign in with SSO** and sign in at your company identity provider.
3. Back in the console, access is granted only if your email is on the operator roster (`PQC_ADMIN_OPERATOR_ROLES`) with a role, or, when no roster is set, in an allowed domain. Anyone else sees "Your account is not an authorized platform operator. Ask an owner to add you to the operator roster."
4. If MFA is required (always in production and staging unless explicitly turned off), the console asks for an authenticator code. See below.

Console sessions end after 30 minutes without activity (`PQC_ADMIN_SESSION_IDLE_SECONDS`) and 8 hours after sign-in at the latest (`PQC_ADMIN_SESSION_ABSOLUTE_SECONDS`). **Sign out** in the operator menu ends the session on the server too. SSO sessions live in a secure cookie that page scripts cannot read; nothing is stored in the tab. **Remember for this tab** only applies to key sign-in.

### MFA enrolment and recovery codes

- **First sign-in:** the screen **Set up your authenticator** shows a QR code and a text key (**Or type this key**). Scan it with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Okta Verify), enter the 6-digit code and press **Verify**.
- **Save your recovery codes:** 10 recovery codes appear once. Store them in a password manager, then press **I saved them — continue**. Each code works once.
- **Later sign-ins:** **Enter your authenticator code**. Lost your phone? Press **Use a recovery code**. Case and the dash don't matter.
- **New codes:** **Access › Operators & roles › Multi-factor authentication › Regenerate recovery codes** (needs a current authenticator code). The old codes stop working.
- **Everything lost:** another **owner** opens **Reset another operator's MFA**, presses **Reset MFA…** and gives a reason. The person's console sessions end and they enrol again at next sign-in. Owners cannot reset their own MFA.
- **Wrong codes:** after 5 failed attempts in 5 minutes the identity must wait ("Too many MFA attempts. Wait five minutes and try again."). Attempts are recorded.

MFA secrets are encrypted with `PQC_VAULT_MASTER_KEY`, so that key must be set for MFA to work.

### Step-up prompts

Some actions ask for a fresh code when your last one is older than 15 minutes (`PQC_ADMIN_STEP_UP_SECONDS`). This applies to SSO sessions and named operator keys with MFA enrolled; if MFA is required and you have not enrolled, the action is refused until you do. The shared key has no identity and is never asked. The dialog **Confirm with your authenticator** accepts a 6-digit code or a recovery code; after **Verify and continue** the action carries on. Actions that ask:

- purge an organization
- run a deleting retention pass
- revoke every session in an organization
- rotate an API key
- change a customer's plan
- migrate platform state
- reset another operator's MFA

### Named operator keys

Scripts, Traffic Lens and people without SSO use named operator keys (`PQC_PLATFORM_OPERATORS`, a JSON list of `name`, `role` and the key's `key_sha256`; create an entry with `cd backend && python -m services.platform_operators --name alice --role operator`). The role is bound to the key and every audit event records the operator name.

Open **Use an operator key** (it reads **Use a named operator key** when the shared key is disabled), paste the key into **Platform admin key** and press **Connect**. When MFA is required, or once the key has enrolled MFA, the key must be verified with a code before use; a verification lasts 8 hours (the absolute session length). The console handles enrolment and verification after you connect, through the MFA card on **Operators & roles**.

### The shared key and break-glass, per environment

| Environment (`PQC_ENVIRONMENT`) | Shared `PQC_PLATFORM_ADMIN_KEY` | MFA default |
|---|---|---|
| `local` (the default) and any value other than those below | Accepted, as **Shared platform key**, up to the ceiling `PQC_PLATFORM_ADMIN_KEY_ROLE`. A request that does not ask for a role runs as auditor. | Off unless `PQC_ADMIN_REQUIRE_MFA=1` |
| `production`, `prod`, `staging`, `stage` | Refused ("The shared platform key is disabled in production. Sign in with SSO…") unless `PQC_ALLOW_BREAK_GLASS_KEY=1` | On unless `PQC_ADMIN_REQUIRE_MFA=0` |

Break-glass rules:

- Use it only when SSO is down and nobody can sign in otherwise.
- Turn it on with `PQC_ALLOW_BREAK_GLASS_KEY=1` and a restart, then sign in with the shared key.
- Every change, and the first read of each page per minute, is recorded as `platform.break_glass_used` with severity high. The bell shows a critical **Break-glass platform key used** notification for 24 hours, and the operator menu warns "Break-glass access: every request is audited with severity high."
- The go-live gate fails **Shared key is break-glass only** while the flag is on.
- Afterwards: remove the flag, restart, and rotate the shared key.

### The operator menu and sessions

The operator menu (top right) shows who you are, your role, **Signed in with** (SSO, Named operator key, Shared platform key or Break-glass shared key), your MFA status and, for SSO, when the session expires. **Access › Sessions › Operator console sessions** lists everyone signed in with SSO (role, method, MFA, last active, expiry); **Revoke…** with a reason signs that person out on their next request.

## 2. Navigation map

The top bar has dropdown menus, a search box (**Ctrl K** or **Cmd K**), the notifications bell and the operator menu. On narrow screens the menus move into a drawer behind the menu button.

- **Dashboard**: KPIs, trends and what needs attention.
- **Customers**
  - **Organizations**: every tenant with status, plan, risk and activity; **New customer**; **Export visible rows**.
  - **Customer 360**: one organization in depth.
  - **Users**: tenant directory, role changes, deactivation, **Add organization member**.
  - **Invitations**: single-use, expiring invitations.
  - **Support sessions**: read-only view-as-customer sessions and revocation.
  - **Onboarding**: activation risk and per-tenant checklists.
  - **Customer feedback**: bugs, ideas and questions to triage.
- **Product**
  - **Usage & adoption**: which features organizations use.
  - **Feature flags**: catalogue and per-organization overrides.
  - **Announcements**: banners in the customer console.
- **Access**
  - **API keys**: issue, rotate and revoke organization keys.
  - **Sessions**: customer sign-in sessions, **Revoke access**, operator console sessions.
  - **Operators & roles**: operator roster, your session, MFA, MFA resets.
  - **Rate limits**: per-organization overrides and 429 pressure.
- **Operations**
  - **Service health**: dependencies, telemetry, request observability, Traffic Lens summary, log storage. The `ai_provider` dependency names the active model provider, its model, and whether tools and streaming are available; a provider that is selected but not fully configured shows as an error with what is missing, while the built-in answerer shows as a configured state rather than a fault.
  - **Traffic Lens**: request metadata by source IP and route (its own page, `/vendor-admin/traffic.html`, same top bar).
  - **Incidents & abuse**: errors, slow requests and rate-limit pressure.
  - **Background jobs**: scheduled work with last and next runs and failures.
  - **Alert routing**: Slack, email, PagerDuty and webhook alerts, with a delivery log.
  - **Maintenance mode**: pause customer writes with a message.
  - **Autopatch**: governed fix intake and draft PRs.
  - **Notifications** (also **View all notifications** in the bell).
- **Security**
  - **Launch readiness**: go-live gate and production readiness checks.
  - **Security truth**: external findings and write-path guardrails.
  - **Tenant isolation & RLS**: cross-tenant probe and row-level security plan.
  - **Audit log**: tenant audit logs, admin audit, authentication events.
  - **Data & retention**: retention runs, state coverage, customer data exports.
- **Help**: **Administrator guide** (opens `/enterprise-admin`), **Support**, **Public website**.

The search palette finds pages, quick actions (**Create customer**, **New announcement**, **Turn maintenance on or off**, **Check launch gate**, **Verify tenant isolation**, **Create API key**, **Revoke access**, **Search admin audit**, **Refresh data**, **Sign out**) and, after two characters, records such as organizations and users.

Roles: **Owner** can do everything, including purge, the operator roster and state migration. **Operator** can change customers, keys, sessions, flags, maintenance and announcements. **Support** and **Auditor** are read-only in the console (write controls are disabled); support can additionally start support sessions.

Traffic Lens uses your console sign-in: if you signed in with SSO in this browser, it detects the session and loads without a key (writes such as **Clear Buffer** carry the session's CSRF token, and **Sign out** ends the session). If the session still waits for an MFA code, it sends you back to `/vendor-admin/` to finish signing in. Without a session, type a named operator key or, locally, the platform key.

## 3. Dashboard

Pick a range with **24h**, **7d**, **30d** or **90d**. Quick actions: **Create customer**, **New announcement**, **Maintenance**, **Check launch gate**.

### KPI tiles

Each tile shows the value for the range, a change against the previous period of the same length, the previous value and a sparkline. Hover a tile to see its source.

| Tile | Definition |
|---|---|
| Organizations | All organizations now; previous = organizations created before the range start |
| Active organizations | Organizations with a successful sign-in or a signed-in request in the range |
| New organizations | Organizations created in the range |
| Users | Sign-in accounts now; previous = accounts created before the range start |
| Active users | Distinct users with a successful sign-in (password or SAML) or a signed-in request |
| New users | Accounts created in the range |
| Successful logins / Failed logins | Authentication journal: login.success and saml.success / login.failure and saml.failure |
| API requests | Requests in the request journal |
| Server error rate (5xx) % | 5xx responses ÷ all requests |
| p95 latency (ms) | 95th percentile response time (nearest rank). Across summarised days it is an estimate from a latency histogram |
| Rate-limited requests (429) | Responses with status 429 |
| Scans | Scans created in the range |
| Assets | Current inventory; no previous value (assets have no creation date) |
| Open remediations | Remediations not rejected or verified-closed; no history, so no previous value |
| Open feedback | Feedback with status new or triaged |
| Autopatches awaiting approval | Autopatch items in needs_review |
| Active API keys | Keys not revoked and not expired; previous = as of range start |
| Active sessions | Built-in sign-in sessions not yet expired; no previous value |
| Admin actions | Platform administration events in the range |

Tile footers mean:

- **no prior data**: the previous period has no usable value to compare with.
- **new this period**: the previous value was zero.
- **no prior period**: the previous period is older than the raw journals and not covered by daily summaries. Hover for the reason.
- **Not tracked**: this server does not produce the metric.
- **No data in range**: the metric exists but has no value, for example an error rate with no requests.

### Charts and lists

- **Signups**, **Active users**, **API requests** (stacked: successful, client errors 4xx, rate limited 429, server errors 5xx), **Latency** (p50 and p95), **Sign-ins**, **Scans**.
- **Top organizations by activity**: requests, sign-ins and scans per organization; open one for its Customer 360.
- **Routes by errors**: route templates with the most 5xx responses.
- **Needs attention**: open notifications, most severe first.
- **Plans**: organizations by plan.
- **Platform status**: go-live verdict, health, alerts, at-risk customers, traffic events and capture policy.
- **Maintenance & announcements**: what customers see right now.

### Coverage, "unavailable" and how history extends

- Raw request records are kept for 7 days (`PQC_TRAFFIC_RETENTION_DAYS`, maximum 30) and sign-in records for 90 days (`PQC_AUTH_LOG_RETENTION_DAYS`, maximum 365).
- Before raw records expire, the **Daily usage rollups** job saves a summary of each finished UTC day per organization: requests, client errors, server errors, rate-limited requests, signed-in requests, a latency profile, successful and failed sign-ins, and scans. Active users are stored as salted hashes, never user ids. It runs at start-up (catching up every complete day still in the raw log) and then every hour (`PQC_USAGE_ROLLUP_INTERVAL_SECONDS`). Summaries are kept 400 days (`PQC_USAGE_ROLLUP_RETENTION_DAYS`).
- The dashboard reads a finished day from its summary as soon as that day is summarised, and the raw log only for today and for any day not summarised yet. A summary is built from exactly the raw rows of that day, so the numbers are the same either way; it is simply much faster than re-reading millions of raw rows on every load. Summaries also hold per-route request and error counts, which is where **Routes by errors** gets its finished days. After an upgrade that changes what a summary holds, the job rebuilds every day still in the raw log before the dashboard uses them again. If you later raise `PQC_TRAFFIC_RETENTION_DAYS`, the days whose raw rows were already deleted under the old setting keep answering from their summary instead of showing a gap.
- A period not covered by raw data or summaries is **blank**, never zero. Charts say "Request data is retained from …; earlier buckets are unknown and left blank." until the summaries cover the range.
- History starts at the last 7 days of raw data on the day the feature is deployed. A fresh deployment reaches full 30-day charts after about 30 days and full 90-day comparisons after about 180 days. Days are UTC; today always comes from the raw log, and so does yesterday until the hourly job has summarised it.
- If the API is down for more than 7 days, those days stay unknown.
- Request attribution to organizations started with this release; older requests stay unattributed. Anonymous requests, rejected tokens and operator traffic to `/platform` and `/vendor-admin` are logged without an organization. Request bodies, query strings, tokens and key secrets are never stored.
- **Unavailable metrics** (bottom of the page) lists every metric this server cannot produce and why.

## 4. Customer 360

Open it from **Customers › Organizations**, a dashboard row, or search.

- **Header**: status, plan, created date, last activity. Actions: **View as customer (read-only)**, **Manage…** (plan, status, lifecycle stage, renewal, account owner, notes, rename, suspend, resume, archive, purge, feature flags), **Suspend**, **Resume**, **Archive…**, **Export** (**GDPR export (JSON)**, **Audit package (ZIP)**, **Tenant audit log (CSV)**).
- **KPIs**: Risk score (activation risk), Scans, Assets, Users, Open remediations, Recent sign-ins. The risk score is an onboarding signal built only from observed facts about this customer — no sign-in on record, no scan, no active user in 7 days, and subscription status — weighted by the platform. It is not a security score and says nothing about their cryptography.
- **Charts**: Sign-ins, API requests (here 429s are counted inside client errors), Scans. These reflect the organization's own signed-in traffic.
- **Cards**: Members, Feature adoption, Recent activity, Onboarding checklist, API keys, Sessions, Feature flags, Account & notes, **Active support sessions**.
- The rate-limit state for the organization is in **Manage…** under **Users & access**: the saved values and whether they are enforced.

## 5. Usage & adoption

- **Adoption**: the share of organizations using each feature in the range.
- **Features** table: organizations using the feature (out of all organizations), event volume, change against the previous period, a trend sparkline and when it was last used.
- A feature counts as used by an organization when that organization has at least one event for it in the range, counted from the product's own records (scans, assets, remediations, webhooks and so on), not from page views.

## 6. Rate limits

**Access › Rate limits** stores two numbers per organization: **API calls per minute** (every signed-in request from that organization) and **Scans per hour** (requests that start a scan: TLS, SSH, SAST, dependency, binary, mobile/IoT, supply-chain, secrets and CI-gate scans, running a scan schedule or collection, crypto discovery). Choose the organization, set both, give a **Reason** and press **Save overrides**.

### Which limit applies

For each organization, in this order:

1. **Override** saved on this page (both values come from it).
2. **Platform default**: `PQC_ORG_DEFAULT_API_CALLS_PER_MIN` and `PQC_ORG_DEFAULT_SCANS_PER_HOUR` (0 = none).

The page note and **Customer 360 › Rate limits** say which one is in force: **operator override**, **platform default**, or **not limited**. The API returns it as `limit_source` (`override`, `plan`, `default`, `none`) with `limit_source_label`.

With none of these, the organization is not limited per organization; per-IP limits still apply. The page then shows the suggested values (100 per minute, 60 per hour) and says "The values shown are the suggested defaults. Save them to enforce them." There is no button to delete an override once saved; lower or raise it instead.

`PQC_ORG_RATE_LIMITS_ENABLED=0` switches enforcement off; values are then stored only.

### Behaviour

- Windows slide: the last 60 seconds for API calls, the last hour for scans. A scan request counts toward both limits, even if the scan is then rejected for bad input.
- Over the limit: HTTP 429 with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0` and a message naming the limit. Allowed responses to a limited organization carry `X-RateLimit-Limit` and `X-RateLimit-Remaining`.
- One organization hitting its limit never affects another.
- **Exempt**: `/platform` and `/vendor-admin`, health and status checks, the web UI and static files, API docs, public pages, all `/auth` routes (they have their own limit, `PQC_RATE_LIMIT_AUTH`, default 10/minute) and anonymous requests.
- A saved change applies at once on the server that saved it and within 15 seconds elsewhere (`PQC_ORG_RATE_LIMIT_CACHE_SECONDS`).

### Redis

With `REDIS_URL` or `CELERY_BROKER_URL` set, all API servers share one count. Without Redis each server counts on its own, so N servers allow up to N times the limit. If Redis fails, servers fall back to local counting and requests are not blocked.

### Seeing 429s

**Rate-limit pressure** on this page and **Operations › Incidents & abuse** list recent blocks by organization and route (sources `org_api_calls_per_min` and `org_scans_per_hour`). That list is in each server's memory and resets on restart. The request journal is the durable record and feeds the "Rate-limited requests (429)" KPI.

## 7. Alert routing

**Operations › Alert routing** sends the same items as the notifications bell to your on-call tools. Owners and operators change channels, and every change needs a reason; support and auditors can view channels and the delivery log.

### What can be alerted

| Kind | When | Severity |
|---|---|---|
| `sla_breach` | A remediation passed its SLA and is still open | critical for high/critical findings, otherwise warn |
| `failed_login_spike` | At least 10 failed sign-ins in the last hour and at least 3× the hourly average of the previous 24 hours | critical |
| `maintenance_overdue` / `maintenance` | Maintenance still on after its end time / maintenance on | critical / warn |
| `go_live_blockers` | The go-live gate has failing required checks or warnings | warn |
| `incident` | API errors or slow requests in the live window | critical if any are high severity, otherwise warn |
| `abuse` | Rate-limit or abuse signals in the live window | warn |
| `security_finding` | An open critical or high external security finding | critical / warn |
| `api_key_expiring` | An organization API key expires within 7 days | warn |
| `org_suspended` | An organization is suspended | warn |
| `feedback` | New customer feedback | warn for a rating of 2 or lower, otherwise info |
| `autopatch_pending` | An autopatch awaits approval | warn |
| `break_glass` | The shared platform key was used as break-glass in production or staging (shown for 24 hours) | critical |
| `support_session` | Vendor support is viewing a customer's console | info, warn for break-glass |

Every kind can be chosen in **Only these kinds**, and PagerDuty resolves each of them when the item clears. The list in the channel editor comes from the server (`notification_kinds` in `GET /platform/alert-channels`), which reads the same catalogue the notifications use.

### Add a channel

Press **Add channel**, choose a **Type**, a **Name**, the target, **Minimum severity** (**Critical only**, **Warn and critical**, **Everything (info, warn, critical)**), optionally **Only these kinds**, **Enabled**, and optional quiet hours (**From**, **Until**, **Time zone (IANA)**, **Still send critical**). Give a reason and press **Save channel**. Then press **Send test** on the row; the message is marked **[TEST]** and the result appears above the list and in the delivery log.

- **Slack incoming webhook**: in Slack, enable Incoming Webhooks for an app, add a webhook for the channel, paste the `https://hooks.slack.com/services/...` URL.
- **Email**: needs platform email (`PQC_SMTP_HOST` and `PQC_SMTP_FROM`, or `PQC_PLATFORM_SMTP_ORG_ID`). Up to 20 comma-separated addresses. Plain-text messages with subjects like `[PQC Scanner] [CRITICAL] …`.
- **PagerDuty Events API v2**: in PagerDuty add the Events API v2 integration to a service and paste its integration (routing) key. The dedup key is the notification id; when the item clears, the incident is resolved. The test opens and immediately resolves a test incident.
- **Generic webhook (JSON)**: an `https://` URL; each alert is a JSON POST with `source`, `event`, `severity`, `subject`, `text`, `link`, `sent_at` and a `notifications` list.

Slack, PagerDuty and webhook targets are encrypted with `PQC_VAULT_MASTER_KEY`; without it those types cannot be saved. After saving, only a hint is shown; leave the target empty when editing to keep it. Webhook URLs must be `https`, contain no username or password and point at a public address; private, loopback, link-local, carrier-grade NAT and reserved addresses are refused on save and on every send, and redirects are not followed.

### Dedupe, renotify, rate cap

- The dispatcher runs inside the API every 60 seconds (`PQC_ALERT_DISPATCH_INTERVAL_SECONDS`). With several API servers only one dispatches at a time.
- **Dedupe**: each channel remembers what it sent; an open item is not re-sent every run.
- **Renotify**: an item still open 24 hours after it was last sent (`PQC_ALERT_RENOTIFY_HOURS`) is sent again, prefixed "Still open:".
- **Resolve**: when an item disappears PagerDuty gets a resolve event; Slack, email and webhooks get nothing. Nothing is resolved from a run in which that source failed to load.
- **Deleting or disabling a PagerDuty channel** resolves every incident that channel still has open first, one resolve per incident (dedup key = notification id), before its routing key is discarded. The response and the delivery log say which incidents were resolved and which were not. A resolve PagerDuty did not accept is kept — with the key, still encrypted — and retried by the dispatcher, up to 10 attempts with a growing wait (`PQC_ALERT_RESOLVE_MAX_ATTEMPTS`); after that the delivery log says to close the incident in PagerDuty. Alerts that went out inside a digest message share one incident whose dedup key is not stored, so those are reported rather than resolved. Re-enabling a channel before a queued resolve goes out drops it: the incident is open again.
- **Rate cap**: at most 20 messages per channel in 10 minutes (`PQC_ALERT_RATE_CAP`, `PQC_ALERT_RATE_WINDOW_MINUTES`). If more are due, the most severe go individually and the last slot becomes one digest. A channel already at its cap waits, and the log shows one "rate limited" entry.
- **Failures** are logged and retried on the next run.
- `PQC_ALERT_DISPATCH_ENABLED=0` stops automatic sending; **Send test** still works.

The **Delivery log** lists every attempt (time, channel, event, status, notification, HTTP status, latency, error), filterable by channel, status and event, kept 30 days (`PQC_ALERT_DELIVERY_RETENTION_DAYS`). Error text never contains the URL or key. Deleting a channel keeps its past log entries, including the resolve it sent for each incident it had open.

## 8. Support sessions

Lets support open a customer's console **read-only**, for a limited time, with a reason the customer sees.

### Starting one

1. **Customers › Customer 360** for the organization, then **View as customer (read-only)**. Requires the owner, operator or support role; auditors can only list sessions and read journals.
2. Fill in **Reason** (at least 10 characters; the customer sees it), **Duration** (5, 15, 30, 45 or 60 minutes; default 30) and **Ticket reference (optional)**.
3. Press **Start read-only session**. The customer console opens in a new tab. The launch link works once, within 60 seconds; if the browser blocked the tab, Customer 360 shows the link for that minute.

The tab shows a dark orange **Support view · read-only** bar with your name, the reason, a countdown and **End session**.

### Limits and what is blocked

- The session behaves like a **viewer** in that organization. Change buttons are greyed out ("Read-only support view: changes are disabled"), and the server refuses every write except ending the session.
- Anything not on the allow-list of read-only pages is refused, and always: stored credentials and secrets (vault, API key material, webhook, Slack, Jira, ServiceNow, email and Cloudflare settings), user, password and token management, bulk exports and downloads (audit CSV, GDPR export, CBOM and scan exports, evidence bundles, readiness and blast-radius exports, installers, generated CI scripts), every `/platform`, `/admin` and vendor admin route, and any other organization.
- Suspended or archived organization: only an owner can start a session, and most customer pages still refuse requests.
- Requires `PQC_AUTH_JWT_SECRET`; without it, starting a session answers 503.

### Ending

**End session** in the bar; the time limit; **Revoke…** from **Active support sessions** in Customer 360 or **Customers › Support sessions** (reason required; the pass stops working within 5 seconds, at once on the server that handled it, and the open tab notices within about 20 seconds); or the customer turning access off (ends immediately).

### Customer opt-in and revocation

Customer organization admins control **Administration › Support access › Allow vendor support access** in their console. It is off unless explicitly approved by the organization admin. Owners cannot override a customer denial. Data Control also exposes this setting and request history. Revocation blocks subsequent support requests; an already-running request cannot be recalled.

### Audit

**Customers › Support sessions** lists every session, filterable by organization, status and operator or ticket, with a **Request journal** of every request made. The customer's audit log records start, launch, revoke and expiry, plus role-checked data loaded under the actor `support:<session id>`. The customer also sees every request the session made (path and time, from the same journal) in **Administration › Support access › Pages viewed**; `GET /org/support-access/history` returns only the caller's own organization's sessions and requests. Expiry is recorded the next time someone lists sessions, opens notifications, loads the customer's history or uses the expired pass.

## 9. Invitations

**Customers › Invitations**: choose the **Organization**, the **Role** (viewer, analyst (operator), org admin (admin)), the **Email**, **Expires after (hours)** (1 to 720, default 72) and a **Reason**, then **Create invitation**. The **Invitation created** dialog shows the invite link once; use **Copy invite link** and send it over a trusted channel. If platform email is configured, each pending invitation has **Email the invite**, which sends the link to the invited address only.

The link looks like `https://<public URL>/invite#token=…` (base from `PQC_PUBLIC_BASE_URL`, otherwise the request origin). The code after `#` is not sent to servers, so it stays out of logs and Referer headers. The invite page shows organization, role, the masked address, expiry and status, and handles "not signed in", "different email", expired, used, revoked and not-found cases. The server enforces: signed in with the matching email, one use, not expired or revoked; lookups are rate limited with the sign-in limit (`PQC_RATE_LIMIT_AUTH`).

Customer organization admins can also invite from their console (**Administration › Invitations › Invite**) and get the same link.

## 10. Announcements and maintenance

- **Product › Announcements**: **Title**, **Message**, **Severity** (info, warn, critical), **Audience** (**All customers** or **Selected organizations** by id), optional **Starts** and **Ends** (local time), then **Publish announcement**. The list shows active, scheduled and expired notices. In the customer console info and warn notices can be dismissed per browser (they reappear if edited); critical notices cannot.
- **Operations › Maintenance mode**: **Customer message**, **Expected end (local time)**, **Reason**, then **Turn maintenance on…** or **Turn maintenance off**. While on, customer requests other than GET, HEAD and OPTIONS answer 503 with your message; sign-in, reads, health, status and platform administration keep working. The expected end is informational: writes stay paused until an operator turns maintenance off, and an overdue window raises a critical notification. Customers see a **Maintenance in progress** banner that cannot be dismissed. Pair it with an announcement.

## 11. Background jobs

**Operations › Background jobs** lists each job with kind, status, last run, next run, runs in 24 hours and the last error: Scheduled scans, Remediation validation, Digest snapshots, Drift sentinel snapshots, Data retention, Webhook deliveries, **Daily usage rollups** (days summarised and range), Request journal writer, Maintenance state cache, Async worker (Celery), **Alert routing dispatcher** (last run, last error, attempts and failures in 24 hours, whether the loop is running, and any PagerDuty resolves from a deleted or disabled channel still waiting to be retried).

## 12. Notifications

The bell groups items by **Critical**, **Warning** and **Info**, refreshes every 60 seconds while the tab is visible, and links each item to the page that deals with it. **Mark all read** is remembered for this tab only. **Operations › Notifications** shows the full list.

## 13. Audit and exports

- **Security › Audit log**:
  - **Tenant audit log**: one organization's tamper-evident log, filter by actor, action and decision, **Export CSV**.
  - **Admin Audit**: every platform administration change with operator, role, organization, reason and time; search, filter by organization, action prefix, operator and dates; **Export CSV**.
  - **Authentication events**: real outcomes (password and SAML sign-ins, refreshes, revocations, rejected tokens, rate limiting). Identity-provider failures need the provider's own logs.
- **Customer 360 › Export** and **Security › Data & retention › Customer data export**: GDPR export (JSON; owner or operator) and audit package (ZIP). Every export is recorded.
- **Data & retention**: preview (**Preview (dry run)**) then **Delete matching rows…** for aged operational records; audit logs are never deleted.
- **Traffic Lens**: filter by IP and route and export up to 5,000 matching requests as NDJSON or OTEL JSON.

## 14. Launch readiness (go-live gate)

**Security › Launch readiness › Go-Live Gate** returns **go** only when every required check passes and no blocking warning stands; advisories are reported but do not block. The required checks include environment, auth mode and auth required, default role, JWT config and issuer, CORS, allowed hosts, platform admin key checks, production demo lockout, security headers, traffic monitor and persistence, security journal, state backend scaling, observability, Airlock signing and agent signatures, retention policy, Postgres, RLS, database role, secrets and queue, plus three operator sign-in checks:

- **Operator SSO**: issuer, client id and a roster or allowed domains are configured.
- **Operator MFA required**: set `PQC_ENVIRONMENT=production` and do not set `PQC_ADMIN_REQUIRE_MFA=0`.
- **Shared key is break-glass only**: fails while `PQC_ALLOW_BREAK_GLASS_KEY=1`.

The gate also lists manual exit criteria (real GitHub App pilot, tenant isolation via POST `/platform/tenant-isolation/verify`, backup and restore drill, audit package review, dashboards checked during pilot traffic, CI security workflow, threat model sign-off). `scripts/check-go-live-gate.ps1` runs the same gate from a shell.

The gate reads settings. It cannot tell you whether the accounts behind them work, because it never
calls them. `scripts/check-integrations.py` does, and it is the check to run before you hand the URL
to a customer:

- `.\scripts\check-integrations.ps1` checks SSO, alert channels, Redis, Postgres, the vault key and the AI provider.
- `.\scripts\check-integrations.ps1 -Offline` checks configuration only, with no network call at all.
- `.\scripts\check-integrations.ps1 -SendTest` also sends ONE labelled test message to each enabled alert channel.

Each area comes back **CONFIGURED**, **MISSING** or **ERROR** with a one-line fix, and it exits `0`
when nothing is broken, `1` when something configured is failing, `2` when a required production
setting is missing. It never prints a secret value, and nothing is sent to a customer: the alert test
message is the only outbound write, it needs `-SendTest`, and it is labelled as a test. Section 1a of
[PRODUCTION_DEPLOYMENT_RUNBOOK.md](PRODUCTION_DEPLOYMENT_RUNBOOK.md) lists what each area checks.

## 15. Runbook: onboard a new customer

1. **Create the organization.** **Customers › Organizations › New customer**: **Organization id** (for example `acme-bank`), **Display name**, **Plan**, **Initial status** (active or trial), **Reason** (for example the order form reference), **Create customer**.
2. **Invite the customer admin.** **Customers › Invitations**: organization, role **org admin (admin)**, their email, expiry, reason, **Create invitation**. Copy the link and send it over a trusted channel, or use **Email the invite**. The person must be able to sign in with that email (through the customer's configured SSO or JWT identity, or a built-in account): there is no self sign-up.
3. **Set limits.** If this organization needs limits other than the platform default, **Access › Rate limits**: choose the organization, **API calls per minute**, **Scans per hour**, reason, **Save overrides**. Leave it alone to use the plan or platform default.
4. **Verify in Customer 360.** Refresh the organization: **Members** shows the admin once they accept; **Manage… › Users & access** shows the rate-limit enforcement state; **Onboarding checklist** shows the next activation steps; **Recent activity** shows your admin changes.
5. **Tell the customer** that support access requires explicit approval and where to control it (**Administration › Support access**).

## 16. Runbook: an alert arrives

1. **Acknowledge** in your on-call tool so nobody else starts the same work. A message beginning "Still open:" is a 24-hour reminder, not a new problem.
2. **Open the console** and the bell or **Operations › Notifications**. Each item links to the page that deals with it.
3. **Triage by kind:**
   - `incident`: **Operations › Incidents & abuse** and **Service health** (request observability shows recent errors and slow requests); check **Background jobs** for failing jobs.
   - `abuse` or 429s: **Incidents & abuse** and **Access › Rate limits › Rate-limit pressure**; decide whether a limit is too low or a client misbehaves. Use **Traffic Lens** for source IPs and routes.
   - `failed_login_spike`: **Security › Audit log › Authentication events**; consider **Access › Sessions › Revoke access** for affected users or organizations.
   - `maintenance_overdue`: finish the work or **Turn maintenance off**.
   - `go_live_blockers`: **Security › Launch readiness**.
   - `security_finding`: **Security › Security truth**.
   - `api_key_expiring`: **Access › API keys**; rotate with a grace period.
   - `org_suspended`, `sla_breach`, `feedback`, `autopatch_pending`: open the linked customer, remediation, feedback or autopatch.
   - **Break-glass platform key used** (bell): confirm the emergency is real; when over, remove `PQC_ALLOW_BREAK_GLASS_KEY`, restart and rotate the shared key.
4. **Communicate** if customers are affected: publish an announcement, and use maintenance mode if writes must stop.
5. **Resolve** the cause. The item clears from notifications on its own; PagerDuty incidents resolve automatically for the kinds in section 7. Resolve other incidents in PagerDuty yourself.
6. **Check delivery** if an expected alert never came: **Alert routing › Delivery log** (failed, suppressed during quiet hours, or rate limited) and the **Alert routing dispatcher** job.
6. **Record** what happened; admin changes are already in **Admin Audit**.

## 17. Rotating the vault master key

`PQC_VAULT_MASTER_KEY` encrypts stored integration credentials, gateway site keys, operators' MFA secrets, GitHub sign-in tokens and alert channel targets. `scripts/rotate-vault-master-key.py` re-encrypts all five.

1. Schedule a maintenance window and back up the databases.
2. Put the current key in `PQC_VAULT_MASTER_KEY` and the new one in `PQC_VAULT_MASTER_KEY_NEW` in the shell only, or pass `--generate-new-key-file <path>` to create one (written only to that owner-only file, never shown).
3. Rehearse (default, changes nothing): `backend/.venv/Scripts/python.exe scripts/rotate-vault-master-key.py`. If any value cannot be decrypted with the current key, it stops and changes nothing.
4. Apply: add `--apply`. Values are verified with the new key before commit.
5. Store the new key as `PQC_VAULT_MASTER_KEY` in the secret manager, restart every server and worker, and check integrations, gateways and MFA sign-in.
6. Press **Send test** on one Slack, PagerDuty or webhook alert channel to confirm its target decrypts with the new key.
7. Destroy the old key and the key file.

Also: SAML users sign in again; evidence signed with the vault key (when no `PQC_EVIDENCE_SIGNING_KEY` is set) no longer verifies, so set a dedicated evidence key first; and, if `PQC_USAGE_ACTOR_SALT` is unset, distinct-user counting restarts.

## 18. Environment variable reference

Names and defaults as read by the code; `.env.prod.example` carries a commented section for each group.

### Operator sign-in

| Variable | Default | Meaning |
|---|---|---|
| `PQC_ENVIRONMENT` | `local` | `production`, `prod`, `staging` and `stage` are strict: shared key refused, MFA on |
| `PQC_ADMIN_OIDC_ISSUER` | none | Identity provider issuer URL |
| `PQC_ADMIN_OIDC_CLIENT_ID` | none | OIDC client id |
| `PQC_ADMIN_OIDC_CLIENT_SECRET` | empty | Leave empty for a public PKCE client |
| `PQC_ADMIN_OIDC_REDIRECT_URI` | `{PQC_PUBLIC_BASE_URL}/vendor-admin/sso/callback` | Must match the IdP registration |
| `PQC_ADMIN_OPERATOR_ROLES` | none | Roster: `email=role` pairs (owner, operator, support, auditor) |
| `PQC_ADMIN_OIDC_ALLOWED_DOMAINS` | none | Allowed email domains |
| `PQC_ADMIN_OIDC_DOMAIN_ROLE` | `auditor` | Role for domain members when no roster is set |
| `PQC_ADMIN_OIDC_SCOPES` | `openid email profile` | Requested scopes |
| `PQC_ADMIN_OIDC_EMAIL_CLAIM` | `email` | Claim holding the email |
| `PQC_ADMIN_OIDC_REQUIRE_EMAIL_VERIFIED` | `1` | Require `email_verified=true` |
| `PQC_ADMIN_SESSION_ABSOLUTE_SECONDS` | `28800` | Longest console session; also how long a named key's MFA verification lasts |
| `PQC_ADMIN_SESSION_IDLE_SECONDS` | `1800` | Inactivity timeout |
| `PQC_ADMIN_REQUIRE_MFA` | on in production/staging | Require TOTP |
| `PQC_ADMIN_STEP_UP_SECONDS` | `900` | How recent a code must be for risky actions |
| `PQC_ALLOW_BREAK_GLASS_KEY` | off | Accept the shared key in production/staging |
| `PQC_PLATFORM_ADMIN_KEY` | none | Shared key (break-glass in production) |
| `PQC_PLATFORM_ADMIN_KEY_ROLE` | `owner` | Ceiling for the shared key |
| `PQC_PLATFORM_OPERATORS` | none | Named operator keys (JSON list with `key_sha256`) |
| `PQC_VAULT_MASTER_KEY` | none | Required for MFA secrets and encrypted alert targets |
| `PQC_VAULT_MASTER_KEY_NEW` | none | Only for a rotation run |

### Usage rollups and rate limits

| Variable | Default | Meaning |
|---|---|---|
| `PQC_USAGE_ROLLUPS_ENABLED` | `1` | Daily summaries on or off |
| `PQC_USAGE_ROLLUP_INTERVAL_SECONDS` | `3600` | Check interval (minimum 60) |
| `PQC_USAGE_ROLLUP_RETENTION_DAYS` | `400` | Summary retention (35 to 3650) |
| `PQC_USAGE_ACTOR_SALT` | derived from `PQC_VAULT_MASTER_KEY` or `PQC_AUTH_JWT_SECRET` | Salt for active-user hashes; set a long random value and keep it stable |
| `PQC_TRAFFIC_RETENTION_DAYS` | `7` (max 30) | Raw request records |
| `PQC_AUTH_LOG_RETENTION_DAYS` | `90` (max 365) | Raw sign-in records |
| `PQC_ORG_RATE_LIMITS_ENABLED` | `1` | Per-organization enforcement |
| `PQC_ORG_RATE_LIMIT_CACHE_SECONDS` | `15` | Override cache per server |
| `PQC_ORG_DEFAULT_API_CALLS_PER_MIN` | `0` | Default per-minute limit (0 = none) |
| `PQC_ORG_DEFAULT_SCANS_PER_HOUR` | `0` | Default hourly scan limit (0 = none) |
| `REDIS_URL` / `CELERY_BROKER_URL` | none | Shared rate-limit counters across servers |
| `PQC_RATE_LIMIT_AUTH` | `10/minute` | Sign-in and invite lookups |

### Support sessions

| Variable | Default | Meaning |
|---|---|---|
| `PQC_AUTH_JWT_SECRET` | none | Required; without it sessions answer 503 |
| `PQC_SUPPORT_SESSION_CACHE_SECONDS` | `5` (capped at 5) | How long a server trusts a cached session status |

### Alert routing and platform email

| Variable | Default | Meaning |
|---|---|---|
| `PQC_ALERT_DISPATCH_ENABLED` | `1` | Automatic sending (tests always work) |
| `PQC_ALERT_DISPATCH_INTERVAL_SECONDS` | `60` | Dispatcher interval (10 to 3600) |
| `PQC_ALERT_RENOTIFY_HOURS` | `24` | Re-send items still open |
| `PQC_ALERT_RATE_CAP` | `20` | Messages per channel per window |
| `PQC_ALERT_RATE_WINDOW_MINUTES` | `10` | Rate-cap window |
| `PQC_ALERT_DELIVERY_RETENTION_DAYS` | `30` | Delivery log retention |
| `PQC_SMTP_HOST`, `PQC_SMTP_PORT`, `PQC_SMTP_USER`, `PQC_SMTP_PASSWORD`, `PQC_SMTP_FROM`, `PQC_SMTP_STARTTLS` | unset; port `587`, STARTTLS `1` | Platform email for alert emails and **Email the invite** |
| `PQC_PLATFORM_SMTP_ORG_ID` | unset | Reuse one organization's saved SMTP settings instead |
| `PQC_PUBLIC_BASE_URL` | request origin | Base for invite links and links in alerts; set it in production |

### Customer console assistant (CipherLens)

CipherLens is provider-agnostic. One environment variable picks the adapter; the rest configure it. The full reference, the capability table and how to add an adapter are in [docs/AI_PROVIDERS.md](AI_PROVIDERS.md).

| Variable | Default | Meaning |
|---|---|---|
| `PQC_LLM_PROVIDER` | unset | Which adapter answers: `anthropic`, `openai`, `azure-openai`, `gemini`, `openai-compatible`, `ollama`, `builtin`, `custom`. Unset keeps the original behaviour (the last two rows) |
| `PQC_LLM_MODEL` | unset | Model name, or the Azure deployment when `PQC_LLM_AZURE_DEPLOYMENT` is not set |
| `PQC_LLM_BASE_URL` | per provider | API root. Required for `azure-openai` and `openai-compatible` |
| `PQC_LLM_API_KEY` | unset | Credential for the chosen provider. Not needed for `ollama` or `builtin` |
| `PQC_LLM_HEADERS` | unset | Extra headers for a gateway, as a JSON object or `k=v,k=v`. `Host`, `Content-Type`, `Content-Length` and the hop-by-hop headers are refused |
| `PQC_LLM_API_VERSION` | `2024-10-21` for Azure | Azure OpenAI `api-version` |
| `PQC_LLM_AZURE_DEPLOYMENT` | unset | Azure deployment name (the model lives in the URL on Azure) |
| `PQC_LLM_TEMPERATURE` | `0.1` | Sampling temperature |
| `PQC_LLM_MAX_TOKENS` | `3000` | Output ceiling for one turn |
| `PQC_LLM_TIMEOUT` | `60` | Per-request timeout in seconds |
| `PQC_LLM_RETRIES` | `2` | Retries for rate limits, timeouts and 5xx, with 0.5s/1s/2s backoff. A bad key or a rejected model is never retried |
| `PQC_LLM_TOOLS` | adapter's own answer | `1`/`0` to override whether this endpoint supports tool calling. Needed for `openai-compatible` and `ollama`, where it depends on the server and the model |
| `PQC_LLM_STREAM` | adapter's own answer | `1`/`0` to override the streaming capability |
| `PQC_LLM_CONTEXT_WINDOW` | per provider | Context window to report, where the adapter cannot know it |
| `PQC_LLM_PRICE_INPUT_PER_MTOK`, `PQC_LLM_PRICE_OUTPUT_PER_MTOK` | unset | Your prices per million tokens. Unset means cost is reported as **unknown** rather than guessed |
| `PQC_LLM_CUSTOM_MODULE` | unset | With `PQC_LLM_PROVIDER=custom`, the dotted import path of your own adapter. Copy `examples/custom_llm_provider.py` |
| `PQC_LLM_DISABLED` | unset | `1` forces the built-in answerer. No model call leaves the deployment, and **no organization setting can override it** |
| `ANTHROPIC_API_KEY` | unset | CipherLens uses Claude when set and `PQC_LLM_PROVIDER` is not |
| `OPENAI_API_KEY` | unset | Used when no Anthropic key is set. With neither key, CipherLens answers with built-in guidance and notes that no AI provider is configured |

**What the console shows.** Every CipherLens answer carries a line naming the provider and model that produced it, or saying the built-in rules answered and no model was called. That line is emitted by the code that made the call, so it cannot name a model that did not reply. When the chosen provider does not support tool calling, the assistant answers from stored evidence without tools and says so. When the provider is unreachable, the answer degrades to the built-in rules with the reason attached, never to a dead end.

**The customer's own page.** A customer admin opens **Data Control > 06 / Model provider** to see the active provider, its model, whether tools and streaming are available, the destination, and what reaches a model. They can supply their own provider and key there -- sealed with this deployment's vault key, never returned by any endpoint, and readable or writable only by their own organization -- and prove it with **Send a test prompt**, which makes one real receipted call. Changing the destination or the model invalidates the approved Data Control policy, so section 01 has to be approved again before the next model call.

**In Service health.** The `ai_provider` dependency row on **Operations › Service health** carries the same summary for the deployment as a whole, so a broken provider shows up next to the database and Redis rather than only inside a customer's page.

**Checking it from the shell.** `python scripts/check-integrations.py --only ai` names the active provider, how it was selected, and anything missing, without touching the network. Add `--check-ai` to spend one cheap read proving the credential and the endpoint.

## 19. Identity provider setup (summary)

Create an OIDC web application with redirect URI `https://<console host>/vendor-admin/sso/callback`, authorization code grant (PKCE is automatic) and scopes `openid email profile`. Then:

- **Okta**: issuer `https://your-org.okta.com` (or `/oauth2/default`); assign the app to your operators group.
- **Microsoft Entra ID**: issuer `https://login.microsoftonline.com/<tenant id>/v2.0`, never `common`. Entra does not send `email_verified`: add the optional `email` claim, or set `PQC_ADMIN_OIDC_EMAIL_CLAIM=preferred_username` and `PQC_ADMIN_OIDC_REQUIRE_EMAIL_VERIFIED=0` with the tenant-specific issuer only.
- **Google Workspace**: issuer `https://accounts.google.com`, consent screen **Internal**, and `PQC_ADMIN_OIDC_ALLOWED_DOMAINS=yourcompany.com`.

Prefer an explicit roster (`PQC_ADMIN_OPERATOR_ROLES`). Removing an email takes effect on that person's next click. Full detail: "Operator SSO, MFA and break-glass" in `docs/COMPLETE_DOCUMENTATION.md`.

## 20. What the platform will not invent

A customer's console shows a figure only when it is measured from that customer's own data, or when it
is labelled as a model or reference with its assumptions and sources attached. Two rules follow, and
support will be asked about both.

- **No peer, sector or industry comparison exists.** The platform receives no other organization's
  posture, so it publishes no percentile, quartile, sector average or "top quartile" figure anywhere.
  The Board & ROI screen's **Peer benchmark** tile reads "—" for every customer, on purpose. If a
  customer asks how they compare to their industry, the honest answer is that the platform has no
  such data and does not estimate it.
- **An empty workspace returns "not enough data yet", never a score.** Until a customer has at least
  one scanned asset on record, `/crypto-agility`, `/board-risk` (and its regulatory and leaderboard
  views), `/migration-velocity`, `/compliance-mapping`, `/actuarial/individual`, `/trust-passport`
  and the FIPS migration timeline all answer with `available: false`, a `reason`, a `minimum_data`
  block naming what is needed, and null in every score field. A new customer is unmeasured, not
  low-scoring, and must not be shown as "Crypto-Rigid", a board score of 65, or a migration that is
  already complete.

Minimum data per metric, as the API reports it in `minimum_data`:

| Metric | Minimum before a number is published |
|---|---|
| Crypto-agility (CryptoFlex score) | 1 scanned asset; each dimension also needs its own evidence (a cadence needs 2 scans, velocity needs 1 resolved remediation) |
| Board risk index, regulatory alignment | 1 asset on record |
| Team agility leaderboard | 1 team with an asset or remediation |
| Migration velocity and projection | 1 scanned asset |
| Compliance framework mapping and grades | 1 scanned asset |
| FIPS migration timeline | 1 scanned asset |
| Actuarial exposure and premium model | 1 asset on record |
| Trust Passport score | 1 evidence record (scan, asset, CI/CD run, firmware scan or canary) |
| Compliance readiness score | 1 finding or 1 remediation |
| Executive risk signal | 1 asset on record |

Figures that are kept because they are modelled or published, not measured, always carry a
`model_basis` block stating the kind (`model`, `reference` or `seed`), a one-line summary, the
assumptions and any sources: Q-Day and HNDL forecasts, the ROI and actuarial models, the FIPS effort
estimate, the playbook time estimates, and the numeric thresholds in the zero-knowledge compliance
profiles (the framework names are real; the pass/fail numbers are the platform's own policy).

## 21. Not verified end to end, and known gaps

`scripts/check-integrations.py` (section 14) answers the configuration half of each one in a single
run; the rest needs a real transaction. Configure and test these in staging before relying on them:

- **SSO** against your real identity provider: sign-in, roster denial, email-claim handling (especially Entra ID), MFA enrolment, step-up and session revoke.
- **Alert channels**: a real Slack webhook, SMTP relay and PagerDuty service, including PagerDuty auto-resolve.
- **Redis-shared rate limits** across more than one API server.

Known gaps found while writing this guide:

- Fixed since the first edition: vault key rotation now covers alert channel targets; break-glass and support-session notifications are selectable kinds and auto-resolve in PagerDuty; Traffic Lens accepts SSO sessions; the console shows the vendor portal link to operators only; CipherLens answers without an AI key; customers see every page a support session requested; deleting or disabling a PagerDuty channel resolves the incidents it left open.
