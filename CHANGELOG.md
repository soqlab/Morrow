# Changelog

All notable changes to Morrow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Vendor check (`/vendors`, services/vendor_check.py): paste or upload a list of vendor domains (50 without an account, 500 signed in) and Morrow gives each the public grade behind its SSRF guard, budgets and cache, as a background job with live progress. The report answers first ("12 of your 40 vendors would let today's traffic be read later. Worst: payroll.example (RSA key exchange)."), lists vendors worst first linking to `/<domain>`, and offers a polite note per vendor for the buyer to send (Morrow sends nothing). Read-only link `/vendors/r/<token>` (unguessable, expires, revocable), CSV export; signed-in lists can be saved and are re-checked on a schedule under the same link (Celery beat `morrow.vendor_recheck`). Table `vendor_check_reports` is in the Postgres RLS plan
- What changed (`/changes`, `/api/public/changes`, `.atom`, `.rss`, services/changes.py): grades crossing B in either direction, from stored grades only, naming only what the "Not yet post-quantum" rules allow (Tranco popular sites, self-listed ready domains; never opt-outs) and counting the named sector lists per week without names; owners' replies shown; filterable by sector
- Sector reports (`/report`, `/report/<sector>`, `/api/public/report[/<sector>[.csv]]`, services/sector_report.py): share post-quantum ready per sector with its weekly trend, comparison with about three months earlier, distribution, stated sample, method and what is not measured, "as of" time, citation and CSV; plain versions at `/plain/report` and `/plain/changes`
- Watch mode (services/watch.py, docs/PUBLIC_GRADE.md): "Watch this domain" on any `/<domain>` page for a signed-in account. A Celery beat tick (`MORROW_WATCH_SCAN`, every 15 minutes) re-checks watched domains every `MORROW_WATCH_INTERVAL_HOURS` (24, bounded 1-168), at most `MORROW_WATCH_TICK_MAX` (10) a tick, with the public grade's guarded probes and the outside-service check, and records what changed in one answer-first sentence ("statements.example.com became post-quantum ready on Tue 14 Nov — the handshake now uses X25519MLKEM768."): post-quantum gained or lost, grade moves, certificate changes that move the grade, outside services switching. Delivered by browser push (Web Push with VAPID, `MORROW_VAPID_PRIVATE_KEY`; off with a plain sentence when unset), the person's Slack or generic webhooks through the platform's SSRF-guarded sender, and a private Atom feed with an unguessable token; listed on the new `/watching` view. Never email
- Claim this domain: the owner proves it with the existing DNS TXT record (`_morrow-verify`), from the domain page. One organization holds a claim while its record stays published; the claim moves when it is gone. Owners get watching, a fix plan, a public reply, their own opt-out and "Talk to SOQLAB about migrating" (a mail draft to contact@soqlab.com, sent from their own mail app). Unclaimed pages say "Is this your domain? Claim it to get alerts when this changes."
- `/about-scanner` (and `/plain/about-scanner`, `GET /api/public/scanner`): what Morrow's checker sends, how often, how to see your own result and how to opt out
- Harvest clock on every domain page (`/<domain>`): "will what you send today still be secret as long as it needs to be?" (Mosca's inequality). Read from the domain's own key exchange: classical is readable from the chosen quantum year, ML-KEM hybrid is not harvestable. Two dials (how long the data must stay private; when a quantum computer arrives, within the labelled Global Risk Institute estimate, low 2035 / likely 2040, plus Morrow's 2045 outer bound) and an expert-only switching-time dial update the sentence and a one-line timeline in the browser; the choices live in the URL (`?keep=`, `?qday=`, `?switch=`). Reference arithmetic in `decrypt_window.harvest`; `/api/public/basis` now carries `crqc_estimate`.
- Who else is exposing you: `GET /api/public/exposure/{domain}` (services/third_party.py) finds the outside services a domain depends on (homepage script/link/img/iframe/form origins, CNAME chain and CDN, MX, hosted sign-in and checkout names) and runs the existing key-exchange probe on each behind the public grade's SSRF guard (pinned public addresses only, opt-outs honoured); at most 12 hosts, 4 at a time, per-connection timeout, 30 s deadline, per-host and per-domain cache, per-IP / per-domain / global budgets. The domain page lists them worst first with the answer on top ("You're ready, but your payment provider isn't (js.stripe.com)") and a fix per row. Mail is listed, not graded (SMTP is never opened).
- Post-quantum signing for customers (docs/PQ_SIGNING.md): `morrow-sign` (tools/morrow_sign) makes an ML-DSA-65 + Ed25519 key pair on the customer's machine, signs release files or a site's file list, and writes a detached `.morrow-sig`; a signature is valid only when both algorithms verify. Public keys are registered for a verified domain (DNS re-checked live, first verifier wins, proof of possession required), rotated, retired and revoked with their history kept; signatures, manifest file lists and withdrawals go on an append-only public record (never a file, never a private key). Visitors check a file at `/verify/<domain>` by dropping it in the browser, which hashes it and verifies the signature locally with @noble/post-quantum 0.7.1 served from this origin; also `GET /api/verify/<domain>`, `POST /api/verify`, `morrow-sign verify`, and an embeddable badge at `/verify/<domain>/badge.svg`. The console's Signing view (keys, signatures, revocations, upload keys) opens with the answer and follows the depth dial. A new API-key scope, `sign`, can only upload signatures. Tested against NIST ACVP ML-DSA-65 vectors
- Public evidence routes under `/api/public` (docs/PUBLIC_GRADE.md, "Evidence routes"): `/basis` (the decrypt years and their cited source, from the new `services/decrypt_window.py`, which the public grade and the console's per-endpoint `decrypt_window` now share); `/build` (the running commit from `MORROW_GIT_COMMIT` / `RENDER_GIT_COMMIT` / `SOURCE_COMMIT` / `GIT_COMMIT`, never guessed); `/deploys` (a hash-chained deploy transparency log, appended at startup when the commit changes, chain verified on every request); `/manifest` (SHA-256 of every `/ui/` file, unsigned); `/league` (sector averages and their weekly trend only, no site named, from 829 well-known domains in eight sectors each graded at most once a week by a Celery beat tick, `MORROW_LEAGUE_SCAN`, or `python -m services.league --tick`); `/instrument/rank` (signed in: your verified domains against their sector, visible only to you); `/pq-ready` and `/pq-ready.atom` (an opt-in list of verified domains graded A or B whose owners chose to be listed; re-checked weekly, removed automatically below B; never ranked); `/not-ready` and `/not-ready.atom` ("Not yet post-quantum": Tranco top sites whose newest check is below B, measured wording with date and source, sector then name, right of reply for verified owners, `POST /corrections`); `/history/{domain}?detail=1` and `/history/{domain}.atom` (a feed of grade changes)
- `scripts/verify-deploy.py`: checks a running server's pages against `git show <commit>:backend/static/...` and the deploy-log chain
- Passkey sign-in (WebAuthn, py_webauthn 3.0.1): one "Sign in with passkey" button with browser autofill, discoverable credentials, user verification required, single-use server-stored challenges and sign-counter clone detection. Invitations and self sign-up create a passkey, never a password. Users list, rename and remove passkeys (never the last). See docs/AUTH_AND_ACCESS_POLICY.md
- `MORROW_PASSKEYS_ONLY=1` (on in render.yaml): no password sign-in for accounts with a passkey, no new passwords anywhere, password sign-in for remaining password accounts only buys a single-use passkey enrollment, and "forgot password" becomes account recovery (an emailed single-use link that registers a new passkey and can remove the others)
- Sign-in without email: the console's sign-in is one "Sign in with a passkey" button with no email field (discoverable passkeys, no transport restriction, so a phone by QR code works too); accounts can exist without an email (an admin creates one with a display name and hands over a single-use setup link, `POST /auth/accounts`); one-time recovery codes (10 at a time, shown once, only keyed hashes stored, single use, a new set cancels the old) buy a short-lived ticket that can only register a new passkey; emailed recovery is a per-account switch, on for every existing account. See docs/AUTH_AND_ACCESS_POLICY.md
- Domain team sign-in: an admin lets anyone with a verified mailbox at a verified, non-free-mail domain join as a viewer (`/join`, `/domain-join`); DNS re-checked on every join, first verifier wins, every join audited
- Public quantum-readiness grade (docs/PUBLIC_GRADE.md): `GET /api/public/grade/{domain}` (JSON, `.txt` for curl), `/badge/{domain}.svg`, `/stats` and `/history/{domain}`, unauthenticated with CORS for soqlab.com only. A minimal read-only handshake probe on 443 (pinned address, SSRF guard, opt-outs, per-IP/per-domain/global budgets, concurrency cap, 1 h cache) graded A-F on post-quantum key exchange, TLS versions, forward secrecy and certificate validity, with three-level summaries, a sourced "decrypt from" year range (GRI Quantum Threat Timeline 2025) and per-server config fixes. Separate from org scans; stores only in `public_grade_checks`. Batch CLI: `python -m services.public_grade --batch domains.txt --out results.jsonl`
- Scanner accuracy suite against real public endpoints (docs/ACCURACY.md): 422 labelled endpoints (386 TLS, 36 SSH) with labels from OpenSSL 3.5 `s_client` and OpenSSH `ssh -vv`, a runner that scores Morrow's real scanners per protocol and attribute (`backend/accuracy/`), an opt-in `network` pytest, and a weekly workflow that relabels, rescans and reports warnings without failing builds

### Changed
- The old website's pages are retired for the instrument. `/trial` and `/trial-request` redirect (308) to passkey sign-in at `/ui/`; `POST /trial-request` and `POST /api/trial-request` answer 410 Gone with a pointer there, record nothing and email nobody (`MORROW_SELF_SIGNUP` and `MORROW_TRIAL_NOTIFY_EMAIL` no longer do anything); operators still read and decide earlier requests under Customers > Trial requests. `/check` redirects to `/` and `/check?domain=x` to `/x`; `/scanner` redirects to `/about-scanner`, whose facts now include the certificate-transparency check's connections. All three are out of the sitemap, and `static/trial.html`, `check.html`, `check.js`, `check.css` and `check-scanner.html` are deleted
- Terms, privacy, DPA, security, support, data boundary, the checker's terms, acceptable use, privacy and opt-out, pricing, pilot, deployment, enterprise admin, trust passport and AI data control pages wear the instrument's header and footer (`static/doc.css`) instead of the Platform / Security / Pricing / Contact navigation; their text is unchanged. The record pages at `/r/<domain>`, the sign-in pages and the console's tool pages lose that navigation too. The console sign-in says an administrator sets accounts up instead of linking "Request access"
- The checker names itself: every HTTP request of the public grade and the outside-service check sends `User-Agent: MorrowPQCheck/1.0 (+https://morrow.soqlab.com/about-scanner)` (was `SOQLAB-Morrow-PublicGrade/1`) and an `X-Morrow-Check` header linking the host's own result; the instrument's policy allows a same-origin service worker (`worker-src 'self'`) for push
- An account's first passkey deletes its password (`morrow_users.password_hash` is now nullable; the table is migrated in place on startup)
- `morrow_users.email` is nullable and `morrow_users.email_recovery` (default 1) is added, migrated in place on startup with every row kept

### Fixed
- TLS scanner: TLS 1.0 and 1.1 were never detected under OpenSSL 3 (the probes failed locally at the default security level); a TLS 1.2 server with only RSA key exchange was reported as not speaking TLS 1.2 and its certificate was not read
- TLS scanner: hybrid key exchange was missed on servers that accept an offered X25519 share instead of asking for X25519MLKEM768 (Fastly, Akamai, Mozilla and others); the probe now sends a browser-shaped X25519MLKEM768 key share
- Harvest-now-decrypt-later verdict now follows the observed key exchange: an endpoint that negotiates a hybrid ML-KEM group is no longer reported "critical"/"high"

## [0.7.0] — 2026-11-06

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

### Security
- CBOM webhook ingest (`POST /v1/cbom/ingest`) took its organization from the client's `X-Org-Id` header, ran no role check, and checked a signature only when one was sent. It now requires an operator or admin session and refuses a conflicting `X-Org-Id`; CI pushes go to `POST /v1/runtime/cbom/ingest` with a per-organization ingest token (salted hash at rest) that alone names the organization; and once an organization has a signing key, unsigned or wrongly signed documents are refused. `GET /v1/cbom/webhook/setup` is admin-only and read-only (it used to create and show the key to any caller); keys are created explicitly (`POST /v1/cbom/webhook/signing-key`). The generated GitHub Actions step reads credentials from repository secrets instead of embedding the key

### Fixed
- Console "Import SBOM" posted a JSON body to `/sbom/import`, which takes a multipart file upload, so every import failed; it now uploads the file

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
