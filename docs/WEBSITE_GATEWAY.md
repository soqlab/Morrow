# Website gateway: scope and deployment

This release adds a separate Coraza / OWASP CRS HTTP gateway and an authenticated
control-plane workspace at `/ui/#gateway`. It is not a hosted worldwide edge,
automatic DNS-provider integration, DDoS scrubbing network, or production approval.

Recorded local verification results are kept privately; the gateway's own test suite in `gateway/` is the reproducible check.

## Customer workflow

1. Add the public HTTPS hostname and a **different** origin HTTPS hostname.
   Reusing the public hostname would cause a routing loop after DNS cutover.
2. Add the two displayed DNS TXT challenges. Both public and origin names must
   be controlled by the customer. Verification expires after 24 hours. No HTTP
   checks, provisioning, or remote gateway access occur before verification.
3. An administrator downloads the one-time provisioning bundle. The control
   plane encrypts its per-site credential using `MORROW_VAULT_MASTER_KEY`. Reads and
   audit records do not expose the credential. Keep the vault master key stable
   and backed up; configure it through your approved secret manager.
4. On the gateway host, run `python gateway/prepare.py PATH_TO_BUNDLE.json`.
   It writes `gateway/local/state/policy.json` and
   `gateway/local/secrets/gateway.secret`. These paths are git-ignored. Never
   commit the downloaded bundle or secrets. The Docker build also excludes
   secrets, certificates, local state, and bundles from its context.
   Re-provisioning rotates the key;
   replace it on every replica and restart the replicas deliberately.
5. Install the public hostname's production certificate chain and private key
   as `gateway/local/certs/fullchain.pem` and `privkey.pem`. Private TLS keys
   stay on the gateway. On Linux, set `AIRLOCK_GATEWAY_UID` and
   `AIRLOCK_GATEWAY_GID` to the owner of the mounted files; the runtime must be
   able to replace the policy file but must not need root privileges.
6. Run `docker compose -f gateway/compose.yml up -d --build`. The default bind
   is loopback port 8443 for safe local installation. For an approved deployment,
   deliberately set `AIRLOCK_LISTEN_IP` and `AIRLOCK_HTTPS_PORT`, then configure
   DNS or the customer's load balancer to reach it on HTTPS port 443.
7. Restrict the origin to gateway egress addresses or an approved authenticated
   origin arrangement. Do not claim bypass protection merely because DNS points
   to the gateway. The current coverage map reports bypass as **not verified**.
8. Verify the gateway in observe mode. Run the approved HEAD compatibility
   checks, then run real application tests and record customer review for login,
   forms, uploads, and WebSockets. HEAD success is not an application test pass.
   A sample automated application runner is included in
   `scripts/gateway-journeys.example.json` / `scripts/gateway-journeys.js`.
9. Review actual CRS rule IDs and counts. Publish an enforce policy with an
   approval reason, then apply it. Only a matching fresh runtime observation
   produces an observe/enforce coverage state. Saving policy never does.

### Customer-run application tests

Adapt `scripts/gateway-journeys.example.json` to your staging application. Each
journey runs in an isolated browser context: include login steps in any journey
that requires a session. Supply test credentials and upload fixtures through the
manifest's environment-variable references, not through the platform.

```text
node scripts/gateway-journeys.js approved-staging.json local-report.json --approved
```

The runner requires the repository's Playwright installation and Chromium or
Chrome. `--approved` is mandatory because tests submit forms and uploads. Actions
stay on the approved base origin; explicitly list required SSO/subresource origins
in `allowed_origins`. Unapproved HTTP and WebSocket destinations are blocked by
the runner. Review pass/fail results locally, then enter a reference in the console.
The report is not automatically uploaded or presented as independent attestation.

## Runtime and recovery

- The gateway uses Coraza 3.7.0 and OWASP CRS 4.25.0 (locked in `gateway/go.mod`
  and `go.sum`). It does not use a home-grown attack-signature list.
- Observe uses `DetectionOnly`; enforce uses `On`. Each candidate configuration
  must compile and pass an actual XSS-rule self-test before activation. Invalid
  updates retain the old handler and on-disk configuration.
- Remote updates require TLS verification, a fresh HMAC-signed nonce response
  from the expected gateway, and then its per-site credential. Policies cannot
  change site identity or origin, and version rollback is rejected. Restoration
  creates a *new* increasing version containing the selected prior policy.
- The Compose example runs two gateway replicas sharing an atomically replaced
  policy file, checked every three seconds, behind a TCP health-checking HAProxy.
  Linux file locking and a shared-disk version check serialize publishers across
  replicas; an outdated replica cannot overwrite a newer published policy.
  This is same-host redundancy, **not** multi-region HA. A probe sees one
  responding replica, not a fleet consensus. Validate every replica before cutover.
  Failover is not instantaneous: health-check convergence and connection timeouts
  can interrupt requests, and existing WebSocket connections must reconnect.
- Origin TLS validation, DNS failure, or origin failure yields an error. There
  is no automatic direct-origin bypass. DNS rollback requires a separate approved
  DNS change and propagation; policy rollback does not change DNS.
- Exact-path and method-scoped exceptions expire per request within seven days.
  Aggregate blocking rules cannot be disabled as a shortcut. Expiry re-enables
  a rule even if the process is not restarted.
- Each process admits at most 16 simultaneous application requests (including
  open WebSocket sessions). Excess concurrency returns 503, never unfiltered
  traffic. Body sizes are bounded even in observe mode. These conservative
  defaults require customer workload/load testing before capacity planning.
- WebSocket upgrade and bidirectional transport are supported, but CRS does not
  inspect frames after the HTTP upgrade. Response-body inspection is disabled.
  This is an HTTP gateway, not arbitrary TCP/UDP protocol translation.
- Rotation of public TLS certificates currently requires a rolling restart.
  Certificate issuance/renewal automation and provider DNS authorization remain
  deployment integrations, not simulated UI buttons.

## Data boundary and evidence

- HTTPS request content is decrypted and inspected in gateway memory. Do not
  promise content-blind WAF filtering. Deploy the gateway in the customer's own
  cloud when raw requests must remain within their environment.
- Coraza audit/debug payload logging and proxy request/error-detail logging are
  disabled. The error callback extracts numeric rule IDs only, never matched
  data, rule messages, URLs, client IPs, headers, cookies, or bodies.
- Gateway observations retain only numeric event kinds, rule IDs, and timestamps
  in bounded process memory, at most 10,000 events and 0-24 hours. Zero disables
  retention. Counts reset on restart/policy change, and can be erased on the
  responding process. A multi-replica purge requires contacting every replica.
  Storage uses a constant-time ring buffer, not a growing traffic log. An origin's
  own 403 is not labeled as a WAF block. In-flight requests on an old policy
  cannot add observations to the new policy's window.
- The control plane reads allowlisted aggregates only, encrypted credentials,
  DNS challenges, customer-entered review references, and a versioned policy
  approval journal. Do not paste application secrets into review references.
  Aggregate snapshots include the responding instance and policy hash; a replica
  on a different policy does not supply valid statistics for the observed policy.
- Signed observations are from a customer-managed gateway, not hardware
  attestation or an independent audit. A compromised holder of its key can forge
  observations. Probes establish that this hostname returned a gateway response,
  not that every path on every network has been independently tested.
- TLS certificate checking is real. Negotiated post-quantum groups are not measured by
  this release's observation protocol: visitor/origin post-quantum status stays unknown.
  Browser-side TLS, origin-side TLS, and application-layer crypto are distinct.

## Platform setup and verification

Install backend requirements, including the explicit dnspython dependency.
For Postgres, provision `gateway_sites` and `gateway_history` with
`services.gateway.init_tables()` using the migration role, then apply the
existing RLS plan before using a restricted application role. Gateway connections
set the tenant context and all queries additionally include organization scope.
SQLite is supported for local development, not multi-host control-plane HA.

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/test_gateway.py backend/test_e2e_readiness.py -q
docker run --rm -v "${PWD}/gateway:/src" -w /src golang:1.26-alpine go test -p 1 -timeout 120s ./...
node scripts/gateway-workspace-smoke.js
node scripts/gateway-journeys-smoke.js
docker build -t airlock-website-gateway:local-check gateway
backend/.venv/Scripts/python.exe scripts/gateway-runtime-smoke.py
```

`backend/test_gateway_auth.py` exercises the real JWT middleware. Set
`MORROW_TEST_PG_DSN` to a disposable test cluster with database/role creation rights
to run `backend/test_gateway_postgres.py`; it creates and removes its own uniquely
named database and non-bypass role. Never point the test at production.

The runtime smoke test uses an isolated Docker network, loopback-only port, and
short-lived test certificate. It contacts no customer origin and removes its own
containers, network, and generated fixtures on completion. Its failover test allows
health-check convergence; it is not evidence of zero dropped production requests.

Production exit criteria still include real domain/certificate setup, safe DNS
cutover, origin-bypass restriction, all-replica health/failover, application tests,
load testing, a current dependency/security review, backup/restore, and customer
approval. Passing local tests does not complete these operator-controlled steps.

Primary implementation references:
- https://github.com/corazawaf/coraza
- https://github.com/corazawaf/coraza-coreruleset
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/retries/
