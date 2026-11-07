# Demo runbook: Morrow 0.7.0 against real services

Every 0.7.0 feature run once end to end against real software in containers, not mocks, with the
exact commands to repeat the run. The same run is automated as `backend/e2e_real/` and the CI job
`.github/workflows/e2e-real.yml` (push to main and manual dispatch).

Run on 2026-11-07 on a shared Windows 11 laptop (Docker Desktop, heavily loaded by other work) from
branch `real-services-e2e`. The final local results, `backend/e2e_real` against this stack: 15
tests, 14 passed across runs and the migration-proof test an expected failure (strict xfail, see
section 6). On that laptop a full pass took close to an hour because of the load; the CI job is
sized for under 20 minutes. Status per feature:

| Feature | Real service | Status |
| --- | --- | --- |
| IKEv2 / IPsec scanner | strongSwan 6 (fixture), dnsmasq for domain verification | verified 2026-11-07 (3/3 tests) |
| Passive TLS discovery | nginx 1.29 + Fluent Bit 4.1, Envoy 1.39 + Vector 0.50 | verified 2026-11-07 after fixing the Envoy setup (docs and deploy/e2e config); 4/4 tests |
| Crypto kill switch | nginx 1.29 on OpenSSL 3.5 | verified 2026-11-07 after fixing the scanner (it reported the hybrid nginx as classical) |
| Gradual PQ rollout | Prometheus 3.7 (HTTPS) scraping Envoy 1.39 | verified 2026-11-07: gate pass on healthy traffic, 1-minute soak, forced failure rolled back (the HTTP error gate tripped first), unreachable Prometheus inconclusive |
| CBOM import (CBOMkit output) | CBOMkit output (Keycloak, vendored) | verified 2026-11-07 (import and dedup of real CBOMkit output) |
| Signed CI CBOM ingest | the generated GitHub Actions step (openssl + curl) | verified 2026-11-07 (signed upload accepted; wrong key and unsigned refused) |
| Migration proof (Ed25519 + ML-DSA-65) | real scans of nginx, `scripts/verify_migration_proof.py` | blocked by a product gap: a real endpoint with a classical certificate never scans clean, so its remediation never closes and no proof can be issued (details in section 6); the offline verifier was not run on a real proof |
| Migration milestones | backend API only | verified 2026-11-07 |
| Cert / KMS inventory | Keyfactor, Venafi, DigiCert, AWS/Azure/GCP KMS | needs credentials (no local emulator for any connector) |
| Ticket sync (Jira / ServiceNow) | Jira Cloud / ServiceNow | needs a Jira or ServiceNow sandbox; only the contract test `backend/test_ticket_sync.py` runs |
| GitHub PR creation | GitHub | needs a token; skipped (the kill switch and rollout run in hand-applied / dry-run mode) |

Console (Playwright, `deploy/e2e/console-smoke.js`), verified 2026-11-07: Asset Inventory ›
Passive discovery lists the shipped Envoy/nginx endpoints including X25519MLKEM768; Scanners › VPN
(IKEv2) scans `vpn.e2e.morrow.test` from the browser and shows ML_KEM_768; the CBOM view lists the
CBOMkit import. The kill-switch / rollout page (`/ui/crypto-switch.html`) was not driven: it only
uses a signed-in bearer session (`morrow_token`), and this stack runs header auth.

```sh
MORROW_E2E_BASE_URL=http://127.0.0.1:18000 MORROW_E2E_ORG=e2e-demo-org PLAYWRIGHT_MODULE=<path to node_modules/playwright> node deploy/e2e/console-smoke.js
```

## What was broken, and is fixed on this branch

1. **The scanner reported hybrid-capable servers as classical.** The key-exchange probe sent only an
   X25519 key share. nginx on OpenSSL 3.5 with `ssl_ecdh_curve X25519MLKEM768:X25519` takes an
   acceptable client share instead of asking for another, so it answered X25519 to Morrow while curl
   (which sends an X25519MLKEM768 share) got X25519MLKEM768. Every scan of such a server said
   "classical", and the kill switch could never confirm a switch. The probe now sends
   X25519MLKEM768 and X25519 shares, as browsers do (`backend/scanner.py`, test
   `backend/test_scanner_hybrid_key_share.py`).
2. **Without a Celery broker, a clean rescan never closed a merged remediation.** The in-process scan
   worker (`app._scan_worker`, used whenever no broker is reachable) skipped the verify loop that the
   Celery task runs, so a single-node install could never reach `verified_closed` and so never issue
   a migration proof (`backend/app.py`, test `backend/test_inprocess_scan_verify_loop.py`).
3. **docs/PASSIVE_DISCOVERY.md gave an Envoy config that does not work as written.**
   `%DOWNSTREAM_TLS_GROUP%` only exists from Envoy 1.39 (1.36 refuses to start with it), and
   `%REQUESTED_SERVER_NAME%` is empty unless the listener runs the TLS inspector, so every line was
   dropped as `missing_host`. Both are documented now, with a tested config.

Observed but not changed: a CBOM pushed through the signed CI route (`/v1/runtime/cbom/ingest`) is
stored and listed under CBOM › Webhook ingests, but it is not merged into the crypto inventory
(`GET /v1/crypto-inventory`); only `POST /v1/cbom/import` feeds the inventory.

## The stack

`deploy/e2e/compose.yml`, project name `morrow-e2e`, network `172.30.77.0/24`. Images are pinned by
digest.

| Service | What it is |
| --- | --- |
| `backend` | Morrow API (uvicorn), SQLite in a named volume, `MORROW_AUTH_MODE=headers`, `MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1`, `MORROW_CODE_HOSTS_ALLOW_PRIVATE=1`. Published on `127.0.0.1:18000`. |
| `dns` | dnsmasq. The backend resolves through it, so domain verification reads a real TXT record. |
| `strongswan-pq`, `strongswan-classic` | `backend/tests/fixtures/strongswan`, as `vpn.e2e.morrow.test` and `vpn-classic.e2e.morrow.test` |
| `nginx` | nginx 1.29 / OpenSSL 3.5, `nginx.e2e.morrow.test:443`, RSA-2048 certificate, key-exchange groups from `state/nginx-groups.conf` |
| `envoy` | Envoy 1.39: `:10443` classic (X25519, P-256), `:11443` X25519MLKEM768 only, admin `:9901` |
| `prometheus` | Prometheus 3.7 over HTTPS (`prometheus.e2e.morrow.test:9090`), scraping Envoy every 2 s |
| `traffic` | curl (OpenSSL 3.5) against all three listeners; `state/traffic_mode` = `fail` adds X25519-only clients and `/fail` (503) requests on the PQ listener |
| `fluent-bit`, `vector` | profile `shippers`: ship the nginx and Envoy access logs with ingest tokens |

`deploy/e2e/gen-state.sh` writes `deploy/e2e/state/` (git-ignored): a throw-away CA and
certificates, the backend vault key, the dnsmasq and nginx group files.

## Start it

From the repository root, in Git Bash or any POSIX shell:

```sh
sh deploy/e2e/gen-state.sh
export MORROW_E2E_VAULT_KEY="$(cat deploy/e2e/state/vault.key)"

# CI builds backend/Dockerfile. On a laptop that already has an image with the backend's
# requirements, put the checkout's code on top of it instead (much faster):
docker build -t morrow-e2e-backend:local backend
#   or: docker build -t morrow-e2e-backend:local -f deploy/e2e/backend-local.Dockerfile --build-arg BASE=<image> backend

docker compose -f deploy/e2e/compose.yml up -d --build --wait
curl -s http://127.0.0.1:18000/healthz
```

Test client: Python 3.11+ with `pip install pytest==9.1.1 httpx==0.28.1 cryptography==50.0.0`.

```sh
cd backend
export MORROW_E2E_BASE_URL=http://127.0.0.1:18000
export MORROW_E2E_ORG=e2e-demo-org      # optional: a fixed organization to look at in the console later
python -m pytest e2e_real -v
```

Every test is skipped when `MORROW_E2E_BASE_URL` is unset, so the normal unit suite is unaffected.
Each step below is one test file; the curl lines show the same calls by hand. `H` is the identity:

```sh
H='-H x-user-role:admin -H x-user-id:demo -H x-org-id:e2e-demo-org'
B=http://127.0.0.1:18000
```

## 0. Prove the domain (needed before any scan)

```sh
curl -s $H -X POST $B/domains -H content-type:application/json -d '{"domain":"e2e.morrow.test"}'
# -> record_name _morrow-verify.e2e.morrow.test, record_value morrow-verify=<token>
printf 'local=/e2e.morrow.test/\nlog-queries\ntxt-record=_morrow-verify.e2e.morrow.test,"morrow-verify=<token>"\n' > deploy/e2e/state/dnsmasq.conf
docker restart morrow-e2e-dns-1
curl -s $H -X POST $B/domains/e2e.morrow.test/verify     # -> "status":"verified","verified_now":true
```

Before this, every scan answers `403 domain_not_verified`, and IP addresses are always refused.

## 1. IKEv2 / IPsec scanner — `e2e_real/test_ike_strongswan.py`

```sh
curl -s $H -X POST $B/v1/scan/ike -H content-type:application/json \
  -d '{"targets":["vpn.e2e.morrow.test:500","vpn-classic.e2e.morrow.test:500"]}'
curl -s $H -X POST $B/v1/scan/ike -H content-type:application/json -d '{"targets":["vpn.e2e.morrow.test:4500"]}'
```

Expected (about a minute per gateway; probes are paced):

- `vpn.e2e.morrow.test`: selected proposal AES-256-GCM / PRF-SHA384 / Curve25519 with
  `additional_key_exchange_1` = `ML_KEM_768`; accepted KE `MODP_2048, CURVE25519`; ADDKE1 `ML_KEM_768`;
  `classical_only_accepted: true` (the classical proposal is still offered), `quantum_risk_level:
  medium`; IKEv1 not accepted.
- `vpn-classic.e2e.morrow.test`: no PQ key exchange, accepted KE `MODP_1024, MODP_2048`, risk `high`.
- Port 4500 (NAT-T): `pq_key_exchange: ["ML_KEM_768"]`.
- `172.30.77.20:500` or `vpn.example.org:500`: `403 domain_not_verified`, nothing sent.

Status: verified 2026-11-07 (3/3 tests)

## 2. Passive TLS discovery — `e2e_real/test_passive_ingest.py`

```sh
curl -s $H -X POST $B/v1/runtime/passive/tokens -H content-type:application/json -d '{"name":"fluent-bit","default_format":"nginx"}'
curl -s $H -X POST $B/v1/runtime/passive/tokens -H content-type:application/json -d '{"name":"vector","default_format":"envoy"}'
export MORROW_E2E_NGINX_INGEST_TOKEN=mpi_...   # the two "secret" values
export MORROW_E2E_ENVOY_INGEST_TOKEN=mpi_...
docker compose -f deploy/e2e/compose.yml --profile shippers up -d fluent-bit vector
curl -s $H "$B/v1/runtime/passive/endpoints?host=envoy.e2e.morrow.test"
curl -s $H "$B/v1/runtime/passive/endpoints?host=nginx.e2e.morrow.test"
curl -s $H "$B/assets/envoy.e2e.morrow.test:11443"
```

Expected within a minute:

- `envoy.e2e.morrow.test:11443`: TLSv1.3, `X25519MLKEM768`, `pq_safe_key_exchange`, format `envoy`.
- `envoy.e2e.morrow.test:10443`: `X25519`, `quantum_vulnerable`.
- `nginx.e2e.morrow.test:443`: TLSv1.3, `TLS_AES_256_GCM_SHA384`, `X25519` (or `X25519MLKEM768` once
  nginx is switched in step 3), format `nginx`.
- The inventory asset carries tag `passive-discovered` and `metadata.discovery_sources: ["passive"]`.
- No token or a wrong one: `401`.

Status: verified 2026-11-07 after fixing the Envoy setup (docs and deploy/e2e config); 4/4 tests

## 3. Crypto kill switch — `e2e_real/test_kill_switch.py`

```sh
echo 'ssl_ecdh_curve X25519:prime256v1;' > deploy/e2e/state/nginx-groups.conf && docker exec morrow-e2e-nginx-1 nginx -s reload
curl -s $H -X POST $B/scans -H content-type:application/json -d '{"targets":["nginx.e2e.morrow.test:443"]}'   # poll GET /scans/<id>
curl -s $H -X POST $B/crypto-switch/incidents -H content-type:application/json \
  -d '{"broken":"X25519","fallback":"X25519MLKEM768","dry_run":true}'
curl -s $H -X POST $B/crypto-switch/incidents/<id>/approve -H content-type:application/json -d '{}'
curl -s $H -X POST $B/crypto-switch/incidents/<id>/execute -H content-type:application/json -d '{}'   # dry run: the nginx change, nothing opened
curl -s $H -X POST $B/crypto-switch/incidents/<id>/go-live
curl -s $H -X POST $B/crypto-switch/incidents/<id>/approve -H content-type:application/json -d '{}'
curl -s $H -X POST $B/crypto-switch/incidents/<id>/execute -H content-type:application/json -d '{}'   # no repository: manual_apply
echo 'ssl_ecdh_curve X25519MLKEM768:X25519;' > deploy/e2e/state/nginx-groups.conf && docker exec morrow-e2e-nginx-1 nginx -s reload
curl -s $H -X POST $B/scans -H content-type:application/json -d '{"targets":["nginx.e2e.morrow.test:443"]}'
curl -s $H -X POST $B/crypto-switch/incidents/<id>/refresh
```

Expected: the first scan observes `x25519`; the plan lists `nginx.e2e.morrow.test:443` with server
type `nginx` and an `ssl_ecdh_curve` change naming X25519MLKEM768; a rescan before the change leaves
the asset `manual_apply`; after the change the scan observes `X25519MLKEM768` and refresh marks the
asset `switched` with the verifying scan id. `GET /audit/journal/verify` stays valid.

Without a GitHub token the incident cannot open pull requests; that path (and merge tracking) is
covered only by the unit tests.

Status: verified 2026-11-07 after fixing the scanner (it reported the hybrid nginx as classical)

## 4. Gradual post-quantum rollout — `e2e_real/test_pq_rollout.py`

Metrics source: `https://prometheus.e2e.morrow.test:9090` (HTTPS is required; the CA is trusted by
the backend through `SSL_CERT_FILE`). Gates:

- handshake failure rate: `sum(rate(envoy_listener_ssl_connection_error{envoy_listener_address="$variant"}[2m])) / sum(rate(envoy_listener_downstream_cx_total{envoy_listener_address="$variant"}[2m]))`
  with `pq_label` `0.0.0.0_11443`, `baseline_label` `0.0.0.0_10443`;
- HTTP error rate: explicit `pq` / `baseline` queries on `envoy_http_downstream_rq_xx{envoy_response_code_class="5"}`
  over `envoy_http_downstream_rq_total` for the `pq_hybrid` and `classic` connection managers.

Flow: create (platform `envoy`, `soak_minutes: 1`, dry run) → approve (baseline read) → advance
(stage 1%) → mark-applied → evaluate until the gate passes and the minute has soaked
(`awaiting_approval`) → advance (10%) → mark-applied → `echo fail > deploy/e2e/state/traffic_mode` →
evaluate.

Expected: healthy traffic gives both gates `pass` with 0 on both sides; with failing clients the next
evaluation returns `rolled_back`, reason "old clients failed the new handshake; HTTP errors rose
behind the post-quantum listener", the failing metric with both values, and a rollback config at
weight 0. `GET /pq-rollouts/summary` counts it. An unreachable Prometheus gives `inconclusive`
("could not be reached"), never a pass. Put the traffic back with `echo normal > deploy/e2e/state/traffic_mode`.

Status: verified 2026-11-07: gate pass on healthy traffic, 1-minute soak, forced failure rolled back (the HTTP error gate tripped first), unreachable Prometheus inconclusive

## 5. CBOM import and signed CI ingest — `e2e_real/test_cbom.py`

```sh
curl -s $H -X POST "$B/v1/cbom/import?source=cbomkit&filename=keycloak-cbom.json" \
  -H content-type:application/json --data-binary @backend/tests/fixtures/cbomkit/keycloak-cbom.json
curl -s $H "$B/v1/crypto-inventory?source=cbomkit"
curl -s $H -X POST $B/v1/cbom/ingest-tokens -H content-type:application/json -d '{"name":"ci"}'   # mci_...
curl -s $H -X POST $B/v1/cbom/webhook/signing-key                                                 # signing key
curl -s $H $B/v1/cbom/webhook/setup    # github_actions_step: run its script with CBOM_FILE, MORROW_CBOM_INGEST_TOKEN, MORROW_CBOM_SIGNING_KEY
```

Expected: the import is schema-valid and fills the inventory; importing it again adds nothing new
(all deduplicated). The generated CI step uploads with an HMAC signature and is accepted; the same
upload with a wrong key, or unsigned, is refused with 401.

CBOMkit itself was not re-run here: the vendored document is real CBOMkit output (Keycloak). The
test can also scan the stack's certificates with cbomkit-theia when `MORROW_E2E_THEIA_IMAGE` names
an image (`ghcr.io/cbomkit/cbomkit-theia`); not run on 2026-11-07 (the test skips without it).

Status: verified 2026-11-07 (import and dedup of real CBOMkit output)

## 6. Migration proof — `e2e_real/test_migration_proof.py`

Classical scan of nginx → remediation → approve → mark-merged → switch nginx to X25519MLKEM768 →
rescan (the verify loop closes the remediation) → `POST /remediations/<id>/migration-proof` →
offline verification:

```sh
curl -s $H -X POST $B/remediations/<id>/migration-proof > proof.json
curl -s $B/.well-known/morrow-proof-keys.json > keys.json
curl -s $H $B/audit/journal/export > journal.json
python scripts/verify_migration_proof.py proof.json --keys keys.json --journal journal.json   # exit 0
```

The remediation row is the one step not reached through a real service: Morrow creates remediations
from a connected GitHub repository, so the test writes it in the backend container with
`db.create_remediation`, as that path would. Everything after it is the API.

Expected: two signatures, `Ed25519` and `ML-DSA-65`; `before_scan` x25519, `after_scan`
X25519MLKEM768; the verifier exits 0, and 1 for a proof whose after-scan was edited.

What actually happens (2026-11-07): the after scan observes X25519MLKEM768, but the remediation
stays `merged`. The verify loop (`db.auto_close_merged_remediations`) closes a remediation only when
the rescan has no findings or risk low/none, and every classical certificate is a finding of at
least medium severity (EC) or high (RSA). The run's after scan was `critical` (RSA-2048 test
certificate, TLS 1.2 ciphers, 30-day validity, short chain), but even a perfect EC setup stays
`medium`, and public CAs do not issue ML-DSA certificates. So no real TLS endpoint can produce a
migration proof today. Closing a remediation when the finding it was opened for is gone (here: the
classical key exchange) is a product decision; the test is a strict xfail until it is made.
`backend/test_migration_proof.py` still covers signing and the offline verifier on recorded scans.

Status: blocked by a product gap: a real endpoint with a classical certificate never scans clean, so its remediation never closes and no proof can be issued (details in section 6); the offline verifier was not run on a real proof

## 7. What still needs a real account

- **Ticket sync (Jira / ServiceNow).** No legitimate local Jira or ServiceNow exists and none is
  documented. `backend/test_ticket_sync.py` checks the webhook contract (signatures, replay,
  tenancy, state changes) against recorded payloads; that is all that runs. A demo needs a Jira Cloud
  or ServiceNow developer instance with the webhook pointed at `/integrations/tickets/inbound/...`.
- **GitHub pull requests** (kill switch execute, rollout stages, remediation PRs): need a GitHub
  token or app installation. Not run.
- **Certificate-manager and KMS inventory**: every connector talks to a vendor SaaS or cloud API
  (see docs/CERTIFICATE_AND_KMS_INVENTORY.md); none was run.

## Stop and clean up

```sh
docker compose -f deploy/e2e/compose.yml --profile shippers down -v --remove-orphans
docker image rm morrow-e2e-backend:local morrow-e2e-dns:local morrow-test-strongswan:local
rm -rf deploy/e2e/state
```
