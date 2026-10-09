# Customer Data Control

Open **Console > Act > Data Control** (`/ui/#data-control`).
Public explanation: `/ui/ai-trust.html`, linked from the landing page, security
FAQ and data-boundary page.

The full deployment and customer-side instructions are bundled with the downloadable
kit and maintained in [the kit README](../backend/customer_data_control/README.md).
That copy is included in the backend container, not fetched from a documentation server.

## Implemented controls

1. Per-organization AI off / customer-hosted / approved external policy. Default
   off, explicit workflow permission, pinned endpoint/model, versioned approval,
   optimistic concurrency, no automatic provider fallback.
2. Mandatory gateway for the existing Anthropic/OpenAI agent and legacy intent and
   remediation model calls. Metadata allowlist by default; explicit permission for
   free text; recognized credential patterns blocked. Free text is NOT complete DLP.
3. Exact metadata-analysis payload preview and a separate offline customer filter. The latter reads
   one selected JSON file; approved digest binds minimized payload, destination and
   policy version. No filesystem discovery, application instrumentation or raw
   traffic collection. Web preview is server-side, not an offline privacy boundary.
4. Customer-visible policy/dispatch/outcome timeline and signed receipt export.
   Tenant Ed25519 keys encrypted by the existing vault key. No prompt/response bodies
   in these receipts. Independent verifier requires a pinned public key. Signatures
   do not establish complete network coverage, provider deletion or training behavior.
5. Stop action invalidates queued requests and later agent rounds. Already-dispatching
   calls cannot be recalled. It remains available through maintenance
   mode (normal authentication/rate limiting still applies).
6. Vendor support sessions require customer opt-in, default denied when no setting
   exists. Customer revocation is checked on subsequent support requests. The old
   owner break-glass override of customer denial is removed from API and operator UI.
   Direct infrastructure/database access is outside this permission mechanism.

The read-only analyst exposes only the bounded organization-summary tool. Existing
explicit console operations retain their authorization. AI never silently runs a
scan, fetches customer source, changes infrastructure or merges a PR through its
conversational tool dispatcher. Policy changes during a conversation stop its next
model round rather than reusing older content under a new approval.

## Migration / operations

- Existing organizations without a Data Control policy now have AI off even if
  provider credentials are present. Deterministic guidance and non-AI workflows
  remain available. An organization admin must review and enable desired workflows.
- Existing explicitly stored support settings are preserved. No-setting organizations
  default to denied. Tell support teams that customer approval is now required and
  cannot be overridden through the support-session API.
- Run the normal deferred schema/RLS migration for PostgreSQL before restricted-role
  runtime startup. New tenant tables: `ai_privacy_policy`, `ai_privacy_events`,
  `ai_privacy_jobs`. SQLite initializes them on first use.
- Preserve `PQC_VAULT_MASTER_KEY`; existing `scripts/rotate-vault-master-key.py`
  now includes receipt signing keys. Never replace the master key without rotation.
- Background maintenance processes registered organizations in pages and removes
  bounded expired-receipt batches. Backups, provider retention and other journals
  have independent retention requirements.
- The UI is snapshot-driven, refreshed on navigation or explicit refresh. No fake
  traffic counters or continuously polling trust badge. A previous dispatch is only
  a previous observation, not evidence of current comprehensive enforcement.

## Verify before deployment

Run the automated checks from the repository root:

```powershell
$tests = @(
  "backend/test_ai_data_control.py", "backend/test_ai_agent_contract.py",
  "backend/test_agent_chat_fallback.py", "backend/test_support_sessions.py",
  "backend/test_vault_key_rotation.py", "backend/test_postgres_rls_plan.py",
  "backend/test_assistant_chat.py", "backend/test_airlock_enterprise.py",
)
backend/.venv/Scripts/python.exe -m pytest @tests -q
node scripts/test-data-control-ui.cjs
```

The browser harness starts an isolated backend on a temporary loopback port/database,
uses real HTTP routes, disables model I/O, and tests desktop/mobile, approval, preview,
kit download, stop, viewer restrictions and the public trust page. It uses the installed
Playwright package (or `.tools/video/node_modules/playwright`) and Edge on Windows;
set `PQC_TEST_BROWSER_CHANNEL` for another installed browser channel.

The optional PostgreSQL runtime test requires `PQC_TEST_PG_DSN` pointing to a
DISPOSABLE server with permission to create temporary databases/roles. It is skipped
without that setting. SQLite success is not proof that PostgreSQL RLS is deployed.

## Local verification record (2026-09-26)

Follow-up: the disposable PostgreSQL suite subsequently passed **88 tests with
zero skips**, including AI policy/receipt RLS. Deployment changes and remaining
launch blockers are tracked in the production-release record, which is maintained privately.

- The regression command above passed: **194 passed, 1 skipped**. The skipped test
  requires a disposable PostgreSQL server. Provider responses were stubbed or served
  by a loopback test server; no real external model account was validated.
- The browser harness passed desktop/mobile layout, policy review/approval,
  metadata preview, kit download, stop, viewer restrictions and the public page.
  Preview/dispatch parity is also covered for OpenAI and Anthropic, with free-text
  permission both on and off; metadata analysis still strips unknown fields.
- Backend Python lint, JavaScript syntax and diff whitespace checks passed.
  The rotation script retains 36 pre-existing lint findings, unchanged by this work;
  its functional key-rotation regression tests passed.
- Restarted local service on `http://127.0.0.1:8001`; health, console, public page,
  JavaScript and Data Control status returned HTTP 200. The local organization's
  policy remained off at version 0; verification did not enable a provider.
- This local instance still uses `PQC_AUTH_MODE=headers` with authentication required.
  Header-based identity is for development, not public deployment. Configure and
  validate production JWT/SSO before exposing customer or admin APIs.

Still validate in staging: real account/model access and request contracts, customer
model hosting, outbound firewall restrictions, provider-region/retention/training
settings and contractual terms, PostgreSQL migration/RLS, backup retention and key
recovery. This feature is not a full-platform security audit or a production launch
certification. It does not promise zero data leakage from other software.
