# Customer Data Control

AI is OFF unless your organization administrator approves a versioned policy.
Ordinary non-AI scanning remains available. The assistant has one read-only tool:
a bounded (up to 5,000 findings) organization cryptographic summary, not live
network visibility. AI cannot scan arbitrary targets, read repositories or change code.
Explicit console workflows retain their own authorization checks.

## Choose your boundary

- **Off:** this application's model gateway refuses AI dispatch. This does not
  disable other platform integrations or prevent data submitted to the platform.
- **Customer-hosted:** deploy the platform and an OpenAI-compatible model endpoint
  in YOUR environment. Set `PQC_AI_DEPLOYMENT_LOCATION=customer`,
  `PQC_AI_LOCAL_URL` (full chat-completions URL), `PQC_AI_LOCAL_MODEL`, and optionally
  `PQC_AI_LOCAL_API_KEY` in your secret manager. HTTPS is required except loopback.
  The location is operator-declared, not remotely attested. No model is bundled.
- **Approved external:** approve a configured provider, exact endpoint and model,
  workflows and data permissions. Endpoint/model changes require reapproval.
  The gateway never silently falls back to another provider.

Keep free text OFF to send only allowlisted numeric facts and algorithm/TLS enums.
Unknown fields AND arbitrary string values are dropped, including hostnames,
source code and record content. Collection is limited; this is not a general
purpose parser or proof against covert information encoded in permitted facts.
Enabling free text permits code, personal data and identifiers; credential-pattern
checks are incomplete DLP. Do not enable it for sensitive material. Code-generating
AI remediation requires this broader approval; it is unavailable otherwise.

## Offline preview before anything leaves your environment

Download the customer kit in Console > Data Control, or use the scripts in
`backend/customer_data_control/`. Python 3.10+ is required. The filter uses only
the standard library and reads ONE file you explicitly select. It does not
inspect your filesystem, applications or production traffic.

1. An organization admin reviews and approves the `metadata_analysis` workflow
   in Data Control. Note its policy version.
2. Export a small JSON object locally, such as `{"assets":[{"algorithm":"RSA",
   "key_bits":2048,"hostname":"internal.example"}]}`. The hostname is discarded.
3. Preview entirely offline:

   `python customer_data_gate.py preview --input metadata.json --endpoint https://your-platform.example --policy-version 1`

4. Review the displayed destination and exact minimized payload. Set
   `PQC_CUSTOMER_GATE_TOKEN` locally to your tenant-scoped bearer token. Never put
   tokens in the JSON file, command line, screenshots or support tickets.
5. Send only after approving the printed digest:

   `python customer_data_gate.py send --input metadata.json --endpoint https://your-platform.example --policy-version 1 --approved-sha256 DIGEST_FROM_PREVIEW`

Any input, destination or policy-version change invalidates this approval. TLS
certificate verification remains enabled. Redirects and inherited proxy settings
are disabled. For development only, `--allow-loopback-http` allows loopback HTTP.
The server re-applies the allowlist, checks current policy/version, then dispatches.
The web preview already sends its input to the platform; use the offline kit to
prevent raw data reaching a hosted platform. Other scan/upload APIs are NOT
automatically routed through this kit. Apply it deliberately at your boundary.

## Stop, access and evidence

Stop AI blocks new and queued calls and later agent rounds. A call already claimed
for dispatch or transmitted cannot be recalled. Support access defaults to denied
for organizations without an explicit stored setting. An admin can approve or
revoke support sessions and inspect their read-only request history. Existing
explicitly enabled settings remain unchanged; this is not a control over direct
infrastructure/database administrator access.

The gateway signs policy changes, dispatch authorization, response outcomes and
gateway-blocked requests. Inputs and model outputs are NOT stored in these
receipts. A keyed payload digest avoids an ordinary dictionary-checkable hash.
Pre-gateway auth rejection and deterministic AI-off responses do not generate
model-dispatch receipts; existing access/audit journals are separate. Signing or
storage failure before dispatch prevents the model call. A post-dispatch audit
failure withholds the result but cannot reverse delivery.

Export receipts and pin the public key using a separate trusted channel.
Install `cryptography` in the independent verifier's environment, then run:

`python verify_ai_receipts.py ai-processing-receipts.json --trusted-public-key-file pinned-key.txt`

Export pages contain at most 1,000 records, newest first. Use `next_before` to
request older pages. Save the key and verified head externally. A retained export
may start after a pruned prefix: verification covers only the supplied segment.
Ed25519 provides conventional authenticity; it is NOT a PQC signature, zero-knowledge
proof, third-party attestation or proof that no other traffic left the system.
The platform holds the signing keys; independent anchoring is necessary to detect
a compromised platform replacing its entire account of events.

Receipt retention is 1-365 days. Reads exclude expired records immediately;
the running server removes bounded batches every minute. Stopped servers and
backups require separate retention operations. This setting does not delete
provider logs, scan records or other platform audit journals.

## Deployment checklist (operator action required)

- Set and protect `PQC_VAULT_MASTER_KEY`; back it up separately from the database.
  Existing vault rotation tooling also rotates encrypted receipt signing keys.
- In PostgreSQL, run the existing schema/RLS migration before switching to the
  restricted runtime role. All three `ai_privacy_*` tables are tenant scoped.
- Enforce outbound network restrictions at the deployment boundary. Application
  checks cannot stop a compromised process or unrelated software from sending
  data. Isolate the AI workload behind a deny-by-default egress firewall/proxy
  with an explicit destination allowlist. The application does NOT install a
  firewall, and its HTTP clients do not use inherited proxy variables. If a
  controlled transport is needed, provision an approved customer-hosted endpoint.
- For external providers, verify your actual account's region, subprocessors,
  retention, training use and contract settings. The UI reports these as unverified.
  `store:false` is not a guarantee of zero retention.
- Exercise revoked policy, unavailable database/signing key/model, blocked content,
  concurrent requests, support revocation and recovery in your own environment.
- Review the separate platform privacy policy/DPA, backups and infrastructure
  operator access. This feature is not a certification or blanket launch approval.

Design references: [OWASP prompt injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
[OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).
