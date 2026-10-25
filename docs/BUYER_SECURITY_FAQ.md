# Buyer Security FAQ

This document answers expected security questions for early enterprise pilots. Keep answers factual and do not overstate certification status.

## Is the platform production certified?

Not yet. The platform is suitable for controlled enterprise pilots after customer-specific deployment, auth, GitHub App, and cloud controls are configured. SOC 2 / ISO 27001 should be treated as a roadmap or procurement milestone unless completed separately.

## How is tenant isolation handled?

Application queries are organization-scoped. A Postgres Row-Level Security hardening plan exists for staging/production verification. For production enterprise use, RLS should be enabled and tested before broad rollout.

## How does authentication work?

The platform supports hosted identity/JWT-based access patterns and local development headers. Enterprise pilots should use real Auth0 or equivalent hosted identity, with role and organization claims mapped into platform authorization.

## How is authorization handled?

The product separates viewer, operator, and admin capabilities. Write actions are blocked for read-only roles, and deny events are expected to appear in audit evidence.

## How are GitHub credentials handled?

Normal operation should use GitHub App installation credentials. Pilot or production credentials must be stored through the configured vault/secret path and must not be hard-coded or exposed in API responses.

## Does the platform make code changes automatically?

The intended governed workflow is suggestion, approval, validation, and PR creation. Production customers should keep human review in the loop unless they explicitly approve more automation later.

## What evidence is captured?

Evidence includes scan state, asset linkage, compliance gate result, remediation status, validation result, PR/merge state, verify-close state, drift checks, notifications/webhooks, and audit events.

## What data does the platform need?

Pilot data usually includes asset metadata, scan/import results, repository metadata, remediation workflow state, validation output, and audit events. Exact data boundaries should be documented for each customer pilot.

## Does Quantum Airlock require deep access?

No by default. The Airlock path is designed for minimum-access enterprise pilots. The customer runs
a read-only collector or CI step inside their boundary, reviews the package, and sends signed
evidence to the platform. The default evidence model excludes source code, private keys, secrets,
raw packet payloads, customer production records, broad filesystem images, and unrestricted shell
access. See `docs/DATA_BOUNDARY_AND_PRIVACY.md` for the exact data classes.

## How is Airlock evidence trusted?

Enterprise pilots should set `MORROW_AIRLOCK_SIGNING_KEY`,
`MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE=1`, and `MORROW_AIRLOCK_MAX_CLOCK_SKEW_SECONDS`. Signed evidence
uses timestamp and nonce checks so the platform can reject stale or unsigned submissions. Unsigned
evidence is acceptable only for local development or clearly marked demos.

## Can the platform operate without customer source-code upload?

Yes for the Airlock-first workflow. External scan evidence, runtime handshake proofs,
privacy-preserving CBOM fingerprints, firmware provenance hashes, CI/CD buzzer results, and Trust
Passport outputs can be generated without uploading source code. Source or repository integration
is optional and should be scoped explicitly when remediation PR workflows are part of the pilot.

## Can CAM protect traffic without app rewrites?

Yes after customer-controlled network deployment. The generated CAM/API package can run as an
ingress reverse proxy, transparent Linux sidecar, or egress gateway. It wraps selected traffic in a
hybrid/post-quantum-capable TLS tunnel and sends only handshake proof metadata to the platform. The customer
still controls sidecar injection, destination CIDRs, DNS/load-balancer routing, certificates, and
rollback. Certificate pinning and app-layer crypto still require separate remediation.

## What remains manual before first paid pilot?

- Configure hosted auth.
- Install the GitHub App.
- Store production secrets.
- Deploy stable cloud infrastructure.
- Verify Postgres persistence and backup/restore.
- Run one real end-to-end remediation and drift scenario.
- Review customer security/legal requirements.

## What should not be promised yet?

- SOC 2 compliance unless formally completed.
- Full autonomous remediation in production.
- Guaranteed regulatory compliance.
- Zero-touch enterprise deployment.
- Complete coverage of all crypto assets without customer-specific discovery setup.
