# Quantum Airlock Enterprise Deployment

Quantum Airlock is the customer-boundary layer for Morrow. It is designed to prove crypto posture without requiring deep access to customer systems.

## Boundary Contract

By default, the agent does not upload:

- source code or repository contents;
- private keys, secrets, tokens, passwords, or environment dumps;
- traffic payloads, packets, PCAPs, request bodies, or response bodies;
- raw firmware binaries.

It uploads:

- TLS handshake metadata and certificate hashes;
- salted CBOM fingerprints and counts;
- firmware hashes and finding summaries;
- signed runtime proof events;
- compliance ledger roots and verifiable credentials.

## Production Requirements

Set these before using Airlock with a customer:

```env
MORROW_AUTH_MODE=jwt
MORROW_AUTH_REQUIRED=1
MORROW_DEFAULT_ROLE=viewer
MORROW_AIRLOCK_SIGNING_KEY=<64 hex chars or stronger>
MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE=1
MORROW_AIRLOCK_MAX_CLOCK_SKEW_SECONDS=600
SENTRY_DSN=<production monitoring DSN>
```

Run:

```powershell
.\scripts\prod-preflight.ps1 -EnvFile .env.prod -Strict
```

## Customer Install

Production JWT flow:

```bash
curl -fsSL -H "Authorization: Bearer $MORROW_TOKEN" \
  "https://YOUR_API/airlock/install.sh?customer_id=acme" | bash
```

PowerShell:

```powershell
iwr -Headers @{Authorization="Bearer $env:MORROW_TOKEN"} `
  "https://YOUR_API/airlock/install.ps1?customer_id=acme" | iex
```

Local dev header flow only:

```bash
curl -fsSL \
  -H "x-user-role: operator" \
  -H "x-user-id: airlock-admin" \
  -H "x-org-id: 00000000-0000-0000-0000-000000000001" \
  "http://127.0.0.1:8001/airlock/install.sh?customer_id=acme" | bash
```

## Verification

After install:

```bash
python .morrow-airlock/morrow_airlock_agent.py --config .morrow-airlock/config.json run-once
python .morrow-airlock/morrow_airlock_agent.py --config .morrow-airlock/config.json flush
```

Then verify:

- `GET /airlock/onboarding-status`
- `GET /airlock/flight-recorder`
- `GET /trust-passport`

## Enterprise Rollout Sequence

1. Run production preflight.
2. Create customer organization and JWT role mapping.
3. Generate/install Airlock agent.
4. Verify first signed flight-recorder event.
5. Run change simulator.
6. Generate signed remediation PR bundle.
7. Generate the CAM/API transparent proxy package and validate it in observe/shadow mode.
8. Enable middleware/kill-switch only after customer approval.
9. Issue Trust Passport.

## Security Notes

- Keep `config.json` in a protected host path or secret manager.
- Rotate `MORROW_AIRLOCK_SIGNING_KEY` if agent config or server env is exposed.
- Do not enable write actions until customer change-control is approved.
- Do not claim payload inspection; Airlock is deliberately payload-blind.
- CAM/API transparent proxy deployment is covered in `docs/CAM_TRANSPARENT_PROXY_DEPLOYMENT.md`.
