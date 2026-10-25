# Autonomous Security Mesh

This layer turns the platform from reactive governance into predictive crypto-security operations.
It is implemented as API endpoints plus customer-boundary deployment packages.
The source of truth for feature status is `GET /autonomous-mesh/capability-truth`.

## Modules

| Capability | Endpoint | What Works Now |
| --- | --- | --- |
| Capability truth matrix | `GET /autonomous-mesh/capability-truth` | Separates active features, artifact generators, blocked dependencies, and production go-live status |
| Passive eBPF crypto sniffer | `POST /autonomous-mesh/ebpf-package` | Generates bpftrace, collector, systemd, policy, and ZIP bundle |
| Entropy binary hunting | `POST /binary/entropy-hunt` and `POST /binary/scan` | Detects high-entropy regions and compiled crypto constants in stripped binaries |
| Multi-hop contagion graph | `POST /autonomous-mesh/contagion/multi-hop` | Propagates CA/KMS/service compromise through transitive trust edges |
| Dynamic Q-Day countdown | `POST /q-intel/dynamic-countdown` | Reprices Q-Day pressure from Q-Intel milestones and supplied research events |
| Multi-variant PR generation | `POST /autopilot/multi-variant-pr` | Produces developer-choice remediation options and PR body |
| Canary traffic shifting | `POST /autopilot/canary-traffic-shift` | Generates Cloudflare Worker, Argo Rollout, monitor, rollback policy, and ZIP bundle |
| HSM/TPM virtualization | `POST /hardware/hsm-virtualization` | Maps hardware crypto capacity to workload requirements |
| HSM/TPM collector package | `POST /hardware/hsm-collector-package` | Generates customer-boundary collector that exports capability metadata only |
| HSM/KMS quantum-drift enforcer | `POST /hardware/crypto-drift/enforce` | Blocks key intents when submitted KMS/HSM observations lack native post-quantum, hardware backing, or approved fallback |
| Hardware crypto bridge collector | `POST /hardware/crypto-bridge/collector-package` | Generates AWS/GCP/Azure/PKCS#11/YubiHSM/TPM metadata collector; no keys exported |
| Crypto-anomaly detection | `POST /crypto-anomaly/detect` | Scores packet/TLS metadata for HNDL harvesting, encrypted blob exfiltration, and post-quantum-size shifts |
| SIEM/XDR package | `POST /crypto-anomaly/siem-package` | Generates Splunk, Datadog, Microsoft Sentinel, and Sigma artifacts from findings |
| Continuous compliance proof | `POST /zk-compliance/continuous-proof` | Hash-commitment proof of aggregate post-quantum threshold without raw identifiers |
| Insurance export | `POST /insurance/underwriting-export` | Structured underwriting metrics with no raw asset identifiers |
| Insurance proof-of-agility | `POST /insurance/proof-of-agility` and `/verify` | Signed privacy-preserving proof bundle for underwriter verification |

## Boundary Rules

- eBPF requires customer-approved Linux permissions such as root or `CAP_BPF`.
- The eBPF collector submits metadata only; it must not collect packet payloads, private keys, or memory dumps.
- Canary traffic shifting generates rollout artifacts. It does not make live provider writes unless a future customer-approved integration supplies credentials and change approval.
- Continuous compliance proof is a hash-commitment attestation, not a formal ZK-SNARK circuit.
- HSM/TPM collection reports capability metadata only. It must never export key material.
- Multi-hop contagion requires supplied nodes and edges. The API does not use a sample graph for production risk claims.
- Canary traffic shifting requires explicit upstream URLs. Empty/example defaults are rejected.
- Hybrid certificate generation is blocked unless a real post-quantum library is installed. Placeholder post-quantum keys are not returned by the API.
- HSM/KMS drift enforcement evaluates submitted observations. It does not hard-code AWS/Azure/GCP/Thales/Utimaco/YubiHSM support claims.
- Crypto-anomaly detection consumes packet/TLS metadata only. It does not require packet payloads, plaintext, source code, or private keys.
- Underwriter proofs expose aggregate scores and hashes by default; raw asset IDs and vendor names are not included.

## UI

Open:

`/ui/` -> Overview -> Strategic capability layer -> Autonomous predictive security mesh -> `Open mesh`

Or use API Explorer -> `Autonomous Mesh`.

## Production Use

Use this sequence for an enterprise pilot:

1. Generate the eBPF and HSM collector packages.
2. Customer reviews the source and policy files.
3. Customer runs collectors inside their boundary.
4. Import passive runtime observations and hardware capability metadata.
5. Run multi-hop contagion and Q-Day countdown.
6. Generate multi-variant PR options.
7. Deploy canary rollout artifacts only after change approval.
8. Enforce HSM/KMS drift checks before key pushes.
9. Feed crypto-anomaly findings into SIEM/XDR.
10. Issue continuous compliance proof, insurance export, and proof-of-agility bundle.
