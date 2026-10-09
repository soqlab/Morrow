# Customer Edge Infra Demo

Controlled demo repository for Crypto Control Plane.

This repo is intentionally small and demo-safe. It shows the kind of
infrastructure-as-code files the platform would inspect, remediate, validate,
and turn into a pull request in a real customer environment.

Demo asset:

- `www.cloudflare.com:443`

Intentional weak posture examples:

- TLS policy starts at `1.2`
- weak cipher assumptions are enabled
- crypto-agility owner is missing
- SSH is open to the internet in the general security example

