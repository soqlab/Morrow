#!/usr/bin/env python3
"""Rotate the migration-proof signing key set of a Morrow deployment.

Run on the server, with the deployment's environment (database settings and
MORROW_VAULT_MASTER_KEY), from the backend directory:

    python ../scripts/rotate-proof-signing-key.py            # rotate
    python ../scripts/rotate-proof-signing-key.py --list     # show published keys

The active Ed25519 (and ML-DSA-65) keys are retired, not deleted: they stay published at
/.well-known/morrow-proof-keys.json with the time they stopped signing, so every proof issued
before the rotation still verifies. New proofs are signed with the new key set. Tell relying
parties the new fingerprints through the same channel you gave them the old ones.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print the published keys and exit")
    args = ap.parse_args()
    from services import proof_signing

    if not args.list:
        try:
            result = proof_signing.rotate()
        except proof_signing.SigningUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"rotated": result}, indent=2))
    print(json.dumps(proof_signing.published_keys(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
