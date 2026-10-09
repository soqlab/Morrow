"""Verify exported receipts against an independently pinned Ed25519 public key."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def verify(bundle, trusted_public_key):
    receipts = bundle["receipts"]
    if not receipts:
        raise ValueError("No receipts to verify")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_key, validate=True))
    # Exports arrive newest first. Keep export order: sorting equal timestamps can break the chain.
    ordered = list(reversed(receipts))
    head = None
    org = ordered[0]["data"]["organization_id"]
    for receipt in ordered:
        if receipt["algorithm"] != "Ed25519" or receipt["public_key"] != trusted_public_key or receipt["data"]["organization_id"] != org:
            raise ValueError("Unexpected key, algorithm or organization")
        key.verify(base64.b64decode(receipt["signature"], validate=True), canonical(receipt["data"]).encode())
        if head is not None and receipt["data"]["previous_hash"] != head:
            raise ValueError("Receipt chain has a gap or was reordered")
        head = hashlib.sha256(canonical(receipt).encode()).hexdigest()
    return {"verified_receipts": len(receipts), "organization_id": org, "head_hash": head,
            "scope": "Signatures and chain within this export only. Pin/save the head externally to detect later rewrites. No proof of deletion or complete traffic coverage."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export")
    parser.add_argument("--trusted-public-key-file", required=True)
    args = parser.parse_args()
    try:
        data = Path(args.export).read_bytes()
        if len(data) > 5000000:
            raise ValueError("Export exceeds 5 MB")
        print(json.dumps(verify(json.loads(data), Path(args.trusted_public_key_file).read_text().strip()), indent=2))
    except Exception as exc:
        print("Verification failed: " + type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
