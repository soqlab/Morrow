# Migration proof

A migration proof is a signed document saying that one system was found quantum-vulnerable, was
fixed, and was re-verified with a clean scan. An auditor, insurer or customer can check it without a
Morrow account and without trusting the Morrow server that issued it.

## Issuing a proof

```
POST /remediations/{remediation_id}/migration-proof      (operator, admin, owner)
```

The request has no body. Everything in the proof comes from Morrow's own records for the caller's
organization:

| Section | Source |
| --- | --- |
| `subject` | the remediation's asset (`host:port`) and organization |
| `finding` | the remediation row: vulnerability, file, repository, PR, verification scan id |
| `before_scan` | the most recent successful scan of the asset, at or before the remediation was recorded, that did not pass |
| `after_scan` | the scan named by the remediation's `verification_scan_id` |
| `timeline` | remediation timestamps, scan times, and the journal entries for approval, PR, merge and closure |
| `journal` | the hash-chained audit-journal entries that record actions on this remediation and on the two scans, plus the chain head at issuance |
| `signing_keys` | the public keys that signed the document |

Scan evidence records what was observed: TLS version, negotiated key-exchange group, cipher,
certificate key type/size/curve and signature algorithm, risk level, finding count, scan time,
scanner version (when the stored scan recorded one; scans from before this release did not) and a
SHA-256 of the stored raw scan result.

A proof is refused (409) when:

- the remediation is not in `verified_closed` state;
- the verification scan's result is not on record, did not pass, or did not observe the endpoint
  (`scan_status` other than `ok`; a scan that could not connect has no findings, which is not a fix);
- no recorded scan shows the asset in its vulnerable state;
- the organization's audit journal fails verification.

A remediation of another organization answers 404. Without `MORROW_VAULT_MASTER_KEY` no signing key
can be sealed, and issuance answers 503.

## Signatures and keys

Each proof carries one signature per key in the deployment's active key set:

- **Ed25519** (always), via `cryptography`;
- **ML-DSA-65** (FIPS 204), via `cryptography` >= 47 on OpenSSL >= 3.5 (the PyPI wheels qualify;
  production pins `cryptography==50.0.0`). If the installed build lacks ML-DSA, proofs are signed with
  Ed25519 only and say so in `signing_keys`.

Both signatures are over `"morrow.migration-proof.v1\n"` followed by the canonical document: JSON with
sorted keys, no whitespace, UTF-8, and no floating-point numbers (numbers that are not integers are
encoded as strings). For these documents that is the RFC 8785 (JCS) serialization.

Key management:

- The key set is generated on first use, per deployment. Private keys are stored only as Fernet
  tokens sealed with the credential vault key (`MORROW_VAULT_MASTER_KEY`), in `proof_signing_keys`.
- Each key's `kid` is derived from its public key (`morrow-ed25519-<sha256 prefix>`).
- Public keys are published, without authentication, at `GET /.well-known/morrow-proof-keys.json`,
  with fingerprint, status and validity window.
- Rotate with `python scripts/rotate-proof-signing-key.py` (run on the server, from `backend/`).
  Retired keys are never deleted and stay published with `valid_until`, so older proofs still verify.
- Rotating `MORROW_VAULT_MASTER_KEY` must re-seal `proof_signing_keys.sealed_private_key` like every
  other vault secret; otherwise the server can no longer sign, though existing proofs still verify.

## Verifying offline

`scripts/verify_migration_proof.py` needs only Python 3.9+ and `pip install cryptography`.

```
python verify_migration_proof.py proof.json --keys morrow-proof-keys.json
python verify_migration_proof.py proof.json --pin <ed25519 fingerprint>
python verify_migration_proof.py proof.json --keys keys.json --journal journal-export.json
```

It checks:

1. every signature, against the key embedded in the document, and that the key appears in the trusted
   keys file (or matches a pinned fingerprint) and was valid when the proof was issued;
2. internal consistency: same asset before and after, vulnerable before and clean after, both scans
   observed the endpoint, before precedes after, the after scan is the verification scan, closure is
   not before the verification scan, the proof was issued after every event, journal entries are in
   chain order and adjacent entries link;
3. with `--journal`: every entry in the export re-hashes correctly and chains to the one before, and
   every journal entry the proof cites is present and unchanged.

Exit status: `0` verified, `1` a check failed, `2` unreadable input, `3` intact but the signer is not
trusted (no `--keys`/`--pin` given). Obtain the keys file or fingerprints through a channel you
trust; a keys file fetched from the same place as the proof proves only that the two match.

## Audit journal

```
GET /audit/journal/verify    (admin, owner)   re-derives every hash of the organization's chain
GET /audit/journal/export    (admin, owner)   the chain with exactly the fields the hash covers
```

Each entry's hash is SHA-256 over `prev_hash|actor_id|actor_role|action|resource_type|resource_id|
decision|reason|details_json|created_at`. The verify route reports the first entries where the stored
chain disagrees. The export contains actor ids; share it with the relying party only as your policy
allows. The verify loop now writes a `remediation.verified_closed` entry when a passing scan closes a
merged remediation.

## Limits

- The journal is a hash chain kept by the same server. It detects edits and deletions of individual
  entries, not wholesale replacement of the chain by someone with database access; anchor the chain
  head externally (WORM storage, a timestamping service) for that.
- `issued_at` is chosen by the signer. A leaked retired key could sign a back-dated proof; keep the
  vault key out of reach and rotate if it is exposed.
- Journal entries for approval and PR creation are authorization records written when the action was
  permitted, before its effect.
- Scans stored before this release have no `scanner_version`; legacy scan rows without `scan_status`
  cannot back a proof.

## Legacy HS256 artifacts

`POST /remediation/proof-package`, `GET /trust-passport`, `POST /trust-passport/share` and
`GET /trust-passport/public/{token}` still work unchanged, but their `signature` is an HMAC-SHA256
(`alg: HS256`) under `MORROW_AIRLOCK_SIGNING_KEY`. Only the server can check it, and anyone able to
check it could forge it, and the proof package signs a template built from request fields. Treat them
as legacy: they are not evidence for a third party. Use migration proofs for that.
