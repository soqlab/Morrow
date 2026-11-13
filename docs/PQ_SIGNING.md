# Post-quantum signing

Morrow lets you sign your releases and your website's files with post-quantum signatures, and gives
your visitors a page where they can check a file they downloaded. You keep your private keys. Morrow
only ever sees public keys, signatures and file fingerprints (SHA-512 hashes): never a private key
and never one of your files.

- **You sign** on your own machines, or in your release pipeline, with the `morrow-sign` command.
- **Morrow publishes** your public keys and the signatures you choose to upload, at
  `https://morrow.soqlab.com/verify/<your-domain>`.
- **Visitors check** a file by dropping it on that page. The page works out the file's fingerprint
  and checks the signature inside their browser. The file is not uploaded.

## What a signature is made of

Every signature is two signatures over the same short statement (your domain, the key, the file's
name, size and SHA-512 fingerprint, and the time of signing):

- **ML-DSA-65**, the post-quantum signature standardised by NIST in FIPS 204 (security category 3);
- **Ed25519**, the widely used classical signature (RFC 8032).

A signature counts as valid only when **both** verify.

### Why two algorithms

ML-DSA is designed to resist quantum computers, but it is new: it was standardised in 2024 and has
far less real-world history than Ed25519. Ed25519 has a long track record but will be broken by a
large enough quantum computer. Requiring both means a forger has to break both: a future quantum
computer is not enough (ML-DSA still holds), and an unexpected flaw in ML-DSA is not enough either
(Ed25519 still holds, at least until such a computer exists). This "hybrid" approach is what
several national security agencies, among them France's ANSSI and Germany's BSI, recommend during the
move to post-quantum cryptography. The cost
is size: a signature file is about 7 KB instead of a few hundred bytes.

The fingerprint is SHA-512, whose strength matches ML-DSA-65's security level better than SHA-256.

## Setting up

### 1. Verify your domain

In the Morrow console, under **Domains**, add your domain and publish the DNS record it shows you
(`_morrow-verify.<domain>  TXT  "morrow-verify=..."`). Morrow accepts signing keys only for a domain
your organization has verified this way. Keep the record published: Morrow checks it again, live,
every time a key is registered. If two organizations have verified the same domain, only the one
that verified it first can register signing keys for it.

### 2. Install morrow-sign

```
pip install morrow-sign
```

Until the package is on PyPI, install it from the repository:

```
pip install "git+https://github.com/soqlab/Morrow#subdirectory=tools/morrow_sign"
```

It needs Python 3.9 or later and the `cryptography` package, version 50 or later, which provides
ML-DSA. No other dependency.

### 3. Make a key pair

```
morrow-sign keygen --domain example.com
```

This writes two files:

- `example.com-mk-....morrow-key`: your **private key**. Keep it secret. Never upload it, never
  commit it, never email it. You are asked for a passphrase; with one, the file is encrypted
  (scrypt and AES-256-GCM). For unattended signing in CI, set `MORROW_SIGN_PASSPHRASE`.
- `example.com-mk-....morrow-pub.json`: your **public key**, with a proof that whoever made it holds
  the private key. This is the file you give to Morrow.

The key id (`mk-` followed by 32 characters) is computed from the public keys, so it cannot be
chosen or reused by someone else.

### 4. Register the public key

In the console, open **Signing** (or press Ctrl+K and type "Signing"), choose **Register a key** and
pick the `.morrow-pub.json` file. Or, with an admin API key for your organization:

```
MORROW_SIGN_TOKEN=pq_... morrow-sign register example.com-mk-....morrow-pub.json --label "Release key 2026"
```

Morrow checks the proof in the file, that your organization verified the domain, and that the DNS
record is still there. Registration is recorded in your organization's audit log.

### 5. Create an upload key (optional)

If you want signatures on the public record (recommended, see "Revocation" below), create an upload
key in **Signing > Upload keys**. It is an API key that can do exactly one thing: put a signature on
the record. It cannot read your workspace or start scans. It is shown once; store it in your CI
secrets as `MORROW_SIGN_UPLOAD_KEY`. It expires after a year.

## Signing

### A release file

```
morrow-sign sign dist/app-1.2.0.tar.gz --key example.com-mk-....morrow-key --upload
```

This writes `dist/app-1.2.0.tar.gz.morrow-sig` next to the file. Publish it next to your download.
With `--upload`, the signature (not the file) is also put on Morrow's public record. Morrow checks
the signature against your registered key before it keeps it. Several files can be signed at once.

### A website

```
morrow-sign sign-site ./public --key example.com-mk-....morrow-key --upload
```

This lists every file under `./public` with its size and SHA-512 in `./public/morrow-manifest.txt`,
and signs that list. Files and folders whose name starts with a dot (`.git`, `.env`), symbolic
links, and `.morrow-key` and `.morrow-sig` files are left out. With `--upload`, the signature and the
list (paths, sizes and fingerprints, never the files) go on the public record, so a visitor can check
any single page or asset of the site.

### Limits

An organization can put up to 2000 signatures on the record per 24 hours (the operator can change
this with `MORROW_PQ_SIGNING_DAILY_LIMIT`). A site manifest lists at most 10,000 files. A domain can
have at most 10 active keys.

## How visitors check a file

### In the browser

The verify page is `https://morrow.soqlab.com/verify/<your-domain>`. It lists your keys with their
history and your latest signatures. A visitor drops the downloaded file on the page (with its
`.morrow-sig` file if they have it). The page:

1. computes the file's SHA-512 in the browser;
2. finds the matching signature: in the dropped `.morrow-sig` file, among the signatures the page
   loaded, or, if neither, by asking Morrow for signatures with that SHA-512 (only the fingerprint is
   sent, never the file);
3. checks the ML-DSA-65 and Ed25519 signatures in the browser, with the open-source
   `@noble/post-quantum` library served by Morrow itself;
4. applies the key's status (active, retired, revoked) and whether the signature was withdrawn.

For a file from a signed site, the page fetches the manifest's file list, rebuilds the manifest,
checks its fingerprint and signature, and then checks that the file is in it.

### Put a badge next to your downloads

```
<a href="https://morrow.soqlab.com/verify/example.com"><img src="https://morrow.soqlab.com/verify/example.com/badge.svg" alt="Post-quantum signed. Verify on Morrow" height="20"></a>
```

The console's Signing view has this snippet with a copy button. `morrow-sign badge --domain
example.com --file app.tar.gz` prints a version that links to one file's signature.

### On the command line

```
morrow-sign verify app-1.2.0.tar.gz                       # uses app-1.2.0.tar.gz.morrow-sig
morrow-sign verify app-1.2.0.tar.gz --domain example.com   # no .morrow-sig: looks the file up on the record
morrow-sign verify app-1.2.0.tar.gz --public-key example.com-mk-....morrow-pub.json   # offline
```

It exits 0 when the file is valid and 1 when it is not, and prints every check. The checks run on
the visitor's machine; Morrow only supplies the public keys and the record. Offline checking
against a public key file cannot see revocations.

### As JSON

- `GET /api/verify/<domain>`: keys with their history, and the latest signatures.
- `GET /api/verify/<domain>/lookup?sha512=<hex>`: signatures for a file with that fingerprint,
  including site manifests that list it.
- `GET /api/verify/<domain>/signatures/<id>`: one signature, with a manifest's file list.
- `POST /api/verify` with `{"signature": <the .morrow-sig contents>, "sha512": "<hex>", "size": <bytes>}`:
  Morrow's verdict and each check. This one is checked on Morrow's server.

## Rotating a key

Make a new key with `morrow-sign keygen`, then in the console choose **Rotate** on the old key and
pick the new public key file (or `morrow-sign register NEW.morrow-pub.json --rotates mk-OLD`). The new
key becomes active and the old one is **retired** in the same step.

A retired key signs nothing new: Morrow refuses uploads signed with it, and a signature dated after
the retirement does not verify. Signatures dated before the retirement stay valid, so files you
already published keep checking out. Destroy the old private key afterwards. If it may have been
copied, revoke it instead.

## Revoking a key

Revoke a key when its private key may be in someone else's hands (a lost laptop, a leaked CI
secret). You say from when the key can no longer be trusted: by default since it was registered, or
from a time you choose. Visitors see the revocation, the date and your reason.

What happens to signatures:

- **On Morrow's record before that time:** still valid. Morrow wrote down when it received them, and
  that time cannot be faked by whoever has the key.
- **Everything else:** no longer valid. That includes signature files that were never uploaded, even
  if they say they were signed earlier: the signing time inside a signature is written by whoever
  holds the key, so after a compromise it proves nothing.

This is why uploading signatures is worth it: it is what lets old releases survive a key compromise.

A revoked key cannot be registered again. Revocation cannot be undone.

## Withdrawing one signature

If you signed the wrong file, choose **Withdraw** on that signature in the console and give a
reason. It stops verifying everywhere, and the record shows it as withdrawn with your reason.

## What Morrow keeps, and for how long

Public keys, each key's history (registered, retired, revoked), signatures, file names, sizes and
SHA-512 fingerprints, manifest file lists, and withdrawals. Nothing is edited or deleted
afterwards: a change is always a new entry. Key registrations, rotations, retirements, revocations,
withdrawals and upload keys are also written to your organization's audit log. All of it is public
on the verify page, except who in your organization made each change, which appears only in your
console and audit log.

## For operators

- Tables: `pq_signing_keys`, `pq_signing_key_events`, `pq_signatures`, `pq_signature_entries`,
  `pq_signature_revocations`, all carrying the tenant in `org_id` and covered by the Postgres
  row-level-security plan (`services/postgres_rls.py`). Public reads run in a named platform scope.
- Server-side ML-DSA-65 comes from `cryptography` (pyca), already pinned in the lock files; it is
  tested against NIST ACVP vectors (`backend/fixtures/acvp/ml_dsa_65_fips204.json`).
- The browser verifier `backend/static/vendor/morrow-pq-verify.js` is built from
  `tools/pq-verify-js` (`npm ci && npm run build`) and committed; the server needs no Node.
- `MORROW_PQ_SIGNING_DAILY_LIMIT` (default 2000): signatures one organization can record per 24 hours.
- Rate limits per client address: uploads 120/minute, key changes 20/minute, public JSON 60/minute,
  `POST /api/verify` 30/minute, verify pages 120/minute, badge 240/minute.
