# morrow-sign

Post-quantum signatures for your releases and your website, checked by anyone at
[Morrow](https://morrow.soqlab.com/verify).

Each signature is ML-DSA-65 (NIST FIPS 204) and Ed25519 together, and is valid only when both
verify. Your private key never leaves your machine: Morrow receives public keys, signatures and
SHA-512 fingerprints, never a private key and never a signed file.

```
pip install morrow-sign

morrow-sign keygen --domain example.com
morrow-sign register example.com-mk-....morrow-pub.json          # needs MORROW_SIGN_TOKEN, or use the console
morrow-sign sign dist/app-1.2.0.tar.gz --key example.com-mk-....morrow-key --upload
morrow-sign sign-site ./public --key example.com-mk-....morrow-key --upload
morrow-sign verify app-1.2.0.tar.gz
morrow-sign badge --domain example.com
```

Environment variables:

- `MORROW_SIGN_SERVER`: the Morrow address (default `https://morrow.soqlab.com`)
- `MORROW_SIGN_TOKEN`: an admin API key, for `register`
- `MORROW_SIGN_UPLOAD_KEY`: an upload key (console: Signing > Upload keys), for `--upload`
- `MORROW_SIGN_PASSPHRASE`: the private key's passphrase, for unattended signing

The full guide, including key rotation and what revocation does, is
[docs/PQ_SIGNING.md](https://github.com/soqlab/Morrow/blob/main/docs/PQ_SIGNING.md).

Requires Python 3.9+ and `cryptography` 50 or later.
