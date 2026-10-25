# Scanner Accuracy Audit

**Date:** 2026-09-20 · **Scope:** does the platform report the truth about what it scans?

**Second pass, same day.** The first pass fixed the classification bugs (B1-B9) and left three
structural ones: `scan_results` could not store a key size, a completed scan never became an asset,
and the negotiated key-exchange group was not observable. All three are fixed — B11, B12 and B13 in
§2, with the key-exchange investigation and its evidence in §6.

The product's core claim is that it finds quantum-vulnerable cryptography. This audit generated a
matrix of TLS servers on loopback whose certificates were minted for the purpose — so the correct
answer is known by construction, not by opinion — scanned them with the product's own
`POST /scan` code path, and followed every recorded field through the asset inventory, HNDL model,
FIPS report, crypto-agility score, migration velocity, compliance mapping, board report, CBOM export
and trust passport.

Nothing outside the machine was contacted. All fixtures ran on 127.0.0.1 ports 9101–9118.

---

## 1. Ground-truth matrix

Eighteen endpoints. Certificates were issued by a throwaway local CA created for the run, with the
CA trusted through `SSL_CERT_FILE` so that both the verified and the unverified scanner paths were
exercised.

| Port | Case | Ground truth |
|---|---|---|
| 9101 | `rsa2048` | RSA 2048, TLS 1.2+1.3, CA-issued, valid |
| 9102 | `rsa3072` | RSA 3072, TLS 1.2+1.3 |
| 9103 | `rsa4096` | RSA 4096, TLS 1.2+1.3 |
| 9104 | `ec_p256` | EC secp256r1 (256-bit), TLS 1.2+1.3 |
| 9105 | `ec_p384` | EC secp384r1 (384-bit) |
| 9106 | `ec_p521` | EC secp521r1 (521-bit) |
| 9107 | `ed25519` | Ed25519 (256-bit), CA-issued |
| 9108 | `tls12_only` | RSA 2048, server max TLS 1.2 |
| 9109 | `tls13_only_x25519` | EC P-256, server min TLS 1.3, X25519 group only |
| 9110 | `expired` | RSA 2048, notAfter 30 days in the past |
| 9111 | `self_signed` | RSA 2048, self-signed (not CA-issued) |
| 9112 | `hostname_mismatch` | RSA 2048, SAN = `other.invalid` only |
| 9113 | `short_expiry` | RSA 2048, 10 days to expiry |
| 9114 | `weak_ciphers_tls12` | RSA 2048, TLS 1.2, `@SECLEVEL=0` (accepts AES128-SHA etc.) |
| 9115 | `slow_no_response` | accepts the TCP connection, never completes the handshake |
| 9116 | `connection_closed` | accepts then resets the connection |
| 9117 | `plaintext_http` | plain HTTP, no TLS |
| 9118 | `closed_port` | nothing listening |

### What the scanner reported — before and after

| Case | Field | Before | After | Ground truth |
|---|---|---|---|---|
| all RSA/EC | key_type, TLS version, cipher, issuer, subject, notAfter, days-to-expiry | correct | correct | ✅ matched throughout |
| all | `key_bits` / `key_curve` | **absent** | 2048 / 3072 / 4096 / 256 / 384 / 521, curve name | ✅ |
| `ed25519` | key_type | `Ed25519PublicKey` | `Ed25519` | Ed25519 |
| `ed25519` | pq_relevance | `LOW` | `HIGH` | quantum-vulnerable |
| `ed25519` | quantum_risk_level | `low` | `high` | high |
| `ed25519` | classical_crypto_dependency | `False` | `True` | True |
| `ed25519` | harvest_now_decrypt_later_risk | `unknown` | `high` | high |
| `ed25519` | crypto_agility_score | `90` | `60` | — |
| `ed25519` | quantum_readiness_level | `ready_to_track_pq_rollout` | `needs_crypto_agility_work` | not ready |
| `self_signed` | verify_reason | `other` (generic VERIFY_FAILED) | `untrusted_issuer` (VERIFY_UNTRUSTED_ISSUER) | self-signed |
| `expired` | findings | CERT_EXPIRED + VERIFY_EXPIRED | unchanged | ✅ correct before and after |
| `hostname_mismatch` | findings | CERT_HOST_NOT_IN_SAN + VERIFY_HOSTNAME_MISMATCH | unchanged | ✅ |
| `short_expiry` | findings | CERT_EXPIRING_SOON (9 days) | unchanged | ✅ |
| `weak_ciphers_tls12` | findings | WEAK_CIPHER_ACCEPTED (critical) + NO_TLS13 | unchanged | ✅ |
| `tls12_only` | tls_supported_versions | `["TLSv1.2"]`, NO_TLS13 fired | unchanged | ✅ |
| 9115–9118 (4 failures) | findings | CERT_NO_CRL_DP, CERT_NO_OCSP_AIA, CHAIN_SHORT_OR_UNAVAILABLE | `SCAN_FAILED` only | no certificate exists |
| 9115–9118 | quantum_risk_level | `low` | `unknown` | unknown |
| 9115–9118 | pq_relevance | `LOW` | `UNKNOWN` | unknown |
| 9115–9118 | crypto_agility_score | `70` | `None` | no score is knowable |
| 9115–9118 | quantum_readiness_level | `needs_crypto_agility_work` | `not_assessed` | not assessed |
| 9115–9118 | scan_status | *(field did not exist)* | `timeout` / `unreachable` / `tls_error` | ✅ |

Every certificate fact the scanner reported — key type, TLS version, negotiated cipher, issuer,
subject, expiry, signature algorithm — matched ground truth **before and after**. The failures were
all in *classification*: what the product concluded from those facts, and what survived the trip
downstream.

---

## 2. Bugs found

### B1 — Ed25519, Ed448, X25519, X448, DSA and DH certificates were classified as not quantum-vulnerable — **Critical**

`scanner._pk_info()` recognised RSA and EC and fell through to `pk.__class__.__name__` for
everything else, so an Ed25519 certificate was reported with `key_type = "Ed25519PublicKey"` — a
string that matches no algorithm table in the product. Every consumer classified it "unknown", and
unknown reads downstream as *not vulnerable*: the endpoint came out at `pq_relevance: LOW`,
`quantum_risk_level: low`, `harvest_now_decrypt_later_risk: unknown`,
`classical_crypto_dependency: false`, `crypto_agility_score: 90` and
`quantum_readiness_level: ready_to_track_pq_rollout`. EdDSA over Curve25519 is broken by Shor's
algorithm exactly like ECDSA. The product told the customer a quantum-vulnerable endpoint was ready.

**Fix** — `backend/scanner.py`: new `_pk_details()` names Ed25519/Ed448/X25519/X448/DSA/DH, returns
`UNKNOWN` (not a class name) for anything genuinely unrecognised, and adds numeric `key_bits` and
`key_curve`. `backend/policy.py`: `QUANTUM_VULNERABLE_KEY_TYPES` and
`is_quantum_vulnerable_key_type()`; new rule `MORROW_CLASSICAL_ENDPOINT` (high) for the EdDSA/DSA/DH
class; `derive_quantum_readiness` uses the full set for `classical_crypto_dependency`.

### B2 — A failed scan was reported as a graded, low-quantum-risk asset — **Critical**

With no certificate, no TLS version and no key, the rule set still fired three findings that assert
things about a certificate that was never retrieved: "No CRL distribution points advertised", "No
OCSP responder advertised (AIA)" and "Certificate chain short or unavailable". The endpoint was then
scored `quantum_risk_level: low`, `pq_relevance: LOW`, `crypto_agility_score: 70`,
`quantum_readiness_level: needs_crypto_agility_work`, with the control list reading "Legacy crypto
cleanup: acceptable — No weak TLS/cipher finding was produced" and "Certificate hygiene:
acceptable". An unreachable host scored **better on quantum risk than a scanned RSA endpoint**, and
a scan of an estate the scanner could not reach looked like a clean one.

The agility score was built entirely from absent evidence: 20 points deducted for "no TLS 1.3" and
10 for "unknown provider" purely because the probe failed, and the remaining 70 kept for findings
that could not fire.

**Fix** — `backend/scanner.py`: `scan_status` and `error_code` fields, set by
`_finalise_scan_status()`. `backend/policy.py`: `_scan_observed_crypto()` gates the three
certificate rules; new `SCAN_FAILED` rule; `quantum_risk_level` and `pq_relevance` become
`unknown`/`UNKNOWN`; `crypto_agility_score` becomes `None` and readiness `not_assessed`; the two
control rows become `unknown` instead of `acceptable`. `backend/app.py`: the migration-report
average excludes unscored assets rather than folding them in, and reports
`assets_with_agility_score` / `assets_not_assessed`.

### B3 — Migration velocity counted every elliptic-curve asset as already migrated — **Critical**

`services/migration_velocity.py` held `ECDSA`, `ECDH`, `P-256` … in its vulnerable list but not the
bare `"EC"`, which is exactly what `scan_results.key_type` stores for every elliptic-curve
certificate — the same data-mapping bug as the one already found in `fips_pq.py`. The report had
only two buckets, so a non-match meant *safe*. A blank algorithm (a failed scan) also counted as
safe.

Measured on the 18-endpoint fixture estate: **"8 of 18 assets quantum-safe, 44.4% migrated"**. The
true answer is 14 vulnerable, 4 unknown, 0 migrated.

**Fix** — added `EC`, `ECC`, `DSA`, `Ed448`, `X448`, `EdDSA` to the vulnerable set, and replaced the
two-bucket split with three: only an asset positively identified as ML-KEM/ML-DSA/SLH-DSA/Falcon/
NTRU/BIKE/HQC/XMSS/LMS counts as migrated. Unobserved algorithms are reported in a new
`quantum_unknown_assets` field instead of being absorbed into "safe".

### B4 — The compliance export marked Ed25519 and X25519 endpoints "quantum-safe, compliant: YES" — **Critical**

`GET /compliance/export.csv` had `"x25519"` and `"ed25519"` in its `pq_safe` set. Both are classical
elliptic-curve algorithms broken by Shor. The Ed25519 fixture was exported to auditors as
`compliant=YES, finding=quantum-safe`. Unreachable endpoints were exported as
`compliant=NO, finding=" is quantum-vulnerable under NIST-PQ"` — a verdict on an asset that was
never contacted, with a blank algorithm name.

**Fix** — `backend/app.py`: the quantum-safe set now contains only the NIST post-quantum families; an asset with
no observed algorithm exports as `compliant=UNKNOWN` with an explicit "cryptography was not
observed" finding.

### B5 — The CBOM export contained no certificates at all — **High**

`services/cbom.generate_cbom()` documents its input as "the per-host dict produced by
`scanner.scan_host()`" but reads `cert_subject`, `cert_issuer`, `cert_key_type`, `cert_key_bits`,
`cert_sig_alg`, `cert_not_before`, `cert_not_after`. `scan_host()` emits `subject`, `issuer`,
`key_type`, `key_bits`, `sig_algorithm`, `not_before`, `not_after`. Nothing bridged the two, so
`subject` was always empty and the entire certificate block was skipped.

Measured: a CBOM generated from the 14 scanned TLS endpoints contained **0 certificate components,
0 public keys and 0 signature algorithms** — only the cipher-suite algorithms. The certificate
inventory is the part of a CBOM an auditor is asking for.

**Fix** — `services/cbom.py` accepts both spellings.

### B6 — The org-wide CBOM collapsed the whole estate into one empty component — **High**

`GET /cbom` read `host`, `port`, `algorithm`, `cipher`, `scan_time`, `cert_subject`, `cert_expiry`
off raw `scan_results` rows. None of those columns exist. Every row got the dedup key `":"` and a
blank algorithm, so an 18-asset estate produced **exactly one** nameless "TLS endpoint" component
with no cryptography in it — and returned HTTP 200. This is the fourth instance of the
`scan_results` column-mismatch class (after migration velocity, `/cbom.csv` and
`/compliance/export.csv`).

**Fix** — `backend/app.py` routes `/cbom` through `_latest_asset_scan_facts()`, the single existing
mapping from `scan_results` to flat host/port/algorithm facts, and excludes assets with no observed
key. After: 14 protocol + 14 certificate + 4 algorithm components.

### B7 — The trust passport was structurally incapable of reflecting findings — **High**

`_trust_passport()` counted high-risk rows out of `state["scans"]`, which is the `scans` table:
`(id, organization_id, status, created_at, progress_json, error_text, results_json, summary_json)`.
There is no `risk_level` or `algorithm` column, so `high_risk` was always 0 and `hybrid_hits` always
empty. The externally shareable passport therefore scored **90 / "monitored"** for any estate,
however many critical endpoints it contained.

Measured on the fixture estate (1 critical, 10 high-risk assets, graded F by the FIPS report):
score 90, status `monitored`, `high_risk_findings: 0`, `scan_count: 1`.

**Fix** — `backend/app.py` reads per-asset facts via `_latest_asset_scan_facts()`. After: score 45,
status `action_required`, `high_risk_findings: 10`, `scan_count: 18`.

### B8 — "secp521r1" was parsed as a 521-bit RSA modulus — **Medium**

`policy._rsa_key_size()` scanned the key detail string for digits and accepted anything ≥ 512. For a
P-521 certificate the curve name yields 521 — which, compared against an `RSA>=3072` policy, looks
like a catastrophically weak RSA key. The rule that consumes it happened to be gated on
`key_type == "RSA"`, so no wrong finding was published, but the function was one caller away from
doing so.

**Fix** — `_rsa_key_size()` returns 0 for anything that is not RSA/DSA/DH, and prefers the new
numeric `key_bits`.

### B9 — Self-signed certificates were downgraded to a generic verification failure — **Medium**

OpenSSL 3.0 renamed the message from "self signed certificate" to "self-signed certificate".
`scanner._classify_verify_error()` and `_error_code_from_verify_reason()` matched only the old
spelling, so on every modern OpenSSL build `VERIFY_UNTRUSTED_ISSUER` never fired and self-signed
endpoints were reported as `VERIFY_FAILED` ("verification failed for default trust store", medium)
with `verify_reason: other`.

**Fix** — both spellings matched.

### Supporting change — UI tone for the new `not_assessed` value

`frontend/index.html`'s `TONE()` matched `"not assessed"` with a space, so the scanner's
`not_assessed` readiness rendered as an untinted pill. Widened to `not.?assessed` so it takes the
neutral "info" tone. `unknown` already mapped to `info` — importantly, neither maps to the green
"ok" tone.

### B11 — `scan_results` could not hold what the scanner observed — **High**

The table was `(asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
pq_relevance, tls_version, key_type, sig_algorithm, owner, team, environment, criticality)`. There
was no key size, no curve, no cipher suite and no scan status, so every org-level report had to
invent the missing half of each observation:

* `cbom.canonical_algorithm()` defaulted to RSA-2048 and ECDSA-P256 when `key_bits` was 0 — and it
  was always 0, because `_latest_asset_scan_facts` returned `"key_bits": None` with the comment
  "not persisted per asset". **An estate of RSA-4096 and P-521 certificates was exported to
  auditors as RSA-2048 and ECDSA-P256.**
* `hndl._classify_algorithm()` bucketed every RSA asset as `rsa2048` and every EC asset as
  `ecc256`, so P-384/P-521 and RSA-3072/4096 endpoints were priced at the Q-Day probability of the
  weakest key in their family.
* `fips_pq.classify_algorithm()` has separate verdicts for RSA-2048 (`critical`), RSA-3072 and
  RSA-4096 (`high`), P-256 (`critical`), P-384 and P-521 (`high`) — none of which could ever be
  reached, because the caller only ever had the bare `"RSA"` or `"EC"`.
* Three input builders in `backend/app.py` (ZK compliance attestation, insurance underwriting
  export, actuarial risk) and `services/migration_autopilot.py:359` defaulted a missing key to a
  hardcoded `"rsa"` / `2048` / `"TLSv1.2"`. That is a fabricated observation presented to an
  auditor and to an insurer as a measurement.

**Fix** — `scan_results` gains `key_bits INTEGER`, `key_curve TEXT`, `cipher_name TEXT`,
`scan_status TEXT` and `key_exchange TEXT`, all NULLable, on SQLite and Postgres. NULL means *not
observed* and every reader renders it as unknown. New module `backend/scan_observation.py` is the
single mapping from `scan_host()` output to those columns, shared by both backends so they cannot
drift. `canonical_algorithm()` returns `None` for a bare RSA/EC with no size instead of guessing;
`hndl._classify_algorithm()` returns `unknown_classical` rather than `rsa2048`;
`fips_pq.classify_algorithm()` takes exact matches before prefix matches, which also removes the
undocumented load-bearing ordering noted in §5.5; the four hardcoded `"rsa"`/`2048` defaults now
read `""` / `0`. `/cbom.csv` and `/compliance/export.csv` carry the observed key size as its own
column, empty when it was not observed.

**Migration** — `alembic/versions/0007_scan_results_observed_key_facts.py` plus the
`ALTER TABLE … ADD COLUMN IF NOT EXISTS` statements in `db_postgres._CORE_SCHEMA_STATEMENTS` (the
path every column previously added to this schema has taken to an existing deployment) and
`db._ensure_scan_result_observation_columns` for SQLite. The backfill fills in only what the stored
`key_type` determines on its own — Ed25519 → 256/Curve25519, Ed448 → 456, X25519 → 256, X448 → 448.
A stored `"RSA"` could be 2048 or 4096 and a stored `"EC"` could be P-256 or P-521, so those rows
stay NULL. Filling them with a plausible number would be the original bug wearing a migration
costume.

### B12 — A completed scan never became an asset — **High**

Nothing in the scan path called `upsert_asset()`. A scan wrote `scan_results` and stopped, so after
scanning 18 endpoints `GET /assets` returned `{"items": []}` and `GET /hndl/dashboard` — which
iterates `list_assets()` — reported `asset_count: 0` and `total_exposure_usd: 0` for an estate with
ten high-risk endpoints in it.

**Fix** — `db.save_scan_asset_summaries()` (the one function all three scan paths go through:
`app._run_scan`, `tasks.run_scan_task`, `POST /scans/synthetic`) registers each scanned endpoint
first, through new `db.register_scanned_asset()` / `db_postgres.pg_register_scanned_asset()`.
`upsert_asset()` is deliberately *not* used: called with its defaults it writes empty strings over
`owner`, `team`, `environment` and `criticality`, so registering through it would erase the
customer's inventory metadata on every re-scan. The new path inserts and stops — `ON CONFLICT DO
NOTHING` against the `(organization_id, asset_key)` primary key — so a re-scan updates the scan
history and creates no second asset row, and no ownership, environment or data-classification value
is ever invented.

`GET /hndl/dashboard` now scores from the stored `key_bits`, `cipher_name` and `key_exchange`, and
an asset whose cryptography has never been observed returns `exposure_usd: null`,
`p_broken: null` and `risk_tier: "unmeasured"` rather than a dollar figure derived from an assumed
algorithm. The response gains `measured_asset_count`, `unmeasured_asset_count` and an
`exposure_basis` sentence saying how many assets the total is actually built from.

### B13 — The scanner could not observe the negotiated key-exchange group — **High**

`scan_host()` recorded nothing about the key exchange, which for a post-quantum product is the
field that matters most: whether an endpoint has already enabled `X25519MLKEM768` was invisible.
`cbom.generate_cbom()` read `key_exchange`, which was never set. The trust passport counted
`hybrid_tls_observations` by looking for "MLKEM" in the *certificate* algorithm, where it can never
appear, so the count was structurally 0 — a fixed 10-point deduction on every estate and an
unreachable `verified` status. `hndl._classify_algorithm()` looked for "kyber"/"mlkem" in the
cipher-suite name; TLS 1.3 suite names (`TLS_AES_256_GCM_SHA384`) never name the key exchange, so
the `pq_hybrid` and `pq_pure` Q-Day buckets were unreachable from any TLS 1.3 scan.

The previous audit concluded this needed an OpenSSL upgrade. It does not — see §6 for what was
actually possible and why.

**Fix** — `scanner._probe_key_exchange_group()` builds a TLS ClientHello by hand and parses the
ServerHello. `scan_host()` gains `key_exchange`, `key_exchange_group_id`, `key_exchange_family`
(`pq_hybrid` / `pq_pure` / `classical`), `key_exchange_observed`,
`key_exchange_observation_method`, `key_exchange_unobservable_reason` and
`key_exchange_hello_retry`. The group is persisted on `scan_results` and consumed by the CBOM, the
HNDL buckets and the trust passport, whose evidence block now reports
`key_exchange_observed_endpoints`, `key_exchange_unobserved_endpoints` and a `hybrid_tls_basis`
sentence, and only deducts the hybrid points where at least one group was actually observed.

### B10 — The developer portal's scan findings are always empty — **Low** *(not fixed)*

`services/dev_portal.list_findings_for_scope()` selects `host, endpoint, finding_type, severity,
algorithm, vulnerability, remediation_hint, scan_ts` from `scan_results`. None of those columns
exist; the query raises and a bare `except Exception: pass` swallows it, so the team/repo findings
view silently reports zero scan findings and shows only remediations. Same class as B6; left unfixed
because it needs a product decision about what that view should show (see §5).

---

## 3. Customer-visible numbers that change

These are real output changes, not refactors. Anyone quoting a previous report will see different
figures.

| Surface | Before | After |
|---|---|---|
| Migration velocity — "% migrated" | EC assets counted as migrated. Fixture estate: **44.4%**, 8 of 18 "quantum-safe" | **0%**, 0 safe, 14 vulnerable, 4 unknown. **Progress will drop for every customer with ECDSA certificates** |
| Migration velocity — response shape | two buckets | new `quantum_unknown_assets` field |
| Trust passport (shareable) | fixture estate scored **90 / monitored**, `high_risk_findings: 0` | **45 / action_required**, `high_risk_findings: 10`. Scores will fall across the board; estates with high-risk assets may move from `monitored` to `action_required` |
| Compliance export CSV | Ed25519/X25519 rows `compliant=YES, quantum-safe` | `compliant=NO, quantum-vulnerable`. Unscanned rows move from `NO` to `UNKNOWN` |
| Org CBOM (`GET /cbom`) | 1 component | 14 protocols + 14 certificates + algorithms |
| Per-scan CBOM (`/scans/{id}/cbom.json`) | no certificate components | certificates with public key and signature algorithm refs |
| Ed25519 endpoints everywhere | `pq_relevance LOW`, `quantum_risk_level low`, agility 90, "ready to track post-quantum rollout" | `HIGH` / `high` / 60 / "needs crypto agility work". Org-level risk counts rise |
| Unreachable / non-TLS / timed-out endpoints | agility score 70, readiness "needs_crypto_agility_work", `quantum_risk_level low` | `crypto_agility_score: null`, readiness `not_assessed`, `quantum_risk_level unknown` |
| Average crypto-agility score | unscanned assets folded in at 70 | excluded; new `assets_with_agility_score` / `assets_not_assessed` counters |
| Scan result shape | — | new fields `scan_status`, `error_code`, `key_bits`, `key_curve` |
| Failed-scan `quantum_risk_score` | 12 (three fabricated certificate findings) | 8 (one `SCAN_FAILED` finding). `risk_level` stays `medium` either way |
| Self-signed endpoints | `VERIFY_FAILED` (medium) | `VERIFY_UNTRUSTED_ISSUER` (medium) — same severity, correct reason |
| Endpoint whose key parsed but matched no algorithm | agility 70 (scored *better* than a known RSA endpoint) | 60, same deduction as a known-vulnerable key; new `CRYPTO_NOT_IDENTIFIED` finding (medium) |
| Org CBOM key sizes (`GET /cbom`) | whole estate reported as **RSA-2048 / ECDSA-P256** | the observed sizes — RSA-3072/4096, ECDSA-P384/P521. **Any customer with keys larger than 2048/P-256 will see different algorithm components** |
| Org CBOM key exchange | absent | the negotiated group; a hybrid endpoint contributes an ML-KEM component |
| `GET /assets` after a scan | `{"items": []}` — scanning registered nothing | one asset per scanned host and port |
| `GET /hndl/dashboard` on a scanned-only estate | `asset_count: 0`, `total_exposure_usd: 0` | real asset count and exposure. **A customer who has only ever scanned goes from $0 to a non-zero figure** |
| HNDL exposure per asset | every RSA asset priced at the RSA-2048 curve, every EC asset at P-256's | priced at the observed size. **Exposure falls for RSA-3072/4096 and P-384/P-521 endpoints** (the old figure overstated it) |
| HNDL asset never scanned | priced at `unknown_classical` and folded into the org total | `exposure_usd: null`, `risk_tier: "unmeasured"`, excluded from the total; new `measured_asset_count` / `unmeasured_asset_count` / `exposure_basis` |
| HNDL `pq_hybrid` / `pq_pure` buckets | unreachable | reached when the observed group is hybrid or pure ML-KEM |
| FIPS report / compliance mapping | every RSA asset graded at the RSA-2048 verdict (`critical`), every EC asset at P-256's | RSA-3072/4096 and P-384/P-521 grade `high`. **Org FIPS scores rise slightly for estates with larger keys** |
| Trust passport `hybrid_tls_observations` | structurally always 0, costing a fixed 10 points | counted from the observed group; new `key_exchange_observed_endpoints`, `key_exchange_unobserved_endpoints`, `hybrid_tls_basis`. The 10-point deduction no longer applies where nothing was observed, so scores rise for estates that have not been re-scanned |
| ZK compliance attestation, insurance underwriting export, actuarial risk, migration autopilot | an unscanned asset was submitted as **RSA-2048 over TLS 1.2** | `key_type: ""`, `key_bits: 0`, `tls_version: ""` |
| `/cbom.csv` | host, port, algorithm, tls_version, risk_level, signature_algorithm, quantum_score, scanned_at | adds `key_bits`, `key_curve`, `cipher_name`, `key_exchange` |
| `/compliance/export.csv` | no key size column | adds `key_bits`; `algorithm` is now size-qualified (`RSA-4096`, `P-521`) |
| Scan result shape | — | adds `key_exchange`, `key_exchange_family`, `key_exchange_observed`, `key_exchange_unobservable_reason`, `key_exchange_group_id`, `key_exchange_hello_retry` |

---

## 4. Tests

* `backend/test_scanner_accuracy.py`
  * `test_ground_truth_matrix` — table-driven over RSA 2048/3072/4096, P-256/384/521 and Ed25519,
    asserting key type, key bits, curve, classical dependency, post-quantum relevance, quantum risk level,
    HNDL tier and readiness. A new key type cannot be added without an answer in every column.
  * `test_ed25519_is_quantum_vulnerable_not_unknown` (B1)
  * `test_ec_curve_size_is_reported_numerically` (B1 / key_bits)
  * `test_p521_curve_is_not_read_as_a_tiny_rsa_modulus` (B8)
  * `test_closed_port_…`, `test_non_tls_port_…`, `test_unresolvable_host_…` — all share
    `_assert_failed_scan_is_not_a_clean_one`, which pins the whole B2 contract: SCAN_FAILED present,
    no fabricated certificate findings, unknown not low, no agility score.
  * `test_self_signed_certificate_is_classified_as_untrusted_issuer` (B9)
* `backend/test_scan_pipeline_accuracy.py` (new) — the downstream half:
  * migration velocity over EC / blank / every classical key type / post-quantum algorithms (B3)
  * `generate_cbom` on genuinely scanner-shaped input, plus a key-size table (B5)
  * `/compliance/export.csv` over a seeded estate — Ed25519 is not quantum-safe, unknown is UNKNOWN (B4)
  * `/cbom` is not a single empty endpoint (B6)
  * `/trust-passport` reflects high-risk assets (B7)

* `backend/test_scanner_accuracy.py` — key-exchange observation (B13)
  * `test_negotiated_key_exchange_group_is_observed` — x25519 on TLS 1.3, secp384r1 through a
    HelloRetryRequest (the reply shape a post-quantum-enabled server gives), secp521r1 on TLS 1.2
  * `test_hybrid_post_quantum_key_exchange_is_recognised` — a fixture server returns a real,
    spec-shaped HelloRetryRequest naming `X25519MLKEM768` (0x11EC). No TLS stack available here
    can *perform* hybrid key exchange, so handing the scanner the bytes such a server would send
    is the only way to prove it recognises the group rather than reading it as plain X25519.
  * `test_unreachable_endpoint_reports_key_exchange_as_unobserved_not_absent`,
    `test_non_tls_endpoint_reports_key_exchange_as_unobserved` — "not observed" carries a reason
    and is never reported as "no post-quantum key exchange"
* `backend/test_scan_pipeline_accuracy.py` — the stored key facts, the asset path, the migration
  * `test_org_cbom_reports_the_key_size_that_was_observed` — an RSA-4096 / P-521 estate must not
    export RSA-2048 or ECDSA-P256 (B11)
  * `test_org_cbom_names_the_hybrid_key_exchange_group`,
    `test_an_unknown_key_stays_unknown_in_the_org_cbom`
  * `test_compliance_export_states_the_observed_key_size` — and leaves the cell empty when there
    was no observation
  * `test_fips_report_grades_rsa_4096_below_rsa_2048` (B11 / §5.5)
  * `test_a_scan_registers_every_endpoint_as_an_asset`,
    `test_rescanning_updates_the_asset_instead_of_duplicating_it`,
    `test_a_scan_does_not_overwrite_ownership_the_customer_set` (B12)
  * `test_hndl_buckets_use_the_observed_key_size` — table-driven, including the two cases where
    the size was *not* observed and the answer must be `unknown_classical`, not `rsa2048`
  * `test_hndl_reaches_the_hybrid_bucket_from_an_observed_group`,
    `test_hndl_does_not_price_an_asset_that_was_never_scanned`,
    `test_hndl_dashboard_counts_scanned_assets_and_excludes_unmeasured_ones` (B12/B13)
  * `test_trust_passport_counts_hybrid_key_exchange_it_actually_observed` (B13)
  * `test_populated_sqlite_database_upgrades_cleanly`,
    `test_populated_sqlite_database_upgrades_through_alembic`,
    `test_populated_postgres_database_upgrades_cleanly` (skipped unless `MORROW_TEST_PG_DSN` is set)
    — each builds a database in the *pre-change* shape, fills it with rows, upgrades it, and
    checks that Ed25519/X25519 were backfilled while RSA and EC stayed NULL

50 tests pass across the two files. Re-run against the final code for regressions, all green
(236 tests total): `test_truthful_outputs`, `test_board_risk`, `test_cbom_conformance`,
`test_compliance_gate`, `test_contract_v1`, `test_airlock_enterprise` (trust passport),
`test_launch_collateral`, `test_crypto_governance`, `test_red_team_sim_data`,
`test_sprint18_compliance_report`, `tests/test_core_scan` and the `test_sprint9_2/9_3/9_4/9_6/9_7`
policy suites.

---

## 5. Still wrong — not fixed

Items 1-3 of this section are **now fixed**; see B11, B12 and B13 in §2 and the hybrid-observation
verdict in §6. They are kept here in outline so anyone following a link to the old numbers can see
what changed.

1. ~~**`scan_results` stores no key size, and no scan status.**~~ *(fixed — B11)* The table now
   carries `key_bits`, `key_curve`, `cipher_name`, `scan_status` and `key_exchange` on SQLite and
   Postgres, all NULLable so that "not observed" stays distinguishable from a value. The four
   hardcoded `"rsa"` / `2048` defaults are gone.
2. ~~**`GET /hndl/dashboard` reports $0 exposure for a scanned-only estate.**~~ *(fixed — B12)* A
   completed scan registers the asset it scanned, without inventing ownership, environment or
   data classification, and an asset whose cryptography has never been observed reads as
   `unmeasured` rather than being priced at a default algorithm.
3. ~~**The scanner cannot observe the negotiated key-exchange group at all.**~~ *(fixed — B13)*
   It can, without upgrading OpenSSL and without a new dependency. §6 has the evidence.

4. **`services/dev_portal.list_findings_for_scope`** (B10) — still queries eight non-existent
   columns inside a bare `except`.

5. ~~**`fips_pq.classify_algorithm` uses prefix matching over an ordered dict.**~~ *(fixed with
   B11)* The ordering was load-bearing and undocumented — moving `"EC"` earlier would silently
   reclassify every ECDH asset — and it was also why `"RSA-4096"` hit the bare `"RSA"` row and was
   graded `critical` instead of its own `high`. Exact matches are now taken across all three tables
   before any prefix match, so the ordering no longer decides the verdict.

6. **`hndl` has no Q-Day curve for P-521 or for a bare ML-KEM signature.** `_Q_DAY_PROBS` stops at
   `ecc384`, so a P-521 endpoint is priced on the P-384 curve. That is much closer than the old
   behaviour (everything landed on `ecc256`) and errs toward over-reporting, but it is still not
   the curve for the key that was observed.

7. **`hndl._classify_algorithm` maps Ed25519 to the `x25519` Q-Day bucket** by a `"25519" in
   key_type` substring test. The probability curve is close enough that it is not a live defect, but
   it matches by coincidence rather than by classification.

8. **Not verified:** Post-quantum certificates (ML-DSA/SLH-DSA — `cryptography` cannot mint them and no
   post-quantum-capable TLS stack is installed), and the SSH and code scanners, which were out of scope.
   Postgres is no longer on this list: the schema change was applied to a populated Postgres
   database through both the runtime path and an alembic upgrade, and the scan → asset → report
   path was exercised end to end against a real server (see §4). The `assets` table is now
   populated by scanning, so the `board-risk` and `crypto-agility` paths run against a non-empty
   inventory in the suite.

---

## 6. Hybrid key exchange: what this deployment can actually observe

The previous pass concluded that observing the negotiated TLS 1.3 key-exchange group required
either an OpenSSL upgrade or shelling out to `openssl s_client`, and put it out of scope. That
conclusion was wrong in an interesting way, so the investigation is recorded here.

### What is available

| Option | Verdict |
|---|---|
| `ssl.SSLSocket.group()` | **Unavailable.** Needs OpenSSL 3.2+. `ssl.OPENSSL_VERSION` is `OpenSSL 3.0.18` and `hasattr(ssl.SSLSocket, "group")` is `False`. |
| `ssl.SSLSocket.group()` after upgrading CPython's OpenSSL | **Would not have solved it.** A group has to be *offered* to be negotiated, and `X25519MLKEM768` first exists in OpenSSL 3.5. A scan run through `ssl` on 3.2, 3.3 or 3.4 could read the group and still never see a hybrid one, because it could not propose one. The field would have reported "no hybrid key exchange" for a server that supports it. |
| `cryptography`'s bundled OpenSSL | **Not usable for this.** `cryptography` 50.0.0 does link a much newer OpenSSL (`backend.openssl_version_text()` reports `OpenSSL 4.0.1`), but it exposes no TLS client: the SSL bindings were removed from the Rust build years ago. The bundled library is reachable for X.509 and primitives only. |
| A local `openssl s_client -groups` subprocess | **Rejected.** The `openssl` on PATH here is 3.1.4, which also predates both `-groups` output for TLS 1.3 and any ML-KEM hybrid. More importantly it makes the scanner depend on an external binary whose version, availability and output format vary per host — exactly the brittleness the product cannot afford in its most load-bearing field. |
| A new dependency with its own TLS stack | **Rejected.** Nothing in `requirements.txt` provides one, and adding a TLS implementation to observe one two-byte field is not a proportionate dependency. |
| **Speak TLS directly** | **Chosen.** |

### What was implemented

`scanner._probe_key_exchange_group()` builds a `ClientHello` by hand and parses the `ServerHello`.
It needs no TLS library, no new dependency and no completed handshake: the server's answer to
"here are the groups I support, which do you choose?" is sent in the clear, in the first flight.

* The offered `supported_groups` list leads with `X25519MLKEM768` (0x11EC), `SecP256r1MLKEM768`
  (0x11EB), `SecP384r1MLKEM1024` (0x11ED) and the pre-standard Kyber draft code points, followed
  by the classical groups. The ClientHello carries a single x25519 key share.
* A server that prefers a group we sent no share for answers with a **HelloRetryRequest naming
  that group** — which is exactly what a post-quantum-enabled server does. Both the ServerHello and the
  HelloRetryRequest branch are parsed, so the hybrid case is reachable and is covered by a test.
* TLS 1.2 is covered too: the named curve is read from `ServerKeyExchange` in the same flight.
* Every failure path sets `key_exchange_observed: False` with a `key_exchange_unobservable_reason`
  and leaves `key_exchange` empty. The probe is wrapped so it can never fail a scan, and it only
  runs when a TLS handshake completed on the port.

### Evidence

Against local fixtures (`cryptography`-minted certificates, loopback only):

| Fixture | Observed |
|---|---|
| TLS 1.3, server default groups | `x25519`, `classical`, no HelloRetryRequest |
| TLS 1.3, server restricted to X25519 | `x25519`, `classical` |
| TLS 1.3, server restricted to secp384r1 | `secp384r1`, `classical`, **HelloRetryRequest** |
| TLS 1.2, server restricted to secp521r1 | `secp521r1`, `classical` |
| Server answering with a HelloRetryRequest naming 0x11EC | `X25519MLKEM768`, **`pq_hybrid`** |
| Closed port | not observed — "connection failed: …" |
| Plaintext HTTP | not observed — "no ServerHello in the first flight" |

The hybrid row is a synthesised ServerHello rather than a live post-quantum server, and that is a real limit
of this evidence: no TLS stack installed here can perform hybrid key exchange, so the handshake
*after* the HelloRetryRequest cannot be exercised. The probe never gets that far — it reads the
group and closes the socket — so what is proven is exactly what the product relies on: the group is
read off the wire and classified as hybrid rather than as plain X25519.

### What the product now says when it cannot observe

Where the group is unobservable, no field reports 0. `scan_host()` returns
`key_exchange_observed: False` with the reason; the trust passport reports
`key_exchange_unobserved_endpoints` alongside `hybrid_tls_observations` and states the basis in
words ("no endpoint's TLS key-exchange group has been observed yet, so hybrid post-quantum key
exchange is not measured for this organization"), and withholds the 10-point hybrid deduction
rather than penalising an estate for a measurement nobody took.

### Still open

* No post-quantum **certificate** can be minted or served here (`cryptography` cannot produce
  ML-DSA/SLH-DSA certificates and no post-quantum-capable TLS stack is installed), so the `pq_pure`
  classification of a *signature* algorithm remains untested against a live endpoint. The
  key-exchange side of `pq_pure` (a bare ML-KEM group) is covered by the classifier tests only.
* The probe reports which group the server selects **from what this scanner offers**. That is the
  right measurement for "has this endpoint enabled hybrid key exchange", but it is not a
  transcript of what the endpoint negotiates with any particular real client.
