# Open-Source Readiness Review

**Repository:** Morrow / PQC Scanner
**Owner:** Yasseen Nandally
**Target licence:** MIT
**Review date:** 3 October 2026
**Verdict: GO, conditional on four items** — see the [go/no-go checklist](#gono-go-checklist).

This document records what was scanned, what was found, what moved, the dependency licence audit,
and the checklist to work through before making the repository public. It is the audit trail for the
decision to publish.

---

## 1. Headline

| Question | Answer |
|---|---|
| Are there secrets in the git history? | **No.** No real credential was found in any blob of any commit on any ref. |
| Is there personal or customer data? | **No real emails, customer names or IP addresses.** One live hostname was found and removed. |
| Does a clean clone start and work? | **Yes.** Verified end to end, including `docker compose up` and the seeded workspace. One real bug was found and fixed in the process. |
| Does anything force the project off MIT? | **No.** No GPL, AGPL or SSPL in any dependency graph. |
| Biggest remaining risk | **Publishing with the existing git history** would expose internal commercial documents that were removed from the working tree but remain in past commits. See [section 6](#6-the-history-problem). |

---

## 2. Secret scan

### Method

A purpose-written scanner (no third-party tool, no network install) walked **every blob reachable
from every ref** — all 69 local branches plus remotes — using `git rev-list --all --objects` and
`git cat-file --batch`.

- **2,054** named objects enumerated; **1,991** scannable after excluding binary media; **1,532**
  text blobs actually read and matched.
- **26 high-signal provider patterns**: OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-`), Stripe
  (`sk_live_`, `rk_live_`, `pk_live_`, `whsec_`), AWS (`AKIA`/`ASIA`), GitHub (`ghp_`,
  `github_pat_`, `gho_`, `ghu_`/`ghs_`/`ghr_`), Slack (`xox[baprs]-`, webhook URLs), Google
  (`AIza`), SendGrid, Twilio, npm, PyPI, HashiCorp Vault, PEM private-key blocks, JWTs, and database
  URLs carrying a password.
- **Assignment-position matching** for credential-shaped names (`*_SECRET`, `*_PASSWORD`, `*_KEY`,
  `*_TOKEN`, `DSN`, `CONNECTION_STRING`, …) in both quoted and bare `.env`/YAML form, filtered by a
  Shannon-entropy and character-class test so that only genuinely random-looking values were
  reported.
- A **second pass specifically for PEM private keys**, distinguishing a real key (`BEGIN` header +
  at least three base64 body lines + `END` footer) from a detection pattern or UI string that merely
  mentions the header.

No secret value is reproduced in this document or was printed during the review. Findings were
recorded as path, line, pattern and a redacted fingerprint (first four characters, length, SHA-256
prefix).

### Result: clean

283 raw matches, every one explained. Nothing requires purging and nothing requires rotation.

| Finding | Location | Verdict |
|---|---|---|
| `postgresql://pqc:pqc@…` ×54 | `backend/compose.yml`, `.github/workflows/ci.yml` | Local dev and CI service credentials for a throwaway container. Benign. |
| `postgresql://unused:unused@localhost/unused` | `backend/alembic.ini` | Placeholder; Alembic reads the real URL from the environment. Benign. |
| `PQC_VAULT_MASTER_KEY` ×6 | `.github/workflows/ci.yml` | Base64 of the ASCII string `pqc-scanner-test-only-key-32byte`, with a comment saying so. A deliberate throwaway Fernet key. Benign. |
| PEM `PRIVATE KEY` headers ×78 | `backend/services/secrets_scanner.py`, `backend/app.py`, `backend/static/index.html`, tests | **The product's own detection patterns** — this is a scanner that looks for leaked keys. Verified: no header anywhere in history is followed by base64 key material. Benign by design. |
| `token_hash = …` ×29 | `backend/services/auth_issuer.py`, `backend/services/operator_auth.py` | False positive: the matched "value" is the SQL string `INSERT OR REPLACE INTO pqc_refresh_tokens (token_hash, …)`. The code hashes a `secrets.token_urlsafe(48)` generated at runtime. Benign. |
| `AKIA…` ×12 | `backend/static/index.html` | An HTML `placeholder=` attribute on the AWS key-ID input field. Benign. |
| `AKIA…` ×1 | `backend/test_secrets_scanner_aws.py` | AWS's own published documentation example key. Benign. |
| Slack webhook ×3 | `backend/test_security_review_findings.py`, private security review | Synthetic fixture of the form `…/T000…/REVIEW…/SECRET…`. Benign. |
| `sk-1…` ×1 | `backend/test_ai_data_control.py` | A 23-character literal inside a redaction test's parameter list — the test asserts that such a string gets masked. Benign. |

### Environment files

`backend/.env` is ignored by `.gitignore` line 13 and **was never tracked**. The only `.env`-shaped
paths that have ever existed in history are templates:

```
.env.prod.example
backend/.env.local.example
backend/.env.production.example
```

The real `.env.prod` in the working tree is ignored by line 14 (`.env.*`) and has never been
committed. Verified by enumerating every path containing `.env` across all of history, not just the
current tree.

> **Standing advice, independent of this scan:** any credential that has ever been pasted into a
> terminal, a screenshot, a chat window or a local `.env` should be rotated before the repository
> goes public, because this scan can only prove the absence of secrets *in git*.

### Reproducing the scan

The scanner was written for this review and lives in the scratch directory, not the repository. To
re-run an equivalent check before publishing, [gitleaks](https://github.com/gitleaks/gitleaks) or
`trufflehog git file://.` over `--all` refs will cover the same ground. If a real secret is ever
found later, the procedure is:

1. **Rotate first.** A secret in a public history must be treated as compromised the moment it is
   published, and purging does not un-publish it. Rotation is the only real remediation.
2. Then purge, with [git-filter-repo](https://github.com/newren/git-filter-repo):
   ```bash
   git filter-repo --path path/to/file --invert-paths          # drop a whole file
   git filter-repo --replace-text replacements.txt             # or redact a literal
   ```
   (or BFG: `bfg --delete-files secrets.env` / `bfg --replace-text replacements.txt`)
3. Force-push, and tell every collaborator to re-clone — a rewrite changes every subsequent commit
   hash, and an old clone can push the removed objects back.

**No history rewrite is needed for secrets.** It is worth considering for a different reason — see
[section 6](#6-the-history-problem).

---

## 3. Personal and sensitive data

### Removed

| What | Where | Action taken |
|---|---|---|
| **Live Cloud Run hostname** `pqc-api-…-ew.a.run.app` | `docs/COMPLETE_DOCUMENTATION.md` (5), `docs/TRY_IT_IN_THE_CLOUD.md` (3), `docs/USER_GUIDE.md` (2) | **Replaced with `YOUR_DEPLOYED_HOST`.** This was a reachable, deployed service presented as the live app UI and an org compliance-report endpoint — publishing it invites traffic and probing. |

**Note:** the hostname remains in git history. It is a hostname, not a credential, so this is a
nuisance rather than a breach — but it is one more argument for [section 6](#6-the-history-problem).
Either way, the service behind it should be considered known and protected accordingly.

### Verified clean

- **Email addresses** — every address in the tracked tree is a reserved placeholder (`*.test`,
  `*.example`, `example.com`, `your-domain.com`) or an OpenSSH algorithm name that merely looks like
  one (`chacha20-poly1305@openssh.com`). The owner's own address appears in `SECURITY.md` by design
  as the security contact.
- **Customer and company names** — none. Every tenant in test and demo data is reserved fiction:
  `Example Financial Group`, `northwind-traders`, `contoso-metals`, `fabrikam-works`, `Acme`. Every
  other company named (Stripe, Cloudflare, Okta, Auth0, AWS, Azure, GCP, …) is an integration
  target, not a customer.
- **IP addresses** — nothing outside documentation and reserved ranges. What the scan surfaced was
  cryptographic OIDs that pattern-match as IPv4 (`1.3.101.112` is Ed25519; `2.16.840.1` is RSA),
  IANA special-purpose ranges used deliberately in the SSRF guard's tests (`192.0.0.0`,
  `192.88.99.0`, `198.18.0.0`, `240.0.0.0`), and `93.184.216.34`, which is `example.com`.
- **Demo database** — `demo/video/demo.db` (18.5 MB + a 10.8 MB WAL) is untracked and is now
  explicitly git-ignored. Its contents are generated by `demo/video/seed-demo-data.py` from an
  invented estate, so nothing real was in it regardless.

---

## 4. Large binaries

**None are tracked.** The only tracked file over 1 MB is `backend/app.py` at 1.1 MB, which is source.

The risk was latent rather than realised: `.gitignore` covered `demo/video/*.mp4` but not the other
generated media, so **a single `git add .` would have committed about 290 MB** permanently.

| Asset | Size | Was it ignored? | Now |
|---|---|---|---|
| `demo/video/*.mp4` (8 files) | ~830 MB | Yes | Yes |
| `demo/video/*.wav` masters (4) | ~190 MB | **No** | **Ignored** |
| `demo/video/demo.db` + WAL | ~29 MB | **No** | **Ignored** |
| `demo/video/raw/*.webm` | ~67 MB | **No** | **Ignored** |
| `demo/tour/ambient-loop.{m4a,mp3}` | ~3 MB | **No** | **Ignored** |
| `demo/tour/*.jpg` (16 screenshots) | ~4 MB | No | **Deliberately kept** — the README embeds them |

After the fix, a `git add .` of the current working tree adds **4.75 MB**, almost all of it the
README screenshots.

### Hosting the videos

The finished videos are legitimate project assets; they just must not live in git, where every clone
pays for them forever and deleting them later does not shrink the repository.

1. **GitHub release assets — recommended.** Up to 2 GB per file, no Git LFS quota, downloadable
   without cloning. Create a release such as `demo-media-v1`, attach the MP4s, and link them from the
   README.
2. **Git LFS** — keeps them "in" the repository but consumes bandwidth quota on every clone and
   makes the repository harder to fork. Not recommended for marketing media.
3. **External hosting** — YouTube or a CDN bucket, embedded in the README. Best reach, least
   repository weight.

The rendering scripts (`render-*.js`, `assemble-*.py`, `make-*-music.py`) stay in the repository, so
the media is reproducible from source. That is the right division: scripts are source, renders are
artefacts.

---

## 5. What was moved out, and why

Moved to **`../pqc-scanner-private/`**, preserved rather than deleted. Nothing was removed silently;
every file below is listed so the owner can relocate it to a private repository.

### The security review — the delicate case

`pqc-scanner-private/docs/SECURITY_REVIEW_2026-09.md` (58 KB, 860 lines) documents 17 findings: 14 fixed with named
regression tests, and **three still open**.

Publishing the fixed findings would be good practice. Publishing the open ones would not. The file
names the exact endpoints, prints working reproduction transcripts, and in one case gives a complete
four-request sequence that still works against a fresh deployment. It also maps where credentials
live in browser storage on an origin whose Content-Security-Policy still permits inline script.

The three options, assessed:

| Option | Assessment |
|---|---|
| **Fix before publishing** | Best outcome, wrong timing. All three are real work — one needs changes to both front ends, one is a restructuring of a 9,500-line single-file SPA, one is inherent to bootstrapping MFA in-band. Blocking publication on them means not publishing. |
| **Redact the open sections** | Workable but reads badly. The open-findings prose is load-bearing for the document's honesty; a version with holes cut in it looks evasive, and the surrounding remediation table still refers to them. |
| **Move it out and publish a summary** | **Chosen.** |

**Action taken:** the full report moved to the private location, and
[`docs/SECURITY_REVIEW_SUMMARY.md`](SECURITY_REVIEW_SUMMARY.md) written in its place. The summary
keeps the method, the fixed-finding classes, the verification, and the "what I could not test"
section — and states the three open items *by class*, with the operational advice that matters (a
fresh deployment should enrol MFA immediately), without the endpoints, payloads or repro steps that
would make them directly actionable. The two that are defence-in-depth weaknesses rather than live
holes are also listed in `SECURITY.md` under *Known gaps*.

This is the honest position: a reader learns that a real review happened, what it found, what was
fixed, and that three items remain — which is more than most projects disclose — while an attacker
gains nothing usable.

### Vendor-confidential commercial material (25 files)

| Category | Files |
|---|---|
| Pricing and go-to-market | `PRICING_AND_PACKAGING.md`, `CONTROLLED_PILOT_OFFER.md`, `GTM_PILOT_PACK.md`, `GO_TO_MARKET_READINESS.md`, `MARKET_LAUNCH_PACK.md`, `PILOT_ONE_PAGER.md` |
| Commercial and legal | `SLO_SLA.md` (uncontracted targets), `DPA_TEMPLATE.md` (unreviewed by counsel) |
| Customer onboarding | `CUSTOMER_ONBOARDING_RUNBOOK.md`, `ENTERPRISE_PILOT_SETUP_CHECKLIST.md`, `SUPPORT_AND_INCIDENT_RESPONSE.md`, `TRUST_PASSPORT_DEMO.md` |
| Demo and marketing production | `DEMO_TALK_TRACK.md`, `DEMO_VIDEO_SCRIPT.md`, `DEMO_VIDEO_SHOT_LIST.md`, `DEMO_VIDEO_WALKTHROUGH.md`, `demo-video-storyboard.html` |
| Internal reviews and dated records | `LAUNCH_REVIEW_2026-09-08.md`, `LOAD_TEST_REPORT.md`, `STAGING_DRY_RUN.md`, `PRODUCTION_HANDOFF.md`, `PRODUCTION_RELEASE_2026-09-26.md`, `enterprise-readiness-handoff.md`, `GATEWAY_VERIFICATION_2026-09-13.md`, `SECURITY_LOGGING_VERIFICATION_2026-09-13.md` |

Reasons: the pricing documents state price bands and one says in its own text not to publish them.
The launch and readiness reviews state the product is not approved for public production deployment
— true in a controlled-pilot context, misleading as a standing public claim. `LOAD_TEST_REPORT.md`
publishes unflattering scale ceilings in a form that reads as a vulnerability inventory.
`STAGING_DRY_RUN.md` contains a live-journey transcript and an unfixed tenant-binding bug.

### Also moved

| Path | Why |
|---|---|
| `reports/` (5.6 MB, 46 tracked files) | Dated internal release-evidence bundles from specific local runs. Verified free of secrets (localhost URLs only), but point-in-time internal artefacts of no value to a reader. |
| `scripts/launch-collateral-check.ps1` | Gates on the presence of the GTM collateral above; broken without it. |
| `pqc-scanner-private/scripts/open-demo-recording.ps1` | Opens the moved marketing storyboard. |

Seven cross-references from documents that remain were rewritten to say the material is maintained
privately, rather than left as broken links.

### Deliberately kept public

`docs/SCANNER_ACCURACY_AUDIT.md` measures the scanner against ground truth and documents where it is
**wrong**, including two items not fixed. This was considered for removal and kept: these are
product-truthfulness limits that the product already surfaces to its own users, not exploitable
security gaps, and publishing them is a credibility asset. `docs/BUYER_SECURITY_FAQ.md` and
`docs/PILOT_SECURITY_REVIEW.md` are honest about the absence of certification and are also kept.

---

## 6. The history problem

**This is the most consequential finding in the review, and it is not about secrets.**

The internal documents in section 5 were removed from the working tree. **They remain in git
history** — every one is reachable in past commits, and `git log --all -- docs/PRICING_AND_PACKAGING.md`
finds it immediately. Publishing this repository with its history intact publishes all of them,
along with the live Cloud Run hostname.

**This was demonstrated, not assumed.** Building a test clone with `git archive HEAD` — which is
what a `git clone` of the current state yields — restored all 26 internal documents, because the
moves are working-tree changes that have not been committed. The final verification run only became
clean after applying the 72 pending deletions on top. In other words: committing the deletions is
necessary but *not sufficient*, because the files remain in the commits behind the deletion.

The repository also carries baggage that has no public value:

- **146 commits** on the current branch and **69 local branches** (`Sprint2` … `Sprint35`,
  `phase8_ext_v3_not_wrking`, …), most of them abandoned work in progress.
- A **351 MB** loose-object store.

### Recommendation: publish as a fresh repository

Create the public repository from a **single initial commit of the cleaned working tree**, and keep
this repository private as the development history.

```bash
# from a clean export of the current working tree, after the checklist below
git init
git add .
git commit -m "Initial public release"
git remote add origin git@github.com:yasseennandally/<public-repo>.git
git push -u origin main
```

Why this rather than `git filter-repo`:

- It needs **no history rewrite** and no force-push to an existing remote.
- It is **provably clean** — the published tree is exactly what was reviewed, with nothing older to
  audit. A filter-repo pass requires re-auditing the rewritten history to prove the removal worked.
- Nobody benefits from 69 sprint branches. Contributors want current code.
- The full history stays available to the owner privately.

The cost is losing public attribution for past commits. For a single-author project where the
history is sprint branches rather than a community record, that is a small price.

**If history must be preserved**, then before publishing, run `git filter-repo --invert-paths` over
every path in section 5 plus `--replace-text` for the Cloud Run hostname, delete the obsolete
branches, re-run a secret scan over the rewritten history, and verify the documents are gone with
`git log --all -- <path>`. This is the longer, riskier route.

---

## 7. Dependency licence audit

Licences were read from installed package metadata (`*.dist-info/METADATA`, `License-Expression`,
classifiers, and the `LICENSE`/`NOTICE` files beside them), not from memory. Full detail and
attribution text: [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

**Nothing forces this project off MIT.** No GPL, AGPL, SSPL, EUPL, Elastic or MongoDB licence
appears in the Python, Go or JavaScript dependency graph of the shipped application.

| Licence | Count | Obligation |
|---|---|---|
| MIT / MIT-0 / MIT-CMU | ~60 | Retain notice |
| BSD 2-/3-Clause | ~20 | Retain notice |
| Apache-2.0 | ~50 | Retain notice; reproduce `NOTICE` files from 9 packages |
| PSF | 4 | Permissive |
| **LGPL-3.0-or-later** | **2** | `psycopg2-binary`, `PyGithub` |
| **MPL-2.0** | **1 runtime** | `certifi` (via `requests`) |
| SIL OFL-1.1 | 3 font families | Attribution — **was incomplete, now fixed** |

### Copyleft, assessed

- **`psycopg2-binary`** (LGPL-3.0-or-later with an OpenSSL exception) and **`PyGithub`**
  (LGPL-3.0-or-later) are used unmodified, imported normally, installed from PyPI. That satisfies
  the LGPL; neither makes this project's code copyleft. Both are now named in
  `THIRD_PARTY_NOTICES.md` with their licence and upstream source, which is the obligation. A
  permissive alternative to psycopg2 exists if wanted: `pg8000` (BSD-3-Clause, pure Python) is
  already a transitive dependency.
- **`certifi`** (MPL-2.0) is file-level copyleft, used unmodified. No obligation attaches.
- **`axe-core`** (MPL-2.0) is in the git-ignored `.tools/` dev tree and never shipped.

### Flagged for a decision

| Item | Issue |
|---|---|
| **Terraform 1.9.8 in `backend/Dockerfile`** | **BUSL-1.1 — not an open-source licence.** The Dockerfile downloads and installs it, so every published image redistributes it, without its licence text. Terraform ≥ 1.6 is BUSL and 1.9.8 stays so until ~late 2028. The product also invokes it at runtime. **Fix:** switch to OpenTofu (MPL-2.0, drop-in fork), pin 1.5.7 (last MPL release), or make it operator-supplied. This is the one genuine licence blocker. |
| **`redis:7-alpine` floating tag** | Redis 7.0–7.2 was BSD-3-Clause; 7.4+ is dual RSALv2/SSPL ("source available"). Using the image imposes nothing on this project, but pin `7.2` or switch to Valkey (BSD-3-Clause) for a fully permissive stack. |
| **FFmpeg (GPL-3.0)** | Invoked as an external process by the demo-video scripts; not vendored, `.tools/` is ignored. No obligation, but **never commit the binaries.** |
| **`google-crc32c`** | Declares no licence in metadata; its bundled `LICENSE` is Apache-2.0. A scanner false positive, documented so it is not re-investigated. |

### Fixed during this review

- **Font attribution.** `backend/static/fonts/OFL.txt` carried only the Instrument Sans copyright
  while `archivo.woff2` and four `plex-*.woff2` files shipped alongside it unattributed. OFL-1.1 §2
  requires the notice for every font redistributed. All three notices are now present, with a note on
  the Reserved Font Name clause for the subsetted files. **This was the only unmet licence
  obligation found.**
- **Undeclared dependency.** `reportlab` is imported by `backend/routers/evidence.py` and
  the PDF export path but was missing from `requirements.txt`, so a clean install
  produced a venv where PDF export raised `ImportError` on first use. Added, pinned to 4.5.1
  (BSD-style licence, MIT-compatible).

### Bundled code and attribution

- **No bundled third-party JavaScript.** No minified library, no `vendor/` directory, and **no page
  loads a script or stylesheet from a CDN** — the console is genuinely self-hosted vanilla JS.
- **Vendored schemas** — the CycloneDX 1.6, JSF and SPDX JSON schemas in
  `backend/schemas/cyclonedx/` are Apache-2.0, vendored deliberately so CBOM conformance tests run
  offline. Now attributed.
- **No third-party copyright header exists anywhere in first-party source.** A repository-wide sweep
  for `Copyright`, `SPDX-License-Identifier`, `Permission is hereby granted`, `adapted from`,
  `based on https` and `stackoverflow` found hits only in bundled font and git-ignored tool licences.
  Nothing appears to be copied without attribution.
- **Originality notes added** to the three hand-written implementations, stating they were written
  from their specifications and are not derived from any existing library — and, where relevant, that
  the constant tables are specification data that any correct implementation necessarily reproduces:

  | What | File |
  |---|---|
  | QR encoder (ISO/IEC 18004) | `backend/services/qr_svg.py` |
  | SSRF guard | `backend/services/alert_routing.py` |
  | TLS ClientHello probe (RFC 8446) | `backend/scanner.py` |

- **Generated demo assets** — the music in `demo/video/` is produced by this project's own
  `make-*-music.py` scripts and the screenshots in `demo/tour/` are captures of this software. Both
  are stated as the project's own work in `THIRD_PARTY_NOTICES.md`.

---

## 8. First-run experience

Tested from a **fresh export of tracked files only**, in a temporary directory, with **no `.env`
present** and every relevant environment variable unset.

| Test | Result |
|---|---|
| Application imports with no configuration | **Pass** — 895 routes registered |
| Unconfigured server serves | **Pass** — `/status`, `/health`, `/health/deep`, `/`, `/ui/`, `/launch` all 200 |
| Falls back to SQLite without Postgres | **Pass** — `/status` reports `"database": {"type": "sqlite"}` |
| Explains what is missing rather than crashing | **Pass** — `/health/deep` names each missing setting and the variable that fixes it |
| Degrades without Redis/Celery | **Pass** — reported as `skipped (no broker URL)`; scans run in-process |
| `docker compose up --build` from a clean clone | **Pass, after one fix** — see below |
| `docker compose run --rm seed` | **Pass** — 38 assets, 8 scans of history, CBOM readable |

`/health/deep` on an unconfigured server returns exactly the right thing: the two deliberately
insecure local defaults (`PQC_AUTH_MODE=headers`, `PQC_DEFAULT_ROLE=admin`) and the unset
`SENTRY_DSN`, each naming the variable to change. That is a genuinely good first-run experience and
nothing needed changing.

### Bugs found and fixed

1. **`docker compose up` died in a restart loop before serving once.** `AUTO_MIGRATE=1` runs Alembic,
   and `alembic/env.py` falls back to the placeholder `postgresql://unused:unused@localhost/unused`
   in `alembic.ini` when no database URL is set. On a SQLite deployment it therefore tried to reach
   Postgres on `localhost:5432` and exited. Since SQLite needs no migrations (`db.init_db()` creates
   the schema at import), `backend/entrypoint.sh` now **skips Alembic with an explanatory message**
   when no database URL is configured, instead of failing. **This would have broken the quick start
   for every single newcomer.**
2. **The seeder failed on its first direct write.** It authenticated over HTTP, then raised
   `PQC_PRODUCT_DATABASE_URL is required for Postgres cutover` because the seed container inherited
   the Dockerfile's `PQC_MAIN_DB_BACKEND=postgres` default. Fixed in `docker-compose.yml`.
3. **The seeder assumed a repository-root layout.** The image contains only `backend/`, with no repo
   root above it. `demo/video/seed-demo-data.py` now honours `PQC_BACKEND_DIR`, `PQC_DEMO_EMAIL` and
   `PQC_DEMO_PASSWORD` so it works both from a checkout and inside a container.

### Test suite

Run from the clean export with no credentials and no services available:

```
1346 passed, 61 skipped, 0 failed  (28m32s)
```

The 61 skips are the correct behaviour: tests needing a real Postgres, Redis or third-party API skip
with a reason naming the variable that enables them (`PQC_TEST_PG_DSN`, `PQC_TEST_REDIS_URL`), rather
than failing. **No test needs a credential to pass**, which is the contract
`.github/workflows/tests.yml` depends on.

One tracked test was failing and is **fixed**:

- `test_load_regressions.py::TestLatestScanFactsIsOneQuery::test_it_is_a_single_statement` raised
  `sqlite3.ProgrammingError: Cannot operate on a closed database` in its own teardown. The test
  installs a trace callback, calls the code under test, then clears the callback in a `finally` — but
  the connection-lifetime work now closes the connection it is handed, so the handle was already
  closed. The assertion the test exists for had already passed; only the cleanup failed. The teardown
  now tolerates a closed connection, with a comment explaining why closed is the desired outcome.

### Lint

`ruff check .` — the command the CI lint job runs — **had 36 violations and was therefore red on
every commit**, signalling nothing. 32 were in tracked, unmodified files, so they were present in a
clean clone. All 32 are **fixed**; the published tree now reports `All checks passed!`.

| Rule | Count | Fix |
|---|---|---|
| `E741` ambiguous name `l` | 17 | Renamed to `label` in `services/platform_analytics.py`. All were dict-comprehension key variables holding a day label, so the scope was the comprehension and the rename is complete. Two were the key expression of a two-line comprehension and needed the preceding line as well. |
| `F401` unused import | 10 | Removed (`routers/invite_landing.py`, `services/analytics_snapshots.py`, `services/audit_queue.py`, `services/qday_forecast.py`, `test_invite_landing.py`, `test_postgres_rls.py`, `test_scan_pipeline_accuracy.py`) |
| `F811` fixture shadowing | 3 | `test_usage_rollups.py` imports the `api` fixture and then names it as a parameter, which is how a test requests a fixture. Marked `# noqa: F811` per line rather than per file, so a genuine redefinition is still caught. |
| `F841` unused local | 3 | `net = self` (dead), `c = Collector()` (built but never referenced — verified no use remains anywhere in `jobs()`), and an unused `as fix` binding. |
| `E731` lambda assignment | 1 | `test_platform_analytics.py` — converted to a `def`. |
| `F541` f-string without placeholder | 1 | `test_alert_routing.py` |

Behaviour was re-verified after the changes, not assumed: `test_platform_analytics.py`,
`test_usage_rollups.py`, `test_alert_routing.py` (77 passed), `test_invite_landing.py`,
`test_postgres_rls.py`, `test_scan_pipeline_accuracy.py` (59 passed, 23 skipped), and every trimmed
module re-imported cleanly.

The four remaining violations are in **untracked** files belonging to the concurrent AI-provider work
(`services/llm/custom.py`, `test_llm_providers.py`) and were deliberately left alone; that agent has
been told. Three are auto-fixable with `ruff check --fix`.

### Outstanding: an untracked test that will break CI when committed

`backend/test_production_launch_contract.py` is **untracked** — concurrent in-flight work, not part
of this review and not present in a clone, so it does not affect the published repository today.
Five of its parameterised cases fail:

```
test_strict_preflight_supports_ai_off_and_verified_redis_tls[change0..4]
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

Cause: the test writes its environment file to pytest's `tmp_path` (outside the repository), then
passes `os.path.relpath(target, ROOT)` to `scripts/prod-preflight.ps1` — a long `..` traversal out
of the repository root. The script produces nothing on stdout and `json.loads("")` raises. The
comment above the call says "the preflight accepts paths relative to the repository root", which is
true but incompatible with a temp directory outside it.

**This needs attention before the file is committed, for two reasons:**

1. Its guard is `@pytest.mark.skipif(not SHELL, ...)` where `SHELL` is `pwsh` or `powershell`.
   **GitHub's `ubuntu-latest` runners ship PowerShell**, so the guard will *not* skip in CI — it will
   run the PowerShell launch scripts and fail.
2. It is owned by whoever is writing the production-launch contract work, so this review deliberately
   did not change it.

Either fix the path handling (write the env file inside the repository tree, or teach the script to
accept an absolute path) or tighten the guard so it skips unless explicitly enabled.

### The seeded workspace is reproducible, not shipped

`demo/video/demo.db` is now git-ignored. The workspace is built by
`demo/video/seed-demo-data.py`, which generates every row through the platform's own evaluation
pipeline (`policy.evaluate_policies` → `derive_risk_and_score` → `derive_pqc_relevance` →
`derive_quantum_readiness`) and posts it through the API, so the dashboards are internally consistent
rather than hand-written numbers. The company (`Example Financial Group`), every hostname
(`*.example.com`, `*.internal.example`) and every certificate issuer are invented.

---

## 9. Files added

| File | Purpose |
|---|---|
| `LICENSE` | MIT, © 2026 Yasseen Nandally |
| `README.md` | Rewritten for a stranger: the HNDL problem, the 2030/2035 deadlines, what it does, screenshots, a verified quick start, architecture and diagram, tests, AI providers, security posture, honest scope limits |
| `CONTRIBUTING.md` | Setup, tests, house style, adding a scanner check, adding an AI adapter, PR expectations |
| `SECURITY.md` | Rewritten: private reporting, response times, scope — including an explicit out-of-scope list so the documented-insecure local defaults are not reported as bugs — and known gaps |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1 |
| `THIRD_PARTY_NOTICES.md` | Dependency licences, Apache `NOTICE` obligations, LGPL/MPL notices, font attribution, dual-licence elections, originality statement |
| `.env.example` | Every setting a newcomer needs, grouped and commented, no real values |
| `docker-compose.yml` | Zero-configuration quick start, plus the optional seed service |
| `docs/SECURITY_REVIEW_SUMMARY.md` | Public summary of the September 2026 review |
| `docs/OPEN_SOURCE_READINESS.md` | This document |
| `.github/workflows/tests.yml` | Tests + lint + quick-start verification, passing with no secrets |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Bug template, routing security reports away from public issues |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Feature template |
| `.github/ISSUE_TEMPLATE/config.yml` | Links to private vulnerability reporting and docs |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist reflecting the house style |

### Files changed

| File | Change |
|---|---|
| `.gitignore` | Closed the ~290 MB gap: WAV masters, `demo.db`, `raw/*.webm`, tour audio |
| `backend/entrypoint.sh` | Skip Alembic when no database URL is set, instead of crashing |
| `backend/requirements.txt` | Added the missing `reportlab` pin |
| `backend/static/fonts/OFL.txt` | Added the Archivo and IBM Plex copyright notices |
| `backend/services/qr_svg.py`, `backend/services/alert_routing.py`, `backend/scanner.py` | Originality / provenance notes |
| `demo/video/seed-demo-data.py` | Overridable backend path and demo credentials |
| `docs/COMPLETE_DOCUMENTATION.md`, `TRY_IT_IN_THE_CLOUD.md`, `USER_GUIDE.md` | Live Cloud Run hostname → `YOUR_DEPLOYED_HOST` |
| `docs/CUSTOMER_DATA_CONTROL.md`, `WEBSITE_GATEWAY.md`, `UI_REFRESH_2026-09-10.md`, `PRODUCTION_READINESS_CHECKLIST.md`, `AI_PROVIDERS.md` | Cross-references to moved documents rewritten |

### On `.env.example` vs `.env.prod.example`

These are now two deliberately different documents rather than overlapping appendices:

- **`.env.example`** (new, repository root) — the smallest thing that runs on a laptop. Every value
  optional, grouped by concern, each insecure local default explained. Opens by saying nothing is
  required because the server starts unconfigured.
- **`.env.prod.example`** (existing, 364 lines, unchanged) — the hardened production template:
  external SSO, managed Postgres and Redis, strict CSP, `REPLACE_WITH_*` for every secret.

Each now points at the other, so a reader is never in the wrong file. The AI section of
`.env.example` was reconciled against the provider-agnostic layer in `backend/services/llm/` and
uses its real variable names (`PQC_LLM_PROVIDER`, `PQC_LLM_API_KEY`, `PQC_LLM_BASE_URL`,
`PQC_LLM_DISABLED`, …) and its real provider ids (`anthropic`, `openai`, `azure-openai`, `gemini`,
`openai-compatible`, `ollama`, `builtin`, `custom`), cross-referenced to `docs/AI_PROVIDERS.md`.

---

## 10. Go/no-go checklist

### Must do before publishing

- [ ] **Decide the history question** (section 6). Publish from a fresh initial commit —
      recommended — or run `git filter-repo` over the section 5 paths and the Cloud Run hostname,
      then re-audit. **Publishing the existing history as-is exposes all 26 internal documents.**
- [ ] **Resolve Terraform BUSL-1.1** in `backend/Dockerfile`: OpenTofu, pin 1.5.7, or make it
      operator-supplied. Until then every published image redistributes a non-open-source binary
      without its licence text.
- [ ] **Move `../pqc-scanner-private/` into a private repository** so it is backed up rather than
      sitting in a sibling directory.
- [ ] **Rotate any credential** that has ever been in a local `.env`, a screenshot, a terminal or a
      chat window. The scan proves nothing leaked *via git*; it cannot prove anything else.
- [ ] **Fix or guard `backend/test_production_launch_contract.py`** before committing it — five cases
      fail on a path bug and its skip guard will not save CI, because GitHub's Ubuntu runners have
      PowerShell. See [section 8](#outstanding-an-untracked-test-that-will-break-ci-when-committed).
      Owned by the production-launch work, not this review.

### Before the public OSINT mode launches — a separate gate

Not blockers for the open-source release. These block the *public scanning service*, which should be
launched separately. Full reasoning in [section 11](#11-planned-public-osint-mode).

- [ ] Terms of use that bind on use, with no signup step, linked from the form itself
- [ ] An acceptable-use policy prohibiting submission of domains the user does not own
- [ ] A published abuse-reporting address, a stated response time, and an honoured opt-out blocklist
- [ ] A privacy notice covering the submitter's IP and the scanned party's certificate data
- [ ] A public page identifying the scanner and explaining how to opt out, as Censys and Shodan do
- [ ] Per-**target** rate limiting and result caching, so the service cannot be used for reflection
- [ ] An anonymous rate-limit bucket (today's limits are keyed per organisation)
- [ ] SSRF guard reused on the user-supplied target, with cloud metadata addresses explicitly refused
- [ ] A code-level allowlist restricting the public path to remote-observable checks only
- [ ] `docs/THREAT_MODEL.md` extended to cover an unauthenticated hostile caller
- [ ] Public results that state what could not be observed (a CDN's posture is not the origin's)

### Should do

- [ ] Upload the demo videos as GitHub release assets and link them from the README (section 4).
- [ ] Enable **GitHub private vulnerability reporting** in Settings → Security, since `SECURITY.md`
      and the issue-template config both point at it.
- [ ] Enable branch protection on `main`: require the `Tests` workflow, require a pull request.
- [ ] Enable Dependabot alerts and security updates.
- [ ] Pin `bandit` and `pip-audit` in `.github/workflows/security.yml` — currently unpinned, so a new
      release can turn a green build red with no commit.
- [ ] Set the repository description, topics (`post-quantum-cryptography`, `pqc`, `cbom`,
      `cryptography`, `security`, `fastapi`) and social preview image.
- [ ] Run `go-licenses report ./...` in `gateway/` to confirm the Go licences from metadata rather
      than knowledge, since that module graph is statically linked into a distributed binary.
- [ ] Pin `redis:7-alpine` to `7.2`, or move to Valkey, if a fully permissive stack matters.
- [ ] Tag an initial release (`v1.0.0`) so `CHANGELOG.md`'s `[Unreleased]` has a floor.

### Could do

- [ ] Add `SPDX-License-Identifier: MIT` headers to first-party source so any future third-party
      addition stands out to tooling.
- [ ] Generate a full machine-produced licence manifest with
      `pip-licenses --with-license-file --with-notice-file` and `COPY` it into the Docker image.
- [ ] Close the three open security items and fold the full review back into the public repository.
- [ ] Consider trimming the 69 stale branches in the private repository too.

### Verified — no action needed

- [x] No secret in any blob of any commit on any ref; `backend/.env` never tracked
- [x] No real email address, customer name, or IP outside documentation ranges
- [x] Live Cloud Run hostname removed from the working tree
- [x] No large binary tracked; `.gitignore` closes the ~290 MB gap
- [x] `LICENSE` present: MIT, © 2026 Yasseen Nandally
- [x] No dependency forces the project off MIT; no GPL/AGPL/SSPL anywhere
- [x] The one unmet licence obligation (font attribution) is fixed
- [x] No third-party code appears to be copied without attribution; originality notes added
- [x] A clean clone starts, serves, and explains what is missing without crashing
- [x] `docker compose up` works from a clean clone with no `.env`, and the seed step works
- [x] The seeded workspace is reproducible from a script, not shipped as a binary database
- [x] Community health files, issue and PR templates in place
- [x] A CI workflow runs tests, lint and the quick start with no secrets
- [x] `ruff check .` passes on the published tree (32 pre-existing violations fixed)
- [x] Test suite green with no credentials: 1346 passed, 61 skipped, 0 failed
- [x] Re-verified end to end on the final published tree: lint clean, unconfigured server
      serves, `docker compose up --build --wait` reaches healthy, `run --rm seed` completes,
      and the seeded estate reads back through `/organizations`, `/assets` and `/cbom`

---

## 11. Planned public OSINT mode

The owner intends to add a **free public readiness check**: a stranger enters a domain name and gets
its post-quantum posture back, with no account. **This review did not build it and nothing in the
repository implements it.** It is assessed here because it changes the project's public face and
carries obligations that must exist *before* launch, not after.

The README now lists it under *Planned* and explicitly says it is not available yet, so the
repository makes no claim it cannot support.

### Why this is a different risk class from everything else here

Every scanner in the platform today runs on behalf of an authenticated user against infrastructure
that user has asserted they own, inside a workspace with an audit trail. A public, unauthenticated
endpoint that takes an arbitrary hostname and connects to it inverts that: **the platform becomes a
service that makes network connections to third parties at an anonymous stranger's request.** That
is a scanning proxy, and it needs to be designed as one.

### What must exist before launch

#### Legal and policy — none of this exists yet

| Requirement | Why |
|---|---|
| **Terms of use covering unauthenticated use** | The current terms assume an account and an accepted agreement. A public endpoint has no signup step, so the terms must bind on use and be linked from the form itself. |
| **Acceptable-use policy** | Must state plainly that submitting a domain you do not own or have permission to test is prohibited, and that the service is not to be used for reconnaissance against third parties. This is the document that distinguishes a readiness tool from an attack tool. |
| **Abuse-reporting route and an opt-out** | A domain owner must be able to report misuse and request exclusion, with a published address and a stated response time. A blocklist of excluded domains has to be honoured by the scanner. `SECURITY.md` covers vulnerabilities in the software; this is a different channel for misuse *of* the service. |
| **Privacy notice for non-users** | Two sets of personal data arrive without consent: the submitter's IP address, and whatever the scanned domain's certificate reveals (often an organisation name and administrative contact). State what is logged, the retention period and the lawful basis. If results are shareable by URL, say so — it makes the scanned party's security posture publicly linkable, which is the part a domain owner will object to. |
| **A published scanner identity** | Recipients see connections from the platform's addresses and will want to know what they are. Censys and Shodan both publish a page explaining their scanning and how to opt out; the same is expected here. Without it the egress addresses get blocklisted. |
| **A stated scope limit** | Commit publicly to performing only the connection a normal client makes — a TLS handshake on the stated port — and to not probing other ports or paths. A TLS handshake on 443 is what every browser does; a port sweep is not, and in several jurisdictions unauthorised scanning is a criminal matter rather than a terms question. |

#### Technical — the abuse surface

| Requirement | Why |
|---|---|
| **This is the project's largest SSRF surface** | The existing guard in `backend/services/alert_routing.py` protects *outbound webhooks* and assumes the URL came from an authenticated operator. A public endpoint takes the target from an anonymous request, which is the textbook SSRF entry point. It must reuse that guard, not reimplement it: resolve first, refuse any non-public address, unwrap IPv4-mapped and 6to4 forms, and pin the connection to the address that was checked. **Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`) are the specific thing an attacker will try**, along with internal hostnames that resolve to RFC 1918 space from inside the deployment's network. |
| **Per-target rate limiting, not just per-source** | Without it the service is a free reflection and amplification tool: an attacker submits one victim repeatedly and the platform generates the traffic. Per-source limiting alone does not prevent this when the sources are distributed. Cap connections per target domain per hour regardless of who asked. |
| **Result caching** | Serves the same answer for a repeated domain instead of re-scanning. Cheaper, and it removes most of the amplification value in one step. |
| **Anonymous-path rate limiting** | Rate limits today are keyed per organisation and per IP and are Redis-backed. An unauthenticated caller has no organisation, so the anonymous path needs its own bucket — and, because the limits live in Redis, a multi-replica deployment without it allows N times the limit. |
| **Strict scope enforcement in code** | The public path must reach only the remote-observable checks: TLS handshake, certificate chain, and optionally DNS. The repository, cloud-posture and credentialed scanners must be unreachable from it. Enforce this with an allowlist of permitted check types, not by omitting a link in the UI. |
| **No workspace creation, no persistence of third-party data** | A public check should not create a tenant or write the scanned party's details into the estate tables. Decide the retention story before the schema makes it for you. |
| **Cost control** | Unauthenticated compute is an unbounded bill. Caching, a request cap and a circuit breaker are the difference between a demo and an incident. |
| **Egress isolation** | Scans should leave from an address range that is not the API's own, so a blocklisting of the scanner does not take the product offline with it. |

#### Documentation and presentation

- The public check becomes the **landing page**, so the landing page becomes the product. The claims
  on it must match what the scanner actually measures — the honesty rules in `CONTRIBUTING.md` apply
  most strictly where the most people will read them.
- A public result must carry its own confidence and say what it could *not* observe. A domain behind
  a CDN shows the CDN's posture, not the origin's, and a result that does not say so is misleading.
  `docs/SCANNER_ACCURACY_AUDIT.md` already documents where the scanner is wrong; the public mode
  needs the user-facing version of that.
- The threat model in `docs/THREAT_MODEL.md` needs a section for an unauthenticated, hostile caller.
  It currently assumes an authenticated tenant.

### Recommendation

Publish the repository **before** building this, not after. Nothing in the OSINT mode blocks the
open-source release, and the release does not depend on it. But launching a public scanning service
needs the terms, the acceptable-use policy, the abuse route and the per-target limits **in place on
day one** — the failure mode is that the service becomes someone's reconnaissance tool, or a
reflection vector, and the resulting reputation damage lands on the project and the owner personally.
It is a separate launch with a separate checklist, and it should get one.

---

## Appendix: what packaging metadata exists

There is **no `pyproject.toml`, `setup.py`, `Cargo.toml` or published package** — the project is
deployed as a container and a service, not distributed as a library, so there is no packaging
metadata needing a `license` field. `LICENSE` at the repository root is therefore the complete
licence declaration for the Python side.

Two manifests do carry a licence field:

- `gateway/go.mod` — Go modules have no licence field; the root `LICENSE` governs.
- `.tools/video/package.json` — declares `"license": "ISC"` with an empty `"author"`, an `npm init`
  default. It is git-ignored dev tooling so it is not published, but if `.tools/` is ever tracked
  this should be corrected to `MIT` or the file excluded.

If the backend is ever packaged for PyPI, add to `pyproject.toml`:

```toml
[project]
license = "MIT"
license-files = ["LICENSE"]
authors = [{ name = "Yasseen Nandally" }]
```
