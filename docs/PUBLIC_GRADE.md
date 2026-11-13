# Public quantum-readiness grade

One letter, A to F, for a public HTTPS endpoint, answering a single question: **is traffic to this
site protected against "harvest now, decrypt later"?** That means recording encrypted traffic today
and decrypting it once a cryptographically relevant quantum computer (CRQC) exists.

- Code: `backend/services/public_grade.py` (probe, rubric, storage, CLI) and
  `backend/routers/public_grade.py` (HTTP surface and CORS).
- Tests: `backend/test_public_grade.py` and `backend/test_public_instrument.py`. None of them use
  the network.
- Rubric version: `2026-11.1`. The JSON field `rubric_version` carries it, and a cached result from
  an older rubric is never served as current.

It is separate from the organisation scanner. It runs no org scan, reads and writes no
organisation's data, and leaves `MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS` alone: that setting governs
the real scanner. It stores results in its own table (`public_grade_checks`) and appends to the
shared abuse log (`public_check_log`, outcomes prefixed `grade_`).

## API

Base URL: `https://morrow.soqlab.com/api/public`. No authentication. GET only.

| Route | What it returns |
|---|---|
| `GET /grade/{domain}` | The graded result as JSON. `?fresh=1` forces a re-check and has a stricter limit. |
| `GET /grade/{domain}.txt` | The same result as about 15 plain lines, for `curl`. No ANSI codes. |
| `GET /badge/{domain}.svg` | A shields-style badge reading "quantum-ready \| A". The grade appears as text, so the badge does not rely on colour alone. Cached for 3 h. A grey "?" badge is cached for 5 min. |
| `GET /stats` | Aggregate counts only: `public_checks_total`, `public_checks_7d`, `domains_checked`, `pq_share_7d`, `grades_7d`, `generated_at`. |
| `GET /history/{domain}` | Up to 30 stored checks, newest first: `[{scanned_at, grade, group, post_quantum}]`. |

Errors use the body `{"error": str, "detail": str}`:

| Status | When |
|---|---|
| 400 `invalid_domain` | The input is not a bare public hostname. |
| 403 `refused_target` / `refused_optout` | A non-public address, this server's own address, or an opted-out domain. |
| 429 `rate_limited` / `busy` | A rate limit or the concurrency cap. The response carries `Retry-After`. |
| 503 `disabled` | The feature is switched off. |
| 504 `unresolvable` / `unreachable` | No DNS answer, or nothing accepted a connection on 443 in time. |

Besides the fields in the contract, a result also carries `tls.untested`, `key_exchange.observed`,
`certificate.verified`, `platform`, `reasons`, `connections` and `notes`.

CORS: only the origins in `MORROW_PUBLIC_API_CORS_ORIGINS` (default `https://soqlab.com`,
`https://www.soqlab.com`, `http://localhost:3100`) are allowed, for GET and HEAD, never with
credentials. This is handled by `PublicApiCorsMiddleware` on `/api/public` only, outside the
application-wide CORS middleware, which allows credentials for the console's own origins.

## Rubric (2026-11.1)

The checks run in this order, and the first one that matches decides the grade:

| Grade | Condition |
|---|---|
| **F** | No TLS on 443. Or the certificate does not verify against the public web PKI (Mozilla roots via certifi) or has expired. Or a modern client is given a key exchange without forward secrecy (static RSA key transport chosen for a default client). |
| **A** | Post-quantum key exchange (for example X25519MLKEM768) is chosen when the server is offered post-quantum and classical groups together, TLS 1.3 is used, TLS 1.0 and 1.1 are disabled, and none of the B weaknesses apply. |
| **B** | Post-quantum key exchange, but a weakness remains. The weakness is one of: TLS 1.0/1.1 enabled; weak suites accepted; RSA key transport accepted as a fallback; or a certificate that expires in under 14 days. |
| **E** | No post-quantum key exchange, plus legacy settings: TLS 1.0/1.1 enabled without TLS 1.3, or weak suites accepted. |
| **C** | TLS 1.3 with forward-secret classical key exchange only. Traffic recorded today is at risk. |
| **D** | TLS 1.2 at most, with forward-secret (EC)DHE. |

"Weak suites" means 3DES, RC4, DES, NULL, EXPORT, MD5 and anonymous suites. ECDHE suites in CBC
mode with SHA-1 do not count as weak here: they are dated but not broken, and nearly every large
site still offers them to old clients.

### Refinements to the brief, and why

1. **Accepting RSA key transport is not an automatic F.** The brief listed "RSA key transport
   accepted" under F. The first live run showed that google.com, cloudflare.com and example.com all
   still accept `AES128-GCM-SHA256` (static RSA) as a fallback for old clients, while every modern
   client gets X25519MLKEM768. Grading them F would say their traffic has no forward secrecy, and
   that is false for every browser in use. The rule now has two parts:
   - F applies when the server gives a **default modern client** a key exchange without forward
     secrecy.
   - Accepting static RSA only as a fallback is a weakness. It is listed in `reasons`. Under
     post-quantum key exchange it caps the grade at B. Under classical key exchange it stays a C or
     D with the weakness stated.

   SSL Labs makes the same distinction.
2. **Under post-quantum key exchange, weak suites cap the grade at B, not E.** The brief listed
   "weak TLS 1.2 ciphers" under both B and E. The rubric resolves this as written for B. E is
   therefore the legacy grade for sites without post-quantum key exchange.
3. **A classical TLS 1.3 site with TLS 1.0/1.1 still enabled is a C, not an E.** This follows the
   brief: E is "TLS 1.0/1.1 with no TLS 1.3". The legacy versions are listed in `reasons` and the
   fixes.
4. **Pure ML-KEM (no classical half) counts as post-quantum**, with `hybrid: false`. The probe
   offers only hybrids alongside classical groups, so in practice an A always means hybrid.
5. **If the key-exchange group cannot be read** (the probe failed), the site is graded as
   classical, and `key_exchange.observed: false` says so. The checker never assumes post-quantum
   key exchange.

The certificate's signature algorithm is **never penalised**. Browsers cannot use ML-DSA
certificates yet. A signature also only has to resist forgery while the connection is live, so a
recorded session is not exposed through it. The cryptographer summary says this explicitly.

### "Expiry date for secrets": the decrypt-year range

When key exchange is not post-quantum, `exposure` gives `decrypt_year_low: 2035` and
`decrypt_year_high: 2040`.

The source is the **Global Risk Institute, *Quantum Threat Timeline Report 2025***, by Michele
Mosca and Marco Piani (evolutionQ), published 9 March 2026. It surveyed 26 experts in 2025:
<https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/>.

- The experts put the chance of a CRQC, meaning a quantum computer that can break RSA-2048 within
  24 hours, at **28-49% within 10 years** ("quite possible").
- They put it at **51-70% within 15 years** ("likely").

Counted from the 2025 survey, that is 2035 to 2040. These are expert-survey probabilities, not a
prediction, and the `basis` string says so. When a new edition is published, update
`DECRYPT_YEAR_LOW/HIGH`, `EXPOSURE_BASIS` and `RUBRIC_VERSION` together.

When key exchange is post-quantum, `recorded_traffic_at_risk` is false, both years are null, and
the source is NIST FIPS 203.

## Fixes

Each fix has the fields `{id, title, applies_to, snippet, notes, requires}`.

The platform is identified from the `Server` header plus CDN headers such as `cf-ray` and
`x-amz-cf-id`. The response's `server_software` field is the raw `Server` header, or null when the
site sends none. When the platform is unknown, the fixes for every server are returned.

| Platform | Change | Requires |
|---|---|---|
| nginx | `ssl_protocols TLSv1.2 TLSv1.3;` and `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;` | nginx built against OpenSSL 3.5+. On 3.5, the default `auto` already includes X25519MLKEM768. |
| Apache httpd | `SSLProtocol -all +TLSv1.2 +TLSv1.3` and `SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp256r1:secp384r1` | mod_ssl 2.4.8+ on OpenSSL 3.5+ |
| Caddy | The defaults already include it. The explicit form is `tls { protocols tls1.2 tls1.3; curves x25519mlkem768 x25519 secp256r1 }` | Caddy 2.10+ (Go 1.24) |
| HAProxy | `ssl-default-bind-options ssl-min-ver TLSv1.2` and `ssl-default-bind-curves X25519MLKEM768:X25519:P-256:P-384` | Linked against OpenSSL 3.5+ or AWS-LC (check `haproxy -vv`) |
| IIS (Schannel) | `Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0`, plus the Schannel registry keys that disable TLS 1.0/1.1 | Windows Server 2025 with KB5099536 (July 2026). Not possible on 2022 or earlier, which is stated honestly; the only route there is a proxy or CDN. |
| Cloudflare | Set Minimum TLS Version to 1.2 (dashboard or the `min_tls_version` API). The edge already negotiates X25519MLKEM768. | The proxy (orange cloud) enabled for the hostname |
| Other CDN | A provider setting, not an origin change. Check the provider's TLS docs. | — |

These were checked against:

- nginx `ngx_http_ssl_module` documentation
- Caddy `tls` directive documentation
- Microsoft's "Windows TLS 1.3 and Post Quantum Crypto FAQ"
- Apache mod_ssl `SSLOpenSSLConfCmd`
- the HAProxy configuration manual and HAProxy's post-quantum blog post

HAProxy notes that stock builds may lack the hybrid groups, which is why `requires` points at
`haproxy -vv`.

## What one check contacts

All traffic goes to one hostname, on one address resolved once and pinned, on port 443. A check
makes about 11 short connections, at most 6 in parallel:

1. A verified handshake. If it fails, a verified legacy handshake, or an unverified one to read the
   certificate.
2. One handshake each pinned to TLS 1.2, 1.1 and 1.0.
3. The existing ClientHello probe, offering the hybrid groups first, followed by one probe per
   standardised hybrid group.
4. One TLS ≤1.2 handshake offering only RSA key transport.
5. One offering only weak suites.
6. One `HEAD /` that reads at most 8 KB of headers and follows nothing.

A typical check takes 3-4 seconds. The connection timeout defaults to 5 s, and the whole check is
cut off after 25 s.

## Safety

- **Input.** A bare hostname only: no scheme, port, path, query or userinfo. Names are
  IDNA-normalised, lowercased, have any trailing dot stripped, and may be at most 253 characters.
  IP literals are refused.
- **SSRF.** The name is resolved once. It is refused if *any* answer is private, loopback,
  link-local, CGNAT (100.64/10), multicast, reserved or unspecified. IPv4-mapped, 6to4 and NAT64
  addresses are unwrapped before the check, and this server's own addresses are refused too. That
  last list is the hostname's addresses plus `MORROW_PUBLIC_GRADE_SELF_ADDRESSES`.
  - The check is `alert_routing.ip_is_public` plus `public_grade.refusal_reason`.
  - Every connection then goes to that one IP, with SNI set to the hostname, so DNS rebinding has
    no second lookup to exploit.
  - The public-check opt-out list (table plus `MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS`) is honoured
    before resolution.
- **Budgets.** These run through `services/org_rate_limits.py`, which is backed by Redis when
  configured, so all replicas share them:

  | Budget | Limit |
  |---|---|
  | Per client IP | 10/min |
  | `fresh=1` per IP | 3/min |
  | Per domain | 12 checks/h, half that for fresh |
  | Global | 600 checks/h |

  There is also a per-process concurrency cap of 4. When it is full, the API answers 429 after
  waiting 3 s. A per-domain lock stops two simultaneous cache misses from probing twice, and the
  per-domain cache lasts 1 h.

## Storage

The table is `public_grade_checks`:

| Column | Notes |
|---|---|
| `id` | |
| `domain` | |
| `scanned_at` | |
| `grade` | |
| `key_exchange_group` | Named this way, not `group`, which is an SQL reserved word. |
| `post_quantum` | |
| `rubric_version` | |
| `result_json` | |

There is no organisation column. The table lives in the feature store and is created by
`public_grade.init_tables()`, registered as the deferred schema `public_grade` next to
`public_check`. That is the same mechanism as the `public_check_*` tables, so it works on SQLite and
on Postgres. It is not an Alembic revision: the Alembic chain covers the product database, not the
feature store.

## Command line (league tables, CI)

Run from `backend/`. It needs no database:

```
python -m services.public_grade --batch domains.txt --out results.jsonl --concurrency 32 --timeout 8
python -m services.public_grade example.com          # one domain, text form
python -m services.public_grade example.com --json   # one domain, JSON
```

- **Input** (`domains.txt`): one domain per line. `#` comments and blank lines are ignored, and in
  `rank,domain` lines (the Tranco format) the last field is used.
- **Output**: one contract object per line. A failure is written as
  `{"domain", "scanned_at", "error", "detail"}`.
- **Resuming**: domains already present in `--out` are skipped, and each result is appended and
  flushed as it finishes. The same SSRF guard applies, and opt-outs are read from the environment
  only.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `MORROW_PUBLIC_GRADE_ENABLED` | 1 | Master switch for the API |
| `MORROW_PUBLIC_GRADE_CACHE_SECONDS` | 3600 | Per-domain cache |
| `MORROW_PUBLIC_GRADE_IP_PER_MINUTE` | 10 | Requests per IP per minute |
| `MORROW_PUBLIC_GRADE_FRESH_PER_MINUTE` | 3 | `fresh=1` requests per IP per minute |
| `MORROW_PUBLIC_GRADE_DOMAIN_PER_HOUR` | 12 | Checks of one domain per hour |
| `MORROW_PUBLIC_GRADE_GLOBAL_PER_HOUR` | 600 | Checks per hour, whole service |
| `MORROW_PUBLIC_GRADE_CONCURRENCY` | 4 | Checks running at once, per process |
| `MORROW_PUBLIC_GRADE_TIMEOUT` | 5 | Per-connection timeout (s) |
| `MORROW_PUBLIC_GRADE_DEADLINE` | 25 | Whole-check deadline (s) |
| `MORROW_PUBLIC_GRADE_SELF_ADDRESSES` | "" | Extra addresses that count as this server's own |
| `MORROW_PUBLIC_API_CORS_ORIGINS` | soqlab.com, www.soqlab.com, localhost:3100 | CORS origins for `/api/public` |
| `MORROW_GIT_COMMIT` | "" | The running commit for `/api/public/build`; else `RENDER_GIT_COMMIT`, `SOURCE_COMMIT`, `GIT_COMMIT` |
| `MORROW_LEAGUE_SCAN` | 1 | Celery beat runs the league tick every 15 minutes; `0` turns it off |
| `MORROW_LEAGUE_TICK_MAX` | 20 | Domains graded per league tick (1-100) |

## Evidence routes: basis, build, deploys, manifest, league, feeds

Also under `/api/public`, also unauthenticated, GET only, same CORS policy. Tests:
`backend/test_public_instrument.py` (no network).

| Route | What it returns |
|---|---|
| `GET /basis` | The decrypt years and their source, from `services/decrypt_window.py`: `{decrypt_year_low, decrypt_year_high, source_label, source_url, basis, pq_basis, pq_source_url}`. The public grade's `exposure` and the console's per-endpoint `decrypt_window` are built from the same module, so they never quote different dates. |
| `GET /build` | `{commit, commit_short, source, repository, commit_url, started_at, rubric_version, python}`. `commit` comes from the first set variable of `MORROW_GIT_COMMIT`, `RENDER_GIT_COMMIT`, `SOURCE_COMMIT`, `GIT_COMMIT` and must match `^[0-9a-f]{7,40}$`; otherwise it is `null` (and `source` names nothing). It is never guessed. |
| `GET /deploys?limit=50` | The deploy transparency log, newest first: `{entries: [{seq, commit, first_seen, prev_hash, entry_hash}], head_hash, chain_ok, count, genesis_hash, hash_rule}`. `chain_ok` is computed over every row on each request. |
| `GET /manifest` | The page file list (below). |
| `GET /league` | Sector averages and their weekly trend; no site is named (below). |
| `GET /history/{domain}?detail=1` | As `/history/{domain}`, each entry also carrying `rubric_version` and the full stored `result`. At most 100 entries. |
| `GET /history/{domain}.atom` | Atom feed (RFC 4287): one entry per grade change, newest first (the first check counts as a change). Entry ids are `urn:morrow:public-grade:<domain>:<scanned_at>`. An opted-out domain is refused with 403, as in the JSON form. |

### Deploy log

At startup (`_lifespan` in app.py, once per process) the server appends a row to
`public_deploy_log` when its commit differs from the newest row's commit. Same commit, or no known
commit: nothing is written. Rows are never updated or deleted. A rollback to an older commit is a
new row.

```
entry_hash = sha256( canonical_json({"commit", "first_seen", "prev_hash", "seq"}) )   # lowercase hex
canonical_json = sorted keys, separators (",", ":"), UTF-8, no ASCII escaping
seq starts at 1; the first prev_hash is 64 zeros ("genesis_hash")
```

Anyone can recompute this from the JSON: `scripts/verify-deploy.py` does, and so can a few lines
in any language. Keep a copy of `head_hash`: an operator who rewrote the whole table could produce
a new valid chain, but not one that still contains the head you saved. Two replicas that start
together both try to write the next `seq`; the primary key lets one win, and the other re-reads
and stops because its commit is then the newest row.

The commit only appears if the platform provides it. Render sets `RENDER_GIT_COMMIT` for
Git-backed services; for images built elsewhere set `MORROW_GIT_COMMIT` (for example from
`git rev-parse HEAD` at build time).

### Page file list

```
{"format": "morrow.page-files/v1", "commit": <sha or null>, "generated_at": <ISO>,
 "files": [{"path": "/ui/<name>", "sha256": <hex>, "bytes": <int>}, ...]}      # sorted by path
```

`files` is every regular file under `backend/static/` (fonts included; dotfiles and symlinks
skipped), hashed once per process. It is not signed (an ML-DSA-signed version was built and then
dropped by decision; the commit banner, this list, the deploy log and the no-tracking readout stay).
What it lets anyone check: the pages this server sends are the bytes of a public commit. It does not
prove that the Python code running is that commit: the list is produced by the running code.
Reproducible release images (docs/REPRODUCIBLE_BUILDS.md) are how that is checked. The /trust view
hashes the files it loaded itself, in the browser, and compares them with this list.

### verify-deploy.py

```
git fetch
python scripts/verify-deploy.py --url https://morrow.soqlab.com --repo .
```

It reads `/api/public/build`, `/api/public/manifest` and `/api/public/deploys`, then: every listed
file must equal `git show <commit>:backend/static/<file>` (sha256 and size), files in the commit
that are not listed are reported, and the deploy chain is recomputed (from genesis when the whole
log is returned) with the newest entry naming the running commit. Exit 0 verified, 1 a mismatch,
2 something could not be read. Standard library and git only.

### League

`backend/league/sectors.json` (ported from the soqlab.com league) defines eight sectors. The league
list is exactly the explicit `domains` of every sector, deduplicated: 829 domains when this was
written (`list_size` reports the live number, after opt-outs). A domain's sector is its exact entry
first, then a registry-reserved suffix rule (`.gov`, `.edu`, `.ac.<cc>`, `.nhs.uk` ...); anything
else is `unclassified`. Nothing is guessed from names or content.

`services/league.py` `tick(max_domains=20)` grades up to N domains whose newest attempt (a stored
grade under the current rubric, or a recorded miss) is older than 7 days, never-tried first. It
uses `public_grade.grade_one` (the same SSRF guard and timeouts) on at most 4 threads, skips
`public_check.opted_out` domains without contacting them, stores successes with
`public_grade.store` (so they appear in `/history`) and failures in `public_league_misses`. Each
tick is a row in `public_league_runs`. The Celery beat entry `league-tick-every-15m` runs it
(`MORROW_LEAGUE_SCAN=0` turns it off; `MORROW_LEAGUE_TICK_MAX` sets N). That is at most 80 domains
an hour and each domain at most once a week. Without a worker:

```
cd backend && python -m services.league --tick --max 20
python -m services.league --list      # the league list
```

`GET /league` publishes **sector averages only** (cached 60 s per process). No site is named or
ranked in public: naming and ranking organisations invites disputes that a readiness check does not
need, and any single domain can still be checked by anyone, on demand, at `/<domain>`. The old
parameters (`sector`, `q`, `sort`, `dir`, `limit`, `offset`) are accepted and ignored.

```
{"generated_at", "rubric_version", "list_size", "graded", "names_published": false,
 "sectors": [{"id", "name", "method", "sources", "count", "graded",
              "grades": {"A": n, ... "F": n}, "pq_share": <0..1, or null when nothing graded>,
              "trend": [{"week": "YYYY-MM-DD" (Monday), "graded", "grades", "pq_share"}]}],
 "last_run": {"started_at", "finished_at", "graded", "failed", "skipped"} | null}
```

`trend` gives, for each week with data (at most 26), the distribution of every listed site's latest
grade as of that week's end. Opted-out domains are left out of every count.

**Your own rank, privately.** `GET /instrument/rank` (signed in, any role; not public) returns, for
each domain the organisation has verified by DNS TXT (`services/domain_verification.py`), its newest
public grade, its sector by the same rules, and how many graded sites in that sector (all sectors
when it is unclassified) have a better, equal or worse grade. No other site is named.

### Post-quantum ready, by choice (opt-in list)

`GET /pq-ready?order=name|joined` and `GET /pq-ready.atom` publish the organisations that chose to
be listed. A domain can be listed only when its organisation verified it by DNS TXT, its newest
public grade is A or B, and an admin opted it in (`PUT /instrument/pq-ready/{domain}`
`{"listed": true|false}`, admin or owner; `GET /instrument/pq-ready` shows the organisation's own
verified domains, their state and, after a removal, why). Nothing is listed by default. Opting out
is immediate. The weekly league tick also re-grades every listed domain and then re-checks the list:
a grade below B, or a domain no longer verified, takes the entry off at once and the reason is kept
for the organisation's view. Entries are alphabetical or by date listed, never ranked. A domain
verified by two organisations appears once.

```
{"entries": [{"domain", "sector", "sector_name", "grade", "checked_at", "joined_at"}],
 "count", "order": "name"|"joined", "about"}
```

Storage: `pq_ready_listings (org_id, domain, listed, joined_at, removed_at, removed_reason, grade,
checked_at, updated_by)`, org-scoped and in the Postgres RLS plan. The public read and the weekly
re-check run in named `tenant_scope.platform_scope` blocks. Tests: `backend/test_pq_ready.py`.

### Not yet post-quantum (named list of popular sites)

`GET /not-ready?sector=` and `GET /not-ready.atom?sector=` (joins and leaves) publish popular sites
whose newest check is below B. Safeguards, all enforced in `services/not_ready.py` and tested in
`backend/test_not_ready.py`:

* **Who:** only domains from the stored Tranco list (`services/tranco.py`, top
  `MORROW_LEAGUE_TRANCO_SIZE`, default 10000, `0` turns it off; refreshed weekly from
  tranco-list.eu by the league tick). Never a domain typed into the checker, never an opted-out
  domain. A site leaves on its first check graded A or B.
* **Wording:** one measured sentence per entry with its date, e.g. `acme.com: traffic recorded
  today could be decrypted around 2035-2040 (checked 2026-11-13). Key exchange: x25519 only.`,
  plus the source of the years. No labels; a test holds every sentence to a list of banned words.
* **Order:** sector, then name. The grade is shown; entries are not ranked against each other.
* **Methodology** is in the response and on the page: rubric version, what is measured, who is
  included, and the source of 2035-2040.
* **Right of reply:** an admin of an organisation that verified the domain can attach one
  plain-text statement (at most 280 characters, control characters removed), shown dated with the
  entry: `PUT/DELETE /instrument/replies/{domain}`, audited. Table `not_ready_replies` is org-scoped
  and in the RLS plan; the public read runs in a named `platform_scope`.
* **Corrections:** `POST /corrections` `{domain, reason, contact}` stores a request in
  `public_correction_requests`, at most 5 an hour per address, and writes it to the checker's
  abuse log (`/platform/public-check/log`) for a person to read.

Coverage depends on the tick: 10,000 sites once a week need about 60 per 15-minute tick
(`MORROW_LEAGUE_TICK_MAX=60`); at the default 20, a full pass takes about three weeks.

New tables (feature store; deferred schemas `public_deploy_log`, `public_league`, `tranco`,
`not_ready` and `pq_ready`; the two org-scoped ones, `pq_ready_listings` and `not_ready_replies`,
are in the RLS plan; the rest have no organisation column): `public_deploy_log (seq, commit_sha, first_seen,
prev_hash, entry_hash)`, `public_league_misses (id, domain, scanned_at, error, detail)` and
`public_league_runs (id, started_at, finished_at, graded, failed, skipped)`.
