# The public post-quantum readiness checker

A free, no-account check at `/check`: anyone types a domain and gets a real
answer about that domain's public TLS endpoint in seconds, with a shareable
permalink and an export. It is the project's shop window, and it is the only
part of the platform that contacts a machine the requester may not own. That
makes the boundaries the most important thing in this document.

- **Code:** `backend/services/public_check.py` (the engine),
  `backend/routers/public_check.py` (the routes),
  `backend/static/check.html` / `check.css` / `check.js` (the page),
  `scripts/pqc-check.py` (the command line).
- **Tests:** `backend/test_public_checker.py`. No network: Certificate
  Transparency, the TLS handshake and DNS are each mocked at their boundary.
- **Tables:** `public_check_results`, `public_check_log`,
  `public_check_optouts`, `public_check_meta`. None of them carries an
  organization id, and a check never reads or writes tenant data.

---

## 1. What it does

### Passive first: Certificate Transparency

Public CT data for the domain, read from a CT search service. This touches
nothing belonging to the target: the certificates are already published in
append-only logs. It yields issuers, validity windows, the number of unexpired
certificates and, for a bounded number of logged certificates, the key type and
size.

Default provider is **crt.sh** (`?q=<domain>&output=json&deduplicate=Y&exclude=expired`).
Two things to know about it:

- Its JSON index does **not** carry the public key. Key type and size therefore
  cost one extra `?d=<id>` request per certificate, bounded by
  `PQC_PUBLIC_CHECK_CT_CERT_FETCH` (default 3, newest first, `0` disables).
- It publishes no rate limit, asks informally for about one request every five
  seconds, and its availability is unreliable. A throttle
  (`PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS`, default 5) and a short timeout
  are enforced in code, and **any** failure is reported as
  `status: "unavailable"` with the reason.

**CT being unavailable is never reported as "this domain has no certificates."**
That distinction is tested (`test_certificate_transparency_unavailable_never_becomes_no_certificates`).

A built-in alternative, **CertSpotter** (SSLMate), is available with
`PQC_PUBLIC_CHECK_CT_PROVIDER=certspotter`. It returns the certificate DER in
the same response, so key history costs no extra requests; unauthenticated use
is limited to a handful of queries an hour, which is why it is not the default.
Set `PQC_PUBLIC_CHECK_CT_TOKEN` to raise that.

### Then one light active check

A TLS handshake to the hostname on port 443, to see what it negotiates *now*:

| Observed | How |
| --- | --- |
| Protocol version, cipher suite, ALPN | the handshake |
| Certificate key type, size, curve | `scanner._leaf_cert_facts` on the leaf |
| Signature algorithm, issuer, subject, validity, days to expiry | same |
| Whether the certificate verifies against public roots | the handshake |
| Negotiated key-exchange group, including hybrid post-quantum | `scanner._probe_key_exchange_group` |

**Honest connection count: at most two, to one host, on one port.** The first is
an ordinary verified handshake — what a browser does. The second sends one
ClientHello that offers post-quantum groups and reads the ServerHello, because
a normal Python handshake cannot ask for them. Both are pinned to the one
address that passed the SSRF guard. The result reports
`observed.connections_made`.

Both reuse the scanner that already exists. Nothing here reimplements TLS
parsing, and the one change made to `backend/scanner.py` was to add an optional
`address=` argument to `_probe_key_exchange_group` so the caller can pin the
connection; the default keeps the internal scanner's behaviour unchanged.

### What it does not do

- No port scanning. One port, 443. **The port is not configurable** — a setting
  for it would turn this into the port prober the guardrails exist to prevent,
  and a test asserts no such setting exists.
- No subdomain discovery or enumeration.
- No vulnerability probing, no exploit attempts, no authentication attempts.
- No crawling, and no HTTP request to the target at all.
- No OCSP or CRL fetch, and no TLS-version or cipher-suite enumeration.
  `scanner.scan_host` does all of those; this module deliberately never calls
  it, and a test parses the AST to prove it.
- No second, unverified handshake when the certificate fails to verify. The
  internal scanner retries unverified because internal estates are full of
  private CAs; a public checker pointed at a stranger's host makes its
  connection and reports what it saw.

---

## 2. Routes and API

### Pages

| Route | Purpose |
| --- | --- |
| `GET /check` | the form; `?domain=` pre-fills it |
| `GET /check/{domain}` | 301 to `/r/{domain}`, the permanent record |
| `GET /r/{domain}` | the record: server-rendered, indexable, with the history of what changed |
| `GET /r/{domain}/at/{id}` | one past observation, immutable and citable |
| `GET /r/{domain}/badge.svg` | the embeddable badge |
| `GET /r/{domain}/export.json` | the JSON export, from the record rather than the cache |
| `GET /r/{domain}/cbom.json` | the CBOM, from the record rather than the cache |
| `GET /public-check/terms` | terms of use, which bind on use because there is no signup |
| `GET /public-check/acceptable-use` | the acceptable-use policy |
| `GET /public-check/privacy` | the privacy notice, for the requester and the checked party |
| `GET /abuse` | abuse reports and the opt-out |
| `GET /scanner` | scanner identity, for an operator reading their own logs |

The five documents are static pages in `_PUBLIC_INFO_PAGES` (so they are
auth-public, strict-CSP and cache-revalidated like the rest of the public set).
They are deliberately **not** under `/check/`, which reads its path segment as a
domain name and would take `/check/terms` for one. `/abuse` and `/scanner` are short and
top-level on purpose: they are what somebody types when they have a connection in
their logs and no link to follow. See §8.

### Public API (unauthenticated, rate limited)

| Route | Purpose |
| --- | --- |
| `GET /api/public-check/config` | the guardrails and their live values, the acceptable-use statement, the deadlines, the limits |
| `POST /api/public-check` `{domain, refresh?}` | **the only route that contacts anything** |
| `GET /api/public-check/{domain}` | the cached result only; 404 when there is none |
| `GET /api/public-check/{domain}/export.json` | the JSON export of a cached result |
| `GET /api/public-check/{domain}/cbom.json` | a CycloneDX 1.6 CBOM for the checked endpoint |

**A GET never starts a check.** A shared record, a crawler, a link preview, a
README badge or a smoke test reads stored data and nothing else. That is what
makes a record safe to share at any volume: no amount of link traffic, crawling
or badge rendering turns into connections to someone else's server. A record page
whose cache has expired still renders from the register, and offers a button
rather than re-checking by itself.

The badge deserves its own note, because it is embedded where its author cannot
see it fail: it carries no `Vary`, sets no cookie and needs no auth, since GitHub
serves README images through a proxy that would otherwise cache it wrongly or not
at all. An opted-out domain and a domain nobody has checked return the identical
neutral badge with a 200, so the image neither breaks the README nor announces
the opt-out.

These paths are exempt from the customer authentication gate
(`app._auth_public_path`) and from the per-organization rate limiter (they have
no organization), but **not** from the per-IP limiter and not from any of the
guardrails below. `/check` is also on the strict Content-Security-Policy list:
the page has no inline script, no inline event handler and no off-origin
request.

### Operator API (platform key or operator session)

| Route | Purpose |
| --- | --- |
| `GET /platform/public-check/log` | the check log, for investigating an abuse report |
| `GET /platform/public-check/opt-outs` | the opt-out list |
| `POST /platform/public-check/opt-outs` `{domain, reason}` | add a domain, and delete its cached result |
| `DELETE /platform/public-check/opt-outs/{domain}` | remove a domain |

The log names every domain that was checked, so it is never public.

---

## 3. The guardrails, and their defaults

Every one of these is enforced in code, not promised in documentation, and every
one is published by `GET /api/public-check/config` so the page states this
deployment's real values rather than a copy of this table.

| Setting | Default | What it does |
| --- | --- | --- |
| `PQC_PUBLIC_CHECK_ENABLED` | `1` | master switch. `0` keeps the page readable and answers 503 to a check |
| `PQC_PUBLIC_CHECK_CACHE_SECONDS` | `3600` | cache TTL per domain. **Floor of 600**, because serving the cache is what stops one visitor per check reaching the target |
| `PQC_PUBLIC_CHECK_IP_LIMIT` | `10` | checks per client IP per hour |
| `PQC_PUBLIC_CHECK_IP_BURST` | `3` | checks per client IP per minute |
| `PQC_PUBLIC_CHECK_DOMAIN_LIMIT` | `4` | checks per **target domain** per hour, whoever asks |
| `PQC_PUBLIC_CHECK_GLOBAL_LIMIT` | `240` | checks per hour for the whole service |
| `PQC_PUBLIC_CHECK_CONCURRENCY` | `4` | checks running at once |
| `PQC_PUBLIC_CHECK_MAX_QUEUE` | `32` | checks admitted but waiting; beyond this, 503 |
| `PQC_PUBLIC_CHECK_QUEUE_WAIT_SECONDS` | `5` | how long a check may wait for a slot before 503 |
| `PQC_PUBLIC_CHECK_DEADLINE_SECONDS` | `15` | whole-check deadline |
| `PQC_PUBLIC_CHECK_HANDSHAKE_TIMEOUT` | `6` | TLS socket timeout |
| `PQC_PUBLIC_CHECK_CT_ENABLED` | `1` | read Certificate Transparency at all |
| `PQC_PUBLIC_CHECK_CT_PROVIDER` | `crtsh` | `crtsh`, `certspotter` or `none` |
| `PQC_PUBLIC_CHECK_CT_TIMEOUT` | `6` | CT HTTP timeout |
| `PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS` | `5` | politeness throttle between outbound CT calls |
| `PQC_PUBLIC_CHECK_CT_MAX_CERTS` | `25` | CT entries summarised |
| `PQC_PUBLIC_CHECK_CT_CERT_FETCH` | `3` | CT certificates downloaded to read key type and size |
| `PQC_PUBLIC_CHECK_CT_TOKEN` | — | bearer token for CertSpotter |
| `PQC_PUBLIC_CHECK_OPTOUT_DOMAINS` | — | comma-separated, in addition to the table |
| `PQC_PUBLIC_CHECK_ABUSE_CONTACT` | — | shown on the page; falls back to `PQC_SUPPORT_EMAIL`, then `PQC_SECURITY_CONTACT_EMAIL` |
| `PQC_PUBLIC_CHECK_LOG_RETENTION_DAYS` | `30` | log rows older than this are pruned on write |
| `PQC_PUBLIC_CHECK_IP_SALT` | — | salt for the IP hash; generated once and stored if unset |
| `PQC_RATE_LIMIT_PUBLIC_CHECK` | `30/minute` | the per-IP slowapi limit on these routes, including cache reads |

### Rate limits

Three budgets, all through `services/org_rate_limits.py`, so they live in Redis
when `REDIS_URL` or `CELERY_BROKER_URL` is set and every API replica shares one
budget (without Redis, each process counts on its own and N replicas allow N
times the limit — say so in your own deployment notes if that matters):

1. **Per client IP** — a burst limit per minute and a budget per hour.
2. **Per target domain** — so the service cannot be used to hammer one host even
   from many addresses. The refusal says so explicitly.
3. **Globally** — an hourly ceiling for the whole service.

A 429 carries `Retry-After`. **A cache hit spends none of these budgets**, which
is the point: a popular domain is checked once per cache window, not once per
visitor.

### The cache

A result is stored per domain with an expiry and served from storage. The
permalink reads it. `refresh: true` (or `--fresh`) bypasses the cache but still
spends the per-domain budget, so it cannot be used to re-check one host
repeatedly. Expired rows older than seven days are pruned on write.

### Refusing targets that are not public internet hosts

Two layers.

**The hostname must be one public hostname.** `normalize_domain` accepts what a
person actually pastes (`https://Example.COM/path`, a trailing dot,
`example.com:443`) and refuses: empty input, whitespace, credentials before the
host, IP literals (v4 and v6, bracketed or not), wildcards, underscores, single-
label names such as `localhost`, labels over 63 characters, names over 253,
numeric TLDs, non-HTTP schemes, and any port other than 443. IDN is accepted and
IDNA-encoded.

**Every resolved address must be globally routable.** The guard is
`services/alert_routing.ip_is_public` and `resolve_host` — the same code that
stops an outbound webhook reaching inside the network, so there is one
definition of "public address" in the process rather than two that can drift.
Refused: private, loopback, link-local (including `169.254.169.254`), carrier-
grade NAT, reserved, multicast and unspecified ranges, in v4 and v6, with
IPv4-mapped (`::ffff:127.0.0.1`) and 6to4 forms unwrapped before the test. A
name that resolves to one public and one private address is refused outright,
because which one a later connect would pick is not something this code can
promise.

**The address that was checked is the address that is connected to.** Both
connections are pinned to it; TLS still verifies against the hostname and SNI
still carries the hostname, so pinning does not weaken certificate validation
and DNS rebinding cannot redirect the handshake inward.

### Opt-out

A domain owner writes to the published abuse address and their domain is
refused. The opt-out is checked **before DNS resolution** — an opted-out domain
is not resolved, let alone connected to — and it covers the domain and
everything under it (`example.com` covers `www.example.com`). Adding one deletes
the cached result for that domain and its subdomains.

Every read route refuses an opted-out domain too, not only the one that runs a
check: `GET /api/public-check/{domain}`, `export.json` and `cbom.json` all
consult the list. Deleting the cached row usually makes that moot, but a domain
added through `PQC_PUBLIC_CHECK_OPTOUT_DOMAINS` deletes nothing, and before this
guard existed a result cached before the opt-out stayed downloadable as JSON and
as a CBOM while the page beside it answered 403.

Two sources, both consulted: the `public_check_optouts` table (add through the
operator route or `scripts/pqc-check.py --opt-out`) and
`PQC_PUBLIC_CHECK_OPTOUT_DOMAINS`. If the table cannot be read, the configured
list still applies and the failure is logged loudly — a storage error must never
silently un-opt-out a domain.

The opt-out address is on the `/check` page itself, not buried in the terms.

### The bounded queue

`PQC_PUBLIC_CHECK_CONCURRENCY` checks run at once;
`PQC_PUBLIC_CHECK_MAX_QUEUE` may wait. Past that, 503 immediately. A check that
cannot get a slot within `PQC_PUBLIC_CHECK_QUEUE_WAIT_SECONDS` gets 503 too, and
the whole check has `PQC_PUBLIC_CHECK_DEADLINE_SECONDS` to finish. A slow target
therefore cannot occupy the server, and a slot is released even when the check
raises.

### The log

One row per attempt — including refusals, which is what makes an abuse report
investigable: domain, time, a **salted** hash of the requester's address, the
outcome, and the duration. The salt comes from `PQC_PUBLIC_CHECK_IP_SALT`, or is
generated once and stored in `public_check_meta` so hashes stay comparable
across restarts. An unsalted SHA-256 of an IPv4 address is reversible by brute
force in seconds, so it is never used. Rows are pruned past
`PQC_PUBLIC_CHECK_LOG_RETENTION_DAYS`.

Two rows with the same hash came from the same address; that is all the log
supports. Describe it in your privacy notice (see §8).

---

## 4. What the result page shows

- **A verdict a non-expert understands.** One of `quantum_vulnerable`,
  `hybrid_key_exchange`, `post_quantum`, `inconclusive`, `not_assessed`, with a
  headline and a plain-English paragraph naming the actual algorithms. A hybrid
  endpoint is credited for its key exchange and **not** for a classical
  certificate — the page says which half is protected and which is not.
- **Every figure sourced.** An `evidence` table where each row carries
  `source: handshake | certificate_transparency | model | reference`. Nothing
  unmeasured is presented as fact, and "not observed" is rendered as "not
  observed", never as "none".
- **A `model_basis`** (`services/model_basis.py`, kind `model`) separating what
  was measured from the Q-Day year, the break probabilities and the
  harvest-now-decrypt-later tier, which are a planning model.
- **Algorithms resolved before they are classified.** The strings off the wire
  (`sha256WithRSAEncryption`, `secp256r1`, `X25519MLKEM768`) are not names the
  classifier knows, and handed over raw they all came back *unknown - manual
  review required*, which on a public page sits beside two "quantum-vulnerable"
  cards and reads as *probably fine*. The CBOM's own resolvers
  (`cbom.canonical_algorithm`, `cbom.signature_algorithm_parts`,
  `cbom.key_exchange_algorithms`) decompose them first, so the page shows
  RSA-2048, SHA-256, and a hybrid group split honestly into X25519
  (quantum-vulnerable) and ML-KEM-768 (compliant).
- **Migration advice narrowed to the role.** `services/fips_pqc.py` keys its
  advice by algorithm, not by role, so RSA-2048 is always answered with
  "Migrate to ML-KEM-768" - right for a key exchange, wrong for a certificate,
  because ML-KEM cannot sign anything. Only the *suggestion* is narrowed, only
  when the catalogue names the wrong kind of primitive for the role, and the
  original wording is kept in `action_from_catalogue` so nothing is silently
  rewritten. Status, risk and reason pass through untouched, so the free and
  paid answers still agree about what is broken.
- **The same classification as the paid product**:
  `services/fips_pqc.classify_algorithm` for algorithms,
  `policy.evaluate_tls_findings` and `policy.derive_quantum_readiness` for the
  readiness assessment, `services/hndl.py` for the HNDL framing, and
  `services/regulatory.py` for the published deadlines. The free answer and the
  paid one cannot disagree. The HNDL **dollar figure is deliberately omitted**:
  it prices a stranger's data from per-port assumptions this check knows nothing
  about.
- **Honest about limits.** One endpoint, one moment, public data only, one
  client's view — stated on the page, with what a full assessment would add
  instead of implying the free check is complete.
- **A failed check is reported as failed.** An unreachable, timed-out or
  unresolvable host gets `outcome: "failed"`, verdict `not_assessed`, a null
  crypto-agility score and an HNDL tier of `unmeasured`. It never scores better
  than an honestly-identified RSA endpoint, and the page says "this is not a
  clean result: it means there is no evidence either way."
- **A permanent, shareable record** (`/r/{domain}`) and two exports: a small stable
  JSON (`airlock.public-check/1`) and a CycloneDX 1.6 CBOM from the existing
  generator.
- **A path into the platform**, stated plainly: what the full product adds, then
  links to pricing, a pilot and the console. No countdowns, no fake scarcity, no
  dark patterns.
- **Phone width and both themes.** `check.css` redefines the shared tokens under
  `prefers-color-scheme: light`, so every shared primitive follows. **No
  third-party requests** from the page at all.

---

## 5. Running it self-hosted

The checker ships with the platform and is on by default. Nothing extra is
needed to serve `/check`; the tables are created on first use.

A responsible minimum before you point it at the public internet:

```bash
# Who to write to about abuse and opt-outs. Put a real, monitored address here;
# the page shows it, and without it the page can only point at /support.
PQC_PUBLIC_CHECK_ABUSE_CONTACT=abuse@your-domain.example

# Share one budget across API replicas. Without this each process counts alone.
REDIS_URL=redis://localhost:6379/0

# A stable salt for the requester-IP hash (otherwise one is generated and stored).
PQC_PUBLIC_CHECK_IP_SALT=<32+ random characters>

# Domains you already know must never be contacted.
PQC_PUBLIC_CHECK_OPTOUT_DOMAINS=someone.example,another.example
```

Tighten the budgets if your egress is shared or metered:

```bash
PQC_PUBLIC_CHECK_IP_LIMIT=5
PQC_PUBLIC_CHECK_DOMAIN_LIMIT=2
PQC_PUBLIC_CHECK_GLOBAL_LIMIT=60
PQC_PUBLIC_CHECK_CACHE_SECONDS=21600
```

Turn the active check off entirely and keep the page as documentation:

```bash
PQC_PUBLIC_CHECK_ENABLED=0
```

Turn off the outbound CT lookup (the handshake still runs):

```bash
PQC_PUBLIC_CHECK_CT_ENABLED=0
```

### From the command line

The same check, through the same code, so the capability is not locked behind
the page. Every guardrail still applies.

```bash
python scripts/pqc-check.py example.com            # the report
python scripts/pqc-check.py example.com --json     # the full result
python scripts/pqc-check.py example.com --cbom     # a CycloneDX 1.6 CBOM
python scripts/pqc-check.py example.com --fresh    # ignore the cache
python scripts/pqc-check.py --settings             # this deployment's guardrails
python scripts/pqc-check.py --opt-out example.com  # never check it again
python scripts/pqc-check.py --list-opt-outs
python scripts/pqc-check.py --log                  # recent checks, for an abuse report
```

Exit status: `0` reached and assessed, `1` ran but reached nothing (a failure,
not a clean result), `2` target refused, `3` rate limited / queued out / off,
`4` an error on this side.

### Verifying a deployment without touching anyone else

Run it against a host you control, or start a local TLS fixture and point the
checker at a name that resolves to it — the SSRF guard will refuse a loopback
address, which is itself the check that the guard works. In the test suite
nothing is contacted at all: CT, the handshake and DNS are mocked at their
boundaries, and a `no_network` fixture makes any stray socket call fail.

---

## 6. Handling an abuse report

1. **Acknowledge, and stop the specific harm first.** If the complaint is about
   a particular domain, add the opt-out before anything else. It takes effect
   immediately, before DNS, and deletes the cached result:

   ```bash
   python scripts/pqc-check.py --opt-out complainant.example
   # or
   curl -X POST https://your-host/platform/public-check/opt-outs \
        -H "x-platform-key: $PQC_PLATFORM_ADMIN_KEY" \
        -H 'content-type: application/json' \
        -d '{"domain":"complainant.example","reason":"owner request, ticket 123"}'
   ```

2. **Find out what actually happened.** The log is per domain:

   ```bash
   curl -H "x-platform-key: $PQC_PLATFORM_ADMIN_KEY" \
        "https://your-host/platform/public-check/log?domain=complainant.example&limit=200"
   ```

   You get the times, the outcomes and a salted hash per requester. The same
   hash means the same address. You cannot recover the address from the hash —
   that is deliberate. If a law-enforcement request requires more, say so
   honestly: the data does not exist.

3. **Decide whether it was one requester or the service.** Many rows with one
   hash is a single user hitting the per-IP budget; many hashes against one
   domain is the per-domain budget doing its job. Either way the budgets are
   visible in `GET /api/public-check/config`.

4. **If it was a single requester**, tighten `PQC_PUBLIC_CHECK_IP_LIMIT` and
   `PQC_PUBLIC_CHECK_IP_BURST`, or block the address upstream. The checker
   itself does not maintain a requester blocklist; the salted hash means it
   could not enforce one anyway.

5. **If it was the service**, lower `PQC_PUBLIC_CHECK_GLOBAL_LIMIT` or set
   `PQC_PUBLIC_CHECK_ENABLED=0`. The page stays readable either way.

6. **Reply with what the tool actually did**, which is narrow and easy to state:
   public CT data, and at most two TLS connections to one hostname on port 443,
   at the times in the log. Pointing at `/check` is usually enough, because the
   acceptable-use statement is on the page.

7. **Record the outcome.** An honoured opt-out is a commitment, not a setting:
   do not remove one without the domain owner asking.

---

## 7. Adding a data source

A CT source is one callable registered in `CT_PROVIDERS`:

```python
# backend/services/public_check.py

def _ct_my_source(domain: str, timeout: float) -> Dict[str, Any]:
    rows = _http_get_json(f"https://ct.example/api?name={quote(domain)}", timeout,
                          {"User-Agent": "airlock-public-check/1.0"})
    if not isinstance(rows, list):
        raise RuntimeError("the source did not return a JSON array")
    entries = [{
        "id": row.get("id"),
        "issuer": str(row.get("issuer") or "")[:300],
        "common_name": str(row.get("cn") or "")[:300],
        "names": [n for n in (row.get("names") or [])][:25],
        "not_before": str(row.get("not_before") or "")[:40],
        "not_after": str(row.get("not_after") or "")[:40],
        "logged_at": str(row.get("logged_at") or "")[:40],
    } for row in rows if isinstance(row, dict)]
    return {"entries": entries, "total": len(entries), "keys": [],
            "provider": "my-source", "provider_url": "https://ct.example/"}


CT_PROVIDERS["my_source"] = _ct_my_source
```

The contract:

- Return `{"entries": [...], "total": int, "keys": [...], "provider": str,
  "provider_url": str}`, or **raise**. Anything you raise becomes
  `status: "unavailable"` with the reason attached.
- **Never fabricate an empty list.** "I could not reach the source" and "this
  domain has no certificates" are different claims and only one of them is ever
  supported by evidence. Returning `[]` for a failure is the single worst bug
  this module can have.
- Honour `timeout`. The caller has a deadline and will shrink your budget to fit
  it.
- If the source needs a credential, read it from an environment variable through
  a small accessor like `ct_token()`, and never log it.
- `keys` rows are `{not_before, not_after, issuer, key_type, key_bits,
  key_curve, sig_algorithm}`. Parse certificates with `scanner._pk_details` so
  key naming matches the rest of the platform; do not write a second parser.
- Select it with `PQC_PUBLIC_CHECK_CT_PROVIDER=my_source`, and add a test that
  mocks `_http_get_json` — never the network.

Adding a whole new *kind* of passive source (DNS CAA, a public scan dataset) is
a new section in `build_result` plus `evidence` rows with a new `source` label,
and the label must also be added to the page's `.src` styles and to the allowed
set in `test_every_figure_on_the_page_names_its_source`. Anything that would
contact the target is not a data source for this tool.

---

## 8. If you self-host this, the responsibility is yours

This is said on the page and in the CLI help, and it is meant literally. The
default configuration is deliberately conservative, but **you** are the party
contacting third-party hosts, and the rules that apply are those of your own
jurisdiction and your hosting provider's acceptable-use policy. Reading a public
TLS handshake is ordinary and is what SSL Labs and crt.sh have done for years;
that is not legal advice, and it is not a defence in every jurisdiction.

Before switching a public instance on, make sure these exist and are honest.
All five are now **drafted and served**, as real pages in the public-page style,
linked from the checker form, the result block, the public footer and from each
other, reachable without authentication, and listed in
`test_launch_collateral.py`. **Every one of them is a draft for a qualified
lawyer to review before the service is switched on for the public.** Nothing in
them is represented as legally sufficient.

| Page | Route | File | State |
| --- | --- | --- | --- |
| Terms that bind without a signup | `/public-check/terms` | `static/check-terms.html` | drafted; governing-law clause (Mauritius) marked for counsel |
| Acceptable-use policy | `/public-check/acceptable-use` | `static/check-acceptable-use.html` | drafted; consistent with the statement `GET /api/public-check/config` serves |
| Abuse and opt-out | `/abuse` | `static/check-abuse.html` | drafted; **response time is a marked placeholder**, and the abuse mailbox is yours to supply |
| Privacy notice, both parties | `/public-check/privacy` | `static/check-privacy.html` | drafted; `static/privacy.html` links it rather than absorbing it |
| Scanner identity | `/scanner` | `static/check-scanner.html` | drafted; **egress addresses and reverse DNS are marked placeholders** for you to fill in |

- **Terms that bind without a signup.** Acceptance works on use, and the
  statement with the links is beside the input box on `/check`, not only in the
  footer. Service, no warranty, point-in-time observation rather than an audit,
  no liability for decisions taken on a result, the authorisation rule, the
  right to refuse and rate-limit, and governing law.
- **The acceptable-use policy** is the document that separates a readiness tool
  from an attack tool. The statement the code serves from
  `GET /api/public-check/config` stays the authority: the page says so, and says
  that a disagreement between the two is a bug in the page.
- **A monitored abuse address.** Still yours: set
  `PQC_PUBLIC_CHECK_ABUSE_CONTACT`. Until it is set, every one of these pages
  says plainly that no address is configured and points at `/support`; none of
  them ships an address in its markup. `static/check-pages.js` fills the real one
  in from the live config, so the pages cannot drift from the deployment.
- **A privacy notice covering both parties**: the submitter (the salted IP hash,
  the retention window, what the log is for, and the fact that the platform's own
  request journal keeps the source address in the clear for its own shorter
  window) *and* the checked party (that a third party can cause a connection to
  their host, what is recorded and published about it, that their certificate
  data is already public in CT, that the result is linkable, and how to opt out).
  Mauritius's Data Protection Act 2017 and the GDPR are named; no compliance is
  claimed.
- **A scanner-identity page** at `/scanner`, so an operator who sees the
  connection in their logs can find out what it was. One honest correction to the
  obvious draft: the User-Agent `airlock-public-check/1.0` goes to the
  Certificate Transparency service, **not** to the checked host, because the
  checker sends the target no HTTP request at all — so that string cannot appear
  in a target's logs, and the page says so rather than sending an operator
  looking for it.

Still outstanding, and both are the operator's to supply:

1. `PQC_PUBLIC_CHECK_ABUSE_CONTACT` — a real, monitored mailbox, plus a response
   time to replace the marked placeholder on `/abuse`.
2. The egress addresses (and reverse DNS) on `/scanner`, which depend on where
   this is deployed. Until they are published, an operator who wants to block the
   service has to identify it by behaviour, which is the situation that gets
   egress ranges blocklisted wholesale.

Keeping a result cached for longer than an hour is usually the kindest setting:
it reduces contact with the target, and the answer rarely changes in a day.

## The permanent record

The permalink used to be the weak point: it pointed at a cache that expires in an
hour and is pruned after a week, so a link shared today broke within the week.
Every completed check now also lands in an append-only record, and the shareable
address is `/r/{domain}` -- server-rendered, indexable, with a history of what
changed and an embeddable badge. `/check/{domain}` is a 301 to it.

What that means for this document: the opt-out promise below now covers the
record as well as the cache, and it covers subdomains, which is why
`add_optout()` hides rather than only deletes. The badge is the single route that
answers an opted-out domain the same way it answers one nobody has checked -- a
403 would break the README it sits in.

[PUBLIC_REGISTRY_DESIGN.md](PUBLIC_REGISTRY_DESIGN.md) has the design, what is
built, and the two seeding modes that are not -- one of which touches no host at
all.
