# Public registry: permanent check pages, badges, and seeding

Design for turning the free check at `/check` into a permanent public record of software
crypto posture.

**Status: steps 1 to 3 of section 10 are built** -- the ledger and catalogue, the
server-rendered record page at `/r/{domain}`, and the badge. Steps 4 (browse and sitemaps) and
5 (seeding) are not. Two decisions changed during implementation and this document has been
corrected to match the code: section 6 on what an opted-out domain is told, and section 3 on
`og:image`.

The free check used to answer a question and forget. A registry keeps the answer at a
stable address, so it can be linked, cited, embedded in a README, indexed by a search engine,
and read by a build pipeline. That is the difference between a tool and a reference, and it is
almost entirely plumbing we already own: `services/public_check.py` produces the answer,
`policy.py` grades it, `services/hndl.py` frames the risk. What is missing is permanence, a
server-rendered page, a badge, and a way to populate the catalogue.

## 1. The blocker that started this: nothing was permanent

`public_check_results` is a cache, not a record:

- one row per domain, overwritten on every run — no history;
- `cached_result()` returns `None` once `expires_at` passes;
- `store_result()` deletes rows older than seven days.

So `result["permalink"]`, which pointed at `/check/<domain>`, was a promise the storage did not
keep: a link shared on Monday rendered "no cached result" by the following Monday. Everything
else here depended on fixing that first. The payload's `permalink` is now `/r/<domain>`, and
`/check/<domain>` returns a 301 to it.

### Two new tables, cache untouched

Leave `public_check_results` exactly as it is. Its TTL semantics are what keep the rate limits
and the one-handshake-per-domain-per-window promise honest, and the registry has the opposite
requirement. Add alongside it:

```sql
-- Append-only. One row per distinct observation, kept permanently.
CREATE TABLE public_check_observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    observed_at  TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,          -- unchanged re-observations extend this instead
    source       TEXT NOT NULL,          -- 'measured' | 'ct' | 'claimed'
    outcome      TEXT NOT NULL,          -- 'ok' | 'failed'
    posture      TEXT NOT NULL,          -- see the posture ladder below
    content_hash TEXT NOT NULL,          -- sha256 of the comparable fields
    result_json  TEXT NOT NULL
);
CREATE INDEX idx_pco_domain ON public_check_observations (domain, observed_at DESC);
CREATE UNIQUE INDEX idx_pco_dedupe ON public_check_observations (domain, content_hash, source);

-- One row per domain: the catalogue, and what the page and sitemap read.
CREATE TABLE public_check_domains (
    domain           TEXT PRIMARY KEY,
    first_seen_at    TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    latest_id        INTEGER NOT NULL,
    posture          TEXT NOT NULL,
    source           TEXT NOT NULL,
    observations     INTEGER NOT NULL DEFAULT 1,
    hidden           INTEGER NOT NULL DEFAULT 0,  -- opt-out, see section 6
    claimed_org_id   TEXT                          -- reserved; not used in v1
);
CREATE INDEX idx_pcd_posture ON public_check_domains (hidden, posture, last_observed_at DESC);
```

`content_hash` covers only the fields that describe the endpoint's cryptography — TLS version,
cipher, key type and size, key exchange, certificate algorithm, chain subjects — and
deliberately not `checked_at`, timings, or queue state. Re-checking an unchanged endpoint then
extends `last_seen_at` on the existing row rather than appending a duplicate, so the history
reads as "this is what changed, and when", not as one row per visit. Without that, a domain
checked hourly accumulates thousands of identical rows and the history becomes unreadable
noise.

### The posture ladder

One vocabulary, used by the page, the badge, the API, the sitemap and the catalogue filter.
Derived from what `derive_quantum_readiness()` already returns; this only names the buckets so
they can be rendered and sorted.

| posture | meaning | badge |
|---|---|---|
| `pq_ready` | a NIST post-quantum algorithm (ML-KEM / ML-DSA) was negotiated | green |
| `hybrid` | a hybrid group was observed, e.g. X25519MLKEM768 | green |
| `classical_only` | RSA, ECDSA, ECDH, Ed25519 or X25519 only — harvestable today | amber |
| `unreachable` | no handshake completed; nothing was measured | grey |
| `unknown` | catalogued but never measured (CT-only, see section 5) | grey |

`unreachable` and `unknown` must stay distinct, and neither may ever render as reassurance.
The scanner accuracy audit found that collapsing "failed" into "clean" is the most damaging
bug this product can have; a registry would publish that mistake at scale.

## 2. URL scheme

| URL | What it serves |
|---|---|
| `/r/<domain>` | the record page, server-rendered (section 3) |
| `/r/<domain>/at/<id>` | one immutable observation, citable |
| `/r/<domain>/badge.svg` | the badge (section 4) |
| `/r/<domain>/export.json` | the existing export, unchanged |
| `/r/<domain>/cbom.json` | the existing CBOM, unchanged |
| `/registry` | browse and filter the catalogue |
| `/registry/sitemap.xml` | sitemap index, sharded (section 7) |
| `/check`, `/check/<domain>` | the tool, unchanged; the permalink 301s to `/r/<domain>` |

`/r/` rather than `/check/<domain>` because they are different things: `/check` is where you
run something, `/r` is where the result lives, and a record URL should not look like an action.
It also keeps the badge URL short enough to read inside a README.

Constraints the implementation inherits:

- `normalize_domain()` already lowercases, IDNA-encodes and rejects anything that is not a
  public hostname. The route must call it and **301 to the canonical form** rather than serve
  both `/r/Example.COM` and `/r/example.com`. Duplicate URLs for one record cost search
  ranking and make the ETag meaningless.
- `/r` joins `_CSP_STRICT_PREFIXES`, so the rendered HTML gets no inline `<script>`, no inline
  event handler and no inline `style` attribute. Styles go in `static/registry.css`.
- `/r` joins the public-path and cheap-path decisions in `app.py` the same way `/check` did,
  through `_route_paths.has_prefix`, so `/R/` and `/v1/r/` reach the same decision as `/r/`.
  The `/assets/` incident is the precedent: a path that looks static but serves API data ends
  up with no rate limit and no journal entry.

## 3. The page

**Server-rendered HTML, not the existing client-rendered document.** This is the one
architectural change worth insisting on. `/check/<domain>` today returns a static shell and
fetches the result with JavaScript, which is right for a tool and useless for a record: no
crawler indexes it, no Slack or LinkedIn unfurl shows anything, and a shared link looks broken
to anyone with JavaScript blocked. A registry that cannot be indexed is a directory with no
visitors.

Rendering reads the latest observation out of `public_check_domains` into `result_json` and
touches no network, so a page view is a single indexed read. Content:

- the verdict headline and explanation, as `build_result()` already phrases them;
- the posture, with the sentence that justifies it;
- the algorithms observed, each with its FIPS classification and why it is or is not
  quantum-vulnerable;
- the HNDL framing: what an adversary recording this traffic today could decrypt later;
- the deadlines from `services/regulatory.py` that apply;
- **when this was observed, and what has changed** — the history from the ledger, which a
  cache could never show and the main reason to keep one;
- what this check does not cover and what a full assessment adds, both already written in
  `_LIMITS` and `_FULL_ASSESSMENT_ADDS`;
- the badge, with a copy-paste Markdown snippet;
- a "re-run this check" control that posts to the existing API — progressive enhancement, so
  the page is complete and readable before any JavaScript runs.

Head and caching:

- `<link rel="canonical">` to the normalised URL;
- Open Graph and Twitter card tags, and **no `og:image`**. The plan was five static PNGs, one
  per posture, because generating a per-domain card at runtime needs a TTF and `static/fonts/`
  holds woff2 only, which Pillow cannot read. On building it, a card that cannot carry the
  domain name says nothing the `og:title` does not already say, so it was dropped rather than
  shipped as decoration. An unfurl shows the title and the description, which is the useful
  part. A per-domain card is worth revisiting only alongside a TTF;
- JSON-LD (`WebPage` plus `Dataset`) so a result can surface as structured data;
- `ETag: "<content_hash>"` and `Cache-Control: public, max-age=300, stale-while-revalidate=86400`.
  The ETag comes from the observation hash, so an unchanged page is a 304 — which is what makes
  serving a large catalogue affordable.

## 4. The badge

```
GET /r/<domain>/badge.svg   ->  image/svg+xml
Cache-Control: public, max-age=3600, s-maxage=86400
ETag: "<content_hash>"
```

Hand-built SVG, the same way `services/qr_svg.py` already builds SVG — no new dependency.
Shields-style: a dark label block reading `post-quantum`, then a coloured value block reading
`ready`, `hybrid`, `classical`, `unreachable` or `unknown`. Width is computed from a
per-character width table rather than measured, because there is no font metrics library in the
image; a 7px-per-character estimate at an 11px font is what shields itself does.

Three rules matter more than the rendering:

1. **No cookies, no `Vary`, no auth.** GitHub proxies README images through Camo; anything that
   varies per viewer is cached wrongly or not at all.
2. **An opted-out domain and a never-checked domain return the identical grey `unknown` badge,
   with status 200.** A 403 would break the README it is embedded in *and* confirm that the
   domain asked to be excluded. The opt-out promise means the badge must leak neither the
   posture nor the existence of the opt-out. This is the one place where the registry
   deliberately does not answer the same way as the API.
3. It renders from stored data only. A badge request must never be able to start a check,
   or every README view becomes an unmetered scan of someone else's endpoint.

## 5. Seeding

A registry launched empty stays empty; the catalogue has to be populated before anyone arrives.
This is also where the legal exposure concentrates, so the design splits it in two and keeps
the two clearly labelled on the page.

**Passive, from Certificate Transparency only.** CT logs are public, and
`certificate_transparency()` already reads them. A certificate gives the key algorithm and
size, the issuer, and the validity window — enough to publish `classical_only` or `unknown`
with the source stated as *"from public certificate logs; this endpoint has not been
measured"*. **No packet reaches the domain.** This scales to as many domains as we care to
catalogue and carries essentially no risk beyond publishing an accurate reading of public data.
It is how the catalogue should be filled.

**Measured, one handshake at a time.** A single TLS connection to port 443 is exactly what a
browser does, which is the position already documented on `/scanner`. Doing it to thousands of
hosts on our own initiative is a different activity from doing it because a visitor asked, and
it should carry:

- the opt-out list consulted before DNS resolution (already enforced in `run_check`);
- at most one handshake per host per 24 hours, and never more than one concurrent connection
  per destination address;
- published egress addresses and reverse DNS naming the scanner, so a receiving admin can
  identify it in their logs with one lookup;
- a monitored mailbox behind `/abuse` with a stated response time — still an open operator
  item, and a hard prerequisite for this job specifically;
- a conservative seed list. For v1 that means **our own domains, domains that opted in, and
  domains someone already checked through `/check`** — organic growth, no mass scanning.
  Going beyond that is a decision for the same counsel reviewing the five policy pages, not a
  default.

Job shape, for a `seed-registry.py` that does not exist yet:

```
--source ct|measured     default ct
--input FILE             one domain per line, or - for stdin
--max N                  hard ceiling on domains touched in this run
--dry-run                resolves and normalises, makes no outbound request, prints the plan
--checkpoint FILE        resumable; a crashed run never restarts from the beginning
--concurrency N          bounded by the existing semaphore in services/public_check.py
```

It must call `run_check()` rather than reimplement anything, so every guardrail — opt-out, SSRF
guard, private-address refusal, deadline, queue, cache — applies identically to a seeded check
and a visitor's check. A seeding job with its own code path is how guardrails silently stop
applying.

## 6. Opt-out, extended

`add_optout()` currently deletes the cached result. With a permanent ledger it must do more,
and that difference is the whole value of the promise:

- set `hidden = 1` on the catalogue row **and on every subdomain's row**. `add_optout()`
  already deletes cached results for `domain` and `%.domain`, and `opted_out()` already
  resolves a subdomain to its covering opt-out, so the registry has to hide the same set or
  the guarantee is narrower in the registry than in the checker;
- the record page, every observation page, `export.json` and `cbom.json` return the existing
  403 wording on every route — `_refuse_if_opted_out` already covers the API routes and must
  cover the new ones;
- the badge returns the neutral `unknown` badge (section 4, rule 2);
- the domain is excluded from `/registry`, from every sitemap shard, and from the feed;
- the observations stay in the table but become unreachable through any public route. They are
  the evidence of what we checked and what we saw, which is what makes an abuse complaint
  answerable; deleting them would leave nothing to answer with.

Removing an opt-out restores the page. The asymmetry is deliberate: hiding is instant,
restoring is an operator action.

## 7. Indexing

`static/robots.txt` gains `Allow: /r/`, `Allow: /registry`, and a `Sitemap:` line. `/api/` stays
disallowed, as it already is.

A sitemap index at `/registry/sitemap.xml` points at shards of 50,000 URLs,
`/registry/sitemap-<n>.xml`, generated from `public_check_domains` where `hidden = 0` **and the
domain has at least one observation with `outcome = 'ok'`**. Pages for domains we could not
reach, or only saw in CT, are legitimate records but thin content, and submitting tens of
thousands of them is the fastest way to get the whole site demoted. They stay reachable and
linkable; they are simply not advertised.

`lastmod` comes from `last_observed_at`, which makes recrawling cheap and correct.

## 8. What v1 does not include

Named so the scope cannot drift: no accounts claiming a domain, no discussions or comments, no
leaderboards, no package or dependency registry, no CLI that consumes the registry. Those come
after, and the one that matters most is the CLI — a registry that build pipelines read is
load-bearing, while one that only humans browse is a directory.

## 9. Tests this needs

The conventions in `test_public_checker.py` apply: no third-party hosts, local TLS fixtures
only.

1. A permalink still renders after the cache TTL has passed — the bug that makes today's
   permalink a false promise.
2. Re-observing an unchanged endpoint extends `last_seen_at` and appends no row; a changed
   endpoint appends exactly one.
3. Opt-out hides the page, the history, both exports and the sitemap entry, and the badge for an
   opted-out domain is byte-identical to the badge for a never-checked one.
4. The rendered HTML contains the verdict text with no JavaScript executed: parse the response
   body and assert the headline is in it.
5. `/r/Example.COM` 301s to `/r/example.com`, and an unchanged page returns 304 against its ETag.
6. The badge is well-formed XML, its width grows with its label, and requesting it starts no
   check — assert the outbound call count stays at zero.
7. The sitemap excludes hidden domains and domains with no successful observation.
8. `seed-registry.py --dry-run` makes zero outbound connections.
9. `/r` is subject to the strict CSP, and the rendered page contains no inline script, no inline
   handler and no `style=` attribute.

## 10. Order of work

Steps 1 to 3 are done. What they added, for anyone reading the code: the two tables in
`public_check.init_tables`, the posture ladder and `record_observation` / `registry_entry` /
`registry_history` / `registry_observation` / `set_registry_hidden` in
`services/public_check.py`, the renderer and badge in `services/registry_page.py`, the routes in
`routers/public_check.py`, `static/registry.css`, and `test_public_registry.py`.

1. The ledger and catalogue tables, plus `store_result()` appending to them. Nothing is visible
   yet, but every later step depends on it and from this point the data accumulates.
2. The server-rendered `/r/<domain>` page, the 301 from `/check/<domain>`, canonical and caching
   headers.
3. The badge and its README snippet. This is the step that makes the registry spread.
4. `/registry` browse, robots and sitemaps.
5. CT-only seeding, then measured seeding once the abuse mailbox is monitored.

Steps 1 to 3 are the useful unit: a permanent, shareable, embeddable record. Steps 4 and 5 are
what make it discoverable.
