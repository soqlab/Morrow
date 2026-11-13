# Public quantum-readiness grade

One letter, A to F, for a public HTTPS endpoint, answering a single question: **is traffic to this
site protected against "harvest now, decrypt later"?** That means recording encrypted traffic today
and decrypting it once a cryptographically relevant quantum computer (CRQC) exists.

- Code: `backend/services/public_grade.py` (probe, rubric, storage, CLI) and
  `backend/routers/public_grade.py` (HTTP surface and CORS).
- Tests: `backend/test_public_grade.py`. None of them use the network.
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
