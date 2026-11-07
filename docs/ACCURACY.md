# Scanner accuracy against real public endpoints

**Measured:** 2026-11-06/07 · **Dataset:** 422 public endpoints (386 TLS, 36 SSH) ·
**Rerun:** weekly, `.github/workflows/accuracy.yml`

[SCANNER_ACCURACY_AUDIT.md](SCANNER_ACCURACY_AUDIT.md) measures the scanner against servers built
on loopback, where the right answer is known by construction. That catches classification bugs but
not the ones that only show up against real deployments: CDNs, load balancers, legacy stacks and
post-quantum rollouts that behave differently from a Python test server. This document measures the
same scanner code against a few hundred real public endpoints, with every label obtained from an
independent reference implementation, and reports precision and recall per protocol and attribute.

It found four scanner bugs. All four are fixed, each with a regression test that reproduces the
server's behaviour on loopback (no live site in the test suite). The numbers below are before and
after those fixes.

---

## 1. Results

Published run: scanner `morrow-tls-scanner/2026.11.1` (this branch), Python 3.11.14 / OpenSSL 3.5.4,
2026-11-07 (first pass finished 06:58 UTC; 20 TLS endpoints whose scan failed on DNS or routing of
the scanning host during a local Docker outage, and the 36 SSH endpoints, rescanned 08:59 UTC; see
§4). Full per-endpoint results: `backend/accuracy/results/published.json`.

| Protocol | Attribute | n | Precision | Recall | F1 | F1 before fixes | Misses |
|---|---|---:|---:|---:|---:|---:|---:|
| TLS | `offers_TLSv1.0` | 386 | 100.0% | 96.5% | 98.2% | 0 (recall 0%) | 2 |
| TLS | `offers_TLSv1.1` | 386 | 100.0% | 100.0% | 100.0% | 0 (recall 0%) | 0 |
| TLS | `offers_TLSv1.2` | 386 | 100.0% | 100.0% | 100.0% | 98.2% | 0 |
| TLS | `offers_TLSv1.3` | 386 | 100.0% | 99.7% | 99.9% | 99.6% | 1 |
| TLS | `pq_hybrid` | 386 | 100.0% | 99.3% | 99.7% | 70.3% | 6 |
| TLS | `cert_key_type` | 386 | 100.0% | 99.2% | 99.6% | 98.4% | 3 |
| TLS | `cert_key_bits` | 386 | 100.0% | 99.2% | 99.6% | 98.4% | 3 |
| TLS | `sig_algorithm` | 386 | 99.7% | 99.0% | 99.4% | 98.2% | 4 |
| TLS | `cert_quantum_vulnerable` | 386 | 100.0% | 99.2% | 99.6% | 98.4% | 3 |
| TLS | `hndl_vulnerable` | 386 | 97.7% | 96.5% | 97.1% | 33.0% | 5 |
| SSH | `pq_hybrid` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| SSH | `kex_algorithms` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| SSH | `host_key_algorithms` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| SSH | `sha1_kex_offered` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| SSH | `hostkey_quantum_vulnerable` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |
| SSH | `hndl_vulnerable` | 36 | 100.0% | 100.0% | 100.0% | 100.0% | 0 |

"Before fixes" is the same dataset scanned with `main` at 6135688 on 2026-11-06 (633
disagreements). That run had more timeouts on the scanning host, so the small differences in the
certificate rows are mostly environment; the large ones (TLS 1.0/1.1, `pq_hybrid`,
`hndl_vulnerable`) are the four bugs in §4.

The 27 remaining disagreements in the published run, all investigated (§4):

| Endpoint | Attributes | Cause |
|---|---|---|
| www.globalsign.com | `offers_TLSv1.3`, `pq_hybrid`, `hndl_vulnerable` | endpoint behaviour: one name, several configurations |
| login.microsoftonline.com | `sig_algorithm` | endpoint behaviour: several certificates for one name |
| www.lacnic.net, cbc.badssl.com, rsa8192.badssl.com | four certificate rows each (12), `hndl_vulnerable` (3) | transient EOF on the primary handshake; all three scan correctly on recheck |
| www.openssl.org | `pq_hybrid`, `hndl_vulnerable` | transient: no ServerHello once; X25519MLKEM768 observed in the previous run and on three rechecks |
| mozilla-old.badssl.com, rsa8192.badssl.com | `offers_TLSv1.0` | transient timeout / EOF; TLS 1.0 completes on recheck |
| tls-v1-2.badssl.com, cbc.badssl.com | `pq_hybrid` (no answer) | transient: no ServerHello once; group observed on recheck |
| static-rsa.badssl.com, dh2048.badssl.com | `pq_hybrid` (no answer) | Morrow abstains: RSA key transport / finite-field DHE has no named group to observe. The label is "no hybrid", Morrow says "not observed". Not wrong, counted as a miss |

None of the 27 is a scanner bug. All but the last row would be a different answer on a rerun.

## 2. Method

### What is compared

| Protocol | Attribute | Morrow field (scan_host / scan_ssh) | Reference label |
|---|---|---|---|
| TLS | `offers_TLSv1.0` … `offers_TLSv1.3` (4 binary attributes) | `tls_supported_versions` | `openssl s_client -tls1 / -tls1_1 / -tls1_2 / -tls1_3` handshake completes (`-cipher ALL:@SECLEVEL=0` for ≤ 1.2, so the client's own policy does not refuse an old server) |
| TLS | `pq_hybrid` — hybrid ML-KEM key exchange supported | `key_exchange_family` ∈ {pq_hybrid, pq_pure} | `openssl s_client -tls1_3 -groups X25519MLKEM768` completes (then `SecP256r1MLKEM768:SecP384r1MLKEM1024` if refused) |
| TLS | `cert_key_type`, `cert_key_bits` | `key_type`, `key_bits` | leaf of a default `s_client -showcerts` handshake, parsed with `openssl x509 -text` |
| TLS | `sig_algorithm` | `sig_algorithm` | same leaf; names compared case/punctuation-insensitively |
| TLS | `cert_quantum_vulnerable` | `classical_crypto_dependency` | leaf key is RSA / EC / EdDSA / DSA |
| TLS | `hndl_vulnerable` — recorded traffic of a current client is decryptable later | `harvest_now_decrypt_later_risk` ∈ {critical, high, medium} | not `pq_hybrid` |
| SSH | `pq_hybrid` | `pq_ready` | server KEXINIT offers an `mlkem*` / `sntrup*` / `*kyber*` method |
| SSH | `kex_algorithms`, `host_key_algorithms` (exact lists) | same | `ssh -vv` "peer server KEXINIT proposal" |
| SSH | `sha1_kex_offered` | `SSH_CRITICAL_KEX` finding | KEXINIT offers a `*-sha1` DH method |
| SSH | `hostkey_quantum_vulnerable` | `SSH_QUANTUM_VULNERABLE_HOST_KEY` finding | any host key algorithm offered |
| SSH | `hndl_vulnerable` | `SSH_NO_MORROW_KEX` finding | no hybrid KEX offered |

### Scoring

* **Binary attributes** are scored on the positive class: precision = TP / (TP + FP), recall =
  TP / (TP + FN). When Morrow gives no answer for a positive (a timeout, an unobserved group) that is
  a miss. It never counts as a pass.
* **Value attributes** (key type, size, signature, algorithm lists): precision is the share of
  Morrow's answers that are right; recall is the share of labelled endpoints Morrow got right. An
  empty answer lowers recall only, a wrong one lowers both.
* An endpoint whose *label* is inconclusive (the reference timed out on that probe) is left out of
  that attribute rather than guessed. In the published run no TLS version label was inconclusive.
* "Misses" in the table counts every labelled endpoint Morrow did not get right, wrong answers
  and no answers together. Every one is listed in `backend/accuracy/results/published.json`.

Code: `backend/accuracy/metrics.py` (scoring, offline-tested by `test_accuracy_metrics.py`).

### Reference tools

| Tool | Version | Used for |
|---|---|---|
| OpenSSL `s_client` / `x509` | 3.5.9 (29 Sep 2026), Alpine 3.22 | TLS labels. 3.5 is the first release that can offer X25519MLKEM768. |
| OpenSSH `ssh -vv` | 10.0p2 | SSH labels. The client stops at "Host key verification failed" (empty known_hosts, BatchMode), so it never attempts authentication. |

Morrow ran in the production base image: Python 3.11.14, OpenSSL 3.5.4 (Debian trixie,
`python:3.11-slim`, as `backend/Dockerfile`). The reference runs in a separate container with a
different OpenSSL build, and shares no parser with Morrow: Morrow's key-exchange probe builds its
own ClientHello and its SSH scanner parses KEXINIT itself. The certificate attributes are the one
place both sides end in OpenSSL's X.509 decoding (Morrow through `cryptography`, the reference
through `openssl x509`); see limitations.

Each label records how it was obtained (`evidence`, the exact probe and its outcome), the tool
version (`label_source`) and the time (`labelled_at`), in `backend/accuracy/endpoints.jsonl`.

### Running it

```
# labels (any machine with Docker)
docker run --rm -v "$PWD/backend:/w" -w /w alpine:3.22 sh -c \
  'apk add -q openssl openssh-client python3 && python3 accuracy/reference_probe.py'
# Morrow's scan and the score
cd backend && python -m accuracy.run_accuracy            # or --only host1,host2
MORROW_ACCURACY_LIVE=1 python -m pytest -m network test_accuracy_live.py -s
```

The live pytest is skipped unless `MORROW_ACCURACY_LIVE=1`; the normal suite never opens a
connection to a public host.

### Pacing and conduct

Every connection is an ordinary client handshake of the kind a browser, `curl` or SSL Labs makes.
Nothing is exploited, no credentials are tried, no SSH authentication is attempted.

* One connection per host at a time, and hosts of one site (same registrable domain, e.g. the 23
  badssl.com hosts, which are one server) one after another. At most 6 sites in flight, with a
  pause between connections to the same host. The committed labels and the first two scans predate the
  site grouping: they ran up to 8 (labels) and 6 (scan) hosts in flight, so the badssl.com server
  could see that many concurrent handshakes from us; later runs cannot.
* Per TLS host: at most 8 reference handshakes, and one Morrow scan (about 16 sequential handshakes:
  the verified handshake, four version probes, ten TLS 1.2 cipher probes, one key-exchange probe).
  Morrow's OCSP/CRL reachability requests are switched off in the runner; they go to certificate
  authorities, not the endpoint, and no measured attribute depends on them.
* Per SSH host: one connection for each side.
* Only hosts that serve the general public on that port: public websites, the public SSH endpoints
  of code-hosting and public shell services, and badssl.com, which exists to be tested against.
  Hosts that ask not to be probed go in `backend/accuracy/optout.txt` and are skipped by every script.

## 3. Dataset

`backend/accuracy/endpoints.jsonl`: one JSON object per endpoint, with the labels, the evidence
for each (the exact probe and its outcome), `label_source` (tool and version) and `labelled_at`.
`backend/accuracy/candidates.txt` is the hand-picked list it was built from, with a free-text hint
of why each host was picked; the hint is never used as a label. Labelled 2026-11-06 21:57–22:18 UTC
(one endpoint, www.globalsign.com, relabelled 2026-11-07; see §4).

Categories are derived from the labels, first match wins:

| Category | Rule | Endpoints |
|---|---|---:|
| `pq_hybrid` | TLS 1.3 with X25519MLKEM768, no TLS 1.0/1.1 | 271 |
| `legacy_tls10_11` | still offers TLS 1.0 or 1.1 (28 of these also offer the hybrid) | 59 |
| `tls13_classical` | TLS 1.3, no ML-KEM hybrid | 45 |
| `tls12_only` | TLS 1.2, refuses 1.3 | 11 |
| `ssh_pq_hybrid` | SSH, KEXINIT offers mlkem768x25519 (21) or sntrup761x25519 (8) | 29 |
| `ssh_classical` | SSH, no hybrid KEX | 7 |
| **Total** | 386 TLS + 36 SSH | **422** |

Attribute spread, TLS:

| | |
|---|---|
| Certificate key | RSA-2048 219 · ECDSA P-256 149 · RSA-4096 14 · ECDSA P-384 3 · RSA-8192 1 |
| Signature | sha256WithRSA 241 · ecdsa-with-SHA384 72 · ecdsa-with-SHA256 66 · sha384WithRSA 5 · sha512WithRSA 2 |
| Versions offered | TLS 1.0: 58 · 1.1: 59 · 1.2: 385 · 1.3: 347 |
| Hybrid group | X25519MLKEM768 on 299 endpoints; no endpoint offered only SecP256r1MLKEM768 or SecP384r1MLKEM1024 |

Sources: the large CDNs and platforms (Google, Cloudflare, Meta, AWS, Fastly, Akamai, Microsoft),
open-source projects and standards bodies, governments on five continents, universities, banks,
news, retail, travel, security vendors and certificate authorities, and 23 badssl.com test hosts
(expired, self-signed, wrong host, untrusted root, incomplete chain, static RSA, CBC, DH, RSA-4096 and
8192, ECC-256/384, Mozilla old/intermediate/modern). SSH: GitHub, GitLab, Bitbucket and Azure DevOps
(port 22 and their port-443 alternates), Codeberg, SourceHut, Gitea, Debian, KDE, Arch, Launchpad,
Tor, Eclipse, SourceForge, Savannah, Alpine, Haskell, Pagure, repo.or.cz, OpenWrt, Xfce, Mozilla hg,
Inria, and public shell services (SDF, tilde.club, tilde.team, tilde.town, ctrl-c.club,
terminal.shop, ssh.chat).

Five candidates were dropped as unreachable from the labelling host (www.kemenkeu.go.id,
gitlab.gnome.org:22, gitlab.freedesktop.org:22, git.kernel.org:22) or unlabellable by the reference
(3des.badssl.com: OpenSSL 3.5 no longer implements 3DES, so it cannot complete a handshake with a
3DES-only server). They stay in `endpoints.jsonl` with `reachable: false` and are not scored.

Not represented, because no public endpoint in the candidate list had them: Ed25519/Ed448
certificates, DSA, SHA-1-signed leaf certificates, servers offering only SecP256r1MLKEM768, and
pure ML-KEM groups. The loopback matrix in SCANNER_ACCURACY_AUDIT.md covers those.

## 4. Every disagreement, investigated

The first run (scanner as on `main`, 6135688) disagreed with the reference 633 times. Each was
classified as a **scanner bug**, a **label error**, an **endpoint change**, or **environment**
(the measurement itself failed, e.g. a timeout on the scanning host). No label errors were found;
two kinds of endpoint behaviour and one environment cause account for everything that is not a bug.

### Bug 1 — TLS 1.0 and 1.1 were never detected (117 misses) — fixed

`_probe_tls_versions()` used Python's default cipher string, which carries `@SECLEVEL=2`. Under
OpenSSL 3 no cipher or signature algorithm is allowed for TLS 1.0/1.1 above security level 0, so
every TLS 1.0 and 1.1 probe failed *on the client* with `[SSL] internal error` before a byte was
sent. The reference found 58 endpoints offering TLS 1.0 and 59 offering 1.1 (Google, YouTube,
Cloudflare's blog, many governments); Morrow reported none, recall 0%. The `POLICY_TLS_BELOW_MIN`
finding could therefore never fire against a real server.

Fix: the version probes use `ALL:@SECLEVEL=0` (`scanner._VERSION_PROBE_CIPHERS`): the question is
what the server speaks, not what the client would accept. Regression:
`test_accuracy_regressions.py::test_legacy_tls_version_is_detected` (loopback TLS 1.0- and
1.1-only servers), plus a test that a modern server is still reported without them.

### Bug 2 — static-RSA-only servers: no TLS 1.2, no certificate — fixed

The same default cipher list has no RSA key transport. A TLS 1.2 server offering only
`AES*-GCM-SHA*` with RSA key exchange (static-rsa.badssl.com) was reported as not speaking TLS 1.2,
and, because the primary verified handshake failed with a `handshake_failure` alert, the scan
returned `tls_error` with no certificate: the endpoint was "unknown" instead of "RSA-2048,
quantum-vulnerable". That is the legacy configuration most in need of migration.

Fix: the version probes use the permissive cipher list (bug 1), and when the primary handshake
fails with a TLS error, `_legacy_cipher_cert_fallback()` reads the certificate with a permissive,
unverified handshake and marks it `unverified_fallback` with the original error kept in
`primary_handshake_error`. Regressions: `test_tls12_server_with_only_rsa_key_exchange_is_detected`,
`test_certificate_is_read_from_a_static_rsa_only_server`.

### Bug 3 — hybrid key exchange missed on 137 of 299 endpoints — fixed

The key-exchange probe offered every hybrid group in `supported_groups` but sent a key share for
X25519 only. Google, Cloudflare, Meta and AWS answer that with a HelloRetryRequest for
X25519MLKEM768, so they were detected. Fastly (pypi.org, python.org, reddit, nytimes, the Guardian,
CNN), Akamai (apple.com), Mozilla and others take the share they were given: they negotiated X25519
and Morrow reported classical key exchange, although each of them negotiates X25519MLKEM768 with
every current browser. Recall 54.2%.

Fix: the ClientHello now carries an X25519MLKEM768 key share (a well-formed ML-KEM-768
encapsulation key, never decapsulated, plus an X25519 key) ahead of the X25519 one, which is the
shape of the ClientHello Chrome, Firefox and Safari send. Regressions:
`test_hybrid_server_that_prefers_an_existing_share_is_seen_as_hybrid` (a loopback server that
replays the share-taking behaviour and checks the ClientHello shape) and
`test_mlkem_encapsulation_key_is_well_formed` (FIPS 203 modulus check).

### Bug 4 — harvest-now-decrypt-later verdict ignored the key exchange (310 misses) — fixed

`policy.derive_quantum_readiness()` computed `harvest_now_decrypt_later_risk` from the certificate
key and the TLS version only. HNDL is about the key exchange: a recording of a session whose key
was agreed with X25519MLKEM768 is not decryptable by a future quantum computer, whatever the
certificate is. Every hybrid endpoint was reported HNDL "critical" or "high"; precision 20.3%. The
product's own passive-discovery path already scored a hybrid group "low".

Fix: an observed hybrid or pure-PQ group sets HNDL to "low"; a classical or unobserved group keeps
the old verdict. The certificate's classical dependency (impersonation risk) is unchanged.
Regressions: `test_hybrid_key_exchange_is_not_reported_as_harvest_now_decrypt_later_exposed`,
`test_classical_or_unobserved_key_exchange_keeps_hndl_exposed`.

### Endpoint behaviour: one name, several configurations

* **www.globalsign.com.** Labelled TLS 1.3 + X25519MLKEM768 + sha256WithRSA. During the post-fix
  run both Morrow and `s_client` got TLS 1.2 only, three times in a row; fifteen minutes later the
  reference got TLS 1.3 + X25519MLKEM768 + sha384WithRSA again (relabelled 2026-11-07 04:48 UTC).
  The name fronts servers with different configurations. Neither side is wrong; whichever
  configuration answers decides the result, so this endpoint may disagree in any run.
* **login.microsoftonline.com** — Morrow saw a leaf signed sha384WithRSA, the reference
  sha256WithRSA, on the same day. Microsoft serves several certificates for this name from
  different front-ends. Endpoint behaviour, not a bug; not relabelled because both are correct.

### Environment: timeouts on the scanning host

The remaining misses in the first runs were probes that timed out (`_ssl.c:999: The handshake
operation timed out`, Morrow's 6-second `DEFAULT_TIMEOUT`) while the scanning machine was heavily
loaded by unrelated work, and transient EOFs (www.cdc.gov, www.parliament.uk, www.postgresql.org)
that did not reproduce on recheck. They cluster on badssl.com, whose 23 hosts are one server: the
first runner scanned up to six of them at once. The runner now scans hosts of one site one after
another (`site_key()`), retries a scan with timeouts once after the others, and records which it
retried (`retried_after_timeout`). Timeouts that survive the retry are still counted as misses in
the published table.

During the published run the Docker engine on the scanning machine failed (HTTP 502 from the
engine API) and, for a while, the scanning container lost DNS and its route: 20 TLS endpoints came
back `Temporary failure in name resolution` or `Network is unreachable`. Those failures are the
scanning host's, so `run_accuracy.py --rescan-from` rescans exactly the endpoints whose scan failed
that way (the criterion is the error text, `environment_failure()`), keeps every other scan as it
was, and records the rescanned ids in `rescanned_after_environment_failure`. The 36 SSH endpoints
were rescanned in the same pass because that run's results file did not yet keep the SSH finding
ids needed to rescore them (one connection per host). Timeouts and EOFs are never rescanned this
way; they stay in the table.

The SSH scanner agreed with OpenSSH on every attribute of every endpoint in every run.

## 5. Weekly rerun

`.github/workflows/accuracy.yml` runs every Monday (and on demand). It relabels every endpoint with
the reference tools first, so the week's disagreements are measured against the week's
configurations, then scans with Morrow in `python:3.11-slim` and scores. It reports, it does not
fail:

* a step summary with the per-protocol table;
* a `::warning::` for every disagreement (first 40) and for every attribute whose F1 fell more than
  two points below `backend/accuracy/results/published.json`;
* a `::notice::` for every endpoint whose label changed since the committed dataset ("endpoint
  changed", relabel the dataset), separate from "scanner wrong";
* the fresh labels and full results as a 90-day artifact.

Every network step is `continue-on-error`, and nothing depends on the workflow.

## 6. Known limitations

* **One vantage point, one moment.** Every label and scan came from one network in Europe on
  2026-11-06/07. CDNs answer differently by region and by front-end; a load-balanced name can be
  several configurations at once (www.globalsign.com and login.microsoftonline.com, §4). The weekly
  rerun narrows "configs change" to a week; it does not remove geography.
* **The certificate attributes share a decoder.** Morrow reads the leaf with `cryptography`,
  the reference with `openssl x509`; both end in OpenSSL's ASN.1 code. A bug common to both would
  not show here. The handshake, version, key-exchange and SSH paths share no code with the reference.
* **"Supports hybrid" is not "every client gets it".** `pq_hybrid` asks whether the server agrees
  to X25519MLKEM768 when a client offers it, which is what a current browser does. Clients that do
  not offer it still get classical key exchange from the same server, and their recorded traffic is
  still harvest-now-decrypt-later exposed. The HNDL verdict (bug 4) is about a current client.
* **Only what the endpoint shows a client.** Certificate key type, size and signature are those of
  the certificate served to a default client (TLS 1.3, both RSA and ECDSA signature algorithms
  offered). A dual-certificate server shows an RSA-only client a different leaf.
* **Thin coverage of some classes.** 11 TLS-1.2-only and 7 classical-SSH endpoints; no Ed25519,
  DSA or SHA-1 leaf certificates and no SecP256r1MLKEM768-only server on the public internet in the
  candidate list. Precision/recall on those cells rests on few points; the loopback matrix in
  SCANNER_ACCURACY_AUDIT.md is the evidence for the missing ones.
* **The TLS 1.2 cipher probes and IKE are not measured.** Morrow's ten TLS 1.2 cipher probes feed
  findings but no attribute here, and IKE (`ike_scanner.py`) has no public endpoints that serve the
  public: VPN gateways are not public services, so probing them is out of bounds for this suite.
  IKE accuracy is covered by the strongSwan tests (`test_ike_scanner_strongswan.py`).
* **Timeouts are scored as misses.** A probe that times out gives no answer, and no answer on a
  positive is a miss. The runner retries a timed-out scan once; residual timeouts are counted, not
  excused. On a slow or congested network the numbers fall for reasons that are not the scanner's.
* **Selection bias.** The endpoints were hand-picked to cover categories, not sampled. The
  per-category counts are not estimates of how common each configuration is on the internet.
