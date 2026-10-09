# Third-Party Notices

Airlock Command is licensed under the MIT License — see [LICENSE](LICENSE). This file records the
licences of the third-party software it depends on, bundles or redistributes, and the attribution
those licences require.

Nothing here changes the licence of this project's own code. Every dependency is permissively
licensed or weak-copyleft used unmodified; no dependency imposes a copyleft obligation on this
codebase.

Licences were read from installed package metadata (`*.dist-info/METADATA` and the `LICENSE` files
beside it), not from memory. The full audit, including transitive dependencies, is in
[docs/OPEN_SOURCE_READINESS.md](docs/OPEN_SOURCE_READINESS.md).

---

## Summary

| Licence | Count (approx.) | Notes |
|---|---|---|
| MIT / MIT-0 / MIT-CMU | ~60 | No obligation beyond retaining the notice |
| BSD 2- and 3-Clause | ~20 | Retain notice |
| Apache-2.0 | ~50 | Retain notice; reproduce `NOTICE` files — see below |
| Python Software Foundation | 4 | Permissive |
| **LGPL-3.0-or-later** | **2** | `psycopg2-binary`, `PyGithub` — see below |
| **MPL-2.0** | **1 runtime** | `certifi` — see below |
| SIL OFL-1.1 | 3 font families | Bundled and served — see below |

No GPL, AGPL, SSPL, EUPL, Elastic, BSL or other "source available" licence appears in the Python,
Go or JavaScript dependency graph of the shipped application. Two items outside that graph need a
decision and are flagged under [Items requiring attention](#items-requiring-attention).

---

## Weak-copyleft dependencies

These are used **unmodified**, imported or dynamically loaded in the ordinary way, and installed from
their public package registries. That satisfies the LGPL's and MPL's conditions; none of them makes
this project's code copyleft. If you fork and *modify* any of them, the modified files remain under
their original licence and you must make that source available.

### psycopg2-binary — LGPL-3.0-or-later, with an OpenSSL linking exception

PostgreSQL database adapter. Declared in `backend/requirements.txt`.
Source: <https://github.com/psycopg/psycopg2> · Licence: <https://www.gnu.org/licenses/lgpl-3.0.html>

Used as a Python C extension module, unmodified. The binary wheel bundles `libpq` and OpenSSL.
A fully-permissive alternative exists if you need one: `pg8000` (BSD-3-Clause, pure Python) is
already present as a transitive dependency.

### PyGithub — LGPL-3.0-or-later

GitHub API client, used for repository correlation. Declared in `backend/requirements.txt`.
Source: <https://github.com/PyGithub/PyGithub> · Licence: <https://www.gnu.org/licenses/lgpl-3.0.html>

Pure Python, imported at runtime, unmodified. No PyGithub source is copied into this repository.

### certifi — MPL-2.0

Mozilla's CA root certificate bundle, pulled in transitively by `requests`.
Source: <https://github.com/certifi/python-certifi> · Licence: <https://mozilla.org/MPL/2.0/>

MPL-2.0 is file-level copyleft. Used unmodified, so no obligation attaches here. The bundled root
store is itself Mozilla's, also under MPL-2.0.

---

## Apache-2.0 attribution

Around fifty dependencies are Apache-2.0, including the OpenTelemetry suite, all `google-cloud-*`
packages, `grpcio`, `bcrypt`, `requests`, `boto3`, `aiohttp`, `python-multipart`, `moto` and
`playwright`. Section 4 of the licence requires the licence text, copyright notices and any
`NOTICE` file to accompany a distribution.

The Docker images built from this repository bundle the installed `site-packages` tree, which makes
them a distribution. These packages ship a `NOTICE` file whose contents must travel with them:

`aiofiles` · `boto3` · `botocore` · `cyclonedx-python-lib` · `license-expression` · `propcache` ·
`requests` · `s3transfer` · `yarl`

To regenerate a complete, machine-produced manifest including every notice file:

```bash
cd backend
pip install pip-licenses
pip-licenses --format=markdown --with-license-file --with-notice-file \
             --output-file=THIRD_PARTY_LICENSES_FULL.md
```

### Dual-licence elections

Three dependencies offer a choice. This project elects the permissive side of each, which removes
their Apache `NOTICE` obligation:

| Package | Offered | Elected |
|---|---|---|
| `cryptography` | Apache-2.0 **OR** BSD-3-Clause | **BSD-3-Clause** |
| `python-dateutil` | Apache-2.0 **OR** BSD-3-Clause | **BSD-3-Clause** |
| `sniffio` | MIT **OR** Apache-2.0 | **MIT** |

`cryptography`'s binary wheel statically links OpenSSL (Apache-2.0) and several Rust crates; those
retain their own licences regardless of the election above.

### Undeclared metadata

`google-crc32c` declares no licence in its metadata fields, but ships the full Apache-2.0 text in
its `dist-info/licenses/LICENSE`. It is Apache-2.0. Automated licence scanners report it as
"unknown"; that is a scanner artefact, not a licensing problem.

---

## Bundled fonts — SIL OFL-1.1

Three font families are redistributed in `backend/static/fonts/` and served to browsers at
`/ui/fonts/`. OFL-1.1 section 2 requires each copy to carry the licence and the copyright notice of
every font included. The full licence text and all three notices are in
[`backend/static/fonts/OFL.txt`](backend/static/fonts/OFL.txt).

| Family | Copyright | Upstream |
|---|---|---|
| Instrument Sans | Copyright 2022 The Instrument Sans Project Authors | <https://github.com/Instrument/instrument-sans> |
| Archivo | Copyright 2020 The Archivo Project Authors | <https://github.com/Omnibus-Type/Archivo> |
| IBM Plex Sans / Mono | Copyright (c) 2017 IBM Corp., with Reserved Font Name "Plex" | <https://github.com/IBM/plex> |

The `.woff2` files are format conversions and subsets made to reduce download size. OFL-1.1 sections
3 and 5 reserve the font names; see the note in `OFL.txt` before re-subsetting or editing them.

---

## Vendored third-party source

Copied into this repository verbatim rather than installed as a dependency:

| Path | What | Licence |
|---|---|---|
| `backend/schemas/cyclonedx/bom-1.6.schema.json` | CycloneDX 1.6 JSON Schema | Apache-2.0, © OWASP Foundation |
| `backend/schemas/cyclonedx/jsf-0.82.schema.json` | JSON Signature Format schema, developed by Anders Rundgren as part of the OpenKeyStore project | Apache-2.0 |
| `backend/schemas/cyclonedx/spdx.schema.json` | SPDX licence-list enumeration, as redistributed by CycloneDX | Apache-2.0; the SPDX licence list itself is CC-BY-3.0 |

These are vendored deliberately so that `backend/test_cbom_conformance.py` validates CBOM output
against the official schema on every test run, with no network access.

---

## Container base images and services

Pulled from their registries at build or run time, not redistributed by this project:

| Image | Licence |
|---|---|
| `python:3.11-slim` | Python PSF licence; Debian base is an aggregate of its components |
| `postgres:16` | PostgreSQL Licence (permissive, BSD-like) |
| `redis:7-alpine` | **See the note below** |
| `golang:1.26-alpine`, `alpine:3.23` | Alpine aggregate |

**Redis licence note.** Redis 7.0–7.2 was BSD-3-Clause. From Redis 7.4 the project moved to a dual
RSALv2 / SSPLv1 licence, which is "source available" and not OSI-approved. The floating `7` tag used
in `backend/compose.yml` and `docker-compose.prod.yml` can therefore resolve to either. Using the
image as a service imposes nothing on this project's MIT licence, but if you require a fully
permissive stack, pin a `7.2` tag or substitute [Valkey](https://valkey.io/) (BSD-3-Clause), which is
protocol-compatible.

---

## Go gateway

`gateway/` builds a static binary that embeds its whole module graph, which is redistribution. The
dependencies are Apache-2.0, BSD-3-Clause and MIT. Two warrant explicit attribution:

| Module | Licence | Note |
|---|---|---|
| `github.com/corazawaf/coraza/v3` | Apache-2.0 | WAF engine |
| `github.com/corazawaf/coraza-coreruleset/v4` | Apache-2.0 | Embeds the **OWASP Core Rule Set**, © OWASP Foundation |

The Go licences above were not verified from on-disk metadata (there is no vendor directory or
module cache in the repository). Run `go-licenses report ./...` from `gateway/` before publishing a
release binary to confirm them.

---

## Development-only tooling

Not part of the shipped application and not redistributed.

| Tool | Licence | Note |
|---|---|---|
| `pytest`, `ruff`, `jsonschema` | MIT | |
| `httpx` | BSD-3-Clause | |
| `moto`, `responses`, `bandit`, `pip-audit`, `playwright` | Apache-2.0 | |
| `axe-core` | **MPL-2.0** | Accessibility checks in `.tools/video/`, which is git-ignored |
| Playwright browser binaries | Chromium BSD-3-Clause, Firefox MPL-2.0, WebKit LGPL-2.1 + BSD | Downloaded per machine |
| **FFmpeg** | **GPL-3.0** | See below |

**FFmpeg.** The demo-video build scripts in `demo/video/` invoke `ffmpeg` and `ffprobe` as external
processes. The commonly distributed Windows "essentials" builds are GPLv3. Invoking a program does
not make the caller a derivative work, and the rendered video is not one either, so this imposes no
obligation — **but a GPLv3 binary must never be vendored into this repository.** `.gitignore`
excludes `.tools/`, and ffmpeg is expected to be supplied by the operator and found on `PATH`.

---

## Items requiring attention

Recorded here so they are not lost. Both are decisions for the maintainer rather than defects.

### 1. Terraform is not shipped — OpenTofu is (resolved)

Terraform 1.6 and later is licensed under the **Business Source License 1.1**, which is not an
open-source licence: it permits production use except in a product competing with HashiCorp, and
converts to MPL-2.0 four years after release. Shipping it in a published image would redistribute a
BUSL-1.1 binary, without its licence text, in an MIT project.

`backend/Dockerfile` therefore installs **[OpenTofu](https://opentofu.org/)** instead:

```dockerfile
ARG OPENTOFU_VERSION=1.8.6
curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/..."
```

OpenTofu is **MPL-2.0**, a CLI-compatible fork maintained under the Linux Foundation. The runtime
(`backend/remediation_validation.py`) looks for `tofu` first and falls back to `terraform`, so an
operator who installs Terraform themselves — their licence position, their choice — still works. The
default validation container is `ghcr.io/opentofu/opentofu:1.8.6`, overridable with
`PQC_VALIDATION_DOCKER_IMAGE`.

### 2. Terraform providers

`infra/gcp/cloudrun/.terraform/` holds provider binaries (`google`, `google-beta`, `random`), all
MPL-2.0. They are git-ignored and not redistributed, so no obligation currently attaches.

---

## Reporting a licensing problem

If you believe something here is misattributed, or that code in this repository is used without
proper attribution, please open an issue or email **contact@soqlab.com**. Mistakes will be
corrected promptly.

## This project's own work

The following are original implementations written for this project, not derived from any existing
library. Each carries a provenance note in its source:

| What | Where |
|---|---|
| QR code encoder (ISO/IEC 18004, Reed-Solomon over GF(256)) | `backend/services/qr_svg.py` |
| SSRF guard with DNS-rebinding-resistant address pinning | `backend/services/alert_routing.py` |
| TLS 1.3 ClientHello probe and ServerHello parser (RFC 8446) | `backend/scanner.py` |

The console's JavaScript and CSS are hand-written; there is no bundled or minified third-party
JavaScript anywhere, and no page loads a script or stylesheet from a CDN. The demo music in
`demo/video/` is generated by this project's own scripts (`make-*-music.py`) and the screenshots in
`demo/tour/` are captures of this software. All are MIT-licensed with the rest of the repository.
