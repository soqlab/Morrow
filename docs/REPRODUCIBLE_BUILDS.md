# Reproducible builds

Each Morrow release is meant to be reproducible: if you rebuild a tag from source, you get exactly
the bytes that were published. That covers both image digests, the three SBOMs and the offline
bundle. You don't have to trust that the published images came from the published source. You can
rebuild them and compare.

This page covers how it works, how to check a release yourself, and what is not reproducible yet.
[SECURITY.md](../SECURITY.md#verifying-a-release) covers checking the signatures.

## What is pinned

| Input | Pinned how | Where |
|---|---|---|
| Base image `python:3.11-slim` | by digest | `FROM` line of both Dockerfiles |
| Debian packages (curl, unzip, ca-certificates, redis-server) | the sources point at `snapshot.debian.org` at a fixed time (`DEBIAN_SNAPSHOT`) during the install, then go back to the originals | both Dockerfiles |
| OpenTofu | version and sha256 of the zip | both Dockerfiles |
| Python packages, transitives included | every file by sha256, installed with `--require-hashes --no-deps --only-binary :all:` | `backend/requirements*.lock` |
| pip, setuptools, wheel in the image | by sha256 | `backend/requirements-bootstrap.lock` |
| BuildKit, which does the image build and layer compression | by digest | `scripts/release/pins.sh` |
| syft, which writes the image SBOMs | by digest | `scripts/release/pins.sh` |
| cyclonedx-bom, which writes the Python SBOM | by sha256 | `scripts/release/sbom-tools.lock` |
| Python, tar and gzip that assemble the bundle and the Python SBOM | the base image digest | `scripts/release/pins.sh` |
| Caddy, shipped in the bundle | linux/amd64 manifest digest | `scripts/release/pins.sh` |

The images don't build frontend assets. `frontend/index.html` is a static file, so there is no npm
step to lock.

## What is normalised

- **Time.** `SOURCE_DATE_EPOCH` is the commit time of the tag (`git log -1 --format=%ct`). BuildKit
  uses it for the image's `created` and history times. `rewrite-timestamp=true` sets every file in
  the new layers to an mtime no later than that time. `useradd` uses it for the `/etc/shadow`
  change date. pip writes hash-based `.pyc` files when it is set. The SBOM timestamps come from it
  too, and so do the bundle's file times.
- **Build context.** The context is `git archive` of the commit, never the working tree. File modes
  (`tar.umask=0022`) and line endings are the same whatever the checkout's settings.
- **Build records.** The Dockerfiles delete what apt and dpkg write about the build itself:
  `/var/log/*`, apt caches, `ldconfig`'s `aux-cache`, and the `*-old` and `/etc/*-` backups.
- **Image format.** BuildKit exports OCI media types, with no buildx provenance or SBOM attached:
  those record the build machine. The release signs its own provenance and SBOM separately.
- **SBOMs.** `scripts/release/normalize_cdx.py` replaces the generator's random `serialNumber` with
  a UUIDv5 of the subject (image name and digest) and its wall-clock timestamp with the commit time.
  It also sorts components and dependencies. Nothing the scanner found is removed.
- **Offline bundle.** `docker save` is not used, because what it writes depends on the Docker
  version and storage driver. `scripts/release/oci_bundle.py` writes the registry blobs themselves,
  each checked against its digest, in the layout `docker save` has used since Docker 25. That layout
  is an OCI image layout plus a `manifest.json`, so both the classic and the containerd image stores
  load it. The tar has fixed order, owner, mode and time. The outer archive is built with
  `tar --sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner` and `gzip -n`,
  inside the pinned Python image.

## Check a release yourself

You need git, curl, Docker with buildx 0.13 or later, and a Linux or macOS shell. On Windows, use
WSL: the scripts work from a Windows shell too, but the published comparison was made on Linux.
Reproducing a release takes 10 to 20 minutes and about 3 GB of disk.

```sh
git clone https://github.com/soqlab/Morrow && cd Morrow
git checkout v1.2.3                         # the scripts and pins of that release
sh scripts/release/reproduce.sh v1.2.3
```

`reproduce.sh` downloads only `IMAGES.txt` and `SHA256SUMS` from the release. It rebuilds
everything with `--no-cache` on a fresh BuildKit (builder `morrow-repro`, created from the pinned
image), then prints one line per artefact:

```
OK        image ghcr.io/soqlab/morrow:1.2.3 sha256:...
OK        image ghcr.io/soqlab/morrow:1.2.3-api sha256:...
OK        IMAGES.txt ...
OK        morrow-1.2.3-image.cdx.json ...
OK        morrow-1.2.3-api-image.cdx.json ...
OK        morrow-1.2.3-python.cdx.json ...
OK        morrow-offline-1.2.3.tar.gz ...
```

Exit status 0 means every published file was rebuilt byte for byte. The rebuilt files are in
`dist/reproduce-1.2.3/build/`. The offline bundle is rebuilt from the image you built, not from the
published one, so nothing published is reused.

To rebuild a single piece instead:

```sh
export MORROW_REF=v1.2.3
sh scripts/release/build-image.sh api 1.2.3            # prints ghcr.io/soqlab/morrow:1.2.3-api@sha256:...
docker buildx imagetools inspect ghcr.io/soqlab/morrow:1.2.3-api   # Digest: must be the same
sh scripts/release/sboms.sh python 1.2.3 morrow-1.2.3-python.cdx.json
sha256sum morrow-1.2.3-python.cdx.json                 # compare with the release's SHA256SUMS
```

The same check runs in CI. `.github/workflows/reproduce.yml` runs after every release, on a fresh
runner, from the tag. Each mismatch becomes an `::error` annotation and fails the run. To run it on
any tag:

```sh
gh workflow run reproduce.yml --repo soqlab/Morrow -f tag=v1.2.3
```

### When something does not match

The images are OCI archives (`*.oci.tar`), so you can compare them layer by layer:

```sh
# Which blob differs? Each manifest lists the config and layer digests.
for f in a/morrow-1.2.3.oci.tar b/morrow-1.2.3.oci.tar; do
  tar -xOf "$f" index.json; echo
done
# Everything, recursively, down to the file inside the layer:
diffoscope a/morrow-1.2.3.oci.tar b/morrow-1.2.3.oci.tar
```

A different config with identical layers usually points to the time or the labels. A different
layer points to the `RUN` that made it. Look up the layer's position in the manifest, and the
matching history entry in the config tells you which step made it.

## Signatures

Reproducing a release shows that the source produces the published bytes. The Sigstore attestations
show that this repository's release workflow published them. The two checks are independent and you
can use either. For the attestations:

```sh
# GitHub CLI 2.49 or later
gh attestation verify oci://ghcr.io/soqlab/morrow:1.2.3 \
  --repo soqlab/Morrow \
  --signer-workflow soqlab/Morrow/.github/workflows/release.yml \
  --source-ref refs/tags/v1.2.3
gh attestation verify morrow-offline-1.2.3.tar.gz --repo soqlab/Morrow \
  --signer-workflow soqlab/Morrow/.github/workflows/release.yml

# Or cosign 2.5 or later: the same attestation, with the workflow identity spelled out
cosign verify-attestation ghcr.io/soqlab/morrow@sha256:<digest from IMAGES.txt> \
  --new-bundle-format --type slsaprovenance1 \
  --certificate-identity "https://github.com/soqlab/Morrow/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# The signed SBOM: --type cyclonedx
```

A digest that `reproduce.sh` rebuilt and that also passes `gh attestation verify` is a strong
result. It means this source produced that image, and this workflow published it.

## What is not reproducible, and why

- **Releases before this change (v0.7.0 and earlier).** Those tags were built with floating base
  images, unpinned Debian and Python transitives, `docker save`, and random SBOM serial numbers. Their
  digests cannot be rebuilt, and `reproduce.sh v0.7.0` reports a mismatch on every line. The first
  reproducible release is the first tag cut after this change.
- **Only with the pins of that commit.** A different BuildKit can compress layers differently, and a
  different syft can find packages differently. A release reproduces with the tools pinned in its own
  `scripts/release/pins.sh`. That is why you check out the tag first.
- **The services the build reads from.** The build fetches from `snapshot.debian.org`, PyPI (by
  hash), GitHub (OpenTofu, by checksum) and Docker Hub (by digest). If one of them deletes what was
  pinned, the rebuild fails loudly. It never quietly builds something else. `snapshot.debian.org` is
  slow and sometimes rate-limited, so retry if apt times out.
- **Only linux/amd64.** Both Dockerfiles download the amd64 OpenTofu binary. On an arm64 machine the
  build runs under emulation, which is slow but gives the same bytes.
- **Not the attestations themselves.** Each Sigstore signature has its own certificate and
  transparency-log timestamp, so no two signatures are alike. What they sign (the digests) is
  reproducible.
- **A `docker build` without the script.** A plain `docker build` (Render, `docker compose build`,
  security.yml) gets the same pinned inputs, but not the fixed epoch, the clean context or the
  timestamp rewrite. Its image works the same, but its digest differs. Only
  `scripts/release/build-image.sh` builds the reproducible image.
- **Lock regeneration.** `scripts/release/lock-requirements.sh` resolves unpinned transitives to the
  newest release at the time you run it. The locks are reproducible as files, but rerunning the
  generator later can change them. That is an upgrade, and it should be reviewed like one.
  `scripts/release/check_locks.py`, run by the release workflow, only checks that every pin in a
  `.txt` file is in its lock.
