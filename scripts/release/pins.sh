# Pinned tools for the reproducible release scripts in this folder (sourced, not run).
# Each image is pinned by digest: a tag can be moved, a digest cannot. The comment names the tag.
# Bump them deliberately: a different BuildKit or syft can produce different bytes from the same
# source, so a release can only be reproduced with the pins of the commit it was built from.

# moby/buildkit:v0.34.2. Runs the image builds (scripts/release/build-image.sh).
BUILDKIT_IMAGE="moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"
# python:3.11.18-slim-trixie. Assembles the offline bundle and the Python SBOM, and generates the
# locks. The same digest as the FROM line of both Dockerfiles.
PYTHON_IMAGE="python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79"
# anchore/syft:v1.57.0. Writes the image SBOMs.
SYFT_IMAGE="anchore/syft:v1.57.0@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a"
# caddy:2.11.9-alpine, linux/amd64 manifest. The reverse proxy shipped in the offline bundle
# (deploy/internal/compose.yml runs it as caddy:2-alpine).
CADDY_IMAGE="docker.io/library/caddy@sha256:fc9cbc100585871d18d4e451cca7021785c90a7006087427ae5ceb3e4efe6424"
# uv, used only to write the lock files (scripts/release/lock-requirements.sh).
UV_VERSION="0.13.7"
