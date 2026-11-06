#!/bin/sh
# Builds one release image reproducibly. release.yml runs this to publish, .github/workflows/
# reproduce.yml runs it to check a published release, and you can run it to check one yourself
# (docs/REPRODUCIBLE_BUILDS.md). The same commit gives the same image digest every time.
#
#   sh scripts/release/build-image.sh <all-in-one|api> <version> [--push]
#
#   all-in-one  deploy/render-hosted/Dockerfile, context: the repository  -> $IMAGE:<version>
#   api         backend/Dockerfile,             context: backend/         -> $IMAGE:<version>-api
#
# Writes, in $OUT_DIR (default dist/repro):
#   morrow-<version>[-api].oci.tar   the image as an OCI archive (what syft and the bundle read)
#   digest-<variant>.txt             its manifest digest, the one a registry shows
# With --push it also pushes the image to $IMAGE (you must be logged in).
#
# Environment:
#   MORROW_REF   commit or tag to build (default HEAD). Uncommitted changes are never built: the
#                context is `git archive` of that commit, which also fixes file modes and line
#                endings whatever the checkout's settings (core.autocrlf, umask).
#   IMAGE        image name (default ghcr.io/soqlab/morrow)
#   MORROW_SOURCE_URL  org.opencontainers.image.source label (default https://github.com/soqlab/Morrow)
#   OUT_DIR      output folder (default dist/repro)
#   BUILDER      buildx builder to use; created from the pinned BuildKit if it does not exist
#                (default morrow-repro).
#
# Needs: git, Docker with buildx 0.13 or later, a Linux or macOS shell (on Windows use WSL: a
# Windows build context does not carry Unix file modes).
set -eu
usage() { echo "usage: $0 <all-in-one|api> <version> [--push]" >&2; exit 2; }
[ $# -ge 2 ] || usage
variant="$1"; version="$2"; push="${3:-}"
case "$push" in ""|--push) ;; *) usage ;; esac

root="$(cd "$(dirname "$0")/../.." && pwd)"
. "$root/scripts/release/pins.sh"

image="${IMAGE:-ghcr.io/soqlab/morrow}"
source_url="${MORROW_SOURCE_URL:-https://github.com/soqlab/Morrow}"
out="${OUT_DIR:-$root/dist/repro}"
builder="${BUILDER:-morrow-repro}"
commit="$(git -C "$root" rev-parse --verify "${MORROW_REF:-HEAD}^{commit}")"

case "$variant" in
  all-in-one) dockerfile=deploy/render-hosted/Dockerfile; subdir=""; suffix="" ;;
  api)        dockerfile=Dockerfile;                      subdir=backend; suffix="-api" ;;
  *) usage ;;
esac

# Every timestamp in the image comes from the commit, not from the clock.
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct "$commit")"
export SOURCE_DATE_EPOCH

mkdir -p "$out"
out="$(cd "$out" && pwd)"
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT INT TERM
# tar.umask=0022: files 0644, executables 0755, as a Linux checkout has them. git archive of a
# commit stamps every entry with the commit time.
git -C "$root" -c tar.umask=0022 -c core.autocrlf=false archive --format=tar "$commit" ${subdir:+"$subdir"} \
  | tar -xpf - -C "$ctx"
context="$ctx${subdir:+/$subdir}"

if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
  docker buildx create --name "$builder" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
fi

ref="$image:$version$suffix"
archive="$out/morrow-$version$suffix.oci.tar"
meta="$out/morrow-$version$suffix.metadata.json"
# rewrite-timestamp: every file in the new layers gets an mtime no later than SOURCE_DATE_EPOCH.
# oci-mediatypes on both outputs so the archive and the pushed image have the same manifest.
# No provenance or SBOM from buildx: they carry build-machine details and the release signs its
# own (release.yml). --no-cache: a check of reproducibility must not reuse an earlier build.
set -- --output "type=oci,dest=$archive,name=$ref,rewrite-timestamp=true,oci-mediatypes=true"
if [ "$push" = "--push" ]; then
  set -- "$@" --output "type=image,name=$ref,push=true,rewrite-timestamp=true,oci-mediatypes=true"
fi

echo "Building $ref from $commit (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)" >&2
docker buildx build \
  --builder "$builder" \
  --platform linux/amd64 \
  --file "$context/$dockerfile" \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --label "org.opencontainers.image.source=$source_url" \
  --label "org.opencontainers.image.revision=$commit" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.licenses=AGPL-3.0-only" \
  --label "org.opencontainers.image.title=morrow$suffix" \
  --provenance=false --sbom=false \
  --no-cache \
  --metadata-file "$meta" \
  "$@" \
  "$context"

digest="$(sed -n 's/.*"containerimage.digest": *"\(sha256:[0-9a-f]*\)".*/\1/p' "$meta" | head -1)"
[ -n "$digest" ] || { echo "No image digest in $meta" >&2; exit 1; }
echo "$digest" > "$out/digest-$variant.txt"
echo "$ref@$digest"
