#!/bin/sh
# Builds the offline bundle: one file a company copies into its network and installs with no
# internet access. Run on a machine WITH internet, from anywhere in the repository:
#   sh deploy/internal/make-bundle.sh
# Output: dist/morrow-offline-<version>.tar.gz containing the images and this folder.
#
# The bundle is reproducible: the same commit and the same images give the same file, byte for
# byte (docs/REPRODUCIBLE_BUILDS.md). The images are written from their registry blobs, not with
# `docker save` (whose output depends on the Docker version and storage driver), and the archive
# is assembled inside the pinned Python image with fixed names, order, owners and times (the
# commit time).
#
# Optional environment (used by .github/workflows/release.yml and reproduce.yml):
#   MORROW_IMAGE            bundle this already-published image (registry/name@sha256:...) instead
#                           of building one, so the bundle holds the exact signed image.
#   MORROW_OCI_ARCHIVE      bundle this image archive from scripts/release/build-image.sh instead.
#   MORROW_BUNDLE_VERSION   version string for the file name and VERSION
#                           (default: <commit date>-<short commit>).
#   MORROW_REGISTRY_USER, MORROW_REGISTRY_PASSWORD  credentials for a private MORROW_IMAGE.
#   MORROW_REF              commit or tag whose files and time go into the bundle (default HEAD).
# With neither image variable set, the image is built from MORROW_REF with build-image.sh.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
. scripts/release/pins.sh

commit="$(git rev-parse --verify "${MORROW_REF:-HEAD}^{commit}")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct "$commit")}"
export SOURCE_DATE_EPOCH
if [ -z "${MORROW_BUNDLE_VERSION:-}" ]; then
  day="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y.%m.%d 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" +%Y.%m.%d)"
  MORROW_BUNDLE_VERSION="$day-$(git rev-parse --short "$commit")"
fi
version="$MORROW_BUNDLE_VERSION"
name="morrow-offline-$version"
mkdir -p dist
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT INT TERM
mkdir -p "$stage/in/files"

if [ -n "${MORROW_IMAGE:-}" ]; then
  echo "Using published image $MORROW_IMAGE as morrow:offline ($version)..." >&2
  morrow_source="registry:$MORROW_IMAGE"
else
  archive="${MORROW_OCI_ARCHIVE:-}"
  if [ -z "$archive" ]; then
    echo "Building morrow:offline ($version)..." >&2
    MORROW_REF="$commit" OUT_DIR="$stage/build" sh scripts/release/build-image.sh all-in-one "$version" >&2
    archive="$stage/build/morrow-$version.oci.tar"
  fi
  cp "$archive" "$stage/in/morrow.oci.tar"
  morrow_source="oci-archive:/w/in/morrow.oci.tar"
fi

# The files come from the commit, not the working tree, so uncommitted edits and a Windows
# checkout's CRLF line endings cannot change the bundle. Everything travels to the container on
# stdin (no bind mounts, so this also works against a remote Docker daemon).
for f in compose.yml Caddyfile morrow.env.example setup.sh README.md; do
  git show "$commit:deploy/internal/$f" > "$stage/in/files/$f"
done
git show "$commit:LICENSE" > "$stage/in/files/LICENSE"
git show "$commit:scripts/release/oci_bundle.py" > "$stage/in/oci_bundle.py"

tar -C "$stage" -cf - in \
  | docker run --rm -i \
      -e SOURCE_DATE_EPOCH -e MORROW_REGISTRY_USER -e MORROW_REGISTRY_PASSWORD \
      -e NAME="$name" -e VERSION="$version" -e MORROW_SOURCE="$morrow_source" \
      -e CADDY_SOURCE="registry:$CADDY_IMAGE" \
      "$PYTHON_IMAGE" sh -euc '
        mkdir /w && cd /w && tar -xf -
        work="/w/out/$NAME"
        mkdir -p "$work"
        python -I in/oci_bundle.py --out /w/images.tar --leak-check morrow:offline \
          "morrow:offline=$MORROW_SOURCE" "caddy:2-alpine=$CADDY_SOURCE" >&2
        gzip -n -c /w/images.tar > "$work/images.tar.gz"
        cp in/files/* "$work/"
        printf "%s\n" "$VERSION" > "$work/VERSION"
        (cd "$work" && sha256sum images.tar.gz > SHA256SUMS)
        chmod 0755 "$work" && chmod 0644 "$work"/* && chmod 0755 "$work/setup.sh"
        tar -C /w/out --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
            --owner=0 --group=0 --numeric-owner --format=gnu -cf - "$NAME" \
          | gzip -n
      ' > "dist/$name.tar.gz.tmp"
mv "dist/$name.tar.gz.tmp" "dist/$name.tar.gz"
echo "Done: dist/$name.tar.gz"
