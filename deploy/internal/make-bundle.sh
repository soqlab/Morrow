#!/bin/sh
# Builds the offline bundle: one file a company copies into its network and installs with no
# internet access. Run on a machine WITH internet, from anywhere in the repository:
#   sh deploy/internal/make-bundle.sh
# Output: dist/morrow-offline-<date>-<commit>.tar.gz containing the images and this folder.
#
# Optional environment (used by .github/workflows/release.yml):
#   MORROW_IMAGE            bundle this already-published image (e.g. ghcr.io/soqlab/morrow@sha256:...)
#                           instead of building one, so the bundle holds the exact signed image.
#   MORROW_BUNDLE_VERSION   version string for the file name and VERSION (default: <date>-<commit>).
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

version="${MORROW_BUNDLE_VERSION:-$(date +%Y.%m.%d)-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
name="morrow-offline-$version"
work="dist/$name"
rm -rf "$work"
mkdir -p "$work"

if [ -n "${MORROW_IMAGE:-}" ]; then
  echo "Using published image $MORROW_IMAGE as morrow:offline ($version)..."
  docker pull --platform linux/amd64 "$MORROW_IMAGE"
  docker tag "$MORROW_IMAGE" morrow:offline
  docker tag "$MORROW_IMAGE" "morrow:$version"
else
  echo "Building morrow:offline ($version)..."
  docker build --platform linux/amd64 -f deploy/render-hosted/Dockerfile -t morrow:offline -t "morrow:$version" .
fi
docker pull --platform linux/amd64 caddy:2-alpine

# Refuse to package local secrets or databases (an image is a file people copy around).
leak_check() {
  found="$(docker run --rm --entrypoint sh "$1" -c "find /app \( -name '.env' -o -name '*.db' -o -name '*.sqlite*' \) 2>/dev/null | head -5")"
  if [ -n "$found" ]; then echo "Refusing to bundle $1: it contains $found" >&2; exit 1; fi
}
leak_check morrow:offline

echo "Saving images..."
docker save morrow:offline caddy:2-alpine | gzip > "$work/images.tar.gz"

for f in compose.yml Caddyfile morrow.env.example setup.sh README.md; do
  cp "deploy/internal/$f" "$work/"
done
cp LICENSE "$work/LICENSE"
echo "$version" > "$work/VERSION"
(cd "$work" && sha256sum images.tar.gz > SHA256SUMS)

tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "$work"
echo "Done: dist/$name.tar.gz"
