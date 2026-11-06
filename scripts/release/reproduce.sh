#!/bin/sh
# Rebuilds a published release from source and checks that every file is byte-identical to what
# was published: both image digests, the three SBOMs and the offline bundle.
#
#   git checkout vX.Y.Z            # the scripts and pins of the release you are checking
#   sh scripts/release/reproduce.sh vX.Y.Z
#
# It downloads IMAGES.txt and SHA256SUMS from the GitHub release (nothing else: the comparison is
# against the published digests, the images themselves are never pulled), rebuilds everything
# locally with --no-cache, and prints one line per file. Exit status 0 means everything matched.
# Under GitHub Actions each mismatch is also an ::error annotation (.github/workflows/reproduce.yml).
#
# Environment: MORROW_REPO (default soqlab/Morrow), OUT_DIR (default dist/reproduce-X.Y.Z), and
# PUBLISHED_DIR to compare against IMAGES.txt and SHA256SUMS you already have instead of
# downloading them. Needs git, curl, Docker with buildx, and a Linux or macOS shell.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <tag>" >&2; exit 2; }
tag="$1"
version="${tag#v}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
repo="${MORROW_REPO:-soqlab/Morrow}"
out="${OUT_DIR:-dist/reproduce-$version}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
image="ghcr.io/soqlab/morrow"

commit="$(git rev-parse --verify "$tag^{commit}")"
head="$(git rev-parse HEAD)"
if [ "$commit" != "$head" ]; then
  echo "warning: HEAD is not $tag; the build scripts and pins come from HEAD ($head)" >&2
fi
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")"
export SOURCE_DATE_EPOCH MORROW_REF="$commit"

published="${PUBLISHED_DIR:-$out/published}"
if [ -z "${PUBLISHED_DIR:-}" ]; then
  mkdir -p "$published"
  for f in IMAGES.txt SHA256SUMS; do
    curl -fsSL "https://github.com/$repo/releases/download/$tag/$f" -o "$published/$f"
  done
fi

# --- rebuild -------------------------------------------------------------------------------------
build="$out/build"
mkdir -p "$build"
OUT_DIR="$build" sh scripts/release/build-image.sh all-in-one "$version" >&2
OUT_DIR="$build" sh scripts/release/build-image.sh api "$version" >&2
sh scripts/release/sboms.sh image "$build/morrow-$version.oci.tar" "$image" "$version" \
  "$build/morrow-$version-image.cdx.json"
sh scripts/release/sboms.sh image "$build/morrow-$version-api.oci.tar" "$image" "$version-api" \
  "$build/morrow-$version-api-image.cdx.json"
sh scripts/release/sboms.sh python "$version" "$build/morrow-$version-python.cdx.json"
# The bundle from the rebuilt image, not the published one: nothing published is trusted.
MORROW_OCI_ARCHIVE="$build/morrow-$version.oci.tar" MORROW_BUNDLE_VERSION="$version" \
  sh deploy/internal/make-bundle.sh >&2
mv "dist/morrow-offline-$version.tar.gz" "$build/"
{
  echo "$image:$version@$(cat "$build/digest-all-in-one.txt")"
  echo "$image:$version-api@$(cat "$build/digest-api.txt")"
} > "$build/IMAGES.txt"

# --- compare -------------------------------------------------------------------------------------
fail=0
report() {  # report <OK|MISMATCH|MISSING> <what> <expected> <got>
  printf '%-9s %s\n' "$1" "$2"
  if [ "$1" != OK ]; then
    printf '          published %s\n          rebuilt   %s\n' "$3" "$4"
    fail=1
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      echo "::error title=Release $tag is not reproducible::$2: published $3, rebuilt $4"
    fi
  fi
}
sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

echo
echo "Release $tag ($commit), SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
for v in "$version" "$version-api"; do
  expected="$(grep -F "$image:$v@" "$published/IMAGES.txt" | sed 's/.*@//' || true)"
  got="$(grep -F "$image:$v@" "$build/IMAGES.txt" | sed 's/.*@//')"
  if [ -z "$expected" ]; then report MISSING "image $image:$v" "(not in IMAGES.txt)" "$got"
  elif [ "$expected" = "$got" ]; then report OK "image $image:$v $got" "" ""
  else report MISMATCH "image $image:$v" "$expected" "$got"; fi
done
for f in IMAGES.txt "morrow-$version-image.cdx.json" "morrow-$version-api-image.cdx.json" \
         "morrow-$version-python.cdx.json" "morrow-offline-$version.tar.gz"; do
  expected="$(awk -v f="$f" '$2 == f || $2 == "*"f { print $1 }' "$published/SHA256SUMS")"
  got="$(sha "$build/$f")"
  if [ -z "$expected" ]; then report MISSING "$f" "(not in SHA256SUMS)" "$got"
  elif [ "$expected" = "$got" ]; then report OK "$f $got" "" ""
  else report MISMATCH "$f" "$expected" "$got"; fi
done
echo
if [ "$fail" -ne 0 ]; then
  echo "NOT reproducible. The rebuilt files are in $build; docs/REPRODUCIBLE_BUILDS.md has how to diff them." >&2
  exit 1
fi
echo "Reproducible: every published file was rebuilt byte for byte."
