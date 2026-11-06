#!/bin/sh
# Writes the release SBOMs reproducibly: the same inputs give the same file, byte for byte.
#
#   sh scripts/release/sboms.sh image  <image.oci.tar> <image-name> <version> <out.cdx.json>
#       CycloneDX SBOM of an image archive from build-image.sh, by the pinned syft.
#   sh scripts/release/sboms.sh python <version> <out.cdx.json>
#       CycloneDX SBOM of the Python environment backend/requirements.lock installs, by the
#       pinned cyclonedx-bom, in a clean venv inside the pinned Python image.
#
# Both are then passed through normalize_cdx.py, which replaces the random serial number and the
# wall-clock timestamp with values derived from the input and SOURCE_DATE_EPOCH (default: the time
# of the commit MORROW_REF, or HEAD).
#
# Files move in and out of the containers with `docker cp` and pipes, never bind mounts, so this
# works the same against a remote Docker daemon or from inside a container.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
. "$root/scripts/release/pins.sh"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct "${MORROW_REF:-HEAD}")"
fi
export SOURCE_DATE_EPOCH

normalize() {  # normalize <subject> < raw > normalized
  docker run --rm -i --network none -e SOURCE_DATE_EPOCH "$PYTHON_IMAGE" \
    python -I -c "$(cat "$root/scripts/release/normalize_cdx.py")" "$1"
}

case "${1:-}" in
  image)
    [ $# -eq 5 ] || { echo "usage: $0 image <image.oci.tar> <image-name> <version> <out>" >&2; exit 2; }
    archive="$2"; name="$3"; version="$4"; dest="$5"
    # The subject of the serial number is the image's manifest digest, from the archive itself.
    digest="$(tar -xOf "$archive" index.json | sed -n 's/.*"digest":"\(sha256:[0-9a-f]*\)".*/\1/p' | head -1)"
    [ -n "$digest" ] || { echo "No manifest digest in $archive" >&2; exit 1; }
    cid="$(docker create --network none "$SYFT_IMAGE" scan oci-archive:/image.oci.tar \
            -o cyclonedx-json --source-name "$name" --source-version "$version" -q)"
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT INT TERM
    docker cp "$archive" "$cid:/image.oci.tar" >/dev/null
    docker start -a "$cid" | normalize "$name@$digest" > "$dest"
    ;;
  python)
    [ $# -eq 3 ] || { echo "usage: $0 python <version> <out>" >&2; exit 2; }
    version="$2"; dest="$3"
    tar -C "$root" -cf - backend/requirements-bootstrap.lock backend/requirements.lock \
        scripts/release/sbom-tools.lock \
      | docker run --rm -i "$PYTHON_IMAGE" sh -euc '
          mkdir /w && cd /w && tar -xf -
          pipi() { "$1" -m pip install --quiet --no-cache-dir --disable-pip-version-check \
                     --require-hashes --only-binary :all: --no-deps -r "$2" >&2; }
          # The runtime environment holds only the lock, so the SBOM lists the full closure and
          # nothing from the tooling.
          python -m venv /tmp/runtime
          pipi /tmp/runtime/bin/python backend/requirements-bootstrap.lock
          pipi /tmp/runtime/bin/python backend/requirements.lock
          /tmp/runtime/bin/python -m pip check >&2
          python -m venv /tmp/tools
          pipi /tmp/tools/bin/python scripts/release/sbom-tools.lock
          /tmp/tools/bin/cyclonedx-py environment --of JSON --output-reproducible \
            -o - /tmp/runtime/bin/python
        ' \
      | normalize "morrow-python@$version" > "$dest"
    ;;
  *)
    echo "usage: $0 image <image.oci.tar> <image-name> <version> <out> | python <version> <out>" >&2
    exit 2
    ;;
esac
echo "wrote $dest ($(wc -c < "$dest") bytes)" >&2
