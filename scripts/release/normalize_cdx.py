"""Make a CycloneDX JSON SBOM byte-for-byte reproducible.

    python -I normalize_cdx.py <subject> < in.cdx.json > out.cdx.json

SBOM generators stamp every run with a random serial number and the current time, so two runs over
the same image differ even when they found exactly the same packages. This replaces both with values
derived from the input (SOURCE_DATE_EPOCH and <subject>, e.g. the image digest), sorts the component
and dependency lists so their order cannot depend on the order the generator walked the files in,
and writes the JSON with fixed formatting.

Nothing else is changed: every component, hash, licence and property the generator found is kept.
Standard library only; scripts/release/sboms.sh runs it inside the pinned Python image.
"""

import json
import os
import sys
import time
import uuid


def _component_key(c):
    return (
        str(c.get("type", "")),
        str(c.get("name", "")),
        str(c.get("version", "")),
        str(c.get("purl", "")),
        str(c.get("bom-ref", "")),
    )


def _sort_components(components):
    for c in components:
        if isinstance(c.get("components"), list):
            _sort_components(c["components"])
    components.sort(key=_component_key)


def normalize(bom, subject, epoch):
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, subject))
    meta = bom.setdefault("metadata", {})
    meta["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    if isinstance(bom.get("components"), list):
        _sort_components(bom["components"])
    if isinstance(bom.get("dependencies"), list):
        for d in bom["dependencies"]:
            if isinstance(d.get("dependsOn"), list):
                d["dependsOn"] = sorted(set(d["dependsOn"]))
        bom["dependencies"].sort(key=lambda d: str(d.get("ref", "")))
    return bom


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: normalize_cdx.py <subject> < in.cdx.json > out.cdx.json")
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch or not epoch.isdigit():
        sys.exit("SOURCE_DATE_EPOCH must be set to the commit time")
    bom = json.load(sys.stdin)
    out = normalize(bom, sys.argv[1], int(epoch))
    sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=False, sort_keys=False) + "\n")


if __name__ == "__main__":
    main()
