"""Say exactly where two builds of the same image differ.

    python -I scripts/release/diff_oci.py a.oci.tar b.oci.tar

Compares the manifests, then the image configs key by key, then each layer that differs entry by
entry (name, type, mode, owner, mtime, size, content hash, link target). Prints at most 60 lines
per layer. Exit status 0 when the manifests are identical, 1 otherwise. Standard library only.
"""

import gzip
import hashlib
import io
import json
import sys
import tarfile


def load(path):
    tar = tarfile.open(path)
    blob = lambda d: tar.extractfile("blobs/" + d.replace(":", "/")).read()  # noqa: E731
    index = json.loads(tar.extractfile("index.json").read())
    mdigest = index["manifests"][0]["digest"]
    manifest = json.loads(blob(mdigest))
    config = json.loads(blob(manifest["config"]["digest"]))
    return tar, blob, mdigest, manifest, config


def entries(data):
    raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as t:
        for m in t:
            h = ""
            if m.isfile():
                h = hashlib.sha256(t.extractfile(m).read()).hexdigest()[:16]
            out[m.name] = (m.type, oct(m.mode), m.uid, m.gid, m.uname, m.gname, m.mtime, m.size, h,
                           m.linkname, sorted(m.pax_headers.items()))
    return out, hashlib.sha256(raw).hexdigest()


def flat(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flat(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from flat(v, f"{prefix}[{i}]")
    else:
        yield prefix, obj


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a = load(sys.argv[1])
    b = load(sys.argv[2])
    print(f"manifest A {a[2]}\nmanifest B {b[2]}")
    if a[2] == b[2]:
        print("identical")
        return 0
    ca, cb = dict(flat(a[4])), dict(flat(b[4]))
    for k in sorted(set(ca) | set(cb)):
        if ca.get(k) != cb.get(k):
            print(f"config {k}: A={ca.get(k)!r} B={cb.get(k)!r}")
    la, lb = a[3]["layers"], b[3]["layers"]
    if len(la) != len(lb):
        print(f"layer count differs: {len(la)} vs {len(lb)}")
    for i, (x, y) in enumerate(zip(la, lb)):
        if x["digest"] == y["digest"]:
            continue
        ea, ua = entries(a[1](x["digest"]))
        eb, ub = entries(b[1](y["digest"]))
        same_content = ua == ub
        print(f"layer {i}: {x['digest']} vs {y['digest']}"
              + (" (same uncompressed tar: compression differs)" if same_content else ""))
        if same_content:
            continue
        shown = 0
        for name in sorted(set(ea) | set(eb)):
            if ea.get(name) != eb.get(name):
                print(f"  {name}\n    A {ea.get(name)}\n    B {eb.get(name)}")
                shown += 1
                if shown >= 60:
                    print("  ... (more)")
                    break
        names_a, names_b = list(ea), list(eb)
        if shown == 0 and names_a != names_b:
            print("  same entries, different order")
    return 1


if __name__ == "__main__":
    sys.exit(main())
