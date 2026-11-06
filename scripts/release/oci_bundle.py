"""Write a `docker load` archive of several images, byte-for-byte reproducibly.

    python -I oci_bundle.py --out images.tar [--leak-check TAG] TAG=SOURCE [TAG=SOURCE ...]

    TAG     the name `docker load` gives the image, e.g. morrow:offline
    SOURCE  oci-archive:<path>     an archive from scripts/release/build-image.sh
            registry:<name@sha256:...>  an image in a registry, by manifest digest

`docker save` cannot be used for a reproducible bundle: what it writes depends on the Docker
version and storage driver (the classic store re-tars every layer uncompressed, the containerd
store writes the registry blobs), and it stamps the archive with the time of the save. This writes
the registry blobs themselves, each checked against its digest, into a tar with fixed names, order,
owners, modes and times (SOURCE_DATE_EPOCH). The layout is the one `docker save` has written since
Docker 25 -- an OCI image layout plus a manifest.json -- so both the containerd store and the
classic store load it, on Docker versions old and new.

Registry credentials, when the image is private: MORROW_REGISTRY_USER and MORROW_REGISTRY_PASSWORD
(sent only to MORROW_REGISTRY_HOST, default ghcr.io). Public images need none.

Standard library only; deploy/internal/make-bundle.sh runs it inside the pinned Python image.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

INDEX = ("application/vnd.oci.image.index.v1+json",
         "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST = ("application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json")
ACCEPT = ",".join(MANIFEST + INDEX)


class BlobStore:
    """Content-addressed blobs on disk; every write is checked against its digest."""

    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def file(self, digest):
        algo, hexd = digest.split(":", 1)
        if algo != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", hexd):
            raise SystemExit(f"unsupported digest {digest}")
        return os.path.join(self.path, hexd)

    def has(self, digest):
        return os.path.exists(self.file(digest))

    def put_stream(self, digest, stream):
        dest = self.file(digest)
        h = hashlib.sha256()
        with tempfile.NamedTemporaryFile(dir=self.path, delete=False) as tmp:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                h.update(chunk)
                tmp.write(chunk)
        if "sha256:" + h.hexdigest() != digest:
            os.unlink(tmp.name)
            raise SystemExit(f"digest mismatch for {digest}: got sha256:{h.hexdigest()}")
        os.replace(tmp.name, dest)

    def read(self, digest):
        with open(self.file(digest), "rb") as f:
            return f.read()


# --- sources -------------------------------------------------------------------------------------

def from_oci_archive(path, store):
    """Copy the one image in an OCI archive into the store; return (manifest digest, media type)."""
    with tarfile.open(path) as tar:
        def member(name):
            f = tar.extractfile(name)
            if f is None:
                raise SystemExit(f"{path}: {name} missing")
            return f
        index = json.load(member("index.json"))
        manifests = index.get("manifests", [])
        if len(manifests) != 1:
            raise SystemExit(f"{path}: expected one image, found {len(manifests)}")
        desc = manifests[0]
        if desc.get("mediaType") not in MANIFEST:
            raise SystemExit(f"{path}: {desc.get('mediaType')} is not a single-platform image")
        digest = desc["digest"]
        blob = lambda d: member("blobs/" + d.replace(":", "/"))  # noqa: E731
        store.put_stream(digest, blob(digest))
        manifest = json.loads(store.read(digest))
        for d in [manifest["config"]] + manifest["layers"]:
            if not store.has(d["digest"]):
                store.put_stream(d["digest"], blob(d["digest"]))
        return digest, desc["mediaType"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Registry:
    def __init__(self, host):
        self.host = host
        self.api = "registry-1.docker.io" if host in ("docker.io", "index.docker.io") else host
        self.token = None
        self.opener = urllib.request.build_opener(_NoRedirect)

    def _basic(self):
        if self.host != os.environ.get("MORROW_REGISTRY_HOST", "ghcr.io"):
            return None
        user = os.environ.get("MORROW_REGISTRY_USER")
        password = os.environ.get("MORROW_REGISTRY_PASSWORD")
        if not user or not password:
            return None
        return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def _authenticate(self, challenge):
        m = re.match(r"\s*Bearer\s+(.*)", challenge or "", re.I)
        if not m:
            raise SystemExit(f"{self.host}: unsupported auth challenge {challenge!r}")
        params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        query = {k: v for k, v in params.items() if k in ("service", "scope")}
        req = urllib.request.Request(params["realm"] + "?" + urllib.parse.urlencode(query))
        basic = self._basic()
        if basic:
            req.add_unredirected_header("Authorization", basic)
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.load(r)
        self.token = body.get("token") or body.get("access_token")

    def get(self, repo, kind, ref, accept=None):
        url = f"https://{self.api}/v2/{repo}/{kind}/{ref}"
        for _ in range(3):
            req = urllib.request.Request(url)
            if accept:
                req.add_header("Accept", accept)
            if self.token:
                # Unredirected: blob downloads redirect to object storage, which must not get it.
                req.add_unredirected_header("Authorization", "Bearer " + self.token)
            try:
                return self.opener.open(req, timeout=300)
            except urllib.error.HTTPError as e:
                if e.code == 401 and self.token is None:
                    self._authenticate(e.headers.get("WWW-Authenticate"))
                    continue
                if e.code in (301, 302, 303, 307, 308):
                    url = urllib.parse.urljoin(url, e.headers["Location"])
                    return urllib.request.urlopen(url, timeout=300)
                raise SystemExit(f"GET {url}: HTTP {e.code}")
        raise SystemExit(f"GET {url}: not authorised")


def from_registry(ref, store):
    m = re.fullmatch(r"([^/]+\.[^/]+|localhost(?::\d+)?)/(.+)@(sha256:[0-9a-f]{64})", ref)
    if not m:
        raise SystemExit(f"{ref}: give the image as registry/name@sha256:<digest>")
    host, repo, digest = m.groups()
    if host == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    reg = Registry(host)
    with reg.get(repo, "manifests", digest, ACCEPT) as r:
        media_type = r.headers.get("Content-Type", "").split(";")[0]
        store.put_stream(digest, r)
    if media_type in INDEX:
        raise SystemExit(f"{ref} is a multi-platform index; pin the linux/amd64 manifest digest")
    if media_type not in MANIFEST:
        media_type = json.loads(store.read(digest)).get("mediaType", MANIFEST[0])
    manifest = json.loads(store.read(digest))
    for d in [manifest["config"]] + manifest["layers"]:
        if not store.has(d["digest"]):
            with reg.get(repo, "blobs", d["digest"]) as r:
                store.put_stream(d["digest"], r)
    return digest, media_type


# --- checks and output ---------------------------------------------------------------------------

LEAK = re.compile(r"(^|/)\.env$|\.db$|\.sqlite[^/]*$")


def leak_check(tag, manifest, store):
    """Refuse to bundle local secrets or databases (an image is a file people copy around)."""
    found = []
    for layer in manifest["layers"]:
        with tarfile.open(store.file(layer["digest"]), "r:*") as tar:
            for info in tar:
                name = info.name.lstrip("./")
                if name.startswith("app/") and info.isfile() and LEAK.search(name):
                    found.append("/" + name)
    if found:
        raise SystemExit(f"Refusing to bundle {tag}: it contains {', '.join(sorted(found)[:5])}")


def _add(tar, name, epoch, data=None, path=None):
    info = tarfile.TarInfo(name)
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    if data is None and path is None:
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        tar.addfile(info)
        return
    info.mode = 0o644
    if path is not None:
        info.size = os.path.getsize(path)
        with open(path, "rb") as f:
            tar.addfile(info, f)
    else:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def write_archive(out, images, store, epoch):
    """images: list of (tag, manifest digest, media type)."""
    index = {"schemaVersion": 2, "mediaType": INDEX[0], "manifests": []}
    legacy = []
    blobs = set()
    for tag, digest, media_type in images:
        manifest = json.loads(store.read(digest))
        name, _, version = tag.rpartition(":")
        full = name if "/" in name else "docker.io/library/" + name
        index["manifests"].append({
            "mediaType": media_type,
            "digest": digest,
            "size": os.path.getsize(store.file(digest)),
            "annotations": {
                "io.containerd.image.name": f"{full}:{version}",
                "org.opencontainers.image.ref.name": version,
            },
        })
        legacy.append({
            "Config": "blobs/" + manifest["config"]["digest"].replace(":", "/"),
            "RepoTags": [tag],
            "Layers": ["blobs/" + l["digest"].replace(":", "/") for l in manifest["layers"]],
        })
        blobs.update([digest, manifest["config"]["digest"]] + [l["digest"] for l in manifest["layers"]])

    dump = lambda o: json.dumps(o, separators=(",", ":"), sort_keys=True).encode() + b"\n"  # noqa: E731
    with open(out, "wb") as f, tarfile.open(fileobj=f, mode="w", format=tarfile.GNU_FORMAT) as tar:
        _add(tar, "blobs", epoch)
        _add(tar, "blobs/sha256", epoch)
        for d in sorted(blobs):
            _add(tar, posixpath.join("blobs", d.replace(":", "/")), epoch, path=store.file(d))
        _add(tar, "index.json", epoch, data=dump(index))
        _add(tar, "manifest.json", epoch, data=dump(legacy))
        _add(tar, "oci-layout", epoch, data=dump({"imageLayoutVersion": "1.0.0"}))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", required=True)
    p.add_argument("--leak-check", action="append", default=[], metavar="TAG")
    p.add_argument("images", nargs="+", metavar="TAG=SOURCE")
    args = p.parse_args()
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be set")

    work = tempfile.mkdtemp()
    try:
        store = BlobStore(os.path.join(work, "blobs"))
        images = []
        for spec in args.images:
            tag, _, source = spec.partition("=")
            kind, _, where = source.partition(":")
            if kind == "oci-archive":
                digest, media_type = from_oci_archive(where, store)
            elif kind == "registry":
                digest, media_type = from_registry(where, store)
            else:
                raise SystemExit(f"{spec}: SOURCE must start with oci-archive: or registry:")
            print(f"{tag}: {digest}", file=sys.stderr)
            if tag in args.leak_check:
                leak_check(tag, json.loads(store.read(digest)), store)
            images.append((tag, digest, media_type))
        write_archive(args.out, images, store, int(epoch))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
