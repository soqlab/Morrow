"""The list of every page file this server serves under /ui/, with hashes. GET /api/public/manifest.

Why: a visitor who reads the source on GitHub has no way to know the server sends the same bytes.
The list names each file in ``backend/static/`` with its SHA-256 and size, and the running commit
(services/build_info.py). scripts/verify-deploy.py fetches it and compares every hash with
``git show <commit>:backend/static/<file>``; the /trust view hashes the files it loaded itself in
the browser and compares them. A page that differs from the published source is caught either way.

What it does not prove: that the Python code running is the published code. The list is produced
by that code. Reproducible release images (docs/REPRODUCIBLE_BUILDS.md) are how that is checked.
"""

from __future__ import annotations

import hashlib
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

FORMAT = "morrow.page-files/v1"
URL_PREFIX = "/ui/"
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

_lock = threading.Lock()
_files_cache: Dict[str, List[Dict[str, Any]]] = {}
_manifest_cache: Dict[Tuple[Any, ...], Dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def compute_files(static_dir: str) -> List[Dict[str, Any]]:
    """Every regular file under static_dir (dotfiles and dot-directories skipped), sorted by path."""
    out: List[Dict[str, Any]] = []
    root = os.path.abspath(static_dir)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in filenames:
            if name.startswith("."):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            digest = hashlib.sha256()
            size = 0
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
                    size += len(chunk)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out.append({"path": URL_PREFIX + rel, "sha256": digest.hexdigest(), "bytes": size})
    out.sort(key=lambda item: item["path"])
    return out


def files(static_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """compute_files, once per process per directory (the files do not change while it runs)."""
    key = os.path.abspath(static_dir or STATIC_DIR)
    with _lock:
        cached = _files_cache.get(key)
        if cached is None:
            cached = compute_files(key)
            _files_cache[key] = cached
        return [dict(item) for item in cached]


def manifest(static_dir: Optional[str] = None) -> Dict[str, Any]:
    from services import build_info

    commit = build_info.commit()
    key = (os.path.abspath(static_dir or STATIC_DIR), commit)
    with _lock:
        cached = _manifest_cache.get(key)
    if cached is None:
        cached = {"format": FORMAT, "commit": commit, "generated_at": _now(), "files": files(static_dir)}
        with _lock:
            _manifest_cache[key] = cached
    return dict(cached)


def reset_cache_for_tests() -> None:
    with _lock:
        _files_cache.clear()
        _manifest_cache.clear()
