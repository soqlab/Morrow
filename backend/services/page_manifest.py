"""A signed list of every page file this server serves under /ui/. Served at GET /api/public/manifest.

Why: a visitor who reads the source on GitHub has no way to know the server sends the same bytes.
The manifest names each file in ``backend/static/`` with its SHA-256 and size, and the running
commit (services/build_info.py); it is signed by the deployment's proof keys (services/
proof_signing.py, published at /.well-known/morrow-proof-keys.json). scripts/verify-deploy.py
fetches it, compares every hash with ``git show <commit>:backend/static/<file>`` and checks the
signatures, so a page that differs from the published source is caught.

Signature
---------
Each active proof key signs ``SIGNING_CONTEXT + canonical_bytes(document)``, where ``document`` is
the manifest without ``signatures`` and ``unsigned_reason``, and canonical_bytes is
proof_signing.canonical_bytes (sorted keys, no whitespace, UTF-8). The context
``morrow.page-manifest.v1\\n`` differs from the migration-proof context, so a manifest signature is
never valid as a proof signature and the reverse.

Without the vault key (``MORROW_VAULT_MASTER_KEY``) there is no signing key: the manifest is then
served unsigned, with ``unsigned_reason`` saying why; the hashes are still checkable against git.

What it does not prove: that the Python code running is the published code. The manifest is
produced by that code. It proves the served pages match a commit, and the signature ties the claim
to the deployment's long-lived key, so a later lie is attributable.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

FORMAT = "morrow.page-manifest/v1"
URL_PREFIX = "/ui/"
KEYS_URL = "/.well-known/morrow-proof-keys.json"
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

_lock = threading.Lock()
_files_cache: Dict[str, List[Dict[str, Any]]] = {}
_manifest_cache: Dict[Tuple[Any, ...], Dict[str, Any]] = {}


def signing_context() -> bytes:
    from services.proof_signing import MANIFEST_SIGNING_CONTEXT

    return MANIFEST_SIGNING_CONTEXT


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


def signed_bytes(manifest: Dict[str, Any]) -> bytes:
    """The bytes the signatures cover: context + canonical JSON of the manifest minus its signatures."""
    from services.proof_signing import canonical_bytes

    body = {k: v for k, v in manifest.items() if k not in ("signatures", "unsigned_reason")}
    return signing_context() + canonical_bytes(body)


def _signatures(document: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    from services import proof_signing
    from services.proof_signing import canonical_bytes

    try:
        rows = proof_signing.active_key_set(create=True)
    except proof_signing.SigningUnavailable:
        return [], "No signing key: the vault key (MORROW_VAULT_MASTER_KEY) is not configured on this server."
    except Exception as exc:
        logger.warning("page manifest: signing keys unavailable (%s)", type(exc).__name__)
        return [], "The signing keys could not be read on this server."
    if not rows:
        return [], "No signing key: the vault key (MORROW_VAULT_MASTER_KEY) is not configured on this server."
    try:
        raw = proof_signing.sign_in_context(signing_context(), canonical_bytes(document), rows)
    except proof_signing.SigningUnavailable:
        return [], "The signing key could not be unsealed with this server's vault key."
    except Exception as exc:
        logger.warning("page manifest: signing failed (%s)", type(exc).__name__)
        return [], "Signing failed on this server."
    return [{"kid": s["kid"], "alg": s["alg"], "sig_b64": s["signature"]} for s in raw], None


def manifest(static_dir: Optional[str] = None) -> Dict[str, Any]:
    from services import build_info

    commit = build_info.commit()
    key = (os.path.abspath(static_dir or STATIC_DIR), commit)
    with _lock:
        cached = _manifest_cache.get(key)
    if cached is not None and cached.get("signatures"):
        return dict(cached)
    document = {
        "format": FORMAT,
        "commit": commit,
        "generated_at": _now(),
        "files": files(static_dir),
        "keys_url": KEYS_URL,
        "signing_context": signing_context().decode("ascii"),
    }
    signatures, reason = _signatures(document)
    out = dict(document)
    out["signatures"] = signatures
    out["unsigned_reason"] = reason
    if signatures:  # an unsigned answer is retried next time: the vault key may arrive later
        with _lock:
            _manifest_cache[key] = out
    return dict(out)


def reset_cache_for_tests() -> None:
    with _lock:
        _files_cache.clear()
        _manifest_cache.clear()
