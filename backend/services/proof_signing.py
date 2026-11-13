"""Asymmetric signing keys for migration proofs.

A migration proof has to be checkable by someone who does not trust this server, so it cannot be
signed with a shared secret the way the legacy HS256 "proof package" and passport envelopes are:
anyone able to check an HMAC can also forge one. These keys are asymmetric.

Key model
---------
* One **key set** per deployment, generated on first use: an Ed25519 key and, when the installed
  ``cryptography`` build provides it (cryptography >= 47 with OpenSSL >= 3.5), an ML-DSA-65
  (FIPS 204) key. Every proof carries one signature per key in the active set, so a verifier gets a
  classical signature and a post-quantum one over the same bytes.
* Private keys are stored only sealed with the credential vault's Fernet key
  (``MORROW_VAULT_MASTER_KEY``, see vault_crypto.py). Without the vault key no key is generated and
  no proof is issued: a proof signed by a key that sits in plaintext in the database is not proof.
* Each key has a ``kid`` derived from its public key, so the identifier cannot be reassigned to a
  different key.
* Rotation retires the active set and generates a new one. Retired keys are never deleted and stay
  published at ``/.well-known/morrow-proof-keys.json`` with their validity window, so proofs signed
  before a rotation remain verifiable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from db_feature_store import feature_conn

try:  # ML-DSA needs a cryptography build linked against OpenSSL >= 3.5.
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _mldsa.MLDSA65PrivateKey.generate()
    MLDSA_AVAILABLE = True
except Exception:  # pragma: no cover - depends on the installed wheel
    _mldsa = None
    MLDSA_AVAILABLE = False

ALG_ED25519 = "Ed25519"
ALG_MLDSA65 = "ML-DSA-65"
KEYS_FORMAT = "morrow.proof-keys/v1"
WELL_KNOWN_PATH = "/.well-known/morrow-proof-keys.json"
#: Every signature is over this prefix followed by the canonical document, so a proof signature can
#: never be replayed as a signature over some other kind of Morrow message.
SIGNING_CONTEXT = b"morrow.migration-proof.v1\n"

_lock = threading.Lock()
_ready = False
_private_cache: Dict[str, Any] = {}


class SigningUnavailable(RuntimeError):
    """No usable signing key: the vault is not configured or the key could not be unsealed."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. Floats are refused.

    For the documents Morrow emits (strings, integers, booleans, null, ASCII keys) this is the same
    byte string RFC 8785 (JCS) produces, so a verifier in another language can reproduce it.
    """
    _reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floats are not allowed in a signed document; encode them as strings")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_floats(item)


def key_id(algorithm: str, public_raw: bytes) -> str:
    prefix = "ed25519" if algorithm == ALG_ED25519 else "mldsa65"
    return f"morrow-{prefix}-{hashlib.sha256(public_raw).hexdigest()[:16]}"


def init_tables() -> None:
    global _ready
    if _ready:
        return
    with feature_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proof_signing_keys (
                kid TEXT PRIMARY KEY,
                key_set TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL,
                sealed_private_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                retired_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proof_signing_keys_status ON proof_signing_keys(status)")
        conn.commit()
    _ready = True


def _seal(raw: bytes) -> str:
    try:
        from vault_crypto import encrypt_secret

        return encrypt_secret(b64(raw))
    except Exception as exc:
        raise SigningUnavailable(f"cannot seal a signing key: {exc}") from exc


def _unseal(token: str) -> bytes:
    try:
        from vault_crypto import decrypt_secret

        return base64.b64decode(decrypt_secret(token))
    except Exception as exc:
        raise SigningUnavailable(f"cannot unseal the signing key: {exc}") from exc


def _generate_set() -> List[Dict[str, str]]:
    created = _now()
    key_set = "ks-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + secrets.token_hex(4)
    rows: List[Dict[str, str]] = []
    ed = Ed25519PrivateKey.generate()
    ed_pub = ed.public_key().public_bytes_raw()
    rows.append({"kid": key_id(ALG_ED25519, ed_pub), "key_set": key_set, "algorithm": ALG_ED25519,
                 "public_key_b64": b64(ed_pub), "sealed_private_key": _seal(ed.private_bytes_raw()),
                 "created_at": created})
    if MLDSA_AVAILABLE:
        seed = secrets.token_bytes(32)
        ml = _mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
        ml_pub = ml.public_key().public_bytes_raw()
        rows.append({"kid": key_id(ALG_MLDSA65, ml_pub), "key_set": key_set, "algorithm": ALG_MLDSA65,
                     "public_key_b64": b64(ml_pub), "sealed_private_key": _seal(seed),
                     "created_at": created})
    return rows


def _insert(conn, rows: List[Dict[str, str]]) -> None:
    for row in rows:
        conn.execute(
            "INSERT INTO proof_signing_keys (kid, key_set, algorithm, public_key_b64, sealed_private_key, "
            "status, created_at, retired_at) VALUES (?, ?, ?, ?, ?, 'active', ?, '')",
            (row["kid"], row["key_set"], row["algorithm"], row["public_key_b64"],
             row["sealed_private_key"], row["created_at"]),
        )


def _active_rows(conn) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT kid, key_set, algorithm, public_key_b64, sealed_private_key, status, created_at, retired_at "
        "FROM proof_signing_keys WHERE status = 'active' ORDER BY created_at ASC, key_set ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def _converge(conn) -> List[Dict[str, Any]]:
    """Keep exactly one active key set: the oldest. Two replicas generating at once both converge."""
    active = _active_rows(conn)
    if not active:
        return []
    winner = active[0]["key_set"]
    losers = sorted({r["key_set"] for r in active if r["key_set"] != winner})
    for loser in losers:
        conn.execute("UPDATE proof_signing_keys SET status='superseded', retired_at=? WHERE key_set=?",
                     (_now(), loser))
    return [r for r in active if r["key_set"] == winner]


def active_key_set(create: bool = True) -> List[Dict[str, Any]]:
    init_tables()
    with _lock, feature_conn() as conn:
        rows = _active_rows(conn)
        if not rows and create:
            _insert(conn, _generate_set())
            rows = _converge(conn)
            conn.commit()
        elif len({r["key_set"] for r in rows}) > 1:
            rows = _converge(conn)
            conn.commit()
    return rows


def rotate() -> Dict[str, Any]:
    """Retire the active key set and generate a new one. Retired keys stay published."""
    init_tables()
    new_rows = _generate_set()  # seal first: a vault failure must leave the old set active
    with _lock, feature_conn() as conn:
        now = _now()
        conn.execute("UPDATE proof_signing_keys SET status='retired', retired_at=? WHERE status='active'", (now,))
        _insert(conn, new_rows)
        conn.commit()
    return {"key_set": new_rows[0]["key_set"], "kids": [r["kid"] for r in new_rows], "rotated_at": now}


def published_keys() -> Dict[str, Any]:
    """Every key ever used to sign proofs on this deployment, public halves only."""
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT kid, key_set, algorithm, public_key_b64, status, created_at, retired_at "
            "FROM proof_signing_keys ORDER BY created_at ASC, kid ASC"
        ).fetchall()
    keys = []
    for r in rows:
        r = dict(r)
        raw = base64.b64decode(r["public_key_b64"])
        keys.append({
            "kid": r["kid"],
            "key_set": r["key_set"],
            "alg": r["algorithm"],
            "public_key": r["public_key_b64"],
            "fingerprint_sha256": hashlib.sha256(raw).hexdigest(),
            "status": r["status"],
            "valid_from": r["created_at"],
            "valid_until": r["retired_at"] or None,
        })
    return {"format": KEYS_FORMAT, "signing_context": SIGNING_CONTEXT.decode("ascii").strip(), "keys": keys}


def public_descriptor(row: Dict[str, Any]) -> Dict[str, str]:
    raw = base64.b64decode(row["public_key_b64"])
    return {"kid": row["kid"], "key_set": row["key_set"], "alg": row["algorithm"],
            "public_key": row["public_key_b64"], "fingerprint_sha256": hashlib.sha256(raw).hexdigest()}


def _private_key(row: Dict[str, Any]):
    kid = row["kid"]
    cached = _private_cache.get(kid)
    if cached is not None:
        return cached
    raw = _unseal(row["sealed_private_key"])
    if row["algorithm"] == ALG_ED25519:
        key = Ed25519PrivateKey.from_private_bytes(raw)
    elif row["algorithm"] == ALG_MLDSA65 and MLDSA_AVAILABLE:
        key = _mldsa.MLDSA65PrivateKey.from_seed_bytes(raw)
    else:
        raise SigningUnavailable(f"algorithm {row['algorithm']} is not available in this build")
    if b64(key.public_key().public_bytes_raw()) != row["public_key_b64"]:
        raise SigningUnavailable(f"sealed key {kid} does not match its published public key")
    _private_cache[kid] = key
    return key


def sign(message: bytes, rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    out = []
    for row in rows:
        signature = _private_key(row).sign(SIGNING_CONTEXT + message)
        out.append({"kid": row["kid"], "alg": row["algorithm"], "signature": b64(signature)})
    return out


def verify_signature(alg: str, public_b64: str, signature_b64: str, message: bytes) -> bool:
    """Server-side mirror of the offline verifier's check (used by tests and the self-check)."""
    try:
        pub = base64.b64decode(public_b64)
        sig = base64.b64decode(signature_b64)
        if alg == ALG_ED25519:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, SIGNING_CONTEXT + message)
            return True
        if alg == ALG_MLDSA65 and MLDSA_AVAILABLE:
            _mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, SIGNING_CONTEXT + message)
            return True
    except Exception:
        return False
    return False


def reset_cache_for_tests() -> None:
    global _ready
    _ready = False
    _private_cache.clear()


def describe_algorithms() -> Optional[List[str]]:
    return [ALG_ED25519] + ([ALG_MLDSA65] if MLDSA_AVAILABLE else [])
