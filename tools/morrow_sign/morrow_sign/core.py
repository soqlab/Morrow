"""Keys, signatures and the checks behind morrow-sign. No network here; see cli.py for that.

The bytes signed are the same as Morrow's server builds (backend/services/pq_signing_format.py)
and the browser verifier builds (backend/static/verify.js):

    morrow-signature/1
    domain <domain>
    key <key id>
    type file|manifest
    name <file name>
    size <bytes>
    sha512 <128 lowercase hex>
    signed-at <YYYY-MM-DDTHH:MM:SSZ>

signed twice, with ML-DSA-65 (FIPS 204, context "morrow-signature/1") and with Ed25519. A
signature is valid only when both verify.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

SIGNATURE_FORMAT = "morrow-signature/1"
PUBLIC_KEY_FORMAT = "morrow-public-key/1"
PRIVATE_KEY_FORMAT = "morrow-private-key/1"
MANIFEST_FORMAT = "morrow-manifest/1"
REGISTRATION_FORMAT = "morrow-key-registration/1"
SIGNATURE_CONTEXT = SIGNATURE_FORMAT.encode("ascii")
REGISTRATION_CONTEXT = REGISTRATION_FORMAT.encode("ascii")

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

#: scrypt cost for an encrypted private key file: 128 MiB, about a second on a laptop.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 17, 8, 1
CHUNK = 1024 * 1024


class SignError(Exception):
    """Something the person running the command can fix. The message says what."""


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        raise SignError("This needs the cryptography package with ML-DSA support (version 50 or later): "
                        "pip install --upgrade 'cryptography>=50'") from None
    return mldsa


def b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(value: Any, length: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(str(value or "").encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise SignError(f"{what} is not valid base64.") from None
    if len(raw) != length:
        raise SignError(f"{what} must be {length} bytes.")
    return raw


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_id(ml_dsa_public: bytes, ed25519_public: bytes) -> str:
    return "mk-" + hashlib.sha256(b"morrow-key/1\n" + bytes(ml_dsa_public) + bytes(ed25519_public)).hexdigest()[:32]


def normalize_domain(value: str) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        raise SignError(f"{value!r} is not a domain name.") from None
    labels = text.split(".")
    if len(text) < 4 or len(labels) < 2 or not all(labels) or any(
            len(x) > 63 or x.startswith("-") or x.endswith("-") or not all(c.isalnum() or c == "-" for c in x)
            for x in labels):
        raise SignError(f"{value!r} is not a domain name. Use the domain you verified in Morrow, like example.com.")
    return text


def statement_bytes(domain: str, key: str, subject_type: str, name: str, size: int, sha512: str,
                    signed_at: str) -> bytes:
    lines = [SIGNATURE_FORMAT, f"domain {domain}", f"key {key}", f"type {subject_type}", f"name {name}",
             f"size {int(size)}", f"sha512 {sha512}", f"signed-at {signed_at}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def registration_bytes(domain: str, key: str, ml_dsa_public: bytes, ed25519_public: bytes) -> bytes:
    lines = [REGISTRATION_FORMAT, f"domain {domain}", f"key {key}",
             f"ml-dsa-65 {b64(ml_dsa_public)}", f"ed25519 {b64(ed25519_public)}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def manifest_bytes(entries: Iterable[Dict[str, Any]]) -> bytes:
    lines = [MANIFEST_FORMAT] + [f"{e['sha512']} {int(e['size'])} {e['path']}" for e in entries]
    return ("\n".join(lines) + "\n").encode("utf-8")


def clean_name(name: str, what: str = "The file name") -> str:
    text = unicodedata.normalize("NFC", str(name or ""))
    if not text or text != text.strip():
        raise SignError(f"{what} {name!r} is empty or starts or ends with a space.")
    if len(text) > 255 and what == "The file name":
        raise SignError(f"{what} is longer than 255 characters.")
    if len(text.encode("utf-8")) > 1024 or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in text):
        raise SignError(f"{what} {name!r} contains a control character or is too long.")
    return text


# ── hashing ──────────────────────────────────────────────────────────────────

def hash_file(path: str) -> Tuple[str, int]:
    digest = hashlib.sha512()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


SKIP_SUFFIXES = (".morrow-key", ".morrow-sig")


def site_entries(root: str, skip: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """Every regular file under root, relative POSIX paths, sorted by their UTF-8 bytes.

    Skipped: dot-files and dot-directories (.git, .env), symbolic links, Morrow key and signature
    files, and the paths in `skip` (the manifest being written).
    """
    base = os.path.abspath(root)
    skipped = {os.path.abspath(p) for p in skip}
    out = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if name.startswith(".") or name.endswith(SKIP_SUFFIXES) or os.path.islink(full) or full in skipped:
                continue
            if not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            rel = "/".join(clean_name(part, "A path") for part in rel.split("/"))
            digest, size = hash_file(full)
            out.append({"path": rel, "size": size, "sha512": digest})
    out.sort(key=lambda e: e["path"].encode("utf-8"))
    if not out:
        raise SignError(f"There are no files to list under {root}.")
    return out


def parse_manifest(data: bytes) -> List[Dict[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SignError("The manifest is not UTF-8 text.") from None
    lines = text.rstrip("\n").split("\n")
    if lines[0] != MANIFEST_FORMAT:
        raise SignError(f"Not a Morrow manifest: the first line must be {MANIFEST_FORMAT}.")
    entries = []
    for line in lines[1:]:
        parts = line.split(" ", 2)
        if len(parts) != 3 or not parts[1].isdigit():
            raise SignError("Each manifest line is '<sha512> <size> <path>'.")
        entries.append({"sha512": parts[0], "size": int(parts[1]), "path": parts[2]})
    return entries


# ── keys ─────────────────────────────────────────────────────────────────────

def _scrypt(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode("utf-8"))


def generate(domain: str, passphrase: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """A new key pair for `domain`: (private key file, public key file), both as JSON-ready dicts."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    mldsa = _mldsa()
    name = normalize_domain(domain)
    seed = secrets.token_bytes(32)
    ml_private = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
    ed_private = Ed25519PrivateKey.generate()
    ml_public = ml_private.public_key().public_bytes_raw()
    ed_public = ed_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed_raw = ed_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
    kid = key_id(ml_public, ed_public)
    message = registration_bytes(name, kid, ml_public, ed_public)
    created = now_stamp()
    public = {
        "format": PUBLIC_KEY_FORMAT, "domain": name, "key": kid, "created_at": created,
        "ml_dsa_65": b64(ml_public), "ed25519": b64(ed_public),
        "proof": {"ml_dsa_65": b64(ml_private.sign(message, REGISTRATION_CONTEXT)),
                  "ed25519": b64(ed_private.sign(message))},
    }
    secret = {"ml_dsa_65_seed": b64(seed), "ed25519": b64(ed_raw)}
    private: Dict[str, Any] = {"format": PRIVATE_KEY_FORMAT, "domain": name, "key": kid, "created_at": created,
                               "warning": "Private signing key. Never share it, never upload it, never commit it."}
    if passphrase:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        data = AESGCM(_scrypt(passphrase, salt)).encrypt(nonce, json.dumps(secret).encode("utf-8"), kid.encode("ascii"))
        private["encrypted"] = {"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": b64(salt),
                                "cipher": "aes-256-gcm", "nonce": b64(nonce), "data": b64(data)}
    else:
        private["secret"] = secret
    return private, public


class SigningKey:
    """A loaded private key file."""

    def __init__(self, doc: Dict[str, Any], passphrase: Optional[str] = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(doc, dict) or doc.get("format") != PRIVATE_KEY_FORMAT:
            raise SignError("Not a Morrow private key file (morrow-sign keygen makes one).")
        self.domain = normalize_domain(doc.get("domain"))
        secret = doc.get("secret")
        if secret is None:
            enc = doc.get("encrypted")
            if not isinstance(enc, dict):
                raise SignError("The private key file holds no key.")
            if not passphrase:
                raise SignError("This private key is encrypted. Give its passphrase (MORROW_SIGN_PASSPHRASE, or "
                                "type it when asked).")
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

            try:
                kek = Scrypt(salt=unb64(enc.get("salt"), 16, "salt"), length=32, n=int(enc["n"]), r=int(enc["r"]),
                             p=int(enc["p"])).derive(passphrase.encode("utf-8"))
                plain = AESGCM(kek).decrypt(unb64(enc.get("nonce"), 12, "nonce"),
                                            base64.b64decode(enc.get("data", "")), str(doc.get("key")).encode("ascii"))
            except InvalidTag:
                raise SignError("Wrong passphrase for this private key.") from None
            secret = json.loads(plain.decode("utf-8"))
        mldsa = _mldsa()
        self._ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(unb64(secret.get("ml_dsa_65_seed"), 32, "The ML-DSA seed"))
        self._ed = Ed25519PrivateKey.from_private_bytes(unb64(secret.get("ed25519"), 32, "The Ed25519 key"))
        from cryptography.hazmat.primitives import serialization

        self.ml_public = self._ml.public_key().public_bytes_raw()
        self.ed_public = self._ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key = key_id(self.ml_public, self.ed_public)
        if doc.get("key") != self.key:
            raise SignError("The private key file is damaged: its key id does not match the key inside.")

    def sign(self, subject_type: str, name: str, size: int, sha512: str, signed_at: Optional[str] = None) -> Dict[str, Any]:
        stamp = signed_at or now_stamp()
        clean = clean_name(name)
        message = statement_bytes(self.domain, self.key, subject_type, clean, size, sha512, stamp)
        return {"format": SIGNATURE_FORMAT, "domain": self.domain, "key": self.key, "type": subject_type,
                "name": clean, "size": int(size), "sha512": sha512, "signed_at": stamp,
                "ml_dsa_65": b64(self._ml.sign(message, SIGNATURE_CONTEXT)), "ed25519": b64(self._ed.sign(message))}


# ── verification ─────────────────────────────────────────────────────────────

def verify_pair(ml_public: bytes, ed_public: bytes, sig: Dict[str, Any]) -> Tuple[bool, bool]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    message = statement_bytes(sig["domain"], sig["key"], sig["type"], sig["name"], sig["size"], sig["sha512"],
                              sig["signed_at"])
    mldsa = _mldsa()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(ml_public).verify(
            unb64(sig.get("ml_dsa_65"), ML_DSA_65_SIGNATURE_BYTES, "The ML-DSA-65 signature"), message, SIGNATURE_CONTEXT)
        ml_ok = True
    except (InvalidSignature, ValueError):
        ml_ok = False
    try:
        Ed25519PublicKey.from_public_bytes(ed_public).verify(
            unb64(sig.get("ed25519"), ED25519_SIGNATURE_BYTES, "The Ed25519 signature"), message)
        ed_ok = True
    except (InvalidSignature, ValueError):
        ed_ok = False
    return ml_ok, ed_ok


def check_signature_shape(sig: Any) -> Dict[str, Any]:
    if not isinstance(sig, dict) or sig.get("format") != SIGNATURE_FORMAT:
        raise SignError(f"Not a Morrow signature file (format {SIGNATURE_FORMAT}).")
    for field in ("domain", "key", "type", "name", "sha512", "signed_at", "ml_dsa_65", "ed25519"):
        if not isinstance(sig.get(field), str):
            raise SignError(f"The signature file has no {field}.")
    if isinstance(sig.get("size"), bool) or not isinstance(sig.get("size"), int):
        raise SignError("The signature file has no size.")
    return sig


def assess(sig: Dict[str, Any], key: Optional[Dict[str, Any]], record: Optional[Dict[str, Any]],
           file_sha512: Optional[str] = None, file_size: Optional[int] = None) -> Dict[str, Any]:
    """The same rules as the server (services/pq_signing.assess) and the browser (verify.js)."""
    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def verdict(valid: bool, reason: str) -> Dict[str, Any]:
        return {"valid": valid, "reason": reason, "checks": checks, "recorded": bool(record),
                "recorded_at": record.get("recorded_at") if record else None}

    if file_sha512 is not None:
        same = file_sha512 == sig["sha512"] and (file_size is None or file_size == sig["size"])
        if not check("file", same, "The file's SHA-512 and size match the signature." if same else
                     "The file's SHA-512 or size differs from the signed one."):
            return verdict(False, "This file is not the one that was signed.")
    if not check("key", key is not None, "The key is on the domain's public record." if key else
                 f"{sig['domain']} has no key {sig['key']} on its public record."):
        return verdict(False, "The signing key is not registered for this domain.")
    state = key.get("state") or {}
    if not check("domain", bool(state.get("domain_verified")), "The key's owner still has the domain verified."
                 if state.get("domain_verified") else "The key's owner no longer has the domain verified."):
        return verdict(False, "The key's owner no longer has this domain verified.")
    ml_ok, ed_ok = verify_pair(unb64(key["ml_dsa_65"], ML_DSA_65_PUBLIC_KEY_BYTES, "The ML-DSA-65 key"),
                               unb64(key["ed25519"], ED25519_PUBLIC_KEY_BYTES, "The Ed25519 key"), sig)
    check("ml_dsa_65", ml_ok, "ML-DSA-65 (FIPS 204) signature verifies." if ml_ok else "ML-DSA-65 signature does not verify.")
    check("ed25519", ed_ok, "Ed25519 signature verifies." if ed_ok else "Ed25519 signature does not verify.")
    if not (ml_ok and ed_ok):
        return verdict(False, "The signature does not verify: both ML-DSA-65 and Ed25519 must.")
    if record and record.get("withdrawn"):
        check("withdrawn", False, f"Withdrawn by the publisher on {record['withdrawn']['at']}: {record['withdrawn']['note']}")
        return verdict(False, "The publisher withdrew this signature.")
    status = state.get("status")
    if status == "revoked":
        since = str(state.get("compromised_since"))
        ok = bool(record) and str(record.get("recorded_at")) < since
        check("key_status", ok, "Recorded on Morrow before the key stopped being trusted." if ok else
              f"The key was revoked: nothing it signed is trusted unless Morrow recorded it before {since}.")
        return verdict(ok, "Valid: recorded before the key was revoked." if ok else "The signing key was revoked.")
    if status == "retired":
        ok = str(sig["signed_at"]) <= str(state.get("retired_at"))
        check("key_status", ok, f"Signed before the key was retired on {state.get('retired_at')}." if ok else
              f"Signed after the key was retired on {state.get('retired_at')}.")
        return verdict(ok, "Valid: signed before the key was retired." if ok else "Signed with a retired key.")
    check("key_status", True, "The key is active.")
    return verdict(True, "Valid post-quantum signature." if record else
                   "Valid post-quantum signature. It is not on Morrow's public record.")


def offline_key(public_doc: Dict[str, Any]) -> Dict[str, Any]:
    """A public key file as a key record, for checking without Morrow (no revocation status)."""
    if not isinstance(public_doc, dict) or public_doc.get("format") != PUBLIC_KEY_FORMAT:
        raise SignError("Not a Morrow public key file.")
    ml = unb64(public_doc.get("ml_dsa_65"), ML_DSA_65_PUBLIC_KEY_BYTES, "The ML-DSA-65 key")
    ed = unb64(public_doc.get("ed25519"), ED25519_PUBLIC_KEY_BYTES, "The Ed25519 key")
    if key_id(ml, ed) != public_doc.get("key"):
        raise SignError("The public key file is damaged: its key id does not match the keys inside.")
    return {"domain": public_doc.get("domain"), "key_id": public_doc["key"], "ml_dsa_65": public_doc["ml_dsa_65"],
            "ed25519": public_doc["ed25519"], "state": {"status": "active", "domain_verified": True}}
