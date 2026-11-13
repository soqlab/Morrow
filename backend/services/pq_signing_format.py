"""The byte formats of post-quantum signing (services/pq_signing.py), and the signature checks.

Kept apart from storage so the exact bytes that get signed are written down in one small module.
The customer's CLI (tools/morrow_sign/morrow_sign/core.py) and the browser verifier
(static/verify.js) build the same bytes; test_pq_signing.py signs with the CLI and checks here,
and checks the browser code against the same vectors.

A signature is two signatures over one statement, and is valid only when both verify:

  * ML-DSA-65 (FIPS 204), with the context string ``morrow-signature/1``;
  * Ed25519 (RFC 8032), over the same statement bytes.

The statement is plain UTF-8 text, one field per line, so every implementation produces it the
same way without a JSON canonicaliser::

    morrow-signature/1
    domain acme.com
    key mk-0123456789abcdef0123456789abcdef
    type file
    name acme-1.2.0.tar.gz
    size 1048576
    sha512 <128 lowercase hex>
    signed-at 2026-11-13T10:00:00Z

A site manifest is a file in the same spirit, one line per file, in the order given::

    morrow-manifest/1
    <sha512> <size> <path>

and is signed like any other file (type ``manifest``), so whoever holds the manifest's entries can
rebuild its bytes, hash them and check the signature without trusting the server that sent them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Tuple

SIGNATURE_FORMAT = "morrow-signature/1"
PUBLIC_KEY_FORMAT = "morrow-public-key/1"
MANIFEST_FORMAT = "morrow-manifest/1"
REGISTRATION_FORMAT = "morrow-key-registration/1"

#: FIPS 204 context strings: a signature made for one purpose cannot be replayed as the other.
SIGNATURE_CONTEXT = SIGNATURE_FORMAT.encode("ascii")
REGISTRATION_CONTEXT = REGISTRATION_FORMAT.encode("ascii")

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

SUBJECT_TYPES = ("file", "manifest")
MAX_NAME_CHARS = 255
MAX_PATH_BYTES = 1024
MAX_SIZE = 2 ** 63 - 1

_HEX512 = re.compile(r"^[0-9a-f]{128}$")
_KEY_ID = re.compile(r"^mk-[0-9a-f]{32}$")
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^(?=.{{4,253}}$)(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,62}}$")


class FormatError(ValueError):
    """The input is not a well-formed signing document. The message says what is wrong."""


# ── primitives ───────────────────────────────────────────────────────────────

def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # cryptography older than the pinned version, or built without it
        raise RuntimeError("This server's cryptography library has no ML-DSA support.") from exc
    return mldsa


def b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(value: Any, length: int, what: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise FormatError(f"{what} is missing.")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise FormatError(f"{what} is not valid base64.") from None
    if len(raw) != length:
        raise FormatError(f"{what} must be {length} bytes, not {len(raw)}.")
    return raw


def key_id(ml_dsa_public: bytes, ed25519_public: bytes) -> str:
    """The key's name everywhere: derived from both public keys, so it cannot be chosen."""
    digest = hashlib.sha256(b"morrow-key/1\n" + bytes(ml_dsa_public) + bytes(ed25519_public)).hexdigest()
    return "mk-" + digest[:32]


def is_key_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_KEY_ID.match(value))


def is_domain(value: Any) -> bool:
    return isinstance(value, str) and bool(_DOMAIN.match(value))


def is_sha512(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX512.match(value))


def _clean_text(value: Any, what: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value:
        raise FormatError(f"{what} is missing.")
    if len(value) > max_chars or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise FormatError(f"{what} is too long.")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in value):
        raise FormatError(f"{what} contains a control or formatting character.")
    if value != value.strip():
        raise FormatError(f"{what} starts or ends with a space.")
    return value


def _size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SIZE:
        raise FormatError("size must be a whole number of bytes.")
    return value


# ── statements ───────────────────────────────────────────────────────────────

def statement_bytes(domain: str, key: str, subject_type: str, name: str, size: int, sha512: str,
                    signed_at: str) -> bytes:
    lines = [SIGNATURE_FORMAT, f"domain {domain}", f"key {key}", f"type {subject_type}", f"name {name}",
             f"size {int(size)}", f"sha512 {sha512}", f"signed-at {signed_at}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def registration_bytes(domain: str, key: str, ml_dsa_public: bytes, ed25519_public: bytes) -> bytes:
    lines = [REGISTRATION_FORMAT, f"domain {domain}", f"key {key}",
             f"ml-dsa-65 {b64(ml_dsa_public)}", f"ed25519 {b64(ed25519_public)}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def clean_path(value: Any) -> str:
    """A manifest path: relative, forward slashes, no '.' or '..' segments, no control characters."""
    path = _clean_text(value, "A manifest path", MAX_PATH_BYTES)
    if path.startswith("/") or "\\" in path or "//" in path or path.endswith("/"):
        raise FormatError(f"Manifest path {path[:80]!r} must be relative, with single forward slashes.")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise FormatError(f"Manifest path {path[:80]!r} contains '.' or '..'.")
    return path


def manifest_bytes(entries: Iterable[Dict[str, Any]]) -> bytes:
    lines = [MANIFEST_FORMAT]
    for entry in entries:
        lines.append(f"{entry['sha512']} {int(entry['size'])} {entry['path']}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_manifest(data: bytes, max_entries: int) -> List[Dict[str, Any]]:
    """The entries of a manifest file, validated. FormatError when it is not one."""
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("The manifest is not UTF-8 text.") from None
    if not text.endswith("\n"):
        raise FormatError("The manifest must end with a newline.")
    lines = text[:-1].split("\n")
    if lines[0] != MANIFEST_FORMAT:
        raise FormatError(f"The manifest must start with the line {MANIFEST_FORMAT}.")
    raw = []
    for line in lines[1:]:
        parts = line.split(" ", 2)
        if len(parts) != 3 or not parts[1].isdigit():
            raise FormatError("Each manifest line is '<sha512> <size> <path>'.")
        raw.append({"sha512": parts[0], "size": int(parts[1]), "path": parts[2]})
    return clean_entries(raw, max_entries)


def clean_entries(raw: Any, max_entries: int) -> List[Dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise FormatError("A manifest lists at least one file.")
    if len(raw) > max_entries:
        raise FormatError(f"A manifest lists at most {max_entries} files.")
    out, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            raise FormatError("Each manifest entry is an object with path, size and sha512.")
        path = clean_path(item.get("path"))
        if path in seen:
            raise FormatError(f"Manifest path {path[:80]!r} is listed twice.")
        seen.add(path)
        digest = item.get("sha512")
        if not is_sha512(digest):
            raise FormatError(f"Manifest entry {path[:80]!r} needs a 128-character lowercase hex sha512.")
        out.append({"path": path, "size": _size(item.get("size")), "sha512": digest})
    return out


# ── documents ────────────────────────────────────────────────────────────────

def parse_signature(doc: Any) -> Dict[str, Any]:
    """A signature file's fields, validated and decoded. FormatError when it is not one."""
    if not isinstance(doc, dict):
        raise FormatError("A signature file is a JSON object.")
    if doc.get("format") != SIGNATURE_FORMAT:
        raise FormatError(f"Not a Morrow signature: format must be {SIGNATURE_FORMAT}.")
    domain = doc.get("domain")
    if not is_domain(domain):
        raise FormatError("domain must be a lower-case domain name.")
    key = doc.get("key")
    if not is_key_id(key):
        raise FormatError("key must be a Morrow key id (mk- and 32 hex characters).")
    subject_type = doc.get("type")
    if subject_type not in SUBJECT_TYPES:
        raise FormatError("type must be file or manifest.")
    name = _clean_text(doc.get("name"), "name", MAX_NAME_CHARS)
    size = _size(doc.get("size"))
    digest = doc.get("sha512")
    if not is_sha512(digest):
        raise FormatError("sha512 must be 128 lowercase hex characters.")
    signed_at = doc.get("signed_at")
    if not isinstance(signed_at, str) or not _STAMP.match(signed_at):
        raise FormatError("signed_at must look like 2026-11-13T10:00:00Z.")
    ml_sig = unb64(doc.get("ml_dsa_65"), ML_DSA_65_SIGNATURE_BYTES, "The ML-DSA-65 signature")
    ed_sig = unb64(doc.get("ed25519"), ED25519_SIGNATURE_BYTES, "The Ed25519 signature")
    return {"domain": domain, "key": key, "type": subject_type, "name": name, "size": size, "sha512": digest,
            "signed_at": signed_at, "ml_dsa_65": ml_sig, "ed25519": ed_sig}


def signature_document(sig: Dict[str, Any]) -> Dict[str, Any]:
    """The JSON form of a parsed signature (the .morrow-sig file)."""
    return {"format": SIGNATURE_FORMAT, "domain": sig["domain"], "key": sig["key"], "type": sig["type"],
            "name": sig["name"], "size": sig["size"], "sha512": sig["sha512"], "signed_at": sig["signed_at"],
            "ml_dsa_65": b64(sig["ml_dsa_65"]), "ed25519": b64(sig["ed25519"])}


def signature_digest(sig: Dict[str, Any]) -> str:
    """Identifies one act of signing: ML-DSA signing here is randomised, so no two are alike."""
    return hashlib.sha256(bytes(sig["ml_dsa_65"]) + bytes(sig["ed25519"])).hexdigest()


def parse_public_key(doc: Any) -> Dict[str, Any]:
    """A public key file (morrow-sign keygen writes it), validated, with its proof of possession checked.

    The proof is both private keys signing the registration statement, so nobody can register a
    public key they do not hold.
    """
    if not isinstance(doc, dict):
        raise FormatError("A public key file is a JSON object.")
    if doc.get("format") != PUBLIC_KEY_FORMAT:
        raise FormatError(f"Not a Morrow public key: format must be {PUBLIC_KEY_FORMAT}.")
    domain = doc.get("domain")
    if not is_domain(domain):
        raise FormatError("domain must be a lower-case domain name.")
    ml_pub = unb64(doc.get("ml_dsa_65"), ML_DSA_65_PUBLIC_KEY_BYTES, "The ML-DSA-65 public key")
    ed_pub = unb64(doc.get("ed25519"), ED25519_PUBLIC_KEY_BYTES, "The Ed25519 public key")
    kid = key_id(ml_pub, ed_pub)
    if doc.get("key") != kid:
        raise FormatError("The key id does not match the public keys in the file.")
    proof = doc.get("proof")
    if not isinstance(proof, dict):
        raise FormatError("The file has no proof of possession. Make the key with morrow-sign keygen.")
    ml_proof = unb64(proof.get("ml_dsa_65"), ML_DSA_65_SIGNATURE_BYTES, "The ML-DSA-65 proof")
    ed_proof = unb64(proof.get("ed25519"), ED25519_SIGNATURE_BYTES, "The Ed25519 proof")
    message = registration_bytes(domain, kid, ml_pub, ed_pub)
    ml_ok, ed_ok = verify_pair(ml_pub, ed_pub, message, REGISTRATION_CONTEXT, ml_proof, ed_proof)
    if not (ml_ok and ed_ok):
        raise FormatError("The proof of possession does not verify: this public key file was altered, "
                          "or was not made by morrow-sign keygen for this domain.")
    return {"domain": domain, "key": kid, "ml_dsa_65": ml_pub, "ed25519": ed_pub,
            "proof": {"ml_dsa_65": b64(ml_proof), "ed25519": b64(ed_proof)}}


def verify_pair(ml_public: bytes, ed_public: bytes, message: bytes, context: bytes, ml_sig: bytes,
                ed_sig: bytes) -> Tuple[bool, bool]:
    """(ML-DSA-65 verifies, Ed25519 verifies). Never raises on a bad signature."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    mldsa = _mldsa()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(bytes(ml_public)).verify(bytes(ml_sig), bytes(message), bytes(context))
        ml_ok = True
    except (InvalidSignature, ValueError):
        ml_ok = False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(ed_public)).verify(bytes(ed_sig), bytes(message))
        ed_ok = True
    except (InvalidSignature, ValueError):
        ed_ok = False
    return ml_ok, ed_ok


def verify_signature(sig: Dict[str, Any], ml_public: bytes, ed_public: bytes) -> Tuple[bool, bool]:
    message = statement_bytes(sig["domain"], sig["key"], sig["type"], sig["name"], sig["size"], sig["sha512"],
                              sig["signed_at"])
    return verify_pair(ml_public, ed_public, message, SIGNATURE_CONTEXT, sig["ml_dsa_65"], sig["ed25519"])
