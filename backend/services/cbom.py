"""
CycloneDX 1.6 Cryptography Bill of Materials (CBOM) generator.

Produces a CBOM from Morrow scan results that validates against the official CycloneDX 1.6
JSON schema (vendored under schemas/cyclonedx/ and enforced by test_cbom_conformance.py).

Spec: https://cyclonedx.org/specification/overview/
CBOM: the CycloneDX 1.6 `cryptographic-asset` component type and `cryptoProperties`.

Why this file is strict about the spec: a CBOM's whole value is that someone else's pipeline can
read it -- Dependency-Track, an OWASP toolchain, a procurement reviewer's validator. An earlier
version of this generator produced six schema violations on a single ordinary scan result
(`executionEnvironment: "software"`, `implementationPlatform: "TLS"`, `primitive: "cipher"`, and
`publicKeyRef` in place of `subjectPublicKeyRef`), so every export was rejected on import by any
conforming consumer, while the module docstring advertised it as standards-compliant.

Beyond validity, this generator links the graph. Certificates reference the algorithm components
that signed them and that their public key uses, protocols reference the algorithms in the
negotiated cipher suite, and a top-level `dependencies` array expresses the tree. A flat,
reference-free CBOM can validate and still tell a reader nothing about what depends on what.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

TOOL_VERSION = "0.7.0"
SPEC_VERSION = "1.6"

# CycloneDX 1.6 enum values, as constants because the obvious-looking words are not the valid ones:
# "software" and "cipher" are both rejected by the schema.
EXEC_SOFTWARE = "software-plain-ram"
PLATFORM_GENERIC = "generic"

# ---------------------------------------------------------------------------------------------
# Algorithm knowledge base.
#
# nist is the NIST post-quantum security *category* (1-5), which is defined by reference to AES-128
# (category 1), AES-192 (category 3) and AES-256 (category 5). 0 means no post-quantum security:
# everything broken by Shor's algorithm -- RSA, finite-field Diffie-Hellman, and all elliptic-curve
# key agreement and signatures -- belongs there regardless of key size.
#
# classical is classical strength in bits, following NIST SP 800-57 Part 1 (RSA-2048 -> 112,
# RSA-3072 -> 128, RSA-7680 -> 192, RSA-15360 -> 256).
#
# OIDs appear only where unambiguous. A wrong OID is worse than an absent one, because consumers
# match on it. ML-KEM and ML-DSA use the NIST CSOR arcs.
# ---------------------------------------------------------------------------------------------
_ALG: Dict[str, Dict[str, Any]] = {
    # post-quantum KEMs (FIPS 203)
    "ML-KEM-512":  {"primitive": "kem", "nist": 1, "classical": 128, "oid": "2.16.840.1.101.3.4.4.1",
                    "functions": ["keygen", "encapsulate", "decapsulate"]},
    "ML-KEM-768":  {"primitive": "kem", "nist": 3, "classical": 192, "oid": "2.16.840.1.101.3.4.4.2",
                    "functions": ["keygen", "encapsulate", "decapsulate"]},
    "ML-KEM-1024": {"primitive": "kem", "nist": 5, "classical": 256, "oid": "2.16.840.1.101.3.4.4.3",
                    "functions": ["keygen", "encapsulate", "decapsulate"]},
    # post-quantum signatures (FIPS 204 / FIPS 205)
    "ML-DSA-44": {"primitive": "signature", "nist": 2, "classical": 128,
                  "oid": "2.16.840.1.101.3.4.3.17", "functions": ["keygen", "sign", "verify"]},
    "ML-DSA-65": {"primitive": "signature", "nist": 3, "classical": 192,
                  "oid": "2.16.840.1.101.3.4.3.18", "functions": ["keygen", "sign", "verify"]},
    "ML-DSA-87": {"primitive": "signature", "nist": 5, "classical": 256,
                  "oid": "2.16.840.1.101.3.4.3.19", "functions": ["keygen", "sign", "verify"]},
    "SLH-DSA-128": {"primitive": "signature", "nist": 1, "classical": 128,
                    "functions": ["keygen", "sign", "verify"]},
    "SLH-DSA-192": {"primitive": "signature", "nist": 3, "classical": 192,
                    "functions": ["keygen", "sign", "verify"]},
    "SLH-DSA-256": {"primitive": "signature", "nist": 5, "classical": 256,
                    "functions": ["keygen", "sign", "verify"]},

    # classical public key: quantum-broken, hence nist 0
    "RSA-1024": {"primitive": "pke", "nist": 0, "classical": 80, "oid": "1.2.840.113549.1.1.1",
                 "functions": ["keygen", "encrypt", "decrypt", "sign", "verify"]},
    "RSA-2048": {"primitive": "pke", "nist": 0, "classical": 112, "oid": "1.2.840.113549.1.1.1",
                 "functions": ["keygen", "encrypt", "decrypt", "sign", "verify"]},
    "RSA-3072": {"primitive": "pke", "nist": 0, "classical": 128, "oid": "1.2.840.113549.1.1.1",
                 "functions": ["keygen", "encrypt", "decrypt", "sign", "verify"]},
    "RSA-4096": {"primitive": "pke", "nist": 0, "classical": 152, "oid": "1.2.840.113549.1.1.1",
                 "functions": ["keygen", "encrypt", "decrypt", "sign", "verify"]},
    "ECDSA-P256": {"primitive": "signature", "nist": 0, "classical": 128, "curve": "P-256",
                   "oid": "1.2.840.10045.4.3.2", "functions": ["keygen", "sign", "verify"]},
    "ECDSA-P384": {"primitive": "signature", "nist": 0, "classical": 192, "curve": "P-384",
                   "oid": "1.2.840.10045.4.3.3", "functions": ["keygen", "sign", "verify"]},
    "ECDSA-P521": {"primitive": "signature", "nist": 0, "classical": 256, "curve": "P-521",
                   "oid": "1.2.840.10045.4.3.4", "functions": ["keygen", "sign", "verify"]},
    "ECDH":    {"primitive": "key-agree", "nist": 0, "classical": 128, "functions": ["keygen", "keyderive"]},
    "ECDHE":   {"primitive": "key-agree", "nist": 0, "classical": 128, "functions": ["keygen", "keyderive"]},
    "DH":      {"primitive": "key-agree", "nist": 0, "classical": 112, "functions": ["keygen", "keyderive"]},
    "DHE":     {"primitive": "key-agree", "nist": 0, "classical": 112, "functions": ["keygen", "keyderive"]},
    "X25519":  {"primitive": "key-agree", "nist": 0, "classical": 128, "curve": "Curve25519",
                "oid": "1.3.101.110", "functions": ["keygen", "keyderive"]},
    "X448":    {"primitive": "key-agree", "nist": 0, "classical": 224, "curve": "Curve448",
                "oid": "1.3.101.111", "functions": ["keygen", "keyderive"]},
    "Ed25519": {"primitive": "signature", "nist": 0, "classical": 128, "curve": "Curve25519",
                "oid": "1.3.101.112", "functions": ["keygen", "sign", "verify"]},
    "Ed448":   {"primitive": "signature", "nist": 0, "classical": 224, "curve": "Curve448",
                "oid": "1.3.101.113", "functions": ["keygen", "sign", "verify"]},
    "DSA":     {"primitive": "signature", "nist": 0, "classical": 112, "functions": ["keygen", "sign", "verify"]},

    # symmetric. AEAD modes use the "ae" primitive, not "block-cipher".
    "AES-128-GCM": {"primitive": "ae", "nist": 1, "classical": 128, "mode": "gcm",
                    "oid": "2.16.840.1.101.3.4.1.6", "functions": ["encrypt", "decrypt", "tag"]},
    "AES-256-GCM": {"primitive": "ae", "nist": 5, "classical": 256, "mode": "gcm",
                    "oid": "2.16.840.1.101.3.4.1.46", "functions": ["encrypt", "decrypt", "tag"]},
    "AES-128-CCM": {"primitive": "ae", "nist": 1, "classical": 128, "mode": "ccm",
                    "functions": ["encrypt", "decrypt", "tag"]},
    "AES-256-CCM": {"primitive": "ae", "nist": 5, "classical": 256, "mode": "ccm",
                    "functions": ["encrypt", "decrypt", "tag"]},
    "AES-128-CBC": {"primitive": "block-cipher", "nist": 1, "classical": 128, "mode": "cbc",
                    "oid": "2.16.840.1.101.3.4.1.2", "functions": ["encrypt", "decrypt"]},
    "AES-256-CBC": {"primitive": "block-cipher", "nist": 5, "classical": 256, "mode": "cbc",
                    "oid": "2.16.840.1.101.3.4.1.42", "functions": ["encrypt", "decrypt"]},
    "CHACHA20-POLY1305": {"primitive": "ae", "nist": 1, "classical": 256,
                          "functions": ["encrypt", "decrypt", "tag"]},
    "3DES": {"primitive": "block-cipher", "nist": 0, "classical": 112, "mode": "cbc",
             "functions": ["encrypt", "decrypt"]},
    "RC4":  {"primitive": "stream-cipher", "nist": 0, "classical": 0, "functions": ["encrypt", "decrypt"]},

    # hashes
    "SHA-1":   {"primitive": "hash", "nist": 0, "classical": 0, "oid": "1.3.14.3.2.26", "functions": ["digest"]},
    "SHA-256": {"primitive": "hash", "nist": 2, "classical": 128, "oid": "2.16.840.1.101.3.4.2.1", "functions": ["digest"]},
    "SHA-384": {"primitive": "hash", "nist": 4, "classical": 192, "oid": "2.16.840.1.101.3.4.2.2", "functions": ["digest"]},
    "SHA-512": {"primitive": "hash", "nist": 4, "classical": 256, "oid": "2.16.840.1.101.3.4.2.3", "functions": ["digest"]},
    "MD5":     {"primitive": "hash", "nist": 0, "classical": 0, "oid": "1.2.840.113549.2.5", "functions": ["digest"]},
}

# X.509 signature algorithm strings mapped to (signing algorithm, digest). Both become components,
# which is what lets a certificate reference them by bom-ref instead of repeating a string.
_SIG_ALG_PATTERNS: List[Tuple[str, str, Optional[str]]] = [
    (r"sha256with?rsa|rsa.*sha-?256", "RSA-2048", "SHA-256"),
    (r"sha384with?rsa|rsa.*sha-?384", "RSA-3072", "SHA-384"),
    (r"sha512with?rsa|rsa.*sha-?512", "RSA-4096", "SHA-512"),
    (r"sha1with?rsa|rsa.*sha-?1\b",   "RSA-2048", "SHA-1"),
    (r"ecdsa.*sha-?256|sha256.*ecdsa", "ECDSA-P256", "SHA-256"),
    (r"ecdsa.*sha-?384|sha384.*ecdsa", "ECDSA-P384", "SHA-384"),
    (r"ecdsa.*sha-?512|sha512.*ecdsa", "ECDSA-P521", "SHA-512"),
    (r"ed25519", "Ed25519", None),
    (r"ed448", "Ed448", None),
    (r"ml-?dsa-?44|dilithium2", "ML-DSA-44", None),
    (r"ml-?dsa-?65|dilithium3", "ML-DSA-65", None),
    (r"ml-?dsa-?87|dilithium5", "ML-DSA-87", None),
]


def _first_int(text: str) -> int:
    m = re.search(r"(\d{2,5})", str(text or ""))
    return int(m.group(1)) if m else 0


def canonical_algorithm(name: str, key_bits: int = 0) -> Optional[str]:
    """Resolve a scanner-provided algorithm string to a key in _ALG, or None if unrecognised.

    Inputs are messy in practice: "RSA" with the bit count in a separate field, "ECDHE",
    "secp384r1", "id-ecPublicKey", "TLS_AES_256_GCM_SHA384".
    """
    raw = str(name or "").strip()
    if not raw:
        return None
    n = re.sub(r"[\s_]+", "-", raw).upper()
    if n in _ALG:
        return n

    # Hybrid TLS key-exchange groups first. "X25519MLKEM768" starts with X25519, so the prefix
    # rules below resolved it to plain X25519 -- reporting an endpoint that had already migrated to
    # hybrid post-quantum key exchange as classical elliptic-curve Diffie-Hellman, which is the
    # exact opposite of the truth. The ML-KEM half is what carries the post-quantum security, so
    # that is the component the CBOM names.
    flat = n.replace("-", "")
    if "MLKEM" in flat or "KYBER" in flat:
        m = re.search(r"(?:MLKEM|KYBER)(512|768|1024)", flat)
        key = f"ML-KEM-{m.group(1)}" if m else "ML-KEM-768"
        return key if key in _ALG else "ML-KEM-768"

    if n.startswith("RSA"):
        # No size anywhere means the scan did not observe one. Defaulting to 2048 reported the
        # whole estate as RSA-2048 -- including every 4096-bit certificate -- and an auditor
        # reading the CBOM could not tell a measured key size from a filled-in one. Unresolved is
        # the honest answer; the caller omits the component rather than naming a key size.
        bits = key_bits or _first_int(n)
        if not bits:
            return None
        for candidate in (1024, 2048, 3072, 4096):
            if bits <= candidate:
                return f"RSA-{candidate}"
        return "RSA-4096"
    if "CHACHA20" in n:
        return "CHACHA20-POLY1305"
    if n in {"SECP256R1", "PRIME256V1", "P-256"}:
        return "ECDSA-P256"
    if n in {"SECP384R1", "P-384"}:
        return "ECDSA-P384"
    if n in {"SECP521R1", "P-521"}:
        return "ECDSA-P521"
    if n.startswith("X25519"):
        return "X25519"
    if n.startswith("X448"):
        return "X448"
    if n.startswith("ED25519"):
        return "Ed25519"
    if n.startswith("ED448"):
        return "Ed448"
    if n.startswith("ECDHE"):
        return "ECDHE"
    if n.startswith("ECDH"):
        return "ECDH"
    if n.startswith("DHE"):
        return "DHE"
    if n == "DH" or n.startswith("DH-"):
        return "DH"
    if n in {"EC", "ECC", "ECDSA", "ID-ECPUBLICKEY", "ECPUBLICKEY"} or n.startswith("ECDSA"):
        # Same as RSA above: a bare "EC" with no curve and no key size used to resolve to P-256,
        # so P-384 and P-521 endpoints were exported at the P-256 security level.
        bits = key_bits or _first_int(n)
        if not bits:
            return None
        if bits >= 500:
            return "ECDSA-P521"
        return "ECDSA-P384" if bits >= 384 else "ECDSA-P256"
    if n.startswith("SHA"):
        digits = _first_int(n)
        if digits in (1, 256, 384, 512):
            return f"SHA-{digits}"
        if n in {"SHA1", "SHA-1"}:
            return "SHA-1"
    if n.startswith("ML-KEM") or "KYBER" in n:
        bits = _first_int(n)
        key = f"ML-KEM-{bits}"
        return key if key in _ALG else "ML-KEM-768"
    if n.startswith("ML-DSA") or "DILITHIUM" in n:
        bits = _first_int(n)
        key = f"ML-DSA-{bits}"
        return key if key in _ALG else "ML-DSA-65"
    if n.startswith("SLH-DSA") or "SPHINCS" in n:
        bits = _first_int(n)
        key = f"SLH-DSA-{bits}"
        return key if key in _ALG else "SLH-DSA-128"
    if n.startswith("AES"):
        bits = _first_int(n) or 128
        mode = "GCM" if "GCM" in n else ("CCM" if "CCM" in n else "CBC")
        key = f"AES-{256 if bits >= 256 else 128}-{mode}"
        return key if key in _ALG else "AES-128-CBC"
    if "3DES" in n or "DES-EDE3" in n or n == "DES":
        return "3DES"
    if n.startswith("RC4"):
        return "RC4"
    if n == "MD5":
        return "MD5"
    if n == "DSA":
        return "DSA"
    return None


def algorithms_in_cipher_suite(suite: str, key_bits: int = 0) -> List[str]:
    """Decompose a TLS cipher suite name into the canonical algorithms it uses.

    TLS_AES_256_GCM_SHA384 -> ["AES-256-GCM", "SHA-384"]. A suite recorded as one opaque string
    tells a CBOM consumer nothing; its constituent algorithms are the point of the document.

    ``key_bits`` is the certificate's observed public-key size. The RSA / ECDSA token in a suite
    name identifies the *authentication* algorithm but carries no key size, so without this the
    decomposition named RSA-2048 for an RSA-4096 endpoint. Callers that know the size pass it;
    callers that do not get the historical default, which is why generate_cbom() always passes it.
    """
    s = str(suite or "").upper()
    if not s:
        return []
    found: List[str] = []

    def add(key: Optional[str]) -> None:
        if key and key in _ALG and key not in found:
            found.append(key)

    if "CHACHA20" in s:
        add("CHACHA20-POLY1305")
    elif "AES" in s:
        # Read the key size from the AES token itself. Searching the whole suite name for "256"
        # matches the digest in TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 and reports a 128-bit cipher
        # as 256-bit, which understates the risk in the exported CBOM.
        m = re.search(r"AES[-_]?(128|192|256)", s)
        bits = int(m.group(1)) if m else 128
        mode = "GCM" if "GCM" in s else ("CCM" if "CCM" in s else "CBC")
        add(f"AES-{256 if bits >= 256 else 128}-{mode}")
    if "3DES" in s or "DES-EDE3" in s:
        add("3DES")
    if "RC4" in s:
        add("RC4")

    for token, key in (("SHA384", "SHA-384"), ("SHA512", "SHA-512"),
                       ("SHA256", "SHA-256"), ("SHA", "SHA-1")):
        if token in s:
            add(key)
            break

    if "ECDHE" in s:
        add("ECDHE")
    elif "ECDH" in s:
        add("ECDH")
    elif "DHE" in s:
        add("DHE")

    if "ECDSA" in s:
        add(canonical_algorithm("ECDSA", key_bits) or "ECDSA-P256")
    elif "RSA" in s:
        add(canonical_algorithm("RSA", key_bits) or "RSA-2048")
    return found


#: TLS supported-group names that are key agreement, not signatures. A group called "secp384r1"
#: resolves through canonical_algorithm() to ECDSA-P384 -- a *signature* algorithm -- which would
#: put a signature component into the CBOM to describe a Diffie-Hellman key exchange.
_KEY_EXCHANGE_GROUPS: Dict[str, List[str]] = {
    "SECP256R1": ["ECDH"], "PRIME256V1": ["ECDH"], "P-256": ["ECDH"],
    "SECP384R1": ["ECDH"], "P-384": ["ECDH"],
    "SECP521R1": ["ECDH"], "P-521": ["ECDH"],
    "X25519": ["X25519"], "X448": ["X448"],
}


def key_exchange_algorithms(group_name: str) -> List[str]:
    """The algorithms a negotiated TLS key-exchange group is built from.

    A hybrid group is genuinely two algorithms -- X25519MLKEM768 is X25519 *and* ML-KEM-768 -- and
    a CBOM that named only one of them would either hide the post-quantum half or hide the
    classical half that is still there to be broken.
    """
    raw = re.sub(r"[\s_]+", "-", str(group_name or "").strip()).upper()
    if not raw:
        return []
    if raw.startswith("FFDHE"):
        return ["DH"]
    flat = raw.replace("-", "")
    out: List[str] = []
    if "MLKEM" in flat or "KYBER" in flat:
        for classical, key in (("X25519", "X25519"), ("X448", "X448"),
                               ("SECP256R1", "ECDH"), ("P256", "ECDH"),
                               ("SECP384R1", "ECDH"), ("P384", "ECDH")):
            if classical in flat:
                out.append(key)
                break
        pq = canonical_algorithm(raw)
        if pq:
            out.append(pq)
        return out
    if raw in _KEY_EXCHANGE_GROUPS:
        return list(_KEY_EXCHANGE_GROUPS[raw])
    resolved = canonical_algorithm(raw)
    return [resolved] if resolved else []


def signature_algorithm_parts(sig_alg: str, key_bits: int = 0) -> Tuple[Optional[str], Optional[str]]:
    """Split an X.509 signature algorithm into (signing algorithm, digest) canonical keys.

    ``key_bits`` is the observed public-key size. An X.509 signature algorithm string names the
    algorithm and the digest but never the key size, so the table below has to assume one -- and
    it assumed 2048 for every RSA signature, which put an RSA-2048 component into the CBOM of an
    estate that contains no 2048-bit key at all. Where the certificate's own key size is known it
    is used instead; where it is not, the table's assumption stands and is the caller's to
    interpret. (Strictly this is the *issuer's* key, which for a self-signed certificate is the
    same key and for a CA-issued one is unobserved either way.)
    """
    s = str(sig_alg or "").lower().replace("_", "").replace(" ", "").replace("encryption", "")
    for pattern, signer, digest in _SIG_ALG_PATTERNS:
        if re.search(pattern, s):
            if key_bits and signer and (signer.startswith("RSA-") or signer.startswith("ECDSA-")):
                family = "RSA" if signer.startswith("RSA-") else "ECDSA"
                signer = canonical_algorithm(family, key_bits) or signer
            return signer, digest
    return canonical_algorithm(sig_alg, key_bits), None


def _stable_ref(prefix: str, *parts: Any) -> str:
    """Content-derived bom-ref.

    Deliberately not random: two exports of an unchanged estate then produce identical references and
    can be diffed. Only the document serialNumber has to be unique per BOM, and it still is.
    """
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def _protocol_version(tls_version: str) -> str:
    """Normalise "TLSv1.3" to "1.3"; the protocol itself is already stated as `type: tls`."""
    m = re.search(r"(\d+\.\d+)", str(tls_version or ""))
    return m.group(1) if m else str(tls_version or "")


class _AlgorithmRegistry:
    """Creates one component per distinct algorithm and hands back its bom-ref."""

    def __init__(self) -> None:
        self._refs: Dict[str, str] = {}
        self.components: List[Dict[str, Any]] = []

    def ref(self, algorithm: Optional[str], key_bits: int = 0) -> Optional[str]:
        key = canonical_algorithm(algorithm or "", key_bits)
        if not key:
            return None
        if key in self._refs:
            return self._refs[key]

        spec = _ALG[key]
        props: Dict[str, Any] = {
            "primitive": spec["primitive"],
            "executionEnvironment": EXEC_SOFTWARE,
            "implementationPlatform": PLATFORM_GENERIC,
            "classicalSecurityLevel": int(spec.get("classical") or 0),
            "nistQuantumSecurityLevel": int(spec.get("nist") or 0),
        }
        for field in ("curve", "mode", "padding"):
            if spec.get(field):
                props[field] = spec[field]
        if spec.get("functions"):
            props["cryptoFunctions"] = list(spec["functions"])
        param = _first_int(key)
        if param:
            props["parameterSetIdentifier"] = str(param)

        crypto: Dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": props}
        if spec.get("oid"):
            crypto["oid"] = spec["oid"]

        bom_ref = f"alg:{key.lower()}"
        self.components.append({
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": key,
            "cryptoProperties": crypto,
        })
        self._refs[key] = bom_ref
        return bom_ref


def generate_cbom(scan_results: List[Dict[str, Any]],
                  org_name: str = "",
                  scan_id: str = "") -> Dict[str, Any]:
    """Generate a CycloneDX 1.6 CBOM from a list of scan result dicts.

    Each result is the per-host dict produced by scanner.scan_host().
    """
    registry = _AlgorithmRegistry()
    endpoints: List[Dict[str, Any]] = []
    certificates: List[Dict[str, Any]] = []
    # bom-refs must be unique across the document, and dependency entries unique by ref. Because
    # refs are derived from content, a caller passing scan history -- several rows for the same
    # host:port, which is exactly what an organization-wide export does -- would otherwise emit the
    # same component twice and produce a document the schema rejects. First occurrence wins, so
    # callers should pass results newest-first for the freshest view of each endpoint.
    seen_endpoints: set = set()
    seen_certificates: set = set()
    dependency_map: Dict[str, set] = {}

    def add_dependency(ref: str, depends_on: List[str]) -> None:
        if not ref or not depends_on:
            return
        dependency_map.setdefault(ref, set()).update(depends_on)

    for r in scan_results or []:
        if r.get("error"):
            continue
        host = str(r.get("host") or "")
        port = r.get("port") or 443
        suite = str(r.get("cipher_name") or "")

        observed_key_bits = int(r.get("cert_key_bits") or r.get("key_bits") or 0)
        alg_refs: List[str] = []
        for alg in algorithms_in_cipher_suite(suite, observed_key_bits):
            ref = registry.ref(alg)
            if ref and ref not in alg_refs:
                alg_refs.append(ref)
        for alg in key_exchange_algorithms(r.get("key_exchange") or ""):
            ref = registry.ref(alg)
            if ref and ref not in alg_refs:
                alg_refs.append(ref)
        sig_field_ref = registry.ref(str(r.get("signature_algorithm") or ""), observed_key_bits)
        if sig_field_ref and sig_field_ref not in alg_refs:
            alg_refs.append(sig_field_ref)

        proto_ref = _stable_ref("proto", host, port)
        protocol_props: Dict[str, Any] = {
            "type": "tls",
            "version": _protocol_version(r.get("tls_version") or ""),
        }
        if suite:
            protocol_props["cipherSuites"] = [{"name": suite, "algorithms": list(alg_refs)}]
        if alg_refs:
            protocol_props["cryptoRefArray"] = list(alg_refs)
        if proto_ref not in seen_endpoints:
            seen_endpoints.add(proto_ref)
            endpoints.append({
                "type": "cryptographic-asset",
                "bom-ref": proto_ref,
                "name": f"TLS endpoint {host}:{port}" if host else "TLS endpoint",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": protocol_props},
            })

        depends_on = list(alg_refs)

        # The certificate block reads cert_* keys, but scanner.scan_host() -- which the docstring
        # above names as the input -- emits subject/issuer/key_type/key_bits/sig_algorithm/
        # not_before/not_after. Nothing bridged the two, so `subject` was always empty and every
        # CBOM exported from a real scan contained cipher-suite algorithms and no certificate,
        # no public key and no signature algorithm at all. Both spellings are accepted now.
        subject = str(r.get("cert_subject") or r.get("subject") or "")
        if subject:
            signer, digest = signature_algorithm_parts(
                r.get("cert_sig_alg") or r.get("sig_algorithm") or "", observed_key_bits
            )
            sig_ref = registry.ref(signer)
            digest_ref = registry.ref(digest)
            key_type_name = str(r.get("cert_key_type") or r.get("key_type") or "")
            key_ref = registry.ref(key_type_name, observed_key_bits)
            if not key_ref:
                # A bare "EC" with no bit count no longer resolves (it used to silently become
                # P-256). The observed curve name does resolve unambiguously, so prefer it before
                # giving up and leaving the certificate without a public-key reference.
                key_ref = registry.ref(str(r.get("key_curve") or r.get("cert_key_curve") or ""))

            issuer_name = str(r.get("cert_issuer") or r.get("issuer") or "")
            cert_props: Dict[str, Any] = {
                "subjectName": subject,
                "issuerName": issuer_name,
                "certificateFormat": "X.509",
            }
            not_before = r.get("cert_not_before") or r.get("not_before")
            not_after = r.get("cert_not_after") or r.get("not_after")
            if not_before:
                cert_props["notValidBefore"] = str(not_before)
            if not_after:
                cert_props["notValidAfter"] = str(not_after)
            # refType fields: these must name a component in this BOM, not restate an algorithm name.
            if sig_ref:
                cert_props["signatureAlgorithmRef"] = sig_ref
            if key_ref:
                cert_props["subjectPublicKeyRef"] = key_ref

            cert_ref = _stable_ref("cert", subject, issuer_name, host)
            if cert_ref not in seen_certificates:
                seen_certificates.add(cert_ref)
                certificates.append({
                    "type": "cryptographic-asset",
                    "bom-ref": cert_ref,
                    "name": subject,
                    "cryptoProperties": {"assetType": "certificate",
                                         "certificateProperties": cert_props},
                })
            add_dependency(cert_ref, [x for x in (sig_ref, digest_ref, key_ref) if x])
            depends_on.append(cert_ref)

        add_dependency(proto_ref, depends_on)

    root_ref = _stable_ref("root", org_name or "morrow", scan_id or "")
    components = endpoints + certificates + registry.components
    top_level = sorted({c["bom-ref"] for c in endpoints + certificates})
    if top_level:
        add_dependency(root_ref, top_level)
    dependencies = [
        {"ref": ref, "dependsOn": sorted(deps)}
        for ref, deps in dependency_map.items() if deps
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{
                "type": "application",
                "name": "morrow",
                "publisher": "Morrow",
                "version": TOOL_VERSION,
            }]},
            "component": {
                "type": "platform",
                "bom-ref": root_ref,
                "name": org_name or "Morrow Export",
                **({"description": f"Scan ID: {scan_id}"} if scan_id else {}),
            },
        },
        "components": components,
        "dependencies": [d for d in dependencies if d.get("dependsOn")],
        "vulnerabilities": _vulnerabilities_from_results(scan_results or []),
    }


def get_cbom_for_org(org_id: str, limit: int = 5000) -> Dict[str, Any]:
    """CBOM covering everything currently recorded for an organization.

    services/ai_agent.py imported this name and it did not exist, so its CBOM tool fell through to a
    hand-rolled document declaring `"type": "crypto-algo"` -- not a CycloneDX component type -- built
    from columns (`algorithm`, `pq_safe`) that scan_results does not have. Both paths raised, so the
    tool never returned a CBOM at all. One generator now serves every caller.
    """
    from db import list_scan_results_since

    rows = list_scan_results_since("1970-01-01T00:00:00Z", limit=limit) or []
    results: List[Dict[str, Any]] = []
    for row in rows:
        asset_key = str(row.get("asset_key") or "")
        host, _, tail = asset_key.partition(":")
        port_text = tail.split(":")[0] if tail else ""
        results.append({
            "host": host or asset_key,
            "port": int(port_text) if port_text.isdigit() else 443,
            "tls_version": row.get("tls_version") or "",
            "cipher_name": row.get("cipher_name") or "",
            "key_exchange": row.get("key_exchange") or "",
            "signature_algorithm": row.get("sig_algorithm") or "",
            "cert_key_type": row.get("key_type") or "",
            "cert_subject": row.get("cert_subject") or "",
            "cert_issuer": row.get("cert_issuer") or "",
            "cert_sig_alg": row.get("sig_algorithm") or "",
        })
    return generate_cbom(results, org_name=str(org_id or ""), scan_id="org-aggregate")


def _vulnerabilities_from_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Quantum-vulnerability findings expressed as CycloneDX vulnerabilities.

    `affects[].ref` must name a component in this BOM. It previously carried "host:port", which
    matched no bom-ref, so every finding pointed at nothing a consumer could resolve.
    """
    vulns: List[Dict[str, Any]] = []
    # Same reason components are deduplicated: refs are content-derived, and scan history repeats the
    # same finding for the same endpoint, which would emit duplicate bom-refs and fail validation.
    seen: set = set()
    valid_severities = {"critical", "high", "medium", "low", "info", "none", "unknown"}
    for r in results:
        host = str(r.get("host") or "")
        port = r.get("port") or 443
        target_ref = _stable_ref("proto", host, port)
        for f in (r.get("findings") or []):
            severity = str(f.get("severity") or "medium").lower()
            if severity not in valid_severities:
                severity = "medium"
            rule = str(f.get("rule_id") or "UNKNOWN")
            vuln_ref = _stable_ref("vuln", host, port, rule)
            if vuln_ref in seen:
                continue
            seen.add(vuln_ref)
            entry: Dict[str, Any] = {
                "bom-ref": vuln_ref,
                "id": f"Post-quantum-{rule}",
                "source": {"name": "Morrow"},
                "ratings": [{"severity": severity, "method": "other"}],
                "affects": [{"ref": target_ref}],
            }
            if f.get("title"):
                entry["description"] = str(f["title"])
            if f.get("fix"):
                entry["detail"] = str(f["fix"])
            vulns.append(entry)
    return vulns
