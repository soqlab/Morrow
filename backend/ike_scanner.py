"""
IKEv2 (IPsec VPN) endpoint scanner for post-quantum readiness assessment.

Sends unauthenticated IKE_SA_INIT requests to UDP 500 (or 4500 with the RFC 3948 non-ESP marker)
and records which transforms the responder accepts:

- Encryption (Transform Type 1), PRF (2), Integrity (3), Key Exchange Method (4)
- RFC 9370 Additional Key Exchanges ADDKE1..ADDKE7 (Transform Types 6-12), which is where a
  hybrid post-quantum IPsec deployment puts ML-KEM
- ML-KEM as a key exchange method: IANA "IKEv2 Transform Type 4 - Key Exchange Method Transform
  IDs" values 35 (ml-kem-512), 36 (ml-kem-768), 37 (ml-kem-1024), registered by
  draft-ietf-ipsecme-ikev2-mlkem section 2.2.
  https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml (checked 2026-11-05;
  registry last updated 2026-10-28)

What it does not do: no authentication, no IKE_AUTH, no IKE_INTERMEDIATE, no Child SA, no tunnel.
The scanner never completes a key exchange; it reads the responder's answer to SA_INIT (an SA
payload, INVALID_KE_PAYLOAD, or NO_PROPOSAL_CHOSEN) and stops.

How acceptance is read. RFC 7296 section 1.2: a responder that selects a proposal whose key
exchange method differs from the initiator's KE payload MUST answer INVALID_KE_PAYLOAD naming the
method it wants. So "INVALID_KE_PAYLOAD" means "this proposal was acceptable", and the scanner
never needs a valid public value for the group under test (in particular it never needs an ML-KEM
encapsulation key). NO_PROPOSAL_CHOSEN means rejected.

Enumeration varies one transform type at a time and offers every known value of the others, so a
probe's answer is about the candidate alone. Apart from the first, every probe's KE payload names a
group its proposals do not offer, so the responder answers without creating any IKE SA state (see
_Session). Probes are paced (_PROBE_INTERVAL), capped (_MAX_PROBES), and the scan stops early if
the responder stops answering. A full scan is about 80 datagrams.

IKEv1: a single Main Mode probe reports whether the responder still speaks IKEv1 and which
transform it chose from a classical offer. IKEv1 transforms are not enumerated.

Scope: refused before any packet is sent for hosts outside the organization's verified domains,
using the same check as scanner.scan_host and ssh_scanner.scan_ssh.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

_TIMEOUT = 3.0           # seconds to wait for one response
_RETRIES = 2             # retransmissions per probe (UDP); a responder's first answer can be slow
_PROBE_INTERVAL = 0.2    # minimum seconds between two packets to the same responder
_MAX_PROBES = 200        # hard cap on IKE_SA_INIT datagrams per scan (COOKIE round trips count)
_MAX_SILENT = 4          # consecutive unanswered probes before the scan gives up
_MAX_RESPONSE = 16384    # larger datagrams are ignored, not parsed
_MAX_COOKIE = 64         # RFC 7296 section 2.6: 1 to 64 octets; a COOKIE is echoed back verbatim

# ── IANA IKEv2 registries ────────────────────────────────────────────────────

T_ENCR, T_PRF, T_INTEG, T_KE = 1, 2, 3, 4
T_ADDKE = (6, 7, 8, 9, 10, 11, 12)   # RFC 9370 Additional Key Exchange 1..7

ENCR_NAMES: Dict[int, str] = {
    1: "DES_IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "BLOWFISH",
    8: "3IDEA", 9: "DES_IV32", 11: "NULL", 12: "AES_CBC", 13: "AES_CTR", 14: "AES_CCM_8",
    15: "AES_CCM_12", 16: "AES_CCM_16", 18: "AES_GCM_8", 19: "AES_GCM_12", 20: "AES_GCM_16",
    21: "NULL_AUTH_AES_GMAC", 23: "CAMELLIA_CBC", 24: "CAMELLIA_CTR", 25: "CAMELLIA_CCM_8",
    26: "CAMELLIA_CCM_12", 27: "CAMELLIA_CCM_16", 28: "CHACHA20_POLY1305",
    32: "KUZNYECHIK_MGM_KTREE", 33: "MAGMA_MGM_KTREE",
}
_AEAD_ENCR = frozenset({14, 15, 16, 18, 19, 20, 25, 26, 27, 28, 32, 33})

PRF_NAMES: Dict[int, str] = {
    1: "HMAC_MD5", 2: "HMAC_SHA1", 3: "HMAC_TIGER", 4: "AES128_XCBC", 5: "HMAC_SHA2_256",
    6: "HMAC_SHA2_384", 7: "HMAC_SHA2_512", 8: "AES128_CMAC", 9: "HMAC_STREEBOG_512",
}

INTEG_NAMES: Dict[int, str] = {
    0: "NONE", 1: "HMAC_MD5_96", 2: "HMAC_SHA1_96", 3: "DES_MAC", 4: "KPDK_MD5",
    5: "AES_XCBC_96", 6: "HMAC_MD5_128", 7: "HMAC_SHA1_160", 8: "AES_CMAC_96",
    9: "AES_128_GMAC", 10: "AES_192_GMAC", 11: "AES_256_GMAC", 12: "HMAC_SHA2_256_128",
    13: "HMAC_SHA2_384_192", 14: "HMAC_SHA2_512_256",
}

KE_NAMES: Dict[int, str] = {
    0: "NONE", 1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048",
    15: "MODP_3072", 16: "MODP_4096", 17: "MODP_6144", 18: "MODP_8192",
    19: "ECP_256", 20: "ECP_384", 21: "ECP_521", 22: "MODP_1024_S160",
    23: "MODP_2048_S224", 24: "MODP_2048_S256", 25: "ECP_192", 26: "ECP_224",
    27: "BRAINPOOL_P224R1", 28: "BRAINPOOL_P256R1", 29: "BRAINPOOL_P384R1",
    30: "BRAINPOOL_P512R1", 31: "CURVE25519", 32: "CURVE448",
    33: "GOST3410_2012_256", 34: "GOST3410_2012_512",
    35: "ML_KEM_512", 36: "ML_KEM_768", 37: "ML_KEM_1024",
}
# Post-quantum key exchange methods (IANA Transform Type 4 values 35-37).
PQ_KE = frozenset({35, 36, 37})

# Notify message types (IANA IKEv2 Notify Message Types)
N_INVALID_SYNTAX = 7
N_NO_PROPOSAL_CHOSEN = 14
N_INVALID_KE_PAYLOAD = 17
N_NAT_DETECTION_SOURCE_IP = 16388
N_NAT_DETECTION_DESTINATION_IP = 16389
N_COOKIE = 16390
N_REDIRECT_SUPPORTED = 16406
N_IKEV2_FRAGMENTATION_SUPPORTED = 16430
N_SIGNATURE_HASH_ALGORITHMS = 16431
N_INTERMEDIATE_EXCHANGE_SUPPORTED = 16438
NOTIFY_NAMES: Dict[int, str] = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE",
    16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "REDIRECT_SUPPORTED", 16418: "CHILDLESS_IKEV2_SUPPORTED",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
}

# Payload types
P_NONE, P_SA, P_KE, P_NONCE, P_NOTIFY, P_VENDOR = 0, 33, 34, 40, 41, 43
_EXCH_IKE_SA_INIT = 34
_ATTR_KEY_LENGTH = 14

# ── Candidates offered by the scanner ────────────────────────────────────────

# (transform id, key length or None)
_ENCR_CANDIDATES: List[Tuple[int, Optional[int]]] = [
    (2, None), (3, None), (7, 128), (12, 128), (12, 192), (12, 256), (13, 128), (13, 256),
    (16, 128), (16, 256), (18, 256), (19, 256), (20, 128), (20, 192), (20, 256), (23, 128),
    (23, 256), (28, None),
]
_PRF_CANDIDATES = [1, 2, 4, 5, 6, 7, 8]
_INTEG_CANDIDATES = [1, 2, 5, 8, 12, 13, 14]
_KE_CANDIDATES = [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                  31, 32, 35, 36, 37]
# Sentinel KE payload groups for stateless probing (see _Session). They are left out of the
# baseline offer so that the KE payload never matches; the KE enumeration still asks about each
# of them individually, using the other as its sentinel. A responder that accepts only these two
# weak groups (ECP_192, ECP_224) is found by the KE enumeration but not by the other loops.
_SENTINEL_GROUPS = (26, 25)
_SENTINEL_KE_BYTES = {25: 48, 26: 56}
_BASE_KE = [k for k in _KE_CANDIDATES if k not in _SENTINEL_GROUPS]
# Additional key exchanges worth asking about: ML-KEM first, then the classical methods a
# multi-KE deployment might stack.
_ADDKE_CANDIDATES = [35, 36, 37, 31, 32, 19, 20, 21, 14, 15, 16]


def _all_encr(aead: bool) -> List[Tuple[int, Optional[int]]]:
    return [c for c in _ENCR_CANDIDATES if (c[0] in _AEAD_ENCR) == aead]


# ── Classification, using Morrow's algorithm knowledge base (services/cbom.py) ──

def _encr_label(tid: int, keylen: Optional[int]) -> str:
    name = ENCR_NAMES.get(tid, f"ENCR_{tid}")
    return f"{name}_{keylen}" if keylen else name


def _canonical_for(ttype: int, tid: int, keylen: Optional[int]) -> Optional[str]:
    """The services/cbom._ALG key for an IKE transform, or None when the knowledge base has none."""
    if ttype == T_ENCR:
        bits = keylen or 0
        if tid in (12,):
            return f"AES-{256 if bits >= 256 else 128}-CBC"
        if tid in (18, 19, 20):
            return f"AES-{256 if bits >= 256 else 128}-GCM"
        if tid in (14, 15, 16):
            return f"AES-{256 if bits >= 256 else 128}-CCM"
        if tid == 28:
            return "CHACHA20-POLY1305"
        if tid in (2, 3):
            return "3DES"
        return None
    if ttype in (T_PRF, T_INTEG):
        name = (PRF_NAMES if ttype == T_PRF else INTEG_NAMES).get(tid, "")
        if "MD5" in name:
            return "MD5"
        if "SHA1" in name:
            return "SHA-1"
        if "SHA2_256" in name:
            return "SHA-256"
        if "SHA2_384" in name:
            return "SHA-384"
        if "SHA2_512" in name:
            return "SHA-512"
        return None
    # key exchange (type 4 and ADDKE)
    if tid == 35:
        return "ML-KEM-512"
    if tid == 36:
        return "ML-KEM-768"
    if tid == 37:
        return "ML-KEM-1024"
    if tid == 31:
        return "X25519"
    if tid == 32:
        return "X448"
    if tid in (19, 20, 21, 25, 26, 27, 28, 29, 30, 33, 34):
        return "ECDH"
    if tid in (1, 2, 5, 14, 15, 16, 17, 18, 22, 23, 24):
        return "DH"
    return None


def _nist_category(canonical: Optional[str]) -> Optional[int]:
    if not canonical:
        return None
    try:
        from services.cbom import _ALG
    except Exception:
        return None
    entry = _ALG.get(canonical)
    return int(entry["nist"]) if entry else None


def _describe(ttype: int, tid: int, keylen: Optional[int] = None) -> Dict[str, Any]:
    if ttype == T_ENCR:
        name = _encr_label(tid, keylen)
    elif ttype == T_PRF:
        name = PRF_NAMES.get(tid, f"PRF_{tid}")
    elif ttype == T_INTEG:
        name = INTEG_NAMES.get(tid, f"INTEG_{tid}")
    else:
        name = KE_NAMES.get(tid, f"KE_{tid}")
    canonical = _canonical_for(ttype, tid, keylen)
    nist = _nist_category(canonical)
    out: Dict[str, Any] = {"id": tid, "name": name, "algorithm": canonical, "nist_pq_category": nist}
    if keylen:
        out["key_length"] = keylen
    if ttype not in (T_ENCR, T_PRF, T_INTEG):
        out["post_quantum"] = tid in PQ_KE
    return out


# ── Packet construction ──────────────────────────────────────────────────────

def _transform(ttype: int, tid: int, keylen: Optional[int], last: bool) -> bytes:
    attrs = struct.pack(">HH", 0x8000 | _ATTR_KEY_LENGTH, keylen) if keylen else b""
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _proposal(num: int, transforms: Sequence[Tuple[int, int, Optional[int]]], last: bool) -> bytes:
    body = b"".join(_transform(t, i, k, idx == len(transforms) - 1)
                    for idx, (t, i, k) in enumerate(transforms))
    return struct.pack(">BBHBBBB", 0 if last else 2, 0, 8 + len(body), num, 1, 0, len(transforms)) + body


def _payload(next_type: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_type, 0, 4 + len(body)) + body


def _notify(ntype: int, data: bytes = b"") -> bytes:
    return struct.pack(">BBH", 0, 0, ntype) + data


def _ke_public(group: int) -> bytes:
    """A key-exchange public value of the right size and form for group.

    Only the X25519 value is ever used to finish a computation on the responder's side; for every
    other group the value exists so that the responder can parse the KE payload and answer
    INVALID_KE_PAYLOAD or select the proposal. Values are freshly generated or, for MODP groups,
    the generator (2) itself, which every MODP implementation accepts as a public value.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448

    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    if group == 31:
        return x25519.X25519PrivateKey.generate().public_key().public_bytes(*raw)
    if group == 32:
        return x448.X448PrivateKey.generate().public_key().public_bytes(*raw)
    curves = {19: ec.SECP256R1, 20: ec.SECP384R1, 21: ec.SECP521R1, 25: ec.SECP192R1,
              26: ec.SECP224R1, 28: ec.BrainpoolP256R1, 29: ec.BrainpoolP384R1,
              30: ec.BrainpoolP512R1}
    if group in curves:
        pub = ec.generate_private_key(curves[group]()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return pub[1:]  # IKEv2 ECP encoding is x || y without the 0x04 prefix (RFC 5903)
    modp_bytes = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
                  22: 128, 23: 256, 24: 256}
    if group in modp_bytes:
        return (2).to_bytes(modp_bytes[group], "big")
    raise ValueError(f"no public value generator for group {group}")


def build_sa_init(
    spi_i: bytes,
    proposals: Sequence[Sequence[Tuple[int, int, Optional[int]]]],
    ke_group: int,
    ke_data: bytes,
    nonce: bytes,
    *,
    cookie: bytes = b"",
    nat_src: bytes = b"",
    nat_dst: bytes = b"",
) -> bytes:
    """Serialise an IKE_SA_INIT request (RFC 7296 section 1.2)."""
    sa_body = b"".join(_proposal(i + 1, p, i == len(proposals) - 1) for i, p in enumerate(proposals))
    chain: List[Tuple[int, bytes]] = []
    if cookie:
        chain.append((P_NOTIFY, _notify(N_COOKIE, cookie)))  # COOKIE must be the first payload
    chain.append((P_SA, sa_body))
    chain.append((P_KE, struct.pack(">HH", ke_group, 0) + ke_data))
    chain.append((P_NONCE, nonce))
    if nat_src and nat_dst:
        chain.append((P_NOTIFY, _notify(N_NAT_DETECTION_SOURCE_IP, nat_src)))
        chain.append((P_NOTIFY, _notify(N_NAT_DETECTION_DESTINATION_IP, nat_dst)))
    chain.append((P_NOTIFY, _notify(N_IKEV2_FRAGMENTATION_SUPPORTED)))
    chain.append((P_NOTIFY, _notify(N_INTERMEDIATE_EXCHANGE_SUPPORTED)))  # RFC 9370 section 2.2.1
    body = b""
    for idx, (ptype, pbody) in enumerate(chain):
        nxt = chain[idx + 1][0] if idx + 1 < len(chain) else P_NONE
        body += _payload(nxt, pbody)
    header = spi_i + b"\x00" * 8 + struct.pack(
        ">BBBBII", chain[0][0], 0x20, _EXCH_IKE_SA_INIT, 0x08, 0, 28 + len(body))
    return header + body


# ── Response parsing ─────────────────────────────────────────────────────────

def parse_sa_init_response(data: bytes, spi_i: Optional[bytes] = None) -> Dict[str, Any]:
    """Parse an IKE_SA_INIT response. Raises ValueError on anything that is not one."""
    if len(data) < 28:
        raise ValueError("datagram shorter than an IKE header")
    # The NAT-T non-ESP marker is removed by _Prober, which knows whether it is in use; guessing it
    # here from four leading zero bytes would truncate a message whose initiator SPI starts so.
    ispi, rspi = data[:8], data[8:16]
    nxt, version, exch, flags, msgid, length = struct.unpack(">BBBBII", data[16:28])
    if spi_i is not None and ispi != spi_i:
        raise ValueError("response is for a different IKE SA")
    if version >> 4 != 2:
        raise ValueError(f"not IKEv2 (major version {version >> 4})")
    if exch != _EXCH_IKE_SA_INIT or not flags & 0x20 or msgid != 0:
        raise ValueError("not an IKE_SA_INIT response")
    if length > len(data) or length < 28:
        raise ValueError("truncated IKE message")
    out: Dict[str, Any] = {"responder_spi": rspi.hex(), "transforms": [], "notifies": [],
                           "vendor_ids": [], "ke_group": None}
    off = 28
    while nxt != P_NONE:
        if off + 4 > length:
            raise ValueError("truncated payload header")
        ptype = nxt
        nxt, _crit, plen = struct.unpack_from(">BBH", data, off)
        if plen < 4 or off + plen > length:
            raise ValueError("bad payload length")
        body = data[off + 4: off + plen]
        if ptype == P_SA:
            out["transforms"] = _parse_first_proposal(body)
        elif ptype == P_KE and len(body) >= 4:
            out["ke_group"] = struct.unpack_from(">H", body, 0)[0]
        elif ptype == P_NOTIFY and len(body) >= 4:
            spi_size = body[1]
            if 4 + spi_size > len(body):
                raise ValueError("notify SPI overruns the payload")
            ntype = struct.unpack_from(">H", body, 2)[0]
            out["notifies"].append({"type": ntype, "name": NOTIFY_NAMES.get(ntype, str(ntype)),
                                    "data": body[4 + spi_size:]})
        elif ptype == P_VENDOR:
            out["vendor_ids"].append(body.hex())
        off += plen
    return out


def _parse_first_proposal(body: bytes) -> List[Tuple[int, int, Optional[int]]]:
    """Transforms of the first proposal. Every length is checked against the proposal it sits
    in: a transform that claims more bytes than remain raises ValueError, instead of its
    attributes being read from the bytes that follow (or failing with struct.error)."""
    if len(body) < 8:
        raise ValueError("SA payload too short")
    _more, _r, plen, _num, _proto, spi_size, ntrans = struct.unpack_from(">BBHBBBB", body, 0)
    if plen < 8 or plen > len(body):
        raise ValueError("bad proposal length")
    off = 8 + spi_size
    end = plen
    found: List[Tuple[int, int, Optional[int]]] = []
    for _ in range(ntrans):
        if off + 8 > end:
            break
        _m, _r2, tlen, ttype, _r3, tid = struct.unpack_from(">BBHBBH", body, off)
        if tlen < 8 or off + tlen > end:
            raise ValueError("bad transform length")
        keylen = None
        aoff = off + 8
        while aoff + 4 <= off + tlen:
            atype, aval = struct.unpack_from(">HH", body, aoff)
            if atype & 0x8000:
                if atype & 0x7FFF == _ATTR_KEY_LENGTH:
                    keylen = aval
                aoff += 4
            else:
                aoff += 4 + aval
        found.append((ttype, tid, keylen))
        off += tlen
    return found


def classify_response(parsed: Optional[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
    """("accepted" | "rejected" | "cookie" | "error" | "no_response", detail)."""
    if parsed is None:
        return "no_response", {}
    names = {n["type"]: n for n in parsed["notifies"]}
    if N_COOKIE in names and 1 <= len(names[N_COOKIE]["data"]) <= _MAX_COOKIE:
        return "cookie", {"cookie": names[N_COOKIE]["data"]}
    if parsed["transforms"]:
        return "accepted", {"transforms": parsed["transforms"]}
    if N_INVALID_KE_PAYLOAD in names:
        data = names[N_INVALID_KE_PAYLOAD]["data"]
        group = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
        return "accepted", {"preferred_ke": group}
    if N_NO_PROPOSAL_CHOSEN in names:
        return "rejected", {}
    errors = [n["name"] for n in parsed["notifies"] if n["type"] < 16384]
    return "error", {"notifies": errors}


# ── IKEv1 Main Mode (single probe) ───────────────────────────────────────────

_V1_ENC = {1: "DES_CBC", 5: "3DES_CBC", 7: "AES_CBC"}
_V1_HASH = {1: "MD5", 2: "SHA1", 4: "SHA2_256"}
_V1_AUTH = {1: "PSK", 3: "RSA_SIG"}
_V1_GROUP = {1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048", 19: "ECP_256", 20: "ECP_384"}


def build_ikev1_main_mode(icookie: bytes) -> bytes:
    """First Main Mode message (RFC 2409) offering a broad classical transform set."""
    combos: List[Tuple[int, Optional[int], int, int, int]] = []
    for enc, klen in ((7, 256), (7, 128), (5, None), (1, None)):
        for hsh in (4, 2, 1):
            for grp in (14, 2, 5, 20, 19, 1):
                for auth in (1, 3):
                    combos.append((enc, klen, hsh, auth, grp))
    combos = combos[:120]
    transforms = b""
    for n, (enc, klen, hsh, auth, grp) in enumerate(combos):
        attrs = struct.pack(">HHHHHHHH", 0x8001, enc, 0x8002, hsh, 0x8003, auth, 0x8004, grp)
        attrs += struct.pack(">HHHH", 0x800B, 1, 0x800C, 28800)
        if klen:
            attrs += struct.pack(">HH", 0x800E, klen)
        last = n == len(combos) - 1
        transforms += struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), n + 1, 1, 0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, len(combos)) + transforms
    sa = struct.pack(">II", 1, 1) + proposal
    sa_payload = struct.pack(">BBH", 0, 0, 4 + len(sa)) + sa
    header = icookie + b"\x00" * 8 + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa_payload))
    return header + sa_payload


def parse_ikev1_response(data: bytes, icookie: bytes) -> Dict[str, Any]:
    if len(data) < 28 or data[:8] != icookie:
        raise ValueError("not an IKEv1 response to this probe")
    nxt, version, _exch, _flags, _msgid, length = struct.unpack(">BBBBII", data[16:28])
    off = 28
    end = min(length, len(data))
    out: Dict[str, Any] = {"accepted": False, "transform": None, "notify": None}
    if version >> 4 == 2:
        # An IKEv2-only responder answers an IKEv1 packet with an IKEv2 INVALID_MAJOR_VERSION
        # notify (RFC 7296 section 2.5). That is a definite "IKEv1 not supported".
        while nxt != 0 and off + 4 <= end:
            ptype = nxt
            nxt, _r, plen = struct.unpack_from(">BBH", data, off)
            if plen < 4:
                break
            if ptype == P_NOTIFY and plen >= 8 and off + 8 <= end and struct.unpack_from(">H", data, off + 6)[0] == 5:
                out["notify"] = "INVALID_MAJOR_VERSION"
                return out
            off += plen
        raise ValueError("IKEv2 message that is not INVALID_MAJOR_VERSION")
    if version >> 4 != 1:
        raise ValueError("not IKEv1")
    while nxt != 0 and off + 4 <= end:
        ptype = nxt
        nxt, _r, plen = struct.unpack_from(">BBH", data, off)
        if plen < 4:
            break
        body = data[off + 4: off + plen]
        if ptype == 1 and len(body) >= 16:  # SA: DOI, situation, proposal, one transform
            t_off = 8 + 8 + body[8 + 6]
            attrs: Dict[int, int] = {}
            a = t_off + 8
            t_end = t_off + struct.unpack_from(">H", body, t_off + 2)[0] if t_off + 4 <= len(body) else 0
            while a + 4 <= min(t_end, len(body)):
                at, av = struct.unpack_from(">HH", body, a)
                if at & 0x8000:
                    attrs[at & 0x7FFF] = av
                    a += 4
                else:
                    a += 4 + av
            out["accepted"] = True
            enc = _V1_ENC.get(attrs.get(1, 0), str(attrs.get(1)))
            out["transform"] = {
                "encryption": enc + (f"_{attrs[14]}" if 14 in attrs else ""),
                "hash": _V1_HASH.get(attrs.get(2, 0), str(attrs.get(2))),
                "auth": _V1_AUTH.get(attrs.get(3, 0), str(attrs.get(3))),
                "group": _V1_GROUP.get(attrs.get(4, 0), str(attrs.get(4))),
            }
        elif ptype == 11 and len(body) >= 8:  # Notification
            out["notify"] = struct.unpack_from(">H", body, 6)[0]
        off += plen
    return out


# ── Transport ────────────────────────────────────────────────────────────────

class _Prober:
    """One connected UDP socket to one responder, paced and capped."""

    def __init__(self, ip: str, port: int, family: int, nat_t: bool = False):
        self.ip, self.port = ip, port
        # RFC 3948 section 2.2: IKE on the NAT-T port is prefixed with a 4-byte non-ESP marker.
        self.marker = b"\x00\x00\x00\x00" if nat_t else b""
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.settimeout(_TIMEOUT)
        self.sock.connect((ip, port))  # connected: datagrams from any other source are dropped
        self.local = self.sock.getsockname()
        self.sent = 0
        self.silent = 0
        self._last = 0.0

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass

    def exchange(self, packet: bytes, accept) -> Optional[Any]:
        """Send packet (with retransmission) and return accept(datagram) for the first datagram
        accept() does not reject with ValueError, or None if nothing usable arrived."""
        for _attempt in range(1 + _RETRIES):
            wait = self._last + _PROBE_INTERVAL - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.sock.send(self.marker + packet)
            deadline = time.monotonic() + _TIMEOUT
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                try:
                    data = self.sock.recv(_MAX_RESPONSE + 1)
                except socket.timeout:
                    break
                except ConnectionRefusedError:
                    return None  # ICMP port unreachable: nothing listening
                if len(data) > _MAX_RESPONSE:
                    continue
                if self.marker:
                    if data[:4] != self.marker:
                        continue  # ESP traffic on the NAT-T port, not IKE
                    data = data[4:]
                try:
                    return accept(data)
                except (ValueError, struct.error, IndexError):
                    continue
        return None


def _nat_hash(spi_i: bytes, ip: str, port: int) -> bytes:
    packed = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
    # RFC 7296 section 2.23 fixes NAT_DETECTION hashes as SHA-1; they detect address rewriting
    # and protect nothing.
    return hashlib.sha1(spi_i + b"\x00" * 8 + packed + struct.pack(">H", port), usedforsecurity=False).digest()


class _Session:
    """Probe sequencing for one responder.

    Stateless probing: an enumeration probe's KE payload names a sentinel group that the probe's
    proposals never offer. A responder that finds the proposal acceptable must then answer
    INVALID_KE_PAYLOAD (RFC 7296 section 1.2), which creates no IKE SA on its side. Probes that
    carry a matching KE payload instead leave a half-open SA behind for each accepted proposal; a
    few of those from one address and strongSwan (charon.block_threshold, default 5) starts
    dropping the scanner's packets, which reads as "rejected" and makes the enumeration wrong as
    well as heavier on the target. If a responder answers a sentinel probe with an error notify
    rather than INVALID_KE_PAYLOAD, the session falls back to matching KE payloads.
    """

    def __init__(self, prober: _Prober):
        self.p = prober
        self.aborted = ""
        self.stateless = True

    def _sentinel(self, proposals) -> int:
        offered = {tid for p in proposals for ttype, tid, _k in p if ttype == T_KE}
        return next(g for g in _SENTINEL_GROUPS if g not in offered)

    def probe(self, proposals, ke_group: Optional[int] = None) -> Tuple[str, Dict[str, Any]]:
        sentinel = ke_group is None and self.stateless
        if ke_group is None:
            ke_group = self._sentinel(proposals) if self.stateless else 31
        verdict, detail = self._probe(proposals, ke_group)
        if sentinel and verdict == "error":
            self.stateless = False
            return self._probe(proposals, 31)
        return verdict, detail

    def _probe(self, proposals, ke_group: int) -> Tuple[str, Dict[str, Any]]:
        if self.aborted:
            return "no_response", {}
        if self.p.sent >= _MAX_PROBES:
            self.aborted = f"probe limit ({_MAX_PROBES}) reached"
            return "no_response", {}
        spi_i = os.urandom(8)
        nonce = os.urandom(32)
        try:
            ke_data = _ke_public(ke_group)
        except Exception:
            ke_data = os.urandom(_SENTINEL_KE_BYTES.get(ke_group, 32))
        nat_src = _nat_hash(spi_i, self.p.local[0], self.p.local[1])
        nat_dst = _nat_hash(spi_i, self.p.ip, self.p.port)
        cookie = b""
        for _ in range(2):  # at most one COOKIE round trip
            pkt = build_sa_init(spi_i, proposals, ke_group, ke_data, nonce, cookie=cookie,
                                nat_src=nat_src, nat_dst=nat_dst)
            self.p.sent += 1
            parsed = self.p.exchange(pkt, lambda d: parse_sa_init_response(d, spi_i))
            verdict, detail = classify_response(parsed)
            if verdict == "cookie" and not cookie:
                cookie = detail["cookie"]
                continue
            break
        if verdict == "no_response":
            self.p.silent += 1
            if self.p.silent >= _MAX_SILENT:
                self.aborted = "responder stopped answering"
        else:
            self.p.silent = 0
            detail["parsed"] = parsed
        return verdict, detail


def _full_offer(*, encr=None, prf=None, integ=None, ke=None, addke=None):
    """Proposals offering every candidate except where the caller pins a transform type.

    Returns one AEAD proposal and one non-AEAD proposal (AEAD ciphers carry no integrity
    transform, RFC 5282). addke maps an ADDKE transform type to the list of IDs to offer.
    """
    prfs = prf if prf is not None else _PRF_CANDIDATES
    kes = ke if ke is not None else _BASE_KE
    integs = integ if integ is not None else _INTEG_CANDIDATES
    extra: List[Tuple[int, int, Optional[int]]] = []
    for ttype, ids in sorted((addke or {}).items()):
        extra += [(ttype, i, None) for i in ids]
    proposals = []
    for aead in (True, False):
        encrs = [c for c in (encr if encr is not None else _ENCR_CANDIDATES)
                 if (c[0] in _AEAD_ENCR) == aead]
        if not encrs:
            continue
        if not aead and integ is not None and not integs:
            continue
        if aead and integ is not None and encr is None:
            continue  # an integrity probe must not be answered by an AEAD proposal
        t: List[Tuple[int, int, Optional[int]]] = [(T_ENCR, i, k) for i, k in encrs]
        t += [(T_PRF, i, None) for i in prfs]
        if not aead:
            t += [(T_INTEG, i, None) for i in integs]
        t += [(T_KE, i, None) for i in kes]
        t += extra
        proposals.append(t)
    return proposals


# ── Scan ─────────────────────────────────────────────────────────────────────

def _resolve(host: str, port: int) -> Tuple[str, int]:
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
    for fam in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == fam:
                return info[4][0], fam
    raise OSError(f"could not resolve {host}")


def scan_ike(host: str, port: int = 500, *, probe_ikev1: bool = True,
             nat_t: Optional[bool] = None) -> Dict[str, Any]:
    """Scan an IKEv2 responder. Returns the Morrow result format with a findings list.

    nat_t selects the RFC 3948 non-ESP marker; by default it is used on port 4500 only.
    """
    if nat_t is None:
        nat_t = port == 4500
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "scan_type": "ike",
        "ike_version": 2,
        "nat_t": bool(nat_t),
        "responded": False,
        "selected_proposal": {},
        "accepted_encryption": [],
        "accepted_prf": [],
        "accepted_integrity": [],
        "accepted_key_exchange": [],
        "accepted_additional_key_exchange": {},
        "pq_key_exchange": [],
        "pq_required": None,
        "classical_only_accepted": None,
        "responder_notifies": [],
        "vendor_ids": [],
        "ikev1": {"probed": False, "enabled": None, "transform": None},
        "probes_sent": 0,
        "findings": [],
        "quantum_risk_score": 0,
        "quantum_risk_level": "unknown",
        "pq_ready": False,
        "error": None,
    }

    # On a hosted deployment an organization scans only its verified domains
    # (services/domain_verification). Refused before any packet is sent.
    from scanner import _scope_refusal

    refusal = _scope_refusal(host)
    if refusal:
        result["error"] = refusal
        result["error_code"] = "NOT_PERMITTED"
        return result

    try:
        ip, family = _resolve(host, port)
        prober = _Prober(ip, port, family, nat_t=bool(nat_t))
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
        result["error_code"] = "DNS_ERROR" if isinstance(exc, socket.gaierror) else "CONNECTION_ERROR"
        _finish(result)
        return result

    try:
        _enumerate(_Session(prober), result)
        if probe_ikev1 and result["responded"]:
            _probe_ikev1(prober, result)
    except OSError as exc:
        result["error"] = str(exc)
        result["error_code"] = "CONNECTION_ERROR"
    finally:
        result["probes_sent"] = prober.sent
        prober.close()

    _finish(result)
    return result


def _enumerate(s: _Session, result: Dict[str, Any]) -> None:
    pq_offer = {6: [0] + sorted(PQ_KE)}  # ADDKE1: NONE or any ML-KEM
    # 1. Preference probe: everything on offer. Answers whether anything listens.
    # This one carries a real X25519 public value, so an accepting responder returns its full
    # selected proposal (and keeps one half-open SA until it times out).
    verdict, detail = s.probe(_full_offer(addke=pq_offer), ke_group=31)
    if verdict == "no_response":
        result["error"] = "no IKEv2 response (nothing listening, filtered, or not IKEv2)"
        result["error_code"] = "TIMEOUT"
        return
    result["responded"] = True
    if verdict == "accepted" and detail.get("preferred_ke") is not None and "transforms" not in detail:
        group = detail["preferred_ke"]
        try:
            v2, d2 = s.probe(_full_offer(addke=pq_offer), ke_group=group)
            if v2 == "accepted" and "transforms" in d2:
                verdict, detail = v2, d2
        except Exception:
            pass  # no public value for that group (e.g. ML-KEM as the primary exchange)
    _record_responder(result, detail.get("parsed"))
    if "transforms" in detail:
        result["selected_proposal"] = _selected(detail["transforms"])
    elif detail.get("preferred_ke") is not None:
        result["selected_proposal"] = {"key_exchange": _describe(T_KE, detail["preferred_ke"])}
    if verdict == "rejected":
        result["error"] = "responder rejected every offered proposal (NO_PROPOSAL_CHOSEN)"

    # 2. Classical-only offer: does the responder accept an SA with no additional key exchange?
    v, _ = s.probe(_full_offer(ke=[k for k in _BASE_KE if k not in PQ_KE]))
    result["classical_only_accepted"] = None if v == "no_response" else v == "accepted"

    # 3. One transform type at a time.
    for tid, klen in _ENCR_CANDIDATES:
        if _ok(s.probe(_full_offer(encr=[(tid, klen)], addke=pq_offer))):
            result["accepted_encryption"].append(_describe(T_ENCR, tid, klen))
    for tid in _PRF_CANDIDATES:
        if _ok(s.probe(_full_offer(prf=[tid], addke=pq_offer))):
            result["accepted_prf"].append(_describe(T_PRF, tid))
    for tid in _INTEG_CANDIDATES:
        if _ok(s.probe(_full_offer(integ=[tid], addke=pq_offer))):
            result["accepted_integrity"].append(_describe(T_INTEG, tid))
    for tid in _KE_CANDIDATES:
        if _ok(s.probe(_full_offer(ke=[tid], addke=pq_offer))):
            result["accepted_key_exchange"].append(_describe(T_KE, tid))

    # 4. RFC 9370 additional key exchanges, slot by slot. A later slot is probed only once an
    #    earlier one has produced a match, with the earlier slots held open (NONE or a match).
    held: Dict[int, List[int]] = {}
    for slot, ttype in enumerate(T_ADDKE, start=1):
        found = []
        for tid in _ADDKE_CANDIDATES:
            if _ok(s.probe(_full_offer(addke={**held, ttype: [tid]}))):
                found.append(_describe(ttype, tid))
        if not found:
            break
        result["accepted_additional_key_exchange"][f"ADDKE{slot}"] = found
        held[ttype] = [0] + [f["id"] for f in found]
    if s.aborted:
        result["error"] = f"scan incomplete: {s.aborted}"


def _ok(outcome: Tuple[str, Dict[str, Any]]) -> bool:
    return outcome[0] == "accepted"


def _selected(transforms: List[Tuple[int, int, Optional[int]]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    labels = {T_ENCR: "encryption", T_PRF: "prf", T_INTEG: "integrity", T_KE: "key_exchange"}
    for ttype, tid, klen in transforms:
        if ttype in labels:
            out[labels[ttype]] = _describe(ttype, tid, klen)
        elif ttype in T_ADDKE and tid != 0:
            out[f"additional_key_exchange_{ttype - 5}"] = _describe(ttype, tid)
    return out


def _record_responder(result: Dict[str, Any], parsed: Optional[Dict[str, Any]]) -> None:
    if not parsed:
        return
    names = []
    for n in parsed["notifies"]:
        entry: Dict[str, Any] = {"type": n["type"], "name": n["name"]}
        if n["type"] == N_SIGNATURE_HASH_ALGORITHMS and len(n["data"]) % 2 == 0:
            entry["hash_algorithms"] = [struct.unpack_from(">H", n["data"], i)[0]
                                        for i in range(0, len(n["data"]), 2)]
        names.append(entry)
    result["responder_notifies"] = names
    result["vendor_ids"] = parsed["vendor_ids"][:10]


def _probe_ikev1(prober: _Prober, result: Dict[str, Any]) -> None:
    icookie = os.urandom(8)
    prober.sent += 1
    reply = prober.exchange(build_ikev1_main_mode(icookie), lambda d: parse_ikev1_response(d, icookie))
    # enabled is True only when the responder chose a transform. An unanswered probe is reported
    # as False with answered False: most IKEv2-only responders drop IKEv1 silently.
    result["ikev1"] = {
        "probed": True,
        "enabled": bool(reply and reply["accepted"]),
        "transform": (reply or {}).get("transform"),
        "answered": reply is not None,
        "response": (reply or {}).get("notify"),
    }


# ── Findings ─────────────────────────────────────────────────────────────────

_WEAK_GROUPS = {1: "critical", 2: "critical", 22: "critical", 5: "high", 25: "high", 26: "medium",
                27: "medium", 23: "medium", 24: "medium"}
_BROKEN_ENCR = frozenset({1, 2, 4, 5, 6, 7, 8, 9, 11})


def _finish(result: Dict[str, Any]) -> None:
    from policy import derive_risk_and_score

    findings: List[Dict[str, Any]] = []

    if not result["responded"]:
        if result.get("error_code") == "NOT_PERMITTED":
            return
        findings.append({
            "rule_id": "SCAN_FAILED",
            "severity": "info",
            "title": "IKE responder could not be scanned",
            "fix": "Confirm host, UDP port (500, or 4500 for NAT-T) and that the network path allows IKE.",
            "confidence": "high",
            "evidence": {"error": result.get("error")},
            "pq_note": "No IKE response, so this endpoint's quantum exposure is unknown.",
        })
        result["findings"] = findings
        scoring = derive_risk_and_score(findings)
        result["quantum_risk_score"] = scoring["quantum_risk_score"]
        result["quantum_risk_level"] = "unknown"
        return

    kes = result["accepted_key_exchange"]
    addke = [a for slot in result["accepted_additional_key_exchange"].values() for a in slot]
    pq = sorted({k["name"] for k in kes + addke if k.get("post_quantum")})
    result["pq_key_exchange"] = pq
    result["pq_ready"] = bool(pq)
    classical_ok = result["classical_only_accepted"]
    classical_kes = [k for k in kes if not k.get("post_quantum")]
    # Required means an offer with no additional key exchange was refused. If ML-KEM is also
    # accepted as the primary exchange, classical groups are still accepted alongside it, so this
    # only claims what the classical-only probe showed.
    result["pq_required"] = bool(pq) and classical_ok is False

    if not pq:
        findings.append({
            "rule_id": "IKE_NO_PQ_KEY_EXCHANGE",
            "severity": "high",
            "title": "No post-quantum key exchange accepted for IKEv2",
            "fix": ("Add an RFC 9370 additional key exchange with ML-KEM, e.g. strongSwan 6 "
                    "proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768, or libreswan/vendor equivalent."),
            "confidence": "high",
            "evidence": {"accepted_key_exchange": [k["name"] for k in kes]},
            "pq_note": ("Every accepted key exchange is broken by Shor's algorithm; recorded VPN traffic "
                        "is exposed to harvest-now-decrypt-later."),
        })
    elif classical_ok:
        findings.append({
            "rule_id": "IKE_PQ_OPTIONAL",
            "severity": "medium",
            "title": "Post-quantum key exchange is offered but not required",
            "fix": "Remove proposals without ke1_mlkem* once every peer supports RFC 9370, so a peer cannot negotiate classical-only.",
            "confidence": "high",
            "evidence": {"pq_key_exchange": pq, "classical_only_accepted": True},
            "pq_note": "A peer (or an attacker able to strip proposals before authentication) can still get a classical-only IKE SA.",
        })
    if pq:
        findings.append({
            "rule_id": "IKE_PQ_HYBRID_AVAILABLE",
            "severity": "info",
            "title": "Post-quantum key exchange is accepted",
            "fix": "No action required. Keep initiators configured to propose the ML-KEM additional key exchange first.",
            "confidence": "high",
            "evidence": {"pq_key_exchange": pq,
                         "additional_key_exchange": result["accepted_additional_key_exchange"]},
            "pq_note": "ML-KEM (FIPS 203) key exchange; IANA IKEv2 Transform Type 4 IDs 35-37.",
        })

    weak = [(k["name"], _WEAK_GROUPS[k["id"]]) for k in classical_kes if k["id"] in _WEAK_GROUPS]
    if weak:
        worst = "critical" if any(s == "critical" for _, s in weak) else (
            "high" if any(s == "high" for _, s in weak) else "medium")
        findings.append({
            "rule_id": "IKE_WEAK_DH_GROUP",
            "severity": worst,
            "title": "Weak Diffie-Hellman groups accepted",
            "fix": f"Remove {', '.join(n for n, _ in weak)} from the IKE proposals.",
            "confidence": "high",
            "evidence": {"groups": [n for n, _ in weak]},
            "pq_note": "These groups are weak against classical attackers already.",
        })

    broken = [e["name"] for e in result["accepted_encryption"] if e["id"] in _BROKEN_ENCR or e["id"] == 3]
    if broken:
        findings.append({
            "rule_id": "IKE_WEAK_ENCRYPTION",
            "severity": "high",
            "title": "Weak IKE encryption algorithms accepted",
            "fix": f"Remove {', '.join(broken)}; use AES-256-GCM (ENCR_AES_GCM_16, 256-bit key).",
            "confidence": "high",
            "evidence": {"algorithms": broken},
            "pq_note": "64-bit block ciphers and DES-family algorithms are broken or deprecated (RFC 8247).",
        })

    weak_mac = [p["name"] for p in result["accepted_prf"] + result["accepted_integrity"]
                if p.get("algorithm") in ("MD5", "SHA-1")]
    if weak_mac:
        findings.append({
            "rule_id": "IKE_WEAK_INTEGRITY",
            "severity": "medium",
            "title": "MD5 or SHA-1 based PRF/integrity accepted",
            "fix": f"Remove {', '.join(weak_mac)}; use PRF_HMAC_SHA2_384 / AUTH_HMAC_SHA2_384_192 or AEAD.",
            "confidence": "high",
            "evidence": {"algorithms": weak_mac},
            "pq_note": "RFC 8247 deprecates MD5 and recommends against SHA-1 for new IKEv2 deployments.",
        })

    small_sym = [e["name"] for e in result["accepted_encryption"]
                 if e.get("nist_pq_category") == 1 and e.get("key_length") in (128,)]
    if small_sym:
        findings.append({
            "rule_id": "IKE_128_BIT_SYMMETRIC",
            "severity": "low",
            "title": "128-bit symmetric encryption accepted",
            "fix": "Prefer 256-bit keys; CNSA 2.0 requires AES-256.",
            "confidence": "high",
            "evidence": {"algorithms": small_sym},
            "pq_note": "AES-128 is NIST post-quantum category 1; AES-256 (category 5) is the conservative choice.",
        })

    v1 = result["ikev1"]
    if v1.get("enabled"):
        findings.append({
            "rule_id": "IKEV1_ENABLED",
            "severity": "medium",
            "title": "IKEv1 is still accepted",
            "fix": "Disable IKEv1; it has no post-quantum key exchange and RFC 9395 deprecates it.",
            "confidence": "high",
            "evidence": {"transform": v1.get("transform")},
            "pq_note": "IKEv1 has no standard post-quantum or hybrid key exchange.",
        })

    result["findings"] = findings
    scoring = derive_risk_and_score(findings)
    result["quantum_risk_score"] = scoring["quantum_risk_score"]
    result["risk_level"] = scoring["risk_level"]
    if not kes and not addke:
        result["quantum_risk_level"] = "unknown"
    elif not pq:
        result["quantum_risk_level"] = "high"
    elif classical_ok:
        result["quantum_risk_level"] = "medium"
    else:
        result["quantum_risk_level"] = "low"


def parse_target(target: str, default_port: int = 500) -> Tuple[str, int]:
    t = str(target or "").strip()
    if t.startswith("[") and "]" in t:
        host, _, rest = t[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else default_port
    if t.count(":") == 1:
        host, port = t.rsplit(":", 1)
        return host, int(port) if port.isdigit() else default_port
    return t, default_port
