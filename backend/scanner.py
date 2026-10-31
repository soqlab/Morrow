# backend/scanner.py
from __future__ import annotations

import socket
import ssl
import hashlib
import logging
import time
import urllib.parse
import urllib.request
import urllib.error
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509 import ocsp as x509_ocsp

from policy import evaluate_tls_findings, derive_risk_and_score, derive_pq_relevance, derive_quantum_readiness

DEFAULT_TIMEOUT = 6

logger = logging.getLogger(__name__)

ERR_TLS_VERSION_TOO_LOW = "TLS_VERSION_TOO_LOW"
ERR_CERT_EXPIRED = "CERT_EXPIRED"
ERR_HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"
ERR_SELF_SIGNED = "SELF_SIGNED"
ERR_DNS = "DNS_ERROR"
ERR_TIMEOUT = "TIMEOUT"
ERR_CONNECTION_ERROR = "CONNECTION_ERROR"
ERR_TLS_VERIFY_FAILED = "TLS_VERIFY_FAILED"
ERR_TLS_ERROR = "TLS_ERROR"
ERR_NOT_PERMITTED = "NOT_PERMITTED"


def _error_code_from_verify_reason(reason: str, message: str = "") -> str:
    text = f"{reason or ''} {message or ''}".lower()
    if "expired" in text:
        return ERR_CERT_EXPIRED
    if "hostname" in text or "doesn't match" in text or "does not match" in text:
        return ERR_HOSTNAME_MISMATCH
    # OpenSSL 3.0 renamed this message from "self signed certificate" to "self-signed
    # certificate"; matching only the old spelling silently downgraded every self-signed endpoint
    # to a generic verification failure.
    if "self signed" in text or "self-signed" in text:
        return ERR_SELF_SIGNED
    return ERR_TLS_VERIFY_FAILED


def _error_code_from_exception(exc: Exception) -> str:
    text = str(exc or "").lower()
    if isinstance(exc, socket.gaierror):
        return ERR_DNS
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(exc, ConnectionRefusedError):
        return ERR_CONNECTION_ERROR
    if "protocol version" in text or "tlsv1 alert" in text:
        return ERR_TLS_VERSION_TOO_LOW
    if isinstance(exc, _SSLCertVerificationError):
        return _error_code_from_verify_reason(getattr(exc, "verify_reason", ""), text)
    if isinstance(exc, ssl.SSLError):
        return ERR_TLS_ERROR
    return ERR_CONNECTION_ERROR

# A small probe set: fast + useful signal
TLS12_CIPHER_PROBES = [
    # Modern-ish
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    # Weak (we want to detect acceptance)
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "AES128-SHA",
    "AES256-SHA",
]

_SSLCertVerificationError = getattr(ssl, "SSLCertVerificationError", ssl.SSLError)

def _classify_verify_error(err: Exception) -> Dict[str, Any]:
    # Best-effort classification of TLS certificate verification failures.
    # SSLCertVerificationError often exposes verify_code/verify_message.
    code = getattr(err, "verify_code", None)
    msg = getattr(err, "verify_message", None) or str(err)
    msg_l = (msg or "").lower()

    reason = "other"
    if "hostname" in msg_l or "does not match" in msg_l or "wrong host" in msg_l:
        reason = "hostname_mismatch"
    elif "certificate has expired" in msg_l or "expired" in msg_l:
        reason = "expired"
    elif "revoked" in msg_l:
        reason = "revoked"
    elif "unable to get local issuer" in msg_l or "unknown ca" in msg_l:
        reason = "untrusted_root"
    elif "self signed" in msg_l or "self-signed" in msg_l:
        reason = "untrusted_issuer"
    elif "unable to get issuer certificate" in msg_l or "unable to verify the first certificate" in msg_l:
        reason = "missing_intermediate"
    elif "certificate chain too long" in msg_l:
        reason = "chain_too_long"

    return {"verify_code": code, "verify_message": msg, "verify_reason": reason}


def _refine_verify_reason(facts: Dict[str, Any]) -> None:
    if str(facts.get("verify_reason") or "") != "untrusted_root":
        return
    try:
        chain_length = int(facts.get("chain_length") or 0)
    except Exception:
        chain_length = 0
    if chain_length <= 1 and facts.get("ca_issuers_urls"):
        facts["verify_reason"] = "missing_intermediate"


def _parse_openssl_ocsp_output(text: str) -> Dict[str, Any]:
    raw = str(text or "")
    low = raw.lower()
    out: Dict[str, Any] = {
        "ocsp_stapling_supported": "ocsp response" in low or "ocsp response status" in low or "cert status" in low,
        "ocsp_stapled": False,
        "ocsp_stapled_status": "",
    }
    if "no response sent" in low:
        out["ocsp_stapling_supported"] = True
        out["ocsp_stapled"] = False
        return out
    if "cert status:" in low:
        out["ocsp_stapled"] = True
        if "cert status: good" in low:
            out["ocsp_stapled_status"] = "good"
        elif "cert status: revoked" in low:
            out["ocsp_stapled_status"] = "revoked"
        elif "cert status: unknown" in low:
            out["ocsp_stapled_status"] = "unknown"
    return out


def parse_target(target: str) -> Tuple[str, int]:
    """
    Public helper (some app.py versions import it).
    Accepts:
      - example.com
      - example.com:443
      - https://example.com
      - https://example.com:8443/path
    Returns (host, port).
    """
    return _parse_target(target)


def _parse_target(target: str) -> Tuple[str, int]:
    t = (target or "").strip()
    if not t:
        return ("", 0)

    # strip scheme
    if "://" in t:
        t = t.split("://", 1)[1]

    # strip path
    if "/" in t:
        t = t.split("/", 1)[0]

    # host:port
    if ":" in t:
        host, port_s = t.rsplit(":", 1)
        host = host.strip()
        try:
            port = int(port_s.strip())
        except Exception:
            port = 443
        return (host, port)

    return (t, 443)


def _utc_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _cert_not_before(cert: x509.Certificate) -> Optional[datetime]:
    return getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)


def _cert_not_after(cert: x509.Certificate) -> Optional[datetime]:
    return getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (dt - now).days


def _new_ssl_context(protocol_const: int) -> ssl.SSLContext:
    # Legacy protocol probes intentionally exercise deprecated TLS versions.
    # Keep the signal without leaking noisy deprecation warnings into test/runtime logs.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return ssl.SSLContext(protocol_const)


def _make_context_for_protocol(protocol_const: int, verify: bool, alpn: Optional[List[str]] = None) -> ssl.SSLContext:
    ctx = _new_ssl_context(protocol_const)

    # reasonable defaults
    ctx.check_hostname = bool(verify)
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE

    if verify:
        ctx.load_default_certs()

    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass

    # Do not force min/max here; let protocol_const drive it.
    return ctx


def _connect_handshake(
    host: str,
    port: int,
    protocol_const: int,
    verify: bool = False,
    cipher: Optional[str] = None,
    alpn: Optional[List[str]] = None,
    sni: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "success": False,
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "verify_error": "",
        "verify_code": None,
        "verify_message": "",
        "verify_reason": "",
        "unverified_fallback": False,
    }

    ctx = _make_context_for_protocol(protocol_const, verify=verify, alpn=alpn)

    if cipher:
        try:
            ctx.set_ciphers(cipher)
        except Exception as e:
            out["verify_error"] = f"set_ciphers failed: {e}"
            return out

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if sni else None) as ssock:
                out["success"] = True
                out["tls_version"] = ssock.version() or ""
                c = ssock.cipher()
                if c:
                    out["cipher_name"] = c[0] or ""
                    out["cipher_bits"] = c[2] if len(c) > 2 else None
                try:
                    out["alpn"] = ssock.selected_alpn_protocol() or ""
                except Exception:
                    out["alpn"] = ""
    except _SSLCertVerificationError as e:
        out["verify_error"] = str(e)
    except ssl.SSLError as e:
        out["verify_error"] = str(e)
    except Exception as e:
        out["verify_error"] = str(e)

    return out


def _probe_tls_versions(host: str, port: int) -> Dict[str, Any]:
    supported: Dict[str, bool] = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}
    errors: Dict[str, str] = {}

    for label, proto in [
        ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
    ]:
        if proto is None:
            continue
        r = _connect_handshake(host, port, protocol_const=proto, verify=False, alpn=["h2", "http/1.1"])
        if r["success"]:
            supported[label] = True
        else:
            errors[label] = r.get("verify_error", "") or ""

    # TLS 1.3 best-effort
    r = _connect_handshake(host, port, protocol_const=ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
    if r["success"] and (r.get("tls_version") == "TLSv1.3"):
        supported["TLSv1.3"] = True
    elif not r["success"]:
        errors["TLSv1.3"] = r.get("verify_error", "") or ""

    return {
        "tls_supported_versions": [k for k, v in supported.items() if v],
        "tls_support_map": supported,
        "tls_probe_errors": errors,
    }


def _is_weak_cipher(name: str) -> bool:
    n = (name or "").upper()
    # This is intentionally conservative for "baseline hardening"
    if "NULL" in n or "EXPORT" in n or "RC4" in n or "3DES" in n or "MD5" in n:
        return True
    if n.endswith("-SHA") and ("GCM" not in n) and ("CHACHA20" not in n):
        return True
    return False


def _probe_tls12_accepted_ciphers(host: str, port: int) -> Dict[str, Any]:
    accepted: List[str] = []
    weak_accepted: List[str] = []
    any_fs = False

    proto = getattr(ssl, "PROTOCOL_TLSv1_2", None)
    if proto is None:
        return {"tls12_accepted_ciphers": [], "tls12_weak_accepted_ciphers": [], "forward_secrecy_possible": False}

    for c in TLS12_CIPHER_PROBES:
        r = _connect_handshake(host, port, protocol_const=proto, verify=False, cipher=c, alpn=["h2", "http/1.1"])
        if r["success"]:
            negotiated = r.get("cipher_name") or c
            accepted.append(negotiated)
            if _is_weak_cipher(negotiated):
                weak_accepted.append(negotiated)
            if "ECDHE" in (negotiated or "").upper() or "DHE" in (negotiated or "").upper():
                any_fs = True

    def dedupe(xs: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "tls12_accepted_ciphers": dedupe(accepted),
        "tls12_weak_accepted_ciphers": dedupe(weak_accepted),
        "forward_secrecy_possible": any_fs,
    }


# ── Negotiated key-exchange group ─────────────────────────────────────────────
#
# For a post-quantum product this is the field that matters most: whether an endpoint has already
# enabled hybrid key exchange (X25519MLKEM768) is the whole question. Python's `ssl` module cannot
# answer it here for two independent reasons:
#
#   1. `ssl.SSLSocket.group()` needs OpenSSL 3.2+. CPython in this deployment links OpenSSL 3.0.18,
#      where the attribute does not exist at all (verified: `hasattr(ssl.SSLSocket, "group")` is
#      False).
#   2. Even on 3.2 it would not help, because the group has to be *offered* to be negotiated, and
#      X25519MLKEM768 only exists in OpenSSL 3.5+. A scan run through `ssl` physically cannot
#      propose hybrid key exchange, so it could never observe a server accepting it.
#
# So the ClientHello is built by hand and only the ServerHello is parsed. That needs no TLS
# library, no new dependency and no completed handshake: the server's answer to "here are the
# groups I support, which do you choose?" is in the clear, in the first flight. A server that
# prefers a group we did not send a key share for replies with a HelloRetryRequest that names it,
# which is exactly the case a post-quantum-enabled server hits, so both branches are covered.
#
# Everything here is advisory. Any failure leaves the field unobserved rather than guessed, and the
# probe never blocks the certificate scan.
#
# Provenance: the record and extension construction below was written from RFC 8446 (TLS 1.3) and
# the IANA Supported Groups registry for this project. It is not derived from, and shares no code
# with, sslyze, testssl.sh, nmap's ssl-enum-ciphers, or any other scanner. "Needs no TLS library"
# means no TLS stack parses or drives the handshake -- `cryptography` is still used to generate the
# X25519 key share, and `secrets` for the client random. Group code points and the fixed
# HelloRetryRequest random (RFC 8446 section 4.1.3) are registry and specification constants, so
# identical values in other tools are required by the standard, not copied. AGPL-3.0, like the rest of this
# repository.

#: IANA TLS Supported Groups, plus the hybrid code points in deployment today.
TLS_NAMED_GROUPS: Dict[int, str] = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
    # Hybrid post-quantum key exchange (RFC 9794 naming; 0x11EB-0x11ED are the standardised ML-KEM hybrids).
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    # Pre-standard drafts still widely deployed.
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0x4588: "X25519MLKEM768Draft",
    # Pure ML-KEM (no classical component).
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}

#: Names that identify a group as post-quantum, and as hybrid rather than pure.
_MORROW_GROUP_TOKENS = ("mlkem", "ml-kem", "kyber", "ntru", "bike", "hqc", "frodo")
_CLASSICAL_GROUP_TOKENS = ("x25519", "x448", "secp", "p256", "p384", "p521", "ffdhe")

#: Offered in preference order, post-quantum first, so a server that supports hybrid selects it.
_OFFERED_GROUPS = (0x11EC, 0x11EB, 0x11ED, 0x6399, 0x639A, 0x4588,
                   0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101)
#: TLS 1.3 suites first, then the common TLS 1.2 ECDHE suites so a 1.2-only server still answers.
_OFFERED_SUITES = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030,
                   0xCCA8, 0xCCA9, 0x009C, 0x009D, 0x002F, 0x0035)
#: SHA-256("HelloRetryRequest"), the fixed ServerHello.random that marks an HRR (RFC 8446 §4.1.3).
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


def classify_key_exchange_group(group_name: str) -> str:
    """"pq_hybrid", "pq_pure", "classical", or "" when nothing was observed."""
    g = str(group_name or "").lower().replace("-", "").replace("_", "")
    if not g:
        return ""
    if any(tok.replace("-", "") in g for tok in _MORROW_GROUP_TOKENS):
        return "pq_hybrid" if any(t in g for t in _CLASSICAL_GROUP_TOKENS) else "pq_pure"
    return "classical"


def _u16(value: int) -> bytes:
    return int(value).to_bytes(2, "big")


def _tls_extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def _build_client_hello(host: str) -> bytes:
    """A TLS 1.3 ClientHello offering every hybrid group we know about."""
    import secrets as _secrets

    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519

    share = _x25519.X25519PrivateKey.generate().public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw
    )

    exts = b""
    is_ip = True
    try:
        socket.inet_aton(host)
    except OSError:
        is_ip = False
    if host and not is_ip:
        try:
            name = host.encode("idna")
        except Exception:
            name = host.encode("ascii", "ignore")
        if name:
            exts += _tls_extension(0x0000, _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name)
    exts += _tls_extension(0x000B, b"\x01\x00")                       # ec_point_formats
    groups = b"".join(_u16(g) for g in _OFFERED_GROUPS)
    exts += _tls_extension(0x000A, _u16(len(groups)) + groups)        # supported_groups
    sig_algs = b"".join(_u16(x) for x in (
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
        0x0401, 0x0501, 0x0601, 0x0201,
    ))
    exts += _tls_extension(0x000D, _u16(len(sig_algs)) + sig_algs)    # signature_algorithms
    exts += _tls_extension(0x002B, b"\x04" + _u16(0x0304) + _u16(0x0303))  # supported_versions
    key_share = _u16(0x001D) + _u16(len(share)) + share
    exts += _tls_extension(0x0033, _u16(len(key_share)) + key_share)  # key_share
    exts += _tls_extension(0x0016, b"")                               # encrypt_then_mac
    exts += _tls_extension(0x0017, b"")                               # extended_master_secret

    body = (
        _u16(0x0303)
        + _secrets.token_bytes(32)
        + b"\x20" + _secrets.token_bytes(32)                          # legacy_session_id (compat)
        + _u16(2 * len(_OFFERED_SUITES)) + b"".join(_u16(c) for c in _OFFERED_SUITES)
        + b"\x01\x00"                                                 # compression: null
        + _u16(len(exts)) + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


def _recv_at_least(sock: socket.socket, want: int, buf: bytearray) -> bool:
    while len(buf) < want:
        chunk = sock.recv(16384)
        if not chunk:
            return False
        buf += chunk
    return True


def _probe_key_exchange_group(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                              address: str = "") -> Dict[str, Any]:
    """Observe the key-exchange group the server selects, by reading its ServerHello.

    Returns ``key_exchange_observed`` False with a reason whenever the group could not be read, so
    a consumer can say "not observed" instead of "no hybrid key exchange found" -- the two are very
    different statements and only one of them is supported by evidence.

    ``address`` pins the connection to an address the caller already resolved and vetted, while the
    SNI and the ClientHello still name ``host``. The public checker (services/public_check.py)
    needs this: it resolves the target, refuses every non-public answer, and must then connect to
    the address it checked rather than re-resolving, or DNS rebinding could point the second
    lookup inward. Default "" keeps the internal scanner's behaviour unchanged.
    """
    out: Dict[str, Any] = {
        "key_exchange": "",
        "key_exchange_group_id": None,
        "key_exchange_family": "",
        "key_exchange_observed": False,
        "key_exchange_observation_method": "tls_client_hello_probe",
        "key_exchange_unobservable_reason": "",
        "key_exchange_hello_retry": False,
    }
    try:
        hello = _build_client_hello(host)
    except Exception as exc:
        out["key_exchange_unobservable_reason"] = f"could not build ClientHello: {exc}"
        return out

    try:
        with socket.create_connection((address or host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(hello)
            buf = bytearray()
            handshake = bytearray()
            for _ in range(8):
                if not _recv_at_least(sock, 5, buf):
                    break
                rec_type = buf[0]
                rec_len = int.from_bytes(bytes(buf[3:5]), "big")
                if not _recv_at_least(sock, 5 + rec_len, buf):
                    break
                payload = bytes(buf[5:5 + rec_len])
                del buf[:5 + rec_len]
                if rec_type == 0x15:                                  # alert
                    out["key_exchange_unobservable_reason"] = (
                        "server rejected the probe ClientHello "
                        f"(TLS alert {payload.hex() or 'unknown'})"
                    )
                    return out
                if rec_type != 0x16:
                    continue
                handshake += payload
                if len(handshake) >= 4:
                    msg_len = int.from_bytes(bytes(handshake[1:4]), "big")
                    if len(handshake) >= 4 + msg_len:
                        break

            if len(handshake) < 4 or handshake[0] != 0x02:
                out["key_exchange_unobservable_reason"] = "no ServerHello in the first flight"
                return out
            msg_len = int.from_bytes(bytes(handshake[1:4]), "big")
            body = bytes(handshake[4:4 + msg_len])
            rest = bytes(handshake[4 + msg_len:])

            pos = 2                                                   # legacy_version
            out["key_exchange_hello_retry"] = body[pos:pos + 32] == _HRR_RANDOM
            pos += 32
            pos += 1 + body[pos]                                      # legacy_session_id_echo
            pos += 3                                                  # cipher_suite + compression
            ext_total = int.from_bytes(body[pos:pos + 2], "big")
            pos += 2
            ext_end = pos + ext_total
            group_id: Optional[int] = None
            while pos + 4 <= ext_end:
                ext_type = int.from_bytes(body[pos:pos + 2], "big")
                ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
                ext_body = body[pos + 4:pos + 4 + ext_len]
                pos += 4 + ext_len
                # key_share: {group} in a HelloRetryRequest, {group, key_exchange} in a ServerHello.
                if ext_type == 0x0033 and len(ext_body) >= 2:
                    group_id = int.from_bytes(ext_body[:2], "big")

            if group_id is None:
                group_id = _tls12_server_key_exchange_group(sock, buf, rest)

            if group_id is None:
                out["key_exchange_unobservable_reason"] = (
                    "the server named no key-exchange group (static RSA key exchange, or a "
                    "TLS version that does not carry one)"
                )
                return out

            name = TLS_NAMED_GROUPS.get(group_id, f"unknown-group-0x{group_id:04x}")
            out["key_exchange"] = name
            out["key_exchange_group_id"] = group_id
            out["key_exchange_family"] = classify_key_exchange_group(name)
            out["key_exchange_observed"] = True
            return out
    except socket.timeout:
        out["key_exchange_unobservable_reason"] = "timed out before the ServerHello arrived"
    except OSError as exc:
        out["key_exchange_unobservable_reason"] = f"connection failed: {exc}"
    except Exception as exc:                                          # never fail the whole scan
        out["key_exchange_unobservable_reason"] = f"{type(exc).__name__}: {exc}"
    return out


def _tls12_server_key_exchange_group(sock: socket.socket, buf: bytearray, rest: bytes) -> Optional[int]:
    """The named curve from a TLS 1.2 ServerKeyExchange, which arrives in the same flight."""
    pending = bytearray(rest)
    for _ in range(12):
        while len(pending) >= 4:
            msg_len = int.from_bytes(bytes(pending[1:4]), "big")
            if len(pending) < 4 + msg_len:
                break
            if pending[0] == 12 and msg_len >= 4 and pending[4] == 0x03:   # named_curve
                return int.from_bytes(bytes(pending[5:7]), "big")
            del pending[:4 + msg_len]
        try:
            if not _recv_at_least(sock, 5, buf):
                return None
            rec_len = int.from_bytes(bytes(buf[3:5]), "big")
            if not _recv_at_least(sock, 5 + rec_len, buf):
                return None
            if buf[0] == 0x16:
                pending += bytes(buf[5:5 + rec_len])
            del buf[:5 + rec_len]
        except OSError:
            return None
    return None


# Public-key algorithms the scanner can name, and the bit strength to report when the key object
# does not carry one. Ed25519/Ed448/X25519/X448 are fixed-size by definition.
_FIXED_KEY_BITS = {"ED25519": 256, "X25519": 256, "ED448": 448, "X448": 448}


def _pk_details(cert: x509.Certificate) -> Dict[str, Any]:
    """Name the certificate's public key algorithm, its size in bits, and its curve.

    The fall-through used to return ``pk.__class__.__name__`` -- so an Ed25519 certificate was
    reported with key_type "Ed25519PublicKey", which matches no algorithm table in the product.
    Every consumer therefore classified it "unknown", and "unknown" reads downstream as *not*
    quantum-vulnerable: the endpoint scored crypto_agility 90, harvest-now-decrypt-later "unknown",
    pq_relevance LOW. EdDSA over Curve25519 is broken by Shor exactly like ECDSA, so that was the
    most dangerous answer the scanner could give. Named algorithms now come back named.

    key_bits is reported as an integer because everything downstream (HNDL Q-Day buckets, the CBOM
    algorithm resolver, blast radius) reads ``key_bits``; the old key_detail string held the size
    for RSA and a curve name for EC, and nothing read it.
    """
    pk = cert.public_key()
    cls = pk.__class__.__name__.upper()
    out: Dict[str, Any] = {"key_type": "", "key_detail": "", "key_bits": 0, "key_curve": ""}

    def _bits(default: int = 0) -> int:
        try:
            return int(getattr(pk, "key_size", 0) or default)
        except Exception:
            return default

    if "RSA" in cls:
        bits = _bits()
        return {"key_type": "RSA", "key_detail": str(bits or ""), "key_bits": bits, "key_curve": ""}

    # EC keys in cryptography are usually EllipticCurvePublicKey
    if "ELLIPTIC" in cls or cls.startswith("EC"):
        curve = getattr(pk, "curve", None)
        name = str(getattr(curve, "name", "") or "") if curve is not None else ""
        try:
            bits = int(getattr(curve, "key_size", 0) or 0)
        except Exception:
            bits = 0
        return {"key_type": "EC", "key_detail": name, "key_bits": bits, "key_curve": name}

    for name in ("ED25519", "ED448", "X25519", "X448"):
        if name in cls:
            pretty = {"ED25519": "Ed25519", "ED448": "Ed448", "X25519": "X25519", "X448": "X448"}[name]
            bits = _FIXED_KEY_BITS[name]
            return {"key_type": pretty, "key_detail": pretty, "key_bits": bits, "key_curve": pretty}

    if "DSA" in cls:
        bits = _bits()
        return {"key_type": "DSA", "key_detail": str(bits or ""), "key_bits": bits, "key_curve": ""}

    if "DH" in cls:
        bits = _bits()
        return {"key_type": "DH", "key_detail": str(bits or ""), "key_bits": bits, "key_curve": ""}

    # Genuinely unrecognised: say so, and keep the raw class name as evidence rather than passing
    # it off as an algorithm name.
    out["key_type"] = "UNKNOWN"
    out["key_detail"] = pk.__class__.__name__
    return out


def _pk_info(cert: x509.Certificate) -> Tuple[str, str]:
    d = _pk_details(cert)
    return (d["key_type"], d["key_detail"])


def _leaf_cert_facts(cert: x509.Certificate) -> Dict[str, Any]:
    """Every fact read off the leaf certificate, for both the verified and unverified paths.

    These two paths each parsed the leaf separately and drifted: the unverified one never set
    sig_algorithm. Verification fails for self-signed certificates, private/internal CAs, expired
    certificates and hostname mismatches -- so on precisely the internal estates where a SHA-1
    signature is most likely to still be in use, the signature algorithm came back empty. A weak
    signature could not be flagged, and the CBOM had no signatureAlgorithmRef to emit. One function
    now, so the two paths cannot disagree about what a certificate says.
    """
    facts: Dict[str, Any] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": _utc_iso(_cert_not_before(cert)),
        "not_after": _utc_iso(_cert_not_after(cert)),
        "days_until_expiry": _days_until(_cert_not_after(cert)),
    }
    try:
        facts["sig_algorithm"] = (
            cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
        )
    except Exception:
        facts["sig_algorithm"] = ""
    facts.update(_pk_details(cert))
    facts.update(_extract_leaf_extensions(cert))
    return facts


def _extract_leaf_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "san_dns": [],
        "san_ip": [],
        "san_other": [],
        "key_usage": {},
        "eku": [],
        "basic_constraints": {},
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],
    }

    # SAN
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns, ip, other = [], [], []
        for gn in san:
            if isinstance(gn, x509.DNSName):
                dns.append(str(gn.value).lower())
            elif isinstance(gn, x509.IPAddress):
                ip.append(str(gn.value))
            else:
                other.append(str(getattr(gn, "value", gn)))
        out["san_dns"] = dns
        out["san_ip"] = ip
        out["san_other"] = other
    except Exception:
        pass

    # KeyUsage
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        out["key_usage"] = {
            "digital_signature": bool(ku.digital_signature),
            "content_commitment": bool(ku.content_commitment),
            "key_encipherment": bool(ku.key_encipherment),
            "data_encipherment": bool(ku.data_encipherment),
            "key_agreement": bool(ku.key_agreement),
            "key_cert_sign": bool(ku.key_cert_sign),
            "crl_sign": bool(ku.crl_sign),
            "encipher_only": bool(getattr(ku, "encipher_only", False)) if ku.key_agreement else False,
            "decipher_only": bool(getattr(ku, "decipher_only", False)) if ku.key_agreement else False,
        }
    except Exception:
        pass

    # EKU
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ekus: List[str] = []
        for oid in eku:
            name = getattr(oid, "_name", None)
            ekus.append(str(name) if name else str(oid.dotted_string))
        out["eku"] = ekus
    except Exception:
        pass

    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        out["basic_constraints"] = {"ca": bool(bc.ca), "path_length": bc.path_length}
    except Exception:
        pass

    # AIA (OCSP + CA Issuers)
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_urls: List[str] = []
        ca_issuers: List[str] = []
        for ad in aia:
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(str(ad.access_location.value))
            elif ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                ca_issuers.append(str(ad.access_location.value))
        out["ocsp_urls"] = ocsp_urls
        out["ca_issuers_urls"] = ca_issuers
    except Exception:
        pass

    # CRL distribution points
    try:
        crldp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls: List[str] = []
        for dp in crldp:
            if not dp.full_name:
                continue
            for n in dp.full_name:
                try:
                    if isinstance(n, x509.UniformResourceIdentifier):
                        urls.append(str(n.value))
                except Exception:
                    continue
        out["crl_urls"] = urls
    except Exception:
        pass

    return out


def _probe_http_endpoint(url: str, timeout: float = 3.0, max_read: int = 4096) -> Dict[str, Any]:
    """Best-effort reachability probe for OCSP/CRL endpoints (NOT a full OCSP request).

    Notes:
      - Many OCSP responders expect POST requests; this probe only checks basic HTTP reachability.
      - Any HTTP response code (including 4xx/5xx) still proves the endpoint is reachable at the network level.
    """
    start = time.time()
    out: Dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "elapsed_ms": None,
        "method": "",
        "error": "",
    }

    def _mark_reachable(method: str, status: Optional[int] = None):
        out["reachable"] = True
        out["method"] = method
        out["status_code"] = status

    try:
        # HEAD first (fast). Some responders reject HEAD (405), which still proves reachability.
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                _mark_reachable("HEAD", getattr(resp, "status", None) or resp.getcode())
        except urllib.error.HTTPError as e:
            _mark_reachable("HEAD", getattr(e, "code", None))
    except Exception as head_err:
        try:
            # Fallback GET with Range to limit bytes.
            req = urllib.request.Request(url, method="GET", headers={"Range": f"bytes=0-{max_read-1}"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    _mark_reachable("GET", getattr(resp, "status", None) or resp.getcode())
                    _ = resp.read(max_read)
            except urllib.error.HTTPError as e:
                _mark_reachable("GET", getattr(e, "code", None))
        except Exception as get_err:
            out["error"] = str(get_err or head_err)
    finally:
        out["elapsed_ms"] = int((time.time() - start) * 1000)

    return out


def _probe_ocsp_post_endpoint(url: str, timeout: float = 2.0, max_read: int = 4096) -> Dict[str, Any]:
    """Sprint 9.7: Best-effort OCSP AIA reachability via POST.

    Requirements:
      - Use requests.post() with strict 2s timeout.
      - Soft fail on timeout: log warning, do not fail scan.

    Notes:
      - We do not construct a real OCSP request body here; we only test network/HTTP reachability.
      - Any HTTP response (including 4xx/5xx) still proves the endpoint is reachable.
    """
    start = time.time()
    out: Dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "elapsed_ms": None,
        "method": "POST",
        "error": "",
    }

    try:
        resp = requests.post(
            url,
            data=b"",
            headers={"Content-Type": "application/ocsp-request"},
            timeout=timeout,
        )
        out["reachable"] = True
        out["status_code"] = getattr(resp, "status_code", None)
        try:
            _ = resp.content[:max_read]
        except Exception:
            pass
    except requests.exceptions.Timeout:
        out["error"] = "timeout"
        logger.warning("OCSP POST reachability probe timed out for %s (%.1fs)", url, timeout)
    except Exception as e:
        out["error"] = str(e)
    finally:
        out["elapsed_ms"] = int((time.time() - start) * 1000)

    return out



def _probe_revocation_endpoints(
    ocsp_urls: List[str],
    crl_urls: List[str],
    max_urls: int = 2,
    ocsp_post: bool = False,
) -> Dict[str, Any]:
    """Probe advertised OCSP/CRL URLs for basic network/HTTP reachability.

    Sprint 9.7:
      - If stapling is missing, probe OCSP AIA URL using POST with 2s timeout.
      - Soft fail on timeout.
    """
    ocsp_results: List[Dict[str, Any]] = []
    crl_results: List[Dict[str, Any]] = []

    for u in [x for x in (ocsp_urls or []) if str(x).strip()][:max_urls]:
        try:
            if ocsp_post:
                ocsp_results.append(_probe_ocsp_post_endpoint(str(u), timeout=2.0))
            else:
                ocsp_results.append(_probe_http_endpoint(str(u)))
        except Exception as e:
            ocsp_results.append({"url": str(u), "reachable": False, "status_code": None, "elapsed_ms": None, "method": "POST" if ocsp_post else "", "error": str(e)})

    for u in [x for x in (crl_urls or []) if str(x).strip()][:max_urls]:
        try:
            crl_results.append(_probe_http_endpoint(str(u)))
        except Exception as e:
            crl_results.append({"url": str(u), "reachable": False, "status_code": None, "elapsed_ms": None, "method": "", "error": str(e)})

    return {"ocsp_reachability": ocsp_results, "crl_reachability": crl_results}


def _parse_stapled_ocsp(der_bytes: bytes) -> Dict[str, Any]:
    """Parse a stapled OCSP response (if present) into status + timestamps."""
    out: Dict[str, Any] = {
        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",
        "ocsp_stapled_is_stale": False,
        "ocsp_stapled_stale_by_days": None,
    }
    try:
        resp = x509_ocsp.load_der_ocsp_response(der_bytes)
        # Cryptography uses OCSPResponseStatus + OCSPCertStatus enums
        out["ocsp_stapled_produced_at"] = _utc_iso(getattr(resp, "produced_at", None))
        if getattr(resp, "response_status", None) is not None:
            out["ocsp_response_status"] = str(resp.response_status).split(".")[-1]
        # Only successful responses have single_response
        single = getattr(resp, "responses", None)
        if single:
            r0 = single[0]
            out["ocsp_stapled_status"] = str(getattr(r0, "cert_status", "")).split(".")[-1].lower()
            out["ocsp_stapled_this_update"] = _utc_iso(getattr(r0, "this_update", None))
            out["ocsp_stapled_next_update"] = _utc_iso(getattr(r0, "next_update", None))
            try:
                nu = getattr(r0, "next_update", None)
                if nu is not None:
                    if nu.tzinfo is None:
                        nu = nu.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    out["ocsp_stapled_is_stale"] = nu < now
                    out["ocsp_stapled_stale_by_days"] = int((now - nu).days) if nu < now else 0
            except Exception:
                pass
    except Exception:
        pass
    return out

def _try_get_ocsp_staple(ssock: ssl.SSLSocket) -> Dict[str, Any]:
    """
    Best-effort OCSP stapling detection + parsing.

    NOTE: Python/OpenSSL exposure varies by platform/build. This function must never raise.
    """
    out = {
        "ocsp_stapling_supported": False,
        "ocsp_stapled": False,
        "ocsp_stapled_len": 0,
        "ocsp_stapled_sha256": "",

        # parsed fields (may remain empty)
        "ocsp_response_status": "",
        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",
        "ocsp_stapled_is_stale": False,
        "ocsp_stapled_stale_by_days": None,

        "ocsp_reachability": [],
        "crl_reachability": [],
    }

    try:
        resp = None

        # Different Python/OpenSSL builds expose this differently.
        candidates = ["ocsp_response", "get_ocsp_response", "_ocsp_response"]
        for name in candidates:
            if hasattr(ssock, name):
                attr = getattr(ssock, name)
                out["ocsp_stapling_supported"] = True
                resp = attr() if callable(attr) else attr
                break

        if isinstance(resp, (bytes, bytearray)) and len(resp) > 0:
            resp_b = bytes(resp)
            out["ocsp_stapled"] = True
            out["ocsp_stapled_len"] = len(resp_b)
            out["ocsp_stapled_sha256"] = hashlib.sha256(resp_b).hexdigest()

            # Parse response into status/timestamps where possible
            try:
                out.update(_parse_stapled_ocsp(resp_b))
            except Exception:
                pass
    except Exception:
        pass

    return out


def _get_cert_chain_der_with_source(ssock: ssl.SSLSocket) -> Tuple[List[bytes], str, str, str]:
    """
    Returns (chain_der_list, chain_source, confidence, confidence_reason)

    We try multiple mechanisms because Python/OpenSSL differs by platform/version.
    """
    # Preferred: verified chain
    for name in ("get_verified_chain", "getpeercertchain"):
        try:
            fn = getattr(ssock, name, None)
            if callable(fn):
                chain = fn()
                if chain:
                    # May already be DER bytes or cert objects; normalize to DER bytes.
                    out: List[bytes] = []
                    for item in chain:
                        if isinstance(item, (bytes, bytearray)):
                            out.append(bytes(item))
                        elif hasattr(item, "public_bytes"):
                            out.append(item.public_bytes())
                    return (out, "get_verified_chain", "high", "Chain comes from get_verified_chain (client-side verified path).")
        except Exception:
            pass

    # Fallback: unverified handshake (we at least have leaf)
    try:
        leaf = ssock.getpeercert(binary_form=True)
        if leaf:
            return ([leaf], "unverified_handshake", "medium", "Chain collected from handshake; may be incomplete.")
    except Exception:
        pass

    return ([], "unverified_handshake", "medium", "No chain details returned.")


def _analyze_cert_chain(chain_der: List[bytes]) -> Dict[str, Any]:
    parsed: List[Dict[str, Any]] = []
    issues: List[str] = []

    for i, der in enumerate(chain_der or []):
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
            kt, kd = _pk_info(cert)
            try:
                sig = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
            except Exception:
                sig = ""
            parsed.append(
                {
                    "index": i,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": _utc_iso(_cert_not_before(cert)),
                    "not_after": _utc_iso(_cert_not_after(cert)),
                    "key": f"{kt} / {kd}".strip(" /"),
                    "sig": sig,
                }
            )
        except Exception:
            continue

    if len(parsed) <= 1:
        issues.append("chain_short_or_unavailable")

    return {
        "cert_chain": parsed,
        "chain_length": len(parsed),
        "chain_issues": issues,
    }


def _finalise_scan_status(facts: Dict[str, Any]) -> None:
    """Record whether this scan actually observed the endpoint's cryptography.

    A failed scan used to be indistinguishable from a clean one. With no certificate, no TLS
    version and no key, the rule set still fired "No CRL distribution points advertised", "No OCSP
    responder advertised" and "Certificate chain short or unavailable" -- three assertions about a
    certificate that was never retrieved -- and the endpoint came out at quantum_risk_level "low",
    pq_relevance "LOW". An unreachable host therefore looked *safer* than a scanned RSA one.

    scan_status distinguishes the two, and the rules and scoring below consult it.
    """
    if facts.get("subject") or facts.get("key_type"):
        facts["scan_status"] = "ok"
        return
    code = str(facts.get("error_code") or "")
    if not code and str(facts.get("error") or "").strip():
        code = ERR_CONNECTION_ERROR
    if code == ERR_NOT_PERMITTED:
        facts["scan_status"] = "not_permitted"
    elif code in (ERR_TIMEOUT,):
        facts["scan_status"] = "timeout"
    elif code in (ERR_DNS,):
        facts["scan_status"] = "dns_error"
    elif code in (ERR_TLS_ERROR, ERR_TLS_VERSION_TOO_LOW):
        facts["scan_status"] = "tls_error"
    elif code:
        facts["scan_status"] = "unreachable"
    else:
        # Handshake succeeded but no certificate could be parsed.
        facts["scan_status"] = "no_certificate"


def _scope_refusal(host: str) -> str:
    """Why the current organization may not scan host, or "" (services/domain_verification)."""
    try:
        from services import domain_verification
    except Exception:
        return ""
    if not domain_verification.enforcement_enabled():
        return ""
    try:
        return domain_verification.refusal_for_current_org(host)
    except Exception as exc:
        # Fail closed: with enforcement on, a check that cannot run is a refusal, not a pass.
        return f"Scan permission could not be checked ({exc.__class__.__name__})."


def scan_host(host: str, port: int = 443) -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "host": host,
        "port": port,

        "error": "",
        "error_code": "",
        # "ok" once a certificate has actually been read off the wire. Anything else means the
        # scan did not observe this endpoint's cryptography, and no report may describe it as if
        # it had. See _finalise_scan_status below.
        "scan_status": "ok",
        "verify_mode": "CERT_REQUIRED",
        "verify_error": "",
        "verify_code": None,
        "verify_message": "",
        "verify_reason": "",
        "unverified_fallback": False,

        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": None,

        # The negotiated key-exchange group -- the field that says whether an endpoint has
        # already enabled hybrid post-quantum key exchange. key_exchange_observed is what every
        # consumer must check: "" with observed False means "not observed here", which is not the
        # same claim as "no post-quantum key exchange in use".
        "key_exchange": "",
        "key_exchange_group_id": None,
        "key_exchange_family": "",
        "key_exchange_observed": False,
        "key_exchange_observation_method": "",
        "key_exchange_unobservable_reason": "",
        "key_exchange_hello_retry": False,

        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,

        "key_type": "",
        "key_detail": "",
        "key_bits": 0,
        "key_curve": "",
        "sig_algorithm": "",

        "san_dns": [],
        "key_usage": {},
        "eku": [],
        "basic_constraints": {},
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],

        "ocsp_stapling_supported": False,
        "ocsp_stapled": False,
        "ocsp_stapled_len": 0,
        "ocsp_stapled_sha256": "",

        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",

        "ocsp_reachability": [],
        "crl_reachability": [],

        "cert_chain": [],
        "chain_length": 0,
        "chain_issues": [],
        "chain_source": "",
        "chain_confidence": "",
        "chain_confidence_reason": "",

        "tls_supported_versions": [],
        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        "forward_secrecy_possible": False,

        "findings": [],
        "risk_level": "low",
        "risk": "low",
        "quantum_risk_score": 0,
        "quantum_risk_level": "low",
        "pq_relevance": "LOW",
        "pq_recommendation": "",
    }

    # On a hosted deployment an organization scans only its verified domains
    # (services/domain_verification). Refused before any connection is opened.
    refusal = _scope_refusal(host)
    if refusal:
        facts["error"] = refusal
        facts["error_code"] = ERR_NOT_PERMITTED
        facts["key_exchange_unobservable_reason"] = "not scanned: " + refusal
    else:
        # Primary handshake (verified)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass

            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    facts["tls_version"] = ssock.version() or ""
                    c = ssock.cipher()
                    if c:
                        facts["cipher_name"] = c[0] or ""
                        facts["cipher_bits"] = c[2] if len(c) > 2 else None
                    try:
                        facts["alpn"] = ssock.selected_alpn_protocol()
                    except Exception:
                        facts["alpn"] = None

                    # OCSP stapling (best-effort)
                    facts.update(_try_get_ocsp_staple(ssock))

                    # Leaf cert
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        facts.update(_leaf_cert_facts(cert))

                        # Revocation endpoint reachability (best-effort)
                        try:
                            probes = _probe_revocation_endpoints(
                                facts.get("ocsp_urls", []),
                                facts.get("crl_urls", []),
                                max_urls=2,
                                ocsp_post=(not bool(facts.get("ocsp_stapled"))),
                            )
                            facts.update(probes)
                        except Exception:
                            pass

                    # Chain (best-effort)
                    chain_der, chain_source, conf, conf_reason = _get_cert_chain_der_with_source(ssock)
                    facts["chain_source"] = chain_source
                    facts["chain_confidence"] = conf
                    facts["chain_confidence_reason"] = conf_reason
                    facts.update(_analyze_cert_chain(chain_der))

        except _SSLCertVerificationError as e:
            facts["verify_error"] = str(e)
            facts.update(_classify_verify_error(e))
            facts["unverified_fallback"] = True
            # Best-effort fallback: collect cert/chain details without verification so we can still produce actionable findings.
            try:
                ctx = _new_ssl_context(ssl.PROTOCOL_TLS)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
                except Exception:
                    pass
                with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        # Populate best-effort facts (do not overwrite verify_error)
                        if not facts.get("tls_version"):
                            facts["tls_version"] = ssock.version() or ""
                        c = ssock.cipher()
                        if c and not facts.get("cipher_name"):
                            facts["cipher_name"] = c[0] or ""
                            facts["cipher_bits"] = c[2] if len(c) > 2 else None
                        try:
                            if facts.get("alpn") is None:
                                facts["alpn"] = ssock.selected_alpn_protocol()
                        except Exception:
                            pass

                        # OCSP stapling (best-effort)
                        facts.update(_try_get_ocsp_staple(ssock))

                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            cert = x509.load_der_x509_certificate(der, default_backend())
                            facts.update(_leaf_cert_facts(cert))

                            # Revocation endpoint reachability (best-effort)
                            try:
                                probes = _probe_revocation_endpoints(
                                    facts.get("ocsp_urls", []),
                                    facts.get("crl_urls", []),
                                    max_urls=2,
                                    ocsp_post=(not bool(facts.get("ocsp_stapled"))),
                                )
                                facts.update(probes)
                            except Exception:
                                pass

                        # Chain (best-effort)
                        chain_der, chain_source, conf, conf_reason = _get_cert_chain_der_with_source(ssock)
                        facts["chain_source"] = chain_source
                        facts["chain_confidence"] = conf
                        facts["chain_confidence_reason"] = conf_reason
                        facts.update(_analyze_cert_chain(chain_der))
            except Exception:
                pass
        except Exception as e:
            facts["error"] = str(e)
            facts["error_code"] = _error_code_from_exception(e)

        # Probes (do not require verification)
        try:
            facts.update(_probe_tls_versions(host, port))
        except Exception:
            pass

        try:
            facts.update(_probe_tls12_accepted_ciphers(host, port))
        except Exception:
            pass

        # Only worth a round trip if something answered on this port at all.
        if facts.get("tls_supported_versions") or facts.get("tls_version"):
            try:
                facts.update(_probe_key_exchange_group(host, port))
            except Exception as exc:
                facts["key_exchange_unobservable_reason"] = f"probe failed: {exc}"
        else:
            facts["key_exchange_unobservable_reason"] = "no TLS handshake completed on this endpoint"

    _finalise_scan_status(facts)

    # Findings + scoring
    findings = evaluate_tls_findings(facts)
    scoring = derive_risk_and_score(findings)
    pq = derive_pq_relevance(findings)
    quantum_readiness = derive_quantum_readiness(facts, findings)

    facts["findings"] = findings
    facts["risk_level"] = scoring["risk_level"]
    facts["risk"] = scoring["risk_label"]
    facts["quantum_risk_score"] = scoring["quantum_risk_score"]
    facts["quantum_risk_level"] = scoring["quantum_risk_level"]
    facts["pq_relevance"] = pq["pq_relevance"]
    facts["pq_recommendation"] = pq["pq_recommendation"]
    facts.update(quantum_readiness)

    return facts


def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for t in targets:
        host, port = _parse_target(t)
        if not host:
            continue
        results.append(scan_host(host, port))
    return results
