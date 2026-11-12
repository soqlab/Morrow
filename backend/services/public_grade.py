"""The public quantum-readiness grade: one letter, A to F, for a public HTTPS endpoint.

What this is
------------
A minimal, read-only, SSL-Labs-style check of a public hostname on port 443, graded on one
question: is traffic to this site protected against "harvest now, decrypt later" -- recording
today, decrypting once a cryptographically relevant quantum computer exists? It powers the public
API under ``/api/public`` (routers/public_grade.py) and the soqlab.com pages that call it.

It is separate from the organisation scanner on purpose. It does not run an org scan, does not
read or write any organisation's data, and does not touch the verified-domain rule
(``MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS``) that governs the real scanner. Its only tables are
``public_grade_checks`` here and the shared abuse log ``public_check_log``.

The rubric (``RUBRIC_VERSION``; full text and reasoning in docs/PUBLIC_GRADE.md)
------------------------------------------------------------------------------
  A  hybrid post-quantum key exchange (e.g. X25519MLKEM768) chosen when offered alongside
     classical groups, TLS 1.3, TLS 1.0/1.1 disabled, no weakness below.
  B  post-quantum key exchange, but a weakness remains: TLS 1.0/1.1 enabled, weak TLS 1.2
     ciphers accepted, or the certificate expires in under 14 days.
  C  TLS 1.3 with forward-secret classical key exchange only -- recorded traffic is at risk.
  D  TLS 1.2 at most, forward-secret (EC)DHE.
  E  legacy: TLS 1.0/1.1 enabled with no TLS 1.3, or weak ciphers (3DES, RC4, NULL, EXPORT, DES,
     MD5, anonymous) accepted.
  F  no forward secrecy (RSA key transport accepted), an invalid or expired certificate, or no TLS.

The certificate's signature algorithm is never penalised: browsers cannot yet use ML-DSA
certificates, and a signature only has to resist forgery while the connection is live, so a
recorded session is not exposed through it.

What one check contacts
-----------------------
One hostname, one pinned address, port 443, about a dozen short connections, no request body:
  * one verified TLS handshake with the platform's default client (version, cipher, certificate);
  * if that fails verification, one unverified handshake to read the certificate it failed on;
  * one handshake each pinned to TLS 1.0, 1.1 and (when not already seen) 1.2;
  * the existing hand-built ClientHello probe (scanner._probe_key_exchange_group) offering the
    post-quantum groups first, then one per standardised hybrid group to list which are accepted;
  * one TLS 1.2 handshake offering only RSA key transport, and one offering only weak suites;
  * one ``HEAD /`` over TLS for the ``Server`` header, reading at most 8 KB and following nothing.

Safety
------
The name is validated as a bare public DNS hostname (services/public_check.normalize_domain, plus
a stricter refusal of anything carrying a scheme, port, path or credentials). It is resolved once;
every answer must pass ``alert_routing.ip_is_public`` (the guard on outbound webhooks) and the
stricter ``refusal_reason`` here -- private, loopback, link-local, CGNAT, multicast, reserved,
unspecified, IPv4-mapped/6to4/NAT64-wrapped non-public, and this server's own addresses are all
refused. Every connection then goes to that one pinned address with SNI set to the hostname, so a
second DNS answer cannot redirect anything inward. The public-check opt-out list is honoured.
Rate limits: per client IP (10/min, fresh 3/min), per target domain, and a global hourly budget,
through services/org_rate_limits.py (Redis-backed when configured); a process-wide concurrency
cap; and a one-hour per-domain cache.

Command line (no database, for batch jobs such as a league table of top sites)
-----------------------------------------------------------------------------
Run from ``backend/``::

    python -m services.public_grade --batch domains.txt --out results.jsonl \\
        --concurrency 32 --timeout 8

``domains.txt`` holds one domain per line; blank lines and ``#`` comments are skipped, and a
``rank,domain`` CSV line (the Tranco list format) uses its last field. Each line of
``results.jsonl`` is one contract JSON object, the same shape as ``GET /api/public/grade/{d}``;
a failure is ``{"domain", "scanned_at", "error", "detail"}``. The run is resumable: domains already
present in ``--out`` are skipped and new lines are appended and flushed one at a time, so an
interrupted run continues where it stopped. The same SSRF guard applies; the opt-out list is read
from ``MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS`` only (the CLI never opens the database). Exit status is 0
even when individual domains fail; a summary line goes to stderr. ``python -m services.public_grade
example.com`` grades one domain and prints the text form.

Settings
--------
``MORROW_PUBLIC_GRADE_ENABLED``              1     master switch for the API
``MORROW_PUBLIC_GRADE_CACHE_SECONDS``        3600  per-domain cache
``MORROW_PUBLIC_GRADE_IP_PER_MINUTE``        10    grade requests per client IP per minute
``MORROW_PUBLIC_GRADE_FRESH_PER_MINUTE``     3     ?fresh=1 requests per client IP per minute
``MORROW_PUBLIC_GRADE_DOMAIN_PER_HOUR``      12    checks of one domain per hour, whoever asks
``MORROW_PUBLIC_GRADE_GLOBAL_PER_HOUR``      600   checks per hour, whole service
``MORROW_PUBLIC_GRADE_CONCURRENCY``          4     checks running at once in this process
``MORROW_PUBLIC_GRADE_TIMEOUT``              5     per-connection timeout, seconds
``MORROW_PUBLIC_GRADE_DEADLINE``             25    whole-check deadline, seconds
``MORROW_PUBLIC_GRADE_SELF_ADDRESSES``       ""    extra addresses that count as this server's own
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

RUBRIC_VERSION = "2026-11.1"
PORT = 443
GRADES = ("A", "B", "C", "D", "E", "F")
USER_AGENT = "SOQLAB-Morrow-PublicGrade/1 (+https://soqlab.com)"

#: Standardised hybrid groups probed one at a time for ``offered_pq_groups_accepted``.
#: 0x11EC X25519MLKEM768, 0x11EB SecP256r1MLKEM768, 0x11ED SecP384r1MLKEM1024
#: (draft-ietf-tls-ecdhe-mlkem; IANA TLS Supported Groups registry).
PQ_PROBE_GROUPS: Tuple[Tuple[int, str], ...] = (
    (0x11EC, "X25519MLKEM768"),
    (0x11EB, "SecP256r1MLKEM768"),
    (0x11ED, "SecP384r1MLKEM1024"),
)

#: When a cryptographically relevant quantum computer may exist. Not invented here: the Global Risk
#: Institute's Quantum Threat Timeline Report 2025 (Mosca and Piani, evolutionQ; published
#: 9 March 2026; 26 experts surveyed in 2025) puts the chance of a quantum computer able to break
#: RSA-2048 within 24 hours at 28-49% within 10 years ("quite possible") and 51-70% ("likely")
#: within 15 years. Counted from the 2025 survey that is 2035 to 2040. Update both numbers, the
#: basis text and RUBRIC_VERSION together when a new edition is published.
DECRYPT_YEAR_LOW = 2035
DECRYPT_YEAR_HIGH = 2040
EXPOSURE_SOURCE_URL = "https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/"
EXPOSURE_BASIS = (
    "Global Risk Institute, Quantum Threat Timeline Report 2025 (Mosca and Piani, published March "
    "2026): experts put the chance of a quantum computer that can break RSA-2048 in 24 hours at "
    "28-49% within 10 years and 51-70% within 15 years of the 2025 survey, i.e. about 2035 to 2040. "
    "Traffic recorded today with classical key exchange could be decrypted from then on."
)
PQ_BASIS = (
    "The key exchange includes ML-KEM (NIST FIPS 203), so a recording of today's traffic cannot be "
    "decrypted later by breaking the key exchange with a quantum computer."
)
PQ_SOURCE_URL = "https://csrc.nist.gov/pubs/fips/203/final"

#: Cipher strings for the TLS 1.2 key-transport and weak-suite probes (OpenSSL syntax).
_RSA_KX_CIPHERS = "kRSA:@SECLEVEL=0"
_WEAK_CIPHERS = "3DES:RC4:DES:NULL:EXPORT:MD5:aNULL:eNULL:@SECLEVEL=0"
_LEGACY_CIPHERS = "ALL:@SECLEVEL=0"
PROBE_WORKERS = 6
_WEAK_TOKENS = ("3DES", "DES-CBC3", "RC4", "NULL", "EXPORT", "EXP-", "MD5", "ADH", "AECDH", "DES-CBC-")

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()
_slots_lock = threading.Lock()
_slots: Dict[str, Any] = {"size": 0, "sem": threading.Semaphore(1)}
_inflight_lock = threading.Lock()
_inflight: Dict[str, threading.Lock] = {}
_own_cache: Dict[str, Any] = {"at": 0.0, "addresses": frozenset()}


class GradeError(Exception):
    """A refusal or failure with an HTTP status, a short code and a plain sentence."""

    def __init__(self, status_code: int, error: str, detail: str, retry_after: Optional[float] = None):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.error = str(error)
        self.detail = str(detail)
        self.retry_after = retry_after

    def as_dict(self) -> Dict[str, Any]:
        return {"error": self.error, "detail": self.detail}


# ── Settings ─────────────────────────────────────────────────────────────────


def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def enabled() -> bool:
    return str(os.getenv("MORROW_PUBLIC_GRADE_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def cache_seconds() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_CACHE_SECONDS", 3600, 60, 7 * 24 * 3600))


def ip_per_minute() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_IP_PER_MINUTE", 10, 1, 10_000))


def fresh_per_minute() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_FRESH_PER_MINUTE", 3, 1, 1_000))


def domain_per_hour() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_DOMAIN_PER_HOUR", 12, 1, 1_000))


def global_per_hour() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_GLOBAL_PER_HOUR", 600, 1, 1_000_000))


def concurrency() -> int:
    return int(_num("MORROW_PUBLIC_GRADE_CONCURRENCY", 4, 1, 64))


def connect_timeout() -> float:
    return _num("MORROW_PUBLIC_GRADE_TIMEOUT", 5.0, 1.0, 30.0)


def deadline_seconds() -> float:
    return _num("MORROW_PUBLIC_GRADE_DEADLINE", 25.0, 3.0, 120.0)


# ── Time ─────────────────────────────────────────────────────────────────────


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_or_none(text: Any) -> Optional[str]:
    raw = str(text or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return iso(parsed)


# ── Target validation and the SSRF guard ─────────────────────────────────────

_FORBIDDEN_CHARS = re.compile(r"[/:@?#\[\]\\%\s]")


def normalize(value: Any) -> str:
    """A bare public DNS hostname, IDNA-normalised and lowercased, or a 400.

    Stricter than the /check form, which accepts a pasted URL: an API caller names a host, so a
    scheme, port, path, query or credentials is a mistake to report, not something to strip.
    """
    from services import public_check

    raw = str(value or "").strip()
    if not raw:
        raise GradeError(400, "invalid_domain", "Give a domain name, for example example.com.")
    if len(raw) > 300:
        raise GradeError(400, "invalid_domain", "That is too long to be a domain name.")
    if _FORBIDDEN_CHARS.search(raw):
        raise GradeError(400, "invalid_domain",
                         "Give a bare hostname: no scheme, port, path, query or credentials.")
    try:
        host = public_check.normalize_domain(raw)
    except public_check.PublicCheckError as exc:
        raise GradeError(400, "invalid_domain", exc.detail) from None
    if len(host) > 253:
        raise GradeError(400, "invalid_domain", "A hostname is at most 253 characters.")
    return host


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _unwrap(ip: Any) -> Any:
    """The IPv4 address hidden inside an IPv4-mapped, 6to4 or NAT64 IPv6 address, if any."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def own_addresses() -> frozenset:
    """This server's own addresses: its hostname's addresses plus MORROW_PUBLIC_GRADE_SELF_ADDRESSES.

    Cached for ten minutes. A lookup failure yields what is configured; the private-range checks
    still refuse every interface address a container or VM normally has.
    """
    now = time.monotonic()
    if _own_cache["addresses"] and now - float(_own_cache["at"]) < 600:
        return _own_cache["addresses"]
    found = set()
    for item in re.split(r"[,;\s]+", str(os.getenv("MORROW_PUBLIC_GRADE_SELF_ADDRESSES", "") or "")):
        try:
            found.add(str(ipaddress.ip_address(item.strip())))
        except ValueError:
            continue
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(str(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])))
    except Exception:
        pass
    _own_cache["addresses"] = frozenset(found)
    _own_cache["at"] = now
    return _own_cache["addresses"]


def refusal_reason(address: str, own: Iterable[str] = ()) -> str:
    """Why this address may not be contacted, or "" when it is an ordinary public address."""
    from services import alert_routing

    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return "not an IP address"
    inner = _unwrap(ip)
    own_set = {str(a) for a in own}
    if str(ip) in own_set or str(inner) in own_set:
        return "this server's own address"
    for candidate in {ip, inner}:
        if candidate.is_unspecified:
            return "the unspecified address"
        if candidate.is_loopback:
            return "a loopback address"
        if candidate.is_link_local:
            return "a link-local address"
        if isinstance(candidate, ipaddress.IPv4Address) and candidate in _CGNAT:
            return "a carrier-grade NAT address (100.64.0.0/10)"
        if candidate.is_multicast:
            return "a multicast address"
        if candidate.is_private:
            return "a private address"
        if candidate.is_reserved:
            return "a reserved address"
        if not candidate.is_global:
            return "not a public internet address"
    if not alert_routing.ip_is_public(str(ip)):
        return "not a public internet address"
    return ""


def resolve_pinned(host: str) -> str:
    """Resolve once, refuse if any answer is not public, and return the one address to connect to."""
    from services import alert_routing

    try:
        addresses = alert_routing.resolve_host(host, PORT)
    except (OSError, UnicodeError):
        raise GradeError(504, "unresolvable", f"{host} does not resolve in public DNS.") from None
    if not addresses:
        raise GradeError(504, "unresolvable", f"{host} does not resolve in public DNS.")
    own = own_addresses()
    for address in addresses:
        reason = refusal_reason(address, own)
        if reason:
            raise GradeError(
                403, "refused_target",
                f"{host} resolves to {address}, which is {reason}. This check only contacts "
                "public internet addresses.")
    ipv4 = [a for a in addresses if ":" not in str(a)]
    return str((ipv4 or list(addresses))[0])


# ── The probe ────────────────────────────────────────────────────────────────

_VERSIONS = {
    "1.0": "TLSv1",
    "1.1": "TLSv1_1",
    "1.2": "TLSv1_2",
    "1.3": "TLSv1_3",
}


def _context(verify: bool, low: str = "", high: str = "", ciphers: str = "",
             alpn: Optional[List[str]] = None) -> ssl.SSLContext:
    if verify:
        # The public web PKI as browsers see it (Mozilla's root store via certifi), not whatever the
        # host OS happens to have cached: Windows, for one, fetches roots lazily and fails otherwise.
        try:
            import certifi

            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if low:
            ctx.minimum_version = getattr(ssl.TLSVersion, _VERSIONS[low])
        if high:
            ctx.maximum_version = getattr(ssl.TLSVersion, _VERSIONS[high])
    if ciphers:
        ctx.set_ciphers(ciphers)
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    return ctx


class _Unreachable(Exception):
    """Nothing accepted a TCP connection on the pinned address and port 443."""


def _handshake(address: str, host: str, ctx: ssl.SSLContext, timeout: float,
               read_cert: bool = False) -> Dict[str, Any]:
    """One TLS handshake to the pinned address with SNI = host. Raises _Unreachable on TCP failure."""
    try:
        sock = socket.create_connection((address, PORT), timeout=timeout)
    except OSError as exc:
        raise _Unreachable(str(exc)[:200]) from None
    with sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            out: Dict[str, Any] = {"version": ssock.version() or "", "cipher": ""}
            cipher = ssock.cipher()
            if cipher:
                out["cipher"] = cipher[0] or ""
            if read_cert:
                out["der"] = ssock.getpeercert(binary_form=True)
            return out


def _cert_facts(der: Optional[bytes]) -> Dict[str, Any]:
    if not der:
        return {}
    import scanner
    from cryptography import x509

    try:
        leaf = scanner._leaf_cert_facts(x509.load_der_x509_certificate(der))
    except Exception as exc:
        return {"parse_error": type(exc).__name__}
    return {
        "key_type": str(leaf.get("key_type") or ""),
        "key_bits": int(leaf.get("key_bits") or 0) or None,
        "signature_algorithm": str(leaf.get("sig_algorithm") or ""),
        "not_after": _iso_or_none(leaf.get("not_after")),
        "issuer": str(leaf.get("issuer") or ""),
        "days_until_expiry": leaf.get("days_until_expiry"),
    }


def _http_head(address: str, host: str, timeout: float, max_bytes: int = 8192) -> Dict[str, str]:
    """Response headers from one ``HEAD /`` over TLS to the pinned address. Follows nothing."""
    ctx = _context(verify=False, alpn=["http/1.1"])
    request = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii")
    sock = socket.create_connection((address, PORT), timeout=timeout)
    data = b""
    with sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(request)
            deadline = time.monotonic() + timeout
            while b"\r\n\r\n" not in data and len(data) < max_bytes and time.monotonic() < deadline:
                chunk = ssock.recv(min(4096, max_bytes - len(data)))
                if not chunk:
                    break
                data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    headers: Dict[str, str] = {}
    for line in head.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.setdefault(name.strip().lower(), value.strip()[:200])
    return headers


def _clean_header(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = "".join(ch for ch in str(value) if " " <= ch <= "~").strip()[:100]
    return text or None


def detect_platform(server_header: Optional[str], headers: Optional[Dict[str, str]] = None) -> str:
    """nginx | apache | caddy | haproxy | iis | cloudflare | cdn | unknown, from response headers."""
    s = str(server_header or "").lower()
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if "cloudflare" in s or "cf-ray" in h:
        return "cloudflare"
    if (any(tok in s for tok in ("akamai", "cloudfront", "fastly", "varnish", "bunnycdn", "gws", "gfe"))
            or "x-amz-cf-id" in h or "x-fastly-request-id" in h or "x-akamai-transformed" in h):
        return "cdn"
    if "nginx" in s or "openresty" in s or "tengine" in s:
        return "nginx"
    if "apache" in s:
        return "apache"
    if "caddy" in s:
        return "caddy"
    if "haproxy" in s:
        return "haproxy"
    if "microsoft-iis" in s or "microsoft-httpapi" in s:
        return "iis"
    return "unknown"


def empty_facts(domain: str, address: str = "") -> Dict[str, Any]:
    return {
        "domain": domain, "address": address, "reachable": True, "tls": False, "error": "",
        "tls_versions": {"1.0": False, "1.1": False, "1.2": False, "1.3": False},
        "tls_untested": [], "negotiated_version": "", "negotiated_cipher": "",
        "certificate_verified": False, "verify_error": "", "certificate": {},
        "kx_group": "", "kx_family": "", "kx_observed": False, "kx_reason": "",
        "pq_groups_accepted": [], "rsa_kx_accepted": None, "rsa_kx_cipher": "",
        "weak_ciphers_accepted": [], "weak_cipher_probe": "not_run",
        "server_header": None, "platform": "unknown", "connections": 0, "notes": [],
    }


def probe(host: str, address: str, timeout: Optional[float] = None,
          deadline: Optional[float] = None) -> Dict[str, Any]:
    """Collect the handshake facts for host at the pinned address. Never raises for target errors.

    ``reachable`` False means no TCP connection was accepted on 443 (the caller answers 504).
    """
    import scanner

    budget = float(timeout if timeout is not None else connect_timeout())
    end = time.monotonic() + float(deadline if deadline is not None else deadline_seconds())
    facts = empty_facts(host, address)

    def left() -> float:
        return end - time.monotonic()

    def step_timeout() -> float:
        return max(0.5, min(budget, left()))

    def out_of_time(what: str) -> bool:
        if left() < 0.5:
            facts["notes"].append(f"skipped {what}: the check ran out of time")
            return True
        return False

    # 1. The handshake a default, verifying client makes. If it fails for a reason other than the
    # certificate, retry verified with legacy versions and suites allowed (a TLS 1.0-only server);
    # if verification itself fails, read the certificate it failed on without verifying.
    main: Optional[Dict[str, Any]] = None
    attempts = (
        ("verified", lambda: _context(verify=True)),
        ("verified-legacy", lambda: _context(verify=True, low="1.0", ciphers=_LEGACY_CIPHERS)),
        ("unverified-legacy", lambda: _context(verify=False, low="1.0", ciphers=_LEGACY_CIPHERS)),
    )
    verify_failed = False
    for name, make in attempts:
        if verify_failed and name == "verified-legacy":
            continue
        if name != "verified" and out_of_time("the fallback handshake"):
            break
        try:
            ctx = make()
        except (ssl.SSLError, ValueError, AttributeError):
            continue
        try:
            facts["connections"] += 1
            main = _handshake(address, host, ctx, step_timeout(), read_cert=True)
            facts["certificate_verified"] = name.startswith("verified")
            break
        except _Unreachable as exc:
            facts["reachable"] = False
            facts["error"] = f"no connection on port {PORT}: {exc}"
            return facts
        except ssl.SSLCertVerificationError as exc:
            verify_failed = True
            facts["verify_error"] = str(getattr(exc, "verify_message", "") or exc)[:200]
        except (ssl.SSLError, OSError) as exc:
            facts["error"] = f"no TLS handshake completed on port {PORT}: {exc}"[:200]
    if main is None:
        return facts

    facts["tls"] = True
    facts["error"] = ""
    facts["negotiated_version"] = main.get("version") or ""
    facts["negotiated_cipher"] = main.get("cipher") or ""
    facts["certificate"] = _cert_facts(main.get("der"))
    label = {"TLSv1": "1.0", "TLSv1.1": "1.1", "TLSv1.2": "1.2", "TLSv1.3": "1.3"}.get(facts["negotiated_version"])
    if label:
        facts["tls_versions"][label] = True

    # 2-5 are independent of each other, so they run side by side (PROBE_WORKERS at a time) on the
    # same pinned address. Each returns its own partial facts; nothing is shared while they run.
    def version_probe(version: str) -> Dict[str, Any]:
        if out_of_time(f"the TLS {version} probe"):
            return {"untested": version, "connections": 0}
        try:
            ctx = _context(verify=False, low=version, high=version, ciphers=_LEGACY_CIPHERS)
        except (ssl.SSLError, ValueError, AttributeError):
            return {"untested": version, "connections": 0}
        try:
            _handshake(address, host, ctx, step_timeout())
            return {"version": version, "ok": True, "connections": 1}
        except (ssl.SSLError, OSError, _Unreachable):
            return {"version": version, "ok": False, "connections": 1}

    def kx_probe(groups: Optional[Tuple[int, ...]] = None) -> Dict[str, Any]:
        if out_of_time("a key-exchange probe"):
            return {"connections": 0}
        out = scanner._probe_key_exchange_group(host, PORT, timeout=step_timeout(), address=address,
                                                groups=groups)
        return {"kx": out, "groups": groups, "connections": 1}

    def cipher_probe(kind: str, ciphers: str) -> Dict[str, Any]:
        if out_of_time(f"the {kind} probe"):
            return {"kind": kind, "status": "not_run", "connections": 0}
        try:
            ctx = _context(verify=False, low="1.0", high="1.2", ciphers=ciphers)
        except (ssl.SSLError, ValueError, AttributeError):
            return {"kind": kind, "status": "untestable", "connections": 0}
        try:
            got = _handshake(address, host, ctx, step_timeout())
            return {"kind": kind, "status": "tested", "cipher": got.get("cipher") or "", "connections": 1}
        except (ssl.SSLError, OSError, _Unreachable):
            return {"kind": kind, "status": "tested", "cipher": "", "connections": 1}

    def head_probe() -> Dict[str, Any]:
        if out_of_time("the Server header request"):
            return {"connections": 0}
        try:
            return {"headers": _http_head(address, host, step_timeout()), "connections": 1}
        except Exception as exc:
            return {"head_error": type(exc).__name__, "connections": 1}

    jobs: List[Tuple[Any, tuple]] = []
    for version in ("1.2", "1.1", "1.0"):
        if not facts["tls_versions"][version]:
            jobs.append((version_probe, (version,)))
    jobs.append((kx_probe, ()))
    if facts["tls_versions"]["1.3"]:
        for code, _name in PQ_PROBE_GROUPS:
            jobs.append((kx_probe, ((code,),)))
    jobs.append((cipher_probe, ("rsa", _RSA_KX_CIPHERS)))
    jobs.append((cipher_probe, ("weak", _WEAK_CIPHERS)))
    jobs.append((head_probe, ()))
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        results = [f.result() for f in [pool.submit(fn, *args) for fn, args in jobs]]

    accepted: List[str] = []
    single: Dict[int, bool] = {}
    for part in results:
        facts["connections"] += int(part.get("connections") or 0)
        if "untested" in part:
            facts["tls_untested"].append(part["untested"])
        elif "version" in part:
            facts["tls_versions"][part["version"]] = bool(part["ok"])
        elif "kx" in part:
            kx = part["kx"]
            if part["groups"] is None:
                facts["kx_observed"] = bool(kx.get("key_exchange_observed"))
                facts["kx_group"] = str(kx.get("key_exchange") or "")
                facts["kx_family"] = str(kx.get("key_exchange_family") or "")
                facts["kx_reason"] = str(kx.get("key_exchange_unobservable_reason") or "")
            else:
                code = part["groups"][0]
                single[code] = bool(kx.get("key_exchange_observed")) and kx.get("key_exchange_group_id") == code
        elif part.get("kind") == "rsa":
            if part["status"] == "tested":
                facts["rsa_kx_accepted"] = bool(part.get("cipher"))
                facts["rsa_kx_cipher"] = part.get("cipher") or ""
        elif part.get("kind") == "weak":
            facts["weak_cipher_probe"] = part["status"]
            if part["status"] == "untestable":
                facts["notes"].append("this server's TLS library cannot offer the weak suites, so they were not tested")
            elif part.get("cipher"):
                facts["weak_ciphers_accepted"] = [part["cipher"]]
        elif "headers" in part:
            facts["server_header"] = _clean_header(part["headers"].get("server"))
            facts["platform"] = detect_platform(facts["server_header"], part["headers"])
        elif "head_error" in part:
            facts["notes"].append(f"no HTTP response headers read ({part['head_error']})")
    if facts["kx_family"] in ("pq_hybrid", "pq_pure"):
        accepted.append(facts["kx_group"])
    for code, name in PQ_PROBE_GROUPS:
        if single.get(code) and name not in accepted:
            accepted.append(name)
    facts["pq_groups_accepted"] = accepted
    if not any(facts["tls_versions"][v] for v in ("1.0", "1.1", "1.2")):
        facts["rsa_kx_accepted"] = False
        facts["rsa_kx_cipher"] = ""
        facts["weak_ciphers_accepted"] = []
        facts["weak_cipher_probe"] = "not_applicable"
    return facts


# ── Grading (pure) ───────────────────────────────────────────────────────────


def _is_weak_cipher(name: str) -> bool:
    upper = str(name or "").upper()
    return any(tok in upper for tok in _WEAK_TOKENS)


def _forward_secret(facts: Dict[str, Any]) -> bool:
    """Whether a modern client gets forward secrecy: read from the handshake a default client made."""
    if not facts.get("tls"):
        return False
    version = str(facts.get("negotiated_version") or "")
    cipher = str(facts.get("negotiated_cipher") or "").upper()
    if version == "TLSv1.3" or cipher.startswith("TLS_"):
        return True
    return "ECDHE" in cipher or "DHE" in cipher


def grade_from_facts(facts: Dict[str, Any]) -> Dict[str, Any]:
    """The grade and everything said about it, from probe facts. Pure: no I/O, no clock."""
    domain = str(facts.get("domain") or "")
    versions = {k: bool((facts.get("tls_versions") or {}).get(k)) for k in ("1.0", "1.1", "1.2", "1.3")}
    cert = dict(facts.get("certificate") or {})
    days = cert.get("days_until_expiry")
    family = str(facts.get("kx_family") or "")
    group = str(facts.get("kx_group") or "")
    post_quantum = family in ("pq_hybrid", "pq_pure")
    hybrid = family == "pq_hybrid"
    legacy = versions["1.0"] or versions["1.1"]
    weak = [c for c in (facts.get("weak_ciphers_accepted") or []) if c]
    rsa_kx = facts.get("rsa_kx_accepted") is True
    expired = isinstance(days, int) and days < 0
    expiring = isinstance(days, int) and 0 <= days < 14
    cert_invalid = bool(facts.get("tls")) and (not facts.get("certificate_verified") or expired)
    forward_secrecy = _forward_secret(facts)

    reasons: List[str] = []
    weaknesses: List[str] = []
    if legacy:
        weaknesses.append("TLS 1.0/1.1 is still enabled")
    if weak:
        weaknesses.append("weak TLS 1.2 ciphers are accepted (" + ", ".join(weak) + ")")
    if rsa_kx:
        weaknesses.append("RSA key transport is accepted as a fallback (" + str(facts.get("rsa_kx_cipher") or "kRSA")
                          + "), so clients that use it get no forward secrecy")
    if expiring:
        weaknesses.append(f"the certificate expires in {days} days")

    if not facts.get("tls"):
        grade, cause = "F", "no_tls"
        reasons.append(f"No TLS handshake completed on port {PORT}.")
    elif cert_invalid:
        grade, cause = "F", "invalid_certificate"
        reasons.append("The certificate is expired." if expired else
                       "The certificate does not verify: " + str(facts.get("verify_error") or "unknown reason") + ".")
    elif not forward_secrecy:
        grade, cause = "F", "no_forward_secrecy"
        reasons.append("A modern client was given a key exchange without forward secrecy ("
                       + str(facts.get("negotiated_cipher") or "unknown suite") + ").")
    elif post_quantum:
        grade, cause = ("B", "pq_with_weakness") if weaknesses else ("A", "pq")
        reasons.append(f"Post-quantum key exchange negotiated: {group}.")
        reasons.extend(w[0].upper() + w[1:] + "." for w in weaknesses)
    elif (legacy and not versions["1.3"]) or weak:
        grade, cause = "E", "legacy"
        if legacy and not versions["1.3"]:
            reasons.append("TLS 1.0/1.1 is enabled and TLS 1.3 is not.")
        if weak:
            reasons.append("Weak ciphers are accepted: " + ", ".join(weak) + ".")
    elif versions["1.3"]:
        grade, cause = "C", "classical_tls13"
        reasons.append("TLS 1.3 with classical key exchange only" + (f" ({group})." if group else "."))
    else:
        grade, cause = "D", "classical_tls12"
        reasons.append("TLS 1.2 at most, forward-secret classical key exchange.")
    if grade in ("C", "D") and legacy:
        reasons.append("TLS 1.0/1.1 is still enabled.")
    if grade in ("C", "D", "E") and rsa_kx:
        reasons.append("RSA key transport is accepted as a fallback (no forward secrecy for clients that use it).")
    if expiring and grade not in ("A", "B"):
        reasons.append(f"The certificate expires in {days} days.")
    if not facts.get("kx_observed") and facts.get("tls"):
        reasons.append("The key-exchange group could not be observed"
                       + (": " + str(facts.get("kx_reason")) if facts.get("kx_reason") else "") + ".")

    at_risk = not post_quantum
    if not facts.get("tls"):
        exposure = {"recorded_traffic_at_risk": True, "decrypt_year_low": None, "decrypt_year_high": None,
                    "basis": "No TLS was negotiated, so there is no encryption to break.",
                    "source_url": EXPOSURE_SOURCE_URL}
    elif at_risk:
        exposure = {"recorded_traffic_at_risk": True, "decrypt_year_low": DECRYPT_YEAR_LOW,
                    "decrypt_year_high": DECRYPT_YEAR_HIGH, "basis": EXPOSURE_BASIS,
                    "source_url": EXPOSURE_SOURCE_URL}
    else:
        exposure = {"recorded_traffic_at_risk": False, "decrypt_year_low": None, "decrypt_year_high": None,
                    "basis": PQ_BASIS, "source_url": PQ_SOURCE_URL}

    server_software = facts.get("server_header") or None
    platform = str(facts.get("platform") or detect_platform(server_software))
    needs = {
        "pq": not post_quantum and bool(facts.get("tls")),
        "protocols": legacy,
        "ciphers": rsa_kx or bool(weak),
        "certificate": cert_invalid or expiring,
    }
    ctx = {
        "domain": domain, "grade": grade, "cause": cause, "group": group, "hybrid": hybrid,
        "post_quantum": post_quantum, "versions": versions, "weaknesses": weaknesses,
        "forward_secrecy": forward_secrecy, "cert": cert, "exposure": exposure,
        "pq_accepted": list(facts.get("pq_groups_accepted") or []), "kx_observed": bool(facts.get("kx_observed")),
    }
    summaries = _summaries(ctx)
    return {
        "grade": grade,
        "summary": summaries.pop("summary"),
        "summaries": summaries,
        "tls": {"versions": versions, "negotiated": str(facts.get("negotiated_version") or ""),
                "untested": list(facts.get("tls_untested") or [])},
        "key_exchange": {"group": group, "post_quantum": post_quantum, "hybrid": hybrid,
                         "offered_pq_groups_accepted": list(facts.get("pq_groups_accepted") or []),
                         "observed": bool(facts.get("kx_observed"))},
        "certificate": {
            "key_type": str(cert.get("key_type") or ""),
            "key_bits": cert.get("key_bits") if isinstance(cert.get("key_bits"), int) else None,
            "signature_algorithm": str(cert.get("signature_algorithm") or ""),
            "not_after": cert.get("not_after") or None,
            "issuer": str(cert.get("issuer") or ""),
            "verified": bool(facts.get("certificate_verified")),
        },
        "forward_secrecy": forward_secrecy,
        "exposure": exposure,
        "server_software": server_software,
        "platform": platform,
        "fixes": [] if grade == "A" else fixes_for(platform, needs),
        "reasons": reasons,
        "rubric_version": RUBRIC_VERSION,
    }


def _summaries(c: Dict[str, Any]) -> Dict[str, str]:
    d, grade, group = c["domain"], c["grade"], c["group"] or "a classical group"
    years = f"{DECRYPT_YEAR_LOW}-{DECRYPT_YEAR_HIGH}"
    items = list(c["weaknesses"])
    if len(items) <= 2:
        weak = " and ".join(items)
    else:
        weak = "; ".join(items[:-1]) + "; and " + items[-1]
    sig_note = ("The certificate signature is classical and is not penalised: browsers cannot use ML-DSA "
                "certificates yet, and a signature only has to resist forgery while the connection is live, "
                "so it does not expose recorded traffic.")
    if grade == "A":
        summary = f"{d} protects new connections against future quantum decryption."
        executive = (f"{d} already uses post-quantum encryption for new connections, so traffic recorded "
                     "today cannot be decrypted later by a quantum computer. Nothing to do.")
        engineer = (f"Negotiates {group} (hybrid post-quantum) under TLS 1.3 when offered alongside classical "
                    "groups; TLS 1.0/1.1 disabled; forward secrecy throughout.")
        crypto = (f"Server selected {group}, a hybrid of ML-KEM (FIPS 203) and an elliptic-curve DH, from a "
                  "ClientHello offering hybrid and classical groups; confidentiality holds if either component "
                  "holds. Accepted hybrids: " + (", ".join(c["pq_accepted"]) or group) + ". " + sig_note)
    elif grade == "B":
        summary = f"{d} uses post-quantum key exchange, but {weak}."
        executive = (f"{d} already uses post-quantum encryption, so recorded traffic is protected, but a "
                     f"housekeeping issue remains: {weak}.")
        engineer = f"Negotiates {group} under TLS 1.3, but: {weak}. See the fixes."
        crypto = (f"Key exchange {group} includes ML-KEM (FIPS 203), so harvest-now-decrypt-later does not apply "
                  f"to new sessions; remaining issues are classical hygiene ({weak}). " + sig_note)
    elif grade in ("C", "D"):
        tls = "TLS 1.3" if grade == "C" else "TLS 1.2 at most"
        summary = (f"{d} uses forward-secret {tls}, but traffic recorded today could be decrypted by a "
                   "future quantum computer.")
        executive = (f"{d} is secure against today's attackers, but someone recording its traffic now could "
                     f"decrypt it once a large quantum computer exists, which experts expect around {years}. "
                     "The fix is a configuration change on the web server or CDN.")
        engineer = (f"{tls} with {group} key exchange; no post-quantum group accepted. Enable X25519MLKEM768 "
                    + ("(and TLS 1.3) " if grade == "D" else "")
                    + "on the TLS terminator; see the fixes for the exact config.")
        crypto = (f"Server chose {group} even though X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 "
                  "were offered; the session key rests on (EC)DH alone, which Shor's algorithm breaks, so a "
                  f"recorded handshake is decryptable by a CRQC (GRI 2025 survey: likely by {years}). "
                  "Forward secrecy limits exposure to recorded sessions, not to a quantum adversary. " + sig_note)
    elif grade == "E":
        summary = f"{d} still allows legacy TLS settings and has no post-quantum key exchange."
        executive = (f"{d} accepts outdated encryption settings and does not use post-quantum encryption; "
                     f"recorded traffic could be decrypted around {years} or sooner by classical attacks on "
                     "the legacy settings.")
        engineer = ("Legacy configuration: " + ("TLS 1.0/1.1 enabled without TLS 1.3. " if c["versions"]["1.0"]
                    or c["versions"]["1.1"] else "") + (weak + ". " if weak else "")
                    + "Disable legacy protocols and suites, enable TLS 1.3 and X25519MLKEM768.")
        crypto = (f"Classical key exchange ({group}) plus legacy protocol/suite acceptance; vulnerable to "
                  "downgrade-era weaknesses today and to harvest-now-decrypt-later by a CRQC. " + sig_note)
    else:
        cause = c["cause"]
        if cause == "no_tls":
            summary = f"{d} does not offer TLS on port 443."
            executive = f"{d} does not offer an encrypted connection on the standard HTTPS port."
            engineer = "No TLS handshake completed on 443 with any protocol version this checker offers."
            crypto = "No TLS session could be established, so there is no key exchange to evaluate."
        elif cause == "invalid_certificate":
            summary = f"{d} presents an invalid or expired certificate."
            executive = (f"Browsers will warn visitors to {d}: its certificate is invalid or expired, so "
                         "connections can be intercepted.")
            engineer = "The certificate fails verification against the public trust store; renew or fix the chain."
            crypto = ("Server authentication fails, so an active attacker can impersonate the endpoint; key "
                      "exchange strength is moot until authentication is restored.")
        else:
            summary = f"{d} accepts encryption without forward secrecy."
            executive = (f"{d} accepts an old form of encryption where one stolen server key unlocks every "
                         "recorded conversation, and a quantum computer could recover that key.")
            engineer = ("RSA key transport (static RSA) suites are accepted; disable them and allow only ECDHE "
                        "suites, then enable TLS 1.3 and X25519MLKEM768.")
            crypto = ("Static RSA key transport: the premaster secret is encrypted to the certificate's RSA key, "
                      "so compromise of that key (classically, or by Shor's algorithm on a CRQC) decrypts all "
                      "recorded sessions retroactively.")
    if not c["kx_observed"] and grade not in ("F",):
        crypto += " Note: the server's key-exchange choice could not be read directly, so it is treated as classical."
    return {"summary": summary, "executive": executive, "engineer": engineer, "cryptographer": crypto}


# ── Fixes ────────────────────────────────────────────────────────────────────

_MODERN_TLS12_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")


def _fix_nginx(needs: Dict[str, bool]) -> Dict[str, str]:
    lines = ["# in the server { } (or http { }) block that terminates TLS"]
    lines.append("ssl_protocols TLSv1.2 TLSv1.3;")
    if needs["pq"]:
        lines.append("ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;")
    if needs["ciphers"]:
        lines.append(f"ssl_ciphers {_MODERN_TLS12_CIPHERS};")
    return {
        "id": "nginx-pq-tls", "title": "nginx: enable X25519MLKEM768 and disable old TLS",
        "applies_to": "nginx", "snippet": "\n".join(lines),
        "notes": ("Check with `nginx -t`, then reload. ssl_ecdh_curve hands the list to OpenSSL; on OpenSSL 3.5 "
                  "the default (`auto`) already includes X25519MLKEM768, so an explicit list without it is the "
                  "usual cause. With OpenSSL older than 3.5 the group name is rejected and nginx will not start: "
                  "check `nginx -V` first. TLSv1.2 TLSv1.3 is nginx's own default since 1.23.4."),
        "requires": "nginx built against OpenSSL 3.5+ (see `nginx -V`)",
    }


def _fix_apache(needs: Dict[str, bool]) -> Dict[str, str]:
    lines = ["# in the <VirtualHost *:443> or global mod_ssl config", "SSLProtocol -all +TLSv1.2 +TLSv1.3"]
    if needs["pq"]:
        lines.append("SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp256r1:secp384r1")
    if needs["ciphers"]:
        lines.append("SSLCipherSuite " + _MODERN_TLS12_CIPHERS)
    return {
        "id": "apache-pq-tls", "title": "Apache httpd: enable X25519MLKEM768 and disable old TLS",
        "applies_to": "Apache httpd", "snippet": "\n".join(lines),
        "notes": ("Check with `apachectl configtest`, then reload. SSLOpenSSLConfCmd passes `Groups` straight to "
                  "OpenSSL's SSL_CONF interface (mod_ssl 2.4.8+); OpenSSL older than 3.5 rejects the group name."),
        "requires": "Apache httpd 2.4.8+ with mod_ssl linked against OpenSSL 3.5+",
    }


def _fix_caddy(needs: Dict[str, bool]) -> Dict[str, str]:
    return {
        "id": "caddy-pq-tls", "title": "Caddy: use the defaults, which include X25519MLKEM768",
        "applies_to": "Caddy", "snippet": ("example.com {\n\ttls {\n\t\tprotocols tls1.2 tls1.3\n"
                                           "\t\tcurves x25519mlkem768 x25519 secp256r1\n\t}\n}"),
        "notes": ("Caddy 2.10+ (Go 1.24+) offers x25519mlkem768 by default and its docs recommend not changing the "
                  "defaults: the simplest fix is to upgrade Caddy and delete any `curves` or `protocols` override. "
                  "The block above is the explicit form. Caddy never enables TLS 1.0/1.1."),
        "requires": "Caddy 2.10+",
    }


def _fix_haproxy(needs: Dict[str, bool]) -> Dict[str, str]:
    lines = ["global", "    ssl-default-bind-options ssl-min-ver TLSv1.2"]
    if needs["pq"]:
        lines.append("    ssl-default-bind-curves X25519MLKEM768:X25519:P-256:P-384")
    if needs["ciphers"]:
        lines.append("    ssl-default-bind-ciphers " + _MODERN_TLS12_CIPHERS)
    return {
        "id": "haproxy-pq-tls", "title": "HAProxy: enable X25519MLKEM768 and disable old TLS",
        "applies_to": "HAProxy", "snippet": "\n".join(lines),
        "notes": ("Check with `haproxy -c -f /etc/haproxy/haproxy.cfg`, then reload. The curve list is passed to the "
                  "TLS library, so the binary must be linked against one that implements ML-KEM; `haproxy -vv` "
                  "shows which. Per-listener, the same settings are the `ssl-min-ver` and `curves` bind options."),
        "requires": "HAProxy linked against OpenSSL 3.5+ or AWS-LC (see `haproxy -vv`)",
    }


def _fix_iis(needs: Dict[str, bool]) -> Dict[str, str]:
    base = r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    lines = ["# Elevated PowerShell on the server"]
    if needs["pq"]:
        lines.append('Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0')
    for version in ("TLS 1.0", "TLS 1.1"):
        lines.append(f"New-Item '{base}\\{version}\\Server' -Force | Out-Null")
        lines.append(f"New-ItemProperty '{base}\\{version}\\Server' -Name Enabled -Value 0 -PropertyType DWord -Force")
        lines.append(f"New-ItemProperty '{base}\\{version}\\Server' -Name DisabledByDefault -Value 1 -PropertyType DWord -Force")
    lines.append("Restart-Computer")
    return {
        "id": "iis-pq-tls", "title": "IIS / Windows Server: enable hybrid ML-KEM in Schannel and disable old TLS",
        "applies_to": "IIS (Schannel)", "snippet": "\n".join(lines),
        "notes": ("Hybrid ML-KEM is off by default in Schannel. Microsoft's Windows TLS 1.3 and PQC FAQ gives the "
                  "Enable-TlsEccCurve command; -Position 0 matters, or the classical group may still be chosen. "
                  "A Group Policy 'ECC Curve Order' overrides it. Windows Server 2022 and earlier have no ML-KEM "
                  "in Schannel: there the only route is a TLS-terminating proxy or CDN in front of IIS."),
        "requires": "Windows Server 2025 with the July 2026 update (KB5099536) or later",
    }


def _fix_cloudflare(needs: Dict[str, bool]) -> Dict[str, str]:
    return {
        "id": "cloudflare-edge-tls", "title": "Cloudflare: set the minimum TLS version at the edge",
        "applies_to": "Cloudflare",
        "snippet": ("# Dashboard: SSL/TLS -> Edge Certificates -> Minimum TLS Version -> TLS 1.2\n"
                    "curl -X PATCH \"https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/min_tls_version\" \\\n"
                    "  -H \"Authorization: Bearer $CF_API_TOKEN\" -H \"Content-Type: application/json\" \\\n"
                    "  --data '{\"value\":\"1.2\"}'"),
        "notes": ("Cloudflare terminates TLS for visitors and negotiates X25519MLKEM768 at its edge; there is no "
                  "origin setting for that leg. If this check still sees a classical group, the hostname may be "
                  "DNS-only (grey cloud) or served by a different provider. The Cloudflare-to-origin leg is graded "
                  "nowhere here: enable X25519MLKEM768 on the origin too (see the server fixes)."),
        "requires": "Cloudflare proxy (orange cloud) enabled for the hostname",
    }


def _fix_cdn(needs: Dict[str, bool]) -> Dict[str, str]:
    return {
        "id": "cdn-edge-tls", "title": "CDN: post-quantum key exchange is a setting of the CDN, not your origin",
        "applies_to": "CDN-fronted (Akamai, Fastly, CloudFront, Google and others)",
        "snippet": "# No origin configuration changes the visitor-facing handshake.\n"
                   "# In the CDN's TLS settings / security policy: minimum TLS 1.2, and enable X25519MLKEM768.",
        "notes": ("The visitor's TLS connection ends at the CDN edge, so it decides the key exchange. Whether "
                  "hybrid ML-KEM can be switched on, and where, differs by provider and plan: check its current TLS "
                  "documentation or ask support. This check cannot see the CDN-to-origin leg."),
        "requires": "a CDN plan that offers X25519MLKEM768 at the edge",
    }


_FIXERS = {
    "nginx": _fix_nginx, "apache": _fix_apache, "caddy": _fix_caddy, "haproxy": _fix_haproxy,
    "iis": _fix_iis, "cloudflare": _fix_cloudflare, "cdn": _fix_cdn,
}


def fixes_for(platform: str, needs: Dict[str, bool]) -> List[Dict[str, str]]:
    """Config changes for the detected platform; every server's fix when it is unknown."""
    if not any(needs.values()):
        return []
    out: List[Dict[str, str]] = []
    if needs.get("pq") or needs.get("protocols") or needs.get("ciphers"):
        if platform in _FIXERS:
            out.append(_FIXERS[platform](needs))
        else:
            for name in ("nginx", "apache", "caddy", "haproxy", "iis"):
                out.append(_FIXERS[name](needs))
    if needs.get("certificate"):
        out.append({
            "id": "certificate-renew", "title": "Renew or fix the certificate",
            "applies_to": "any", "snippet": "certbot renew   # or your CA's / platform's renewal process",
            "notes": "Serve the full chain (leaf plus intermediates) for the exact hostname, and automate renewal.",
            "requires": "control of the certificate for this hostname",
        })
    return out


# ── The result document, text and badge ─────────────────────────────────────


def build_result(facts: Dict[str, Any], scanned_at: str, cached: bool = False) -> Dict[str, Any]:
    graded = grade_from_facts(facts)
    out: Dict[str, Any] = {"domain": facts.get("domain"), "scanned_at": scanned_at, "cached": bool(cached)}
    out.update(graded)
    out["connections"] = int(facts.get("connections") or 0)
    out["notes"] = list(facts.get("notes") or [])
    return out


def render_text(result: Dict[str, Any]) -> str:
    """The result for a terminal: about fifteen plain lines, no colour codes."""
    def yn(value: Any) -> str:
        return "yes" if value else "no"

    tls = result.get("tls") or {}
    versions = tls.get("versions") or {}
    kx = result.get("key_exchange") or {}
    cert = result.get("certificate") or {}
    exp = result.get("exposure") or {}
    lines = [
        f"{result.get('domain')}  grade {result.get('grade')}",
        str(result.get("summary") or ""),
        "",
        "TLS versions     " + "  ".join(f"{v} {yn(versions.get(v))}" for v in ("1.3", "1.2", "1.1", "1.0"))
        + f"  (negotiated {tls.get('negotiated') or '-'})",
        f"Key exchange     {kx.get('group') or 'not observed'}  post-quantum: {yn(kx.get('post_quantum'))}"
        f"  hybrid: {yn(kx.get('hybrid'))}",
        "PQ groups        " + (", ".join(kx.get("offered_pq_groups_accepted") or []) or "none accepted"),
        f"Forward secrecy  {yn(result.get('forward_secrecy'))}",
        f"Certificate      {cert.get('key_type') or '-'} {cert.get('key_bits') or ''}".rstrip()
        + f", {cert.get('signature_algorithm') or '-'}, expires {(cert.get('not_after') or '-')[:10]}",
        f"Issuer           {cert.get('issuer') or '-'}"[:100],
    ]
    if exp.get("recorded_traffic_at_risk") and exp.get("decrypt_year_low"):
        lines.append(f"Recorded traffic at risk: yes, decryptable from about "
                     f"{exp.get('decrypt_year_low')}-{exp.get('decrypt_year_high')}")
        lines.append(f"  source: {exp.get('source_url')}")
    else:
        lines.append(f"Recorded traffic at risk: {yn(exp.get('recorded_traffic_at_risk'))}")
    lines.append(f"Server           {result.get('server_software') or 'not disclosed'}")
    fixes = result.get("fixes") or []
    if fixes:
        first = fixes[0]
        more = f" (+{len(fixes) - 1} more in the JSON)" if len(fixes) > 1 else ""
        lines.append(f"Fix              {first.get('title')}{more}")
        lines.append(f"  requires: {first.get('requires')}")
    lines.append(f"Checked {result.get('scanned_at')}{' (cached)' if result.get('cached') else ''}"
                 f", rubric {result.get('rubric_version')}")
    return "\n".join(lines) + "\n"


_BADGE_COLORS = {
    "A": ("#2e7d32", "#fff"), "B": ("#558b2f", "#fff"), "C": ("#f9a825", "#1a1a1a"),
    "D": ("#ef6c00", "#fff"), "E": ("#d84315", "#fff"), "F": ("#c62828", "#fff"),
}


def badge_svg(grade: Optional[str]) -> str:
    """A shields-style badge. The grade is in the text as well as the colour."""
    label = "quantum-ready"
    value = grade if grade in _BADGE_COLORS else "?"
    color, ink = _BADGE_COLORS.get(value, ("#9e9e9e", "#fff"))
    lw, vw = 96, 24
    width = lw + vw
    title = f"{label}: grade {value}" if value != "?" else f"{label}: not graded yet"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{title}">'
        f"<title>{title}</title>"
        '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect width="{width}" height="20" fill="url(#s)"/></g>'
        '<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{label}</text>'
        f'<text x="{lw / 2:.0f}" y="14" fill="#fff">{label}</text>'
        f'<text x="{lw + vw / 2:.0f}" y="14" fill="{ink}" font-weight="bold">{value}</text>'
        "</g></svg>"
    )


# ── Storage: public_grade_checks (feature store, like public_check_*) ────────


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def init_tables() -> None:
    """Create public_grade_checks. No organization column: nothing here belongs to a tenant."""
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        from db_feature_store import feature_conn

        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS public_grade_checks (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain             TEXT NOT NULL,
                    scanned_at         TEXT NOT NULL,
                    grade              TEXT NOT NULL,
                    key_exchange_group TEXT NOT NULL DEFAULT '',
                    post_quantum       INTEGER NOT NULL DEFAULT 0,
                    rubric_version     TEXT NOT NULL DEFAULT '',
                    result_json        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_public_grade_checks_domain
                    ON public_grade_checks (domain, scanned_at);
                CREATE INDEX IF NOT EXISTS idx_public_grade_checks_scanned
                    ON public_grade_checks (scanned_at);
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def store(result: Dict[str, Any]) -> None:
    from db_feature_store import feature_conn

    init_tables()
    kx = result.get("key_exchange") or {}
    stored = dict(result)
    stored.pop("cached", None)
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO public_grade_checks (domain, scanned_at, grade, key_exchange_group, post_quantum, "
            "rubric_version, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(result.get("domain")), str(result.get("scanned_at")), str(result.get("grade")),
             str(kx.get("group") or ""), 1 if kx.get("post_quantum") else 0, RUBRIC_VERSION,
             json.dumps(stored, separators=(",", ":"), sort_keys=True)))
        conn.commit()


def latest(domain: str, max_age_seconds: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """The newest stored result for domain under the current rubric, if young enough."""
    from db_feature_store import feature_conn

    init_tables()
    sql = ("SELECT scanned_at, result_json FROM public_grade_checks WHERE domain = ? AND rubric_version = ?")
    params: List[Any] = [domain, RUBRIC_VERSION]
    if max_age_seconds is not None:
        sql += " AND scanned_at >= ?"
        params.append(iso(now_utc() - timedelta(seconds=int(max_age_seconds))))
    sql += " ORDER BY scanned_at DESC, id DESC LIMIT 1"
    with feature_conn() as conn:
        row = conn.execute(sql, tuple(params)).fetchone()
    if not row:
        return None
    try:
        result = json.loads(row["result_json"])
    except (TypeError, ValueError):
        return None
    result["cached"] = True
    return result


def history(domain: str, limit: int = 30) -> List[Dict[str, Any]]:
    from db_feature_store import feature_conn

    init_tables()
    limit = max(1, min(100, int(limit)))
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT scanned_at, grade, key_exchange_group, post_quantum FROM public_grade_checks "
            "WHERE domain = ? ORDER BY scanned_at DESC, id DESC LIMIT ?", (domain, limit)).fetchall()
    return [{"scanned_at": r["scanned_at"], "grade": r["grade"], "group": r["key_exchange_group"],
             "post_quantum": bool(r["post_quantum"])} for r in rows]


def stats() -> Dict[str, Any]:
    """Aggregate counts only. Nothing here names a domain, a requester or an organisation."""
    from db_feature_store import feature_conn

    init_tables()
    since = iso(now_utc() - timedelta(days=7))
    with feature_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM public_grade_checks").fetchone()["n"]
        week = conn.execute("SELECT COUNT(*) AS n, SUM(post_quantum) AS pq FROM public_grade_checks "
                            "WHERE scanned_at >= ?", (since,)).fetchone()
        domains = conn.execute("SELECT COUNT(DISTINCT domain) AS n FROM public_grade_checks").fetchone()["n"]
        grades = conn.execute("SELECT grade, COUNT(*) AS n FROM public_grade_checks WHERE scanned_at >= ? "
                              "GROUP BY grade", (since,)).fetchall()
    week_n = int(week["n"] or 0)
    return {
        "public_checks_total": int(total or 0),
        "public_checks_7d": week_n,
        "domains_checked": int(domains or 0),
        "pq_share_7d": round(float(week["pq"] or 0) / week_n, 4) if week_n else 0.0,
        "grades_7d": {g: 0 for g in GRADES} | {str(r["grade"]): int(r["n"]) for r in grades if r["grade"] in GRADES},
        "rubric_version": RUBRIC_VERSION,
        "generated_at": iso(now_utc()),
    }


# ── The guarded check, as the API runs it ────────────────────────────────────


def _limit(kind: str, key: str, limit: int, window: float, detail: str) -> None:
    from services import org_rate_limits

    hit = org_rate_limits.hit(kind, key, limit, window)
    if not hit.get("allowed"):
        raise GradeError(429, "rate_limited", detail, retry_after=float(hit.get("retry_after") or window))


def _semaphore() -> threading.Semaphore:
    want = concurrency()
    with _slots_lock:
        if _slots["size"] != want:
            _slots["sem"] = threading.Semaphore(want)
            _slots["size"] = want
        return _slots["sem"]


def _domain_lock(domain: str) -> threading.Lock:
    with _inflight_lock:
        if len(_inflight) > 1024:
            for key in [k for k, v in _inflight.items() if not v.locked()]:
                _inflight.pop(key, None)
        return _inflight.setdefault(domain, threading.Lock())


def charge_request(client_ip: str, fresh: bool = False) -> str:
    """Spend the per-IP budget for one grade request. Returns the salted IP hash."""
    from services import public_check

    ip_hash = public_check.hash_ip(client_ip)
    _limit("public_grade_ip", ip_hash, ip_per_minute(), 60.0,
           f"More than {ip_per_minute()} grade requests a minute from your address. Wait a moment.")
    if fresh:
        _limit("public_grade_fresh_ip", ip_hash, fresh_per_minute(), 60.0,
               f"More than {fresh_per_minute()} fresh re-checks a minute from your address. The cached "
               "result is at most an hour old.")
    return ip_hash


def check(domain: Any, client_ip: str = "", fresh: bool = False, charge: bool = True,
          cache_only: bool = False) -> Dict[str, Any]:
    """Validate, rate limit, serve the cache or run one guarded probe, store and return the result.

    ``charge`` False skips the per-IP budget (the caller already charged it, e.g. the badge route).
    ``cache_only`` returns None-equivalent by raising 404 instead of probing.
    """
    from services import public_check

    if not enabled():
        raise GradeError(503, "disabled", "The public grade is switched off on this server.")
    host = normalize(domain)
    covered = public_check.opted_out(host)
    if covered:
        raise GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
    ip_hash = charge_request(client_ip, fresh) if charge else public_check.hash_ip(client_ip)

    if not fresh:
        cached = latest(host, cache_seconds())
        if cached is not None:
            return cached
    if cache_only:
        raise GradeError(404, "not_checked", f"{host} has not been graded recently.")

    with _domain_lock(host):
        if not fresh:
            cached = latest(host, cache_seconds())
            if cached is not None:
                return cached
        if fresh:
            _limit("public_grade_fresh_domain", host, max(1, domain_per_hour() // 2), 3600.0,
                   f"{host} has been re-checked too often this hour. The cached result is the same answer.")
        _limit("public_grade_domain", host, domain_per_hour(), 3600.0,
               f"{host} has been checked {domain_per_hour()} times this hour; try again later.")
        _limit("public_grade_global", "all", global_per_hour(), 3600.0,
               "The public grade is at its hourly limit for everyone. Try again shortly.")
        sem = _semaphore()
        if not sem.acquire(timeout=3.0):
            raise GradeError(429, "busy", "Too many checks are running right now. Try again in a moment.",
                             retry_after=10.0)
        started = time.monotonic()
        try:
            try:
                address = resolve_pinned(host)
            except GradeError as exc:
                public_check.log_check(host, ip_hash, "grade_" + exc.error, exc.detail)
                raise
            facts = probe(host, address)
        finally:
            sem.release()
        duration = int((time.monotonic() - started) * 1000)
        if not facts.get("reachable"):
            public_check.log_check(host, ip_hash, "grade_unreachable", str(facts.get("error") or ""), duration)
            raise GradeError(504, "unreachable",
                             f"{host} did not accept a connection on port {PORT} in time.")
        result = build_result(facts, iso(now_utc()), cached=False)
        public_check.log_check(host, ip_hash, "grade_ok", "grade " + str(result.get("grade")), duration)
        try:
            store(result)
        except Exception:
            logger.warning("public grade: could not store the result for %s", host)
        return result


# ── Command line ─────────────────────────────────────────────────────────────


def _env_optouts() -> set:
    out = set()
    for item in re.split(r"[,;\s]+", str(os.getenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "") or "")):
        cleaned = item.strip().lower().rstrip(".")
        if cleaned:
            out.add(cleaned)
    return out


def grade_one(domain: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Validate, guard, probe and grade one domain with no database. Never raises."""
    started = iso(now_utc())
    try:
        host = normalize(domain)
    except GradeError as exc:
        return {"domain": str(domain), "scanned_at": started, **exc.as_dict()}
    try:
        labels = host.split(".")
        optouts = _env_optouts()
        if any(".".join(labels[i:]) in optouts for i in range(len(labels) - 1)):
            raise GradeError(403, "refused_optout", f"{host} has asked not to be checked.")
        address = resolve_pinned(host)
        facts = probe(host, address, timeout=timeout, deadline=max(10.0, timeout * 4))
        if not facts.get("reachable"):
            raise GradeError(504, "unreachable", f"{host} did not accept a connection on port {PORT}.")
        return build_result(facts, iso(now_utc()), cached=False)
    except GradeError as exc:
        return {"domain": host, "scanned_at": started, **exc.as_dict()}
    except Exception as exc:  # one bad domain must never stop a batch
        return {"domain": host, "scanned_at": started, "error": "internal_error",
                "detail": f"{type(exc).__name__}: {exc}"[:300]}


def _read_domains(path: str) -> List[str]:
    out: List[str] = []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            if "," in text:
                text = text.rsplit(",", 1)[-1].strip()
            key = text.lower().rstrip(".")
            if key and key not in seen:
                seen.add(key)
                out.append(text)
    return out


def _done_domains(path: str) -> set:
    done = set()
    if not os.path.exists(path):
        return done
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                done.add(str(json.loads(line).get("domain") or "").lower())
            except (ValueError, AttributeError):
                continue
    return done


def run_batch(domains_path: str, out_path: str, concurrency_n: int = 32, timeout: float = 8.0) -> Dict[str, int]:
    domains = _read_domains(domains_path)
    done = _done_domains(out_path)
    todo = [d for d in domains if d.lower().rstrip(".") not in done]
    counts = {"total": len(domains), "skipped": len(domains) - len(todo), "ok": 0, "error": 0}
    lock = threading.Lock()
    with open(out_path, "a", encoding="utf-8") as out:
        def work(name: str) -> None:
            result = grade_one(name, timeout=timeout)
            line = json.dumps(result, separators=(",", ":"), sort_keys=True)
            with lock:
                out.write(line + "\n")
                out.flush()
                counts["error" if "error" in result else "ok"] += 1

        with ThreadPoolExecutor(max_workers=max(1, min(256, int(concurrency_n)))) as pool:
            for _ in pool.map(work, todo):
                pass
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m services.public_grade",
                                     description="Grade public HTTPS endpoints for quantum readiness (A-F).")
    parser.add_argument("domain", nargs="?", help="grade one domain and print the text form")
    parser.add_argument("--batch", help="file with one domain per line (or rank,domain CSV)")
    parser.add_argument("--out", help="JSONL output; existing domains in it are skipped (resumable)")
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=8.0, help="per-connection timeout, seconds")
    parser.add_argument("--json", action="store_true", help="with a single domain, print JSON instead of text")
    args = parser.parse_args(argv)
    if args.batch:
        if not args.out:
            parser.error("--batch needs --out")
        counts = run_batch(args.batch, args.out, args.concurrency, args.timeout)
        sys.stderr.write(f"graded {counts['ok']}, failed {counts['error']}, skipped {counts['skipped']} "
                         f"(already in {args.out}), of {counts['total']}\n")
        return 0
    if not args.domain:
        parser.error("give a domain, or --batch FILE --out FILE")
    result = grade_one(args.domain, timeout=args.timeout)
    if args.json or "error" in result:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_text(result))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
