"""Pre-flight: does a post-quantum ClientHello get through the network path to a host?

Why this exists
---------------
Offering the hybrid key exchange X25519MLKEM768 makes a TLS ClientHello about 1.2 KB larger: the
client's key share is 1,216 bytes instead of X25519's 32. A browser-sized hello then no longer fits
in one TCP segment (about 1,460 bytes of payload on an ordinary 1,500-byte Ethernet path), so it
arrives in two. TCP has always allowed that, but some firewalls, load balancers, TLS-inspecting
proxies and server TLS stacks read only the first segment, or one ``read()``, and then fail. The
client sees a timeout or a reset; nothing in the server's own logs says why.

Sources (read 2026-11-19; the wording on the page and in the API cites the same list, ``SOURCES``):
  * Chromium blog, "Protecting Chrome Traffic with Hybrid Kyber KEM" (2023-08-10): the hybrid share
    "adds over a kilobyte of extra data to the TLS ClientHello"; "in certain limited cases, TLS
    middleboxes failed due to improperly hardcoded restrictions on message size"; enterprises were
    given the PostQuantumKeyAgreementEnabled policy as a temporary measure and told to get the
    vendors to fix the bugs.
    https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html
  * tldr.fail (David Adrian, Bas Westerbaan and others): post-quantum ClientHellos "exceed the
    threshold for transmission in a single packet", and "most buggy servers are not prepared to
    have to call read() more than once"; the symptom is often ERR_CONNECTION_RESET; it lists the
    affected and patched products (Cisco, Palo Alto, Zscaler, Broadcom ProxySG, Envoy, Ingress Nginx
    in TLS passthrough, Apache Traffic Server, Vercel) and suggests the test this module runs:
    send half a ClientHello, pause, and see whether the server copes. https://tldr.fail/
  * Cloudflare blog, "Automatic Key Exchange" (2026-09-08): "An X25519MLKEM768 keyshare is 1,216
    bytes compared to X25519's 32 bytes", "pushing the ClientHello past a single network packet";
    "some legacy middleboxes and origin servers can fail when receiving ClientHello messages split
    across multiple packets"; about 0.34% of scanned origins failed with a post-quantum share first.
    https://blog.cloudflare.com/automatic-key-exchange-for-origins/
  * Cloudflare Radar changelog (2026-05-29): its post-quantum check reports a split ClientHello bug
    when "the connection fails with a fragmented post-quantum ClientHello but succeeds with classical
    handshakes", "typically caused by middleboxes or firewalls that cannot reassemble split TLS
    messages". https://developers.cloudflare.com/changelog/post/2026-05-29-radar-pq-tls-bug-detection/

What one pre-flight sends
-------------------------
From Morrow's server, to one pinned public address on port 443 (the signed-in variant: a port the
verified owner names), up to three ClientHellos, each on its own TCP connection, each closed as soon
as the ServerHello (or an alert, a reset or the timeout) arrives. No handshake is completed and no
HTTP request is made:

  (a) ``classical``: X25519, P-256 and P-384 offered, one X25519 key share. About 300 bytes, one segment.
  (b) ``pq``: X25519MLKEM768 first, then X25519, P-256, P-384, with X25519MLKEM768 and X25519 key
      shares, as Chrome and Firefox send today, padded (RFC 7685) to at least ``BROWSER_HELLO_BYTES``,
      the size a Chromium 140 ClientHello measured here (1,756 bytes). Sent in one write; the
      operating system splits it into segments.
  (c) ``pq_split``: the same hello written in two halves with ``SPLIT_PAUSE`` seconds between them
      and Nagle off, so the halves leave as separate segments and arrive in separate reads -- the
      tldr.fail test. A path that copes when both segments land together can still fail here, and
      real connections hit that case at random.

When the classical hello gets an answer and a post-quantum one does not, the failing hello and the
classical one are each sent once more, and the verdict is "path problem" only if the failure repeats.
So the most a pre-flight sends is six ClientHellos.

The ClientHellos are hand-built (scanner.py explains why Python's ``ssl`` cannot offer
X25519MLKEM768 here) and only the server's first record is parsed, with scanner.py's bounded,
checked parsers. The hello's ML-KEM-768 key is a real one when the ``cryptography`` build has
ML-KEM, otherwise a well-formed one (scanner._mlkem768_encapsulation_key); the probe never
decapsulates, so either is fine for a server that only has to answer.

Verdicts (``VERDICTS``)
-----------------------
  safe_to_turn_on   the post-quantum hellos got answers: nothing on this path blocks them
  path_problem      the classical hello got an answer and a post-quantum one failed, twice
  already_safe      the server chose X25519MLKEM768 (or asked for it with a HelloRetryRequest)
  couldnt_test      no TCP connection, or not even the classical hello got an answer

Limits, said on every answer (``measured``): an outside test covers the public path from Morrow's
server to the host's public address -- with a CDN in front, the path to its edge -- not the networks
inside a company, between a CDN and its origin, or from other places on the internet. The inside
test (tools/preflight/preflight.py, stdlib only) runs the same three hellos from inside a network.
Post-quantum (ML-DSA) certificates are not in the web PKI yet, so nothing here tests them.

The guard
---------
Exactly the public grade's (services/public_grade.py): the name is validated by
``public_grade.normalize``, the opt-out list is honoured, the name is resolved once and every answer
must pass ``public_grade.refusal_reason`` (private, loopback, link-local, CGNAT, reserved, wrapped
IPv6 and this server's own addresses are refused), and every connection goes to that one pinned
address with SNI set to the name. Budgets (services/org_rate_limits.py, Redis-backed when
configured): per client IP, one probe set per host per ``minutes()`` minutes whoever asks (inside
that window the stored answer is served), and a global hourly budget; a process-wide concurrency
cap. Each run is logged in the shared abuse log ``public_check_log`` with a salted IP hash.

Settings
--------
``MORROW_PREFLIGHT_ENABLED``          1    master switch
``MORROW_PREFLIGHT_MINUTES``          10   one probe set per host per this many minutes; the answer is reused
``MORROW_PREFLIGHT_IP_PER_MINUTE``    6    pre-flight requests per client IP per minute
``MORROW_PREFLIGHT_GLOBAL_PER_HOUR``  300  probe sets per hour, whole service
``MORROW_PREFLIGHT_ORG_PER_HOUR``     30   signed-in probe sets per organization per hour
``MORROW_PREFLIGHT_CONCURRENCY``      3    probe sets running at once in this process
``MORROW_PREFLIGHT_TIMEOUT``          6    seconds to wait for a ServerHello, per hello
"""

from __future__ import annotations

import json
import logging
import math
import os
import socket
import threading
import time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from services import public_grade as _grade

logger = logging.getLogger(__name__)

API_VERSION = "preflight/1"
PORT = 443

#: The size of a Chromium 140.0.7339.16 ClientHello offering X25519MLKEM768 (TLS record, header
#: included), captured on 2026-11-19 from a headless Chromium connecting to a local socket. It
#: carries GREASE, ALPN, an ECH GREASE extension and both key shares; the post-quantum hello here is
#: padded to at least this so it crosses the same segment boundary a browser's does.
BROWSER_HELLO_BYTES = 1756
#: TCP payload per segment assumed when the operating system will not say (1,500-byte MTU, IPv4,
#: no TCP options): the usual Ethernet path.
ASSUMED_MSS = 1460
#: Seconds between the two halves of the split hello: long enough that they arrive as separate reads.
SPLIT_PAUSE = 0.2

GROUP_X25519MLKEM768 = 0x11EC
GROUP_X25519 = 0x001D
CLASSICAL_GROUPS: Tuple[int, ...] = (0x001D, 0x0017, 0x0018)
PQ_GROUPS: Tuple[int, ...] = (GROUP_X25519MLKEM768, 0x001D, 0x0017, 0x0018)
#: TLS 1.3 suites, then ECDHE TLS 1.2 suites, so a TLS 1.2 server still answers.
_SUITES = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8)
_SIG_ALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807)

HANDSHAKES = (
    ("classical", "Classical hello", "X25519, P-256 and P-384, one X25519 key share"),
    ("pq", "Post-quantum hello", "X25519MLKEM768 first, then X25519, as browsers send it"),
    ("pq_split", "Post-quantum hello, in two parts",
     "the same hello sent as two separate TCP segments with a short pause"),
)

VERDICTS = ("safe_to_turn_on", "path_problem", "already_safe", "couldnt_test")

#: TLS alert descriptions (RFC 8446 section 6) worth naming in a sentence.
_ALERTS = {
    10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow", 40: "handshake_failure",
    47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    120: "no_application_protocol",
}

SOURCES: List[Dict[str, str]] = [
    {"name": "Chromium blog: Protecting Chrome Traffic with Hybrid Kyber KEM (2023-08-10)",
     "url": "https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html",
     "says": "The hybrid key share adds over a kilobyte to the ClientHello; some TLS middleboxes failed "
             "on hard-coded message-size limits, and the vendors were asked to fix them."},
    {"name": "tldr.fail", "url": "https://tldr.fail/",
     "says": "Post-quantum ClientHellos no longer fit in one packet; servers and middleboxes that read only "
             "once fail, often with a connection reset. Lists affected and patched products."},
    {"name": "Cloudflare blog: Automatic Key Exchange (2026-09-08)",
     "url": "https://blog.cloudflare.com/automatic-key-exchange-for-origins/",
     "says": "An X25519MLKEM768 key share is 1,216 bytes, against 32 for X25519; some middleboxes and "
             "origins fail on a ClientHello split across packets (about 0.34% of origins scanned)."},
    {"name": "Cloudflare Radar changelog: post-quantum TLS bug detection (2026-05-29)",
     "url": "https://developers.cloudflare.com/changelog/post/2026-05-29-radar-pq-tls-bug-detection/",
     "says": "Radar flags a split-ClientHello bug when a fragmented post-quantum hello fails and a "
             "classical one succeeds, typically a middlebox or firewall that cannot reassemble it."},
]

INSIDE_TEST = {
    "label": "Test from inside your network",
    "docs": "https://github.com/soqlab/Morrow/blob/main/tools/preflight/README.md",
    "script": "https://raw.githubusercontent.com/soqlab/Morrow/main/tools/preflight/preflight.py",
    "run": "python3 preflight.py intranet.example.internal:443",
    "what": "One Python file, standard library only. It sends the same three hellos from wherever you run "
            "it, so it can reach hosts inside your network that Morrow cannot.",
}

NOT_TESTED = [
    "Post-quantum (ML-DSA) certificates: they are not in the web PKI yet, so no browser can use them and "
    "nothing here tests them. They will make the server's answer larger too; that is future work.",
    "QUIC (HTTP/3): it never assumed a one-packet ClientHello, so this problem is much rarer there; only TCP is tested.",
]

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()
_slots_lock = threading.Lock()
_slots: Dict[str, Any] = {"size": 0, "sem": threading.Semaphore(1)}
_inflight_lock = threading.Lock()
_inflight: Dict[str, threading.Lock] = {}


# ── Settings ─────────────────────────────────────────────────────────────────


def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def enabled() -> bool:
    return str(os.getenv("MORROW_PREFLIGHT_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def minutes() -> int:
    return int(_num("MORROW_PREFLIGHT_MINUTES", 10, 1, 24 * 60))


def ip_per_minute() -> int:
    return int(_num("MORROW_PREFLIGHT_IP_PER_MINUTE", 6, 1, 10_000))


def global_per_hour() -> int:
    return int(_num("MORROW_PREFLIGHT_GLOBAL_PER_HOUR", 300, 1, 1_000_000))


def org_per_hour() -> int:
    return int(_num("MORROW_PREFLIGHT_ORG_PER_HOUR", 30, 1, 10_000))


def concurrency() -> int:
    return int(_num("MORROW_PREFLIGHT_CONCURRENCY", 3, 1, 32))


def hello_timeout() -> float:
    return _num("MORROW_PREFLIGHT_TIMEOUT", 6.0, 1.0, 30.0)


# ── The ClientHellos ─────────────────────────────────────────────────────────


def _x25519_public() -> bytes:
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import x25519 as _x25519

    return _x25519.X25519PrivateKey.generate().public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)


def build_hello(host: str, kind: str, target_bytes: int = BROWSER_HELLO_BYTES) -> bytes:
    """One TLS ClientHello record. ``kind`` "classical" or "pq" (the split hello is the "pq" bytes).

    Both carry the same extensions a browser sends (SNI, ALPN h2/http1.1, supported_versions 1.3
    and 1.2, signature algorithms, PSK modes, extended master secret, renegotiation_info); only the
    groups and key shares differ. The post-quantum hello is padded with the RFC 7685 padding
    extension to ``target_bytes`` when it is shorter.
    """
    import secrets

    import scanner

    u16, ext = scanner._u16, scanner._tls_extension
    groups = PQ_GROUPS if kind == "pq" else CLASSICAL_GROUPS
    exts = b""
    name = b""
    if host and not _is_ip(host):
        try:
            name = host.encode("idna")
        except Exception:
            name = host.encode("ascii", "ignore")
    if name:
        exts += ext(0x0000, u16(len(name) + 3) + b"\x00" + u16(len(name)) + name)   # server_name
    exts += ext(0x0017, b"")                                                          # extended_master_secret
    exts += ext(0xFF01, b"\x00")                                                      # renegotiation_info
    group_bytes = b"".join(u16(g) for g in groups)
    exts += ext(0x000A, u16(len(group_bytes)) + group_bytes)                          # supported_groups
    exts += ext(0x000B, b"\x01\x00")                                                  # ec_point_formats
    alpn = b"\x02h2\x08http/1.1"
    exts += ext(0x0010, u16(len(alpn)) + alpn)                                        # ALPN
    sigs = b"".join(u16(s) for s in _SIG_ALGS)
    exts += ext(0x000D, u16(len(sigs)) + sigs)                                        # signature_algorithms
    shares = b""
    if kind == "pq":
        hybrid = scanner._mlkem768_encapsulation_key() + _x25519_public()             # 1184 + 32 = 1216 bytes
        shares += u16(GROUP_X25519MLKEM768) + u16(len(hybrid)) + hybrid
    x = _x25519_public()
    shares += u16(GROUP_X25519) + u16(len(x)) + x
    exts += ext(0x0033, u16(len(shares)) + shares)                                    # key_share
    exts += ext(0x002D, b"\x01\x01")                                                  # psk_key_exchange_modes
    exts += ext(0x002B, b"\x04" + u16(0x0304) + u16(0x0303))                          # supported_versions

    def assemble(extensions: bytes) -> bytes:
        body = (u16(0x0303) + secrets.token_bytes(32) + b"\x20" + secrets.token_bytes(32)
                + u16(2 * len(_SUITES)) + b"".join(u16(c) for c in _SUITES) + b"\x01\x00"
                + u16(len(extensions)) + extensions)
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + u16(len(handshake)) + handshake

    record = assemble(exts)
    if kind == "pq" and len(record) < target_bytes:
        pad = max(0, target_bytes - len(record) - 4)
        record = assemble(exts + ext(0x0015, b"\x00" * pad))                        # padding (RFC 7685)
    return record


def _is_ip(text: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, text)
            return True
        except (OSError, ValueError):
            continue
    return False


def group_name(group_id: Optional[int]) -> str:
    import scanner

    if group_id is None:
        return ""
    return scanner.TLS_NAMED_GROUPS.get(int(group_id), f"unknown-group-0x{int(group_id):04x}")


def is_pq_group(group_id: Optional[int]) -> bool:
    import scanner

    return scanner.classify_key_exchange_group(group_name(group_id)) in ("pq_hybrid", "pq_pure")


# ── One hello on one connection ──────────────────────────────────────────────


def _mss(sock: Any) -> Tuple[int, str]:
    opt = getattr(socket, "TCP_MAXSEG", None)
    if opt is not None:
        try:
            value = int(sock.getsockopt(socket.IPPROTO_TCP, opt))
            if 500 <= value <= 65495:
                return value, "measured"
        except (OSError, ValueError):
            pass
    return ASSUMED_MSS, "assumed"


def _read_server_hello(sock: Any, deadline: float, clock: Callable[[], float]) -> Dict[str, Any]:
    """Read the server's first flight up to the ServerHello. Bounded by deadline and 64 KB."""
    import scanner

    reader = scanner._RecordReader(sock, deadline, budget=64 * 1024, clock=clock)
    pending = b""
    for _ in range(16):
        record = reader.next_record()
        if record is None:
            return {"outcome": "closed"}
        rec_type, payload = record
        if rec_type == 0x15:
            code = payload[1] if len(payload) > 1 else None
            return {"outcome": "alert", "alert": code}
        if rec_type != 0x16:
            return {"outcome": "protocol", "detail": "the server's first record was not a handshake"}
        pending += payload
        messages, pending = scanner.split_handshake_messages(pending)
        if messages:
            msg_type, body = messages[0]
            if msg_type != 0x02:
                return {"outcome": "protocol", "detail": "the server's first message was not a ServerHello"}
            return {"outcome": "hello", "hello": scanner.parse_server_hello(body)}
    return {"outcome": "protocol", "detail": "no ServerHello in the first records"}


def attempt(address: str, host: str, port: int, kind: str, timeout: Optional[float] = None,
            connect: Callable[..., Any] = socket.create_connection,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.perf_counter,
            hello: Optional[bytes] = None) -> Dict[str, Any]:
    """Send one hello (``kind`` "classical", "pq" or "pq_split") and record what came back. Never raises.

    ``ms`` is the time from the last byte of the hello being handed to the network to the
    ServerHello's arrival (for the split hello, from the second half), so the pause is not counted.
    """
    import scanner

    budget = float(timeout if timeout is not None else hello_timeout())
    split = kind == "pq_split"
    data = hello if hello is not None else build_hello(host, "pq" if kind != "classical" else "classical")
    out: Dict[str, Any] = {
        "id": kind, "completed": False, "ms": None, "error": None, "error_detail": "",
        "hello_bytes": len(data), "segments_sent": None, "segments_basis": "",
        "group": "", "group_id": None, "post_quantum": False, "hello_retry": False, "tls_version": "",
        "failed_after_ms": None,
    }
    began = clock()
    try:
        sock = connect((address, int(port)), timeout=budget)
    except socket.timeout:
        out.update(failed_after_ms=int(round((clock() - began) * 1000)), error="connect", error_detail=f"no TCP connection to port {port} within {budget:g} s")
        return out
    except OSError as exc:
        out.update(failed_after_ms=int(round((clock() - began) * 1000)), error="connect", error_detail=f"no TCP connection to port {port}: {_os_reason(exc)}")
        return out
    sent = {"at": None}

    def since() -> Optional[int]:
        return int(round((clock() - (began if sent["at"] is None else sent["at"])) * 1000))

    try:
        with sock:
            sock.settimeout(budget)
            mss, basis = _mss(sock)
            if split:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                half = len(data) // 2
                out["segments_sent"] = 1 + math.ceil((len(data) - half) / mss)
                out["segments_basis"] = f"written in two parts {int(SPLIT_PAUSE * 1000)} ms apart; MSS {mss} ({basis})"
                sock.sendall(data[:half])
                sleep(SPLIT_PAUSE)
                sock.sendall(data[half:])
            else:
                out["segments_sent"] = max(1, math.ceil(len(data) / mss))
                out["segments_basis"] = f"one write; MSS {mss} ({basis})"
                sock.sendall(data)
            sent_at = sent["at"] = clock()
            got = _read_server_hello(sock, sent_at + budget, clock)
            elapsed = int(round((clock() - sent_at) * 1000))
    except socket.timeout:
        out.update(failed_after_ms=since(), error="timeout", error_detail=f"no answer within {budget:g} s")
        return out
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        out.update(failed_after_ms=since(), error="reset", error_detail="the connection was reset")
        return out
    except scanner.TLSParseError as exc:
        out.update(failed_after_ms=since(), error="protocol", error_detail=f"the answer was not TLS: {exc}"[:200])
        return out
    except OSError as exc:
        out.update(failed_after_ms=since(), error="reset", error_detail=f"the connection failed: {_os_reason(exc)}")
        return out
    except Exception as exc:  # never fail the whole set
        out.update(error="protocol", error_detail=f"{type(exc).__name__}"[:200])
        return out
    outcome = got.get("outcome")
    if outcome == "closed":
        out.update(failed_after_ms=elapsed, error="reset", error_detail="the connection was closed without an answer")
    elif outcome == "alert":
        code = got.get("alert")
        label = _ALERTS.get(code, f"alert {code}") if code is not None else "an alert"
        out.update(error="alert", error_detail=f"the server answered with a TLS alert ({label})", ms=elapsed)
    elif outcome == "protocol":
        out.update(failed_after_ms=elapsed, error="protocol", error_detail=str(got.get("detail") or "")[:200])
    else:
        hello_facts = got["hello"]
        gid = hello_facts.get("key_share_group")
        version = hello_facts.get("selected_version")
        out.update(completed=True, ms=elapsed, hello_retry=bool(hello_facts.get("hello_retry")),
                   group_id=gid, group=group_name(gid), post_quantum=is_pq_group(gid),
                   tls_version="TLS 1.3" if version == 0x0304 else "TLS 1.2 or older")
    return out


def _os_reason(exc: OSError) -> str:
    text = str(getattr(exc, "strerror", "") or exc.__class__.__name__)
    return text[:120]


# ── The verdict (pure) ───────────────────────────────────────────────────────


def _how_failed(h: Dict[str, Any]) -> str:
    error = h.get("error")
    if error == "timeout":
        return "got no answer (it timed out)"
    if error == "reset":
        return "was cut off (the connection was reset or closed)"
    if error == "alert":
        return "was refused with a TLS alert"
    if error == "connect":
        return "could not even open a connection"
    return "got an answer that was not TLS"


def verdict(classical: Dict[str, Any], pq: Dict[str, Any], split: Optional[Dict[str, Any]] = None,
            host: str = "", confirmed: bool = True) -> Dict[str, Any]:
    """The verdict from three attempts (``split`` may be None when it was not run). Pure."""
    name = host or "this host"
    pq_ok = bool(pq.get("completed"))
    split_ok = split is None or bool(split.get("completed"))
    classical_ok = bool(classical.get("completed"))

    if pq_ok and split_ok:
        size = f"{int(pq.get('hello_bytes') or 0):,} bytes in {pq.get('segments_sent')} TCP segments"
        notes: List[str] = []
        if not classical_ok:
            notes.append("The classical hello failed this time while the post-quantum ones got through; the "
                         "path carried the large hello, which is what this test is about.")
        if pq.get("tls_version") and pq.get("tls_version") != "TLS 1.3":
            notes.append(f"{name} answered with TLS 1.2 or older. Post-quantum key exchange needs TLS 1.3, so "
                         "turn that on first.")
        if pq.get("post_quantum") or (split and split.get("post_quantum")):
            group = pq.get("group") or (split or {}).get("group") or "X25519MLKEM768"
            return {
                "id": "already_safe", "headline": "Server already quantum-safe.",
                "detail": (f"{name} chose {group} for the post-quantum hello ({size}), and the hello got "
                           "through the public path. New connections from browsers that offer it are already "
                           "protected against later quantum decryption."),
                "cause": "", "fixes": [], "notes": notes, "confirmed": True,
            }
        return {
            "id": "safe_to_turn_on", "headline": "Safe to turn on.",
            "detail": (f"A post-quantum hello ({size}) reached {name} and got an answer, as the classical one "
                       "did, and so did the same hello sent in two parts. Nothing on the public path blocks it, "
                       "so switching on X25519MLKEM768 should not break connections that come in over the internet."
                       if split is not None else
                       f"A post-quantum hello ({size}) reached {name} and got an answer. Nothing on the public path "
                       "blocks it, so switching on X25519MLKEM768 should not break connections from the internet."),
            "cause": "", "fixes": [], "notes": notes, "confirmed": True,
        }

    if classical_ok:
        failed = pq if not pq_ok else split
        which = "The post-quantum hello" if not pq_ok else "The post-quantum hello sent in two parts"
        partial = ""
        if pq_ok and not split_ok:
            partial = (" The same hello sent in one go got through, so the failure depends on how the segments "
                       "arrive: real connections hit it at random.")
        ms = classical.get("ms")
        return {
            "id": "path_problem", "headline": "Path problem.",
            "detail": (f"The classical hello got an answer{f' in {ms} ms' if ms is not None else ''}, but "
                       f"{which.lower()} ({int(failed.get('hello_bytes') or 0):,} bytes) {_how_failed(failed)}"
                       f"{', twice' if confirmed else ''}.{partial}"),
            "cause": ("Something between Morrow and the server mishandles a ClientHello that arrives in more than "
                      "one TCP segment: most often a firewall, load balancer or TLS-inspecting proxy that reads only "
                      "the first segment, sometimes the server's own TLS code. Browsers already send this larger "
                      "hello (Chrome and Firefox offer X25519MLKEM768 by default), so some visitors may be failing "
                      "to connect today, whether or not you switch anything on."),
            "fixes": [
                {"title": "Update what sits in front of the server",
                 "detail": "Firewalls, load balancers and proxies from several vendors had this bug and have shipped "
                           "fixes (Palo Alto, Zscaler, Broadcom ProxySG, Apache Traffic Server and others; Cisco "
                           "tracks it as CSCwj82736). Update to a fixed release.",
                 "source": "https://tldr.fail/"},
                {"title": "Turn on the vendor's fix for a split ClientHello",
                 "detail": "Some products fix it with a setting rather than a release (Envoy's is configuration only): "
                           "look for reassembling or buffering the full ClientHello before inspecting it.",
                 "source": "https://tldr.fail/"},
                {"title": "Check the server's own TLS code",
                 "detail": "A server that calls read() once and expects the whole ClientHello has the same bug. "
                           "Send half a hello, pause, send the rest: the inside test does exactly that.",
                 "source": "https://tldr.fail/"},
            ],
            "notes": ([] if confirmed else ["On the repeat the classical hello failed too, so this may be an unreliable "
                                            "path rather than a size problem: run it again later."]),
            "confirmed": bool(confirmed),
        }

    if classical.get("error") == "connect" and pq.get("error") == "connect":
        reason = f"Nothing accepted a connection: {classical.get('error_detail') or 'no TCP connection'}."
    else:
        reason = (f"Not even the classical hello got an answer: it {_how_failed(classical)}. Without a working "
                  "classical handshake there is nothing to compare the post-quantum one with.")
    return {"id": "couldnt_test", "headline": "Couldn't test.", "detail": reason, "cause": "", "fixes": [],
            "notes": [], "confirmed": False}


# ── One probe set ────────────────────────────────────────────────────────────


def run_set(host: str, address: str, port: int = PORT, split: bool = True, timeout: Optional[float] = None,
            attempt_fn: Callable[..., Dict[str, Any]] = attempt) -> Dict[str, Any]:
    """Run the hellos in order (classical, pq, pq_split), repeat a failure once, and decide. No guards here:
    callers pass an address that already passed public_grade.resolve_pinned (or, in tests, a local one)."""
    kinds = ["classical", "pq"] + (["pq_split"] if split else [])
    shots: Dict[str, Dict[str, Any]] = {}
    for kind in kinds:
        shots[kind] = attempt_fn(address, host, port, kind, timeout=timeout)
        shots[kind]["attempts"] = 1
    confirmed = True
    failed = [k for k in kinds[1:] if not shots[k].get("completed")]
    if shots["classical"].get("completed") and failed:
        again_classical = attempt_fn(address, host, port, "classical", timeout=timeout)
        shots["classical"]["attempts"] = 2
        for kind in failed:
            again = attempt_fn(address, host, port, kind, timeout=timeout)
            if again.get("completed"):
                again["attempts"] = 2
                again["notes"] = ["failed on the first try, got through on the second"]
                shots[kind] = again
            else:
                shots[kind]["attempts"] = 2
        if not again_classical.get("completed"):
            confirmed = False
    result = verdict(shots["classical"], shots["pq"], shots.get("pq_split"), host=host, confirmed=confirmed)
    if result["id"] == "safe_to_turn_on" and any(shots[k].get("attempts", 1) > 1 for k in kinds[1:]):
        result["notes"].append("A post-quantum hello failed once and got through on a second try: an unreliable "
                               "path, worth running again later.")
    labels = {k: (label, what) for k, label, what in HANDSHAKES}
    handshakes = []
    for kind in kinds:
        entry = dict(shots[kind])
        entry["label"], entry["what"] = labels[kind]
        handshakes.append(entry)
    return {"verdict": result, "handshakes": handshakes}


def measured(host: str, port: int, address: str, checked_at: str, vantage: str = "public",
             sent: int = 0) -> Dict[str, Any]:
    """The measured-wording fields: where from, when, what it covers and what it cannot."""
    where = ("Morrow's server, on the public internet" if vantage == "public"
             else "Morrow's server, on the public internet, for a domain your organization verified")
    return {
        "from": where,
        "at": checked_at,
        "target": f"{address}:{port}",
        "wording": (f"Measured from {where}, at {checked_at}, against {host} ({address}) on port {port}: "
                    f"{sent or 'up to six'} ClientHellos, each on its own connection, closed after the server's first "
                    "answer."),
        "covers": f"The public path from the internet to {host}'s public address, and the server that answers there.",
        "does_not_cover": [
            "Networks inside your company: proxies, firewalls and VPNs your own staff go through. Run the inside test.",
            "The path from a CDN or load balancer to your origin, when one sits in front: this reaches its edge.",
            "Paths from other places on the internet, which may cross different equipment.",
        ],
    }


def build_result(host: str, port: int, address: str, outcome: Dict[str, Any], checked_at: str,
                 vantage: str = "public") -> Dict[str, Any]:
    return {
        "api_version": API_VERSION,
        "domain": host,
        "port": int(port),
        "checked_at": checked_at,
        "cached": False,
        "next_check_after": _grade.iso(_parse(checked_at) + timedelta(minutes=minutes())),
        "verdict": outcome["verdict"],
        "handshakes": outcome["handshakes"],
        "measured": measured(host, port, address, checked_at, vantage,
                             sum(int(h.get("attempts") or 1) for h in outcome["handshakes"])),
        "inside_test": dict(INSIDE_TEST),
        "not_tested": list(NOT_TESTED),
        "sources": [dict(s) for s in SOURCES],
    }


def _parse(text: str):
    from datetime import datetime, timezone

    try:
        value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return _grade.now_utc()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# ── Storage: public_preflight_checks ─────────────────────────────────────────


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def init_tables() -> None:
    """Create public_preflight_checks. No organization column: a public result belongs to nobody."""
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
                CREATE TABLE IF NOT EXISTS public_preflight_checks (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain       TEXT NOT NULL,
                    port         INTEGER NOT NULL DEFAULT 443,
                    checked_at   TEXT NOT NULL,
                    verdict      TEXT NOT NULL,
                    api_version  TEXT NOT NULL DEFAULT '',
                    result_json  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_public_preflight_domain
                    ON public_preflight_checks (domain, port, checked_at);
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def store(result: Dict[str, Any]) -> None:
    from db_feature_store import feature_conn

    init_tables()
    stored = dict(result)
    stored.pop("cached", None)
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO public_preflight_checks (domain, port, checked_at, verdict, api_version, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(result["domain"]), int(result["port"]), str(result["checked_at"]), str(result["verdict"]["id"]),
             API_VERSION, json.dumps(stored, separators=(",", ":"), sort_keys=True)))
        conn.execute("DELETE FROM public_preflight_checks WHERE checked_at < ?",
                     (_grade.iso(_grade.now_utc() - timedelta(days=30)),))
        conn.commit()


def latest(domain: str, port: int = PORT, max_age_seconds: Optional[int] = None) -> Optional[Dict[str, Any]]:
    from db_feature_store import feature_conn

    init_tables()
    sql = "SELECT result_json FROM public_preflight_checks WHERE domain = ? AND port = ? AND api_version = ?"
    params: List[Any] = [domain, int(port), API_VERSION]
    if max_age_seconds is not None:
        sql += " AND checked_at >= ?"
        params.append(_grade.iso(_grade.now_utc() - timedelta(seconds=int(max_age_seconds))))
    sql += " ORDER BY checked_at DESC, id DESC LIMIT 1"
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


# ── The guarded check, as the API runs it ────────────────────────────────────


def _semaphore() -> threading.Semaphore:
    want = concurrency()
    with _slots_lock:
        if _slots["size"] != want:
            _slots["sem"] = threading.Semaphore(want)
            _slots["size"] = want
        return _slots["sem"]


def _host_lock(key: str) -> threading.Lock:
    with _inflight_lock:
        if len(_inflight) > 1024:
            for k in [k for k, v in _inflight.items() if not v.locked()]:
                _inflight.pop(k, None)
        return _inflight.setdefault(key, threading.Lock())


def _run_guarded(host: str, port: int, ip_hash: str, vantage: str, budget_key: str,
                 budget_detail: str) -> Dict[str, Any]:
    """Serve the stored answer inside the window, else spend the budgets and run one probe set."""
    from services import public_check

    window = minutes() * 60
    cached = latest(host, port, window)
    if cached is not None:
        return cached
    with _host_lock(f"{host}:{port}"):
        cached = latest(host, port, window)
        if cached is not None:
            return cached
        # One probe set per host per window, whoever asks, in every worker (the window is shared in Redis).
        _grade._limit("public_preflight_host", f"{host}:{port}", 1, float(window),
                      f"{host} had a pre-flight in the last {minutes()} minutes; its answer is being reused.")
        _grade._limit(budget_key, "all" if budget_key == "public_preflight_global" else ip_hash,
                      global_per_hour() if budget_key == "public_preflight_global" else org_per_hour(), 3600.0,
                      budget_detail)
        sem = _semaphore()
        if not sem.acquire(timeout=3.0):
            raise _grade.GradeError(429, "busy", "Too many pre-flights are running right now. Try again in a moment.",
                                    retry_after=10.0)
        started = time.monotonic()
        try:
            try:
                address = _grade.resolve_pinned(host)
            except _grade.GradeError as exc:
                public_check.log_check(host, ip_hash, "preflight_" + exc.error, exc.detail)
                raise
            outcome = run_set(host, address, port)
        finally:
            sem.release()
        duration = int((time.monotonic() - started) * 1000)
        result = build_result(host, port, address, outcome, _grade.iso(_grade.now_utc()), vantage)
        public_check.log_check(host, ip_hash, "preflight_ok", f"port {port}: {result['verdict']['id']}", duration)
        try:
            store(result)
        except Exception:
            logger.warning("pre-flight: could not store the result for %s", host)
        return result


def check(domain: Any, client_ip: str = "") -> Dict[str, Any]:
    """The public pre-flight for one domain on port 443. Raises public_grade.GradeError."""
    from services import public_check

    if not enabled():
        raise _grade.GradeError(503, "disabled", "The pre-flight is switched off on this server.")
    host = _grade.normalize(domain)
    covered = public_check.opted_out(host)
    if covered:
        raise _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
    ip_hash = public_check.hash_ip(client_ip)
    _grade._limit("public_preflight_ip", ip_hash, ip_per_minute(), 60.0,
                  f"More than {ip_per_minute()} pre-flight requests a minute from your address. Wait a moment.")
    return _run_guarded(host, PORT, ip_hash, "public", "public_preflight_global",
                        "The pre-flight is at its hourly limit for everyone. Try again shortly.")


def stored(domain: Any, port: int = PORT) -> Optional[Dict[str, Any]]:
    """The newest stored answer, however old, without sending anything. Raises GradeError on a bad name."""
    from services import public_check

    host = _grade.normalize(domain)
    covered = public_check.opted_out(host)
    if covered:
        raise _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
    return latest(host, port)


def check_owned(org_id: str, host_value: Any, port: Any = PORT) -> Dict[str, Any]:
    """The signed-in pre-flight: a host under one of the organization's verified domains, on a port it names.

    The same public-address guard, the opt-out list and the one-set-per-window rule as the public
    check; the budget is the organization's own (``org_per_hour``) instead of the per-IP one.
    Internal hosts are refused here like anywhere else: that is what the inside test is for.
    """
    from services import domain_verification, public_check

    if not enabled():
        raise _grade.GradeError(503, "disabled", "The pre-flight is switched off on this server.")
    host = _grade.normalize(host_value)
    try:
        number = int(str(port or PORT).strip())
    except ValueError:
        number = 0
    if not 1 <= number <= 65535:
        raise _grade.GradeError(400, "invalid_port", "Give a TCP port from 1 to 65535.")
    org = str(org_id or "").strip()
    names = domain_verification.verified_domains(org) if org else []
    if not any(host == d or host.endswith("." + d) for d in names):
        raise _grade.GradeError(403, "not_verified", f"{host} is not under a domain your organization has verified. "
                                "Verify it under Domains first, or use the public pre-flight on port 443.")
    covered = public_check.opted_out(host)
    if covered:
        raise _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
    return _run_guarded(host, number, "org:" + org, "owned", "public_preflight_org",
                        f"Your organization ran {org_per_hour()} pre-flights this hour. Try again later.")
