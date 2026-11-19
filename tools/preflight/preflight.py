#!/usr/bin/env python3
"""Morrow pre-flight, the inside test: does a post-quantum ClientHello get through your network?

Run it from inside your own network, against your own hosts, before you switch on post-quantum key
exchange (X25519MLKEM768). It sends three TLS ClientHellos to each host, each on its own TCP
connection, and closes each connection as soon as the server's first answer arrives:

  classical   X25519, P-256 and P-384 offered, one X25519 key share. About 250 bytes: one TCP segment.
  pq          X25519MLKEM768 first, then the classical groups, with an X25519MLKEM768 and an X25519 key
              share, as Chrome and Firefox send it, padded to 1,756 bytes (a Chromium 140 ClientHello):
              two TCP segments on an ordinary 1,500-byte path.
  pq_split    the same hello written in two halves, 200 ms apart, so they arrive as separate reads.

Then it gives the same verdict as the pre-flight on Morrow's site:

  Safe to turn on              the post-quantum hellos got answers
  Path problem                 the classical hello got an answer and a post-quantum one failed (twice)
  Server already quantum-safe  the server chose X25519MLKEM768
  Couldn't test                not even the classical hello got an answer

Why: the X25519MLKEM768 key share is 1,216 bytes instead of 32, so the ClientHello no longer fits in
one TCP segment, and some firewalls, load balancers, TLS-inspecting proxies and TLS servers fail on
a ClientHello that arrives in pieces (https://tldr.fail/, https://blog.cloudflare.com/automatic-key-exchange-for-origins/,
https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html).

No handshake is completed, no HTTP request is made and nothing is sent to Morrow or anyone else.
Python 3.8+ and its standard library only: copy this one file to any machine and run it.

Usage:
  python3 preflight.py intranet.example.internal
  python3 preflight.py 10.0.0.12:8443 --sni app.example.internal
  python3 preflight.py host-a host-b:8443 --json
  python3 preflight.py --file hosts.txt --timeout 8 --no-split

Exit status: 0 when every host is "Safe to turn on" or "Server already quantum-safe", 1 when any
host has a path problem, 2 when any host could not be tested (and none has a path problem), 64 for
bad arguments.

AGPL-3.0, part of Morrow (https://github.com/soqlab/Morrow). Not affiliated with any vendor named.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.0"
API_VERSION = "preflight/1"
DEFAULT_PORT = 443
BROWSER_HELLO_BYTES = 1756
ASSUMED_MSS = 1460
SPLIT_PAUSE = 0.2

GROUP_X25519MLKEM768 = 0x11EC
GROUP_X25519 = 0x001D
CLASSICAL_GROUPS = (0x001D, 0x0017, 0x0018)
PQ_GROUPS = (GROUP_X25519MLKEM768, 0x001D, 0x0017, 0x0018)
_SUITES = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8)
_SIG_ALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807)
_HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
_MAX_RECORD = 2 ** 14 + 2048

GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00", 0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}
PQ_GROUP_IDS = frozenset({0x11EB, 0x11EC, 0x11ED, 0x6399, 0x639A, 0x0200, 0x0201, 0x0202})
ALERTS = {
    10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow", 40: "handshake_failure",
    47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    120: "no_application_protocol",
}
HANDSHAKES = (
    ("classical", "Classical hello"),
    ("pq", "Post-quantum hello"),
    ("pq_split", "Post-quantum hello, in two parts"),
)
HEADLINES = {
    "safe_to_turn_on": "Safe to turn on.",
    "path_problem": "Path problem.",
    "already_safe": "Server already quantum-safe.",
    "couldnt_test": "Couldn't test.",
}
SCOPE = ("Measured from this machine. It covers the path from here to each host, not paths from "
         "other networks or from the internet.")


class ParseError(ValueError):
    pass


# ── Key shares (no third-party library) ──────────────────────────────────────


def x25519_public(private: bytes) -> bytes:
    """X25519(k, 9): the public key for a 32-byte private key (RFC 7748 section 5, Montgomery ladder)."""
    p = 2 ** 255 - 19
    k = bytearray(private)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(bytes(k), "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def mlkem768_encapsulation_key() -> bytes:
    """A well-formed ML-KEM-768 encapsulation key: 768 coefficients below q = 3329, 12 bits each, and a
    32-byte seed (FIPS 203). The server only encapsulates to it and this tool never decapsulates, so a
    key with no private half kept is enough to get the server's answer."""
    out = bytearray()
    for _ in range(768 // 2):
        a, b = secrets.randbelow(3329), secrets.randbelow(3329)
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(out) + secrets.token_bytes(32)


# ── The ClientHellos ─────────────────────────────────────────────────────────


def _u16(value: int) -> bytes:
    return int(value).to_bytes(2, "big")


def _ext(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def _is_ip(text: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, text)
            return True
        except (OSError, ValueError):
            continue
    return False


def build_hello(sni: str, kind: str, target_bytes: int = BROWSER_HELLO_BYTES) -> bytes:
    """One ClientHello record, byte for byte the shape Morrow's server sends (services/preflight.py)."""
    groups = PQ_GROUPS if kind == "pq" else CLASSICAL_GROUPS
    exts = b""
    name = b""
    if sni and not _is_ip(sni):
        try:
            name = sni.encode("idna")
        except Exception:
            name = sni.encode("ascii", "ignore")
    if name:
        exts += _ext(0x0000, _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name)
    exts += _ext(0x0017, b"")
    exts += _ext(0xFF01, b"\x00")
    group_bytes = b"".join(_u16(g) for g in groups)
    exts += _ext(0x000A, _u16(len(group_bytes)) + group_bytes)
    exts += _ext(0x000B, b"\x01\x00")
    alpn = b"\x02h2\x08http/1.1"
    exts += _ext(0x0010, _u16(len(alpn)) + alpn)
    sigs = b"".join(_u16(s) for s in _SIG_ALGS)
    exts += _ext(0x000D, _u16(len(sigs)) + sigs)
    shares = b""
    if kind == "pq":
        hybrid = mlkem768_encapsulation_key() + x25519_public(secrets.token_bytes(32))
        shares += _u16(GROUP_X25519MLKEM768) + _u16(len(hybrid)) + hybrid
    x = x25519_public(secrets.token_bytes(32))
    shares += _u16(GROUP_X25519) + _u16(len(x)) + x
    exts += _ext(0x0033, _u16(len(shares)) + shares)
    exts += _ext(0x002D, b"\x01\x01")
    exts += _ext(0x002B, b"\x04" + _u16(0x0304) + _u16(0x0303))

    def assemble(extensions: bytes) -> bytes:
        body = (_u16(0x0303) + secrets.token_bytes(32) + b"\x20" + secrets.token_bytes(32)
                + _u16(2 * len(_SUITES)) + b"".join(_u16(c) for c in _SUITES) + b"\x01\x00"
                + _u16(len(extensions)) + extensions)
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + _u16(len(handshake)) + handshake

    record = assemble(exts)
    if kind == "pq" and len(record) < target_bytes:
        record = assemble(exts + _ext(0x0015, b"\x00" * max(0, target_bytes - len(record) - 4)))
    return record


# ── Reading the server's first answer ────────────────────────────────────────


def parse_server_hello(body: bytes) -> Dict[str, Any]:
    """hello_retry, selected_version and key_share_group from a ServerHello body. Raises ParseError."""
    if len(body) < 38:
        raise ParseError("ServerHello shorter than its fixed fields")
    out: Dict[str, Any] = {"hello_retry": body[2:34] == _HRR_RANDOM, "selected_version": None, "key_share_group": None}
    sid = body[34]
    if sid > 32:
        raise ParseError("session id longer than 32 bytes")
    pos = 35 + sid + 3
    if pos > len(body):
        raise ParseError("ServerHello truncated")
    if pos == len(body):
        return out
    if pos + 2 > len(body):
        raise ParseError("ServerHello truncated in the extensions length")
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    if end != len(body):
        raise ParseError("extensions length does not match the ServerHello")
    while pos < end:
        if end - pos < 4:
            raise ParseError("truncated extension")
        ext_type = int.from_bytes(body[pos:pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
        pos += 4
        if pos + ext_len > end:
            raise ParseError("extension overruns the ServerHello")
        data = body[pos:pos + ext_len]
        pos += ext_len
        if ext_type == 0x0033 and len(data) >= 2:
            out["key_share_group"] = int.from_bytes(data[:2], "big")
        elif ext_type == 0x002B and len(data) == 2:
            out["selected_version"] = int.from_bytes(data, "big")
    return out


def read_first_answer(sock: Any, deadline: float, clock: Callable[[], float] = time.perf_counter,
                      budget: int = 64 * 1024) -> Dict[str, Any]:
    """{"outcome": "hello"|"alert"|"closed"|"protocol", ...}. Raises socket.timeout and OSError."""
    buf = bytearray()
    received = 0
    pending = b""

    def fill(want: int) -> bool:
        nonlocal received
        while len(buf) < want:
            left = deadline - clock()
            if left <= 0:
                raise socket.timeout("deadline passed")
            sock.settimeout(left)
            chunk = sock.recv(16384)
            if not chunk:
                return False
            received += len(chunk)
            if received > budget:
                raise ParseError("the server sent too much before its ServerHello")
            buf.extend(chunk)
        return True

    for _ in range(16):
        if not fill(5):
            return {"outcome": "closed"}
        rec_type, rec_len = buf[0], int.from_bytes(buf[3:5], "big")
        if rec_type not in (0x14, 0x15, 0x16, 0x17) or buf[1] != 0x03 or rec_len > _MAX_RECORD:
            return {"outcome": "protocol", "detail": "the answer was not TLS"}
        if not fill(5 + rec_len):
            return {"outcome": "closed"}
        payload = bytes(buf[5:5 + rec_len])
        del buf[:5 + rec_len]
        if rec_type == 0x15:
            return {"outcome": "alert", "alert": payload[1] if len(payload) > 1 else None}
        if rec_type != 0x16:
            return {"outcome": "protocol", "detail": "the server's first record was not a handshake"}
        pending += payload
        if len(pending) >= 4 and len(pending) - 4 >= int.from_bytes(pending[1:4], "big"):
            if pending[0] != 0x02:
                return {"outcome": "protocol", "detail": "the server's first message was not a ServerHello"}
            length = int.from_bytes(pending[1:4], "big")
            return {"outcome": "hello", "hello": parse_server_hello(pending[4:4 + length])}
    return {"outcome": "protocol", "detail": "no ServerHello in the first records"}


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


def attempt(address: str, sni: str, port: int, kind: str, timeout: float = 6.0,
            connect: Callable[..., Any] = socket.create_connection,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.perf_counter) -> Dict[str, Any]:
    """One hello on one connection; the same fields as Morrow's API. Never raises."""
    data = build_hello(sni, "classical" if kind == "classical" else "pq")
    out: Dict[str, Any] = {
        "id": kind, "completed": False, "ms": None, "error": None, "error_detail": "",
        "hello_bytes": len(data), "segments_sent": None, "segments_basis": "",
        "group": "", "group_id": None, "post_quantum": False, "hello_retry": False, "tls_version": "",
        "failed_after_ms": None,
    }
    began = clock()
    try:
        sock = connect((address, int(port)), timeout=timeout)
    except socket.timeout:
        out.update(failed_after_ms=int(round((clock() - began) * 1000)), error="connect", error_detail=f"no TCP connection to port {port} within {timeout:g} s")
        return out
    except OSError as exc:
        out.update(failed_after_ms=int(round((clock() - began) * 1000)), error="connect", error_detail=f"no TCP connection to port {port}: {exc.strerror or type(exc).__name__}")
        return out
    sent = {"at": None}

    def since() -> Optional[int]:
        return int(round((clock() - (began if sent["at"] is None else sent["at"])) * 1000))

    try:
        with sock:
            sock.settimeout(timeout)
            mss, basis = _mss(sock)
            if kind == "pq_split":
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                half = len(data) // 2
                sock.sendall(data[:half])
                sleep(SPLIT_PAUSE)
                sock.sendall(data[half:])
                out["segments_sent"] = 1 + math.ceil((len(data) - half) / mss)
                out["segments_basis"] = f"written in two parts {int(SPLIT_PAUSE * 1000)} ms apart; MSS {mss} ({basis})"
            else:
                sock.sendall(data)
                out["segments_sent"] = max(1, math.ceil(len(data) / mss))
                out["segments_basis"] = f"one write; MSS {mss} ({basis})"
            sent_at = sent["at"] = clock()
            got = read_first_answer(sock, sent_at + timeout, clock)
            elapsed = int(round((clock() - sent_at) * 1000))
    except socket.timeout:
        out.update(failed_after_ms=since(), error="timeout", error_detail=f"no answer within {timeout:g} s")
        return out
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        out.update(failed_after_ms=since(), error="reset", error_detail="the connection was reset")
        return out
    except ParseError as exc:
        out.update(failed_after_ms=since(), error="protocol", error_detail=f"the answer was not TLS: {exc}")
        return out
    except OSError as exc:
        out.update(failed_after_ms=since(), error="reset", error_detail=f"the connection failed: {exc.strerror or type(exc).__name__}")
        return out
    outcome = got.get("outcome")
    if outcome == "closed":
        out.update(failed_after_ms=elapsed, error="reset", error_detail="the connection was closed without an answer")
    elif outcome == "alert":
        code = got.get("alert")
        out.update(error="alert", ms=elapsed,
                   error_detail=f"the server answered with a TLS alert ({ALERTS.get(code, f'alert {code}')})")
    elif outcome == "protocol":
        out.update(failed_after_ms=elapsed, error="protocol", error_detail=str(got.get("detail") or ""))
    else:
        hello = got["hello"]
        gid = hello.get("key_share_group")
        out.update(completed=True, ms=elapsed, hello_retry=bool(hello.get("hello_retry")), group_id=gid,
                   group=GROUP_NAMES.get(gid, f"unknown-group-0x{gid:04x}") if gid is not None else "",
                   post_quantum=gid in PQ_GROUP_IDS,
                   tls_version="TLS 1.3" if hello.get("selected_version") == 0x0304 else "TLS 1.2 or older")
    return out


# ── The verdict: the same rules as services/preflight.verdict ────────────────


def verdict_id(classical: Dict[str, Any], pq: Dict[str, Any], split: Optional[Dict[str, Any]]) -> str:
    pq_ok = bool(pq.get("completed"))
    split_ok = split is None or bool(split.get("completed"))
    if pq_ok and split_ok:
        return "already_safe" if (pq.get("post_quantum") or (split or {}).get("post_quantum")) else "safe_to_turn_on"
    if classical.get("completed"):
        return "path_problem"
    return "couldnt_test"


def explain(vid: str, host: str, classical: Dict[str, Any], pq: Dict[str, Any], split: Optional[Dict[str, Any]],
            confirmed: bool = True) -> str:
    if vid == "already_safe":
        return (f"{host} chose {pq.get('group') or 'X25519MLKEM768'} for the post-quantum hello, and the "
                f"{int(pq.get('hello_bytes') or 0):,}-byte hello got through.")
    if vid == "safe_to_turn_on":
        return (f"The post-quantum hello ({int(pq.get('hello_bytes') or 0):,} bytes, {pq.get('segments_sent')} segments) got an "
                "answer, as the classical one did. Nothing on this path blocks it.")
    if vid == "path_problem":
        failed = pq if not pq.get("completed") else split or {}
        twice = ", twice" if confirmed else ""
        return (f"The classical hello got an answer, but the {'split ' if failed is split else ''}post-quantum hello "
                f"failed ({failed.get('error')}: {failed.get('error_detail')}){twice}. Something on this path -- a "
                "firewall, load balancer, TLS-inspecting proxy or the server's TLS code -- mishandles a ClientHello "
                "that arrives in more than one TCP segment. Update it, or turn on the vendor's fix for a split "
                "ClientHello (see https://tldr.fail/).")
    return f"Not even the classical hello got an answer ({classical.get('error')}: {classical.get('error_detail')})."


def run_host(target: Dict[str, Any], timeout: float = 6.0, split: bool = True,
             attempt_fn: Callable[..., Dict[str, Any]] = attempt,
             resolve: Callable[[str, int], str] = None) -> Dict[str, Any]:
    """All hellos for one target, a repeat of any post-quantum failure, and the verdict."""
    host, port, sni = target["host"], int(target["port"]), target.get("sni") or target["host"]
    checked_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = {"api_version": API_VERSION, "tool_version": VERSION, "domain": host, "port": port, "sni": sni,
            "checked_at": checked_at, "vantage": "inside", "scope": SCOPE}
    try:
        address = (resolve or _resolve)(host, port)
    except OSError as exc:
        return dict(base, address="", handshakes=[],
                    verdict={"id": "couldnt_test", "headline": HEADLINES["couldnt_test"],
                             "detail": f"{host} does not resolve from here ({exc.strerror or type(exc).__name__}).",
                             "confirmed": False})
    kinds = ["classical", "pq"] + (["pq_split"] if split else [])
    shots = {}
    for kind in kinds:
        shots[kind] = attempt_fn(address, sni, port, kind, timeout=timeout)
        shots[kind]["attempts"] = 1
    confirmed = True
    failed = [k for k in kinds[1:] if not shots[k].get("completed")]
    if shots["classical"].get("completed") and failed:
        again_classical = attempt_fn(address, sni, port, "classical", timeout=timeout)
        shots["classical"]["attempts"] = 2
        for kind in failed:
            again = attempt_fn(address, sni, port, kind, timeout=timeout)
            if again.get("completed"):
                again["attempts"] = 2
                shots[kind] = again
            else:
                shots[kind]["attempts"] = 2
        confirmed = bool(again_classical.get("completed"))
    vid = verdict_id(shots["classical"], shots["pq"], shots.get("pq_split"))
    labels = dict(HANDSHAKES)
    handshakes = [dict(shots[k], label=labels[k]) for k in kinds]
    return dict(base, address=address, handshakes=handshakes,
                verdict={"id": vid, "headline": HEADLINES[vid],
                         "detail": explain(vid, host, shots["classical"], shots["pq"], shots.get("pq_split"), confirmed),
                         "confirmed": confirmed if vid == "path_problem" else vid != "couldnt_test"})


def _resolve(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    return str((v4 or [i[4][0] for i in infos])[0])


# ── Command line ─────────────────────────────────────────────────────────────


def parse_target(text: str, default_port: int = DEFAULT_PORT, sni: str = "") -> Dict[str, Any]:
    """"host", "host:port", "[v6]:port" or "https://host:port/path". Raises ValueError."""
    raw = str(text or "").strip()
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        if scheme.lower() not in ("https", "tls"):
            raise ValueError(f"{text}: only https:// targets make sense here")
    raw = raw.split("/", 1)[0].split("?", 1)[0]
    if "@" in raw:
        raise ValueError(f"{text}: leave credentials out")
    port = default_port
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0:
            raise ValueError(f"{text}: unclosed [ in an IPv6 address")
        host, rest = raw[1:end], raw[end + 1:]
        if rest.startswith(":"):
            port = _port(rest[1:], text)
        elif rest:
            raise ValueError(f"{text}: unexpected text after the IPv6 address")
    elif raw.count(":") == 1:
        host, number = raw.split(":")
        port = _port(number, text)
    else:
        host = raw
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"{text}: no host")
    return {"host": host, "port": port, "sni": sni or ("" if _is_ip(host) else host)}


def _port(text: str, original: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError(f"{original}: the port must be a number from 1 to 65535")
    return int(text)


def render_text(result: Dict[str, Any]) -> str:
    lines = [f"{result['domain']}:{result['port']}" + (f"  ({result['address']})" if result.get("address") else "")]
    for h in result.get("handshakes") or []:
        mark = "ok  " if h.get("completed") else "FAIL"
        timing = f"{h['ms']} ms" if h.get("ms") is not None else (h.get("error") or "")
        group = f"  {h['group']}" if h.get("group") else ""
        lines.append(f"  {mark} {h['label']:<34} {h['hello_bytes']:>5} bytes  {str(h.get('segments_sent') or '-'):>2} seg  "
                     f"{timing:>8}{group}")
        if not h.get("completed") and h.get("error_detail"):
            lines.append(f"       {h['error_detail']}")
    v = result["verdict"]
    lines.append(f"  => {v['headline']} {v['detail']}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="preflight.py", description="Does a post-quantum ClientHello get through this network? "
        "Sends a classical and a post-quantum ClientHello to each host and compares them.")
    parser.add_argument("targets", nargs="*", help="host, host:port, [v6]:port or https://host:port")
    parser.add_argument("--file", help="read targets from a file, one per line (# comments allowed)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port when a target names none (443)")
    parser.add_argument("--sni", default="", help="server name to send, when the target is an address")
    parser.add_argument("--timeout", type=float, default=6.0, help="seconds to wait for each answer (6)")
    parser.add_argument("--no-split", action="store_true", help="skip the hello sent in two parts")
    parser.add_argument("--json", action="store_true", help="print one JSON document instead of text")
    parser.add_argument("--version", action="version", version=f"morrow-preflight {VERSION}")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 64
    texts = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as handle:
                texts += [ln.split("#", 1)[0].strip() for ln in handle if ln.split("#", 1)[0].strip()]
        except OSError as exc:
            print(f"preflight: cannot read {args.file}: {exc.strerror}", file=sys.stderr)
            return 64
    if not texts:
        parser.print_usage(sys.stderr)
        print("preflight: name at least one host", file=sys.stderr)
        return 64
    if not 1 <= args.port <= 65535 or not 0.5 <= args.timeout <= 120:
        print("preflight: --port must be 1-65535 and --timeout 0.5-120 seconds", file=sys.stderr)
        return 64
    try:
        targets = [parse_target(t, args.port, args.sni) for t in texts]
    except ValueError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 64
    results = [run_host(t, timeout=args.timeout, split=not args.no_split) for t in targets]
    if args.json:
        print(json.dumps({"api_version": API_VERSION, "tool_version": VERSION, "scope": SCOPE, "results": results},
                         indent=2))
    else:
        for result in results:
            print(render_text(result))
            print()
        print(SCOPE)
    ids = {r["verdict"]["id"] for r in results}
    if "path_problem" in ids:
        return 1
    if "couldnt_test" in ids:
        return 2
    return 0


if __name__ == "__main__":
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    sys.exit(main())
