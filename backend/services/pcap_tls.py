"""TLS key exchange read from a traffic capture (.pcap / .pcapng), offline, in pure Python.

What it reports, per TCP connection whose first bytes are a TLS handshake: the groups the client
offered (supported_groups), the groups it sent key shares for (key_share), and the group the server
chose (the ServerHello or HelloRetryRequest key_share, or a TLS 1.2 ServerKeyExchange). The
ServerHello is parsed by scanner.read_key_exchange_group, the same code the live probe uses, so a
capture and a live check can never disagree about what a handshake means.

Why it is safe to run on a stranger's file:
  * Nothing here decompresses, executes or follows anything. Only fixed-layout headers are read with
    struct, and every length is checked against the bytes present before it is used.
  * Hard limits, all checked as the file is walked: the file size (MAX_BYTES), the packet count
    (MAX_PACKETS), the connections tracked (MAX_FLOWS), the bytes buffered per direction of a
    connection (MAX_STREAM_BYTES), the TCP segments kept per direction (MAX_SEGMENTS) and a wall-clock
    deadline (DEADLINE_SECONDS). Crossing one stops the walk and says so; it never raises past here.
  * QUIC (HTTP/3) handshakes are encrypted even in their first packet, so UDP is counted, not read.

The capture itself is never stored. Only the summary below leaves this module.
"""

from __future__ import annotations

import struct
import time
from typing import Any, Dict, List, Optional, Tuple

MAX_BYTES = 10 * 1024 * 1024
MAX_PACKETS = 200_000
MAX_FLOWS = 5_000
MAX_STREAM_BYTES = 64 * 1024
MAX_SEGMENTS = 64
MAX_REPORTED = 200
DEADLINE_SECONDS = 8.0

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1e-6), b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9), b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link types (https://www.tcpdump.org/linktypes.html)
_LINK_NULL, _LINK_ETHERNET, _LINK_RAW, _LINK_LOOP = 0, 1, 101, 108
_LINK_SLL, _LINK_IPV4, _LINK_IPV6, _LINK_SLL2 = 113, 228, 229, 276
SUPPORTED_LINKS = {_LINK_NULL, _LINK_ETHERNET, _LINK_RAW, _LINK_LOOP, _LINK_SLL, _LINK_IPV4, _LINK_IPV6, _LINK_SLL2}


class CaptureError(ValueError):
    """The file is not a capture this module can read. The message is safe to show."""


def is_capture(data: bytes) -> bool:
    return data[:4] in PCAP_MAGICS or data[:4] == PCAPNG_MAGIC


# ── Containers ───────────────────────────────────────────────────────────────

def _pcap_packets(data: bytes):
    """(link type, frame bytes) for each record of a classic pcap file."""
    endian, _ = PCAP_MAGICS[data[:4]]
    if len(data) < 24:
        raise CaptureError("The capture is shorter than its own header.")
    link = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    pos = 24
    while pos + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
        pos += 16
        if incl > len(data) - pos or incl > 262_144:
            return                                   # truncated or nonsense record: stop here
        yield link, data[pos:pos + incl]
        pos += incl


def _pcapng_packets(data: bytes):
    """(link type, frame bytes) for each packet block of a pcapng file (any section byte order)."""
    pos = 0
    endian = "<"
    links: List[int] = []
    while pos + 12 <= len(data):
        btype_raw = data[pos:pos + 4]
        if btype_raw == PCAPNG_MAGIC:
            bom = data[pos + 8:pos + 12]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise CaptureError("The pcapng section header has an unknown byte order.")
            links = []
        btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
        if blen < 12 or blen % 4 or blen > len(data) - pos:
            return                                   # malformed or truncated block: stop
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:            # Interface Description Block
            links.append(struct.unpack(endian + "H", body[0:2])[0])
        elif btype == 6 and len(body) >= 20:         # Enhanced Packet Block
            iface, _, _, cap = struct.unpack(endian + "IIII", body[0:16])
            if iface < len(links) and cap <= len(body) - 20:
                yield links[iface], body[20:20 + cap]
        elif btype == 3 and len(body) >= 4 and links:  # Simple Packet Block (interface 0)
            yield links[0], body[4:]
        pos += blen


# ── Frames to TCP segments ───────────────────────────────────────────────────

def _ip_payload(link: int, frame: bytes) -> Optional[Tuple[int, bytes]]:
    """(IP version, IP packet) inside one frame, or None."""
    if link == _LINK_ETHERNET:
        if len(frame) < 14:
            return None
        etype, off = struct.unpack("!H", frame[12:14])[0], 14
        for _ in range(2):                           # up to two VLAN tags (802.1Q / QinQ)
            if etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
                etype, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        pkt = frame[off:]
        return (4, pkt) if etype == 0x0800 else (6, pkt) if etype == 0x86DD else None
    if link in (_LINK_NULL, _LINK_LOOP):
        if len(frame) < 4:
            return None
        fam = max(struct.unpack("<I", frame[:4])[0], struct.unpack(">I", frame[:4])[0]) & 0xFF
        pkt = frame[4:]
    elif link == _LINK_SLL:
        if len(frame) < 16:
            return None
        proto = struct.unpack("!H", frame[14:16])[0]
        return (4, frame[16:]) if proto == 0x0800 else (6, frame[16:]) if proto == 0x86DD else None
    elif link == _LINK_SLL2:
        if len(frame) < 20:
            return None
        proto = struct.unpack("!H", frame[0:2])[0]
        return (4, frame[20:]) if proto == 0x0800 else (6, frame[20:]) if proto == 0x86DD else None
    else:                                            # raw IP
        pkt, fam = frame, 0
    if not pkt:
        return None
    version = pkt[0] >> 4
    if link in (_LINK_NULL, _LINK_LOOP) and fam not in (2, 24, 28, 30) and version not in (4, 6):
        return None
    return (version, pkt) if version in (4, 6) else None


def _addr(version: int, raw: bytes) -> str:
    if version == 4:
        return ".".join(str(b) for b in raw)
    words = [f"{(raw[i] << 8) | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(words)


def _transport(version: int, pkt: bytes) -> Optional[Tuple[int, str, str, bytes]]:
    """(protocol, source, destination, transport bytes); fragments other than the first are skipped."""
    if version == 4:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack("!H", pkt[2:4])[0]
        frag = struct.unpack("!H", pkt[6:8])[0] & 0x1FFF
        if ihl < 20 or len(pkt) < ihl or frag:
            return None
        end = min(len(pkt), total) if total >= ihl else len(pkt)
        return pkt[9], _addr(4, pkt[12:16]), _addr(4, pkt[16:20]), pkt[ihl:end]
    if len(pkt) < 40:
        return None
    nxt, off = pkt[6], 40
    plen = struct.unpack("!H", pkt[4:6])[0]
    end = min(len(pkt), 40 + plen) if plen else len(pkt)
    for _ in range(8):                               # a bounded walk over extension headers
        if nxt in (0, 43, 60) and off + 8 <= end:
            nxt, off = pkt[off], off + (pkt[off + 1] + 1) * 8
        elif nxt == 44:                              # fragment header: not reassembled
            return None
        else:
            break
    if off > end:
        return None
    return nxt, _addr(6, pkt[8:24]), _addr(6, pkt[24:40]), pkt[off:end]


# ── TLS from a reassembled stream ────────────────────────────────────────────

class _Stream:
    """One direction of one TCP connection: the first MAX_STREAM_BYTES, in sequence order."""

    __slots__ = ("isn", "segments", "size", "full")

    def __init__(self) -> None:
        self.isn: Optional[int] = None
        self.segments: Dict[int, bytes] = {}
        self.size = 0
        self.full = False

    def add(self, seq: int, syn: bool, payload: bytes) -> None:
        if syn:
            self.isn = (seq + 1) & 0xFFFFFFFF
        if not payload or self.full:
            return
        if len(self.segments) >= MAX_SEGMENTS or self.size + len(payload) > MAX_STREAM_BYTES:
            self.full = True
            return
        if seq not in self.segments:
            self.segments[seq] = payload
            self.size += len(payload)

    def data(self) -> bytes:
        if not self.segments:
            return b""
        start = self.isn if self.isn is not None and self.isn in self.segments else min(self.segments)
        out = bytearray()
        want = start
        for _ in range(len(self.segments)):
            chunk = self.segments.get(want)
            if chunk is None:
                # A retransmission that overlaps: take the segment that covers `want`.
                cover = [s for s in self.segments if 0 < (want - s) & 0xFFFFFFFF < len(self.segments[s])]
                if not cover:
                    break
                s = cover[0]
                chunk = self.segments[s][(want - s) & 0xFFFFFFFF:]
            out += chunk
            want = (want + len(chunk)) & 0xFFFFFFFF
        return bytes(out)


class _BytesRecords:
    """scanner.read_key_exchange_group's reader, over bytes already captured."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def next_record(self) -> Optional[Tuple[int, bytes]]:
        from scanner import parse_tls_record_header

        if len(self.data) - self.pos < 5:
            return None
        rec_type, rec_len = parse_tls_record_header(self.data[self.pos:self.pos + 5])
        if len(self.data) - self.pos - 5 < rec_len:
            return None
        payload = self.data[self.pos + 5:self.pos + 5 + rec_len]
        self.pos += 5 + rec_len
        return rec_type, payload


def _handshake_bytes(stream: bytes, max_records: int = 64) -> bytes:
    """The handshake-record payloads at the start of a stream, concatenated."""
    from scanner import parse_tls_record_header

    out = bytearray()
    pos = 0
    for _ in range(max_records):
        if len(stream) - pos < 5:
            break
        rec_type, rec_len = parse_tls_record_header(stream[pos:pos + 5])
        if rec_type != 0x16:
            break
        out += stream[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len
    return bytes(out)


def _u16s(raw: bytes) -> List[int]:
    return [struct.unpack("!H", raw[i:i + 2])[0] for i in range(0, len(raw) - 1, 2)]


def parse_client_hello(stream: bytes) -> Optional[Dict[str, Any]]:
    """Offered groups, key-share groups, versions and SNI from a client stream, or None."""
    hs = _handshake_bytes(stream)
    if len(hs) < 4 or hs[0] != 0x01:
        return None
    length = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + length]
    if len(body) < 38:
        return None
    pos = 34
    sid = body[pos]
    pos += 1 + sid
    if pos + 2 > len(body):
        return None
    pos += 2 + struct.unpack("!H", body[pos:pos + 2])[0]          # cipher suites
    if pos + 1 > len(body):
        return None
    pos += 1 + body[pos]                                          # compression methods
    out: Dict[str, Any] = {"offered": [], "key_shares": [], "versions": [], "sni": "", "truncated": len(body) < length}
    if pos + 2 > len(body):
        return out
    end = min(len(body), pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0])
    pos += 2
    for _ in range(128):
        if pos + 4 > end:
            break
        etype, elen = struct.unpack("!HH", body[pos:pos + 4])
        ext = body[pos + 4:min(end, pos + 4 + elen)]
        pos += 4 + elen
        if etype == 0x000A and len(ext) >= 2:
            out["offered"] = _u16s(ext[2:2 + struct.unpack("!H", ext[:2])[0]])[:64]
        elif etype == 0x0033 and len(ext) >= 2:
            p, stop = 2, min(len(ext), 2 + struct.unpack("!H", ext[:2])[0])
            while p + 4 <= stop and len(out["key_shares"]) < 16:
                group, klen = struct.unpack("!HH", ext[p:p + 4])
                out["key_shares"].append(group)
                p += 4 + klen
        elif etype == 0x002B and ext:
            out["versions"] = _u16s(ext[1:1 + ext[0]])[:16]
        elif etype == 0x0000 and len(ext) >= 5 and ext[2] == 0:
            n = struct.unpack("!H", ext[3:5])[0]
            name = ext[5:5 + n].decode("ascii", "replace")
            out["sni"] = "".join(c for c in name if c.isalnum() or c in ".-_")[:253]
    return out


def _server_hello(stream: bytes) -> Dict[str, Any]:
    from scanner import TLSParseError, parse_server_hello, read_key_exchange_group, split_handshake_messages

    out: Dict[str, Any] = {"group": None, "hello_retry": False, "version": None, "reason": ""}
    try:
        group, hrr, reason = read_key_exchange_group(_BytesRecords(stream))
        out.update(group=group, hello_retry=hrr, reason=reason)
        hs = _handshake_bytes(stream, max_records=2)
        messages, _ = split_handshake_messages(hs)
        if messages and messages[0][0] == 0x02:
            hello = parse_server_hello(messages[0][1])
            out["version"] = hello.get("selected_version") or (struct.unpack("!H", messages[0][1][:2])[0]
                                                               if len(messages[0][1]) >= 2 else None)
    except (TLSParseError, ValueError, IndexError, struct.error):
        out["reason"] = "the server's first flight is not a well-formed TLS handshake"
    return out


def _group_name(code: Optional[int]) -> str:
    from scanner import TLS_NAMED_GROUPS

    if code is None:
        return ""
    if (code & 0x0F0F) == 0x0A0A:
        return ""                                    # GREASE (RFC 8701): not a real group
    return TLS_NAMED_GROUPS.get(code, f"unknown-0x{code:04x}")


def _version_name(code: Optional[int]) -> str:
    return {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}.get(code or 0, "")


def _names(codes: List[int]) -> List[str]:
    return [n for n in (_group_name(c) for c in codes) if n]


# ── The walk ─────────────────────────────────────────────────────────────────

def analyze(data: bytes, clock: Any = time.monotonic) -> Dict[str, Any]:
    """Summarise the TLS key exchange of every connection in a capture. Raises CaptureError."""
    from scanner import classify_key_exchange_group

    if len(data) > MAX_BYTES:
        raise CaptureError(f"The capture is larger than {MAX_BYTES // (1024 * 1024)} MB.")
    if data[:4] == PCAPNG_MAGIC:
        packets, fmt = _pcapng_packets(data), "pcapng"
    elif data[:4] in PCAP_MAGICS:
        packets, fmt = _pcap_packets(data), "pcap"
    else:
        raise CaptureError("This is not a pcap or pcapng capture.")
    deadline = clock() + DEADLINE_SECONDS
    flows: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
    stopped = ""
    counts = {"packets": 0, "tcp": 0, "udp": 0, "unreadable": 0, "quic_443": 0}
    links_seen = set()
    for link, frame in packets:
        counts["packets"] += 1
        if counts["packets"] > MAX_PACKETS:
            stopped = f"stopped after {MAX_PACKETS:,} packets"
            break
        if counts["packets"] % 500 == 0 and clock() > deadline:
            stopped = f"stopped after {DEADLINE_SECONDS:g} seconds of reading"
            break
        links_seen.add(link)
        if link not in SUPPORTED_LINKS:
            counts["unreadable"] += 1
            continue
        ip = _ip_payload(link, frame)
        tr = _transport(*ip) if ip else None
        if not tr:
            counts["unreadable"] += 1
            continue
        proto, src, dst, seg = tr
        if proto == 17:
            counts["udp"] += 1
            if len(seg) >= 4 and 443 in struct.unpack("!HH", seg[:4]):
                counts["quic_443"] += 1
            continue
        if proto != 6 or len(seg) < 20:
            continue
        counts["tcp"] += 1
        sport, dport, seq = struct.unpack("!HHI", seg[:8])
        off = (seg[12] >> 4) * 4
        flags = seg[13]
        if off < 20 or off > len(seg):
            continue
        payload = seg[off:]
        key_fwd = (src, sport, dst, dport)
        key_rev = (dst, dport, src, sport)
        if key_fwd in flows:
            flow, direction = flows[key_fwd], "c"
        elif key_rev in flows:
            flow, direction = flows[key_rev], "s"
        else:
            if not payload and not (flags & 0x02):
                continue
            if len(flows) >= MAX_FLOWS:
                stopped = stopped or f"tracked the first {MAX_FLOWS:,} connections only"
                continue
            # The side that sends the SYN (not SYN-ACK) or the first payload is the client.
            if (flags & 0x12) == 0x12:
                key_fwd, direction = key_rev, "s"
            else:
                direction = "c"
            flow = flows[key_fwd] = {"key": key_fwd, "c": _Stream(), "s": _Stream()}
        flow[direction].add(seq, bool(flags & 0x02), payload)

    connections: List[Dict[str, Any]] = []
    not_tls = 0
    for flow in flows.values():
        if clock() > deadline + 2:
            stopped = stopped or "stopped while reading the handshakes"
            break
        try:
            client = parse_client_hello(flow["c"].data())
        except Exception:
            client = None
        if client is None:
            not_tls += 1
            continue
        server = _server_hello(flow["s"].data()) if flow["s"].segments else {"group": None, "hello_retry": False,
                                                                             "version": None, "reason": "no answer from the server in the capture"}
        chosen = _group_name(server["group"])
        family = classify_key_exchange_group(chosen) if chosen else ""
        offered = _names(client["offered"])
        c, cport, s, sport = flow["key"]
        connections.append({
            "client": f"{c}:{cport}" if ":" not in c else f"[{c}]:{cport}",
            "server": f"{s}:{sport}" if ":" not in s else f"[{s}]:{sport}",
            "sni": client["sni"],
            "offered_groups": offered,
            "key_share_groups": _names(client["key_shares"]),
            "client_offers_pq": any(classify_key_exchange_group(g).startswith("pq") for g in offered),
            "negotiated_group": chosen,
            "post_quantum": family.startswith("pq"),
            "family": family,
            "hello_retry": bool(server["hello_retry"]),
            "version": _version_name(server.get("version")),
            "note": "" if chosen else (server.get("reason") or "the key exchange is not visible in the capture"),
        })
    pq = sum(1 for x in connections if x["post_quantum"])
    seen = [x for x in connections if x["negotiated_group"]]
    by_group: Dict[str, int] = {}
    for x in seen:
        by_group[x["negotiated_group"]] = by_group.get(x["negotiated_group"], 0) + 1
    connections.sort(key=lambda x: (x["post_quantum"], not x["negotiated_group"], x["server"]))
    return {
        "format": fmt,
        "packets": min(counts["packets"], MAX_PACKETS),
        "tcp_packets": counts["tcp"],
        "udp_packets": counts["udp"],
        "quic_packets": counts["quic_443"],
        "unreadable_packets": counts["unreadable"],
        "unsupported_link_types": sorted(x for x in links_seen if x not in SUPPORTED_LINKS)[:10],
        "tls_connections": len(connections),
        "other_tcp_connections": not_tls,
        "negotiated_seen": len(seen),
        "post_quantum": pq,
        "classical": len(seen) - pq,
        "by_group": dict(sorted(by_group.items(), key=lambda kv: -kv[1])),
        "connections": connections[:MAX_REPORTED],
        "connections_truncated": len(connections) > MAX_REPORTED,
        "stopped": stopped,
        "limits": {"bytes": MAX_BYTES, "packets": MAX_PACKETS, "connections": MAX_FLOWS,
                   "bytes_per_direction": MAX_STREAM_BYTES, "seconds": DEADLINE_SECONDS},
    }
