"""One property check per parser of remote bytes, shared by the Hypothesis tests and Atheris.

Each check_* function hands its input to a parser and asserts what must hold for every input:

  * only the parser's documented error type escapes (anything else propagates and is a crash);
  * the call finishes within TIME_LIMIT seconds (ParserHang otherwise);
  * nothing is buffered beyond the parser's own cap, whatever a length field claims;
  * the output is consistent with the input (lengths within the input, ports in range, ...).

A check returns normally when the parser rejected the input the documented way or accepted it
with a consistent result.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import socket
import sqlite3
import threading
import time
from typing import Any, Iterator, List, Optional, Sequence

#: Seconds one input may take. Generous: CI runners are slow and Windows has no SIGALRM, where the
#: limit is checked after the call instead of interrupting it.
TIME_LIMIT = float(os.environ.get("MORROW_FUZZ_TIME_LIMIT", "3"))


class ParserHang(BaseException):
    """A parser ran past the time limit. BaseException, so a broad `except Exception` inside the
    code under test cannot swallow it."""


@contextlib.contextmanager
def time_limit(seconds: float = TIME_LIMIT, what: str = "parser") -> Iterator[None]:
    use_alarm = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    start = time.monotonic()
    if use_alarm:
        def _fire(_sig, _frame):
            raise ParserHang(f"{what} ran longer than {seconds:g}s")

        previous = signal.signal(signal.SIGALRM, _fire)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        if use_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    elapsed = time.monotonic() - start
    if elapsed > seconds:
        raise ParserHang(f"{what} took {elapsed:.2f}s (limit {seconds:g}s)")


class FakePeer:
    """A remote peer that sends `data` in chunks of at most `chunk` bytes and then closes."""

    def __init__(self, data: bytes, chunk: int = 16384):
        self.data = bytes(data)
        self.chunk = max(1, chunk)
        self.pos = 0
        self.recv_calls = 0
        self.sent = 0

    def settimeout(self, _t: Optional[float]) -> None:
        pass

    def connect(self, _addr: Any) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += len(data)

    def recv(self, n: int) -> bytes:
        self.recv_calls += 1
        out = self.data[self.pos:self.pos + min(n, self.chunk)]
        self.pos += len(out)
        return out

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


_WARM = set()


def _warm_up(name: str, fn) -> None:
    """Run fn once, outside any time limit: first calls pay for lazy imports and key generation."""
    if name not in _WARM:
        _WARM.add(name)
        fn()


# A reason that starts like "IndexError: ..." comes from the probe's last-resort handler: the
# parser crashed and the crash was reported as if it were an observation.
_CRASH_REASON = re.compile(r"^[A-Z][A-Za-z]*(Error|Exception)\b")


# ── TLS ───────────────────────────────────────────────────────────────────────

def check_tls_server_hello(data: bytes) -> None:
    import scanner

    with time_limit(what="parse_server_hello"):
        try:
            out = scanner.parse_server_hello(data)
        except scanner.TLSParseError:
            return
    assert set(out) == {"hello_retry", "cipher_suite", "selected_version", "key_share_group"}
    assert 0 <= out["cipher_suite"] <= 0xFFFF
    for key in ("selected_version", "key_share_group"):
        assert out[key] is None or 0 <= out[key] <= 0xFFFF


def check_tls_handshake_split(data: bytes) -> None:
    import scanner

    messages, rest = scanner.split_handshake_messages(data)
    assert sum(4 + len(body) for _t, body in messages) + len(rest) == len(data)
    assert len(rest) < 4 or int.from_bytes(rest[1:4], "big") > len(rest) - 4


def check_tls_first_flight(data: bytes, chunk: int = 16384) -> None:
    """The server's first flight, read through the real record reader from a fake socket."""
    import scanner

    peer = FakePeer(data, chunk)
    reader = scanner._RecordReader(peer, time.monotonic() + 3600)
    with time_limit(what="read_key_exchange_group"):
        try:
            group, _hrr, reason = scanner.read_key_exchange_group(reader)
        except scanner.TLSParseError:
            return
    assert reader.received <= scanner._TLS_MAX_FIRST_FLIGHT
    assert (group is None) == bool(reason), (group, reason)
    assert group is None or 0 <= group <= 0xFFFF


def check_tls_probe(data: bytes, chunk: int = 16384) -> None:
    """scanner._probe_key_exchange_group end to end against a fake server sending `data`."""
    import scanner

    _warm_up("tls", lambda: (scanner._build_client_hello("warm.example"), scanner._scope_refusal("warm.example")))
    peer = FakePeer(data, chunk)
    original = scanner.socket.create_connection
    scanner.socket.create_connection = lambda *_a, **_k: peer
    try:
        with time_limit(what="_probe_key_exchange_group"):
            out = scanner._probe_key_exchange_group("fuzz.example", 443, timeout=5)
    finally:
        scanner.socket.create_connection = original
    reason = out["key_exchange_unobservable_reason"]
    assert out["key_exchange_observed"] is not bool(reason), out
    assert not _CRASH_REASON.match(reason), f"parser crash reported as a reason: {reason}"
    assert peer.pos <= scanner._TLS_MAX_FIRST_FLIGHT + 16384


def check_x509_der(data: bytes) -> None:
    """A certificate as the server presented it: every fact extraction must survive it."""
    from cryptography import x509

    import scanner

    try:
        cert = x509.load_der_x509_certificate(data)
    except ValueError:
        return
    with time_limit(what="_leaf_cert_facts"):
        facts = scanner._leaf_cert_facts(cert)
        chain = scanner._analyze_cert_chain([data])
    for key in ("subject", "issuer", "not_before", "not_after", "sig_algorithm", "key_type"):
        assert isinstance(facts[key], str), key
    assert isinstance(facts["key_bits"], int)
    assert chain["chain_length"] <= 1


# ── IKE ───────────────────────────────────────────────────────────────────────

def check_ike_sa_init(data: bytes) -> None:
    import ike_scanner as ike

    with time_limit(what="parse_sa_init_response"):
        try:
            parsed = ike.parse_sa_init_response(data)
        except ValueError:
            return
        verdict, detail = ike.classify_response(parsed)
        result = {"responder_notifies": [], "vendor_ids": []}
        ike._record_responder(result, parsed)
        if "transforms" in detail:
            ike._selected(detail["transforms"])
        if detail.get("preferred_ke") is not None:
            ike._describe(ike.T_KE, detail["preferred_ke"])
    assert verdict in ("accepted", "rejected", "cookie", "error")
    assert sum(len(n["data"]) for n in parsed["notifies"]) <= len(data)
    assert len(parsed["transforms"]) <= len(data) // 8
    assert sum(len(v) // 2 for v in parsed["vendor_ids"]) <= len(data)
    if verdict == "cookie":
        assert 1 <= len(detail["cookie"]) <= ike._MAX_COOKIE


def check_ikev1(data: bytes) -> None:
    import ike_scanner as ike

    icookie = data[:8] if len(data) >= 8 else b"\x00" * 8
    with time_limit(what="parse_ikev1_response"):
        try:
            out = ike.parse_ikev1_response(data, icookie)
        except ValueError:
            return
    assert set(out) == {"accepted", "transform", "notify"}


# ── SSH ───────────────────────────────────────────────────────────────────────

def check_ssh_kexinit(data: bytes) -> None:
    import ssh_scanner as ssh

    with time_limit(what="parse_kexinit"):
        try:
            lists = ssh.parse_kexinit(data)
        except ssh.SSHParseError:
            return
    assert sum(len(",".join(v)) for v in lists.values()) <= len(data)


def check_ssh_packet(data: bytes) -> None:
    import ssh_scanner as ssh

    with time_limit(what="ssh packet framing"):
        try:
            pkt_len = ssh.parse_packet_length(data[:4])
            payload = ssh.parse_packet_body(data[4:4 + pkt_len])
        except ssh.SSHParseError:
            return
    assert pkt_len <= ssh._MAX_PACKET
    assert len(payload) <= pkt_len - 5


class _SocketShim:
    """Stands in for the socket module inside ssh_scanner: socket.socket() returns the peer."""

    AF_INET = socket.AF_INET
    SOCK_STREAM = socket.SOCK_STREAM
    timeout = socket.timeout

    def __init__(self, peer: FakePeer):
        self._peer = peer

    def socket(self, *_a, **_k) -> FakePeer:
        return self._peer


def check_ssh_server(data: bytes, chunk: int = 4096) -> None:
    """ssh_scanner.scan_ssh end to end against a fake server that sends `data`."""
    import scanner
    import ssh_scanner as ssh

    _warm_up("ssh", lambda: scanner._scope_refusal("127.0.0.1"))
    peer = FakePeer(data, chunk)
    original = ssh.socket
    ssh.socket = _SocketShim(peer)
    try:
        with time_limit(what="scan_ssh"):
            result = ssh.scan_ssh("127.0.0.1", 22)
    finally:
        ssh.socket = original
    assert result["error"] is None or isinstance(result["error"], str)
    assert peer.pos <= 4 + ssh._MAX_PACKET + ssh._MAX_BANNER_LINE
    if result["error"] is None:
        assert result["banner"].startswith("SSH-")


# ── Passive log ingest ────────────────────────────────────────────────────────

_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
_PQ_STATUS = {"pq_safe_key_exchange", "quantum_vulnerable", "unknown"}
_HOST_RE = re.compile(r"^[0-9a-z_.:-]{1,253}$")


def check_passive_batch(fmt: str, records: Sequence[Any]) -> None:
    from services import passive_discovery as pd

    with time_limit(TIME_LIMIT + len(records) / 50, what=f"parse_batch({fmt})"):
        out = pd.parse_batch(fmt, records)
    assert out["received"] == len(records)
    assert out["parsed"] + out["skipped"] + out["unparseable"] == out["received"]
    assert len(out["unparseable_samples"]) <= 20
    for obs in out["observations"]:
        assert 1 <= obs["port"] <= 65535
        assert _HOST_RE.match(obs["host"]), obs["host"]
        assert obs["tls_version"] in _TLS_VERSIONS
        assert len(obs["cipher"]) <= 128 and len(obs["group"]) <= 64
        assert obs["pq_status"] in _PQ_STATUS


def check_passive_body(body: bytes, content_type: str = "", content_encoding: str = "") -> None:
    from services import passive_discovery as pd
    from services import passive_ingest as pi

    with time_limit(what="decode_records"):
        try:
            records = pi.decode_records(body, content_type, content_encoding)
        except pi.PayloadError as exc:
            assert exc.status in (400, 413, 415)
            return
    assert len(records) <= pi.max_lines()
    for fmt in pd.FORMATS:
        check_passive_batch(fmt, records)


_CONTENT_TYPES = ("", "application/json", "application/x-ndjson", "text/plain")


def check_passive_bytes(data: bytes) -> None:
    """Byte-level entry for Atheris: byte 0 picks the content type, the rest is the body."""
    if not data:
        return
    check_passive_body(data[1:], _CONTENT_TYPES[data[0] % len(_CONTENT_TYPES)])


# ── CBOM / SBOM import ────────────────────────────────────────────────────────

def _bom_conn() -> sqlite3.Connection:
    from services import sbom_import

    conn = sqlite3.connect(":memory:")
    sbom_import.init_tables(conn)
    return conn


def check_sbom(data: bytes) -> None:
    """POST /v1/sbom/import: parse_cyclonedx_json, classification, import_sbom."""
    from services import sbom_import as si

    with time_limit(what="parse_cyclonedx_json"):
        try:
            parsed = si.parse_cyclonedx_json(data)
        except ValueError:
            return
        for comp in parsed["components"]:
            if si._is_crypto_component(comp):
                row = si.classify_crypto_component(comp)
                for key in ("name", "version", "algorithm", "component_type", "supplier", "description"):
                    assert isinstance(row[key], str), key
                assert row["key_length"] is None or 0 < row["key_length"] <= 1 << 20
    with closing_conn() as conn, time_limit(TIME_LIMIT * 3, what="import_sbom"):
        result = si.import_sbom(conn, "org-fuzz", "fuzz.json", data)
        si.list_inventory(conn, "org-fuzz")
    assert result["crypto_component_count"] <= result["component_count"] == len(parsed["components"])


def check_cbom(data: bytes) -> None:
    """POST /v1/cbom/import: import_cbom raises only ValueError (400/413/422)."""
    from services import sbom_import as si

    with closing_conn() as conn, time_limit(TIME_LIMIT * 5, what="import_cbom"):
        try:
            result = si.import_cbom(conn, "org-fuzz", "fuzz.json", data)
        except ValueError:
            return
        si.list_inventory(conn, "org-fuzz")
    assert result["crypto_component_count"] <= result["component_count"]


def check_cbom_ingest(data: bytes) -> None:
    """POST /v1/cbom/ingest and the signed CI path: parse_payload then ingest_cbom."""
    from services import cbom_webhook

    with time_limit(what="cbom_webhook.parse_payload"):
        try:
            payload = cbom_webhook.parse_payload(data)
        except (ValueError, OverflowError):
            return
    with closing_conn(webhook=True) as conn, time_limit(what="cbom_webhook.ingest_cbom"):
        out = cbom_webhook.ingest_cbom(conn, "org-fuzz", payload)
    assert out["summary"]["total_components"] <= len(payload.get("components") or [])


@contextlib.contextmanager
def closing_conn(webhook: bool = False) -> Iterator[sqlite3.Connection]:
    conn = _bom_conn()
    if webhook:
        from services import cbom_webhook

        cbom_webhook.init_tables(conn)
    try:
        yield conn
    finally:
        conn.close()


# ── Certificate-manager API fields (services/cert_inventory) ──────────────────

def check_cert_inventory_value(value: Any) -> None:
    from services import cert_inventory as ci

    with time_limit(what="cert_inventory field parsing"):
        date = ci._date(value)
        family = ci._family(value)
        size = ci._int(value)
        curve = ci._curve(value)
        ci._fp(value)
        ci._b64len_bits(value)
        ci._csr_key(value)
        item = ci._item(key_algorithm=family, key_size=size, curve=curve, algorithm_detail=str(value)[:200],
                        signature_algorithm=str(value)[:100], fingerprint=value, not_after=date)
        verdict = ci.classify(item)
    assert isinstance(date, str) and len(date) <= 40
    assert isinstance(verdict["quantum_vulnerable"], bool)


def mutate(data: bytes, ops: List[tuple]) -> bytes:
    """Apply (kind, position, value) byte mutations; shared by the Hypothesis strategies."""
    buf = bytearray(data)
    for kind, pos, value in ops:
        at = pos % (len(buf) + 1)
        if kind == 0 and buf:                                  # overwrite one byte
            buf[at % len(buf)] = value & 0xFF
        elif kind == 1:                                        # insert bytes
            buf[at:at] = bytes([value & 0xFF]) * (1 + (value >> 8) % 64)
        elif kind == 2:                                        # delete a slice
            del buf[at:at + 1 + value % 64]
        elif kind == 3:                                        # truncate
            del buf[at:]
        elif kind == 4 and len(buf) >= 2:                      # an "interesting" 16-bit length
            v = (0, 1, 3, 4, 0x7F, 0x80, 0xFF, 0x100, 0x3FFF, 0x4000, 0x7FFF, 0xFFFF)[value % 12]
            i = at % (len(buf) - 1)
            buf[i:i + 2] = v.to_bytes(2, "big")
        elif kind == 5 and len(buf) >= 4:                      # an "interesting" 32-bit length
            v = (0, 1, 4, 5, 0xFFFF, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF)[value % 8]
            i = at % (len(buf) - 3)
            buf[i:i + 4] = v.to_bytes(4, "big")
    return bytes(buf)
