"""Pre-flight: the verdict, the hellos, one attempt, the guard and budgets, the API, the inside test.

No public network. The verdict is pure and tested on recorded and made-up handshakes; one attempt on
scripted sockets (timeouts, resets, alerts, ServerHellos); the guard with alert_routing.resolve_host
replaced (the seam the public grade's tests use); the API through the app with the probe replaced.
Two integration tests run a real TLS server on 127.0.0.1: once directly, and once behind a tiny TCP
proxy that, like the buggy middleboxes tldr.fail describes, reads a ClientHello only once.
"""

import importlib.util
import json
import os
import pathlib
import socket
import ssl
import struct
import threading
import time

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import alert_routing as _alert_routing
from services import org_rate_limits as _limits
from services import preflight as _pf
from services import public_check as _check
from services import public_grade as _grade

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_PATH = ROOT / "tools" / "preflight" / "preflight.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("morrow_preflight_cli", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    db = tmp_path / "preflight.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PREFLIGHT_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.setattr(_grade, "own_addresses", lambda: frozenset({"203.0.113.250"}))
    _check._TABLES_READY.clear()
    _pf._TABLES_READY.clear()
    _limits.reset()
    yield db
    _check._TABLES_READY.clear()
    _pf._TABLES_READY.clear()
    _limits.reset()


def shot(kind, completed=True, ms=20, error=None, group="x25519", gid=0x001D, pq=False, size=None, segs=None,
         version="TLS 1.3", detail=""):
    """A recorded handshake in the API's shape."""
    big = kind != "classical"
    return {
        "id": kind, "completed": completed, "ms": ms if completed or error == "alert" else None,
        "error": None if completed else error, "error_detail": detail,
        "hello_bytes": size or (1756 if big else 246), "segments_sent": segs or (2 if big else 1),
        "segments_basis": "one write; MSS 1460 (assumed)", "group": group if completed else "",
        "group_id": gid if completed else None, "post_quantum": pq if completed else False,
        "hello_retry": False, "tls_version": version if completed else "",
    }


OK_C = shot("classical")
OK_PQ = shot("pq")
OK_SPLIT = shot("pq_split")
PQ_PQ = shot("pq", group="X25519MLKEM768", gid=0x11EC, pq=True)
PQ_SPLIT = shot("pq_split", group="X25519MLKEM768", gid=0x11EC, pq=True)


# ── the verdict (pure) ───────────────────────────────────────────────────────


def test_both_hellos_answered_and_a_classical_group_is_safe_to_turn_on():
    v = _pf.verdict(OK_C, OK_PQ, OK_SPLIT, host="shop.example")
    assert v["id"] == "safe_to_turn_on"
    assert v["headline"] == "Safe to turn on."
    assert "1,756 bytes in 2 TCP segments" in v["detail"] and "shop.example" in v["detail"]
    assert v["fixes"] == []


def test_the_server_choosing_x25519mlkem768_is_already_quantum_safe():
    v = _pf.verdict(OK_C, PQ_PQ, PQ_SPLIT, host="shop.example")
    assert v["id"] == "already_safe"
    assert v["headline"] == "Server already quantum-safe."
    assert "X25519MLKEM768" in v["detail"]


@pytest.mark.parametrize("error,needle", [
    ("timeout", "timed out"),
    ("reset", "reset or closed"),
    ("alert", "TLS alert"),
])
def test_classical_answered_and_post_quantum_failed_is_a_path_problem(error, needle):
    v = _pf.verdict(OK_C, shot("pq", completed=False, error=error), shot("pq_split", completed=False, error=error),
                    host="shop.example")
    assert v["id"] == "path_problem"
    assert v["headline"] == "Path problem."
    assert needle in v["detail"] and "twice" in v["detail"]
    assert "more than one TCP segment" in v["cause"]
    assert [f["title"] for f in v["fixes"]][:2] == ["Update what sits in front of the server",
                                                    "Turn on the vendor's fix for a split ClientHello"]
    assert all(f["source"] == "https://tldr.fail/" for f in v["fixes"])


def test_only_the_split_hello_failing_is_still_a_path_problem_and_says_it_is_intermittent():
    v = _pf.verdict(OK_C, OK_PQ, shot("pq_split", completed=False, error="reset"), host="shop.example")
    assert v["id"] == "path_problem"
    assert "in two parts" in v["detail"] and "at random" in v["detail"]


def test_an_unconfirmed_path_problem_says_so():
    v = _pf.verdict(OK_C, shot("pq", completed=False, error="timeout"), None, confirmed=False)
    assert v["id"] == "path_problem" and v["confirmed"] is False
    assert "twice" not in v["detail"]
    assert "unreliable" in v["notes"][0]


def test_nothing_answering_is_couldnt_test():
    dead = dict(completed=False, error="connect", detail="no TCP connection to port 443: refused")
    v = _pf.verdict(shot("classical", **dead), shot("pq", **dead), shot("pq_split", **dead))
    assert v["id"] == "couldnt_test" and v["headline"] == "Couldn't test."
    assert "Nothing accepted a connection" in v["detail"]
    v = _pf.verdict(shot("classical", completed=False, error="timeout"), shot("pq", completed=False, error="timeout"))
    assert v["id"] == "couldnt_test" and "Not even the classical hello" in v["detail"]


def test_a_tls12_server_is_told_to_turn_on_tls13_first():
    old = dict(version="TLS 1.2 or older", group="", gid=None)
    v = _pf.verdict(shot("classical", **old), shot("pq", **old), shot("pq_split", **old), host="old.example")
    assert v["id"] == "safe_to_turn_on"
    assert any("TLS 1.3" in n for n in v["notes"])


def test_a_recorded_real_answer_reads_as_already_safe():
    # Recorded from cloudflare.com on 2026-11-19 (services.preflight.run_set, from a home connection).
    recorded = json.loads(
        '[{"id":"classical","completed":true,"ms":9,"error":null,"hello_bytes":249,"segments_sent":1,"group":"x25519",'
        '"group_id":29,"post_quantum":false,"tls_version":"TLS 1.3"},{"id":"pq","completed":true,"ms":13,"error":null,'
        '"hello_bytes":1756,"segments_sent":2,"group":"X25519MLKEM768","group_id":4588,"post_quantum":true,'
        '"tls_version":"TLS 1.3"},{"id":"pq_split","completed":true,"ms":12,"error":null,"hello_bytes":1756,'
        '"segments_sent":2,"group":"X25519MLKEM768","group_id":4588,"post_quantum":true,"tls_version":"TLS 1.3"}]')
    assert _pf.verdict(*recorded, host="cloudflare.com")["id"] == "already_safe"


# ── run_set: order, the repeat, confirmation ─────────────────────────────────


def scripted(plan):
    """An attempt_fn that answers from plan[kind] (a list consumed in order) and records the calls."""
    calls = []

    def fn(address, host, port, kind, timeout=None):
        calls.append(kind)
        return dict(plan[kind].pop(0))
    return fn, calls


def test_run_set_sends_classical_pq_then_split_and_nothing_more_when_all_pass():
    fn, calls = scripted({"classical": [OK_C], "pq": [OK_PQ], "pq_split": [OK_SPLIT]})
    out = _pf.run_set("shop.example", "198.51.100.7", attempt_fn=fn)
    assert calls == ["classical", "pq", "pq_split"]
    assert out["verdict"]["id"] == "safe_to_turn_on"
    assert [h["id"] for h in out["handshakes"]] == ["classical", "pq", "pq_split"]
    assert out["handshakes"][1]["label"] == "Post-quantum hello"


def test_a_failure_is_repeated_once_and_a_repeat_failure_is_confirmed():
    bad = shot("pq", completed=False, error="timeout")
    fn, calls = scripted({"classical": [OK_C, OK_C], "pq": [bad, bad], "pq_split": [OK_SPLIT]})
    out = _pf.run_set("shop.example", "198.51.100.7", attempt_fn=fn)
    assert calls == ["classical", "pq", "pq_split", "classical", "pq"]
    assert out["verdict"]["id"] == "path_problem" and out["verdict"]["confirmed"] is True
    assert out["handshakes"][1]["attempts"] == 2
    assert out["handshakes"][0]["attempts"] == 2                        # the classical hello was sent again too
    measured = _pf.build_result("shop.example", 443, "198.51.100.7", out, "2026-11-19T10:00:00Z")["measured"]
    assert ": 5 ClientHellos" in measured["wording"]


def test_a_failure_that_passes_on_the_repeat_is_not_a_path_problem_but_is_noted():
    bad = shot("pq_split", completed=False, error="reset")
    fn, _calls = scripted({"classical": [OK_C, OK_C], "pq": [OK_PQ], "pq_split": [bad, OK_SPLIT]})
    out = _pf.run_set("shop.example", "198.51.100.7", attempt_fn=fn)
    assert out["verdict"]["id"] == "safe_to_turn_on"
    assert any("second try" in n for n in out["verdict"]["notes"])


def test_no_repeat_when_even_the_classical_hello_failed():
    down = shot("classical", completed=False, error="connect")
    fn, calls = scripted({"classical": [down], "pq": [shot("pq", completed=False, error="connect")],
                          "pq_split": [shot("pq_split", completed=False, error="connect")]})
    out = _pf.run_set("shop.example", "198.51.100.7", attempt_fn=fn)
    assert calls == ["classical", "pq", "pq_split"]
    assert out["verdict"]["id"] == "couldnt_test"


# ── the hellos ───────────────────────────────────────────────────────────────


def _parse_hello(record):
    assert record[0] == 0x16 and len(record) == 5 + int.from_bytes(record[3:5], "big")
    body = record[9:]
    pos = 2 + 32
    pos += 1 + body[pos]
    pos += 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 1 + body[pos]
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    exts = {}
    order = []
    while pos < end:
        t = int.from_bytes(body[pos:pos + 2], "big")
        n = int.from_bytes(body[pos + 2:pos + 4], "big")
        exts[t] = body[pos + 4:pos + 4 + n]
        order.append(t)
        pos += 4 + n
    assert pos == end == len(body)
    groups = [int.from_bytes(exts[0x0A][2 + i:4 + i], "big") for i in range(0, len(exts[0x0A]) - 2, 2)]
    shares = {}
    ks = exts[0x33][2:]
    i = 0
    while i < len(ks):
        g, n = int.from_bytes(ks[i:i + 2], "big"), int.from_bytes(ks[i + 2:i + 4], "big")
        shares[g] = n
        i += 4 + n
    return {"order": order, "groups": groups, "shares": shares, "exts": exts}


@pytest.mark.parametrize("build", [_pf.build_hello, cli.build_hello], ids=["server", "inside-test"])
def test_the_post_quantum_hello_is_browser_sized_and_the_classical_one_fits_one_segment(build):
    pq = build("shop.example.com", "pq")
    classical = build("shop.example.com", "classical")
    assert len(pq) == _pf.BROWSER_HELLO_BYTES == 1756
    assert len(pq) > _pf.ASSUMED_MSS and len(classical) < 400
    p, c = _parse_hello(pq), _parse_hello(classical)
    assert p["groups"][:2] == [0x11EC, 0x001D] and 0x11EC not in c["groups"]
    assert p["shares"] == {0x11EC: 1216, 0x001D: 32} and c["shares"] == {0x001D: 32}
    assert 0x0015 in p["exts"] and 0x0015 not in c["exts"]          # RFC 7685 padding only on the big one
    assert b"shop.example.com" in p["exts"][0x0000]
    assert p["exts"][0x0010] == b"\x00\x0c\x02h2\x08http/1.1"


def test_a_hello_already_over_the_target_is_not_padded():
    for build in (_pf.build_hello, cli.build_hello):
        hello = build("shop.example.com", "pq", target_bytes=1000)
        assert len(hello) > 1000 and 0x0015 not in _parse_hello(hello)["exts"]


def test_the_inside_test_sends_the_same_hello_shape_as_the_server():
    a, b = _parse_hello(_pf.build_hello("x.example", "pq")), _parse_hello(cli.build_hello("x.example", "pq"))
    assert a["order"] == b["order"] and a["groups"] == b["groups"] and a["shares"] == b["shares"]
    a, b = _parse_hello(_pf.build_hello("x.example", "classical")), _parse_hello(cli.build_hello("x.example", "classical"))
    assert a["order"] == b["order"] and a["groups"] == b["groups"]


def test_the_inside_tests_own_x25519_matches_rfc_7748():
    # RFC 7748 section 6.1, Alice's key pair.
    private = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    assert cli.x25519_public(private).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"


def test_the_inside_tests_ml_kem_key_is_well_formed():
    key = cli.mlkem768_encapsulation_key()
    assert len(key) == 1184
    coefficients = []
    for i in range(0, 1152, 3):
        a, b, c = key[i:i + 3]
        coefficients += [a | ((b & 0x0F) << 8), (b >> 4) | (c << 4)]
    assert len(coefficients) == 768 and max(coefficients) < 3329


# ── one attempt, on scripted sockets ─────────────────────────────────────────


def server_hello(group=0x001D, hrr=False, version=0x0304):
    exts = b""
    if version == 0x0304:
        exts += b"\x00\x2b\x00\x02" + version.to_bytes(2, "big")
    if group is not None:
        share = group.to_bytes(2, "big") if hrr else group.to_bytes(2, "big") + b"\x00\x20" + b"\x11" * 32
        exts += b"\x00\x33" + len(share).to_bytes(2, "big") + share
    random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") if hrr else b"\x22" * 32
    body = b"\x03\x03" + random + b"\x20" + b"\x33" * 32 + b"\x13\x01\x00" + len(exts).to_bytes(2, "big") + exts
    msg = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(msg).to_bytes(2, "big") + msg


class FakeSock:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.options = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def setsockopt(self, *args):
        self.options.append(args)

    def getsockopt(self, *args):
        raise OSError("not supported")

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, n):
        if not self.chunks:
            return b""
        item = self.chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def connect_to(sock):
    def connect(addr, timeout=None):
        if isinstance(sock, BaseException):
            raise sock
        return sock
    return connect


@pytest.mark.parametrize("module", [_pf, cli], ids=["server", "inside-test"])
def test_an_answered_hello_records_group_version_size_and_time(module):
    sock = FakeSock([server_hello(0x11EC)])
    out = module.attempt("198.51.100.7", "shop.example", 443, "pq", timeout=2, connect=connect_to(sock))
    assert out["completed"] is True and out["error"] is None
    assert out["group"] == "X25519MLKEM768" and out["post_quantum"] is True and out["tls_version"] == "TLS 1.3"
    assert out["hello_bytes"] == 1756 and out["segments_sent"] == 2 and "1460 (assumed)" in out["segments_basis"]
    assert isinstance(out["ms"], int)
    assert len(sock.sent) == 1 and len(sock.sent[0]) == 1756


@pytest.mark.parametrize("module", [_pf, cli], ids=["server", "inside-test"])
def test_the_split_hello_is_written_in_two_parts_with_nagle_off_and_a_pause(module):
    sock = FakeSock([server_hello(0x001D)])
    pauses = []
    out = module.attempt("198.51.100.7", "shop.example", 443, "pq_split", timeout=2, connect=connect_to(sock),
                         sleep=pauses.append)
    assert out["completed"] is True
    assert [len(p) for p in sock.sent] == [878, 878]
    assert pauses == [0.2]
    assert (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in sock.options
    assert "two parts" in out["segments_basis"]


@pytest.mark.parametrize("module", [_pf, cli], ids=["server", "inside-test"])
def test_a_hello_retry_request_counts_as_an_answer(module):
    out = module.attempt("198.51.100.7", "h.example", 443, "classical", timeout=2,
                         connect=connect_to(FakeSock([server_hello(0x0017, hrr=True)])))
    assert out["completed"] is True and out["hello_retry"] is True and out["group"] == "secp256r1"


@pytest.mark.parametrize("module", [_pf, cli], ids=["server", "inside-test"])
@pytest.mark.parametrize("chunks,error,needle", [
    ([socket.timeout("timed out")], "timeout", "no answer within"),
    ([ConnectionResetError(10054, "reset")], "reset", "reset"),
    ([], "reset", "closed without an answer"),
    ([b"\x15\x03\x03\x00\x02\x02\x28"], "alert", "handshake_failure"),
    ([b"HTTP/1.1 400 Bad Request\r\n\r\n"], "protocol", "not TLS"),
])
def test_failures_are_named(module, chunks, error, needle):
    out = module.attempt("198.51.100.7", "h.example", 443, "pq", timeout=2, connect=connect_to(FakeSock(chunks)))
    assert out["completed"] is False and out["error"] == error
    assert needle in out["error_detail"]
    assert isinstance(out["ms"] if error == "alert" else out["failed_after_ms"], int)   # the race bar's length


@pytest.mark.parametrize("module", [_pf, cli], ids=["server", "inside-test"])
def test_no_tcp_connection_is_a_connect_error(module):
    out = module.attempt("198.51.100.7", "h.example", 443, "classical", timeout=2,
                         connect=connect_to(ConnectionRefusedError(10061, "refused")))
    assert out["error"] == "connect" and "no TCP connection" in out["error_detail"]


def test_a_server_hello_split_across_records_is_read():
    raw = server_hello(0x001D)
    msg = raw[5:]
    records = (b"\x16\x03\x03" + (10).to_bytes(2, "big") + msg[:10]
               + b"\x16\x03\x03" + (len(msg) - 10).to_bytes(2, "big") + msg[10:])
    for module in (_pf, cli):
        out = module.attempt("198.51.100.7", "h.example", 443, "classical", timeout=2,
                             connect=connect_to(FakeSock([records[:7], records[7:]])))
        assert out["completed"] is True and out["group"] == "x25519"


# ── the verdict rules agree between the server and the inside test ───────────


@pytest.mark.parametrize("c_ok", [True, False])
@pytest.mark.parametrize("pq", ["ok", "pq", "fail"])
@pytest.mark.parametrize("split", ["ok", "pq", "fail", None])
def test_the_inside_test_gives_the_same_verdict_as_the_server(c_ok, pq, split):
    def make(kind, state):
        if state is None:
            return None
        if state == "fail":
            return shot(kind, completed=False, error="timeout")
        if state == "pq":
            return shot(kind, group="X25519MLKEM768", gid=0x11EC, pq=True)
        return shot(kind)
    c = shot("classical") if c_ok else shot("classical", completed=False, error="reset")
    p, s = make("pq", pq), make("pq_split", split)
    assert cli.verdict_id(c, p, s) == _pf.verdict(c, p, s)["id"]
    assert cli.HEADLINES[cli.verdict_id(c, p, s)] == _pf.verdict(c, p, s)["headline"]


# ── a real TLS server on 127.0.0.1, directly and behind a proxy that reads once ──


@pytest.fixture
def tls_server(tmp_path):
    """A real TLS 1.2/1.3 server (Python's ssl / OpenSSL) on 127.0.0.1 that answers every hello."""
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "preflight.test")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve_one(conn):
        try:
            conn.settimeout(5)
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except Exception:
            pass

    def loop():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=serve_one, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    listener.close()
    thread.join(2)


@pytest.fixture
def reads_once_proxy(tls_server):
    """A TCP proxy in front of tls_server with the bug tldr.fail describes: it reads the ClientHello with
    one recv() and, when that read does not hold the whole TLS record, resets the connection. With
    drop_large set it instead swallows any ClientHello over 1,460 bytes (one segment) and never answers."""
    state = {"drop_large": False}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    stop = threading.Event()

    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(client):
        try:
            client.settimeout(5)
            first = client.recv(65536)
            want = 5 + int.from_bytes(first[3:5], "big") if len(first) >= 5 else 1 << 30
            if state["drop_large"] and want > 1460:
                time.sleep(8)                                  # a black hole: no answer, no reset
                client.close()
                return
            if len(first) < want:                             # read once, got half: give up, like the bug
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                  struct.pack("HH" if os.name == "nt" else "ii", 1, 0))
                client.close()
                return
            upstream = socket.create_connection(("127.0.0.1", tls_server), timeout=5)
            upstream.sendall(first)
            threading.Thread(target=pump, args=(upstream, client), daemon=True).start()
            pump(client, upstream)
        except OSError:
            pass

    def loop():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    state["port"] = listener.getsockname()[1]
    yield state
    stop.set()
    listener.close()
    thread.join(2)


def test_a_real_tls_server_answers_both_hellos_and_is_safe_to_turn_on(tls_server):
    out = _pf.run_set("preflight.test", "127.0.0.1", port=tls_server, timeout=4)
    by_id = {h["id"]: h for h in out["handshakes"]}
    assert all(h["completed"] for h in out["handshakes"]), out["handshakes"]
    assert by_id["pq"]["hello_bytes"] == 1756 and by_id["classical"]["hello_bytes"] < 400
    # This OpenSSL does not have X25519MLKEM768 (3.5+ has), so it chose a classical group.
    assert out["verdict"]["id"] in ("safe_to_turn_on", "already_safe")
    if not ssl.OPENSSL_VERSION_INFO >= (3, 5):
        assert out["verdict"]["id"] == "safe_to_turn_on" and by_id["pq"]["group"] == "x25519"


def test_the_inside_test_against_the_same_real_server(tls_server):
    result = cli.run_host({"host": "127.0.0.1", "port": tls_server, "sni": "preflight.test"}, timeout=4)
    assert result["verdict"]["id"] in ("safe_to_turn_on", "already_safe")
    assert [h["id"] for h in result["handshakes"]] == ["classical", "pq", "pq_split"]


def test_a_proxy_that_reads_the_hello_once_is_a_path_problem(reads_once_proxy):
    out = _pf.run_set("preflight.test", "127.0.0.1", port=reads_once_proxy["port"], timeout=3)
    by_id = {h["id"]: h for h in out["handshakes"]}
    assert by_id["classical"]["completed"] is True
    assert by_id["pq_split"]["completed"] is False and by_id["pq_split"]["error"] == "reset"
    assert by_id["pq_split"]["attempts"] == 2
    assert out["verdict"]["id"] == "path_problem" and out["verdict"]["confirmed"] is True
    cli_result = cli.run_host({"host": "127.0.0.1", "port": reads_once_proxy["port"], "sni": "preflight.test"},
                              timeout=3)
    assert cli_result["verdict"]["id"] == "path_problem"


def test_a_proxy_that_swallows_large_hellos_times_out_into_a_path_problem(reads_once_proxy):
    reads_once_proxy["drop_large"] = True
    out = _pf.run_set("preflight.test", "127.0.0.1", port=reads_once_proxy["port"], split=False, timeout=1.0)
    by_id = {h["id"]: h for h in out["handshakes"]}
    assert by_id["classical"]["completed"] is True
    assert by_id["pq"]["error"] == "timeout"
    assert out["verdict"]["id"] == "path_problem"
    assert "timed out" in out["verdict"]["detail"]


# ── the guard, the opt-out and the budgets ───────────────────────────────────


@pytest.fixture
def probe(monkeypatch):
    """Replace DNS (through the real guard) and the probe set. Returns a state dict to steer."""
    state = {"answers": ["93.184.216.34"], "sets": [], "outcome": {"verdict": _pf.verdict(OK_C, OK_PQ, OK_SPLIT),
                                                                   "handshakes": [OK_C, OK_PQ, OK_SPLIT]}}
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port=443: list(state["answers"]))

    def fake_run_set(host, address, port=443, split=True, timeout=None, attempt_fn=None):
        state["sets"].append((host, address, port))
        return json.loads(json.dumps(state["outcome"]))

    monkeypatch.setattr(_pf, "run_set", fake_run_set)
    return state


@pytest.mark.parametrize("address", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.1.1", "::ffff:10.0.0.1",
                                     "203.0.113.250"])
def test_the_guard_refuses_anything_but_a_public_address_and_sends_nothing(probe, address):
    probe["answers"] = [address]
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("internal.example.com", "198.51.100.1")
    assert caught.value.status_code == 403 and caught.value.error == "refused_target"
    assert probe["sets"] == []


def test_the_probe_connects_only_to_the_pinned_address(probe):
    result = _pf.check("shop.example.com", "198.51.100.1")
    assert probe["sets"] == [("shop.example.com", "93.184.216.34", 443)]
    assert result["measured"]["target"] == "93.184.216.34:443"


def test_an_opted_out_domain_is_refused_before_dns(probe, monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.org")
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda *a, **k: pytest.fail("looked up DNS"))
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("www.example.org", "198.51.100.1")
    assert caught.value.status_code == 403 and caught.value.error == "refused_optout"


@pytest.mark.parametrize("bad", ["", "https://example.com", "example.com:8443", "user@example.com", "a/b"])
def test_only_a_bare_host_name_is_accepted(probe, bad):
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check(bad, "198.51.100.1")
    assert caught.value.status_code == 400


def test_one_probe_set_per_host_per_window_whoever_asks(probe):
    first = _pf.check("shop.example.com", "198.51.100.1")
    second = _pf.check("shop.example.com", "198.51.100.2")
    assert len(probe["sets"]) == 1
    assert first["cached"] is False and second["cached"] is True
    assert second["checked_at"] == first["checked_at"]


def test_the_window_holds_across_workers_even_without_the_stored_answer(probe, monkeypatch):
    monkeypatch.setattr(_pf, "store", lambda result: None)           # another worker: nothing stored here
    _pf.check("shop.example.com", "198.51.100.1")
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("shop.example.com", "198.51.100.2")
    assert caught.value.status_code == 429 and caught.value.retry_after
    assert len(probe["sets"]) == 1


def test_the_per_address_budget(probe, monkeypatch):
    monkeypatch.setenv("MORROW_PREFLIGHT_IP_PER_MINUTE", "2")
    _pf.check("a.example.com", "198.51.100.1")
    _pf.check("b.example.com", "198.51.100.1")
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("c.example.com", "198.51.100.1")
    assert caught.value.status_code == 429


def test_the_global_budget(probe, monkeypatch):
    monkeypatch.setenv("MORROW_PREFLIGHT_GLOBAL_PER_HOUR", "1")
    _pf.check("a.example.com", "198.51.100.1")
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("b.example.com", "198.51.100.9")
    assert caught.value.status_code == 429 and "everyone" in caught.value.detail


def test_switched_off(probe, monkeypatch):
    monkeypatch.setenv("MORROW_PREFLIGHT_ENABLED", "0")
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check("a.example.com")
    assert caught.value.status_code == 503


def test_each_run_is_written_to_the_abuse_log_with_a_hashed_address(probe):
    _pf.check("shop.example.com", "198.51.100.1")
    rows = _check.recent_log(10, "shop.example.com")
    assert rows and rows[0]["outcome"] == "preflight_ok"
    assert "198.51.100.1" not in json.dumps(rows)


# ── the signed-in variant ────────────────────────────────────────────────────


def test_signed_in_only_for_hosts_under_a_verified_domain(probe, monkeypatch):
    from services import domain_verification

    monkeypatch.setattr(domain_verification, "verified_domains", lambda org: ["example.com"] if org == "org-1" else [])
    result = _pf.check_owned("org-1", "api.example.com", "8443")
    assert probe["sets"] == [("api.example.com", "93.184.216.34", 8443)]
    assert result["port"] == 8443 and "verified" in result["measured"]["from"]
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check_owned("org-1", "api.other.net", "443")
    assert caught.value.error == "not_verified"
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check_owned("org-2", "api.example.com", "443")
    assert caught.value.error == "not_verified"
    for port in ("0", "70000", "ssh"):
        with pytest.raises(_grade.GradeError) as caught:
            _pf.check_owned("org-1", "api.example.com", port)
        assert caught.value.error == "invalid_port"


def test_signed_in_still_refuses_internal_addresses(probe, monkeypatch):
    from services import domain_verification

    monkeypatch.setattr(domain_verification, "verified_domains", lambda org: ["example.com"])
    probe["answers"] = ["192.168.1.10"]
    with pytest.raises(_grade.GradeError) as caught:
        _pf.check_owned("org-1", "intranet.example.com", "443")
    assert caught.value.error == "refused_target"


# ── the API ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client(isolated_store, monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def test_the_api_answer_shape(client, probe):
    response = client.get("/api/public/preflight/shop.example.com")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["api_version"] == "preflight/1"
    assert body["domain"] == "shop.example.com" and body["port"] == 443 and body["cached"] is False
    assert set(body["verdict"]) >= {"id", "headline", "detail", "cause", "fixes", "notes", "confirmed"}
    assert body["verdict"]["id"] in _pf.VERDICTS
    assert [h["id"] for h in body["handshakes"]] == ["classical", "pq", "pq_split"]
    for h in body["handshakes"]:
        assert set(h) >= {"completed", "ms", "error", "hello_bytes", "segments_sent", "group", "post_quantum"}
    measured = body["measured"]
    assert measured["wording"].startswith("Measured from Morrow's server, on the public internet")
    assert "public path" in measured["covers"]
    assert any("inside your company" in line for line in measured["does_not_cover"])
    assert body["inside_test"]["label"] == "Test from inside your network"
    assert body["inside_test"]["script"].endswith("tools/preflight/preflight.py")
    assert any("ML-DSA" in line for line in body["not_tested"])
    assert {s["url"] for s in body["sources"]} >= {"https://tldr.fail/",
                                                   "https://blog.cloudflare.com/automatic-key-exchange-for-origins/"}
    assert body["next_check_after"] > body["checked_at"]
    again = client.get("/api/public/preflight/shop.example.com").json()
    assert again["cached"] is True and len(probe["sets"]) == 1


def test_the_api_errors(client, probe, monkeypatch):
    assert client.get("/api/public/preflight/not_a_host").status_code == 400
    probe["answers"] = ["10.1.2.3"]
    refused = client.get("/api/public/preflight/internal.example.com")
    assert refused.status_code == 403 and refused.json()["error"] == "refused_target"
    monkeypatch.setenv("MORROW_PREFLIGHT_IP_PER_MINUTE", "1")
    _limits.reset()
    probe["answers"] = ["93.184.216.34"]
    assert client.get("/api/public/preflight/a.example.com").status_code == 200
    limited = client.get("/api/public/preflight/b.example.com")
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert limited.headers["Cache-Control"] == "no-store"


def test_stored_only_never_probes(client, probe):
    missing = client.get("/api/public/preflight/shop.example.com?stored=1")
    assert missing.status_code == 404 and probe["sets"] == []
    client.get("/api/public/preflight/shop.example.com")
    hit = client.get("/api/public/preflight/shop.example.com?stored=1")
    assert hit.status_code == 200 and hit.json()["cached"] is True and len(probe["sets"]) == 1


def test_the_signed_in_route_needs_a_sign_in(client, probe):
    response = client.get("/instrument/preflight/api.example.com?port=8443")
    assert response.status_code in (401, 403)
    assert probe["sets"] == []


def test_about_scanner_says_what_a_pre_flight_sends():
    from services import watch

    facts = watch.about_scanner()
    part = [w for w in facts["what"] if w["part"] == "Pre-flight"]
    assert len(part) == 1 and "six TLS ClientHellos" in part[0]["sends"]
    assert "no HTTP request" in part[0]["sends"]


# ── the inside test's command line ───────────────────────────────────────────


@pytest.mark.parametrize("text,host,port,sni", [
    ("intranet.corp", "intranet.corp", 443, "intranet.corp"),
    ("intranet.corp:8443", "intranet.corp", 8443, "intranet.corp"),
    ("https://App.Corp.:9443/path?q=1", "app.corp", 9443, "app.corp"),
    ("10.0.0.12", "10.0.0.12", 443, ""),
    ("[fd00::12]:8443", "fd00::12", 8443, ""),
    ("fd00::12", "fd00::12", 443, ""),
])
def test_cli_targets(text, host, port, sni):
    assert cli.parse_target(text) == {"host": host, "port": port, "sni": sni}


def test_cli_sni_for_an_address():
    assert cli.parse_target("10.0.0.12:8443", sni="app.corp")["sni"] == "app.corp"


@pytest.mark.parametrize("bad", ["http://x.corp", "x.corp:0", "x.corp:99999", "x.corp:https", "user@x.corp", "[fd00::1",
                                 ""])
def test_cli_bad_targets(bad):
    with pytest.raises(ValueError):
        cli.parse_target(bad)


def _fake_run_host(verdicts):
    def run(target, timeout=6.0, split=True):
        vid = verdicts[target["host"]]
        hs = [dict(OK_C, label="Classical hello"), dict(OK_PQ, label="Post-quantum hello")]
        if vid == "path_problem":
            hs[1] = dict(shot("pq", completed=False, error="timeout", detail="no answer within 6 s"),
                         label="Post-quantum hello")
        return {"api_version": cli.API_VERSION, "domain": target["host"], "port": target["port"], "address": "10.0.0.1",
                "handshakes": hs, "verdict": {"id": vid, "headline": cli.HEADLINES[vid], "detail": "d"}}
    return run


def test_cli_text_output_and_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_host", _fake_run_host({"a.corp": "safe_to_turn_on", "b.corp": "already_safe"}))
    assert cli.main(["a.corp", "b.corp"]) == 0
    text = capsys.readouterr().out
    assert "Safe to turn on." in text and "Server already quantum-safe." in text
    assert "ok   Classical hello" in text and "1756 bytes" in text
    assert "not paths from other networks" in text
    monkeypatch.setattr(cli, "run_host", _fake_run_host({"a.corp": "path_problem", "b.corp": "couldnt_test"}))
    assert cli.main(["a.corp", "b.corp"]) == 1
    out = capsys.readouterr().out
    assert "FAIL Post-quantum hello" in out and "no answer within 6 s" in out
    monkeypatch.setattr(cli, "run_host", _fake_run_host({"a.corp": "couldnt_test"}))
    assert cli.main(["a.corp"]) == 2


def test_cli_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_host", _fake_run_host({"a.corp": "path_problem"}))
    assert cli.main(["a.corp:8443", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["api_version"] == "preflight/1" and doc["results"][0]["port"] == 8443
    assert doc["results"][0]["verdict"]["id"] == "path_problem"


def test_cli_reads_a_file_and_rejects_bad_arguments(monkeypatch, capsys, tmp_path):
    seen = []
    monkeypatch.setattr(cli, "run_host", lambda t, timeout=6.0, split=True: (seen.append((t["host"], split)),
                                                                             _fake_run_host({t["host"]: "safe_to_turn_on"})(t))[1])
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# ours\na.corp\n\nb.corp:8443  # the API\n", encoding="utf-8")
    assert cli.main(["--file", str(hosts), "--no-split"]) == 0
    assert seen == [("a.corp", False), ("b.corp", False)]
    capsys.readouterr()
    assert cli.main([]) == 64
    assert cli.main(["x.corp", "--timeout", "0"]) == 64
    assert cli.main(["ftp://x.corp"]) == 64
    assert cli.main(["--file", str(tmp_path / "missing.txt")]) == 64
    assert cli.main(["--bogus"]) == 64


def test_cli_couldnt_resolve_is_couldnt_test():
    def nope(host, port):
        raise socket.gaierror(11001, "getaddrinfo failed")
    result = cli.run_host({"host": "nowhere.corp", "port": 443, "sni": "nowhere.corp"}, resolve=nope)
    assert result["verdict"]["id"] == "couldnt_test" and "does not resolve" in result["verdict"]["detail"]


def test_cli_uses_only_the_standard_library():
    import ast
    import sys

    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    if stdlib:
        assert names <= stdlib, names - stdlib
