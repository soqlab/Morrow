"""Fuzz: the TLS scanner's ServerHello / first-flight parser and X.509 fact extraction.

Properties (fuzz/checks.py): only TLSParseError escapes the parsers, every input finishes within
the time limit, the record reader never buffers past _TLS_MAX_FIRST_FLIGHT, a parser crash is
never reported as an "unobservable" reason, and certificate fact extraction survives any
certificate that cryptography loads.
"""

from __future__ import annotations

import socket
import struct

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import scanner  # noqa: E402
from fuzz import checks  # noqa: E402
from fuzz.hypo import byte_inputs, fuzz_settings, seed_files, seeds  # noqa: E402

CHUNKS = st.sampled_from([1, 2, 5, 13, 16384])


@fuzz_settings(300)
@given(byte_inputs("tls_server_hello"))
def test_server_hello_parser(data):
    checks.check_tls_server_hello(data)


@fuzz_settings(300)
@given(byte_inputs("tls_flight"), CHUNKS)
def test_first_flight_reader(data, chunk):
    checks.check_tls_first_flight(data, chunk)


@fuzz_settings(150)
@given(byte_inputs("tls_flight"), CHUNKS)
def test_key_exchange_probe_end_to_end(data, chunk):
    checks.check_tls_probe(data, chunk)


@fuzz_settings(200)
@given(st.binary(max_size=512))
def test_handshake_splitter_accounts_for_every_byte(data):
    checks.check_tls_handshake_split(data)


@fuzz_settings(200)
@given(byte_inputs("x509", max_size=2048))
def test_certificate_fact_extraction(data):
    checks.check_x509_der(data)


def _u16(v):
    return struct.pack(">H", v)


_EXTENSION = st.tuples(st.integers(0, 0xFFFF).filter(lambda t: t not in (0x0033, 0x002B)),
                       st.binary(max_size=40))


@fuzz_settings(200)
@given(sid=st.binary(max_size=32), suite=st.integers(0, 0xFFFF), group=st.integers(0, 0xFFFF),
       key=st.binary(min_size=1, max_size=200), others=st.lists(_EXTENSION, max_size=6, unique_by=lambda e: e[0]),
       hrr=st.booleans())
def test_well_formed_server_hello_round_trips(sid, suite, group, key, others, hrr):
    """Any spec-shaped ServerHello is parsed, and yields exactly the group it carries."""
    random = scanner._HRR_RANDOM if hrr else b"\x01" * 32
    key_share = _u16(group) if hrr else _u16(group) + _u16(len(key)) + key
    exts = b"".join(_u16(t) + _u16(len(b)) + b for t, b in others)
    exts += _u16(0x0033) + _u16(len(key_share)) + key_share
    body = _u16(0x0303) + random + bytes([len(sid)]) + sid + _u16(suite) + b"\x00" + _u16(len(exts)) + exts
    out = scanner.parse_server_hello(body)
    assert out["key_share_group"] == group
    assert out["cipher_suite"] == suite
    assert out["hello_retry"] is hrr


@pytest.mark.parametrize("path", seed_files("tls_flight", regressions=False), ids=lambda p: p.stem)
def test_seed_flights_are_read_not_rejected(path):
    """The seeds (spec-shaped flights and real OpenSSL captures) parse: the fuzz targets start
    from valid inputs, not from garbage the parser rejects at the first byte."""
    peer = checks.FakePeer(path.read_bytes())
    group, _hrr, reason = scanner.read_key_exchange_group(scanner._RecordReader(peer, 1e12))
    if path.stem.startswith("alert"):
        assert "alert" in reason
    elif "static-rsa" in path.stem:
        assert group is None and reason
    else:
        assert group is not None, reason


class _TricklingPeer(checks.FakePeer):
    """Sends one byte per recv, each recv costing one second on the fake clock."""

    def __init__(self, data, clock):
        super().__init__(data, chunk=1)
        self.clock = clock

    def recv(self, n):
        self.clock[0] += 1.0
        return super().recv(n)


def test_trickling_server_is_cut_off_by_the_overall_deadline():
    """Regression: a server sending one byte just inside the per-recv timeout held the probe for
    as long as it liked (a 16 KB record, one byte every 5 s, is almost a day)."""
    clock = [0.0]
    record = bytes([22, 3, 3]) + _u16(16384) + b"\x00" * 16384
    peer = _TricklingPeer(record, clock)
    reader = scanner._RecordReader(peer, deadline=12.0, clock=lambda: clock[0])
    with pytest.raises(socket.timeout):
        scanner.read_key_exchange_group(reader)
    assert peer.recv_calls <= 13


def test_oversized_record_length_is_refused_before_reading_it():
    data = bytes([22, 3, 3]) + _u16(0xFFFF)
    with pytest.raises(scanner.TLSParseError):
        scanner.read_key_exchange_group(scanner._RecordReader(checks.FakePeer(data), 1e12))


def test_mldsa_certificate_is_not_reported_as_dsa():
    """Regression: _pk_details matched "DSA" inside "MLDSA65PublicKey", so a post-quantum ML-DSA
    certificate was reported as classical, Shor-breakable DSA."""
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from cryptography import x509

    for data in seeds("x509"):
        cert = x509.load_der_x509_certificate(data)
        if "MLDSA" in type(cert.public_key()).__name__.upper():
            facts = scanner._leaf_cert_facts(cert)
            assert facts["key_type"] == "ML-DSA"
            assert facts["key_detail"].startswith("ML-DSA-")
            return
    pytest.skip("no ML-DSA seed certificate (cryptography without ML-DSA)")


def test_certificate_with_an_unloadable_key_still_yields_facts():
    """Regression: a certificate whose public key cryptography cannot load (an algorithm it does
    not implement) made _leaf_cert_facts raise, and the whole scan reported an error."""
    from cryptography import x509

    oid = b"\x06\x03\x2b\x65\x70"                                       # 1.3.101.112, Ed25519
    ed = next(d for d in seeds("x509") if d.count(oid) == 3)
    # The OID appears as the TBS signature algorithm, in the SubjectPublicKeyInfo, and as the outer
    # signature algorithm; only the second is the key's. 1.3.101.127 is unassigned.
    first = ed.index(oid)
    second = ed.index(oid, first + 1)
    data = ed[:second] + b"\x06\x03\x2b\x65\x7f" + ed[second + len(oid):]
    cert = x509.load_der_x509_certificate(data)
    facts = scanner._leaf_cert_facts(cert)
    assert facts["key_type"] == "UNKNOWN"
    assert facts["key_detail"] == "1.3.101.127"
    assert facts["subject"]
