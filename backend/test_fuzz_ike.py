"""Fuzz: IKE_SA_INIT / IKEv1 response parsing in ike_scanner (transforms, notifies, RFC 9370 ADDKE).

Seeds are the datagrams strongSwan 6.1.0 sent back to the scanner (tests/fixtures/ike). Property:
only ValueError escapes (the transport retries on it), parsed lengths stay within the datagram,
and an echoed COOKIE is at most 64 bytes.
"""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import ike_scanner as ike  # noqa: E402
from fuzz import checks  # noqa: E402
from fuzz.hypo import byte_inputs, fuzz_settings  # noqa: E402


@fuzz_settings(400)
@given(byte_inputs("ike"))
def test_sa_init_response_parser(data):
    checks.check_ike_sa_init(data)


@fuzz_settings(300)
@given(byte_inputs("ikev1"))
def test_ikev1_response_parser(data):
    checks.check_ikev1(data)


_TRANSFORM = st.tuples(st.sampled_from([1, 2, 3, 4, *ike.T_ADDKE]), st.integers(0, 0xFFFF),
                       st.one_of(st.none(), st.integers(0, 0xFFFF)))


def _response(spi, payloads):
    body = b""
    for idx, (ptype, pbody) in enumerate(payloads):
        nxt = payloads[idx + 1][0] if idx + 1 < len(payloads) else ike.P_NONE
        body += ike._payload(nxt, pbody)
    first = payloads[0][0] if payloads else ike.P_NONE
    return spi + b"\x22" * 8 + struct.pack(">BBBBII", first, 0x20, 34, 0x20, 0, 28 + len(body)) + body


@fuzz_settings(200)
@given(transforms=st.lists(_TRANSFORM, min_size=1, max_size=20),
       notifies=st.lists(st.tuples(st.integers(0, 0xFFFF), st.binary(max_size=80)), max_size=5))
def test_well_formed_response_round_trips(transforms, notifies):
    """A spec-shaped IKE_SA_INIT response yields exactly the transforms and notifies it carries."""
    spi = b"\x11" * 8
    proposal = ike._proposal(1, transforms, last=True)
    payloads = [(ike.P_SA, proposal)]
    payloads += [(ike.P_NOTIFY, ike._notify(t, d)) for t, d in notifies]
    parsed = ike.parse_sa_init_response(_response(spi, payloads), spi)
    assert parsed["transforms"] == [(t, i, k or None) for t, i, k in transforms]   # keylen 0: no attribute
    assert [(n["type"], n["data"]) for n in parsed["notifies"]] == notifies


def test_transform_overrunning_its_proposal_is_a_valueerror():
    """Regression: a transform whose length ran past the proposal had its attributes read from
    the bytes after it, and struct.error escaped once they ran past the payload."""
    attrs = struct.pack(">HH", 0x800E, 256)
    transform = struct.pack(">BBHBBH", 0, 0, 8 + 200, ike.T_ENCR, 0, 20) + attrs   # claims 208 bytes
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    data = _response(b"\x11" * 8, [(ike.P_SA, proposal)])
    with pytest.raises(ValueError):
        ike.parse_sa_init_response(data)


def test_ikev2_answer_to_ikev1_probe_with_a_short_notify_is_a_valueerror():
    """Regression: a NOTIFY header claiming 8 bytes at the end of the datagram raised
    struct.error from parse_ikev1_response."""
    icookie = b"A" * 8
    data = icookie + b"\x00" * 8 + struct.pack(">BBBBII", 41, 0x20, 2, 0, 0, 32) + bytes([0, 0, 0, 8])
    with pytest.raises(ValueError):
        ike.parse_ikev1_response(data, icookie)


def test_oversized_cookie_is_not_echoed():
    """RFC 7296 section 2.6 caps a COOKIE at 64 octets; a responder could otherwise make every
    retry carry up to 16 KB of its choosing."""
    spi = b"\x11" * 8
    parsed = ike.parse_sa_init_response(_response(spi, [(ike.P_NOTIFY, ike._notify(ike.N_COOKIE, b"c" * 65))]), spi)
    assert ike.classify_response(parsed)[0] != "cookie"
    parsed = ike.parse_sa_init_response(_response(spi, [(ike.P_NOTIFY, ike._notify(ike.N_COOKIE, b"c" * 64))]), spi)
    assert ike.classify_response(parsed) == ("cookie", {"cookie": b"c" * 64})
