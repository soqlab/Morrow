"""IKEv2 scanner (ike_scanner.py): packet format, recorded strongSwan responses, scope refusal, API.

The fixtures under tests/fixtures/ike/ are the datagrams a real strongSwan 6.1.0 responder sent back
to scan_ike, recorded in probe order (configs in tests/fixtures/strongswan/). Replaying them through
the scanner checks the whole enumeration and classification offline: the scanner sends the same
probes in the same order, so response N answers probe N. The live counterpart, against running
containers, is test_ike_scanner_strongswan.py.
"""
from __future__ import annotations

import json
import pathlib
import socket
import struct

import pytest

import ike_scanner as ike

FIXTURES = pathlib.Path(__file__).resolve().parent / "tests" / "fixtures" / "ike"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class _ReplayProber:
    """Stands in for ike_scanner._Prober and answers each exchange with the next recorded datagram."""

    responses: list = []

    def __init__(self, ip, port, family, nat_t=False):
        self.ip, self.port, self.nat_t = ip, port, nat_t
        self.local = ("192.0.2.10", 40000)
        self.sent = 0
        self.silent = 0
        self._i = 0
        self.requests = []

    def close(self):
        pass

    def exchange(self, packet, accept):
        self.requests.append(packet)
        resp = self.responses[self._i] if self._i < len(self.responses) else None
        self._i += 1
        if resp is None:
            return None
        data = bytes.fromhex(resp)
        if self.nat_t:  # recorded off the wire: strip the non-ESP marker as _Prober does
            assert data[:4] == b"\x00\x00\x00\x00"
            data = data[4:]
        # The recorded run used other random SPIs; answer for this probe's IKE SA.
        data = packet[:8] + data[8:]
        try:
            return accept(data)
        except (ValueError, struct.error, IndexError):
            return None


@pytest.fixture
def replay(monkeypatch):
    def run(fixture, **kwargs):
        rec = _load(fixture) if isinstance(fixture, str) else fixture
        _ReplayProber.responses = rec["responses"]
        monkeypatch.setattr(ike, "_Prober", _ReplayProber)
        monkeypatch.setattr(ike, "_resolve", lambda host, port: ("192.0.2.1", socket.AF_INET))
        return ike.scan_ike("vpn.example.test", rec["port"], nat_t=rec["nat_t"], **kwargs)
    return run


def _names(items):
    return [i["name"] for i in items]


# ── recorded strongSwan responders ────────────────────────────────────────────

def test_pq_optional_responder(replay):
    """swanctl.conf: aes256gcm16-prfsha384-x25519-ke1_mlkem768, aes256-sha256-modp2048."""
    r = replay("strongswan-pq-optional.json")
    assert r["responded"] and r["error"] is None
    sel = r["selected_proposal"]
    assert sel["encryption"]["name"] == "AES_GCM_16_256"
    assert sel["prf"]["name"] == "HMAC_SHA2_384"
    assert sel["key_exchange"]["name"] == "CURVE25519"
    assert sel["additional_key_exchange_1"]["name"] == "ML_KEM_768"
    assert _names(r["accepted_encryption"]) == ["AES_CBC_256", "AES_GCM_16_256"]
    assert _names(r["accepted_prf"]) == ["HMAC_SHA2_256", "HMAC_SHA2_384"]
    assert _names(r["accepted_integrity"]) == ["HMAC_SHA2_256_128"]
    assert _names(r["accepted_key_exchange"]) == ["MODP_2048", "CURVE25519"]
    assert {k: _names(v) for k, v in r["accepted_additional_key_exchange"].items()} == {"ADDKE1": ["ML_KEM_768"]}
    assert r["pq_key_exchange"] == ["ML_KEM_768"] and r["pq_ready"] is True
    assert r["classical_only_accepted"] is True and r["pq_required"] is False
    assert r["quantum_risk_level"] == "medium"
    assert [f["rule_id"] for f in r["findings"]] == ["IKE_PQ_OPTIONAL", "IKE_PQ_HYBRID_AVAILABLE"]
    assert "INTERMEDIATE_EXCHANGE_SUPPORTED" in _names(r["responder_notifies"])
    assert r["ikev1"] == {"probed": True, "enabled": False, "transform": None, "answered": True,
                          "response": "INVALID_MAJOR_VERSION"}


def test_pq_optional_responder_over_nat_t(replay):
    """The same responder on UDP 4500: every probe carries, and every answer strips, the non-ESP marker."""
    r = replay("strongswan-pq-optional-natt.json")
    assert r["nat_t"] is True and r["port"] == 4500
    assert r["pq_key_exchange"] == ["ML_KEM_768"] and r["quantum_risk_level"] == "medium"
    assert _names(r["accepted_key_exchange"]) == ["MODP_2048", "CURVE25519"]


def test_pq_required_responder(replay):
    """swanctl-pq-required.conf: every proposal needs ADDKE1 = ML-KEM-768 or ML-KEM-1024."""
    r = replay("strongswan-pq-required.json")
    assert {k: _names(v) for k, v in r["accepted_additional_key_exchange"].items()} == {
        "ADDKE1": ["ML_KEM_768", "ML_KEM_1024"]}
    assert r["classical_only_accepted"] is False and r["pq_required"] is True
    assert r["pq_key_exchange"] == ["ML_KEM_1024", "ML_KEM_768"]
    assert r["quantum_risk_level"] == "low"
    assert [f["rule_id"] for f in r["findings"]] == ["IKE_PQ_HYBRID_AVAILABLE"]
    ml = r["accepted_additional_key_exchange"]["ADDKE1"][0]
    assert ml["post_quantum"] is True and ml["algorithm"] == "ML-KEM-768" and ml["nist_pq_category"] == 3


def test_classical_responder(replay):
    """swanctl-classic.conf: aes128-sha1-modp2048, aes256-sha256-modp1024."""
    r = replay("strongswan-classical.json")
    assert r["selected_proposal"]["key_exchange"]["name"] == "MODP_2048"
    assert _names(r["accepted_key_exchange"]) == ["MODP_1024", "MODP_2048"]
    assert r["accepted_additional_key_exchange"] == {} and r["pq_key_exchange"] == []
    assert r["quantum_risk_level"] == "high" and r["pq_ready"] is False
    by_rule = {f["rule_id"]: f for f in r["findings"]}
    assert by_rule["IKE_NO_PQ_KEY_EXCHANGE"]["severity"] == "high"
    assert by_rule["IKE_WEAK_DH_GROUP"]["severity"] == "critical"
    assert by_rule["IKE_WEAK_DH_GROUP"]["evidence"]["groups"] == ["MODP_1024"]
    assert set(by_rule["IKE_WEAK_INTEGRITY"]["evidence"]["algorithms"]) == {"HMAC_SHA1", "HMAC_SHA1_96"}
    assert by_rule["IKE_128_BIT_SYMMETRIC"]["evidence"]["algorithms"] == ["AES_CBC_128"]
    # Morrow's knowledge base (services/cbom._ALG): finite-field DH has no post-quantum security.
    assert all(k["nist_pq_category"] == 0 for k in r["accepted_key_exchange"])


def test_unanswered_responder_is_unknown_not_low(replay):
    r = replay({"port": 500, "nat_t": False, "responses": [None] * 10})
    assert r["responded"] is False and r["error_code"] == "TIMEOUT"
    assert r["quantum_risk_level"] == "unknown"
    assert [f["rule_id"] for f in r["findings"]] == ["SCAN_FAILED"]
    assert r["probes_sent"] == 1  # nothing answered the first probe, so nothing else was sent


def _offered_and_ke(packet):
    """(KE transform IDs offered, KE payload group) of a request, read with the scanner's parser."""
    as_resp = bytearray(packet)
    as_resp[19] |= 0x20
    parsed = ike.parse_sa_init_response(bytes(as_resp))
    # parse_sa_init_response reads the first proposal only; read the rest from the SA payload.
    return {tid for t, tid, _k in parsed["transforms"] if t == ike.T_KE}, parsed["ke_group"]


def test_enumeration_probes_create_no_responder_state(monkeypatch):
    """Only the first probe carries a KE payload the responder could accept; every enumeration
    probe names a group it does not offer, so an acceptable proposal is answered with
    INVALID_KE_PAYLOAD and the responder keeps no half-open SA."""
    rec = _load("strongswan-pq-required.json")
    _ReplayProber.responses = rec["responses"]
    probers = []

    class Recording(_ReplayProber):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            probers.append(self)

    monkeypatch.setattr(ike, "_Prober", Recording)
    monkeypatch.setattr(ike, "_resolve", lambda host, port: ("192.0.2.1", socket.AF_INET))
    ike.scan_ike("vpn.example.test", 500, probe_ikev1=False)
    sa_init = [p for p in probers[0].requests if p[18] == 34]
    assert sa_init[0][28:] and _offered_and_ke(sa_init[0])[1] == 31
    for pkt in sa_init[1:]:
        offered, ke = _offered_and_ke(pkt)
        assert ke in ike._SENTINEL_GROUPS and ke not in offered


def _notify_response(spi, ntype):
    body = struct.pack(">BBH", 0, 0, 8) + struct.pack(">BBH", 0, 0, ntype)
    return (spi + b"\x05" * 8 + struct.pack(">BBBBII", 41, 0x20, 34, 0x20, 0, 28 + len(body)) + body).hex()


def test_falls_back_when_sentinel_is_answered_with_an_error(replay):
    """A responder that rejects the sentinel KE payload with INVALID_SYNTAX instead of
    INVALID_KE_PAYLOAD gets matching KE payloads from then on."""
    accepted = next(r for r in _load("strongswan-pq-optional.json")["responses"] if r)
    responses = [accepted, _notify_response(b"\x00" * 8, ike.N_INVALID_SYNTAX), accepted] + [None] * 10
    r = replay({"port": 500, "nat_t": False, "responses": responses}, probe_ikev1=False)
    assert r["responded"] and r["classical_only_accepted"] is True


# ── packet format ─────────────────────────────────────────────────────────────

def test_sa_init_request_layout():
    spi = bytes(range(8))
    pkt = ike.build_sa_init(spi, [[(1, 20, 256), (2, 6, None), (4, 31, None), (6, 36, None)]],
                            31, b"\x11" * 32, b"\x22" * 32, nat_src=b"\x33" * 20, nat_dst=b"\x44" * 20)
    assert pkt[:8] == spi and pkt[8:16] == b"\x00" * 8
    nxt, ver, exch, flags, msgid, length = struct.unpack(">BBBBII", pkt[16:28])
    assert (nxt, ver, exch, flags, msgid, length) == (33, 0x20, 34, 0x08, 0, len(pkt))
    # The responder's view of it: flip to a response and parse with the scanner's own parser.
    as_resp = bytearray(pkt)
    as_resp[19] = 0x20
    parsed = ike.parse_sa_init_response(bytes(as_resp), spi)
    assert parsed["transforms"] == [(1, 20, 256), (2, 6, None), (4, 31, None), (6, 36, None)]
    assert parsed["ke_group"] == 31
    assert {n["name"] for n in parsed["notifies"]} == {
        "NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP",
        "IKEV2_FRAGMENTATION_SUPPORTED", "INTERMEDIATE_EXCHANGE_SUPPORTED"}


def test_cookie_notify_goes_first():
    pkt = ike.build_sa_init(b"\x01" * 8, [[(1, 12, 128), (2, 5, None), (3, 12, None), (4, 14, None)]],
                            14, b"\x00" * 256, b"\x00" * 32, cookie=b"\xaa" * 16)
    assert pkt[16] == 41  # first payload is the COOKIE notify (RFC 7296 section 2.6)
    assert struct.unpack_from(">H", pkt, 28 + 6)[0] == ike.N_COOKIE


def test_iana_ml_kem_transform_ids():
    # IANA IKEv2 Transform Type 4 (Key Exchange Method) IDs 35-37, draft-ietf-ipsecme-ikev2-mlkem.
    assert (ike.KE_NAMES[35], ike.KE_NAMES[36], ike.KE_NAMES[37]) == ("ML_KEM_512", "ML_KEM_768", "ML_KEM_1024")
    assert ike.PQ_KE == {35, 36, 37}
    assert ike.T_ADDKE == (6, 7, 8, 9, 10, 11, 12)  # RFC 9370 ADDKE1..7


def test_ke_public_values_have_registry_sizes():
    sizes = {31: 32, 32: 56, 19: 64, 20: 96, 21: 132, 14: 256, 2: 128}
    for group, size in sizes.items():
        assert len(ike._ke_public(group)) == size, group


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("strongswan-*.json")))
def test_parser_never_raises_anything_but_valueerror_on_truncation(fixture):
    for resp in _load(fixture)["responses"][:20]:
        if not resp:
            continue
        data = bytes.fromhex(resp)
        for cut in range(0, len(data), 7):
            try:
                ike.parse_sa_init_response(data[:cut])
            except (ValueError, struct.error):
                pass


def test_spi_with_leading_zero_bytes_is_not_mistaken_for_a_nat_t_marker():
    spi = b"\x00\x00\x00\x00\x12\x34\x56\x78"
    parsed = ike.parse_sa_init_response(bytes.fromhex(_notify_response(spi, ike.N_NO_PROPOSAL_CHOSEN)), spi)
    assert ike.classify_response(parsed)[0] == "rejected"


def test_response_for_another_sa_is_ignored():
    resp = next(r for r in _load("strongswan-classical.json")["responses"] if r)
    with pytest.raises(ValueError):
        ike.parse_sa_init_response(bytes.fromhex(resp), b"\xff" * 8)


def test_ikev1_main_mode_offer_and_answer():
    icookie = b"\x07" * 8
    pkt = ike.build_ikev1_main_mode(icookie)
    assert pkt[:8] == icookie and pkt[17] == 0x10 and pkt[18] == 2  # IKEv1, Identity Protection
    # A responder answering with one chosen transform: AES-256 / SHA2-256 / PSK / MODP-2048.
    attrs = struct.pack(">HHHHHHHHHH", 0x8001, 7, 0x8002, 4, 0x8003, 1, 0x8004, 14, 0x800E, 256)
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack(">II", 1, 1) + proposal
    body = struct.pack(">BBH", 0, 0, 4 + len(sa)) + sa
    resp = icookie + b"\x09" * 8 + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(body)) + body
    out = ike.parse_ikev1_response(resp, icookie)
    assert out["accepted"] is True
    assert out["transform"] == {"encryption": "AES_CBC_256", "hash": "SHA2_256", "auth": "PSK", "group": "MODP_2048"}


def test_parse_target():
    assert ike.parse_target("vpn.example.com") == ("vpn.example.com", 500)
    assert ike.parse_target("vpn.example.com:4500") == ("vpn.example.com", 4500)
    assert ike.parse_target("[2001:db8::1]:500") == ("2001:db8::1", 500)


# ── scope refusal and API ─────────────────────────────────────────────────────

def test_scope_refusal_before_any_packet(monkeypatch):
    import scanner

    monkeypatch.setattr(scanner, "_scope_refusal", lambda host: "Not a verified domain.")

    def no_socket(*a, **k):
        raise AssertionError("a socket was opened for a refused host")

    monkeypatch.setattr(ike.socket, "socket", no_socket)
    monkeypatch.setattr(ike.socket, "getaddrinfo", no_socket)
    r = ike.scan_ike("vpn.unverified.example", 500)
    assert r["error_code"] == "NOT_PERMITTED" and r["probes_sent"] == 0 and r["findings"] == []
