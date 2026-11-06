"""ike_scanner against real strongSwan responders. Skipped unless MORROW_STRONGSWAN_TARGETS is set.

Build and start the responders (configs in tests/fixtures/strongswan/; strongSwan 6.x with ML-KEM):

    docker build -t morrow-test-strongswan backend/tests/fixtures/strongswan
    docker run -d --name ss-pq --cap-add NET_ADMIN -p 127.0.0.1:15500:500/udp -p 127.0.0.1:15450:4500/udp morrow-test-strongswan
    docker run -d --name ss-classic --cap-add NET_ADMIN -p 127.0.0.1:15600:500/udp \
        -v $PWD/backend/tests/fixtures/strongswan/swanctl-classic.conf:/etc/swanctl/swanctl.conf:ro morrow-test-strongswan
    docker run -d --name ss-pqreq --cap-add NET_ADMIN -p 127.0.0.1:15700:500/udp \
        -v $PWD/backend/tests/fixtures/strongswan/swanctl-pq-required.conf:/etc/swanctl/swanctl.conf:ro morrow-test-strongswan

    MORROW_STRONGSWAN_TARGETS="pq=127.0.0.1:15500,natt=127.0.0.1:15450,classic=127.0.0.1:15600,pqreq=127.0.0.1:15700" \
        pytest test_ike_scanner_strongswan.py

Each scan takes about a minute: probes are paced (ike_scanner._PROBE_INTERVAL) and strongSwan
starts answering COOKIE challenges once enough half-open SAs accumulate.
"""
from __future__ import annotations

import os

import pytest

import ike_scanner as ike


def _targets():
    out = {}
    for item in (os.environ.get("MORROW_STRONGSWAN_TARGETS") or "").split(","):
        if "=" in item:
            name, target = item.split("=", 1)
            host, port = ike.parse_target(target.strip())
            out[name.strip()] = (host, port)
    return out


TARGETS = _targets()
pytestmark = pytest.mark.skipif(not TARGETS, reason="MORROW_STRONGSWAN_TARGETS not set")


def _scan(name, **kw):
    if name not in TARGETS:
        pytest.skip(f"no {name} responder configured")
    host, port = TARGETS[name]
    return ike.scan_ike(host, port, **kw)


def _names(items):
    return [i["name"] for i in items]


def test_pq_optional():
    r = _scan("pq")
    assert r["error"] is None, r["error"]
    assert r["selected_proposal"]["additional_key_exchange_1"]["name"] == "ML_KEM_768"
    assert {k: _names(v) for k, v in r["accepted_additional_key_exchange"].items()} == {"ADDKE1": ["ML_KEM_768"]}
    assert _names(r["accepted_key_exchange"]) == ["MODP_2048", "CURVE25519"]
    assert r["classical_only_accepted"] is True and r["quantum_risk_level"] == "medium"
    assert r["ikev1"]["enabled"] is False


def test_pq_optional_nat_t():
    r = _scan("natt", nat_t=True)
    assert r["error"] is None, r["error"]
    assert r["pq_key_exchange"] == ["ML_KEM_768"]


def test_pq_required():
    r = _scan("pqreq")
    assert r["error"] is None, r["error"]
    assert {k: _names(v) for k, v in r["accepted_additional_key_exchange"].items()} == {
        "ADDKE1": ["ML_KEM_768", "ML_KEM_1024"]}
    assert r["pq_required"] is True and r["quantum_risk_level"] == "low"


def test_classical():
    r = _scan("classic")
    assert r["error"] is None, r["error"]
    assert r["pq_key_exchange"] == [] and r["quantum_risk_level"] == "high"
    assert _names(r["accepted_key_exchange"]) == ["MODP_1024", "MODP_2048"]
    assert {f["rule_id"] for f in r["findings"]} >= {"IKE_NO_PQ_KEY_EXCHANGE", "IKE_WEAK_DH_GROUP"}
