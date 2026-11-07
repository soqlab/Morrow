"""POST /v1/scan/ike against real strongSwan 6 responders (backend/tests/fixtures/strongswan), through
the API with the verified-domain scope check on, as a hosted customer would run it."""
from __future__ import annotations


def _names(items):
    return [i["name"] for i in items]


def test_unverified_targets_are_refused_before_any_packet(api):
    # An IP address can never be verified; another domain is not this organization's.
    for target in ("172.30.77.20:500", "vpn.example.org:500"):
        r = api.post("/v1/scan/ike", json={"targets": [target]}, expect=403)
        assert r["detail"]["code"] == "domain_not_verified", r


def test_scan_pq_optional_and_classical_responders(api, verified_zone):
    r = api.post("/v1/scan/ike", json={"targets": [f"vpn.{verified_zone}:500", f"vpn-classic.{verified_zone}:500"]})
    by_host = {res["host"]: res for res in r["results"]}
    pq, classic = by_host[f"vpn.{verified_zone}"], by_host[f"vpn-classic.{verified_zone}"]

    assert pq["error"] is None, pq["error"]
    assert pq["selected_proposal"]["additional_key_exchange_1"]["name"] == "ML_KEM_768"
    assert {k: _names(v) for k, v in pq["accepted_additional_key_exchange"].items()} == {"ADDKE1": ["ML_KEM_768"]}
    assert _names(pq["accepted_key_exchange"]) == ["MODP_2048", "CURVE25519"]
    assert pq["classical_only_accepted"] is True and pq["quantum_risk_level"] == "medium"
    assert pq["ikev1"]["enabled"] is False

    assert classic["error"] is None, classic["error"]
    assert classic["pq_key_exchange"] == [] and classic["quantum_risk_level"] == "high"
    assert _names(classic["accepted_key_exchange"]) == ["MODP_1024", "MODP_2048"]


def test_scan_over_nat_t_port(api, verified_zone):
    r = api.post("/v1/scan/ike", json={"targets": [f"vpn.{verified_zone}:4500"], "probe_ikev1": False})
    res = r["results"][0]
    assert res["error"] is None, res["error"]
    assert res["pq_key_exchange"] == ["ML_KEM_768"]
