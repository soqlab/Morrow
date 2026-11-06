"""CBOM import (services/sbom_import.import_cbom) with real CBOMkit output, and the discovery routes.

tests/fixtures/cbomkit/ holds two CBOMs published in the CBOMkit repository
(https://github.com/cbomkit/cbomkit/tree/main/example, Apache-2.0, commit ca2968f): CBOMkit's scans
of apache/kafka and keycloak/keycloak. Both are CycloneDX 1.6 and validate against the vendored
schema; between them they carry algorithm, related-crypto-material and protocol assets, evidence
occurrences and a dependencies graph.
"""
from __future__ import annotations

import copy
import io
import json
import pathlib
import sqlite3

import pytest

from services import sbom_import as S

CBOMKIT = pathlib.Path(__file__).resolve().parent / "tests" / "fixtures" / "cbomkit"
KAFKA = (CBOMKIT / "kafka-cbom.json").read_bytes()
KEYCLOAK = (CBOMKIT / "keycloak-cbom.json").read_bytes()


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    S.init_tables(c)
    yield c
    c.close()


def _inv(conn, org="org-a", **kw):
    return {r["inventory_key"]: r for r in S.list_inventory(conn, org, **kw)}


def test_kafka_cbom_import(conn):
    r = S.import_cbom(conn, "org-a", "kafka-cbom.json", KAFKA)
    assert r["source"] == "cbomkit" and r["schema_valid"] is True
    assert r["component_count"] == 11 and r["crypto_component_count"] == 11
    assert r["assets_by_type"] == {"algorithm": 7, "related-crypto-material": 4}
    assert r["repository"] == {"gitUrl": "https://github.com/apache/kafka", "revision": "trunk", "commit": "f20f299"}
    inv = _inv(conn)
    sha256 = inv["algorithm:sha-256"]
    assert sha256["oid"] == "2.16.840.1.101.3.4.2.1" and sha256["nist_pq_category"] == 2
    assert sha256["quantum_vulnerable"] is False and sha256["sources"] == ["cbomkit"]
    assert sha256["occurrences"][0]["location"].endswith("CommonNameLoggingTrustManagerFactoryWrapper.java")
    dsa = inv["algorithm:dsa"]
    assert dsa["quantum_vulnerable"] is True and dsa["nist_pq_category"] == 0
    # CBOMkit's key@<uuid> components resolve, through the dependencies graph, to their algorithm.
    keys = [v for k, v in inv.items() if v["asset_type"] == "related-crypto-material"]
    assert keys and all(k["algorithm"] for k in keys)
    assert any(k["depends_on"] == ["algorithm:dsa"] for k in keys)


def test_keycloak_cbom_classification_and_dedup_within_document(conn):
    r = S.import_cbom(conn, "org-a", "keycloak-cbom.json", KEYCLOAK)
    assert r["crypto_component_count"] == 56
    # 33 per-location key@<uuid> components collapse to one row per key type + algorithm + size.
    assert r["inventory_assets"] < r["crypto_component_count"]
    assert r["assets_by_type"]["protocol"] == 1
    inv = _inv(conn)
    assert inv["algorithm:ecdsa-p384"]["name"] == "EC-secp384r1"
    assert inv["algorithm:rsa-2048"]["risk_level"] == "critical"
    assert inv["algorithm:sha-1"]["risk_level"] == "critical"
    assert inv["algorithm:aes-128-gcm"]["nist_pq_category"] == 1
    assert inv["algorithm:aes-128"]["algorithm"] == "AES-128"  # no mode stated, none invented
    for name in ("RSA-2048", "EC-secp256r1", "Ed25519", "ECDH", "EdDSA", "DSA"):
        assert name in r["quantum_vulnerable"], name
    tls = next(v for v in inv.values() if v["asset_type"] == "protocol")
    assert tls["name"] == "TLS" and tls["occurrence_count"] >= 2


def test_reimport_and_cross_document_dedup(conn):
    first = S.import_cbom(conn, "org-a", "kafka.json", KAFKA)
    before = _inv(conn)
    again = S.import_cbom(conn, "org-a", "kafka.json", KAFKA)
    assert again["new_inventory_assets"] == 0 and again["deduplicated_inventory_assets"] == first["inventory_assets"]
    after = _inv(conn)
    assert after.keys() == before.keys()
    # Re-importing identical evidence does not inflate occurrence counts.
    assert {k: v["occurrence_count"] for k, v in after.items()} == {k: v["occurrence_count"] for k, v in before.items()}
    kc = S.import_cbom(conn, "org-a", "keycloak.json", KEYCLOAK)
    assert kc["deduplicated_inventory_assets"] > 0  # SHA-256, RSA-2048, DSA... already known from kafka
    merged = _inv(conn)["algorithm:sha-256"]
    assert merged["occurrence_count"] == before["algorithm:sha-256"]["occurrence_count"] + 12
    assert len(S.list_imports(conn, "org-a")) == 3


def test_sbom_and_cbom_share_the_inventory(conn):
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "cryptographic-asset", "name": "SHA-256"},
    ]}
    S.import_sbom(conn, "org-a", "app.sbom.json", json.dumps(sbom).encode())
    S.import_cbom(conn, "org-a", "kafka.json", KAFKA)
    row = _inv(conn)["algorithm:sha-256"]
    assert row["sources"] == ["sbom", "cbomkit"]
    assert set(_inv(conn, source="cbomkit")) >= {"algorithm:sha-256"}
    assert "algorithm:sha-256" in _inv(conn, source="sbom")


def test_inventory_is_org_scoped(conn):
    S.import_cbom(conn, "org-a", "kafka.json", KAFKA)
    assert S.list_inventory(conn, "org-b") == []
    assert S.list_imports(conn, "org-b") == []
    S.import_cbom(conn, "org-b", "kafka.json", KAFKA)
    assert len(S.list_inventory(conn, "org-b")) == len(S.list_inventory(conn, "org-a"))
    # The second organization's import is new to it, not a duplicate of the first's.
    assert S.import_cbom(conn, "org-b", "keycloak.json", KEYCLOAK)["inventory_assets"] > 0
    assert S.list_inventory(conn, "org-a", source="cbomkit")[0]["sources"] == ["cbomkit"]


def test_schema_invalid_document_is_refused(conn):
    doc = json.loads(KAFKA)
    doc["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "cipher"  # not in the enum
    with pytest.raises(S.SchemaInvalid) as exc:
        S.import_cbom(conn, "org-a", "bad.json", json.dumps(doc).encode())
    assert exc.value.errors and "primitive" in exc.value.errors[0]["path"]
    assert S.list_inventory(conn, "org-a") == [] and S.list_imports(conn, "org-a") == []


@pytest.mark.parametrize("mutate,error", [
    (lambda d: d.update(specVersion="1.5"), S.SchemaInvalid),
    (lambda d: d.update(bomFormat="SPDX"), S.SchemaInvalid),
])
def test_non_cyclonedx_16_is_refused(conn, mutate, error):
    doc = json.loads(KAFKA)
    mutate(doc)
    with pytest.raises(error):
        S.import_cbom(conn, "org-a", "x.json", json.dumps(doc).encode())


def test_size_limits(conn, monkeypatch):
    monkeypatch.setattr(S, "MAX_IMPORT_BYTES", 1000)
    with pytest.raises(S.ImportTooLarge):
        S.import_cbom(conn, "org-a", "big.json", KAFKA)
    with pytest.raises(S.ImportTooLarge):
        S.import_sbom(conn, "org-a", "big.json", KAFKA)
    monkeypatch.setattr(S, "MAX_IMPORT_BYTES", 10 * 1024 * 1024)
    monkeypatch.setattr(S, "MAX_IMPORT_COMPONENTS", 5)
    with pytest.raises(S.ImportTooLarge):
        S.import_cbom(conn, "org-a", "many.json", KAFKA)


def test_malformed_json_is_a_valueerror(conn):
    for data in (b"{", b"[]", b"\xff\xfe", b"[" * 100000):
        with pytest.raises(ValueError):
            S.import_cbom(conn, "org-a", "x.json", data)


def test_certificate_component(conn):
    doc = json.loads(KAFKA)
    doc["components"].append({
        "type": "cryptographic-asset", "bom-ref": "cert-1", "name": "server.example",
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
            "subjectName": "CN=server.example", "issuerName": "CN=Example CA",
            "notValidAfter": "2027-01-01T00:00:00Z", "certificateFormat": "X.509",
            "signatureAlgorithmRef": "5dc8d1ab-85a2-40a0-a336-351438a620ec"}},
    })
    doc["dependencies"].append({"ref": "cert-1", "dependsOn": ["5dc8d1ab-85a2-40a0-a336-351438a620ec"]})
    S.import_cbom(conn, "org-a", "c.json", json.dumps(doc).encode())
    cert = next(v for v in _inv(conn).values() if v["asset_type"] == "certificate")
    assert cert["details"]["subject"] == "CN=server.example"
    assert cert["details"]["signatureAlgorithmRef"] == "DSA"
    assert cert["depends_on"] == ["algorithm:dsa"]


# ── HTTP routes ───────────────────────────────────────────────────────────────

from test_invite_landing import api, make_org  # noqa: E402,F401  (api is a fixture)
from test_domain_verification import bearer, enforced, verify  # noqa: E402,F401


def _upload(client, headers, data, name="kafka-cbom.json", **params):
    return client.post("/v1/cbom/import", headers=headers, params=params,
                       files={"file": (name, io.BytesIO(data), "application/json")})


def test_cbom_import_route_and_inventory(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    make_org(client, "org-other", "Other")
    acme = bearer(client, app, email="admin@acme.example", org="org-acme")
    other = bearer(client, app, email="admin@other.example", org="org-other")

    res = _upload(client, acme, KAFKA)
    assert res.status_code == 200, res.text
    assert res.json()["source"] == "cbomkit" and res.json()["new_inventory_assets"] == 11

    inv = client.get("/v1/crypto-inventory", headers=acme, params={"source": "cbomkit"})
    assert inv.status_code == 200 and inv.json()["count"] == 11
    assert client.get("/v1/crypto-inventory", headers=other).json()["count"] == 0
    assert client.get("/sbom/imports", headers=other).json()["count"] == 0
    assert client.get("/sbom/imports", headers=acme).json()["imports"][0]["source"] == "cbomkit"

    bad = copy.deepcopy(json.loads(KAFKA))
    bad["components"][0]["type"] = "not-a-type"
    res = _upload(client, acme, json.dumps(bad).encode())
    assert res.status_code == 422 and res.json()["detail"]["errors"]
    assert _upload(client, acme, KAFKA, source="nope").status_code == 400

    # The console posts the document as the raw JSON body.
    raw = client.post("/v1/cbom/import", headers={**acme, "Content-Type": "application/json"},
                      params={"filename": "keycloak-cbom.json"}, content=KEYCLOAK)
    assert raw.status_code == 200, raw.text
    assert raw.json()["filename"] == "keycloak-cbom.json" and raw.json()["deduplicated_inventory_assets"] > 0
    assert client.get("/v1/crypto-inventory", headers=acme, params={"source": "x%"}).status_code == 400


def test_cbom_import_route_size_limit(api, monkeypatch):
    client, app = api
    make_org(client, "org-acme", "Acme")
    acme = bearer(client, app)
    monkeypatch.setattr(S, "MAX_IMPORT_BYTES", 4096)
    res = _upload(client, acme, KAFKA)
    assert res.status_code == 413


def test_viewer_cannot_import(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    viewer = bearer(client, app, email="viewer@acme.example", role="viewer")
    assert _upload(client, viewer, KAFKA).status_code == 403


def test_ike_route_refuses_unverified_hosts(enforced, monkeypatch):
    client, app = enforced
    make_org(client, "org-acme", "Acme")
    auth = bearer(client, app)
    import ike_scanner

    def must_not_run(*a, **k):
        raise AssertionError("scan ran for an unverified host")

    monkeypatch.setattr(ike_scanner, "scan_ike", must_not_run)
    refused = client.post("/v1/scan/ike", json={"targets": ["vpn.acme.example:500"]}, headers=auth)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "domain_not_verified"

    verify(monkeypatch, "org-acme", "acme.example")
    seen = []

    def fake_scan(host, port, probe_ikev1=True):
        from services import domain_verification as dv
        seen.append((host, port, dv.refusal_for_current_org(host)))
        return {"host": host, "port": port, "findings": []}

    monkeypatch.setattr(ike_scanner, "scan_ike", fake_scan)
    ok = client.post("/v1/scan/ike", json={"targets": ["vpn.acme.example", "gw.acme.example:4500"]}, headers=auth)
    assert ok.status_code == 200, ok.text
    assert sorted(seen) == [("gw.acme.example", 4500, ""), ("vpn.acme.example", 500, "")]
