from fastapi.testclient import TestClient

import app as fastapi_app


HEADERS = {"x-user-role": "admin", "x-user-id": "test-admin", "x-org-id": "default-org"}


def test_security_intent_evaluate_returns_controls():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/security-intents/evaluate",
            headers=HEADERS,
            json={"intent": "No RSA-2048 after 2027 and all vendors need post-quantum attestation evidence."},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["intent_id"]
    assert body["summary"]["controls"] >= 1
    assert any(c["id"] == "pq.crypto_agility" for c in body["controls"])
    assert any(c["id"] == "vendor.pq_attestation" for c in body["controls"])


def test_security_truth_blocks_unsafe_change():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/security-truth/validate",
            headers=HEADERS,
            json={"change": 'resource "aws_s3_bucket_acl" "x" { acl = "public-read" }', "intent": "no public storage"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "block"
    assert body["findings"][0]["rule_id"] == "infra.public_storage"
    assert any(a["name"] == "terraform" for a in body["adapters"])


def test_security_graph_shape():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/security-graph", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert body["api_version"] == "v1"
    assert "nodes" in body
    assert "edges" in body


def test_vendor_attestation_scoring():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/vendor-attestations/score",
            headers=HEADERS,
            json={"dependent_assets": 2, "attestation": {"roadmap": "NIST post-quantum migration by 2027 with CBOM evidence."}},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["vendor_score"] >= 50
    assert body["risk_level"] in {"low", "medium", "high"}


def test_security_intent_lifecycle_and_policy_bundle():
    with TestClient(fastapi_app.app) as client:
        create = client.post(
            "/security-intents/evaluate",
            headers=HEADERS,
            json={"name": "No public storage", "intent": "No public storage and no admin IAM.", "save": True},
        )
        assert create.status_code == 200
        saved = create.json()["saved"]
        intent_id = int(saved["id"])

        published = client.post(f"/security-intents/{intent_id}/publish", headers=HEADERS)
        assert published.status_code == 200
        assert published.json()["item"]["status"] == "published"

        bundle = client.get("/security-truth/policy-bundle", headers=HEADERS)
        assert bundle.status_code == 200
        body = bundle.json()
        assert body["published_intents"] >= 1
        assert body["ci_integration"]["endpoint"] == "/v1/security-truth/validate"

        disabled = client.post(f"/security-intents/{intent_id}/disable", headers=HEADERS)
        assert disabled.status_code == 200
        assert disabled.json()["item"]["status"] == "disabled"


def test_crypto_mesh_profile_and_canary_flow():
    with TestClient(fastapi_app.app) as client:
        mesh = client.post(
            "/crypto-mesh/profiles",
            headers=HEADERS,
            json={"name": "Emergency hybrid mesh", "intent": "Roll out hybrid ML-KEM where supported.", "save": True},
        )
        assert mesh.status_code == 200
        body = mesh.json()
        assert body["profile"]["primary_profile"]["tls_groups"][0] == "X25519MLKEM768"
        assert body["saved"]["status"] == "draft"

        canary = client.post(
            "/hndl-canaries",
            headers=HEADERS,
            json={"label": "Decoy API key", "scope": "demo/customer-edge", "metadata": {"owner": "security"}},
        )
        assert canary.status_code == 200
        token = canary.json()["token"]
        hit = client.post(
            "/hndl-canaries/hit",
            headers=HEADERS,
            json={"token": token, "source": "unit-test", "event": {"kind": "access"}},
        )
        assert hit.status_code == 200
        assert hit.json()["matched"] is True


def test_vendor_private_proof_flow():
    with TestClient(fastapi_app.app) as client:
        proof = client.post(
            "/vendor-private-proofs",
            headers=HEADERS,
            json={
                "vendor_name": "Example Vendor",
                "scan_summary": {"scan_time": "2026-06-12T00:00:00Z", "topology_hash": "private"},
                "claims": {"pq_compliant": True, "legacy_rsa_keys": 0, "nist_profile": "ML-KEM/ML-DSA readiness"},
            },
        )
        assert proof.status_code == 200
        proof_body = proof.json()
        assert proof_body["signature"]
        verify = client.post("/vendor-private-proofs/verify", headers=HEADERS, json={"proof": proof_body})
        assert verify.status_code == 200
        assert verify.json()["valid"] is True
        assert verify.json()["decision"] == "accept"
