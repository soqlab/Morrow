import hashlib
import hmac
import importlib
import json
import os
import time

import pytest
from fastapi.testclient import TestClient


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@pytest.fixture()
def client(tmp_path):
    keys = (
        "PQC_SCANNER_DB",
        "PQC_AUTH_MODE",
        "PQC_AUTH_REQUIRED",
        "PQC_DEFAULT_ROLE",
        "PQC_ENVIRONMENT",
        "PQC_AIRLOCK_SIGNING_KEY",
        "PQC_AIRLOCK_REQUIRE_AGENT_SIGNATURE",
    )
    old_env = {k: os.environ.get(k) for k in keys}
    os.environ["PQC_SCANNER_DB"] = str(tmp_path / "airlock.db")
    os.environ["PQC_AUTH_MODE"] = "headers"
    os.environ["PQC_AUTH_REQUIRED"] = "1"
    os.environ["PQC_DEFAULT_ROLE"] = "viewer"
    os.environ["PQC_ENVIRONMENT"] = "development"
    os.environ["PQC_AIRLOCK_SIGNING_KEY"] = "a" * 64
    os.environ["PQC_AIRLOCK_REQUIRE_AGENT_SIGNATURE"] = "1"

    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()
    with TestClient(fastapi_app.app) as c:
        yield c

    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    importlib.reload(fastapi_app)


def _operator_headers(extra=None):
    headers = {
        "x-user-id": "operator-1",
        "x-user-role": "operator",
        "x-org-id": "00000000-0000-0000-0000-000000000001",
    }
    if extra:
        headers.update(extra)
    return headers


def test_enterprise_agent_package_contains_working_collector(client):
    response = client.post(
        "/airlock/agent-package",
        headers=_operator_headers(),
        json={"customer_id": "acme", "deployment_mode": "read_only", "allow_write_actions": False},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "enterprise_quantum_airlock_agent_package"
    assert body["profile"]["allow_write_actions"] is False
    assert body["profile"]["privacy_contract"]["no_payloads"] is True
    assert body["bundle"]["filename"] == "pqc-airlock-agent.zip"
    assert "pqc_airlock_agent.py" in body["artifacts"]
    compile(body["artifacts"]["pqc_airlock_agent.py"], "pqc_airlock_agent.py", "exec")


def test_signed_flight_recorder_submission_is_persisted(client):
    pkg = client.post(
        "/airlock/agent-package",
        headers=_operator_headers(),
        json={"customer_id": "acme"},
    ).json()
    config = pkg["profile"]
    payload = {
        "agent_id": config["agent_id"],
        "batch_id": "batch-1",
        "policy_version": config["policy_version"],
        "observations": [
            {
                "service_name": "internal-api",
                "peer": "orders",
                "tls_version": "TLSv1.3",
                "negotiated_group": "X25519MLKEM768",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "payload_visible": False,
            }
        ],
    }
    ts = str(int(time.time()))
    signature = hmac.new(
        config["agent_secret"].encode("utf-8"),
        f"{ts}.{_canonical(payload)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    submit = client.post(
        "/airlock/flight-recorder/submit",
        headers=_operator_headers({
            "x-airlock-agent-id": config["agent_id"],
            "x-airlock-timestamp": ts,
            "x-airlock-signature": f"sha256={signature}",
        }),
        json=payload,
    )

    assert submit.status_code == 200
    submitted = submit.json()
    assert submitted["accepted_count"] == 1
    assert submitted["agent_signature"]["verified"] is True
    assert submitted["events"][0]["decision"] == "verified"

    listed = client.get("/airlock/flight-recorder", headers=_operator_headers())
    assert listed.status_code == 200
    assert listed.json()["summary"]["returned"] == 1


def test_airlock_redaction_blocks_sensitive_customer_data(client):
    pkg = client.post(
        "/airlock/agent-package",
        headers=_operator_headers(),
        json={"customer_id": "acme"},
    ).json()
    config = pkg["profile"]
    body = {
        "source": "test",
        "evidence_type": "metadata",
        "asset_key": "api",
        "privacy_mode": "proofs_only",
        "payload": {
            "source_code": "def secret(): pass",
            "private_key": "-----BEGIN PRIVATE KEY-----",
            "payload_sample": "customer traffic",
            "safe_metric": 7,
        },
    }
    ts = str(int(time.time()))
    signature = hmac.new(
        config["agent_secret"].encode("utf-8"),
        f"{ts}.{_canonical(body)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    response = client.post(
        "/airlock/evidence",
        headers=_operator_headers({
            "x-airlock-agent-id": config["agent_id"],
            "x-airlock-timestamp": ts,
            "x-airlock-signature": f"sha256={signature}",
        }),
        json=body,
    )

    assert response.status_code == 200
    payload = response.json()["payload"]
    assert payload["accepted"] is True
    assert len(payload["redaction_report"]) == 3
    assert payload["payload"]["safe_metric"] == 7
    assert payload["payload"]["source_code"]["redacted"] is True


def test_trust_passport_does_not_claim_verified_without_evidence(client):
    response = client.get("/trust-passport", headers=_operator_headers())

    assert response.status_code == 200
    passport = response.json()["payload"]["passport"]
    assert passport["status"] == "insufficient_evidence"
    # No evidence, no number. A score of 50 would still be a claim about nothing.
    assert passport["score"] is None
    assert passport["available"] is False
    assert passport["reason"].strip()
    assert passport["evidence"]["evidence_count"] == 0


def test_change_simulator_and_pr_factory_are_review_only(client):
    sim = client.post(
        "/airlock/change-simulator",
        headers=_operator_headers(),
        json={
            "rollout_percent": 10,
            "services": [
                {"name": "legacy-api", "algorithm": "TLS_RSA_WITH_AES_128_CBC_SHA", "supports_hybrid_tls": False},
                {"name": "orders", "algorithm": "TLS_AES_256_GCM_SHA384 X25519MLKEM768", "supports_hybrid_tls": True},
            ],
            "legacy_clients": [{"name": "old-java", "max_tls": "TLSv1.2", "supports_hybrid_tls": False}],
        },
    )
    assert sim.status_code == 200
    sim_payload = sim.json()["payload"]
    assert sim_payload["no_change_applied"] is True
    assert sim_payload["estimated_breakage_risk"] == "high"

    pr = client.post(
        "/airlock/remediation-pr-factory",
        headers=_operator_headers(),
        json={"repository": "acme/platform", "asset_key": "legacy-api:443", "finding": "TLS_RSA"},
    )
    assert pr.status_code == 200
    pr_body = pr.json()
    assert pr_body["bundle"]["filename"] == "pqc-airlock-remediation-pr.zip"
    assert "patch.diff" in pr_body["artifacts"]
    assert "slsa-provenance.intoto.json" in pr_body["artifacts"]


def test_one_command_installers_and_onboarding_status(client):
    sh = client.get("/airlock/install.sh?customer_id=acme", headers=_operator_headers())
    ps1 = client.get("/airlock/install.ps1?customer_id=acme", headers=_operator_headers())
    status = client.get("/airlock/onboarding-status", headers=_operator_headers())

    assert sh.status_code == 200
    assert "pqc_airlock_agent.py" in sh.text
    assert "run-once" in sh.text
    assert ps1.status_code == 200
    assert "pqc_airlock_agent.py" in ps1.text
    assert status.status_code == 200
    assert status.json()["kind"] == "enterprise_airlock_onboarding_status"
