import base64
import importlib
import io
import json
import os
import zipfile

import yaml
from fastapi.testclient import TestClient


def _operator_headers():
    return {
        "x-user-id": "operator-1",
        "x-user-role": "operator",
        "x-org-id": "00000000-0000-0000-0000-000000000001",
    }


def test_crypto_middleware_generates_transparent_cam_package(tmp_path):
    old_env = {
        "PQC_SCANNER_DB": os.environ.get("PQC_SCANNER_DB"),
        "PQC_AUTH_MODE": os.environ.get("PQC_AUTH_MODE"),
        "PQC_AUTH_REQUIRED": os.environ.get("PQC_AUTH_REQUIRED"),
        "PQC_DEFAULT_ROLE": os.environ.get("PQC_DEFAULT_ROLE"),
    }
    os.environ["PQC_SCANNER_DB"] = str(tmp_path / "cam.db")
    os.environ["PQC_AUTH_MODE"] = "headers"
    os.environ["PQC_AUTH_REQUIRED"] = "1"
    os.environ["PQC_DEFAULT_ROLE"] = "viewer"

    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()
    client = TestClient(fastapi_app.app)

    response = client.post(
        "/crypto-mesh/middleware-plan",
        headers=_operator_headers(),
        json={
            "name": "pqc-agility-middleware",
            "deployment_mode": "transparent_sidecar",
            "emergency_algorithm": "X25519MLKEM768",
            "outbound_capture_port": 15001,
            "services": [
                {
                    "name": "payments-api",
                    "upstream_host": "payments-upstream",
                    "upstream_port": 8443,
                    "listen_port": 15443,
                    "gateway_host": "payments-pqc-gateway",
                    "destination_cidr": "10.42.10.15/32",
                }
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "crypto_agility_middleware_plan"
    assert body["mode"] == "automated_cam_transparent_proxy"
    assert body["capabilities"]["transparent_sidecar"] is True
    assert body["profile"]["zero_application_code_changes"] is True
    assert body["profile"]["payload_inspection_required"] is False

    artifacts = body["artifacts"]
    required = {
        "cam-policy.json",
        "docker-compose.transparent.yml",
        "kubernetes-ingress-gateway.yaml",
        "kubernetes-transparent-sidecar.yaml",
        "install-transparent.sh",
        "verify-transparent.sh",
        "pqc-cam/envoy/ingress-gateway.yaml",
        "pqc-cam/envoy/sidecar-egress.yaml",
        "pqc-cam/scripts/transparent-egress-enable.sh",
        "pqc-cam/scripts/transparent-egress-disable.sh",
        "pqc-cam/scripts/transparent-egress-enable.ps1",
        "pqc-cam/telemetry/cam_telemetry_agent.py",
        "pqc-cam/Dockerfile.sidecar",
    }
    assert required.issubset(set(artifacts))
    assert "iptables -t nat" in artifacts["pqc-cam/scripts/transparent-egress-enable.sh"]
    assert "envoy.filters.listener.original_dst" in artifacts["pqc-cam/envoy/sidecar-egress.yaml"]
    assert "X25519MLKEM768" in artifacts["pqc-cam/envoy/ingress-gateway.yaml"]
    yaml.safe_load(artifacts["pqc-cam/envoy/ingress-gateway.yaml"])
    yaml.safe_load(artifacts["pqc-cam/envoy/sidecar-egress.yaml"])
    list(yaml.safe_load_all(artifacts["kubernetes-ingress-gateway.yaml"]))
    yaml.safe_load(artifacts["kubernetes-transparent-sidecar.yaml"])
    assert "payload_visible" in artifacts["pqc-cam/telemetry/cam_telemetry_agent.py"]
    compile(artifacts["pqc-cam/telemetry/cam_telemetry_agent.py"], "cam_telemetry_agent.py", "exec")

    policy = json.loads(artifacts["cam-policy.json"])
    assert "sidecar injection" in " ".join(policy["limitations"]).lower()
    assert policy["services"][0]["destination_cidr"] == "10.42.10.15/32"

    raw_zip = base64.b64decode(body["bundle"]["content_base64"])
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        names = set(zf.namelist())
    assert required.issubset(names)

    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    importlib.reload(fastapi_app)
