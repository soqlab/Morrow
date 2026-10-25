import base64
import importlib
import io
import os
import zipfile

from fastapi.testclient import TestClient


def _headers(role="operator"):
    return {
        "x-user-id": "mesh-tester",
        "x-user-role": role,
        "x-org-id": "00000000-0000-0000-0000-000000000001",
    }


def _client(tmp_path):
    keys = ("MORROW_SCANNER_DB", "MORROW_AUTH_MODE", "MORROW_AUTH_REQUIRED", "MORROW_DEFAULT_ROLE", "MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE")
    old_env = {k: os.environ.get(k) for k in keys}
    os.environ["MORROW_SCANNER_DB"] = str(tmp_path / "mesh.db")
    os.environ["MORROW_AUTH_MODE"] = "headers"
    os.environ["MORROW_AUTH_REQUIRED"] = "1"
    os.environ["MORROW_DEFAULT_ROLE"] = "viewer"
    os.environ["MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE"] = "0"

    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()
    return TestClient(fastapi_app.app), fastapi_app, old_env


def _restore(fastapi_app, old_env):
    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    importlib.reload(fastapi_app)


def test_autonomous_mesh_packages_and_predictive_controls(tmp_path):
    client, fastapi_app, old_env = _client(tmp_path)
    try:
        blueprint = client.get("/autonomous-mesh/blueprint", headers=_headers("viewer"))
        assert blueprint.status_code == 200
        assert blueprint.json()["kind"] == "autonomous_predictive_security_mesh"
        assert blueprint.json()["truth_endpoint"] == "/autonomous-mesh/capability-truth"

        truth = client.get("/autonomous-mesh/capability-truth", headers=_headers("viewer"))
        assert truth.status_code == 200
        assert truth.json()["kind"] == "capability_truth_matrix"
        assert any(c["key"] == "hybrid_certificate_generation" for c in truth.json()["capabilities"])

        ebpf = client.post("/autonomous-mesh/ebpf-package", headers=_headers(), json={"name": "pq-ebpf"})
        assert ebpf.status_code == 200
        ebpf_body = ebpf.json()
        assert ebpf_body["capabilities"]["payload_collection"] is False
        assert "pq_crypto_sniffer.bt" in ebpf_body["artifacts"]
        compile(ebpf_body["artifacts"]["collector.py"], "collector.py", "exec")
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(ebpf_body["bundle"]["content_base64"]))) as zf:
            assert "collector.py" in set(zf.namelist())

        graph = client.post("/autonomous-mesh/contagion/multi-hop", headers=_headers("viewer"), json={
            "compromised_node_id": "root-ca",
            "qday_probability": 0.5,
            "nodes": [
                {"id": "root-ca", "name": "Root CA", "risk_level": "critical"},
                {"id": "kms-core", "name": "Core KMS", "risk_level": "high"},
                {"id": "payments", "name": "Payments API", "risk_level": "medium"},
                {"id": "checkout", "name": "Checkout", "risk_level": "low"},
            ],
            "edges": [
                {"from": "root-ca", "to": "kms-core", "trust_weight": 0.90, "type": "signs"},
                {"from": "kms-core", "to": "payments", "trust_weight": 0.80, "type": "encrypts"},
                {"from": "payments", "to": "checkout", "trust_weight": 0.55, "type": "service_trust"},
            ],
        })
        assert graph.status_code == 200
        assert graph.json()["affected_count"] >= 3
        assert graph.json()["summary"]["largest_degradation"] > 0

        qday = client.post("/q-intel/dynamic-countdown", headers=_headers("viewer"), json={
            "milestones": [{
                "date": "2026-08-21",
                "system": "test-logical-array",
                "significance": "critical",
                "logical_qubits_eq": 100,
            }]
        })
        assert qday.status_code == 200
        assert qday.json()["research_pressure_score"] > 0

        pr = client.post("/autopilot/multi-variant-pr", headers=_headers(), json={
            "scan_result": {"host": "payments.example.com", "server": "envoy"}
        })
        assert pr.status_code == 200
        assert len(pr.json()["variants"]) == 3
        assert "Option" in pr.json()["github_pr_body"]

        shift = client.post("/autopilot/canary-traffic-shift", headers=_headers(), json={
            "service_name": "payments",
            "baseline_url": "https://legacy-payments.acme-corp.net",
            "candidate_url": "https://pq-payments.acme-corp.net",
            "canary_percent": 1,
        })
        assert shift.status_code == 200
        assert "cloudflare-worker.js" in shift.json()["artifacts"]
        assert shift.json()["guardrails"]["automatic_live_provider_writes"] is False

        hsm = client.post("/hardware/hsm-virtualization", headers=_headers("viewer"), json={
            "devices": [{"name": "hsm-a", "algorithms": ["ml-kem", "ml-dsa"], "tps": 5000, "region": "us"}],
            "workloads": [{"name": "signer", "required_algorithms": ["ml-kem"], "tps": 1000, "region": "us"}],
        })
        assert hsm.status_code == 200
        assert hsm.json()["matches"][0]["risk"] == "low"

        hsm_pkg = client.post("/hardware/hsm-collector-package", headers=_headers())
        assert hsm_pkg.status_code == 200
        assert "hsm_tpm_collector.py" in hsm_pkg.json()["artifacts"]
        compile(hsm_pkg.json()["artifacts"]["hsm_tpm_collector.py"], "hsm_tpm_collector.py", "exec")

        bridge_pkg = client.post("/hardware/crypto-bridge/collector-package", headers=_headers(), json={})
        assert bridge_pkg.status_code == 200
        assert "hardware_crypto_bridge_collector.py" in bridge_pkg.json()["artifacts"]
        compile(bridge_pkg.json()["artifacts"]["hardware_crypto_bridge_collector.py"], "hardware_crypto_bridge_collector.py", "exec")

        observation = {
            "provider": "customer-hsm",
            "key_id": "payments-signing-key",
            "algorithms": ["rsa-2048"],
            "hardware_backed": True,
            "native_pq": False,
            "software_fallback": True,
        }
        receipt = client.post("/hardware/crypto-drift/observations", headers=_headers(), json={"observations": [observation]})
        assert receipt.status_code == 200
        assert receipt.json()["key_exported"] is False

        drift = client.post("/hardware/crypto-drift/enforce", headers=_headers(), json={
            "observations": [observation],
            "key_intents": [{
                "key_id": "payments-signing-key",
                "required_algorithms": ["ml-dsa"],
                "require_native_pq": True,
            }],
            "policy": {"allow_software_fallback": False},
        })
        assert drift.status_code == 200
        assert drift.json()["ci_gate"] == "block"
        assert drift.json()["blocked_count"] == 1

        drift_missing = client.post("/hardware/crypto-drift/enforce", headers=_headers(), json={})
        assert drift_missing.status_code == 422

        anomaly = client.post("/crypto-anomaly/detect", headers=_headers(), json={
            "baseline": {"payload_size_p95_bytes": 2048, "bytes_out_per_minute": 100000},
            "records": [{
                "asset_key": "internal-backup-flow",
                "source_segment": "prod-db",
                "bytes_out": 900000,
                "payload_size_p95_bytes": 8192,
                "entropy": 7.8,
                "repeated_ciphertext_blocks": 50,
            }],
        })
        assert anomaly.status_code == 200
        assert anomaly.json()["payload_collection"] is False
        assert anomaly.json()["finding_count"] == 1
        finding = anomaly.json()["findings"][0]
        assert finding["hndl_harvesting_signal"] is True

        anomaly_empty = client.post("/crypto-anomaly/detect", headers=_headers(), json={"records": []})
        assert anomaly_empty.status_code == 422

        siem = client.post("/crypto-anomaly/siem-package", headers=_headers(), json={"findings": [finding], "destination": "sentinel"})
        assert siem.status_code == 200
        assert "microsoft-sentinel-rule.kql" in siem.json()["artifacts"]

        proof = client.post("/zk-compliance/continuous-proof", headers=_headers(), json={
            "threshold_pct": 50,
            "assets": [
                {"algorithm": "X25519MLKEM768"},
                {"algorithm": "rsa2048"},
            ],
        })
        assert proof.status_code == 200
        assert proof.json()["proof"]["claim"]["result"] == "pass"
        assert proof.json()["proof"]["claim"]["raw_identifiers_revealed"] is False

        insurance = client.post("/insurance/underwriting-export", headers=_headers(), json={
            "qri_score": 80,
            "controls": {"cam_enabled": True, "zk_proof": True, "hndl_canaries": 5},
            "scan_assets": [{"key_type": "rsa", "risk_level": "high"}],
        })
        assert insurance.status_code == 200
        assert insurance.json()["kind"] == "pq_insurance_underwriting_export"
        assert insurance.json()["raw_asset_identifiers_included"] is False

        agility = client.post("/insurance/proof-of-agility", headers=_headers(), json={
            "qri_score": 82,
            "remediation_metrics": {
                "merged_prs_30d": 8,
                "median_crypto_fix_days": 4,
                "critical_apps_assessed": 4,
                "critical_apps_total": 5,
            },
            "controls": {
                "airlock_signed_evidence": True,
                "cam_enabled": True,
                "cicd_buzzer": True,
                "hsm_crypto_bridge": True,
                "crypto_anomaly_detection": True,
            },
        })
        assert agility.status_code == 200
        assert agility.json()["proof"]["privacy"]["raw_asset_identifiers_included"] is False
        verify = client.post("/insurance/proof-of-agility/verify", headers=_headers("viewer"), json={
            "envelope": agility.json()["envelope"]
        })
        assert verify.status_code == 200
        assert verify.json()["valid"] is True

        no_graph = client.post("/autonomous-mesh/contagion/multi-hop", headers=_headers("viewer"), json={
            "compromised_node_id": "root-ca",
        })
        assert no_graph.status_code == 422

        no_pr = client.post("/autopilot/multi-variant-pr", headers=_headers(), json={"scan_result": {}})
        assert no_pr.status_code == 422

        placeholder_shift = client.post("/autopilot/canary-traffic-shift", headers=_headers(), json={
            "baseline_url": "https://legacy.example.com",
            "candidate_url": "https://morrow.example.com",
        })
        assert placeholder_shift.status_code == 422

        empty_proof = client.post("/zk-compliance/continuous-proof", headers=_headers(), json={"threshold_pct": 1, "assets": []})
        assert empty_proof.status_code == 200
        assert empty_proof.json()["proof"]["claim"]["result"] == "fail"
        assert empty_proof.json()["proof"]["claim"]["evidence_available"] is False

        libs = client.get("/hybrid-cert/libraries", headers=_headers("viewer"))
        cert = client.post("/hybrid-cert/generate", headers=_headers(), json={"common_name": "api.acme-corp.net"})
        if libs.json()["real_pq_available"]:
            assert cert.status_code == 200
            assert cert.json()["pq_key_real"] is True
        else:
            assert cert.status_code == 503
            assert cert.json()["detail"]["error"] == "real_pq_library_unavailable"
    finally:
        _restore(fastapi_app, old_env)


def test_entropy_hunting_is_active_in_binary_scans(tmp_path):
    client, fastapi_app, old_env = _client(tmp_path)
    try:
        aes_sbox_prefix = bytes.fromhex(
            "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
        )
        binary = b"\x7fELF" + (b"\x00" * 256) + aes_sbox_prefix + os.urandom(8192)

        entropy = client.post(
            "/binary/entropy-hunt",
            headers=_headers(),
            files={"file": ("crypto.bin", binary, "application/octet-stream")},
        )
        assert entropy.status_code == 200
        assert entropy.json()["entropy_summary"]["crypto_constant_hits"] >= 1

        scan = client.post(
            "/binary/scan",
            headers=_headers("admin"),
            files={"file": ("crypto.bin", binary, "application/octet-stream")},
        )
        assert scan.status_code == 200
        body = scan.json()
        assert body["detection_method"] == "static_string_extraction_plus_entropy_hunting"
        assert body["summary"]["entropy_hunting_enabled"] is True
        assert any(f["library"] == "compiled_crypto_constants" for f in body["findings"])
    finally:
        _restore(fastapi_app, old_env)
