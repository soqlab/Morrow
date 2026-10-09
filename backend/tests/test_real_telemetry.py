from datetime import datetime, timezone

from db import (
    reset_current_organization_id,
    save_scan_asset_summaries,
    save_scan_results,
    save_scan_row,
    set_current_organization_id,
)


def test_telemetry_kpis_use_persisted_scan_evidence(client, auth, org_id):
    scan_id = "telemetry-real-scan"
    now = datetime.now(timezone.utc)
    result = {
        "host": "telemetry.example",
        "port": 443,
        "risk_level": "critical",
        "quantum_risk_score": 95,
        "findings": [{"severity": "critical", "rule": "rsa-key-exchange"}],
        "tls_version": "TLSv1.2",
        "key_type": "RSA",
        "sig_algorithm": "sha256WithRSAEncryption",
    }

    token = set_current_organization_id(org_id)
    try:
        save_scan_row(scan_id, "completed", now, {"total": 1, "done": 1, "percent": 100}, "", [result], {"critical": 1})
        save_scan_results(scan_id, [result], {"critical": 1}, status="completed")
        save_scan_asset_summaries(scan_id, now.isoformat().replace("+00:00", "Z"), [result])
    finally:
        reset_current_organization_id(token)

    kpis = client.get("/v1/telemetry/kpis", headers=auth)
    assert kpis.status_code == 200
    body = kpis.json()
    assert body["data_mode"] == "real_evidence_only"
    assert body["scans_last_hour"] >= 1
    assert body["critical_findings_24h"] >= 1
    assert "scans" in body["evidence_sources"]
    assert "scan_results" in body["evidence_sources"]

    events = client.get("/v1/telemetry/events?event_type=finding_new", headers=auth)
    assert events.status_code == 200
    assert any(
        event["data"].get("asset_key") == "telemetry.example:443"
        for event in events.json()["events"]
    )
