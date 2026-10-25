import os
import tempfile
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    append_audit_log,
    asset_key,
    create_remediation,
    create_validation_job,
    init_db,
    link_asset_repository,
    save_scan_asset_summaries,
    save_scan_results,
    save_scan_row,
    set_current_organization_id,
    reset_current_organization_id,
    update_validation_job,
    upsert_asset,
    upsert_repository,
)


@pytest.fixture(scope="module")
def client_and_report_data():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name

    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/compliance-demo", "https://github.com/acme/compliance-demo")
        ak = asset_key("critical.example", 443)
        upsert_asset(ak, owner="alice", team="security", environment="prod", criticality="tier-0")
        link_asset_repository(ak, int(repo["id"]))

        result = {
            "host": "critical.example",
            "port": 443,
            "findings": [{"id": "tls-old"}],
            "risk_level": "critical",
            "quantum_score": 91.0,
            "pq_relevance": "high",
            "tls_version": "TLSv1.2",
            "key_type": "RSA",
            "sig_algorithm": "sha256WithRSAEncryption",
        }
        save_scan_row(
            "scan-report-1",
            "completed",
            datetime.utcnow(),
            {"total": 1, "done": 1, "percent": 100},
            "",
            [result],
            {"critical": 1, "total": 1},
        )
        save_scan_results("scan-report-1", [result], {"critical": 1, "total": 1}, status="completed")
        save_scan_asset_summaries("scan-report-1", datetime.utcnow().isoformat() + "Z", [result])

        rem_verified = create_remediation(
            ak,
            int(repo["id"]),
            "main.tf",
            "Upgrade minimum TLS to 1.3",
            "--- main.tf\n+++ main.tf\n@@\n-tls = \"1.2\"\n+tls = \"1.3\"",
            original_content='tls = "1.2"\n',
            suggested_content='tls = "1.3"\n',
            status="verified_closed",
        )
        validation = create_validation_job(int(rem_verified["id"]), validator_type="terraform", git_ref="main", status="running")
        update_validation_job(
            int(validation["id"]),
            status="passed",
            validator_type="terraform",
            git_ref="main",
            stdout="terraform validate ok",
            stderr="",
            exit_code=0,
            details={"commands": [["terraform", "validate", "-no-color"]]},
            finished=True,
        )

        rem_merged = create_remediation(
            ak,
            int(repo["id"]),
            "outputs.tf",
            "Pin TLS output to 1.3",
            "--- outputs.tf\n+++ outputs.tf\n@@\n-output = \"1.2\"\n+output = \"1.3\"",
            original_content='output = "1.2"\n',
            suggested_content='output = "1.3"\n',
            status="merged",
        )

        append_audit_log(
            actor_id="sec-admin",
            actor_role="admin",
            action="remediation.validate",
            resource_type="remediation",
            resource_id=str(rem_verified["id"]),
            decision="allow",
            reason="",
            details={"validation_job_id": int(validation["id"])},
        )
        append_audit_log(
            actor_id="sec-admin",
            actor_role="admin",
            action="organization.compliance_report",
            resource_type="organization",
            resource_id=fastapi_app.DEFAULT_ORG_ID,
            decision="allow",
            reason="",
            details={"seed": True},
        )

        with TestClient(fastapi_app.app) as client:
            yield client, {"asset_key": ak, "repo": repo, "verified_id": int(rem_verified["id"]), "merged_id": int(rem_merged["id"])}
    finally:
        reset_current_organization_id(token)
        # Put the database selection back. This fixture is module-scoped, so its teardown runs
        # after the per-test cleanup in conftest; without this, MORROW_SCANNER_DB keeps pointing at
        # this (now deleted) file for every module that runs afterwards.
        if _previous_db is None:
            os.environ.pop("MORROW_SCANNER_DB", None)
        else:
            os.environ["MORROW_SCANNER_DB"] = _previous_db
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_org_compliance_report_json(client_and_report_data):
    client, seeded = client_and_report_data

    resp = client.get(
        "/org/compliance-report?format=json&audit_limit=10",
        headers={"x-user-id": "sec-admin", "x-user-role": "admin"},
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["organization"]["id"] == fastapi_app.DEFAULT_ORG_ID
    assert body["summary"]["remediations_total"] == 2
    assert body["summary"]["validated_total"] == 1
    assert body["summary"]["validated_passed_total"] == 1
    assert body["summary"]["verified_closed_total"] == 1
    assert body["summary"]["merged_total"] == 1
    assert 0 <= int(body["summary"]["compliance_readiness_score"]) <= 100
    assert body["summary"]["developer_hours_saved_estimate"] >= 3.0

    vulnerability_assets = {item["asset_key"] for item in body["vulnerabilities"]}
    assert seeded["asset_key"] in vulnerability_assets

    remediation_ids = {item["id"] for item in body["remediations"]}
    assert seeded["verified_id"] in remediation_ids
    assert seeded["merged_id"] in remediation_ids

    validated = next(item for item in body["remediations"] if item["id"] == seeded["verified_id"])
    assert validated["validation"]["status"] == "passed"
    assert validated["validation"]["exit_code"] == 0


def test_org_compliance_report_denies_viewer(client_and_report_data):
    client, _ = client_and_report_data

    resp = client.get(
        "/org/compliance-report",
        headers={"x-user-id": "viewer-user", "x-user-role": "viewer"},
    )
    assert resp.status_code == 403
