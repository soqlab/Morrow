import os
import tempfile
from datetime import datetime, timezone

from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    create_remediation,
    init_db,
    save_scan_asset_summaries,
    save_scan_results,
    save_scan_row,
    set_current_organization_id,
    reset_current_organization_id,
    upsert_asset,
    upsert_repository,
)


def _setup_tmp_db():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["PQC_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    return tmp_db


def test_iac_security_check_detects_open_ssh_and_mcp_tool():
    tmp_db = _setup_tmp_db()
    try:
        content = '''
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
'''
        with TestClient(fastapi_app.app) as client:
            resp = client.post(
                "/iac/security/check",
                headers={"x-user-role": "operator", "x-user-id": "sec-op"},
                json={"content": content, "file_path": "sg.tf"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "FAIL"
            assert body["findings"][0]["rule_id"] == "IAC_OPEN_SSH_TO_INTERNET"

            mcp = client.post(
                "/mcp",
                headers={"x-user-role": "operator", "x-user-id": "sec-op"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "check_iac_compliance", "arguments": {"content": content, "file_path": "sg.tf"}},
                },
            )
            assert mcp.status_code == 200
            assert mcp.json()["result"]["isError"] is True
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_guardrails_evaluate_change_blocks_insecure_iac_and_mcp_tool():
    tmp_db = _setup_tmp_db()
    try:
        bad_tf = '''
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.example.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
'''
        with TestClient(fastapi_app.app) as client:
            direct = client.post(
                "/v1/guardrails/evaluate-change",
                headers={"x-user-role": "operator", "x-user-id": "ai-agent"},
                json={
                    "repo": "acme/infra",
                    "tool_source": "copilot",
                    "intent": "propose_change",
                    "changed_files": [{"file_path": "s3.tf", "content": bad_tf}],
                },
            )
            assert direct.status_code == 200
            body = direct.json()
            assert body["kind"] == "guardrails.evaluate_change"
            assert body["decision"] == "block"
            assert body["blocking"] is True
            assert body["evidence_id"].startswith("guardrail-")
            assert any(v.get("rule_id") == "IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED" for v in body["violations"])

            mcp = client.post(
                "/mcp",
                headers={"x-user-role": "operator", "x-user-id": "ai-agent"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "evaluate_change_guardrails",
                        "arguments": {
                            "repo": "acme/infra",
                            "tool_source": "mcp-test",
                            "changed_files": [{"file_path": "s3.tf", "content": bad_tf}],
                        },
                    },
                },
            )
            assert mcp.status_code == 200
            result = mcp.json()["result"]
            assert result["isError"] is True
            assert result["content"][0]["json"]["decision"] == "block"
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_guardrails_evaluate_change_allows_clean_change():
    tmp_db = _setup_tmp_db()
    try:
        with TestClient(fastapi_app.app) as client:
            resp = client.post(
                "/v1/guardrails/evaluate-change",
                headers={"x-user-role": "viewer", "x-user-id": "dev-agent"},
                json={
                    "repo": "acme/app",
                    "tool_source": "coding-agent",
                    "changed_files": [{"file_path": "README.md", "content": "# docs only\n"}],
                },
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["decision"] == "allow"
            assert body["blocking"] is False
            assert body["violations_total"] == 0
            assert "Attach this evidence ID" in " ".join(body["required_actions"])
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_roi_metrics_and_ci_status_check():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/secure-iac", "https://github.com/acme/secure-iac")
        asset = "app.example:443"
        upsert_asset(asset, repository_id=int(repo["id"]), criticality="high")
        result = {
            "host": "app.example",
            "port": 443,
            "findings": [{"rule_id": "PQC_RSA_ENDPOINT", "severity": "critical"}],
            "risk_level": "critical",
            "quantum_score": 95.0,
        }
        save_scan_row("scan-roi", "completed", datetime.now(timezone.utc), {"total": 1}, "", [result], {"critical": 1})
        save_scan_results("scan-roi", [result], {"critical": 1}, status="completed")
        save_scan_asset_summaries("scan-roi", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), [result])
        create_remediation(asset, int(repo["id"]), "main.tf", "Fix TLS", "diff", status="verified_closed")
        create_remediation(asset, int(repo["id"]), "main.tf", "Drift follow-up", "diff", status="verified_closed", origin_kind="drift_followup")

        with TestClient(fastapi_app.app) as client:
            metrics = client.get(
                f"/org/{fastapi_app.DEFAULT_ORG_ID}/metrics",
                headers={"x-user-role": "admin", "x-user-id": "sec-admin"},
            )
            assert metrics.status_code == 200
            body = metrics.json()
            assert body["roi"]["engineering_hours_saved_total"] >= 4.0
            assert body["drift_analytics"]["manual_non_compliant_changes_reverted"] >= 1

            clean_gate = client.post(
                "/integrations/ci/status-check",
                headers={"x-user-role": "operator", "x-user-id": "sec-op"},
                json={"repo": "acme/secure-iac", "changed_files": []},
            )
            assert clean_gate.status_code == 200
            assert clean_gate.json()["state"] == "success"

            bad_gate = client.post(
                "/integrations/ci/status-check",
                headers={"x-user-role": "operator", "x-user-id": "sec-op"},
                json={
                    "repo": "acme/secure-iac",
                    "changed_files": [{"file_path": "sg.tf", "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }'}],
                },
            )
            assert bad_gate.status_code == 200
            assert bad_gate.json()["state"] == "failure"
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
