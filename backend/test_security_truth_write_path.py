import importlib

from fastapi.testclient import TestClient


def _load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "security_truth.db"))
    monkeypatch.setenv("PQC_DEFAULT_ORG_ID", f"test-org-{tmp_path.name}")
    monkeypatch.setenv("PQC_AUTH_MODE", "headers")
    monkeypatch.setenv("PQC_AUTH_REQUIRED", "0")
    monkeypatch.setenv(
        "PQC_TOOL_API_KEYS",
        "wiz:tool-secret:guardrails:evaluate|findings:write|findings:read|write_path:request",
    )
    monkeypatch.setenv("PQC_PLATFORM_ADMIN_KEY", "admin-secret")

    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()
    return fastapi_app


def test_external_tool_key_can_call_guardrails_and_blocks_iam_admin(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    iam_admin = '''
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
'''
    with TestClient(fastapi_app.app) as client:
        r = client.post(
            "/v1/guardrails/evaluate-change",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "repo": "acme/identity",
                "tool_source": "wiz",
                "changed_files": [{"file_path": "iam.tf", "content": iam_admin}],
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "block"
    assert any(v.get("rule_id") == "IAC_IAM_ADMIN_PRIVILEGE" for v in body["violations"])


def test_invalid_tool_key_is_rejected(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        r = client.post(
            "/v1/guardrails/evaluate-change",
            headers={"x-tool-api-key": "bad"},
            json={"repo": "acme/infra", "changed_files": []},
        )
    assert r.status_code == 401


def test_external_findings_ingest_returns_batch_and_top_findings(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        r = client.post(
            "/v1/integrations/findings/ingest",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "snyk",
                "integration_type": "sca",
                "findings": [
                    {
                        "external_id": "SNYK-1",
                        "title": "Critical vulnerable package",
                        "severity": "critical",
                        "repo": "acme/app",
                        "file_path": "requirements.txt",
                    }
                ],
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["batch_id"].startswith("findings-")
    assert body["ingested"] == 1
    assert body["counts_by_severity"]["critical"] == 1
    assert body["top_findings"][0]["external_id"] == "SNYK-1"
    assert body["persisted"] == 1
    assert body["finding_ids"][0] > 0


def test_external_findings_can_be_listed_and_converted_to_write_path(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        ingest = client.post(
            "/v1/integrations/findings/ingest",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "wiz",
                "integration_type": "cnapp",
                "findings": [
                    {
                        "external_id": "WIZ-1",
                        "title": "Public SSH exposure",
                        "severity": "high",
                        "repo": "acme/infra",
                        "resource_id": "sg-prod",
                        "remediation": "Restrict SSH ingress to approved bastion CIDRs.",
                        "evidence": {
                            "changed_files": [
                                {
                                    "file_path": "sg.tf",
                                    "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                                }
                            ]
                        },
                    }
                ],
            },
        )
        finding_id = ingest.json()["finding_ids"][0]
        listed = client.get("/v1/integrations/findings", headers={"x-tool-api-key": "tool-secret"})
        detail = client.get(f"/v1/integrations/findings/{finding_id}", headers={"x-tool-api-key": "tool-secret"})
        converted = client.post(
            f"/v1/integrations/findings/{finding_id}/write-path",
            headers={"x-tool-api-key": "tool-secret"},
            json={"dry_run": True},
        )
    assert listed.status_code == 200
    assert any(i["external_id"] == "WIZ-1" for i in listed.json()["items"])
    assert detail.status_code == 200
    assert detail.json()["finding"]["external_id"] == "WIZ-1"
    assert converted.status_code == 200
    converted_body = converted.json()
    assert converted_body["request_id"].startswith("fixreq-")
    assert converted_body["status"] == "blocked_by_guardrails"
    assert converted_body["finding"]["status"] == "fix_requested"


def test_platform_security_truth_summarizes_findings(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        client.post(
            "/v1/integrations/findings/ingest",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "wiz",
                "integration_type": "cnapp",
                "findings": [{"external_id": "WIZ-2", "title": "Admin IAM policy", "severity": "critical"}],
            },
        )
        r = client.get("/platform/security-truth", headers={"x-platform-key": "admin-secret"})
    assert r.status_code == 200
    body = r.json()
    assert body["open_high_critical"] >= 1
    assert body["counts_by_severity"]["critical"] >= 1
    assert any(i["external_id"] == "WIZ-2" for i in body["recent_findings"])


def test_platform_admin_can_promote_finding_to_write_path(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        ingest = client.post(
            "/v1/integrations/findings/ingest",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "wiz",
                "integration_type": "cnapp",
                "findings": [{"external_id": "WIZ-3", "title": "Public admin role", "severity": "high"}],
            },
        )
        finding_id = ingest.json()["finding_ids"][0]
        promoted = client.post(
            f"/platform/security-truth/findings/{finding_id}/write-path",
            # A shared-key caller must ask for a write role; without the header it is an auditor.
            headers={"x-platform-key": "admin-secret", "x-platform-admin-role": "operator"},
            json={"dry_run": True},
        )
    assert promoted.status_code == 200
    body = promoted.json()
    assert body["request_id"].startswith("fixreq-")
    assert body["finding"]["status"] == "fix_requested"


def test_platform_write_path_feature_flag_blocks_promotion(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(
        fastapi_app,
        "_platform_feature_flags",
        lambda organization_id="": [{"organization_id": organization_id, "flag_key": "write_path", "enabled": False}],
    )
    with TestClient(fastapi_app.app) as client:
        ingest = client.post(
            "/v1/integrations/findings/ingest",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "wiz",
                "integration_type": "cnapp",
                "findings": [{"external_id": "WIZ-4", "title": "Public admin role", "severity": "high"}],
            },
        )
        finding_id = ingest.json()["finding_ids"][0]
        promoted = client.post(
            f"/platform/security-truth/findings/{finding_id}/write-path",
            # A shared-key caller must ask for a write role; without the header it is an auditor.
            headers={"x-platform-key": "admin-secret", "x-platform-admin-role": "operator"},
            json={"dry_run": True},
        )
    assert promoted.status_code == 403
    assert "write_path" in promoted.json()["detail"]


def test_write_path_fix_request_evaluates_guardrails_before_acceptance(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    with TestClient(fastapi_app.app) as client:
        r = client.post(
            "/v1/write-path/fix-requests",
            headers={"x-tool-api-key": "tool-secret"},
            json={
                "tool_source": "wiz",
                "finding_id": "WIZ-123",
                "repo": "acme/infra",
                "desired_outcome": "Fix public SSH exposure",
                "changed_files": [
                    {
                        "file_path": "sg.tf",
                        "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                    }
                ],
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["request_id"].startswith("fixreq-")
    assert body["status"] == "blocked_by_guardrails"
    assert body["guardrails"]["decision"] == "block"
