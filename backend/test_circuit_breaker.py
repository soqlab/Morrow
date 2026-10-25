import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db, list_flight_recorder_events


def test_circuit_breaker_blocks_iac_policy_violation_and_records_flight_event():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            payload = {
                "repo": "acme/platform-infra",
                "ref": "abc123",
                "mode": "block",
                "actor_type": "ci",
                "actor_id": "github-actions",
                "intent": "deploy",
                "changed_files": [
                    {
                        "file_path": "main.tf",
                        "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                    }
                ],
                "deployment_context": {"environment": "prod"},
            }
            response = client.post(
                "/v1/enforcement/circuit-breaker",
                headers={"x-user-id": "operator-1", "x-user-role": "operator"},
                json=payload,
            )

            assert response.status_code == 200
            body = response.json()
            assert body["decision"] == "block"
            assert body["status"] == "BLOCK"
            assert body["exit_code"] == 1
            assert body["violations_total"] >= 1

        events = list_flight_recorder_events(intent="block_deploy", resource_type="repository", resource_id="acme/platform-infra")
        assert len(events) == 1
        assert events[0]["decision"] == "blocked"
        assert events[0]["evidence_refs"]["violations_total"] >= 1
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_circuit_breaker_warn_mode_does_not_block_exit_code():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            response = client.post(
                "/v1/enforcement/evaluate",
                headers={"x-user-id": "viewer-1", "x-user-role": "viewer"},
                json={
                    "repo": "acme/platform-infra",
                    "mode": "warn",
                    "changed_files": [
                        {
                            "file_path": "main.tf",
                            "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                        }
                    ],
                },
            )

            assert response.status_code == 200
            body = response.json()
            assert body["decision"] == "warn"
            assert body["status"] == "WARN"
            assert body["exit_code"] == 0
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_circuit_breaker_uses_org_policy_default_mode():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            saved = client.put(
                "/v1/org/00000000-0000-0000-0000-000000000001/policy",
                headers={"x-user-id": "admin-1", "x-user-role": "admin"},
                json={"policy": {"version": "test-policy", "circuit_breaker_mode": "warn", "fail_ci_on_iac_policy_violation": True}},
            )
            assert saved.status_code == 200

            response = client.post(
                "/v1/enforcement/evaluate",
                headers={"x-user-id": "viewer-1", "x-user-role": "viewer"},
                json={
                    "repo": "acme/platform-infra",
                    "changed_files": [
                        {
                            "file_path": "main.tf",
                            "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                        }
                    ],
                },
            )

            assert response.status_code == 200
            body = response.json()
            assert body["policy_version"] == "test-policy"
            assert body["enforcement_mode"] == "warn"
            assert body["decision"] == "warn"
            assert body["exit_code"] == 0
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_github_required_check_publishes_circuit_breaker_decision(monkeypatch):
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    published = {}

    def fake_check_run(owner, repo, head_sha, token, *, name, conclusion, summary, text="", details_url=""):
        published.update(
            {
                "owner": owner,
                "repo": repo,
                "head_sha": head_sha,
                "token": token,
                "name": name,
                "conclusion": conclusion,
                "summary": summary,
                "text": text,
                "details_url": details_url,
            }
        )
        return {"ok": True, "http_status": 201, "id": 123}

    monkeypatch.setattr(fastapi_app, "_github_repo_token_or_502", lambda credential_id, repo: "ghs_test")
    monkeypatch.setattr(fastapi_app, "github_create_check_run", fake_check_run)
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            response = client.post(
                "/v1/enforcement/github-required-check",
                headers={"x-user-id": "operator-1", "x-user-role": "operator"},
                json={
                    "repo": "acme/platform-infra",
                    "ref": "abc123",
                    "mode": "block",
                    "github_credential_id": 7,
                    "publish_mode": "check_run",
                    "changed_files": [
                        {
                            "file_path": "main.tf",
                            "content": 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
                        }
                    ],
                },
            )

            assert response.status_code == 200
            body = response.json()
            assert body["decision"] == "block"
            assert body["github_required_check"]["published"] is True
            assert body["github_required_check"]["context"] == "morrow/security-policy"
            assert published["owner"] == "acme"
            assert published["repo"] == "platform-infra"
            assert published["head_sha"] == "abc123"
            assert published["conclusion"] == "failure"
            assert "Blocking post-quantum/security policy violations" in published["text"]
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
