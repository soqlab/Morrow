import os
import tempfile

from fastapi.testclient import TestClient
from datetime import datetime

import app as fastapi_app
from db import init_db, reset_current_organization_id, save_scan_row, set_current_organization_id, upsert_asset, upsert_repository


def _setup_tmp_db():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    tmp_db.close()
    os.environ["MORROW_MAIN_DB_BACKEND"] = ""
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    os.environ.pop("GITHUB_WEBHOOK_SECRET", None)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    return tmp_db


def _headers(role="operator"):
    return {"x-user-role": role, "x-user-id": f"{role}-user"}


def test_ci_status_check_idempotency_replays_and_conflicts():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        unsafe_iac = 'resource "aws_security_group_rule" "ssh" { type = "ingress" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }'
        payload = {
            "repo": "acme/platform-infra",
            "changed_files": [{"file_path": "security.tf", "content": unsafe_iac}],
        }
        headers = {**_headers("operator"), "Idempotency-Key": "ci-gate-idem-1"}
        with TestClient(fastapi_app.app) as client:
            first = client.post("/integrations/ci/status-check", headers=headers, json=payload)
            assert first.status_code == 200
            first_body = first.json()
            assert first_body["state"] == "failure"
            assert first_body["github_status"]["published"] is False
            assert any(v.get("rule_id") == "IAC_OPEN_SSH_TO_INTERNET" for v in first_body.get("violations", []))

            second = client.post("/integrations/ci/status-check", headers=headers, json=payload)
            assert second.status_code == 200
            assert second.json() == first_body

            conflict = client.post(
                "/integrations/ci/status-check",
                headers=headers,
                json={"repo": "acme/platform-infra", "changed_files": []},
            )
            assert conflict.status_code == 409
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_ci_status_check_blocks_banned_crypto_and_returns_fix_suggestions():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/eu-edge", "https://github.com/acme/eu-edge")
        upsert_asset(
            "portal.eu.example:443",
            repository_id=int(repo["id"]),
            metadata={"region": "eu"},
            tags=["eu", "prod"],
        )
        save_scan_row(
            "scan-eu-rsa",
            "completed",
            datetime.utcnow(),
            {"total": 1, "done": 1, "percent": 100},
            "",
            [
                {
                    "asset_key": "portal.eu.example:443",
                    "host": "portal.eu.example",
                    "port": 443,
                    "risk_level": "medium",
                    "findings": [],
                    "key_type": "RSA",
                    "key_detail": "RSA 2048",
                    "sig_algorithm": "sha256WithRSAEncryption",
                    "harvest_now_decrypt_later_risk": "medium",
                    "provider_guess": "cloudflare",
                }
            ],
            {"total": 1},
        )

        with TestClient(fastapi_app.app) as client:
            resp = client.post(
                "/integrations/ci/status-check",
                headers=_headers("operator"),
                json={"repo": "acme/eu-edge", "ref": "abc123"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["state"] == "failure"
            assert body["blocking"] is True
            assert body["merge_gate"] == "blocked"
            assert body["required_check_context"] == "morrow/security-policy"
            assert any(v.get("kind") == "crypto_policy" for v in body["violations"])
            assert any("Replace the banned classical crypto" in s.get("suggestion", "") for s in body["fix_suggestions"])
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_github_webhook_records_pr_lifecycle_events():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        pr_url = "https://github.com/acme/platform-infra/pull/12"
        payload = {
            "action": "synchronize",
            "pull_request": {"html_url": pr_url, "number": 12, "merged": False},
        }
        with TestClient(fastapi_app.app) as client:
            hook = client.post(
                "/integrations/github/webhook",
                headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-sync-1"},
                json=payload,
            )
            assert hook.status_code == 200
            assert hook.json()["action"] == "synchronize"

            events = client.get(
                "/integrations/github/pr-events",
                headers=_headers("viewer"),
                params={"pr_url": pr_url},
            )
            assert events.status_code == 200
            items = events.json()["items"]
            assert len(items) == 1
            assert items[0]["pr_url"] == pr_url
            assert items[0]["action"] == "synchronize"
            assert items[0]["status"] == "pr_updated"
            assert items[0]["payload"]["number"] == 12
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_branch_cleanup_and_status_publish_history_endpoints_are_readable():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        with TestClient(fastapi_app.app) as client:
            cleanup = client.get(
                "/remediations/branches/cleanup/status",
                headers=_headers("viewer"),
                params={"limit": 5},
            )
            assert cleanup.status_code == 200
            cleanup_body = cleanup.json()
            assert cleanup_body["ok"] is True
            assert cleanup_body["summary"]["total"] == 0
            assert cleanup_body["items"] == []

            history = client.get(
                "/integrations/github/status-publishes",
                headers=_headers("viewer"),
                params={"limit": 5},
            )
            assert history.status_code == 200
            assert history.json()["items"] == []
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
