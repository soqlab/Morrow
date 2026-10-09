import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
import remediation_drift as drift_mod
import remediation_validation as validation_mod
from db import (
    create_remediation,
    create_validation_job,
    get_remediation,
    init_db,
    list_audit_logs,
    list_webhook_events,
    set_remediation_pr,
    update_validation_job,
    upsert_repository,
)
from events import emit_platform_event


@pytest.fixture()
def client():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["PQC_SCANNER_DB"] = tmp_db.name
    os.environ["PQC_MAIN_DB_BACKEND"] = ""
    os.environ["GITHUB_WEBHOOK_SECRET"] = ""

    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()

    with TestClient(fastapi_app.app) as test_client:
        yield test_client

    try:
        os.remove(tmp_db.name)
    except OSError:
        pass


def _create_slack_webhook(client: TestClient, name: str = "slack-alerts") -> int:
    resp = client.post(
        "/integrations/webhooks",
        json={
            "name": name,
            "url": "https://hooks.slack.com/services/T000/B000/XXXX",
            "events": ["validation.failed", "remediation.merged", "remediation.drifted"],
            "enabled": True,
        },
    )
    assert resp.status_code == 200, resp.text
    return int(resp.json()["webhook"]["id"])


def test_slack_webhook_can_be_enabled_without_vault_secret(client):
    _create_slack_webhook(client)

    emit_platform_event(
        "validation.failed",
        {
            "validation_job_id": 8,
            "remediation_id": 5,
            "asset_key": "slack.example:443",
            "repository": "acme/demo",
            "file_path": "main.tf",
            "exit_code": 1,
        },
        dedupe_key="validation.failed:test-slack",
    )

    rows = list_webhook_events(limit=10)
    matching = [row for row in rows if str(row.get("event_type") or "") == "validation.failed"]
    assert matching
    assert str((matching[0].get("payload") or {}).get("text") or "").startswith("[PQC] validation failed")


def test_validation_failure_emits_notification_and_audit(client, monkeypatch):
    _create_slack_webhook(client, name="slack-validation")
    repo = upsert_repository("acme/validation-demo", "https://github.com/acme/validation-demo")
    rem = create_remediation(
        "validation.example:443",
        int(repo["id"]),
        "main.tf",
        "Upgrade minimum TLS to 1.3",
        "--- main.tf\n+++ main.tf\n@@\n-old\n+new",
        original_content='tls_version = "1.2"\n',
        suggested_content="-----BEGIN FILE-----\ntls_version = \"1.3\"\n-----END FILE-----\n",
        status="approved",
    )
    validation = create_validation_job(int(rem["id"]), validator_type="generic", git_ref="main", status="queued")

    monkeypatch.setattr(
        validation_mod,
        "resolve_github_repo_token",
        lambda credential_id, repo_name: {"ok": True, "token": "gh-token"},
    )
    monkeypatch.setattr(
        validation_mod,
        "_download_repo_archive",
        lambda owner, repo, git_ref, token, temp_dir: temp_dir,
    )
    monkeypatch.setattr(validation_mod, "_detect_validator", lambda file_path, requested: "generic")

    result = validation_mod.execute_validation_job(
        int(validation["id"]),
        int(rem["id"]),
        1,
        git_ref="main",
        validator_type="generic",
        timeout_seconds=30,
    )
    assert result["status"] == "failed"

    audit_rows = list_audit_logs(limit=20, action="validation.failed")
    assert any(int(row.get("resource_id") or 0) == int(validation["id"]) for row in audit_rows)

    events = list_webhook_events(limit=20)
    assert any(str(row.get("event_type") or "") == "validation.failed" for row in events)


def test_github_webhook_merge_emits_notification(client):
    _create_slack_webhook(client, name="slack-merged")
    repo = upsert_repository("acme/merge-demo", "https://github.com/acme/merge-demo")
    rem = create_remediation(
        "merge.example:443",
        int(repo["id"]),
        "main.tf",
        "Upgrade minimum TLS to 1.3",
        "--- main.tf\n+++ main.tf\n@@\n-old\n+new",
        original_content='tls_version = "1.2"\n',
        suggested_content='tls_version = "1.3"\n',
        status="approved",
    )
    set_remediation_pr(int(rem["id"]), "https://github.com/acme/merge-demo/pull/22", status="pr_created")

    resp = client.post(
        "/integrations/github/webhook",
        headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-merge-1"},
        json={
            "action": "closed",
            "pull_request": {
                "merged": True,
                "html_url": "https://github.com/acme/merge-demo/pull/22",
                "merged_at": "2026-04-28T12:00:00Z",
            },
        },
    )
    assert resp.status_code == 200
    updated = get_remediation(int(rem["id"])) or {}
    assert updated.get("status") == "merged"

    events = list_webhook_events(limit=20)
    assert any(str(row.get("event_type") or "") == "remediation.merged" for row in events)


def test_drift_check_marks_remediation_and_updates_report(client, monkeypatch):
    _create_slack_webhook(client, name="slack-drift")
    repo = upsert_repository("acme/drift-demo", "https://github.com/acme/drift-demo")
    rem = create_remediation(
        "drift.example:443",
        int(repo["id"]),
        "main.tf",
        "Upgrade minimum TLS to 1.3",
        "--- main.tf\n+++ main.tf\n@@\n-old\n+new",
        original_content='tls_version = "1.2"\n',
        suggested_content='tls_version = "1.3"\n',
        status="verified_closed",
    )
    validation = create_validation_job(int(rem["id"]), validator_type="terraform", git_ref="main", status="running")
    update_validation_job(
        int(validation["id"]),
        status="passed",
        validator_type="terraform",
        git_ref="main",
        stdout="terraform validate ok",
        stderr="",
        exit_code=0,
        details={"normalized_content": 'tls_version = "1.3"\n'},
        finished=True,
    )

    monkeypatch.setattr(
        drift_mod,
        "resolve_github_repo_token",
        lambda credential_id, repo_name: {"ok": True, "token": "gh-token"},
    )
    monkeypatch.setattr(
        drift_mod,
        "_github_get_file",
        lambda owner, repo, file_path, git_ref, token: {
            "ok": True,
            "content": 'tls_version = "1.2"\n',
            "sha": "sha-drift-1",
        },
    )

    outcome = drift_mod.check_remediation_drift(int(rem["id"]), github_credential_id=1)
    assert outcome["drift_status"] == "drifted"

    updated = get_remediation(int(rem["id"])) or {}
    assert updated.get("drift_status") == "drifted"
    assert updated.get("drift_detected_at")

    audit_rows = list_audit_logs(limit=20, action="remediation.drifted")
    assert any(str(row.get("resource_id") or "") == str(rem["id"]) for row in audit_rows)

    events = list_webhook_events(limit=20)
    assert any(str(row.get("event_type") or "") == "remediation.drifted" for row in events)

    report = client.get(
        "/org/compliance-report?format=json&audit_limit=20",
        headers={"x-user-id": "sec-admin", "x-user-role": "admin"},
    )
    assert report.status_code == 200
    body = report.json()
    assert int(body["summary"]["drifted_total"] or 0) >= 1
    assert any(str(item.get("action") or "") == "remediation.drifted" for item in body.get("recent_alerts") or [])
