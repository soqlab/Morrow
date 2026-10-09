import os
import tempfile

from fastapi.testclient import TestClient
import pytest

import app as fastapi_app
import remediation_drift as drift_mod
from db import (
    create_remediation,
    create_validation_job,
    get_remediation,
    init_db,
    list_audit_logs,
    list_remediations,
    update_validation_job,
    upsert_repository,
)


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


def _auth_headers():
    return {"x-user-id": "sec-admin", "x-user-role": "admin"}


def _seed_verified_remediation():
    repo = upsert_repository("acme/drift-response", "https://github.com/acme/drift-response")
    rem = create_remediation(
        "drift-response.example:443",
        int(repo["id"]),
        "main.tf",
        "Restore validated Terraform content",
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
    return rem


def test_drift_creates_followup_and_reuses_it(client, monkeypatch):
    rem = _seed_verified_remediation()

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
            "sha": "sha-drift-response-1",
        },
    )

    first = drift_mod.check_remediation_drift(int(rem["id"]), github_credential_id=1)
    parent = get_remediation(int(rem["id"])) or {}
    followup_id = int(parent.get("drift_followup_remediation_id") or 0)
    assert first["drift_status"] == "drifted"
    assert followup_id > 0

    followup = get_remediation(followup_id) or {}
    assert int(followup.get("parent_remediation_id") or 0) == int(rem["id"])
    assert str(followup.get("origin_kind") or "") == "drift_followup"
    assert str(followup.get("status") or "") == "pending"

    second = drift_mod.check_remediation_drift(int(rem["id"]), github_credential_id=1)
    parent_again = get_remediation(int(rem["id"])) or {}
    assert int(parent_again.get("drift_followup_remediation_id") or 0) == followup_id
    assert int(second.get("followup_remediation_id") or 0) == followup_id

    followups = [
        row for row in list_remediations(origin_kind="drift_followup", limit=20)
        if int(row.get("parent_remediation_id") or 0) == int(rem["id"])
    ]
    assert len(followups) == 1


def test_acknowledge_and_revalidate_drift_endpoints(client, monkeypatch):
    rem = _seed_verified_remediation()

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
            "sha": "sha-drift-response-2",
        },
    )
    drift_mod.check_remediation_drift(int(rem["id"]), github_credential_id=1)

    ack = client.post(
        f"/remediations/{int(rem['id'])}/drift/acknowledge",
        headers=_auth_headers(),
        json={"note": "accepted temporary drift"},
    )
    assert ack.status_code == 200, ack.text
    acknowledged = ack.json()["remediation"]
    assert acknowledged["drift_acknowledged_at"]
    assert acknowledged["drift_acknowledged_by"] == "sec-admin"
    assert acknowledged["drift_ack_note"] == "accepted temporary drift"

    audit_rows = list_audit_logs(limit=20, action="remediation.drift_acknowledged")
    assert any(str(row.get("resource_id") or "") == str(rem["id"]) for row in audit_rows)

    monkeypatch.setattr(
        drift_mod,
        "_github_get_file",
        lambda owner, repo, file_path, git_ref, token: {
            "ok": True,
            "content": 'tls_version = "1.3"\n',
            "sha": "sha-drift-response-3",
        },
    )
    revalidate = client.post(
        f"/remediations/{int(rem['id'])}/drift/revalidate",
        headers=_auth_headers(),
        json={"github_credential_id": 1, "async_mode": False},
    )
    assert revalidate.status_code == 200, revalidate.text
    assert revalidate.json()["result"]["drift_status"] == "clean"

    updated = get_remediation(int(rem["id"])) or {}
    assert updated.get("drift_status") == "clean"

    report = client.get("/org/compliance-report?format=json", headers=_auth_headers())
    assert report.status_code == 200, report.text
    summary = report.json()["summary"]
    assert int(summary.get("drift_acknowledged_total") or 0) >= 1
    assert int(summary.get("drift_followup_open_total") or 0) >= 1
