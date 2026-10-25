import os
import sqlite3
import tempfile

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    append_audit_log,
    create_remediation,
    get_connection,
    init_db,
    upsert_repository,
)


@pytest.fixture(scope="module")
def client_and_repo():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name

    # Disable startup hooks (Vault/Postgres) for isolated tests.
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()
    repo = upsert_repository("acme/rbac-demo", "https://github.com/acme/rbac-demo")

    # Stub external dependencies
    fastapi_app.get_credential = lambda *_a, **_k: {"id": 1, "secret": "gh-token"}
    fastapi_app._github_get_file = lambda owner, repo, path, ref, token: {
        "ok": True,
        "sha": "abc123",
        "content": 'minimum_tls_version = "TLS1_2"\n',
        "json": {},
    }
    fastapi_app._openai_chat = lambda prompt, **_k: {
        "ok": True,
        "json": {"choices": [{"message": {"content": 'minimum_tls_version = "TLS1_3"\n'}}]},
        "raw": "",
    }

    with TestClient(fastapi_app.app) as client:
        yield client, repo

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


def test_rbac_denies_viewer_for_approve(client_and_repo):
    client, repo = client_and_repo

    rem = create_remediation(
        asset_key_str="rbac.example:443",
        repo_id=int(repo["id"]),
        file_path="main.tf",
        vulnerability="Require TLS1.3",
        original_content='minimum_tls_version = "TLS1_2"\n',
        suggested_fix="",
        suggested_content='minimum_tls_version = "TLS1_3"\n',
        status="pending",
    )
    rid = int(rem["id"])

    # Viewer must not be allowed to approve code changes.
    resp = client.post(
        f"/remediations/{rid}/approve",
        headers={"x-user-id": "viewer-user", "x-user-role": "viewer"},
        json={"note": "try approve"},
    )
    assert resp.status_code == 403

    # Deny action should be recorded in immutable audit log.
    logs = client.get(
        "/audit/logs?action=remediation.approve&decision=deny",
        headers={"x-user-role": "admin", "x-user-id": "admin-user"},
    )
    assert logs.status_code == 200
    items = logs.json().get("items") or []
    assert any((x.get("actor_id") == "viewer-user") for x in items)


def test_guardrail_blocks_iam_firewall_changes(client_and_repo):
    client, repo = client_and_repo

    resp = client.post(
        "/remediations/suggest",
        headers={"x-user-id": "operator-1", "x-user-role": "operator"},
        json={
            "asset_key": "guardrail.example:443",
            "repository_id": int(repo["id"]),
            "file_path": "main.tf",
            "vulnerability": "Update IAM policy and firewall to fix security",
            "github_credential_id": 1,
            "ref": "main",
        },
    )
    assert resp.status_code == 400
    detail = str((resp.json() or {}).get("detail") or "").lower()
    assert ("iam" in detail) or ("firewall" in detail)

    logs = client.get(
        "/audit/logs?action=remediation.suggest&decision=deny",
        headers={"x-user-role": "admin", "x-user-id": "admin-user"},
    )
    assert logs.status_code == 200
    items = logs.json().get("items") or []
    assert any(("iam" in str(x.get("reason") or "").lower()) for x in items)


def test_rbac_denies_viewer_for_synthetic_scan_import(client_and_repo):
    client, _repo = client_and_repo

    resp = client.post(
        "/scans/synthetic",
        headers={"x-user-id": "viewer-user", "x-user-role": "viewer"},
        json={
            "scan_id": "viewer-deny-1",
            "results": [{"host": "viewer.example", "port": 443, "findings": []}],
        },
    )
    assert resp.status_code == 403

    logs = client.get(
        "/audit/logs?action=scan.synthetic&decision=deny",
        headers={"x-user-role": "admin", "x-user-id": "admin-user"},
    )
    assert logs.status_code == 200
    items = logs.json().get("items") or []
    assert any((x.get("actor_id") == "viewer-user") for x in items)


def test_audit_log_is_immutable():
    row = append_audit_log(
        actor_id="audit-test",
        actor_role="admin",
        action="audit.test",
        resource_type="audit_log",
        resource_id="seed",
        decision="allow",
        reason="seed row",
        details={"k": "v"},
    )
    rid = int(row["id"])
    with get_connection() as conn:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_logs SET reason=? WHERE id=?", ("tamper", rid))
            conn.commit()
