import os
import re
import tempfile

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    init_db,
    upsert_repository,
    get_remediation,
    auto_close_merged_remediations,
    update_validation_job,
    set_current_organization_id,
    reset_current_organization_id,
)


@pytest.fixture(scope="module")
def client_and_repo():
    # isolated temp DB
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name

    # Disable startup hooks (Vault/Postgres)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()
    repo = upsert_repository("acme/demo", "https://github.com/acme/demo")

    # Stub Vault + external calls
    fastapi_app.resolve_github_repo_token = lambda *_a, **_k: {
        "ok": True,
        "token": "gh-token",
        "credential_provider": "github",
        "credential_id": 1,
    }

    fastapi_app._github_get_file = lambda owner, repo, path, ref, token: {
        "ok": True,
        "sha": "abc123",
        "content": "tls_version = \"1.2\"\\n",
        "json": {},
    }

    fastapi_app._openai_chat = lambda prompt, **_k: {
        "ok": True,
        "json": {"choices": [{"message": {"content": "tls_version = \"1.3\"\\n"}}]},
        "raw": "",
    }

    fastapi_app._github_create_branch = lambda *_a, **_k: {"ok": True, "sha": "base-sha"}
    fastapi_app._github_put_file = lambda *_a, **_k: {"ok": True, "http_status": 201, "json": {"content": {}}}
    fastapi_app._github_create_pr = lambda *_a, **_k: {
        "ok": True,
        "http_status": 201,
        "json": {"html_url": "https://github.com/acme/demo/pull/1"},
    }
    original_execute_validation_job = fastapi_app.execute_validation_job
    fastapi_app.execute_validation_job = lambda validation_job_id, *_a, **_k: (
        update_validation_job(
            int(validation_job_id),
            status="passed",
            validator_type="terraform",
            git_ref="main",
            stdout="terraform validate ok",
            stderr="",
            exit_code=0,
            details={"commands": [["terraform", "validate", "-no-color"]], "validator_type": "terraform"},
            finished=True,
        )
    )

    with TestClient(fastapi_app.app) as client:
        yield client, repo

    fastapi_app.execute_validation_job = original_execute_validation_job
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


def test_remediation_lifecycle(client_and_repo):
    client, repo = client_and_repo

    # 1) suggest (creates pending remediation)
    resp = client.post(
        "/remediations/suggest",
        json={
            "asset_key": "example.com:443",
            "repository_id": int(repo["id"]),
            "file_path": "main.tf",
            "vulnerability": "TLS 1.2 is too weak; require TLS 1.3",
            "github_credential_id": 1,
            "ref": "main",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    rem = body["remediation"]
    rid = int(rem["id"])
    assert rem["status"] == "pending"
    assert "tls_version = \"1.2\"" in (rem.get("original_content") or "")
    assert "tls_version" in (rem.get("suggested_content") or "")

    # 2) approve
    resp = client.post(f"/remediations/{rid}/approve", json={"note": "looks good"})
    assert resp.status_code == 200
    rem = resp.json()["remediation"]
    assert rem["status"] == "approved"

    # 2.5) validate
    resp = client.post(
        f"/remediations/{rid}/validate",
        json={"github_credential_id": 1, "ref": "main", "async_mode": False},
    )
    assert resp.status_code == 200
    assert resp.json()["validation"]["status"] == "passed"
    assert resp.json()["validation"]["exit_code"] == 0

    # 3) create PR
    resp = client.post(
        f"/remediations/{rid}/create-pr",
        json={
            "github_credential_id": 1,
            "base_branch": "main",
            "branch_prefix": "fix/pq-remediation",
            "title": "Upgrade TLS to 1.3",
            "body": "test",
        },
    )
    assert resp.status_code == 200
    rem = resp.json()["remediation"]
    assert rem["status"] == "pr_created"
    assert rem["pr_url"] == "https://github.com/acme/demo/pull/1"

    # 4) mark merged
    resp = client.post(f"/remediations/{rid}/mark-merged", json={"merged_at": ""})
    assert resp.status_code == 200
    rem = resp.json()["remediation"]
    assert rem["status"] == "merged"

    # 5) verify loop: scan comes back clean -> remediation auto-closes
    stats = auto_close_merged_remediations(
        scan_id="scan-verify-1",
        results=[{"host": "example.com", "port": 443, "findings": [], "risk_level": "none"}],
    )
    assert int(stats.get("closed") or 0) == 1

    rem = get_remediation(rid) or {}
    assert rem.get("status") == "verified_closed"


def test_remediation_pr_branch_name_is_collision_resistant():
    first = fastapi_app._build_remediation_branch_name("fix/pq-remediation", 7)
    second = fastapi_app._build_remediation_branch_name("fix/pq-remediation", 7)

    assert first != second
    assert first.startswith("fix/pq-remediation-7-")
    assert re.match(r"^fix/pq-remediation-7-\d{14}-[0-9a-f]{8}$", first)


def test_github_webhook_marks_merged(client_and_repo):
    client, repo = client_and_repo

    # Keep webhook signature optional in tests.
    os.environ["GITHUB_WEBHOOK_SECRET"] = ""

    # Build a fresh remediation that stops at pr_created
    resp = client.post(
        "/remediations/suggest",
        json={
            "asset_key": "webhook.example:443",
            "repository_id": int(repo["id"]),
            "file_path": "main.tf",
            "vulnerability": "Upgrade minimum TLS to 1.3",
            "github_credential_id": 1,
            "ref": "main",
        },
    )
    assert resp.status_code == 200
    rid = int(resp.json()["remediation"]["id"])

    resp = client.post(f"/remediations/{rid}/approve", json={"note": "ready"})
    assert resp.status_code == 200
    assert resp.json()["remediation"]["status"] == "approved"

    resp = client.post(
        f"/remediations/{rid}/validate",
        json={"github_credential_id": 1, "base_branch": "main", "ref": "main", "async_mode": False},
    )
    assert resp.status_code == 200
    assert resp.json()["validation"]["status"] == "passed"

    resp = client.post(
        f"/remediations/{rid}/create-pr",
        json={
            "github_credential_id": 1,
            "base_branch": "main",
            "branch_prefix": "fix/pq-remediation",
        },
    )
    assert resp.status_code == 200
    rem = resp.json()["remediation"]
    assert rem["status"] == "pr_created"
    pr_url = rem["pr_url"]

    # Simulate GitHub "pull_request closed+merged" webhook.
    payload = {
        "action": "closed",
        "pull_request": {
            "merged": True,
            "html_url": pr_url,
            "merged_at": "2026-02-15T00:00:00Z",
        },
    }
    resp = client.post(
        "/integrations/github/webhook",
        headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "test-delivery-1"},
        json=payload,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert int(body.get("updated") or 0) >= 1

    rem = get_remediation(rid) or {}
    assert rem.get("status") == "merged"


def test_github_webhook_marks_merged_across_orgs(client_and_repo):
    client, repo = client_and_repo

    os.environ["GITHUB_WEBHOOK_SECRET"] = ""

    token = set_current_organization_id("org-alpha")
    try:
        alpha_repo = upsert_repository("acme/demo", "https://github.com/acme/demo")
        resp = client.post(
            "/remediations/suggest",
            headers={"x-org-id": "org-alpha"},
            json={
                "asset_key": "cross-org.example:443",
                "repository_id": int(alpha_repo["id"]),
                "file_path": "main.tf",
                "vulnerability": "Upgrade minimum TLS to 1.3",
                "github_credential_id": 1,
                "ref": "main",
            },
        )
        assert resp.status_code == 200
        rid = int(resp.json()["remediation"]["id"])

        resp = client.post(
            f"/remediations/{rid}/approve",
            headers={"x-org-id": "org-alpha"},
            json={"note": "ready"},
        )
        assert resp.status_code == 200

        resp = client.post(
            f"/remediations/{rid}/validate",
            headers={"x-org-id": "org-alpha"},
            json={"github_credential_id": 1, "base_branch": "main", "ref": "main", "async_mode": False},
        )
        assert resp.status_code == 200
        assert resp.json()["validation"]["status"] == "passed"

        resp = client.post(
            f"/remediations/{rid}/create-pr",
            headers={"x-org-id": "org-alpha"},
            json={
                "github_credential_id": 1,
                "base_branch": "main",
                "branch_prefix": "fix/pq-remediation",
            },
        )
        assert resp.status_code == 200
        pr_url = resp.json()["remediation"]["pr_url"]
    finally:
        reset_current_organization_id(token)

    payload = {
        "action": "closed",
        "pull_request": {
            "merged": True,
            "html_url": pr_url,
            "merged_at": "2026-02-15T00:00:00Z",
        },
    }
    resp = client.post(
        "/integrations/github/webhook",
        headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "test-delivery-cross-org"},
        json=payload,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert int(body.get("updated") or 0) >= 1

    token = set_current_organization_id("org-alpha")
    try:
        rem = get_remediation(rid) or {}
    finally:
        reset_current_organization_id(token)
    assert rem.get("status") == "merged"


def test_synthetic_scan_can_verify_close_remediation(client_and_repo):
    client, repo = client_and_repo

    resp = client.post(
        "/remediations/suggest",
        json={
            "asset_key": "verify.example:443",
            "repository_id": int(repo["id"]),
            "file_path": "main.tf",
            "vulnerability": "Upgrade minimum TLS to 1.3",
            "github_credential_id": 1,
            "ref": "main",
        },
    )
    assert resp.status_code == 200
    rid = int(resp.json()["remediation"]["id"])

    resp = client.post(f"/remediations/{rid}/approve", json={"note": "approved"})
    assert resp.status_code == 200

    resp = client.post(
        f"/remediations/{rid}/validate",
        json={"github_credential_id": 1, "ref": "main", "async_mode": False},
    )
    assert resp.status_code == 200
    assert resp.json()["validation"]["status"] == "passed"

    resp = client.post(
        f"/remediations/{rid}/create-pr",
        json={
            "github_credential_id": 1,
            "base_branch": "main",
            "branch_prefix": "fix/pq-remediation",
        },
    )
    assert resp.status_code == 200

    resp = client.post(f"/remediations/{rid}/mark-merged", json={"merged_at": ""})
    assert resp.status_code == 200
    assert resp.json()["remediation"]["status"] == "merged"

    resp = client.post(
        "/scans/synthetic",
        headers={"x-user-id": "sec-admin", "x-user-role": "admin"},
        json={
            "scan_id": "synthetic-verify-1",
            "results": [
                {
                    "host": "verify.example",
                    "port": 443,
                    "findings": [],
                    "risk_level": "none",
                }
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert int((body.get("verification") or {}).get("closed") or 0) == 1
    assert body["scan"]["status"] == "completed"

    rem = get_remediation(rid) or {}
    assert rem.get("status") == "verified_closed"
    assert rem.get("verification_scan_id") == "synthetic-verify-1"


def test_create_pr_requires_validation(client_and_repo):
    client, repo = client_and_repo

    resp = client.post(
        "/remediations/suggest",
        json={
            "asset_key": "novalidation.example:443",
            "repository_id": int(repo["id"]),
            "file_path": "main.tf",
            "vulnerability": "Require TLS 1.3",
            "github_credential_id": 1,
            "ref": "main",
        },
    )
    assert resp.status_code == 200
    rid = int(resp.json()["remediation"]["id"])

    resp = client.post(f"/remediations/{rid}/approve", json={"note": "approved"})
    assert resp.status_code == 200

    resp = client.post(
        f"/remediations/{rid}/create-pr",
        json={
            "github_credential_id": 1,
            "base_branch": "main",
            "branch_prefix": "fix/pq-remediation",
        },
    )
    assert resp.status_code == 400
    assert "pass validation" in str(resp.json().get("detail") or "").lower()


def test_create_pr_uses_normalized_content_from_validation(client_and_repo):
    client, repo = client_and_repo

    captured = {"content": ""}
    original_execute = fastapi_app.execute_validation_job
    original_put = fastapi_app._github_put_file
    try:
        fastapi_app.execute_validation_job = lambda validation_job_id, *_a, **_k: (
            update_validation_job(
                int(validation_job_id),
                status="passed",
                validator_type="terraform",
                git_ref="main",
                stdout="terraform validate ok",
                stderr="",
                exit_code=0,
                details={
                    "commands": [["terraform", "fmt", "-no-color", "main.tf"]],
                    "validator_type": "terraform",
                    "normalized_content": "locals {\n  min_tls = \"1.3\"\n}\n",
                },
                finished=True,
            )
        )
        fastapi_app._github_put_file = lambda owner, repo, path, branch, message, content, sha, token: (
            captured.update({"content": content}) or {"ok": True, "http_status": 201, "json": {"content": {}}}
        )

        resp = client.post(
            "/remediations/suggest",
            json={
                "asset_key": "normalized.example:443",
                "repository_id": int(repo["id"]),
                "file_path": "main.tf",
                "vulnerability": "Require TLS 1.3",
                "github_credential_id": 1,
                "ref": "main",
            },
        )
        assert resp.status_code == 200
        rid = int(resp.json()["remediation"]["id"])

        resp = client.post(f"/remediations/{rid}/approve", json={"note": "approved"})
        assert resp.status_code == 200

        resp = client.post(
            f"/remediations/{rid}/validate",
            json={"github_credential_id": 1, "ref": "main", "async_mode": False},
        )
        assert resp.status_code == 200
        assert resp.json()["validation"]["status"] == "passed"

        resp = client.post(
            f"/remediations/{rid}/create-pr",
            json={
                "github_credential_id": 1,
                "base_branch": "main",
                "branch_prefix": "fix/pq-remediation",
            },
        )
        assert resp.status_code == 200
        assert captured["content"] == "locals {\n  min_tls = \"1.3\"\n}\n"
    finally:
        fastapi_app.execute_validation_job = original_execute
        fastapi_app._github_put_file = original_put


def test_llm_wrapped_file_content_is_unwrapped():
    wrapped = (
        "```terraform\n"
        "-----BEGIN FILE-----\n"
        "locals {\n"
        "  minimum_tls_version = \"1.3\"\n"
        "}\n"
        "-----END FILE-----\n"
        "```"
    )
    parsed = fastapi_app._extract_patch_from_llm(wrapped)
    assert parsed["mode"] == "content"
    assert parsed["content"] == "locals {\n  minimum_tls_version = \"1.3\"\n}"


def test_remediation_suggest_strips_outer_file_wrappers_from_llm_output(client_and_repo):
    client, repo = client_and_repo

    original_get = fastapi_app._github_get_file
    original_chat = fastapi_app._openai_chat
    try:
        fastapi_app._github_get_file = lambda owner, repo, path, ref, token: {
            "ok": True,
            "sha": "abc123",
            "content": "-----BEGIN FILE-----\nlocals {\n  minimum_tls_version = \"1.2\"\n}\n-----END FILE-----\n",
            "json": {},
        }
        fastapi_app._openai_chat = lambda prompt, **_k: {
            "ok": True,
            "json": {
                "choices": [
                    {
                        "message": {
                            "content": (
                                "-----BEGIN FILE-----\n"
                                "locals {\n"
                                "  minimum_tls_version = \"1.3\"\n"
                                "}\n"
                                "-----END FILE-----\n"
                            )
                        }
                    }
                ]
            },
            "raw": "",
        }

        resp = client.post(
            "/remediations/suggest",
            json={
                "asset_key": "wrapped.example:443",
                "repository_id": int(repo["id"]),
                "file_path": "main.tf",
                "vulnerability": "Require TLS 1.3",
                "github_credential_id": 1,
                "ref": "main",
            },
        )
        assert resp.status_code == 200
        remediation = resp.json()["remediation"]
        assert "-----BEGIN FILE-----" not in (remediation.get("suggested_content") or "")
        assert "-----END FILE-----" not in (remediation.get("suggested_content") or "")
        assert "minimum_tls_version = \"1.3\"" in (remediation.get("suggested_content") or "")
    finally:
        fastapi_app._github_get_file = original_get
        fastapi_app._openai_chat = original_chat


def test_llm_wrapped_patch_is_applied():
    wrapped = (
        "-----BEGIN PATCH-----\n"
        "--- README.md\n"
        "+++ README.md\n"
        "@@ -2,4 +2,5 @@\n"
        " first trial\n"
        " \n"
        " This is my first time using Github\n"
        "+Note: The baseline requires TLS 1.3.\n"
        "-----END PATCH-----"
    )
    parsed = fastapi_app._extract_patch_from_llm(wrapped)
    assert parsed["mode"] == "diff"
    updated = fastapi_app._apply_unified_diff(
        "# hello-world\nfirst trial\n\nThis is my first time using Github\n",
        parsed["diff"],
    )
    assert "Note: The baseline requires TLS 1.3." in updated
