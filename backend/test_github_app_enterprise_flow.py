import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db, reset_current_organization_id, set_current_organization_id, upsert_github_installation
from integrations import github_app as github_app_mod


def _setup_tmp_db():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    tmp_db.close()
    os.environ["PQC_MAIN_DB_BACKEND"] = ""
    os.environ["PQC_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    return tmp_db


def _headers(role="operator"):
    return {"x-user-role": role, "x-user-id": f"{role}-user"}


def test_github_app_status_reports_installations_and_credential(monkeypatch):
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        upsert_github_installation(
            installation_id=12345,
            account_login="acme",
            account_type="Organization",
            target_type="Organization",
            permissions={"contents": "write", "pull_requests": "write"},
            repositories_count=4,
        )
        monkeypatch.setattr(
            fastapi_app,
            "github_app_credential_status",
            lambda credential_id: {
                "ok": True,
                "ready": True,
                "credential_id": int(credential_id),
                "provider": "github_app",
                "installations_count": 1,
                "missing": [],
            },
        )
        with TestClient(fastapi_app.app) as client:
            resp = client.get(
                "/integrations/github-app/status",
                headers=_headers("viewer"),
                params={"credential_id": 99},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["ok"] is True
            assert body["credential"]["ready"] is True
            assert body["installations_count"] == 1
            assert body["installations"][0]["installation_id"] == 12345
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_github_app_repo_diagnostics_endpoint_uses_safe_payload(monkeypatch):
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        captured = {}

        def fake_diagnose(credential_id, repo_full_name, check_repo_metadata=None):
            captured["credential_id"] = credential_id
            captured["repo"] = repo_full_name
            captured["check_live"] = check_repo_metadata is not None
            return {
                "ok": True,
                "ready": True,
                "safe_to_attempt_pr": True,
                "credential_provider": "github_app",
                "installation_id": 777,
                "repo": repo_full_name,
                "steps": [{"name": "repo_token", "ok": True}],
            }

        monkeypatch.setattr(fastapi_app, "diagnose_github_repo_access", fake_diagnose)
        with TestClient(fastapi_app.app) as client:
            resp = client.post(
                "/integrations/github-app/repo-diagnostics",
                headers=_headers("operator"),
                json={"credential_id": 12, "repository": "acme/platform", "check_live_repo": True},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["safe_to_attempt_pr"] is True
            assert body["installation_id"] == 777
            assert "token" not in body
            assert captured == {"credential_id": 12, "repo": "acme/platform", "check_live": True}
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_diagnose_github_repo_access_masks_token_and_supports_metadata_check(monkeypatch):
    monkeypatch.setattr(
        github_app_mod,
        "get_credential",
        lambda credential_id, reveal=False: {
            "id": credential_id,
            "name": "github-app",
            "provider": "github_app",
            "secret": "pem" if reveal else "",
            "meta_json": {"app_id": "123"},
        },
    )
    monkeypatch.setattr(github_app_mod, "list_github_installations", lambda limit=2000: [])
    monkeypatch.setattr(
        github_app_mod,
        "resolve_github_repo_token",
        lambda credential_id, repo_full_name: {
            "ok": True,
            "token": "secret-token",
            "credential_provider": "github_app",
            "installation_id": 456,
            "expires_at": "2026-05-23T15:00:00Z",
        },
    )

    checked = {}

    def fake_metadata(owner, repo, token):
        checked["owner"] = owner
        checked["repo"] = repo
        checked["token"] = token
        return {"ok": True, "http_status": 200, "json": {"full_name": f"{owner}/{repo}"}}

    result = github_app_mod.diagnose_github_repo_access(1, "acme/platform", check_repo_metadata=fake_metadata)
    assert result["ok"] is True
    assert result["safe_to_attempt_pr"] is True
    assert result["installation_id"] == 456
    assert result["repository_metadata_check"]["ok"] is True
    assert "token" not in result
    assert checked == {"owner": "acme", "repo": "platform", "token": "secret-token"}


def test_diagnose_github_repo_access_reports_bad_repo_format(monkeypatch):
    result = github_app_mod.diagnose_github_repo_access(1, "not-a-full-name")
    assert result["ok"] is False
    assert result["ready"] is False
    assert "repository must be owner/repo" in result["missing"]
