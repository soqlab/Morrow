import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from integrations import github_app as github_app_mod
from db import init_db, reset_current_organization_id, set_current_organization_id, upsert_github_installation


@pytest.fixture(scope="module")
def client():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("PQC_SCANNER_DB")
    os.environ["PQC_SCANNER_DB"] = tmp_db.name

    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()
    with TestClient(fastapi_app.app) as c:
        yield c

    # Put the database selection back. This fixture is module-scoped, so its teardown runs
    # after the per-test cleanup in conftest; without this, PQC_SCANNER_DB keeps pointing at
    # this (now deleted) file for every module that runs afterwards.
    if _previous_db is None:
        os.environ.pop("PQC_SCANNER_DB", None)
    else:
        os.environ["PQC_SCANNER_DB"] = _previous_db
    try:
        os.remove(tmp_db.name)
    except OSError:
        pass


def test_github_app_installations_are_scoped_by_org(client):
    t1 = set_current_organization_id("org-alpha")
    try:
        upsert_github_installation(
            installation_id=111,
            account_login="acme",
            account_type="Organization",
            target_type="Organization",
            permissions={"contents": "read"},
            repositories_count=3,
        )
    finally:
        reset_current_organization_id(t1)

    t2 = set_current_organization_id("org-beta")
    try:
        upsert_github_installation(
            installation_id=222,
            account_login="beta",
            account_type="Organization",
            target_type="Organization",
            permissions={"contents": "read"},
            repositories_count=7,
        )
    finally:
        reset_current_organization_id(t2)

    resp = client.get("/integrations/github-app/installations", headers={"x-org-id": "org-alpha"})
    assert resp.status_code == 200
    rows = resp.json().get("items") or []
    ids = {int(r.get("installation_id") or 0) for r in rows}
    assert 111 in ids
    assert 222 not in ids


def test_github_app_sync_endpoints_wiring(client, monkeypatch):
    monkeypatch.setattr(
        fastapi_app,
        "sync_github_app_installations",
        lambda credential_id: {"ok": True, "credential_id": int(credential_id), "synced": 1},
    )
    inline = client.post(
        "/integrations/github-app/sync-installations",
        headers={"x-org-id": "org-alpha"},
        json={"credential_id": 12, "async_mode": False},
    )
    assert inline.status_code == 200
    assert inline.json().get("credential_id") == 12

    calls = {}

    class _Job:
        id = "job-bridge-1"

    def _fake_send_task(name, args=None, kwargs=None):
        calls["name"] = name
        calls["args"] = args
        calls["kwargs"] = kwargs
        return _Job()

    monkeypatch.setattr(fastapi_app.celery_app, "send_task", _fake_send_task)
    queued = client.post(
        "/integrations/github-app/sync-repositories",
        headers={"x-org-id": "org-queue"},
        json={"credential_id": 12, "installation_id": 999, "async_mode": True},
    )
    assert queued.status_code == 200
    assert queued.json().get("job_id") == "job-bridge-1"
    assert calls.get("name") == "pqc.sync_github_app_repositories"
    assert calls.get("args") == [12, 999, "org-queue"]


def test_resolve_github_repo_token_uses_installation_token_for_github_app(monkeypatch):
    monkeypatch.setattr(
        github_app_mod,
        "get_credential",
        lambda credential_id, reveal=True: {
            "id": credential_id,
            "provider": "github_app",
            "secret": "pem",
            "meta_json": {"app_id": "123"},
        },
    )
    monkeypatch.setattr(github_app_mod, "_resolve_app_credential", lambda credential_id: {"ok": True, "app_jwt": "jwt", "app_id": "123"})
    monkeypatch.setattr(github_app_mod, "_installation_for_repo", lambda app_jwt, owner, repo: {"ok": True, "installation_id": 456, "account_login": owner})
    monkeypatch.setattr(
        github_app_mod,
        "_installation_access_token",
        lambda app_jwt, installation_id: {"ok": True, "token": "inst-token", "expires_at": "2026-04-27T00:00:00Z"},
    )

    resolved = github_app_mod.resolve_github_repo_token(1, "acme/demo")
    assert resolved["ok"] is True
    assert resolved["token"] == "inst-token"
    assert resolved["credential_provider"] == "github_app"
    assert resolved["installation_id"] == 456


def test_resolve_github_repo_token_returns_raw_secret_for_github_pat(monkeypatch):
    monkeypatch.setattr(
        github_app_mod,
        "get_credential",
        lambda credential_id, reveal=True: {
            "id": credential_id,
            "provider": "github",
            "secret": "pat-token",
            "meta_json": {},
        },
    )

    resolved = github_app_mod.resolve_github_repo_token(2, "acme/demo")
    assert resolved["ok"] is True
    assert resolved["token"] == "pat-token"
    assert resolved["credential_provider"] == "github"
