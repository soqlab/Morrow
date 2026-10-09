import os
import tempfile
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db


@pytest.fixture(scope="module")
def test_client():
    # Use an isolated SQLite file to avoid clobbering real data
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("PQC_SCANNER_DB")
    os.environ["PQC_SCANNER_DB"] = tmp_db.name

    # Skip Vault/Postgres startup side effects
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    # Ensure SQLite schema exists
    init_db()

    # Stub external sync functions to avoid network calls
    def _stub_gcp(credential_id: int, project_id: str | None = None) -> Dict[str, Any]:
        return {"ok": True, "project_id": project_id or "test-project", "credential_id": credential_id}

    def _stub_gh(credential_id: int, org: str | None = None, visibility: str = "all") -> Dict[str, Any]:
        return {"ok": True, "org": org or "test-org", "visibility": visibility, "credential_id": credential_id}

    def _stub_correlate(credential_id: int, asset_limit: int = 500) -> Dict[str, Any]:
        return {"ok": True, "linked": 0, "assets_checked": 0, "credential_id": credential_id, "asset_limit": asset_limit}

    fastapi_app.sync_gcp_assets = _stub_gcp
    fastapi_app.sync_github_repos = _stub_gh
    fastapi_app.correlate_assets = _stub_correlate

    with TestClient(fastapi_app.app) as client:
        yield client

    # Cleanup temp DB file
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


def test_gcp_sync_inline(test_client: TestClient):
    resp = test_client.post("/integrations/gcp/sync", json={"credential_id": 123, "project_id": "demo", "async_mode": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["project_id"] == "demo"
    assert body["credential_id"] == 123


def test_github_sync_inline(test_client: TestClient):
    resp = test_client.post("/integrations/github/sync", json={"credential_id": 99, "org": "acme", "visibility": "private", "async_mode": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["org"] == "acme"
    assert body["visibility"] == "private"
    assert body["credential_id"] == 99


def test_correlate_inline(test_client: TestClient):
    resp = test_client.post("/integrations/correlate-assets", json={"credential_id": 77, "asset_limit": 42, "async_mode": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["asset_limit"] == 42
    assert body["credential_id"] == 77
