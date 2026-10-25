import os
import tempfile
from datetime import datetime

from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    create_remediation,
    create_validation_job,
    init_db,
    reset_current_organization_id,
    save_scan_row,
    set_current_organization_id,
    update_validation_job,
    upsert_asset,
    upsert_github_installation,
    upsert_repository,
)


def _setup_tmp_db():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    tmp_db.close()
    os.environ["MORROW_MAIN_DB_BACKEND"] = ""
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    return tmp_db


def _headers(role="viewer"):
    return {"x-user-role": role, "x-user-id": f"{role}-user"}


def test_e2e_readiness_reports_blockers_on_empty_workspace():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        with TestClient(fastapi_app.app) as client:
            resp = client.get("/v1/readiness/e2e", headers=_headers())
            assert resp.status_code == 200
            body = resp.json()
            assert body["summary"]["total"] == 25
            assert body["summary"]["blocked"] > 0
            assert any(i["id"] == "money_flow" and i["status"] == "blocked" for i in body["items"])
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_e2e_readiness_counts_core_money_flow_evidence():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/platform", "https://github.com/acme/platform")
        upsert_github_installation(installation_id=123, account_login="acme", repositories_count=1)
        upsert_asset("app.example:443", repository_id=int(repo["id"]), owner="sec", team="platform")
        save_scan_row(
            "scan-1",
            "completed",
            datetime.utcnow(),
            {"total": 1, "done": 1, "percent": 100},
            "",
            [{"asset_key": "app.example:443", "host": "app.example", "port": 443, "risk_level": "high"}],
            {"total": 1},
        )
        remediation = create_remediation(
            asset_key_str="app.example:443",
            repo_id=int(repo["id"]),
            file_path="infra/tls.tf",
            vulnerability="RSA-2048 certificate",
            suggested_fix="",
            suggested_content='resource "tls" "pq" {}',
            status="approved",
        )
        validation = create_validation_job(int(remediation["id"]), status="queued")
        update_validation_job(int(validation["id"]), status="passed", exit_code=0, finished=True)
        with TestClient(fastapi_app.app) as client:
            resp = client.get("/readiness/e2e", headers=_headers())
            assert resp.status_code == 200
            body = resp.json()
            assert body["source_counts"]["repositories"] == 1
            assert body["source_counts"]["completed_scans"] == 1
            assert body["source_counts"]["linked_assets"] == 1
            assert body["source_counts"]["passed_validations"] == 1
            assert any(i["id"] == "validation" and i["status"] == "ready" for i in body["items"])
            assert any(i["id"] == "pr_creation" and i["status"] == "blocked" for i in body["items"])
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_e2e_readiness_export_markdown_and_compact_json():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        with TestClient(fastapi_app.app) as client:
            md = client.get("/v1/readiness/e2e/export", headers=_headers(), params={"format": "markdown"})
            assert md.status_code == 200
            assert "Post-Quantum Platform E2E Readiness Handoff" in md.text
            assert "## Blockers" in md.text

            js = client.get("/readiness/e2e/export", headers=_headers(), params={"format": "json"})
            assert js.status_code == 200
            body = js.json()
            assert body["ok"] is True
            assert "blocked" in body
            assert "summary" in body
            assert "items" not in body
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
