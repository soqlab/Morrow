import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    create_remediation,
    create_validation_job,
    init_db,
    reset_current_organization_id,
    set_current_organization_id,
    update_validation_job,
    upsert_repository,
)


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


def _remediation(status="approved"):
    repo = upsert_repository("acme/payments", "https://github.com/acme/payments")
    return create_remediation(
        asset_key_str="payments.example:443",
        repo_id=int(repo["id"]),
        file_path="infra/tls.tf",
        vulnerability="RSA-2048 certificate",
        original_content='resource "tls" "old" {}',
        suggested_fix="",
        suggested_content='resource "tls" "pqc" {}',
        status=status,
    )


def test_pr_readiness_blocks_until_validation_and_github_credential_are_present():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        remediation = _remediation(status="approved")
        with TestClient(fastapi_app.app) as client:
            resp = client.get(f"/remediations/{remediation['id']}/pr-readiness", headers=_headers("viewer"))
            assert resp.status_code == 200
            body = resp.json()
            assert body["ready"] is False
            assert body["phase"] == "needs_validation"
            assert body["next_action"] == "validate"
            assert "github_credential_id is required" in body["blockers"]
            assert "latest validation must pass before PR creation" in body["blockers"]
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_pr_readiness_ready_after_validation_and_live_github_diagnostic():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    original_diag = getattr(fastapi_app, "diagnose_github_repo_access", None)
    fastapi_app.diagnose_github_repo_access = lambda credential_id, repo_full_name, check_repo_metadata=True: {
        "ok": True,
        "credential_id": credential_id,
        "repo_full_name": repo_full_name,
        "checks": {"repo_metadata": bool(check_repo_metadata)},
    }
    try:
        remediation = _remediation(status="approved")
        validation = create_validation_job(int(remediation["id"]), status="queued")
        update_validation_job(int(validation["id"]), status="passed", exit_code=0, finished=True)
        with TestClient(fastapi_app.app) as client:
            resp = client.get(
                f"/v1/remediations/{remediation['id']}/pr-readiness",
                headers=_headers("operator"),
                params={"github_credential_id": 7, "check_live_repo": True},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["ready"] is True
            assert body["phase"] == "ready"
            assert body["next_action"] == "create_pr"
            assert body["github"]["diagnostics"]["ok"] is True
            assert body["calls"]["create_pr"].endswith("/create-pr")
    finally:
        if original_diag is not None:
            fastapi_app.diagnose_github_repo_access = original_diag
        else:
            delattr(fastapi_app, "diagnose_github_repo_access")
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
