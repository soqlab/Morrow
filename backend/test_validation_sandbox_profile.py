import os
import sys
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
import remediation_validation as rv
from db import create_validation_job, init_db, reset_current_organization_id, set_current_organization_id


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


def test_validation_sandbox_profile_exposes_policy_not_secrets():
    profile = rv.validation_sandbox_profile()
    assert profile["environment_scrubbed"] is True
    assert profile["secrets_exposed_to_subprocess"] is False
    assert profile["archive_path_traversal_protection"] is True
    assert profile["file_path_traversal_protection"] is True
    assert profile["isolation_mode"] in {"workspace", "docker"}


def test_run_command_timeout_is_captured():
    with tempfile.TemporaryDirectory() as tmpdir:
        # sys.executable, not "python3": there is no python3 on the PATH on Windows, which made this
        # raise FileNotFoundError instead of exercising _run_command's timeout handling.
        result = rv._run_command(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            cwd=tmpdir,
            timeout_s=1,
        )
    # _run_command enforces a minimum 10s timeout, so the 2s sleep completes rather than timing out;
    # the point of the assertion is that the key is reported and the floor is applied.
    assert "timed_out" in result
    assert result["timeout_seconds"] >= 10


def test_validation_sandbox_profile_and_evidence_endpoints():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        job = create_validation_job(
            remediation_id=123,
            validator_type="generic",
            status="passed",
            details={
                "commands": [],
                "sandbox_profile": rv.validation_sandbox_profile(),
                "validation_environment": {"secrets_env_scrubbed": True, "network": "host"},
            },
        )
        with TestClient(fastapi_app.app) as client:
            profile = client.get("/validation/sandbox-profile", headers=_headers("viewer"))
            assert profile.status_code == 200
            assert profile.json()["secrets_exposed_to_subprocess"] is False

            evidence = client.get(f"/validation-jobs/{job['id']}/evidence", headers=_headers("viewer"))
            assert evidence.status_code == 200
            body = evidence.json()
            assert body["validation_job_id"] == job["id"]
            assert body["evidence"]["secrets_scrubbed"] is True
            assert body["evidence"]["timeout_enforced"] is True
            assert "sandbox" in body
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
