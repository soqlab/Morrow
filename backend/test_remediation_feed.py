import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    create_migration_task,
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
    os.environ["MORROW_MAIN_DB_BACKEND"] = ""
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    return tmp_db


def _headers(role="operator"):
    return {"x-user-role": role, "x-user-id": f"{role}-user"}


def test_remediation_feed_returns_action_cards_and_summary():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/platform", "https://github.com/acme/platform")
        create_remediation(
            "api.example:443",
            int(repo["id"]),
            "infra/tls.tf",
            "high risk RSA certificate dependency",
            "Replace RSA with hybrid post-quantum-ready TLS configuration",
            status="pending",
        )
        approved = create_remediation(
            "checkout.example:443",
            int(repo["id"]),
            "infra/checkout.tf",
            "critical TLS policy gap",
            "Enforce TLS 1.3 and hybrid key exchange",
            status="approved",
        )
        validation = create_validation_job(int(approved["id"]), validator_type="terraform", status="queued")
        update_validation_job(int(validation["id"]), status="passed", exit_code=0, stdout="ok", stderr="", finished=True)
        create_migration_task(
            asset_key_str="legacy.example:443",
            repository_name="acme/platform",
            repo_id=int(repo["id"]),
            file_path="requirements.txt",
            rule_id="legacy-crypto-library",
            legacy_dependency="pycrypto",
            migration_target="cryptography",
            confidence="high",
            status="open",
        )

        with TestClient(fastapi_app.app) as client:
            resp = client.get("/v1/work/remediation-feed", headers=_headers("viewer"))
            assert resp.status_code == 200
            body = resp.json()
            assert body["api_version"] == "v1"
            assert body["summary"]["total"] == 3
            assert body["summary"]["safe_to_apply"] >= 2
            assert body["summary"]["columns"]["candidates"] == 1
            assert body["summary"]["columns"]["pull_request"] == 1
            assert body["summary"]["columns"]["migration_tasks"] == 1

            cards = body["cards"]
            kinds = {card["kind"] for card in cards}
            assert {"remediation", "migration_task"} == kinds
            assert any(card["next_action"] == "create_pr" and card["validation_status"] == "passed" for card in cards)
            assert any(card["next_action"] == "plan_migration" and card["safe_to_apply"] is False for card in cards)
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_remediation_feed_filters_by_kind_and_repository():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        repo = upsert_repository("acme/payments", "https://github.com/acme/payments")
        create_migration_task(
            asset_key_str="payments.example:443",
            repository_name="acme/payments",
            repo_id=int(repo["id"]),
            file_path="pom.xml",
            legacy_dependency="legacy-jce-provider",
            migration_target="modern-provider",
            status="planned",
        )

        with TestClient(fastapi_app.app) as client:
            resp = client.get(
                "/work/remediation-feed",
                headers=_headers("viewer"),
                params={"kind": "migration_task", "repository": "payments"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["summary"]["total"] == 1
            assert body["cards"][0]["kind"] == "migration_task"
            assert body["cards"][0]["repository"] == "acme/payments"
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
