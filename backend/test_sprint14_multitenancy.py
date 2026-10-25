import base64
import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    append_audit_log,
    create_schedule,
    create_remediation,
    get_collection,
    get_schedule,
    init_db,
    list_collections,
    list_schedules,
    reset_current_organization_id,
    set_current_organization_id,
    upsert_collection,
    upsert_asset,
    upsert_repository,
)


def _fake_jwt(payload: dict) -> str:
    def _enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    return f"{_enc({'alg':'none','typ':'JWT'})}.{_enc(payload)}."


@pytest.fixture(scope="module")
def client():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    _previous_db = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name

    # Disable startup hooks (Vault/Postgres)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()
    with TestClient(fastapi_app.app) as c:
        yield c

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


def test_org_context_from_jwt_and_header_fallback(client):
    tok = _fake_jwt({"org_id": "org-alpha"})
    r = client.get(
        "/auth/context",
        headers={"authorization": f"Bearer {tok}", "x-user-role": "operator", "x-user-id": "alice"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["organization_id"] == "org-alpha"
    assert body["actor_role"] == "operator"

    # Header fallback when no JWT
    r2 = client.get(
        "/auth/context",
        headers={"x-org-id": "org-beta", "x-user-role": "viewer", "x-user-id": "bob"},
    )
    assert r2.status_code == 200
    assert r2.json()["organization_id"] == "org-beta"


def test_remediations_are_scoped_by_org(client):
    t1 = set_current_organization_id("org-alpha")
    try:
        r1 = create_remediation(
            asset_key_str="alpha.example:443",
            repo_id=0,
            file_path="main.tf",
            vulnerability="require tls1.3",
            suggested_fix="",
            original_content='minimum_tls_version = "TLS1_2"\n',
            suggested_content='minimum_tls_version = "TLS1_3"\n',
            status="pending",
        )
    finally:
        reset_current_organization_id(t1)

    t2 = set_current_organization_id("org-beta")
    try:
        r2 = create_remediation(
            asset_key_str="beta.example:443",
            repo_id=0,
            file_path="main.tf",
            vulnerability="require tls1.3",
            suggested_fix="",
            original_content='minimum_tls_version = "TLS1_2"\n',
            suggested_content='minimum_tls_version = "TLS1_3"\n',
            status="pending",
        )
    finally:
        reset_current_organization_id(t2)

    tok_alpha = _fake_jwt({"org_id": "org-alpha"})
    resp_alpha = client.get(
        "/remediations",
        headers={"authorization": f"Bearer {tok_alpha}", "x-user-role": "operator", "x-user-id": "alice"},
    )
    assert resp_alpha.status_code == 200
    ids_alpha = {int(x["id"]) for x in (resp_alpha.json().get("items") or [])}
    assert int(r1["id"]) in ids_alpha
    assert int(r2["id"]) not in ids_alpha

    tok_beta = _fake_jwt({"organization_id": "org-beta"})
    resp_beta = client.get(
        "/remediations",
        headers={"authorization": f"Bearer {tok_beta}", "x-user-role": "operator", "x-user-id": "bob"},
    )
    assert resp_beta.status_code == 200
    ids_beta = {int(x["id"]) for x in (resp_beta.json().get("items") or [])}
    assert int(r2["id"]) in ids_beta
    assert int(r1["id"]) not in ids_beta


def test_audit_logs_are_scoped_by_org(client):
    ta = set_current_organization_id("org-alpha")
    try:
        append_audit_log(
            actor_id="alpha-admin",
            actor_role="admin",
            action="org.test",
            resource_type="tenant",
            resource_id="alpha",
        )
    finally:
        reset_current_organization_id(ta)

    tb = set_current_organization_id("org-beta")
    try:
        append_audit_log(
            actor_id="beta-admin",
            actor_role="admin",
            action="org.test",
            resource_type="tenant",
            resource_id="beta",
        )
    finally:
        reset_current_organization_id(tb)

    tok_alpha = _fake_jwt({"org": "org-alpha"})
    a = client.get(
        "/audit/logs?action=org.test",
        headers={"authorization": f"Bearer {tok_alpha}", "x-user-role": "admin", "x-user-id": "sec-alpha"},
    )
    assert a.status_code == 200
    items_a = a.json().get("items") or []
    assert any(x.get("actor_id") == "alpha-admin" for x in items_a)
    assert all(x.get("actor_id") != "beta-admin" for x in items_a)


def test_cross_tenant_duplicate_repo_and_asset_keys_allowed(client):
    t1 = set_current_organization_id("org-alpha")
    try:
        ra = upsert_repository("shared/repo", "https://github.com/shared/repo")
        upsert_asset("shared.example:443", repository_id=int(ra["id"]))
    finally:
        reset_current_organization_id(t1)

    t2 = set_current_organization_id("org-beta")
    try:
        rb = upsert_repository("shared/repo", "https://github.com/shared/repo")
        upsert_asset("shared.example:443", repository_id=int(rb["id"]))
    finally:
        reset_current_organization_id(t2)

    assert int(ra["id"]) != int(rb["id"])

    repos_alpha = client.get("/repositories", headers={"x-org-id": "org-alpha"}).json().get("items") or []
    repos_beta = client.get("/repositories", headers={"x-org-id": "org-beta"}).json().get("items") or []
    shared_alpha = [r for r in repos_alpha if r.get("name") == "shared/repo"]
    shared_beta = [r for r in repos_beta if r.get("name") == "shared/repo"]
    assert len(shared_alpha) == 1
    assert len(shared_beta) == 1
    assert int(shared_alpha[0]["id"]) != int(shared_beta[0]["id"])

    assets_alpha = client.get("/assets", headers={"x-org-id": "org-alpha"}).json().get("items") or []
    assets_beta = client.get("/assets", headers={"x-org-id": "org-beta"}).json().get("items") or []
    sa = [a for a in assets_alpha if a.get("asset_key") == "shared.example:443"]
    sb = [a for a in assets_beta if a.get("asset_key") == "shared.example:443"]
    assert len(sa) == 1
    assert len(sb) == 1
    assert int(sa[0].get("repository_id") or 0) == int(shared_alpha[0]["id"])
    assert int(sb[0].get("repository_id") or 0) == int(shared_beta[0]["id"])


def test_collections_and_schedules_are_scoped_by_org(client):
    ta = set_current_organization_id("org-alpha")
    try:
        ca = upsert_collection("daily-prod", "alpha.example:443")
        sa = create_schedule(int(ca["id"]), 60, enabled=True)
    finally:
        reset_current_organization_id(ta)

    tb = set_current_organization_id("org-beta")
    try:
        cb = upsert_collection("daily-prod", "beta.example:443")
        sb = create_schedule(int(cb["id"]), 120, enabled=True)
        beta_collections = list_collections()
        beta_schedules = list_schedules()
    finally:
        reset_current_organization_id(tb)

    assert int(ca["id"]) != int(cb["id"])
    assert [x["name"] for x in beta_collections] == ["daily-prod"]
    assert {int(x["id"]) for x in beta_schedules} == {int(sb["id"])}

    ta = set_current_organization_id("org-alpha")
    try:
        alpha_collections = list_collections()
        alpha_schedules = list_schedules()
        assert get_collection(int(ca["id"]))["name"] == "daily-prod"
        assert get_schedule(int(sa["id"]))["interval_minutes"] == 60
        with pytest.raises(KeyError):
            get_collection(int(cb["id"]))
        with pytest.raises(KeyError):
            get_schedule(int(sb["id"]))
    finally:
        reset_current_organization_id(ta)

    assert [x["name"] for x in alpha_collections] == ["daily-prod"]
    assert {int(x["id"]) for x in alpha_schedules} == {int(sa["id"])}
