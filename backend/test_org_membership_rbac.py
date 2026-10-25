import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    get_organization_member,
    init_db,
    reset_current_organization_id,
    set_current_organization_id,
    upsert_organization,
    upsert_organization_member,
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


def _headers(user_id="admin-user", role="admin", org_id="org-alpha"):
    return {"x-user-id": user_id, "x-user-role": role, "x-org-id": org_id}


def test_org_admin_can_manage_members_and_auth_context_uses_membership_role():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id("org-alpha")
    try:
        upsert_organization("org-alpha", "Org Alpha")
        upsert_organization_member("org-alpha", "admin-user", role="admin")
        with TestClient(fastapi_app.app) as client:
            created = client.post(
                "/organizations/org-alpha/members",
                headers=_headers(),
                json={"user_id": "operator-user", "role": "operator", "display_name": "Operator", "email": "op@example.com"},
            )
            assert created.status_code == 200
            assert created.json()["member"]["role"] == "operator"

            context = client.get("/auth/context", headers=_headers(user_id="operator-user", role="viewer"))
            assert context.status_code == 200
            assert context.json()["actor_role"] == "operator"
            assert context.json()["membership"]["user_id"] == "operator-user"

            updated = client.patch(
                "/organizations/org-alpha/members/operator-user",
                headers=_headers(),
                json={"role": "viewer", "status": "active"},
            )
            assert updated.status_code == 200
            assert updated.json()["member"]["role"] == "viewer"
            assert get_organization_member("org-alpha", "operator-user")["role"] == "viewer"

            memberships = client.get("/auth/memberships", headers=_headers(user_id="operator-user", role="viewer"))
            assert memberships.status_code == 200
            assert memberships.json()["items"][0]["organization_id"] == "org-alpha"
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_viewer_cannot_manage_members_and_cross_org_is_blocked():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id("org-alpha")
    try:
        upsert_organization("org-alpha", "Org Alpha")
        upsert_organization("org-beta", "Org Beta")
        upsert_organization_member("org-alpha", "viewer-user", role="viewer")
        upsert_organization_member("org-alpha", "admin-user", role="admin")
        with TestClient(fastapi_app.app) as client:
            denied = client.post(
                "/organizations/org-alpha/members",
                headers=_headers(user_id="viewer-user", role="admin", org_id="org-alpha"),
                json={"user_id": "new-user", "role": "viewer"},
            )
            assert denied.status_code == 403

            cross = client.post(
                "/organizations/org-beta/members",
                headers=_headers(user_id="admin-user", role="admin", org_id="org-alpha"),
                json={"user_id": "beta-user", "role": "viewer"},
            )
            assert cross.status_code == 403
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_admin_can_remove_member():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id("org-alpha")
    try:
        upsert_organization("org-alpha", "Org Alpha")
        upsert_organization_member("org-alpha", "admin-user", role="admin")
        upsert_organization_member("org-alpha", "remove-me", role="viewer")
        with TestClient(fastapi_app.app) as client:
            removed = client.delete(
                "/organizations/org-alpha/members/remove-me",
                headers=_headers(),
            )
            assert removed.status_code == 200
            assert removed.json()["deleted"] == 1
            assert get_organization_member("org-alpha", "remove-me") is None
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
