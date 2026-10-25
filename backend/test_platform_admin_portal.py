"""Vendor admin portal backend: operator identity, the four auth defects, and the operator additions.

Runs the real ASGI stack (middleware, routes, SQLite) against a throwaway database, with JWT auth
required as in production. Each defect test fails on the code before the fix:

  1. POST /platform/retention/run let support/auditor run a real (deleting) retention pass.
  2. /auth/users* skipped the admin check when no bearer token was sent, and trusted x-org-id.
  3. POST /admin/accept-invite had no guard: any caller with a token could accept for anyone, twice.
  4. A missing or unknown x-platform-admin-role meant owner.
"""

import csv
import hashlib
import io
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from services import api_keys, auth_issuer

SECRET = "portal-tests-jwt-signing-key-not-for-deployment-73"
LEGACY = "legacy-shared-platform-key-for-tests-0123456789"
ALICE = "alice-named-operator-key-for-tests-0123456789"
SAM = "sam-support-operator-key-for-tests-0123456789"
ADMIN_EMAIL = "portal-admin@example.test"
PASSWORD = "portal-tests-password-731"


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "portal.db"))
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("MORROW_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("MORROW_ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("MORROW_PLATFORM_OPERATORS", json.dumps([
        {"name": "alice", "role": "owner", "key_sha256": _sha(ALICE)},
        {"name": "sam", "role": "support", "key_sha256": _sha(SAM)},
    ]))
    monkeypatch.delenv("MORROW_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_ISSUER_ENABLED": True,
        "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": SECRET,
        "AUTH_JWT_ISSUER": "morrow", "AUTH_JWT_AUDIENCE": "morrow",
        "AUTH_USER_ID_CLAIM": "sub", "AUTH_ROLE_CLAIM": "role", "AUTH_ORG_ID_CLAIM": "org_id",
        "_PLATFORM_ADMIN_KEY": LEGACY, "API_KEY": "", "PRODUCTION_ENVIRONMENT": False,
        "RATE_LIMIT_MAX_REQUESTS": 100000,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(auth_issuer, "_SECRET", SECRET)
    monkeypatch.setattr(auth_issuer, "_ISSUER", "morrow")
    monkeypatch.setattr(auth_issuer, "_AUDIENCE", "morrow")
    monkeypatch.setattr(auth_issuer, "_ENABLED", True)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    client = TestClient(app.app, client=("192.0.2.20", 40000))
    yield client, app
    client.close()


def legacy(role=None):
    headers = {"x-platform-key": LEGACY}
    if role:
        headers["x-platform-admin-role"] = role
    return headers


def named(key, role=None):
    headers = {"x-platform-key": key}
    if role:
        headers["x-platform-admin-role"] = role
    return headers


def bearer(token):
    return {"authorization": f"Bearer {token}"}


def make_org(client, org_id):
    res = client.post("/platform/customers", headers=legacy("owner"),
                      json={"organization_id": org_id, "name": org_id.title(), "reason": "test setup"})
    assert res.status_code == 200, res.text


def make_user(app, email, role="viewer", org="org-alpha"):
    with app._db() as conn:
        return auth_issuer.create_user(conn, email, PASSWORD, "Test User", role, org)


def login(client, email):
    res = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return res.json()


# ── Defect 4 and operator identity ───────────────────────────────────────────


def test_shared_key_without_a_role_is_an_auditor_and_cannot_write(api):
    client, _ = api
    who = client.get("/platform/whoami", headers=legacy())
    assert who.status_code == 200, who.text
    assert who.json()["role"] == "auditor"
    assert who.json()["ceiling_role"] == "owner" and who.json()["role_bound"] is False
    assert client.post("/platform/traffic/clear", headers=legacy()).status_code == 403
    assert client.post("/platform/traffic/clear", headers=legacy("owner")).status_code == 200


def test_unknown_role_is_rejected_instead_of_becoming_owner(api):
    client, _ = api
    assert client.get("/platform/whoami", headers=legacy("superuser")).status_code == 400
    assert client.post("/platform/traffic/clear", headers=legacy("root")).status_code == 400


def test_shared_key_cannot_exceed_its_configured_ceiling(api, monkeypatch):
    client, _ = api
    monkeypatch.setenv("MORROW_PLATFORM_ADMIN_KEY_ROLE", "support")
    assert client.get("/platform/whoami", headers=legacy("owner")).status_code == 403
    assert client.get("/platform/whoami", headers=legacy("support")).json()["role"] == "support"


def test_named_operator_role_is_bound_to_the_key_and_named_in_the_audit_trail(api, monkeypatch):
    client, app = api
    sam = client.get("/platform/whoami", headers=named(SAM)).json()
    assert sam["operator"] == "sam" and sam["role"] == "support" and sam["role_bound"] is True
    assert client.get("/platform/whoami", headers=named(SAM, "owner")).status_code == 403
    assert client.get("/platform/whoami", headers=named(SAM, "auditor")).json()["role"] == "auditor"
    denied = client.post("/platform/customers", headers=named(SAM),
                         json={"organization_id": "org-sam", "name": "Sam", "reason": "should be refused"})
    assert denied.status_code == 403
    assert client.get("/platform/operators", headers=named(SAM)).status_code == 403
    roster = client.get("/platform/operators", headers=named(ALICE))
    assert roster.status_code == 200 and _sha(ALICE) not in roster.text

    created = client.post("/platform/customers", headers=named(ALICE),
                          json={"organization_id": "org-alice", "name": "Alice Co", "reason": "named operator setup"})
    assert created.status_code == 200, created.text
    events = client.get("/platform/admin-events/search?action=platform.customer_created", headers=named(ALICE)).json()["items"]
    assert events and events[0]["actor_id"] == "alice" and events[0]["operator_role"] == "owner"
    assert events[0]["details"]["operator"]["credential_source"] == "named_operator"

    # Named operators work with the shared key switched off entirely.
    monkeypatch.setattr(app, "_PLATFORM_ADMIN_KEY", "")
    assert client.get("/platform/whoami", headers=named(ALICE)).json()["operator"] == "alice"
    assert client.get("/platform/whoami", headers=legacy("owner")).status_code in (401, 403)


# ── Defect 1 ────────────────────────────────────────────────────────────────


def test_a_deleting_retention_run_requires_a_write_role(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app, "_run_platform_retention", lambda req: {"api_version": "v1", "dry_run": req.dry_run, "items": []})
    assert client.post("/platform/retention/run", headers=legacy("auditor"), json={"dry_run": True}).status_code == 200
    for role in ("auditor", "support"):
        res = client.post("/platform/retention/run", headers=legacy(role), json={"dry_run": False})
        assert res.status_code == 403, f"{role} ran a deleting retention pass"
    assert client.post("/platform/retention/run", headers=legacy("operator"), json={"dry_run": False}).status_code == 200


# ── Defect 2 ────────────────────────────────────────────────────────────────


def test_auth_user_management_always_requires_an_admin_bearer_for_its_own_org(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)  # the endpoint must defend itself, not rely on middleware
    make_user(app, "viewer-a@example.test", "viewer", "org-alpha")
    other = make_user(app, "other-org@example.test", "viewer", "org-beta")
    for method, path, body in (("GET", "/auth/users", None),
                               ("PUT", f"/auth/users/{other['id']}/role", {"role": "admin"}),
                               ("POST", f"/auth/users/{other['id']}/deactivate", None)):
        res = client.request(method, path, json=body, headers={"x-org-id": "org-beta"})
        assert res.status_code == 401, f"{method} {path} answered {res.status_code} without a bearer token"
    viewer = login(client, "viewer-a@example.test")["access_token"]
    assert client.get("/auth/users", headers=bearer(viewer)).status_code == 403
    admin = login(client, ADMIN_EMAIL)["access_token"]
    listed = client.get("/auth/users", headers={**bearer(admin), "x-org-id": "org-beta"})
    assert listed.status_code == 200
    emails = {u["email"] for u in listed.json()["users"]}
    assert ADMIN_EMAIL in emails and "other-org@example.test" not in emails
    cross = client.put(f"/auth/users/{other['id']}/role", headers={**bearer(admin), "x-org-id": "org-beta"}, json={"role": "admin"})
    assert cross.status_code == 404
    mine = make_user(app, "promote-me@example.test", "viewer", "org-alpha")
    assert client.put(f"/auth/users/{mine['id']}/role", headers=bearer(admin), json={"role": "superuser"}).status_code == 400
    assert client.put(f"/auth/users/{mine['id']}/role", headers=bearer(admin), json={"role": "operator"}).status_code == 200


# ── Defect 3 ────────────────────────────────────────────────────────────────


def test_accepting_an_invite_is_bound_to_the_signed_in_invitee_and_single_use(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)
    make_org(client, "org-invite")
    created = client.post("/platform/customers/org-invite/invitations", headers=legacy("operator"),
                          json={"email": "Invitee@Example.test", "role": "analyst", "reason": "onboarding"})
    assert created.status_code == 200, created.text
    invitation = created.json()["invitation"]
    # The response carries the one-time link, never the bare token (September 2026 review, 3).
    assert "token" not in invitation, invitation
    token = re.search(r"#token=([A-Za-z0-9_-]+)", invitation["invite_link"]).group(1)
    listed = client.get("/platform/customers/org-invite/invitations", headers=legacy()).json()["items"]
    assert listed[0]["invite_id"] == invitation["invite_id"] and token not in json.dumps(listed)

    # The token travels in the JSON body; a query string would be logged by every proxy in front
    # of the app, and this is a live bearer credential.
    path, body = "/admin/accept-invite", {"token": token}
    assert client.post(path, json=body).status_code == 401
    make_user(app, "someone-else@example.test")
    make_user(app, "invitee@example.test")
    wrong = login(client, "someone-else@example.test")["access_token"]
    assert client.post(path, json=body, headers=bearer(wrong)).status_code == 403
    invitee = login(client, "invitee@example.test")
    accepted = client.post(path, json=body, headers=bearer(invitee["access_token"]))
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["user_id"] == invitee["user"]["id"] and accepted.json()["membership_role"] == "operator"
    assert client.post(path, json=body, headers=bearer(invitee["access_token"])).status_code == 409
    assert client.post(path, json={"token": "not-a-real-invitation"},
                       headers=bearer(invitee["access_token"])).status_code == 404
    assert client.post(f"{path}?token={token}", headers=bearer(invitee["access_token"])).status_code == 422

    from db import get_organization_member
    assert get_organization_member("org-invite", invitee["user"]["id"])["role"] == "operator"

    late = client.post("/platform/customers/org-invite/invitations", headers=legacy("operator"),
                       json={"email": "invitee@example.test", "role": "viewer", "reason": "second invite"}).json()["invitation"]
    late_token = re.search(r"#token=([A-Za-z0-9_-]+)", late["invite_link"]).group(1)
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE admin_invitations SET expires_at = ? WHERE token = ?", ("2000-01-01T00:00:00+00:00", late_token))
        conn.commit()
    assert client.post(path, json={"token": late_token},
                       headers=bearer(invitee["access_token"])).status_code == 410


def test_invitations_can_be_revoked_by_id(api):
    client, _ = api
    make_org(client, "org-revoke-invite")
    invitation = client.post("/platform/customers/org-revoke-invite/invitations", headers=legacy("operator"),
                             json={"email": "gone@example.test", "role": "viewer", "reason": "mistake"}).json()["invitation"]
    url = f"/platform/customers/org-revoke-invite/invitations/{invitation['invite_id']}"
    assert client.delete(url, headers=legacy("auditor")).status_code in (403, 422)
    assert client.delete(url + "?reason=sent+in+error", headers=legacy("operator")).status_code == 200
    assert client.get("/platform/customers/org-revoke-invite/invitations", headers=legacy()).json()["items"] == []


# ── Sessions ────────────────────────────────────────────────────────────────


def test_revoking_a_user_cuts_off_access_and_refresh_tokens(api):
    client, app = api
    make_user(app, "session-user@example.test", "viewer", "org-alpha")
    session = login(client, "session-user@example.test")
    uid = session["user"]["id"]
    assert client.get("/auth/context", headers=bearer(session["access_token"])).json()["authenticated"] is True
    listed = client.get(f"/platform/sessions?user_id={uid}", headers=legacy())
    assert listed.status_code == 200 and len(listed.json()["items"]) == 1
    assert session["refresh_token"] not in listed.text
    body = {"user_id": uid, "reason": "lost laptop"}
    assert client.post("/platform/sessions/revoke", headers=legacy(), json=body).status_code == 403
    revoked = client.post("/platform/sessions/revoke", headers=legacy("operator"), json=body)
    assert revoked.status_code == 200 and revoked.json()["refresh_sessions_revoked"] == 1
    assert client.get("/auth/context", headers=bearer(session["access_token"])).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
    time.sleep(1.1)  # tokens issued in the revocation second are still cut off
    fresh = login(client, "session-user@example.test")
    assert client.get("/auth/context", headers=bearer(fresh["access_token"])).json()["authenticated"] is True


# ── API keys ────────────────────────────────────────────────────────────────


def test_api_keys_are_bound_to_one_org_scoped_and_fail_once_revoked_rotated_or_expired(api):
    client, _ = api
    make_org(client, "org-keys-a")
    make_org(client, "org-keys-b")
    create_url = "/platform/customers/org-keys-a/api-keys"
    assert client.post(create_url, headers=legacy(), json={"name": "x", "scopes": ["read"], "reason": "auditor"}).status_code == 403
    read = client.post(create_url, headers=legacy("operator"), json={"name": "CI reader", "scopes": ["read"], "reason": "pipeline"})
    assert read.status_code == 200, read.text
    read_secret, read_id = read.json()["secret"], read.json()["key"]["id"]
    assert read_secret.startswith("pq_")
    listing = client.get(create_url, headers=legacy()).text
    assert read_secret not in listing and "key_hash" not in listing and "salt" not in listing

    ctx = client.get("/auth/context", headers={**bearer(read_secret), "x-org-id": "org-keys-b"})
    assert ctx.status_code == 200, ctx.text
    assert ctx.json()["authenticated"] is True
    assert ctx.json()["organization_id"] == "org-keys-a" and ctx.json()["actor_role"] == "viewer"
    assert client.post("/assets", headers=bearer(read_secret), json={}).status_code == 403
    assert client.get("/platform/whoami", headers=bearer(read_secret)).status_code == 403
    assert client.get("/auth/users", headers=bearer(read_secret)).status_code == 403

    write = client.post(create_url, headers=legacy("operator"), json={"name": "Deployer", "scopes": ["write"], "reason": "deploys"}).json()
    assert client.get("/auth/context", headers=bearer(write["secret"])).json()["actor_role"] == "operator"
    rotated = client.post(f"/platform/api-keys/{write['key']['id']}/rotate", headers=legacy("operator"), json={"reason": "scheduled rotation"})
    assert rotated.status_code == 200, rotated.text
    assert client.get("/auth/context", headers=bearer(write["secret"])).status_code == 401
    assert client.get("/auth/context", headers=bearer(rotated.json()["secret"])).status_code == 200

    assert client.post(f"/platform/api-keys/{read_id}/revoke", headers=legacy("operator"), json={"reason": "leaked"}).status_code == 200
    revoked = client.get("/auth/context", headers=bearer(read_secret))
    assert revoked.status_code == 401 and "revoked" in revoked.json()["detail"]

    expiring = client.post(create_url, headers=legacy("operator"),
                           json={"name": "Short", "scopes": ["read"], "expires_in_days": 1, "reason": "temporary"}).json()
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE platform_api_keys SET expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00Z", expiring["key"]["id"]))
        conn.commit()
    api_keys._clear_cache()
    expired = client.get("/auth/context", headers=bearer(expiring["secret"]))
    assert expired.status_code == 401 and "expired" in expired.json()["detail"]
    assert client.get("/auth/context", headers=bearer("pq_notavalidkey")).status_code == 401
    bad_scope = client.post(create_url, headers=legacy("operator"), json={"name": "x", "scopes": ["root"], "reason": "bad scope"})
    assert bad_scope.status_code == 400


# ── Announcements & maintenance ─────────────────────────────────────────────


def test_announcements_target_orgs_and_maintenance_pauses_only_customer_writes(api):
    client, app = api
    make_org(client, "org-news")
    make_user(app, "news-user@example.test", "viewer", "org-news")
    session = login(client, "news-user@example.test")
    token = session["access_token"]

    def create(**payload):
        res = client.post("/platform/announcements", headers=legacy("operator"), json=payload)
        assert res.status_code == 200, res.text
        return res.json()["announcement"]

    everyone = create(title="Planned upgrade", body="Saturday 09:00 UTC", severity="warn")
    targeted = create(title="Your renewal", audience="orgs", organization_ids=["org-news"])
    create(title="Future notice", starts_at="2999-01-01T00:00:00Z")
    assert client.post("/platform/announcements", headers=legacy("operator"), json={"title": "Bad", "audience": "orgs"}).status_code == 400

    anonymous = client.get("/announcements/active")
    assert anonymous.status_code == 200
    assert [i["id"] for i in anonymous.json()["items"]] == [everyone["id"]]
    mine = client.get("/announcements/active", headers=bearer(token)).json()
    assert {i["id"] for i in mine["items"]} == {everyone["id"], targeted["id"]} and mine["organization_id"] == "org-news"

    maintenance = {"enabled": True, "message": "Database upgrade in progress", "reason": "upgrade window"}
    assert client.put("/platform/maintenance", headers=legacy("auditor"), json=maintenance).status_code == 403
    assert client.put("/platform/maintenance", headers=legacy("operator"), json=maintenance).json()["enabled"] is True
    blocked = client.post("/assets", headers=bearer(token), json={})
    assert blocked.status_code == 503
    assert blocked.json()["detail"] == "Database upgrade in progress" and int(blocked.headers["retry-after"]) > 0
    assert client.get("/auth/context", headers=bearer(token)).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 200
    status = client.get("/status").json()
    assert status["maintenance"] == {"enabled": True, "message": "Database upgrade in progress", "ends_at": ""}
    assert client.get("/announcements/active").json()["maintenance"]["enabled"] is True

    assert client.put("/platform/maintenance", headers=legacy("operator"), json={"enabled": False, "reason": "done"}).status_code == 200
    assert client.post("/assets", headers=bearer(token), json={}).status_code != 503
    assert client.get("/status").json()["maintenance"]["enabled"] is False


# ── Lifecycle, access, audit ────────────────────────────────────────────────


def test_purge_requires_the_owner_and_the_typed_organization_id(api):
    client, _ = api
    make_org(client, "org-purge")
    body = {"confirm_organization_id": "org-purge", "reason": "contract ended"}
    url = "/platform/customers/org-purge/purge"
    assert client.post(url, headers=legacy("operator"), json=body).status_code == 403
    assert client.post(url, headers=legacy("owner"), json={**body, "confirm_organization_id": "org-purg"}).status_code == 400
    done = client.post(url, headers=legacy("owner"), json=body)
    assert done.status_code == 200, done.text
    assert client.get("/platform/customers/org-purge/users", headers=legacy()).status_code == 404


def test_member_role_change_deactivation_and_removal_are_audited(api):
    client, _ = api
    make_org(client, "org-members")
    base = "/platform/customers/org-members"
    added = client.post(f"{base}/members", headers=legacy("operator"),
                        json={"user_id": "sso-123", "email": "sso@example.test", "role": "viewer", "reason": "SSO onboarding"})
    assert added.status_code == 200, added.text
    changed = client.patch(f"{base}/members/sso-123", headers=legacy("operator"), json={"role": "admin", "reason": "promoted"})
    assert changed.status_code == 200 and changed.json()["member"]["role"] == "admin"
    off = client.post(f"{base}/users/sso-123/deactivate", headers=legacy("operator"), json={"reason": "left the company"})
    assert off.status_code == 200
    assert off.json()["member"]["status"] == "disabled" and off.json()["access_tokens_revoked"] is True
    users = client.get("/platform/users?q=sso@example", headers=legacy()).json()["items"]
    assert users and users[0]["status"] == "disabled" and users[0]["role"] == "admin"
    assert client.delete(f"{base}/members/sso-123", headers=legacy("operator")).status_code == 422
    assert client.delete(f"{base}/members/sso-123?reason=offboarded", headers=legacy("operator")).status_code == 200
    actions = {e["action"] for e in client.get("/platform/admin-events/search?organization_id=org-members&limit=50", headers=legacy()).json()["items"]}
    assert {"platform.member_added", "platform.member_role_changed", "platform.user_deactivated", "platform.member_removed"} <= actions


def test_admin_event_search_validates_dates_and_csv_export_neutralises_formulas(api):
    client, _ = api
    res = client.post("/platform/customers", headers=legacy("owner"),
                      json={"organization_id": "org-audit", "name": "Audit Co", "reason": '=HYPERLINK("http://evil.example")'})
    assert res.status_code == 200, res.text
    found = client.get("/platform/admin-events/search?q=HYPERLINK&organization_id=org-audit", headers=legacy()).json()
    assert found["total"] == 1 and found["items"][0]["action"] == "platform.customer_created"
    assert client.get("/platform/admin-events/search?since=yesterday", headers=legacy()).status_code == 400
    export = client.get("/platform/admin-events/export.csv?organization_id=org-audit", headers=legacy())
    assert export.status_code == 200 and export.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(export.text)))
    assert rows and all(not r["reason"].startswith("=") for r in rows)
    assert any(r["reason"].startswith("'=") for r in rows)


@pytest.mark.parametrize("method,path", [
    ("PUT", "/platform/maintenance"),
    ("POST", "/platform/sessions/revoke"),
    ("POST", "/platform/customers"),
    ("POST", "/platform/customers/org-x/purge"),
    ("POST", "/platform/customers/org-x/archive"),
    ("POST", "/platform/api-keys/1/revoke"),
    ("POST", "/platform/api-keys/1/rotate"),
    ("PUT", "/platform/announcements/1"),
    ("DELETE", "/platform/announcements/1"),
    ("DELETE", "/platform/customers/org-x/members/1"),
])
def test_destructive_platform_routes_reject_an_empty_body(api, method, path):
    """The endpoint smoke test sends {} to every write route as an owner; none of these may act on it."""
    client, _ = api
    assert client.request(method, path, headers=legacy("owner"), json={}).status_code == 422
