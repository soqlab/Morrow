"""Vendor support "view as customer": read-only, time-limited, customer-visible, hard-limited.

Runs the real ASGI stack against a throwaway database with JWT auth required, as in production.
"""

import hashlib
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from services import auth_issuer
from services import support_sessions as support

SECRET = "support-view-tests-jwt-signing-key-not-for-deploy-41"
LEGACY = "legacy-shared-platform-key-for-support-tests-0123456789"
ALICE = "alice-owner-key-for-support-tests-0123456789"
OLGA = "olga-operator-key-for-support-tests-0123456789"
SAM = "sam-support-key-for-support-tests-0123456789"
AUDREY = "audrey-auditor-key-for-support-tests-0123456789"
PASSWORD = "support-tests-password-731"
ORG = "org-support-a"
OTHER = "org-support-b"


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "support.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("PQC_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("PQC_ADMIN_EMAIL", "support-admin@example.test")
    monkeypatch.setenv("PQC_SUPPORT_SESSION_CACHE_SECONDS", "0")
    monkeypatch.setenv("PQC_PLATFORM_OPERATORS", json.dumps([
        {"name": "alice", "role": "owner", "key_sha256": _sha(ALICE)},
        {"name": "olga", "role": "operator", "key_sha256": _sha(OLGA)},
        {"name": "sam", "role": "support", "key_sha256": _sha(SAM)},
        {"name": "audrey", "role": "auditor", "key_sha256": _sha(AUDREY)},
    ]))
    monkeypatch.delenv("PQC_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_ISSUER_ENABLED": True,
        "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": SECRET,
        "AUTH_JWT_ISSUER": "pqc-scanner", "AUTH_JWT_AUDIENCE": "pqc-scanner",
        "AUTH_USER_ID_CLAIM": "sub", "AUTH_ROLE_CLAIM": "role", "AUTH_ORG_ID_CLAIM": "org_id",
        "_PLATFORM_ADMIN_KEY": LEGACY, "API_KEY": "", "PRODUCTION_ENVIRONMENT": False,
        "RATE_LIMIT_MAX_REQUESTS": 100000,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(auth_issuer, "_SECRET", SECRET)
    monkeypatch.setattr(auth_issuer, "_ISSUER", "pqc-scanner")
    monkeypatch.setattr(auth_issuer, "_AUDIENCE", "pqc-scanner")
    monkeypatch.setattr(auth_issuer, "_ENABLED", True)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    client = TestClient(app.app, client=("192.0.2.40", 40000))
    for org in (ORG, OTHER):
        res = client.post("/platform/customers", headers=key(ALICE),
                          json={"organization_id": org, "name": org.title(), "reason": "test setup"})
        assert res.status_code == 200, res.text
        support.set_support_access(org, True, "customer-test-admin")
    yield client, app
    client.close()


def key(value):
    return {"x-platform-key": value}


def bearer(token, org=None):
    headers = {"authorization": f"Bearer {token}"}
    if org:
        headers["x-org-id"] = org
    return headers


def start(client, operator=SAM, org=ORG, **body):
    payload = {"reason": "Customer ticket: dashboard shows no scans", "minutes": 30, **body}
    return client.post(f"/platform/customers/{org}/support-sessions", headers=key(operator), json=payload)


def code_of(res):
    url = res.json()["launch_url"]
    assert url.startswith("/ui/#support=")
    return url.split("=", 1)[1]


def open_session(client, **kwargs):
    res = start(client, **kwargs)
    assert res.status_code == 200, res.text
    ex = client.post("/auth/support-session/exchange", json={"code": code_of(res)})
    assert ex.status_code == 200, ex.text
    return res.json()["session"], ex.json()["access_token"]


def customer_admin_token(client, app, org=ORG, email="cust-admin@example.test"):
    with app._db() as conn:
        auth_issuer.create_user(conn, email, PASSWORD, "Customer Admin", "admin", org)
    res = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def tenant_audit(client, app, org, action):
    from db import list_audit_logs, reset_current_organization_id, set_current_organization_id

    token = set_current_organization_id(org)
    try:
        return list_audit_logs(limit=500, action=action)
    finally:
        reset_current_organization_id(token)


def admin_events(client, org, action):
    res = client.get(f"/platform/admin-events/search?organization_id={org}&action={action}&limit=100", headers=key(ALICE))
    assert res.status_code == 200, res.text
    return res.json()["items"]


# ── Creation: roles, validation, org state ───────────────────────────────────


@pytest.mark.parametrize("operator", [ALICE, OLGA, SAM])
def test_owner_operator_and_support_can_start_a_session(api, operator):
    client, _ = api
    res = start(client, operator=operator)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["session"]["status"] == "active" and body["session"]["organization_id"] == ORG
    assert body["launch_code_expires_in"] == 60
    assert "access_token" not in body and "token" not in json.dumps(body["session"])


def test_auditor_and_bad_credentials_cannot_start_a_session(api):
    client, _ = api
    assert start(client, operator=AUDREY).status_code == 403
    assert start(client, operator="not-a-key-" + "x" * 40).status_code in (401, 403)
    res = client.post(f"/platform/customers/{ORG}/support-sessions", json={"reason": "no credential at all", "minutes": 10})
    assert res.status_code in (401, 403)


@pytest.mark.parametrize("body", [
    {"reason": "too short", "minutes": 30},
    {"reason": "Long enough reason text", "minutes": 4},
    {"reason": "Long enough reason text", "minutes": 61},
    {"minutes": 30},
])
def test_reason_and_duration_are_validated(api, body):
    client, _ = api
    res = client.post(f"/platform/customers/{ORG}/support-sessions", headers=key(SAM), json=body)
    assert res.status_code == 422, res.text


def test_duration_defaults_to_thirty_minutes(api):
    client, _ = api
    res = client.post(f"/platform/customers/{ORG}/support-sessions", headers=key(SAM),
                      json={"reason": "Default duration check"})
    assert res.status_code == 200, res.text
    assert res.json()["session"]["minutes"] == 30


def test_unknown_org_is_404(api):
    client, _ = api
    assert start(client, org="org-does-not-exist").status_code == 404


def test_suspended_or_archived_org_refused_unless_owner(api):
    client, _ = api
    res = client.post(f"/platform/customers/{ORG}/suspend", headers=key(ALICE), json={"reason": "billing hold"})
    assert res.status_code == 200, res.text
    refused = start(client, operator=OLGA)
    assert refused.status_code == 403
    assert "suspended" in refused.json()["detail"] and "owner" in refused.json()["detail"]
    assert start(client, operator=ALICE).status_code == 200


# ── One-time launch code ─────────────────────────────────────────────────────


def test_launch_code_is_single_use(api):
    client, _ = api
    res = start(client)
    code = code_of(res)
    first = client.post("/auth/support-session/exchange", json={"code": code})
    assert first.status_code == 200, first.text
    again = client.post("/auth/support-session/exchange", json={"code": code})
    assert again.status_code == 409
    assert client.post("/auth/support-session/exchange", json={"code": "x" * 43}).status_code == 404


def test_launch_code_expires_after_sixty_seconds(api, monkeypatch):
    client, _ = api
    code = code_of(start(client))
    real_now = support._now
    monkeypatch.setattr(support, "_now", lambda: real_now() + support.timedelta(seconds=61))
    res = client.post("/auth/support-session/exchange", json={"code": code})
    assert res.status_code == 410
    assert "expired" in res.json()["detail"]


def test_only_a_hash_of_the_code_is_stored(api):
    client, _ = api
    code = code_of(start(client))
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        stored = [r[0] for r in conn.execute("SELECT code_hash FROM platform_support_codes").fetchall()]
    assert code not in stored and support._hash_code(code) in stored


# ── Token claims ─────────────────────────────────────────────────────────────


def test_token_claims_are_distinct_and_bounded_by_the_session(api):
    client, _ = api
    session, token = open_session(client, minutes=15)
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], audience="pqc-scanner", issuer="pqc-scanner")
    assert claims["typ"] == "support_view"
    assert claims["sid"] == session["id"]
    assert claims["role"] == "viewer"
    assert claims["org_id"] == ORG
    assert claims["act"]["operator"] == "sam"
    assert claims["sub"] == f"support:{session['id']}"
    expires = support._parse(session["expires_at"])
    assert claims["exp"] == int(expires.timestamp())
    assert claims["exp"] - claims["iat"] <= 15 * 60 + 2


# ── Enforcement ──────────────────────────────────────────────────────────────


def test_reads_are_allowed_and_banner_endpoint_works(api):
    client, _ = api
    session, token = open_session(client)
    assert client.get("/assets", headers=bearer(token)).status_code == 200
    assert client.get("/v1/assets", headers=bearer(token)).status_code == 200
    ctx = client.get("/auth/context", headers=bearer(token, ORG))
    assert ctx.status_code == 200 and ctx.json()["organization_id"] == ORG and ctx.json()["actor_role"] == "viewer"
    cur = client.get("/support-session/current", headers=bearer(token))
    assert cur.status_code == 200, cur.text
    assert cur.json()["session"]["operator"] == "sam" and cur.json()["session"]["read_only"] is True


@pytest.mark.parametrize("method,path", [
    ("POST", "/scan"), ("POST", "/assets/import"), ("PUT", "/org/support-access"), ("DELETE", "/assets/example.com:443"),
    ("PATCH", "/assets"), ("POST", "/feedback"), ("PUT", "/sla/config"),
])
def test_writes_are_refused(api, method, path):
    client, _ = api
    _, token = open_session(client)
    res = client.request(method, path, headers=bearer(token), json={"allowed": False})
    assert res.status_code == 403, res.text
    assert "read-only" in res.json()["detail"]


@pytest.mark.parametrize("path", [
    "/vault/credentials", "/vault/credentials/1/reveal", "/auth/users", "/auth/me", "/integrations/settings",
    "/integrations/slack/settings", "/integrations/webhooks", "/webhooks", "/notifications/config",
    "/audit/logs/export.csv", "/organizations/org-support-a/export", "/scans/x/export.csv", "/scans/x/cbom.json",
    "/cbom", "/cbom.csv", "/compliance/export.csv", "/readiness/e2e/export", "/blast-radius/export",
    "/evidence/repos/acme/app", "/cbom/webhook/setup", "/organizations", "/badge/token", "/trust-passport",
    "/platform/customers", "/platform/whoami", "/v1/platform/customers", "/admin/orgs", "/admin/audit-log",
    "/something/not-on-the-allow-list",
])
def test_deny_list_and_unlisted_routes_are_refused(api, path):
    client, _ = api
    _, token = open_session(client)
    res = client.get(path, headers=bearer(token))
    assert res.status_code == 403, f"{path}: {res.status_code} {res.text}"


def test_support_token_cannot_call_platform_even_with_a_platform_key(api):
    client, _ = api
    _, token = open_session(client)
    headers = {**bearer(token), **key(ALICE)}
    assert client.get("/platform/customers", headers=headers).status_code == 403
    assert client.post(f"/platform/customers/{ORG}/support-sessions", headers=headers,
                       json={"reason": "escalation attempt here", "minutes": 60}).status_code == 403
    assert client.get("/admin/orgs", headers=headers).status_code == 403


def test_allow_list_never_overlaps_the_deny_list():
    for template in support.ALLOWED_GET_ROUTES:
        assert not support.denied_reason(template), template


def test_other_org_is_refused(api):
    client, _ = api
    _, token = open_session(client)
    assert client.get("/assets", headers=bearer(token, OTHER)).status_code == 403
    assert client.get(f"/org/{OTHER}/metrics", headers=bearer(token)).status_code == 403
    assert client.get(f"/remediation-feed?organization_id={OTHER}", headers=bearer(token)).status_code == 403
    assert client.get("/assets", headers=bearer(token, ORG)).status_code == 200


def test_revocation_is_enforced(api):
    client, _ = api
    session, token = open_session(client)
    assert client.get("/assets", headers=bearer(token)).status_code == 200
    res = client.post(f"/platform/support-sessions/{session['id']}/revoke", headers=key(OLGA), json={"reason": "done here"})
    assert res.status_code == 200 and res.json()["session"]["status"] == "revoked"
    after = client.get("/assets", headers=bearer(token))
    assert after.status_code == 401 and "revoked" in after.json()["detail"]


def test_revocation_takes_effect_within_the_cache_window(api, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_SUPPORT_SESSION_CACHE_SECONDS", "30")
    assert support._cache_seconds() == 5.0  # capped
    session, token = open_session(client)
    assert client.get("/assets", headers=bearer(token)).status_code == 200
    support.revoke_session(session["id"], revoked_by="test", reason="revoked by test")
    assert client.get("/assets", headers=bearer(token)).status_code == 401  # same replica: immediate


def test_expiry_is_enforced_and_recorded(api, monkeypatch):
    client, app = api
    session, token = open_session(client, minutes=5)
    real_now = support._now
    monkeypatch.setattr(support, "_now", lambda: real_now() + support.timedelta(minutes=6))
    res = client.get("/assets", headers=bearer(token))
    assert res.status_code == 401 and "ended" in res.json()["detail"]
    assert tenant_audit(client, app, ORG, "support_session.expired")
    assert admin_events(client, ORG, "support_session.expired")


def test_expired_jwt_is_rejected(api):
    client, _ = api
    session, _ = open_session(client)
    now = int(time.time())
    stale = jwt.encode({"typ": "support_view", "sid": session["id"], "sub": "support:x", "role": "viewer", "org_id": ORG,
                        "iss": "pqc-scanner", "aud": "pqc-scanner", "iat": now - 4000, "exp": now - 10}, SECRET, algorithm="HS256")
    assert client.get("/assets", headers=bearer(stale)).status_code == 401


def test_forged_or_tampered_tokens_are_rejected(api):
    client, _ = api
    session, token = open_session(client)
    forged = jwt.encode({"typ": "support_view", "sid": session["id"], "sub": "x", "role": "admin", "org_id": ORG,
                         "iss": "pqc-scanner", "aud": "pqc-scanner", "exp": int(time.time()) + 600}, "wrong-key", algorithm="HS256")
    assert client.get("/assets", headers=bearer(forged)).status_code == 401
    other_org = jwt.encode({"typ": "support_view", "sid": session["id"], "sub": "x", "role": "viewer", "org_id": OTHER,
                            "iss": "pqc-scanner", "aud": "pqc-scanner", "exp": int(time.time()) + 600}, SECRET, algorithm="HS256")
    assert client.get("/assets", headers=bearer(other_org)).status_code == 401


def test_session_can_end_itself_and_nothing_else(api):
    client, _ = api
    session, token = open_session(client)
    res = client.post("/support-session/end", headers=bearer(token))
    assert res.status_code == 200, res.text
    assert res.json()["session"]["status"] == "revoked"
    assert client.get("/support-session/current", headers=bearer(token)).status_code == 401


def test_every_support_request_is_journaled(api):
    client, _ = api
    session, token = open_session(client)
    client.get("/assets", headers=bearer(token))
    client.post("/scan", headers=bearer(token), json={})
    detail = client.get(f"/platform/support-sessions/{session['id']}", headers=key(AUDREY))
    assert detail.status_code == 200, detail.text
    requests = detail.json()["requests"]
    assert {(r["method"], r["path"], r["status_code"]) for r in requests} >= {("GET", "/assets", 200), ("POST", "/scan", 403)}
    assert all(r["session_id"] == session["id"] for r in requests)
    assert detail.json()["session"]["request_count"] >= 2


# ── Audit trail in both logs ─────────────────────────────────────────────────


def test_start_exchange_and_revoke_are_in_both_logs(api):
    client, app = api
    session, token = open_session(client)
    client.post(f"/platform/support-sessions/{session['id']}/revoke", headers=key(SAM), json={"reason": "finished"})
    for event in ("started", "exchanged", "revoked"):
        tenant = tenant_audit(client, app, ORG, f"support_session.{event}")
        assert any(r["resource_id"] == session["id"] for r in tenant), event
        platform = admin_events(client, ORG, f"support_session.{event}")
        assert platform, event
    started = tenant_audit(client, app, ORG, "support_session.started")[0]
    assert "dashboard shows no scans" in started["reason"]
    # The customer sees it through their own console, as one line per session.
    admin_token = customer_admin_token(client, app)
    history = client.get("/org/support-access/history", headers=bearer(admin_token))
    assert history.status_code == 200, history.text
    item = next(i for i in history.json()["items"] if i["id"] == session["id"])
    assert item["operator"] == "sam" and item["status"] == "revoked" and item["duration_seconds"] is not None
    # Requests made with the session appear in the tenant audit log under the session actor.
    client.get("/assets", headers=bearer(token))  # rejected now; earlier reads were recorded
    other = tenant_audit(client, app, OTHER, "support_session.started")
    assert not other


def test_list_filters(api):
    client, _ = api
    session, _ = open_session(client)
    start(client, org=OTHER)
    client.post(f"/platform/support-sessions/{session['id']}/revoke", headers=key(SAM), json={"reason": "finished"})
    everything = client.get("/platform/support-sessions", headers=key(AUDREY)).json()["items"]
    assert len(everything) == 2
    active = client.get("/platform/support-sessions?active=true", headers=key(AUDREY)).json()["items"]
    assert [s["organization_id"] for s in active] == [OTHER]
    mine = client.get(f"/platform/support-sessions?organization_id={ORG}&active=false", headers=key(AUDREY)).json()["items"]
    assert [s["id"] for s in mine] == [session["id"]]


# ── Customer opt-out and break-glass ─────────────────────────────────────────


def test_customer_opt_out_blocks_creation_and_owner_break_glass_is_high_severity(api):
    client, app = api
    session, token = open_session(client)
    admin_token = customer_admin_token(client, app)
    assert client.get("/org/support-access", headers=bearer(admin_token)).json()["allowed"] is True
    off = client.put("/org/support-access", headers=bearer(admin_token), json={"allowed": False, "reason": "policy"})
    assert off.status_code == 200 and off.json()["allowed"] is False
    # Turning access off ends the session in progress.
    assert client.get("/assets", headers=bearer(token)).status_code == 401

    refused = start(client, operator=OLGA)
    assert refused.status_code == 403 and refused.json()["detail"] == "customer has disabled support access"
    assert start(client, operator=OLGA, break_glass=True).status_code == 403
    assert start(client, operator=ALICE).status_code == 403  # owner without the explicit flag

    glass = start(client, operator=ALICE, break_glass=True, reason="Sev-1 outage, customer on bridge call")
    assert glass.status_code == 403
    assert "customer consent" in glass.json()["detail"]


def test_only_customer_admins_change_the_setting(api):
    client, app = api
    with app._db() as conn:
        auth_issuer.create_user(conn, "viewer@example.test", PASSWORD, "Viewer", "viewer", ORG)
    viewer = client.post("/auth/login", json={"email": "viewer@example.test", "password": PASSWORD}).json()["access_token"]
    assert client.put("/org/support-access", headers=bearer(viewer), json={"allowed": False}).status_code == 403
    _, token = open_session(client)
    assert client.put("/org/support-access", headers=bearer(token), json={"allowed": True}).status_code == 403


# ── Normal customer tokens are unaffected ────────────────────────────────────


def test_normal_customer_token_is_unaffected(api):
    client, app = api
    open_session(client)
    admin_token = customer_admin_token(client, app)
    assert client.get("/assets", headers=bearer(admin_token)).status_code == 200
    assert client.get("/auth/users", headers=bearer(admin_token)).status_code == 200
    res = client.put("/org/support-access", headers=bearer(admin_token), json={"allowed": True})
    assert res.status_code == 200
    assert "x-support-session" not in res.headers
    assert client.get("/support-session/current", headers=bearer(admin_token)).status_code == 404


def test_enforcement_also_applies_in_header_auth_mode(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app, "AUTH_MODE", "headers")
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)
    _, token = open_session(client)
    spoof = {**bearer(token), "x-user-role": "admin", "x-user-id": "someone"}
    assert client.get("/assets", headers=spoof).status_code == 200
    assert client.post("/scan", headers=spoof, json={}).status_code == 403
    assert client.get("/vault/credentials", headers=spoof).status_code == 403
    ctx = client.get("/auth/context", headers=spoof).json()
    assert ctx["actor_role"] == "viewer" and ctx["actor_id"].startswith("support:")


def test_notifications_list_active_support_sessions(api):
    client, _ = api
    session, _ = open_session(client)
    res = client.get("/platform/notifications", headers=key(AUDREY))
    assert res.status_code == 200, res.text
    items = [i for i in res.json().get("items", []) if i.get("kind") == "support_session"]
    assert any(session["id"] in i["id"] for i in items)


# ── Customer-visible page history ────────────────────────────────────────────


def test_customer_history_lists_every_page_viewed_and_is_org_scoped(api):
    client, app = api
    session, token = open_session(client)
    other_session, other_token = open_session(client, org=OTHER)
    assert client.get("/assets", headers=bearer(token)).status_code == 200
    client.get("/fix-next", headers=bearer(token))
    client.post("/scan", headers=bearer(token), json={})  # refused, still journaled and listed
    client.get("/assets", headers=bearer(other_token))
    client.post(f"/platform/support-sessions/{session['id']}/revoke", headers=key(SAM), json={"reason": "finished"})

    admin_token = customer_admin_token(client, app)
    items = client.get("/org/support-access/history", headers=bearer(admin_token)).json()["items"]
    item = next(i for i in items if i["id"] == session["id"])
    paths = [r["path"] for r in item["requests"]]
    assert {"/assets", "/fix-next", "/scan"} <= set(paths)
    assert item["requests_total"] == len(item["requests"]) and item["requests_truncated"] is False
    assert all(set(r) == {"path", "at"} for r in item["requests"]), "paths and times only"
    assert other_session["id"] not in {i["id"] for i in items}, "another organization's session is not listed"
    journal = {r["path"] for r in client.get(f"/platform/support-sessions/{session['id']}", headers=key(AUDREY)).json()["requests"]}
    assert set(paths) == journal, "the customer sees the same pages as the vendor journal"

    other_admin = customer_admin_token(client, app, org=OTHER, email="other-admin@example.test")
    other_items = client.get("/org/support-access/history", headers=bearer(other_admin)).json()["items"]
    assert session["id"] not in {i["id"] for i in other_items}
    mine = next(i for i in other_items if i["id"] == other_session["id"])
    assert {r["path"] for r in mine["requests"]} == {"/assets"}

    # The service never returns another organization's rows, even when handed that session's id.
    from services import support_sessions as svc

    leaked = svc.customer_request_history(OTHER, [session["id"]])
    assert leaked[session["id"]] == {"requests": [], "total": 0}


def test_support_end_screen_states_what_the_customer_can_see():
    import pathlib

    html = (pathlib.Path(__file__).resolve().parent / "static" / "index.html").read_text(encoding="utf-8")
    assert "recorded in the customer's audit log" not in html
    assert "can see the full list, with times, under Administration › Support access" in html
    assert "Pages viewed" in html and "x.requests_total" in html
