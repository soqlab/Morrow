"""Executable record of the September 2026 adversarial security review (docs/SECURITY_REVIEW_2026-09.md).

Every test here asserts the behaviour the platform SHOULD have. They were written as
xfail(strict=True) reproductions of live defects; the marker comes off in the same change that
fixes the finding, so a regression is an ordinary failure from then on.

The findings, in the order they appear below:

  1 (critical) /admin/orgs/{org_id}/* is role-checked but not tenant-checked          -- FIXED
  2 (critical) /v1/v1/... defeats the API-key route denylist                          -- FIXED
  3 (high)     raw invitation tokens are returned and stored in the admin audit log   -- FIXED
  5 (high)     /digest/config is on the support-view allow-list and returns Slack/PagerDuty
               credentials                                                            -- FIXED
  6 (medium)   the same secrets are readable by a customer "viewer"                   -- FIXED
  7 (medium)   an operator SSO session never opens the RLS platform scope             -- FIXED

Also covered here, from the staging dry-run (docs/STAGING_DRY_RUN.md):

  F2 (high)    accepting an invitation does not move the built-in issuer's tokens to the
               accepted tenant, so the invitee keeps operating in their old organization

Findings 4 and 10-16 are covered elsewhere: 4 in test_postgres_rls*.py (it needs a live Postgres),
10/11 in test_billing.py, and the rest are small code changes proved by their own suites.
"""

import re
import socket
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from services import auth_issuer

SECRET = "security-review-2026-09-jwt-signing-key-not-for-deployment"
LEGACY = "security-review-2026-09-platform-key-0123456789abcdef"
ORG_A = "org-review-a"
ORG_B = "org-review-b"


@pytest.fixture
def api(tmp_path, monkeypatch):
    """The real ASGI stack in production-like mode: JWT required, header identity off."""
    import app

    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "secreview.db"))
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", SECRET)
    monkeypatch.delenv("MORROW_PLATFORM_OPERATORS", raising=False)
    monkeypatch.delenv("MORROW_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    monkeypatch.delenv("MORROW_PUBLIC_BASE_URL", raising=False)
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

    def no_network(*args, **kwargs):
        raise AssertionError("a test tried to open a real network connection")
    monkeypatch.setattr(socket, "create_connection", no_network)

    app.init_db()
    client = TestClient(app.app, client=("192.0.2.41", 41000))
    for org, name in ((ORG_A, "Review A"), (ORG_B, "Review B")):
        res = client.post("/platform/customers", headers=operator("owner"),
                          json={"organization_id": org, "name": name, "reason": "security review fixture"})
        assert res.status_code == 200, res.text
    yield client, app
    client.close()


def operator(role: str = "operator") -> Dict[str, str]:
    return {"x-platform-key": LEGACY, "x-platform-admin-role": role}


def customer(org: str = ORG_A, role: str = "admin", email: str = "attacker@review.test") -> Dict[str, str]:
    """A legitimately signed customer token: exactly what a real IdP would hand a tenant admin."""
    import time
    import uuid

    import jwt
    now = int(time.time())
    token = jwt.encode(
        {"sub": email, "email": email, "role": role, "org_id": org, "iss": "morrow",
         "aud": "morrow", "iat": now, "nbf": now, "exp": now + 3600, "jti": uuid.uuid4().hex},
        SECRET, algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def org_api_key(client: TestClient, org: str = ORG_A, scopes=("admin",)) -> str:
    res = client.post(f"/platform/customers/{org}/api-keys", headers=operator("owner"),
                      json={"name": "security-review", "scopes": list(scopes), "reason": "security review"})
    assert res.status_code == 200, res.text
    return res.json()["secret"]


def _token_from_link(body: Dict[str, Any]) -> str:
    """The invitation token, read out of the one-time link.

    The bare token is deliberately no longer a field of its own in any response (finding 3): the
    server builds the link, the link carries the token in a URL fragment, and that is the only
    place it appears. Tests that need the token take it from there, exactly as the invitee's
    browser does.
    """
    match = re.search(r"#token=([A-Za-z0-9_\-]+)", str(body.get("invite_link") or ""))
    assert match, f"no invite link to read a token from: {body}"
    return match.group(1)


# --------------------------------------------------------------------------- #
# Finding 1 (critical): /admin/orgs/{org_id}/* is role-checked, not tenant-checked
# app.py:17377 (invite), :17390 (invitations), :17369 (users), :17437 (users/role),
# :17446 (users delete). The guard, _require_role at app.py:10164, compares only the role;
# the org_id from the path or body is never compared with the caller's own tenant.
# --------------------------------------------------------------------------- #

def test_admin_invite_is_refused_for_another_tenant(api):
    client, _ = api
    res = client.post(f"/admin/orgs/{ORG_B}/invite", headers=customer(org=ORG_A, role="admin"),
                      json={"org_id": ORG_B, "email": "attacker@review.test",
                            "role": "org_admin", "invited_by": "attacker@review.test"})
    assert res.status_code == 403, f"an admin of {ORG_A} created an invitation in {ORG_B}: {res.text}"


def test_cross_tenant_invite_cannot_be_accepted_into_the_victim_org(api):
    """The full chain from the review: invite into a foreign tenant, accept, become its admin.

    Step one is now refused, so there is no token to accept. The chain is re-run anyway with an
    invitation that ORG_B's own admin creates, to prove that the part which *is* still reachable --
    acceptance -- binds to the invited email and not to whoever presents the token.
    """
    client, _ = api
    invited = client.post(f"/admin/orgs/{ORG_B}/invite", headers=customer(org=ORG_A, role="admin"),
                          json={"org_id": ORG_B, "email": "attacker@review.test",
                                "role": "org_admin", "invited_by": "x"})
    assert invited.status_code == 403, f"an admin of {ORG_A} created an invitation in {ORG_B}: {invited.text}"
    assert "token" not in invited.text

    # ORG_B's own admin invites somebody else; the ORG_A identity must not be able to redeem it.
    legitimate = client.post(f"/admin/orgs/{ORG_B}/invite", headers=customer(org=ORG_B, role="admin",
                                                                             email="boss@review.test"),
                             json={"org_id": ORG_B, "email": "invitee@review.test",
                                   "role": "org_admin", "invited_by": "boss@review.test"})
    assert legitimate.status_code == 200, legitimate.text
    token = _token_from_link(legitimate.json())
    stolen = client.post("/admin/accept-invite", json={"token": token}, headers=customer(org=ORG_A, role="admin"))
    assert stolen.status_code == 403, (
        f"an admin of {ORG_A} gained membership_role="
        f"{stolen.json().get('membership_role')!r} in {ORG_B}"
    )


def test_admin_org_user_routes_are_refused_for_another_tenant(api):
    client, _ = api
    headers = customer(org=ORG_A, role="admin")
    refused = {
        "GET users": client.get(f"/admin/orgs/{ORG_B}/users", headers=headers).status_code,
        "GET rate-limits": client.get(f"/admin/orgs/{ORG_B}/rate-limits", headers=headers).status_code,
        "PUT users/role": client.put("/admin/users/role", headers=headers,
                                     json={"org_id": ORG_B, "email": "victim@b.test",
                                           "new_role": "org_admin", "actor": "x"}).status_code,
        "DELETE users": client.request("DELETE", "/admin/users", headers=headers,
                                       json={"org_id": ORG_B, "email": "victim@b.test",
                                             "actor": "x"}).status_code,
    }
    assert all(code == 403 for code in refused.values()), refused


def test_admin_audit_log_is_scoped_to_the_callers_tenant(api):
    client, _ = api
    client.post(f"/admin/orgs/{ORG_B}/invite", headers=customer(org=ORG_B, role="admin"),
                json={"org_id": ORG_B, "email": "someone@b.test", "role": "org_admin", "invited_by": "x"})
    res = client.get("/admin/audit-log?limit=50", headers=customer(org=ORG_A, role="admin"))
    assert res.status_code == 200, res.text
    foreign = [row for row in res.json()["log"] if str(row.get("org_id") or "") not in ("", ORG_A)]
    assert not foreign, f"an admin of {ORG_A} read audit rows for other tenants: {foreign[:3]}"


# --------------------------------------------------------------------------- #
# Finding 2 (critical): /v1/v1/... defeats the API-key route denylist
# services/api_keys.py:399-401 strips one /v1 before checking BLOCKED_PREFIXES (:41, :402);
# app.py:2591-2611 also strips one, and /v1/admin/... aliases exist, so the doubled prefix
# passes the guard and still routes.
# --------------------------------------------------------------------------- #

def test_api_key_cannot_reach_admin_routes_through_a_doubled_v1_prefix(api):
    client, _ = api
    key = org_api_key(client)
    auth = {"Authorization": f"Bearer {key}"}
    assert client.get("/admin/audit-log", headers=auth).status_code == 403
    assert client.get("/v1/admin/audit-log", headers=auth).status_code == 403
    doubled = client.get("/v1/v1/admin/audit-log", headers=auth)
    assert doubled.status_code == 403, (
        f"an organization API key reached /v1/v1/admin/audit-log: {doubled.status_code} {doubled.text[:200]}"
    )


def test_api_key_cannot_invite_into_another_tenant_via_doubled_prefix(api):
    client, _ = api
    key = org_api_key(client)
    res = client.post(f"/v1/v1/admin/orgs/{ORG_B}/invite", headers={"Authorization": f"Bearer {key}"},
                      json={"org_id": ORG_B, "email": "keyholder@review.test",
                            "role": "org_admin", "invited_by": "x"})
    assert res.status_code == 403, f"API key created an invitation in {ORG_B}: {res.text[:200]}"


def test_api_key_guard_normalises_repeated_v1_prefixes():
    from services import api_keys

    for path in ("/admin/x", "/v1/admin/x", "/v1/v1/admin/x", "/v1/v1/v1/admin/x",
                 "/platform/x", "/v1/v1/platform/x"):
        claims, error, status = api_keys.claims_for_request("pq_not_a_real_token", "GET", path)
        assert status == 403 and "cannot call platform" in (error or ""), (
            f"{path} was not recognised as a blocked route (status={status}, error={error!r})"
        )


# --------------------------------------------------------------------------- #
# Finding 3 (high): raw invitation tokens are returned and durably stored
# services/admin_console.py:306 selects `token`; :215 writes the raw token as the audit target_id.
# services/platform_access.py:65-87 shows the correct shape (an invite_id, never the token).
# --------------------------------------------------------------------------- #

def test_pending_invitations_do_not_expose_the_raw_token(api):
    client, _ = api
    created = client.post(f"/admin/orgs/{ORG_A}/invite", headers=customer(org=ORG_A, role="admin"),
                          json={"org_id": ORG_A, "email": "invitee@review.test",
                                "role": "org_admin", "invited_by": "x"})
    assert created.status_code == 200, created.text
    assert "token" not in created.json(), "the creation response still carries a bare token field"
    token = _token_from_link(created.json())
    listed = client.get(f"/admin/orgs/{ORG_A}/invitations", headers=customer(org=ORG_A, role="admin"))
    assert token not in listed.text, "the invitations endpoint handed back a live invitation token"
    assert listed.json()["invitations"][0]["invite_id"], "an invitation needs a non-secret id to act on"


def test_admin_audit_log_does_not_store_the_raw_invitation_token(api):
    client, _ = api
    created = client.post(f"/admin/orgs/{ORG_A}/invite", headers=customer(org=ORG_A, role="admin"),
                          json={"org_id": ORG_A, "email": "invitee@review.test",
                                "role": "org_admin", "invited_by": "x"})
    token = _token_from_link(created.json())
    log = client.get("/admin/audit-log?action=invite_user&limit=50",
                     headers=customer(org=ORG_A, role="admin"))
    assert token not in log.text, "the admin audit log is a cleartext store of live invitation tokens"

    # ... and the row is still useful: it names the invitation by its non-secret id.
    from services import platform_access

    rows = [r for r in log.json()["log"] if r.get("action") == "invite_user"]
    assert any(r.get("target_id") == platform_access.invite_id(token) for r in rows), rows[:3]


# --------------------------------------------------------------------------- #
# Findings 5 and 6: /digest/config returns customer credentials
# It is on ALLOWED_GET_ROUTES (services/support_sessions.py:179) and is readable by "viewer"
# (app.py:17035). The handler returns slack_webhook / teams_webhook / pd_routing_key verbatim.
# --------------------------------------------------------------------------- #

SLACK = "https://hooks.slack.com/services/T000/B000/REVIEWSECRETTOKEN"
PAGERDUTY = "PD-ROUTING-KEY-REVIEW-SECRET"


def _set_digest_secrets(client: TestClient) -> None:
    res = client.post("/digest/config", headers=customer(org=ORG_A, role="admin"),
                      json={"frequency": "weekly", "slack_webhook": SLACK, "teams_webhook": "",
                            "pd_routing_key": PAGERDUTY, "enabled": True})
    assert res.status_code == 200, res.text


def _support_token(client: TestClient, org: str = ORG_A) -> str:
    approved = client.put("/org/support-access", headers=customer(org=org, role="admin"),
                          json={"allowed": True, "reason": "Approve read-only security review session"})
    assert approved.status_code == 200, approved.text
    created = client.post(f"/platform/customers/{org}/support-sessions", headers=operator("owner"),
                          json={"reason": "security review verification", "minutes": 30})
    assert created.status_code == 200, created.text
    code = created.json()["launch_url"].split("=", 1)[1]
    exchanged = client.post("/auth/support-session/exchange", json={"code": code})
    assert exchanged.status_code == 200, exchanged.text
    return exchanged.json()["access_token"]


def test_support_view_cannot_read_the_customers_webhook_credentials(api):
    client, _ = api
    _set_digest_secrets(client)
    token = _support_token(client)
    res = client.get("/digest/config", headers={"Authorization": f"Bearer {token}"})
    leaked = [name for name, value in (("slack_webhook", SLACK), ("pd_routing_key", PAGERDUTY))
              if value in res.text]
    assert not leaked, (
        f"a read-only vendor support session read {leaked} in cleartext "
        f"(status {res.status_code}); the module promises no credentials in a support view"
    )


def test_customer_viewer_cannot_read_the_webhook_credentials(api):
    client, _ = api
    _set_digest_secrets(client)
    res = client.get("/digest/config", headers=customer(org=ORG_A, role="viewer"))
    assert SLACK not in res.text and PAGERDUTY not in res.text, (
        "a read-only customer seat read the organization's outbound webhook credentials"
    )


# --------------------------------------------------------------------------- #
# Finding 7 (medium): an operator SSO session never opens the RLS platform scope
# app.py:3314-3317 returns before the enter_platform_scope call at app.py:3372, and that call
# site is the only one in the application. On Postgres this makes the operator console read
# nothing; it also means the console is never exercised against live RLS.
# --------------------------------------------------------------------------- #

def test_operator_session_opens_the_platform_scope(api, monkeypatch):
    client, app_module = api
    from services import operator_auth, tenant_scope

    # The roster is what makes an SSO session stay valid: require_session_actor re-reads it on
    # every request so a removal takes effect immediately.
    monkeypatch.setenv("MORROW_ADMIN_OPERATOR_ROLES", "alice@corp.example=owner")
    raw, _row = operator_auth.create_session(
        "alice@corp.example", "owner", "sso", email="alice@corp.example", mfa_verified=True,
    )
    monkeypatch.setenv("MORROW_ADMIN_REQUIRE_MFA", "0")
    client.cookies.set(operator_auth.SESSION_COOKIE, raw, path="/")
    tenant_scope.reset_audit_log()
    res = client.get("/platform/customers")
    client.cookies.clear()
    assert res.status_code == 200, res.text
    reasons = [event["reason"] for event in tenant_scope.escape_events(20)]
    assert any(reason.startswith("platform-admin ") for reason in reasons), (
        "a cookie-authenticated operator request never opened the audited cross-tenant scope; "
        f"the ledger recorded {reasons!r}. On Postgres the operator console would read nothing, "
        "and postgres_rls.operator_access_rule claims this path opens the scope."
    )


# =========================================================================== #
# Regression cover added with the fixes: the allow/deny matrix for every route
# that changed, the path spellings the guards must collapse, the rest of the
# support allow-list, and the tenant binding an acceptance has to perform.
# =========================================================================== #

#: Every /admin/* route that names an organization, with the method and a body where one is needed.
#: A new entry here is a new route that must be tenant-checked.
ADMIN_ORG_ROUTES = (
    ("GET",    "/admin/orgs/{org}",                None),
    ("GET",    "/admin/orgs/{org}/usage",          None),
    ("GET",    "/admin/orgs/{org}/users",          None),
    ("GET",    "/admin/orgs/{org}/invitations",    None),
    ("GET",    "/admin/orgs/{org}/rate-limits",    None),
    ("POST",   "/admin/orgs/{org}/invite",         {"email": "newbie@review.test", "role": "viewer", "invited_by": "x"}),
    ("POST",   "/admin/orgs/{org}/rate-limits",    {"scans_per_hour": 10, "api_calls_per_min": 10, "actor": "x"}),
    ("PUT",    "/admin/orgs/{org}",                {"name": "renamed", "actor": "x"}),
    ("DELETE", "/admin/orgs/{org}",                None),
    ("PUT",    "/admin/users/role",                {"email": "victim@review.test", "new_role": "viewer", "actor": "x"}),
    ("DELETE", "/admin/users",                     {"email": "victim@review.test", "actor": "x"}),
)


def _call(client: TestClient, method: str, template: str, org: str, body, headers):
    path = template.format(org=org)
    payload = None if body is None else {**body, "org_id": org}
    return client.request(method, path, headers=headers, json=payload)


def test_every_admin_org_route_refuses_another_tenant_for_a_customer_admin(api):
    """The deny half of the matrix: an administrator of ORG_A, against ORG_B, on every route."""
    client, _ = api
    headers = customer(org=ORG_A, role="admin")
    leaked = {}
    for method, template, body in ADMIN_ORG_ROUTES:
        res = _call(client, method, template, ORG_B, body, headers)
        if res.status_code != 403:
            leaked[f"{method} {template}"] = (res.status_code, res.text[:120])
    assert not leaked, f"routes reachable across tenants by a customer admin: {leaked}"


def test_every_admin_org_route_allows_a_customer_admin_in_their_own_tenant(api):
    """The allow half: the same calls, aimed at the caller's own organization, must work.

    A tenant check that also broke the legitimate path would be a worse bug than the one it fixes,
    so this runs the whole list. The DELETE is left out because it suspends the organization and
    every later request in the fixture would then answer 403 for an unrelated reason.
    """
    client, _ = api
    headers = customer(org=ORG_A, role="admin")
    broken = {}
    for method, template, body in ADMIN_ORG_ROUTES:
        if method == "DELETE":
            continue
        res = _call(client, method, template, ORG_A, body, headers)
        # 404 is an authorized answer: admin_orgs is a registry the operator populates, and the
        # fixture's tenants were created through /platform/customers. 403 is the failure to catch.
        if res.status_code not in (200, 404):
            broken[f"{method} {template}"] = (res.status_code, res.text[:160])
    assert not broken, f"a customer admin cannot administer their own organization: {broken}"


def test_admin_org_routes_refuse_a_customer_viewer_in_their_own_tenant(api):
    """Role is still checked: tenancy is an extra gate, not a replacement for one."""
    client, _ = api
    headers = customer(org=ORG_A, role="viewer", email="viewer@review.test")
    allowed = {}
    for method, template, body in ADMIN_ORG_ROUTES:
        res = _call(client, method, template, ORG_A, body, headers)
        if res.status_code != 403:
            allowed[f"{method} {template}"] = res.status_code
    assert not allowed, f"a read-only seat reached admin routes: {allowed}"


def test_admin_org_routes_refuse_an_organization_api_key(api):
    """An API key never reaches /admin/*, in its own tenant or any other."""
    client, _ = api
    auth = {"Authorization": f"Bearer {org_api_key(client)}"}
    reached = {}
    for method, template, body in ADMIN_ORG_ROUTES:
        for org in (ORG_A, ORG_B):
            res = _call(client, method, template, org, body, auth)
            if res.status_code != 403:
                reached[f"{method} {template} -> {org}"] = (res.status_code, res.text[:120])
    assert not reached, f"an organization API key reached admin routes: {reached}"


def test_platform_operator_crosses_tenants_only_through_the_platform_routes(api):
    """Where cross-tenant administration lives now.

    /admin/* is a customer surface: it is scoped to the caller's own tenant, and a platform key is
    not a customer credential, so an operator is refused there. The operator's cross-tenant surface
    is /platform/customers/..., which is credential-guarded, role-ceilinged, reason-logged and
    opens the audited RLS scope.
    """
    client, _ = api
    refused = client.get(f"/admin/orgs/{ORG_B}/users", headers=operator("owner"))
    assert refused.status_code in (401, 403), refused.text

    allowed = client.get(f"/platform/customers/{ORG_B}/users", headers=operator("owner"))
    assert allowed.status_code == 200, allowed.text
    created = client.post(f"/platform/customers/{ORG_B}/invitations", headers=operator("owner"),
                          json={"email": "invitee@review.test", "role": "viewer",
                                "reason": "security review verification"})
    assert created.status_code == 200, created.text
    invitation = created.json()["invitation"]
    assert "token" not in invitation and invitation["invite_id"], invitation
    assert invitation["invite_link"].startswith("http")


def test_admin_audit_log_query_parameter_cannot_name_another_tenant(api):
    client, _ = api
    res = client.get(f"/admin/audit-log?org_id={ORG_B}", headers=customer(org=ORG_A, role="admin"))
    assert res.status_code == 403, res.text


def test_admin_org_registry_listing_is_scoped_to_the_caller(api):
    """GET /admin/orgs used to return every customer on the platform to any admin."""
    client, _ = api
    for org in (ORG_A, ORG_B):
        res = client.post(f"/admin/orgs/{org}/rate-limits", headers=customer(org=org, role="admin"),
                          json={"org_id": org, "scans_per_hour": 5, "api_calls_per_min": 5, "actor": "x"})
        assert res.status_code == 200, res.text
    listed = client.get("/admin/orgs", headers=customer(org=ORG_A, role="admin"))
    assert listed.status_code == 200, listed.text
    assert all(str(row.get("id")) == ORG_A for row in listed.json()["orgs"]), listed.json()["orgs"]
    overview = client.get("/admin/platform", headers=customer(org=ORG_A, role="admin"))
    assert overview.status_code == 200 and overview.json()["scope"] == ORG_A
    assert ORG_B not in overview.text


# --------------------------------------------------------------------------- #
# Finding 2, the general form: one canonical path, used by every guard.
# --------------------------------------------------------------------------- #

#: Spellings of /admin/audit-log that a guard must treat as /admin/audit-log.
EQUIVALENT_SPELLINGS = (
    "/admin/audit-log",
    "/v1/admin/audit-log",
    "/v1/v1/admin/audit-log",
    "/v1/v1/v1/v1/admin/audit-log",
    "/admin/audit-log/",
    "//admin/audit-log",
    "/admin//audit-log",
    "/./admin/audit-log",
    "/ui/../admin/audit-log",
    "/%61dmin/audit-log",
    "/admin%2Faudit-log",
    "/ADMIN/audit-log",
    "/v1/%2e/admin/audit-log",
)


def test_the_api_key_guard_blocks_every_spelling_of_a_denied_route():
    from services import api_keys

    missed = [p for p in EQUIVALENT_SPELLINGS if not api_keys.blocked_route(p)]
    assert not missed, f"these spellings of /admin/audit-log were not recognised as blocked: {missed}"
    # ...and the guard still lets ordinary customer routes through, in their own spellings.
    for allowed in ("/assets", "/v1/assets", "/auth/context", "/scans/"):
        assert not api_keys.blocked_route(allowed), allowed


def test_an_api_key_reaches_no_spelling_of_a_denied_route_over_http(api):
    client, _ = api
    auth = {"Authorization": f"Bearer {org_api_key(client)}"}
    reached = {}
    for path in EQUIVALENT_SPELLINGS:
        res = client.get(path, headers=auth)
        if res.status_code == 200:
            reached[path] = res.text[:120]
    assert not reached, f"an organization API key read the admin audit log as: {reached}"


def test_the_support_view_refuses_every_spelling_of_a_denied_route(api):
    """The same normaliser backs the support allow-list, so it inherits the same coverage."""
    client, _ = api
    auth = {"Authorization": f"Bearer {_support_token(client)}"}
    reached = {p: client.get(p, headers=auth).status_code for p in EQUIVALENT_SPELLINGS}
    assert all(code != 200 for code in reached.values()), reached


# --------------------------------------------------------------------------- #
# Finding 5, generalised: nothing on the support allow-list hands out a secret.
# --------------------------------------------------------------------------- #

#: Field names that are credentials wherever they appear in a response body.
CREDENTIAL_FIELDS = (
    "slack_webhook", "teams_webhook", "pd_routing_key", "webhook_url", "api_key", "apikey",
    "secret", "password", "private_key", "client_secret", "signing_key", "routing_key",
)


def test_no_route_on_the_support_allow_list_returns_a_credential_field(api):
    """A structural check over the whole allow-list, not just the route the review found.

    Every allow-listed template without a path parameter is fetched with a real support token and
    the response is searched for a credential-shaped field carrying a value. Naming such a field is
    fine and sometimes the point -- /airlock/policy and /sovereign-copilot/redaction-policy publish
    the list of keys that must never leave the process -- so the check is for `"name": "value"`,
    not for the name on its own. Redaction is what /digest/config now does; a route that genuinely
    needs to return a live credential has to leave the allow-list instead.
    """
    client, _ = api
    _set_digest_secrets(client)
    auth = {"Authorization": f"Bearer {_support_token(client)}"}
    from services import support_sessions

    offenders = {}
    for template in support_sessions.ALLOWED_GET_ROUTES:
        if "{" in template:
            continue                                   # parameterised reads need per-route fixtures
        res = client.get(template, headers=auth)
        if res.status_code != 200 or not res.headers.get("content-type", "").startswith("application/json"):
            continue
        found = [f for f in CREDENTIAL_FIELDS
                 if re.search(rf'"{f}"\s*:\s*"[^"]{{6,}}"', res.text)]
        if found:
            offenders[template] = found
    assert not offenders, f"support-view reads that return credential fields: {offenders}"


def test_digest_config_still_tells_an_admin_what_is_configured(api):
    """Redaction has to stay useful: the console needs to show that a webhook is set."""
    client, _ = api
    _set_digest_secrets(client)
    body = client.get("/digest/config", headers=customer(org=ORG_A, role="admin")).json()
    assert body["slack_webhook_configured"] is True
    assert body["pd_routing_key_configured"] is True
    assert body["teams_webhook_configured"] is False
    assert body["slack_webhook_hint"].startswith("https://hooks.slack.com/")
    assert SLACK not in str(body) and PAGERDUTY not in str(body)


# --------------------------------------------------------------------------- #
# Staging dry-run F2 (high): acceptance must bind the account to the tenant.
# docs/STAGING_DRY_RUN.md - with the built-in issuer the invitee kept the org_id
# of the organization they registered in, so they operated in the wrong tenant.
# --------------------------------------------------------------------------- #

PASSWORD = "Sec-Review-Passw0rd!"


def _register_and_login(client: TestClient, app_module, email: str, org: str, role: str = "admin"):
    from services import auth_issuer as issuer

    with app_module._db() as db:
        issuer.init_tables(db)
        issuer.create_user(db, email, PASSWORD, "Review User", role, org)
    res = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return res.json()


def _org_of(token: str) -> str:
    import jwt as _jwt

    return _jwt.decode(token, SECRET, algorithms=["HS256"], audience="morrow",
                       issuer="morrow")["org_id"]


def test_accepting_an_invitation_moves_the_built_in_token_to_the_new_tenant(api):
    client, app_module = api
    session = _register_and_login(client, app_module, "mover@review.test", ORG_A)
    assert _org_of(session["access_token"]) == ORG_A

    created = client.post(f"/admin/orgs/{ORG_B}/invite",
                          headers=customer(org=ORG_B, role="admin", email="boss-b@review.test"),
                          json={"org_id": ORG_B, "email": "mover@review.test",
                                "role": "org_admin", "invited_by": "boss-b@review.test"})
    assert created.status_code == 200, created.text
    accepted = client.post("/admin/accept-invite", json={"token": _token_from_link(created.json())},
                           headers={"Authorization": "Bearer " + session["access_token"]})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["organization_binding_updated"] is True, accepted.text

    # The old token is still scoped to the old tenant: nothing retroactively re-scopes a credential.
    assert _org_of(session["access_token"]) == ORG_A
    # The next token is scoped to the accepted tenant. That is the fix.
    refreshed = client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]})
    assert refreshed.status_code == 200, refreshed.text
    assert _org_of(refreshed.json()["access_token"]) == ORG_B
    again = client.post("/auth/login", json={"email": "mover@review.test", "password": PASSWORD})
    assert _org_of(again.json()["access_token"]) == ORG_B


def test_a_member_of_two_tenants_cannot_act_in_one_with_the_others_token(api):
    client, app_module = api
    session = _register_and_login(client, app_module, "dual@review.test", ORG_A)
    for org in (ORG_A, ORG_B):
        created = client.post(f"/admin/orgs/{org}/invite",
                              headers=customer(org=org, role="admin", email=f"boss-{org}@review.test"),
                              json={"org_id": org, "email": "dual@review.test",
                                    "role": "org_admin", "invited_by": "x"})
        assert created.status_code == 200, created.text
        accepted = client.post("/admin/accept-invite", json={"token": _token_from_link(created.json())},
                               headers={"Authorization": "Bearer " + session["access_token"]})
        assert accepted.status_code == 200, accepted.text

    # Two active memberships, one token. The token names ORG_B (the most recent acceptance).
    token = client.post("/auth/login", json={"email": "dual@review.test",
                                             "password": PASSWORD}).json()["access_token"]
    assert _org_of(token) == ORG_B
    auth = {"Authorization": "Bearer " + token}
    assert client.get(f"/admin/orgs/{ORG_B}/users", headers=auth).status_code == 200
    assert client.get(f"/admin/orgs/{ORG_A}/users", headers=auth).status_code == 403, \
        "a membership in ORG_A let a token minted for ORG_B act there"

    # Switching is explicit, checks the membership, and mints a token for the new tenant.
    switched = client.post("/auth/switch-organization", headers=auth, json={"organization_id": ORG_A})
    assert switched.status_code == 200, switched.text
    assert _org_of(switched.json()["access_token"]) == ORG_A
    new_auth = {"Authorization": "Bearer " + switched.json()["access_token"]}
    assert client.get(f"/admin/orgs/{ORG_A}/users", headers=new_auth).status_code == 200
    assert client.get(f"/admin/orgs/{ORG_B}/users", headers=new_auth).status_code == 403


def test_switching_to_an_organization_without_a_membership_is_refused(api):
    client, app_module = api
    session = _register_and_login(client, app_module, "outsider@review.test", ORG_A)
    res = client.post("/auth/switch-organization",
                      headers={"Authorization": "Bearer " + session["access_token"]},
                      json={"organization_id": ORG_B})
    assert res.status_code == 403, res.text


def test_an_external_idp_identity_keeps_its_providers_organization_claim(api):
    """The external-IdP path is unchanged: there the claim is the provider's to issue.

    Acceptance still records the membership and reports honestly that it did not move any token,
    instead of silently doing nothing and claiming success.
    """
    client, _ = api
    created = client.post(f"/admin/orgs/{ORG_B}/invite",
                          headers=customer(org=ORG_B, role="admin", email="boss-idp@review.test"),
                          json={"org_id": ORG_B, "email": "idp-user@review.test",
                                "role": "analyst", "invited_by": "x"})
    assert created.status_code == 200, created.text
    accepted = client.post("/admin/accept-invite", json={"token": _token_from_link(created.json())},
                           headers=customer(org=ORG_A, role="viewer", email="idp-user@review.test"))
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["membership_recorded"] is True
    assert body["organization_binding_updated"] is False
    assert "identity provider" in body["next_step"]


# --------------------------------------------------------------------------- #
# Finding 8 (medium): script-src 'unsafe-inline' on the origin holding the key
# --------------------------------------------------------------------------- #

def test_the_operator_console_origin_forbids_inline_script(api):
    """The console that keeps the platform key in sessionStorage now runs under a real CSP.

    Every script tag it serves has a src and none of its markup carries an inline handler, so it
    needs no exception. The customer console at /ui/ still has inline <script> blocks and keeps the
    permissive policy; that is recorded in the review's Remediation section rather than half-done.
    """
    client, _ = api
    for path in ("/vendor-admin/", "/invite"):
        csp = client.get(path).headers.get("content-security-policy", "")
        assert "script-src 'self';" in csp or csp.rstrip(";").endswith("script-src 'self'"), (path, csp)
        assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0], (path, csp)
        assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp

    # And the pages under the strict policy really do serve no inline script, which is what makes
    # the header true rather than merely present.
    import pathlib

    root = pathlib.Path(__file__).resolve().parent
    for name in ("static_admin/index.html", "static_admin/traffic.html", "static/invite.html"):
        html = (root / name).read_text(encoding="utf-8")
        for tag in re.findall(r"<script[^>]*>", html):
            assert " src=" in tag, f"{name} has an inline script: {tag}"
        assert not re.search(r"\son(click|change|submit|input|load|error)\s*=", html), name


def test_logout_compares_the_csrf_token_in_constant_time():
    """Finding 13: the one comparison in the module that used `!=` on a secret."""
    import inspect

    from routers import operator_auth as router_module

    source = inspect.getsource(router_module)
    logout = source.split("def session_logout", 1)[1].split("def ", 1)[0]
    assert "compare_digest" in logout, logout[:400]
    assert "!= _auth.csrf_token_for" not in source


def test_the_webhook_ssrf_guard_pins_the_port():
    """Finding 14: https://8.8.8.8:22/hook used to validate. The scheme was pinned; the port was not."""
    from services import alert_routing

    assert alert_routing.ALLOWED_WEBHOOK_PORTS == frozenset({443})
    for url in ("https://hooks.example.com:22/x", "https://hooks.example.com:8080/x",
                "https://hooks.example.com:25/x"):
        with pytest.raises(alert_routing.AlertRoutingError) as raised:
            alert_routing.validate_webhook_url(url, resolve=False)
        assert "port 443" in raised.value.detail, url
    # 443, explicit or implied, still validates.
    assert alert_routing.validate_webhook_url("https://hooks.example.com/x", resolve=False)
    assert alert_routing.validate_webhook_url("https://hooks.example.com:443/x", resolve=False)


def test_an_emailed_invite_link_never_takes_its_host_from_the_request():
    """Finding 15: the link that leaves the process must come from configuration.

    TrustedHostMiddleware is only installed when MORROW_ALLOWED_HOSTS is not '*', so on a default
    deployment a forged Host header would have put the attacker's origin in a real invitee's email,
    next to a real token.
    """
    import os

    from services import invite_links

    saved = os.environ.pop("MORROW_PUBLIC_BASE_URL", None)
    try:
        with pytest.raises(invite_links.PublicBaseUrlMissing):
            invite_links.external_invite_link("a-token-value-0123456789")
        os.environ["MORROW_PUBLIC_BASE_URL"] = "https://app.example.test"
        assert invite_links.external_invite_link("tok") == "https://app.example.test/invite#token=tok"
    finally:
        os.environ.pop("MORROW_PUBLIC_BASE_URL", None)
        if saved is not None:
            os.environ["MORROW_PUBLIC_BASE_URL"] = saved
