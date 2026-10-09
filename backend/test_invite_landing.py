"""Invitation landing page: /invite, POST /auth/invite/preview, invite links and invitation email.

Runs the real ASGI stack with JWT auth required, as in production. SMTP is replaced; nothing is sent.
"""

import re
import socket
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from services import auth_issuer

SECRET = "invite-landing-tests-jwt-signing-key-not-for-deployment-19"
LEGACY = "invite-landing-tests-platform-key-0123456789abcdef"
PASSWORD = "invite-landing-password-8841"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "invite.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_AUTH_JWT_SECRET", SECRET)
    monkeypatch.delenv("PQC_PLATFORM_OPERATORS", raising=False)
    monkeypatch.delenv("PQC_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    monkeypatch.delenv("PQC_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("PQC_SMTP_HOST", raising=False)
    monkeypatch.delenv("PQC_PLATFORM_SMTP_ORG_ID", raising=False)
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

    def no_network(*args, **kwargs):
        raise AssertionError("a test tried to open a real network connection")
    monkeypatch.setattr(socket, "create_connection", no_network)
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    client = TestClient(app.app, client=("192.0.2.40", 40000))
    yield client, app
    client.close()


def op(role="operator"):
    return {"x-platform-key": LEGACY, "x-platform-admin-role": role}


def make_org(client, org_id, name):
    res = client.post("/platform/customers", headers=op("owner"), json={"organization_id": org_id, "name": name, "reason": "test setup"})
    assert res.status_code == 200, res.text


def token_from_link(link):
    match = re.search(r"#token=([A-Za-z0-9_-]+)", str(link or ""))
    assert match, f"no token in invite link {link!r}"
    return match.group(1)


def invite(client, org_id="org-acme", email="Invitee@Corp.example", role="analyst"):
    res = client.post(f"/platform/customers/{org_id}/invitations", headers=op(),
                      json={"email": email, "role": role, "reason": "onboarding"})
    assert res.status_code == 200, res.text
    body = res.json()
    # The API returns the one-time link and never the bare token (September 2026 review, finding 3:
    # a token in a field of its own ends up in logs, screenshots and the audit trail). Tests that
    # need the token read it out of the link's fragment, exactly as the invitee's browser does.
    assert "token" not in body["invitation"], body["invitation"]
    body["invitation"]["token"] = token_from_link(body["invitation"]["invite_link"])
    return body


def preview(client, token):
    return client.post("/auth/invite/preview", json={"token": token})


def make_user(app, email, org="org-acme"):
    with app._db() as conn:
        return auth_issuer.create_user(conn, email, PASSWORD, "Test User", "viewer", org)


def login(client, email):
    res = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return res.json()


def test_invitation_create_returns_a_landing_link_and_preview_masks_the_email(api):
    client, _ = api
    make_org(client, "org-acme", "Acme Industries")
    created = invite(client)
    invitation = created["invitation"]
    token = invitation["token"]
    assert invitation["invite_link"] == f"http://testserver/invite#token={token}"
    assert created["email_configured"] is False

    res = preview(client, token)
    assert res.status_code == 200, res.text
    assert res.headers["cache-control"].startswith("no-store")
    assert res.json() == {"organization_name": "Acme Industries", "role": "Analyst", "invited_email_masked": "i***@corp.example",
                          "expires_at": invitation["expires_at"], "status": "valid"}
    assert "invitee@corp.example" not in res.text.lower() and "org-acme" not in res.text


def test_public_base_url_is_used_for_links(api, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://app.airlock.example/")
    make_org(client, "org-acme", "Acme")
    token = invite(client)["invitation"]["token"]
    assert invite(client, email="second@corp.example")["invitation"]["invite_link"].startswith("https://app.airlock.example/invite#token=")
    assert token


def test_preview_reports_expired_used_and_revoked(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    expired = invite(client, email="late@corp.example")["invitation"]
    used = invite(client, email="user@corp.example")["invitation"]
    revoked = invite(client, email="gone@corp.example")["invitation"]

    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE admin_invitations SET expires_at = ? WHERE token = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), expired["token"]))
        conn.commit()
    assert preview(client, expired["token"]).json()["status"] == "expired"

    make_user(app, "user@corp.example")
    session = login(client, "user@corp.example")
    accepted = client.post("/admin/accept-invite", json={"token": used["token"]},
                           headers={"authorization": "Bearer " + session["access_token"]})
    assert accepted.status_code == 200, accepted.text
    assert preview(client, used["token"]).json()["status"] == "used"

    assert client.delete(f"/platform/customers/org-acme/invitations/{revoked['invite_id']}?reason=sent+by+mistake", headers=op()).status_code == 200
    gone = preview(client, revoked["token"]).json()
    assert gone["status"] == "revoked" and gone["invited_email_masked"] == "g***@corp.example" and gone["organization_name"] == "Acme"

    for bogus in ["A" * 43, "short", "not a token!", "x" * 300]:
        res = preview(client, bogus)
        assert res.status_code in (404, 422), bogus
        assert "@" not in res.text


def test_preview_is_rate_limited(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app.limiter, "enabled", True)
    app.limiter.reset()
    try:
        statuses = [preview(client, "B" * 43).status_code for _ in range(25)]
    finally:
        app.limiter.reset()
    assert 429 in statuses and statuses[0] == 404


def test_accept_still_requires_the_invited_email(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    token = invite(client, email="right@corp.example")["invitation"]["token"]
    # The token goes in the JSON body, never in the request line: a query string is written to
    # every proxy, WAF and APM access log in front of the app, and this is a live bearer credential.
    body = {"token": token}
    path = "/admin/accept-invite"
    assert client.post(path, json=body).status_code == 401
    make_user(app, "wrong@corp.example")
    make_user(app, "right@corp.example")
    wrong = login(client, "wrong@corp.example")["access_token"]
    assert client.post(path, json=body, headers={"authorization": "Bearer " + wrong}).status_code == 403
    assert preview(client, token).json()["status"] == "valid", "a refused acceptance does not consume the invitation"
    right = login(client, "right@corp.example")["access_token"]
    assert client.post(path, json=body, headers={"authorization": "Bearer " + right}).status_code == 200
    assert client.post(path, json=body, headers={"authorization": "Bearer " + right}).status_code == 409
    # The query-string form is gone: the token is a required body field.
    assert client.post(f"{path}?token={token}", headers={"authorization": "Bearer " + right}).status_code == 422


def test_invite_page_is_public_with_safe_headers(api):
    client, app = api
    page = client.get("/invite")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "no-store" in page.headers["cache-control"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "noindex" in page.headers.get("x-robots-tag", "")
    html = page.text
    assert '<meta name="referrer" content="no-referrer">' in html
    assert "/ui/invite.js?v=" in html and "/ui/public.css" in html and "/ui/experience.css" in html
    # No third-party requests: every src/href is same-origin.
    for url in re.findall(r'(?:src|href)="([^"]+)"', html):
        assert url.startswith(("/", "#")), url
    script = client.get("/ui/invite.js")
    assert script.status_code == 200
    assert not re.search(r"https?://", script.text), "invite.js must not call another origin"
    assert "/auth/invite/preview" in script.text and "/admin/accept-invite" in script.text
    assert "accept-invite?token=" not in script.text, "the token must not ride in the request line"

    # Reachable without a login while everything else still requires one.
    assert client.post("/auth/invite/preview", json={"token": "C" * 43}).status_code == 404
    assert client.get("/assets").status_code in (401, 403)
    policy = client.get("/auth/access-policy").json()
    assert "/invite" in {p["path"] for p in policy["public_no_login"]}


def test_email_the_invite_uses_smtp_only_when_configured(api, monkeypatch):
    client, _ = api
    make_org(client, "org-acme", "Acme Industries")
    invitation = invite(client, email="mail@corp.example")["invitation"]
    url = f"/platform/customers/org-acme/invitations/{invitation['invite_id']}/email"

    status = client.get("/platform/invitations/email-status", headers=op("auditor")).json()
    assert status["email_configured"] is False and "isn't configured" in status["detail"]
    res = client.post(url, headers=op(), json={"reason": "send it"})
    assert res.status_code == 503 and "isn't configured" in res.json()["detail"]

    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            assert host == "smtp.example.test"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, user, password):
            pass

        def send_message(self, msg, from_addr=None, to_addrs=None):
            sent.append({"to": to_addrs, "subject": msg["Subject"], "body": msg.get_content(), "from": from_addr})

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("PQC_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("PQC_SMTP_FROM", "no-reply@airlock.example")

    # A link that leaves the process must not take its origin from the request Host header:
    # TrustedHostMiddleware is only installed when PQC_ALLOWED_HOSTS is not '*', so without this
    # an attacker could have the server email a real invitee a real token on an origin they own.
    refused = client.post(url, headers=op(), json={"reason": "send it"})
    assert refused.status_code == 503 and "PQC_PUBLIC_BASE_URL" in refused.json()["detail"]
    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://app.airlock.example")

    assert client.post(url, headers=op("auditor"), json={"reason": "send it"}).status_code == 403
    assert client.post(url, headers=op(), json={}).status_code == 422
    ok = client.post(url, headers=op(), json={"reason": "send it"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["sent_to"] == "m***@corp.example"
    assert sent[0]["to"] == ["mail@corp.example"] and "Acme Industries" in sent[0]["subject"]
    assert f"https://app.airlock.example/invite#token={invitation['token']}" in sent[0]["body"]
    assert invitation["token"] not in ok.text

    assert client.post("/platform/customers/org-acme/invitations/0123456789abcdef0123/email", headers=op(),
                       json={"reason": "send it"}).status_code == 404
    assert client.post(f"/platform/customers/org-missing/invitations/{invitation['invite_id']}/email", headers=op(),
                       json={"reason": "send it"}).status_code == 404


def test_customer_admin_invite_response_includes_the_link(api):
    client, app = api
    with app._db() as conn:
        auth_issuer.create_user(conn, "boss@corp.example", PASSWORD, "Org Admin", "admin", "org-acme")
    admin = login(client, "boss@corp.example")["access_token"]
    res = client.post("/admin/orgs/org-acme/invite", headers={"authorization": "Bearer " + admin},
                      json={"org_id": "org-acme", "email": "x@corp.example", "role": "viewer", "invited_by": "boss@corp.example"})
    assert res.status_code == 200, res.text
    body = res.json()
    # The link, and only the link: the bare token is not a field of its own in any response.
    assert "token" not in body, body
    token = token_from_link(body["invite_link"])
    assert body["invite_link"] == f"http://testserver/invite#token={token}"
    assert body["invite_id"]
    assert preview(client, token).json()["status"] == "valid"
