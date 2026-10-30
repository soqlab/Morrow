"""Password reset for built-in accounts, and the operator email for new trial requests.

Reuses the real-stack fixture from test_invite_landing. Mail is captured, never sent; background
sends run inline so the tests can read them.
"""

import re

import pytest

from test_invite_landing import PASSWORD, api, make_org  # noqa: F401  (api is a fixture)

NEW_PASSWORD = "brand-new-password-5512"


class InlineThread:
    def __init__(self, target=None, **kwargs):
        self.target = target

    def start(self):
        self.target()


@pytest.fixture
def mail(api, monkeypatch):
    client, app = api
    from types import SimpleNamespace

    from routers import trial_requests as trial_router
    from services import platform_mail

    sent = []
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://app.example")
    monkeypatch.setattr(platform_mail, "configured", lambda: True)
    monkeypatch.setattr(platform_mail, "send_text", lambda to, subject, body, timeout=20.0: sent.append((to, subject, body)) or {"ok": True})
    # Only the two mail senders run inline; the test client itself needs real threads.
    inline = SimpleNamespace(Thread=InlineThread)
    monkeypatch.setattr(app, "threading", inline)
    monkeypatch.setattr(trial_router, "threading", inline)
    return sent


def account(app, email="user@acme.example", password=PASSWORD, org="org-acme"):
    with app._db() as db:
        return app._issuer_create_user(db, email, password, "", "viewer", org)


def link_token(body):
    # The origin is the configured one, whatever Host the request carried.
    match = re.search(r"https://app\.example/reset-password#token=([A-Za-z0-9_-]+)", body)
    assert match, body
    return match.group(1)


def test_reset_changes_password_signs_out_and_works_once(api, mail):
    client, app = api
    account(app)
    old = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()

    res = client.post("/auth/password-reset/request", json={"email": "User@Acme.example"})
    assert res.status_code == 200
    assert len(mail) == 1 and mail[0][0] == ["user@acme.example"]
    token = link_token(mail[0][2])

    done = client.post("/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD})
    assert done.status_code == 200, done.text
    assert client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).status_code == 401
    assert client.post("/auth/login", json={"email": "user@acme.example", "password": NEW_PASSWORD}).status_code == 200
    # Sessions from before the reset are gone.
    assert client.post("/auth/refresh", json={"refresh_token": old["refresh_token"]}).status_code == 401
    # The link works once.
    again = client.post("/auth/password-reset/confirm", json={"token": token, "password": "another-password-7781"})
    assert again.status_code == 410


def test_unknown_address_gets_the_same_answer_and_no_email(api, mail):
    client, app = api
    account(app)
    known = client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    unknown = client.post("/auth/password-reset/request", json={"email": "nobody@acme.example"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()
    assert [m[0] for m in mail] == [["user@acme.example"]]


def test_weak_password_keeps_the_link_and_newer_link_replaces_older(api, mail):
    client, app = api
    account(app)
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    first = link_token(mail[-1][2])
    assert client.post("/auth/password-reset/confirm", json={"token": first, "password": "short"}).status_code == 400
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    second = link_token(mail[-1][2])
    assert client.post("/auth/password-reset/confirm", json={"token": first, "password": NEW_PASSWORD}).status_code == 404
    assert client.post("/auth/password-reset/confirm", json={"token": second, "password": NEW_PASSWORD}).status_code == 200


def test_expired_link_is_refused(api, mail, monkeypatch):
    client, app = api
    account(app)
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    token = link_token(mail[-1][2])
    import time as _time
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 3600)
    assert client.post("/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD}).status_code == 410


def test_without_email_reset_is_unavailable_and_not_advertised(api):
    client, app = api
    account(app)
    assert client.post("/auth/password-reset/request", json={"email": "user@acme.example"}).status_code == 503
    assert client.get("/auth/config").json().get("password_reset_enabled") is False
    assert client.get("/reset-password").status_code == 200


def test_new_trial_request_emails_the_operator_once(api, mail, monkeypatch):
    client, app = api
    monkeypatch.setenv("MORROW_TRIAL_NOTIFY_EMAIL", "owner@soqlab.example")
    body = {"email": "lead@initech.example", "name": "Lead", "company": "Initech", "domain": "initech.example",
            "use_case": "Checking our TLS estate before the 2030 deadline."}
    assert client.post("/api/trial-request", json=body).status_code == 200
    assert client.post("/api/trial-request", json=body).status_code == 200  # duplicate
    notes = [m for m in mail if m[0] == ["owner@soqlab.example"]]
    assert len(notes) == 1 and "Initech" in notes[0][1] and "lead@initech.example" in notes[0][2]
