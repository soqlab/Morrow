"""POST /auth/invite/register: an invited person creates their built-in account from the invitation.

Reuses the real-stack fixture from test_invite_landing. Covers the path a brand-new customer takes
(no account yet), and that the token, not the request, decides the address and organization.
"""

import pytest

from test_invite_landing import PASSWORD, api, invite, make_org  # noqa: F401  (api is a fixture)

NEW_PASSWORD = "first-customer-password-2047"


def register(client, token, password=NEW_PASSWORD, **extra):
    return client.post("/auth/invite/register", json={"token": token, "password": password, **extra})


def bearer(body):
    return {"Authorization": "Bearer " + body["access_token"]}


def test_new_customer_creates_account_joins_and_is_scoped_to_the_invited_org(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    make_org(client, "org-globex", "Globex")
    token = invite(client, "org-acme", "First@Acme.example", "org_admin")["invitation"]["token"]

    res = register(client, token, full_name="Ada")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["user"]["email"] == "first@acme.example"
    assert body["user"]["org_id"] == "org-acme"
    me = client.get("/auth/me", headers=bearer(body))
    assert me.status_code == 200 and me.json()["org_id"] == "org-acme"

    # The invitation is consumed: a second attempt cannot mint another account or reset the password.
    again = register(client, token, password="another-password-3391")
    assert again.status_code == 404
    login = client.post("/auth/login", json={"email": "first@acme.example", "password": NEW_PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["org_id"] == "org-acme"


def test_existing_account_is_sent_to_sign_in_and_invitation_stays_usable(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    with app._db() as db:
        app._issuer_create_user(db, "taken@acme.example", PASSWORD, "", "viewer", "org-other")
    token = invite(client, "org-acme", "taken@acme.example")["invitation"]["token"]

    res = register(client, token)
    assert res.status_code == 409
    # Nothing was claimed, so the owner can still sign in and accept it the normal way.
    assert client.post("/auth/invite/preview", json={"token": token}).json()["status"] == "valid"
    login = client.post("/auth/login", json={"email": "taken@acme.example", "password": PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["org_id"] == "org-other"


@pytest.mark.parametrize("password", ["short1", "no-digits-in-this-one"])
def test_weak_password_is_refused_without_using_the_invitation(api, password):
    client, app = api
    make_org(client, "org-acme", "Acme")
    token = invite(client, "org-acme", "weak@acme.example")["invitation"]["token"]
    assert register(client, token, password=password).status_code == 400
    assert client.post("/auth/invite/preview", json={"token": token}).json()["status"] == "valid"
    with app._db() as db:
        assert db.execute("SELECT COUNT(*) FROM morrow_users WHERE email=?", ("weak@acme.example",)).fetchone()[0] == 0


def test_unknown_token_and_request_supplied_email_are_ignored(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    assert register(client, "x" * 43).status_code == 404
    token = invite(client, "org-acme", "real@acme.example")["invitation"]["token"]
    # An email in the request body has no effect: the account is always the invited address.
    res = register(client, token, email="attacker@evil.example")
    assert res.status_code == 200 and res.json()["user"]["email"] == "real@acme.example"
    with app._db() as db:
        assert db.execute("SELECT COUNT(*) FROM morrow_users WHERE email=?", ("attacker@evil.example",)).fetchone()[0] == 0
