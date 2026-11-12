"""Domain team sign-in (services/team_join.py): verified domain + verified mailbox + passkey = member.

Reuses the real-stack fixture from test_invite_landing and the software authenticator from
test_passkeys. DNS is a dictionary: the tests publish and withdraw TXT records in it.
"""

import re

import pytest

from test_invite_landing import PASSWORD, api_fixture, make_org  # noqa: F401  (api_fixture registers the "api" fixture)
from test_passkeys import SoftAuthenticator, bearer, events, mail_fixture, passkey_login  # noqa: F401  (mail_fixture registers "mail")

from services import domain_verification as dv
from services import team_join


@pytest.fixture
def dns(api, mail, monkeypatch):
    records = {}
    monkeypatch.setattr(dv, "_ready", False)
    monkeypatch.setattr(team_join, "_ready", False)
    dv._cache.clear()
    monkeypatch.setattr(dv, "_txt_values", lambda name: list(records.get(name, [])))
    return records


def admin(client, app, email="admin@acme.example", org="org-acme"):
    with app._db() as db:
        app._issuer_create_user(db, email, PASSWORD, "", "admin", org)
    return bearer(client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"])


def verify(client, headers, dns, domain="acme.example"):
    row = client.post("/domains", headers=headers, json={"domain": domain}).json()["domain"]
    dns.setdefault(row["record_name"], []).append(row["record_value"])
    res = client.post(f"/domains/{domain}/verify", headers=headers)
    assert res.status_code == 200 and res.json()["domain"]["status"] == "verified", res.text
    return row


def enable(client, headers, domain="acme.example", enabled=True):
    return client.put(f"/domain-join/{domain}", headers=headers, json={"enabled": enabled})


def join_token(mail):
    match = re.search(r"https://app\.example/join#token=([A-Za-z0-9_-]+)", mail[-1][2])
    assert match, mail[-1][2]
    return match.group(1)


def finish_join(client, token, authn=None, name="New Person"):
    authn = authn or SoftAuthenticator()
    begin = client.post("/auth/passkey/register/begin", json={"kind": "join", "token": token, "full_name": name})
    if begin.status_code != 200:
        return begin, authn
    credential = authn.create(begin.json()["options"])
    return client.post("/auth/passkey/register/finish", json={"challenge_id": begin.json()["challenge_id"],
                                                              "credential": credential, "token": token}), authn


@pytest.fixture
def acme(api, dns):
    client, app = api
    make_org(client, "org-acme", "Acme Industries")
    headers = admin(client, app)
    row = verify(client, headers, dns)
    assert enable(client, headers).status_code == 200
    return client, app, headers, row


def test_happy_path_joins_as_viewer_with_a_passkey_and_is_audited(acme, mail):
    client, app, headers, _ = acme
    res = client.post("/auth/team-join/request", json={"email": "New.Person@Acme.example"})
    assert res.status_code == 200
    assert mail[-1][0] == ["new.person@acme.example"] and "Acme Industries" in mail[-1][1]
    token = join_token(mail)

    preview = client.post("/auth/team-join/preview", json={"token": token}).json()
    assert preview["organization_name"] == "Acme Industries" and preview["email_masked"] == "n***@acme.example"
    assert preview["role"] == "viewer"

    done, authn = finish_join(client, token)
    assert done.status_code == 200, done.text
    body = done.json()
    assert body["user"]["email"] == "new.person@acme.example" and body["user"]["org_id"] == "org-acme"
    assert body["user"]["role"] == "viewer" and body["joined"]["domain"] == "acme.example"
    me = client.get("/auth/me", headers=bearer(body["access_token"])).json()
    assert me["org_id"] == "org-acme" and me["role"] == "viewer" and me["has_password"] is False
    # Signs in with the passkey afterwards.
    assert passkey_login(client, authn)[0].status_code == 200
    # The link is used up.
    assert client.post("/auth/team-join/preview", json={"token": token}).status_code == 410

    # Admin sees who joined; every trail has the join.
    listing = client.get("/domain-join", headers=headers).json()
    assert listing["joined"][0]["email"] == "new.person@acme.example" and listing["joined"][0]["role"] == "viewer"
    assert listing["policies"][0]["enabled"] is True
    assert events("team_join.joined")
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE org_id='org-acme' AND action='domain_join'").fetchone()["n"] == 1
    from db import list_audit_logs, reset_current_organization_id, set_current_organization_id
    ctx = set_current_organization_id("org-acme")
    try:
        actions = [e.get("action") for e in list_audit_logs(limit=200)]
    finally:
        reset_current_organization_id(ctx)
    assert "domains.team_join.joined" in actions and "domains.team_join.enable" in actions


def test_free_mail_is_refused_for_requests_and_policies(api, dns, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    headers = admin(client, app)
    assert client.post("/auth/team-join/request", json={"email": "someone@gmail.com"}).status_code == 400
    client.post("/domains", headers=headers, json={"domain": "outlook.com"})
    res = enable(client, headers, "outlook.com")
    assert res.status_code == 400 and "free email" in res.json()["detail"]
    assert mail == []


def test_unverified_domain_cannot_be_enabled(api, dns, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    headers = admin(client, app)
    client.post("/domains", headers=headers, json={"domain": "acme.example"})  # pending, record never published
    res = enable(client, headers)
    assert res.status_code == 409 and "Verify" in res.json()["detail"]
    assert client.post("/auth/team-join/request", json={"email": "x@acme.example"}).status_code == 200
    assert mail == []   # same answer, no link


def test_only_admins_manage_team_sign_in(acme):
    client, app, _, _ = acme
    with app._db() as db:
        app._issuer_create_user(db, "viewer@acme.example", PASSWORD, "", "viewer", "org-acme")
    viewer = bearer(client.post("/auth/login", json={"email": "viewer@acme.example", "password": PASSWORD}).json()["access_token"])
    assert enable(client, viewer, enabled=False).status_code == 403
    assert client.get("/domain-join", headers=viewer).status_code == 403


def test_expired_link_is_refused(acme, mail, monkeypatch):
    client, _, _, _ = acme
    client.post("/auth/team-join/request", json={"email": "late@acme.example"})
    token = join_token(mail)
    import time as _time
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 7200)
    res, _ = finish_join(client, token)
    assert res.status_code == 410


def test_link_cannot_be_used_twice_or_after_an_account_exists(acme, mail):
    client, app, _, _ = acme
    client.post("/auth/team-join/request", json={"email": "twice@acme.example"})
    token = join_token(mail)
    assert finish_join(client, token)[0].status_code == 200
    assert finish_join(client, token)[0].status_code == 410
    # An existing account gets no link at all.
    sent = len(mail)
    assert client.post("/auth/team-join/request", json={"email": "twice@acme.example"}).status_code == 200
    assert len(mail) == sent


def test_another_organizations_domain_first_verifier_wins(acme, dns, mail):
    client, app, _, _ = acme
    make_org(client, "org-globex", "Globex")
    globex = admin(client, app, "admin@globex.example", "org-globex")
    verify(client, globex, dns)                  # verified later than Acme
    res = enable(client, globex)
    assert res.status_code == 409 and "first" in res.json()["detail"]
    listed = client.get("/domain-join", headers=globex).json()["policies"][0]
    assert listed["claimed_by_other_organization"] is True and listed["enabled"] is False
    # People at the domain still join Acme, the first verifier.
    client.post("/auth/team-join/request", json={"email": "who@acme.example"})
    res, _ = finish_join(client, join_token(mail))
    assert res.status_code == 200 and res.json()["user"]["org_id"] == "org-acme"


def test_withdrawn_dns_record_stops_joins_until_it_is_back(acme, dns, mail):
    client, _, _, row = acme
    client.post("/auth/team-join/request", json={"email": "dns@acme.example"})
    token = join_token(mail)
    dns[row["record_name"]] = []                  # the TXT record is gone
    res, _ = finish_join(client, token)
    assert res.status_code == 403 and "no longer verified" in res.json()["detail"]
    assert events("team_join.refused")
    # Nothing was used up: once the record is back, the same link works.
    dns[row["record_name"]] = [row["record_value"]]
    res, _ = finish_join(client, token)
    assert res.status_code == 200
    # And a new request while the record is missing sends nothing.
    dns[row["record_name"]] = []
    sent = len(mail)
    assert client.post("/auth/team-join/request", json={"email": "other@acme.example"}).status_code == 200
    assert len(mail) == sent


def test_disabling_stops_new_joins_and_pending_links(acme, mail):
    client, _, headers, _ = acme
    client.post("/auth/team-join/request", json={"email": "pending@acme.example"})
    token = join_token(mail)
    assert enable(client, headers, enabled=False).status_code == 200
    res, _ = finish_join(client, token)
    assert res.status_code == 403
    sent = len(mail)
    client.post("/auth/team-join/request", json={"email": "after@acme.example"})
    assert len(mail) == sent


def test_subdomain_addresses_do_not_join_through_the_parent(acme, mail):
    client, _, _, _ = acme
    sent = len(mail)
    assert client.post("/auth/team-join/request", json={"email": "x@eu.acme.example"}).status_code == 200
    assert len(mail) == sent
