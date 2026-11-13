"""Public sign-up with a passkey, invite links instead of emailed join links, recovery without email.

Runs the real ASGI stack (the fixture from test_invite_landing) with the software authenticator from
test_passkeys, which builds real WebAuthn responses that py_webauthn verifies. Mail is captured, so
"nothing is sent" is checked directly. MORROW_PASSKEYS_ONLY=1 and MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1
are the hosted settings; the last tests switch the flag off and check the old behaviour is intact.
"""

import re

import pytest

from test_invite_landing import PASSWORD, api_fixture, invite, make_org  # noqa: F401  (api_fixture registers the "api" fixture)
from test_passkeys import (  # noqa: F401  (mail_fixture registers "mail")
    SoftAuthenticator,
    bearer,
    events,
    mail_fixture,
    passkey_login,
    password_account,
    register,
)

from services import domain_verification as dv
from services import team_join, watch

CODE_RE = re.compile(r"^[A-HJ-KM-NP-Z2-9]{4}(-[A-HJ-KM-NP-Z2-9]{4}){3}$")


@pytest.fixture
def hosted(api, mail, monkeypatch):
    """The hosted configuration: passkeys only, scans limited to verified domains, sign-up open."""
    monkeypatch.setenv("MORROW_PASSKEYS_ONLY", "1")
    monkeypatch.setenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", "1")
    monkeypatch.delenv("MORROW_SCAN_UNRESTRICTED_ORGS", raising=False)
    monkeypatch.delenv("MORROW_PASSKEY_SIGNUP", raising=False)
    for name in ("MORROW_SIGNUP_PER_IP_PER_HOUR", "MORROW_SIGNUP_PER_IP_PER_DAY", "MORROW_SIGNUP_GLOBAL_PER_HOUR",
                 "MORROW_SIGNUP_GLOBAL_PER_DAY", "MORROW_SIGNUP_API_CALLS_PER_MIN", "MORROW_SIGNUP_SCANS_PER_HOUR",
                 "MORROW_TRIAL_API_CALLS_PER_MIN", "MORROW_TRIAL_SCANS_PER_HOUR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(dv, "_ready", False)
    monkeypatch.setattr(team_join, "_ready", False)
    monkeypatch.setattr(watch, "_ready", "")
    dv._cache.clear()
    yield api
    dv._cache.clear()


def signup(client, authn=None, name="Ada Lovelace", organization="Analytical Engines", **extra):
    """Run the whole sign-up ceremony. -> (finish response, authenticator); begin's response on refusal."""
    authn = authn or SoftAuthenticator(synced=True)
    begin = client.post("/auth/passkey/register/begin",
                        json={"kind": "signup", "full_name": name, "organization": organization, **extra})
    if begin.status_code != 200:
        return begin, authn
    options = begin.json()["options"]
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    credential = authn.create(options)
    return client.post("/auth/passkey/register/finish",
                       json={"challenge_id": begin.json()["challenge_id"], "credential": credential}), authn


def signed_up(client, **kwargs):
    res, authn = signup(client, **kwargs)
    assert res.status_code == 200, res.text
    return res.json(), authn


# ── when sign-up is open ──────────────────────────────────────────────────────────────────────

def test_sign_up_is_open_on_the_hosted_configuration_only(api, mail, monkeypatch):
    client, _ = api
    monkeypatch.setenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", "1")
    assert client.get("/auth/config").json()["signup_enabled"] is False  # passkeys-only is off
    monkeypatch.setenv("MORROW_PASSKEYS_ONLY", "1")
    assert client.get("/auth/config").json()["signup_enabled"] is True
    monkeypatch.setenv("MORROW_PASSKEY_SIGNUP", "0")
    assert client.get("/auth/config").json()["signup_enabled"] is False
    assert signup(client)[0].status_code == 404
    monkeypatch.setenv("MORROW_PASSKEY_SIGNUP", "1")
    monkeypatch.delenv("MORROW_PASSKEYS_ONLY")
    assert client.get("/auth/config").json()["signup_enabled"] is True
    # Never without the verified-domain scan guard: an account anyone can make must not scan anything.
    monkeypatch.delenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS")
    assert client.get("/auth/config").json()["signup_enabled"] is False
    assert signup(client)[0].status_code == 404


def test_the_signup_page_is_public_and_strict(hosted):
    client, _ = hosted
    page = client.get("/signup")
    assert page.status_code == 200 and "Create your account" in page.text
    assert "script-src 'self'" in page.headers.get("content-security-policy", "")
    assert "<script>" not in page.text and "trial" not in page.text.lower()
    script = client.get("/ui/signup.js").text
    # Nothing to type but a name and an organization: no email field anywhere.
    assert '"signup"' in script and "/instrument/watch/" in script and 'type="email"' not in script


# ── the happy path ────────────────────────────────────────────────────────────────────────────

def test_sign_up_creates_an_organization_its_admin_and_a_passkey_with_no_email(hosted, mail):
    client, app = hosted
    data, authn = signed_up(client)
    assert data["access_token"] and data["refresh_token"]
    org = data["organization"]
    assert org["name"] == "Analytical Engines" and org["id"].startswith("org_")
    me = client.get("/auth/me", headers=bearer(data["access_token"])).json()
    assert me["org_id"] == org["id"] and me["role"] == "admin" and not me.get("email")
    with app._db() as db:
        row = db.execute("SELECT email, password_hash, full_name FROM morrow_users WHERE id=?", (me["id"],)).fetchone()
    assert row[0] is None and row[1] is None and row[2] == "Ada Lovelace"
    # The passkey signs in, usernameless.
    res, _, _ = passkey_login(client, authn)
    assert res.status_code == 200 and res.json()["user"]["org_id"] == org["id"]
    assert [e for e in events("signup.completed")]
    assert mail == []


def test_names_are_optional(hosted):
    client, _ = hosted
    data, _ = signed_up(client, name="", organization="")
    assert data["organization"]["name"] == "My organization"
    data, _ = signed_up(client, name="Grace", organization="")
    assert data["organization"]["name"] == "Grace's organization"


def test_recovery_codes_are_shown_once_and_work(hosted, mail):
    client, app = hosted
    data, _ = signed_up(client)
    codes = data["recovery_codes"]
    assert len(codes) == 10 and all(CODE_RE.match(c) for c in codes)
    status = client.get("/auth/recovery-codes", headers=bearer(data["access_token"]))
    assert status.status_code == 200 and "codes" not in status.json()
    assert status.json()["recovery_codes"]["remaining"] == 10
    with app._db() as db:
        stored = " ".join(str(r[0]) for r in db.execute("SELECT code_hmac FROM morrow_recovery_codes").fetchall())
    assert not any(c in stored or c.replace("-", "") in stored for c in codes)
    # A code buys a new passkey for this account.
    redeemed = client.post("/auth/recovery-codes/redeem", json={"code": codes[0]})
    assert redeemed.status_code == 200, redeemed.text
    res = register(client, SoftAuthenticator(), "recover", redeemed.json()["recovery_token"])
    assert res.status_code == 200 and res.json()["user"]["org_id"] == data["organization"]["id"]
    assert mail == []


# ── abuse controls ────────────────────────────────────────────────────────────────────────────

def test_per_address_limit(hosted, monkeypatch):
    client, _ = hosted
    monkeypatch.setenv("MORROW_SIGNUP_PER_IP_PER_HOUR", "2")
    signed_up(client)
    signed_up(client)
    refused, _ = signup(client)
    assert refused.status_code == 429 and "network" in refused.json()["detail"]
    assert [e for e in events("signup.rate_limited")]
    monkeypatch.setenv("MORROW_SIGNUP_PER_IP_PER_HOUR", "0")  # 0 switches a limit off
    signed_up(client)


def test_global_limit_is_checked_again_when_the_ceremony_finishes(hosted, monkeypatch):
    client, _ = hosted
    monkeypatch.setenv("MORROW_SIGNUP_GLOBAL_PER_HOUR", "1")
    # Two ceremonies started while the budget still had room: only one may finish.
    begins = [client.post("/auth/passkey/register/begin", json={"kind": "signup"}) for _ in range(2)]
    assert all(b.status_code == 200 for b in begins)
    results = []
    for begin in begins:
        credential = SoftAuthenticator().create(begin.json()["options"])
        results.append(client.post("/auth/passkey/register/finish",
                                   json={"challenge_id": begin.json()["challenge_id"], "credential": credential}))
    assert [r.status_code for r in results] == [200, 429]
    assert client.post("/auth/passkey/register/begin", json={"kind": "signup"}).status_code == 429


def test_the_hidden_field_refuses_scripts(hosted):
    client, _ = hosted
    refused, _ = signup(client, website="https://spam.example")
    assert refused.status_code == 400
    assert [e for e in events("signup.refused")]


def test_new_organizations_get_the_configured_caps(hosted, monkeypatch):
    client, _ = hosted
    monkeypatch.setenv("MORROW_SIGNUP_API_CALLS_PER_MIN", "30")
    monkeypatch.setenv("MORROW_SIGNUP_SCANS_PER_HOUR", "5")
    data, _ = signed_up(client)
    from services import admin_console

    limits = admin_console.get_rate_limits(data["organization"]["id"])
    assert limits["api_calls_per_min"] == 30 and limits["scans_per_hour"] == 5


# ── a new organization is on its own ──────────────────────────────────────────────────────────

def test_new_organizations_are_isolated_from_each_other(hosted, monkeypatch):
    client, _ = hosted
    a, _ = signed_up(client, name="A", organization="Org A")
    b, _ = signed_up(client, name="B", organization="Org B")
    assert a["organization"]["id"] != b["organization"]["id"]
    ha, hb = bearer(a["access_token"]), bearer(b["access_token"])
    assert client.post("/domains", headers=hb, json={"domain": "b-only.example"}).status_code == 200
    assert client.get("/domains", headers=ha).json()["domains"] == []
    assert [d["domain"] for d in client.get("/domains", headers=hb).json()["domains"]] == ["b-only.example"]
    users_a = client.get("/auth/users", headers=ha).json()
    listed = users_a.get("users", users_a) if isinstance(users_a, dict) else users_a
    assert {u["org_id"] for u in listed} == {a["organization"]["id"]}
    assert client.put("/instrument/watch/shared.example", headers=ha).status_code == 200
    assert client.get("/instrument/watch", headers=hb).json()["watches"] == []


def test_a_new_organization_cannot_scan_a_domain_it_has_not_verified(hosted, monkeypatch):
    client, _ = hosted
    data, _ = signed_up(client)
    headers = bearer(data["access_token"])
    refused = client.post("/scan", json={"targets": ["victim.example"]}, headers=headers)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "domain_not_verified"
    assert client.post("/scan", json={"targets": ["192.0.2.10"]}, headers=headers).status_code == 403
    # Proving control by DNS is the way in, exactly as for any other organization.
    record = client.post("/domains", headers=headers, json={"domain": "mine.example"}).json()["domain"]
    monkeypatch.setattr(dv, "_txt_values", lambda name: [record["record_value"]] if name == record["record_name"] else [])
    assert client.post("/domains/mine.example/verify", headers=headers).json()["domain"]["status"] == "verified"
    allowed = client.post("/scan", json={"targets": ["www.mine.example"]}, headers=headers)
    assert allowed.status_code == 200 and allowed.json()["results"][0]["error_code"] != "NOT_PERMITTED"


def test_watching_a_domain_right_after_signing_up(hosted):
    """What /signup?watch=<domain> does once the codes are saved: PUT the watch with the new session."""
    client, _ = hosted
    data, _ = signed_up(client)
    headers = bearer(data["access_token"])
    res = client.put("/instrument/watch/example.com", headers=headers)
    assert res.status_code == 200 and res.json()["watching"] is True
    assert [w["domain"] for w in client.get("/instrument/watch", headers=headers).json()["watches"]] == ["example.com"]
    # The admin of the new organization may also start a DNS claim (/signup?claim=<domain>).
    claim = client.post("/instrument/claims/example.com", headers=headers)
    assert claim.status_code == 200, claim.text
    # And the domain page sends signed-out visitors to sign-up with the domain.
    watch_js = client.get("/ui/instrument-watch.js").text
    assert '"/signup?watch=' in watch_js and '"/signup?claim=' in watch_js


# ── invite links instead of emailed join links ────────────────────────────────────────────────

def invite_token(link):
    match = re.fullmatch(r"https://app\.example/join#invite=([A-Za-z0-9_-]+)", link)
    assert match, link
    return match.group(1)


def test_an_admin_hands_over_an_invite_link_and_the_person_joins_with_a_passkey(hosted, mail):
    client, _ = hosted
    owner, _ = signed_up(client, organization="Acme")
    headers = bearer(owner["access_token"])
    made = client.post("/auth/invite-links", headers=headers)
    assert made.status_code == 200, made.text
    token = invite_token(made.json()["invite_link"])
    preview = client.post("/auth/invite-links/preview", json={"token": token})
    assert preview.status_code == 200 and preview.json()["organization_name"] == "Acme" and preview.json()["role"] == "viewer"
    assert [link["id"] for link in client.get("/auth/invite-links", headers=headers).json()["invite_links"]] == [made.json()["id"]]

    authn = SoftAuthenticator()
    begin = client.post("/auth/passkey/register/begin", json={"kind": "team", "token": token, "full_name": "New Member"})
    assert begin.status_code == 200, begin.text
    finish = client.post("/auth/passkey/register/finish", json={"challenge_id": begin.json()["challenge_id"],
                                                                "credential": authn.create(begin.json()["options"]), "token": token})
    assert finish.status_code == 200, finish.text
    joined = finish.json()
    assert joined["user"]["org_id"] == owner["organization"]["id"] and joined["user"]["role"] == "viewer"
    assert joined["joined"]["organization_name"] == "Acme"
    # Single use, and gone from the open list.
    assert client.post("/auth/invite-links/preview", json={"token": token}).status_code == 410
    assert client.post("/auth/passkey/register/begin", json={"kind": "team", "token": token}).status_code == 410
    assert client.get("/auth/invite-links", headers=headers).json()["invite_links"] == []
    assert passkey_login(client, authn)[0].status_code == 200
    assert mail == []


def test_invite_links_are_admin_only_revocable_and_scoped_to_one_organization(hosted):
    client, _ = hosted
    owner, _ = signed_up(client, organization="Acme")
    other, _ = signed_up(client, organization="Other")
    headers = bearer(owner["access_token"])
    made = client.post("/auth/invite-links", headers=headers).json()
    token = invite_token(made["invite_link"])
    # Another organization's admin can neither see nor revoke it.
    assert client.get("/auth/invite-links", headers=bearer(other["access_token"])).json()["invite_links"] == []
    assert client.delete(f"/auth/invite-links/{made['id']}", headers=bearer(other["access_token"])).status_code == 404
    # A viewer can't make one.
    begin = client.post("/auth/passkey/register/begin", json={"kind": "team", "token": token})
    viewer = client.post("/auth/passkey/register/finish", json={"challenge_id": begin.json()["challenge_id"],
                                                                "credential": SoftAuthenticator().create(begin.json()["options"]),
                                                                "token": token}).json()
    assert client.post("/auth/invite-links", headers=bearer(viewer["access_token"])).status_code == 403
    second = client.post("/auth/invite-links", headers=headers).json()
    assert client.delete(f"/auth/invite-links/{second['id']}", headers=headers).json()["invite_links"] == []
    assert client.post("/auth/invite-links/preview", json={"token": invite_token(second["invite_link"])}).status_code == 404


def test_join_by_email_sends_nothing_when_passkeys_only(hosted, mail):
    client, _ = hosted
    cfg = client.get("/auth/config").json()
    assert cfg["team_join_enabled"] is False and cfg["invite_links_enabled"] is True
    res = client.post("/auth/team-join/request", json={"email": "someone@acme.example"})
    assert res.status_code == 410 and "invite link" in res.json()["detail"]
    assert mail == []
    assert client.get("/join").status_code == 200


# ── /reset-password without email ─────────────────────────────────────────────────────────────

def test_reset_password_sends_nothing_when_passkeys_only(hosted, mail):
    client, app = hosted
    password_account(app, "user@acme.example")
    assert client.get("/auth/config").json()["password_reset_enabled"] is False
    res = client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    assert res.status_code == 410 and "recovery code" in res.json()["detail"]
    assert client.post("/auth/password-reset/request", json={"email": "nobody@acme.example"}).status_code == 410
    assert mail == []
    page = client.get("/reset-password")
    assert page.status_code == 200 and "Lost your passkey?" in page.text


def test_an_admin_issues_a_recovery_link_for_a_member_who_lost_everything(hosted, mail):
    client, _ = hosted
    owner, _ = signed_up(client, organization="Acme")
    other, _ = signed_up(client, organization="Other")
    headers = bearer(owner["access_token"])
    token = invite_token(client.post("/auth/invite-links", headers=headers).json()["invite_link"])
    begin = client.post("/auth/passkey/register/begin", json={"kind": "team", "token": token})
    member = client.post("/auth/passkey/register/finish", json={"challenge_id": begin.json()["challenge_id"],
                                                                "credential": SoftAuthenticator().create(begin.json()["options"]),
                                                                "token": token}).json()
    member_id = member["user"]["id"]
    # Only an admin of the member's own organization.
    assert client.post(f"/auth/accounts/{member_id}/recovery-link", headers=bearer(other["access_token"])).status_code == 404
    assert client.post(f"/auth/accounts/{member_id}/recovery-link", headers=bearer(member["access_token"])).status_code == 403
    issued = client.post(f"/auth/accounts/{member_id}/recovery-link", headers=headers)
    assert issued.status_code == 200, issued.text
    match = re.fullmatch(r"https://app\.example/reset-password#recover=([A-Za-z0-9_-]+)", issued.json()["recovery_link"])
    assert match
    fresh = SoftAuthenticator()
    res = register(client, fresh, "recover", match.group(1), revoke_other_passkeys=True)
    assert res.status_code == 200 and res.json()["user"]["id"] == member_id and res.json()["other_passkeys_removed"] == 1
    # The member's old session is signed out.
    assert client.post("/auth/refresh", json={"refresh_token": member["refresh_token"]}).status_code == 401
    assert [e for e in events("account_recovery.issued")]
    assert mail == []


# ── with the flag off, self-hosters keep the emailed flows ────────────────────────────────────

def test_flag_off_keeps_emailed_recovery_and_closes_sign_up(api, mail, monkeypatch):
    client, app = api
    monkeypatch.setenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", "1")
    cfg = client.get("/auth/config").json()
    assert cfg["password_reset_enabled"] is True and cfg["team_join_enabled"] is True and cfg["signup_enabled"] is False
    password_account(app, "user@acme.example")
    assert client.post("/auth/password-reset/request", json={"email": "user@acme.example"}).status_code == 200
    assert len(mail) == 1 and "/reset-password#token=" in mail[0][2]
    # The join request answers as before (nothing to join here, so nothing is sent, but no refusal).
    assert client.post("/auth/team-join/request", json={"email": "someone@acme.example"}).status_code == 200
