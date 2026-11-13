"""Sign-in without email: usernameless passkeys, accounts without an email, recovery codes.

Runs the real ASGI stack (the fixture from test_invite_landing) with the software authenticator
from test_passkeys, which builds real WebAuthn responses that py_webauthn verifies. Mail is captured.
"""

import os
import re
import sqlite3
import time

import pytest

from test_invite_landing import PASSWORD, api_fixture, invite, make_org  # noqa: F401  (api_fixture registers the "api" fixture)
from test_passkeys import (  # noqa: F401  (mail_fixture registers "mail")
    SoftAuthenticator,
    bearer,
    events,
    mail_fixture,
    passkey_login,
    password_account,
    password_hash_of,
    register,
)

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
CODE_RE = re.compile(r"^[A-HJ-KM-NP-Z2-9]{4}(-[A-HJ-KM-NP-Z2-9]{4}){3}$")


def admin_headers(client, app, email="admin@acme.example", org="org-acme"):
    password_account(app, email, org=org, role="admin")
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return bearer(login.json()["access_token"])


def setup_token(link):
    match = re.fullmatch(r"https://app\.example/reset-password#setup=([A-Za-z0-9_-]+)", link)
    assert match, link
    return match.group(1)


def emailless_account(client, app, name="Ada Lovelace", role="viewer"):
    """An account made by an admin with a display name only, set up with a passkey. -> (authn, session)"""
    headers = admin_headers(client, app)
    created = client.post("/auth/accounts", headers=headers, json={"full_name": name, "role": role})
    assert created.status_code == 200, created.text
    assert created.json()["user"]["email"] == ""
    authn = SoftAuthenticator(synced=True)
    res = register(client, authn, "setup", setup_token(created.json()["setup_link"]))
    assert res.status_code == 200, res.text
    return authn, res.json()


def invited_passkey_account(client, email="r@acme.example"):
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    res = register(client, authn, "invite", invite(client, "org-acme", email)["invitation"]["token"])
    assert res.status_code == 200, res.text
    return authn, res.json()


def new_codes(client, session):
    res = client.post("/auth/recovery-codes", headers=bearer(session["access_token"]))
    assert res.status_code == 200, res.text
    return res.json()["codes"]


def use_code(client, code, authn=None, **finish):
    """Redeem a code and register a new passkey with the ticket. -> (redeem response, finish response)"""
    redeemed = client.post("/auth/recovery-codes/redeem", json={"code": code})
    if redeemed.status_code != 200:
        return redeemed, None
    token = redeemed.json()["recovery_token"]
    return redeemed, register(client, authn or SoftAuthenticator(), "recover", token, **finish)


# ── 1. usernameless sign-in ───────────────────────────────────────────────────────────────────

def test_usernameless_sign_in_asks_for_a_discoverable_passkey_and_restricts_no_transport(api, mail):
    client, app = api
    password_account(app)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()
    begin = client.post("/auth/passkey/register/begin", json={"kind": "account"}, headers=bearer(login["access_token"])).json()
    selection = begin["options"]["authenticatorSelection"]
    assert selection["residentKey"] == "required" and selection["userVerification"] == "required"
    # No attachment asked for: this device, a security key or a phone by QR code are all offered.
    assert "authenticatorAttachment" not in selection
    authn = SoftAuthenticator()
    finish = client.post("/auth/passkey/register/finish", headers=bearer(login["access_token"]),
                         json={"challenge_id": begin["challenge_id"], "credential": authn.create(begin["options"])})
    assert finish.status_code == 200, finish.text

    begin = client.post("/auth/passkey/login/begin", json={})
    assert begin.status_code == 200
    options = begin.json()["options"]
    assert options.get("allowCredentials") in (None, []) and options["userVerification"] == "required"
    res, _, _ = passkey_login(client, authn)
    assert res.status_code == 200 and res.json()["user"]["email"] == "user@acme.example"

    # A second passkey: the existing one is excluded by id only, never by transport.
    again = client.post("/auth/passkey/register/begin", json={"kind": "account"}, headers=bearer(res.json()["access_token"])).json()
    assert again["options"]["excludeCredentials"] and all("transports" not in c for c in again["options"]["excludeCredentials"])
    # The email fallback (kept for authenticators that can't discover) doesn't restrict transports either.
    fallback = client.post("/auth/passkey/login/begin", json={"email": "user@acme.example"}).json()["options"]
    assert fallback["allowCredentials"] and all("transports" not in c for c in fallback["allowCredentials"])


def test_config_offers_recovery_codes_with_passkeys(api, mail):
    client, _ = api
    cfg = client.get("/auth/config").json()
    assert cfg["passkeys_enabled"] is True and cfg["recovery_codes_enabled"] is True


# ── 2. accounts without an email ─────────────────────────────────────────────────────────────

def test_admin_creates_an_account_with_a_display_name_only_and_it_signs_in_with_a_passkey(api, mail):
    client, app = api
    headers = admin_headers(client, app)
    created = client.post("/auth/accounts", headers=headers, json={"full_name": "  Ada   Lovelace ", "role": "operator"})
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["user"]["email"] == "" and body["user"]["full_name"] == "Ada Lovelace" and body["user"]["org_id"] == "org-acme"
    assert body["expires_in"] == 259200
    token = setup_token(body["setup_link"])
    assert not mail  # nothing is emailed: the admin hands the link over
    with app._db() as db:
        row = db.execute("SELECT email, password_hash, role FROM morrow_users WHERE id=?", (body["user"]["id"],)).fetchone()
    assert tuple(row) == (None, None, "operator")

    begin = client.post("/auth/passkey/register/begin", json={"kind": "setup", "token": token}).json()
    # The device lists the display name, since there is no email.
    assert begin["options"]["user"]["name"] == "Ada Lovelace" and begin["options"]["user"]["displayName"] == "Ada Lovelace"
    authn = SoftAuthenticator()
    finish = client.post("/auth/passkey/register/finish", json={"challenge_id": begin["challenge_id"], "token": token,
                                                                "credential": authn.create(begin["options"])})
    assert finish.status_code == 200, finish.text
    assert finish.json()["access_token"] and finish.json()["user"]["email"] == ""
    me = client.get("/auth/me", headers=bearer(finish.json()["access_token"])).json()
    assert me["email"] == "" and me["passkey_count"] == 1 and me["has_password"] is False and me["role"] == "operator"
    assert me["email_recovery"] is False and me["recovery_codes_remaining"] == 0

    res, _, _ = passkey_login(client, authn)
    assert res.status_code == 200 and res.json()["user"]["id"] == body["user"]["id"]
    # The setup link worked once, and the account can't get another one now that it's in use.
    assert client.post("/auth/passkey/register/begin", json={"kind": "setup", "token": token}).status_code == 410
    assert client.post(f"/auth/accounts/{body['user']['id']}/setup-link", headers=headers).status_code == 409
    listed = client.get("/auth/users", headers=headers).json()["users"]
    assert {u["full_name"]: u["email"] for u in listed}["Ada Lovelace"] == ""
    assert events("account_setup.issued") and events("passkey.registered")


def test_several_accounts_without_email_coexist_and_email_stays_unique(api, mail):
    client, app = api
    headers = admin_headers(client, app)
    for name in ("One", "Two", "Three"):
        assert client.post("/auth/accounts", headers=headers, json={"full_name": name}).status_code == 200
    with app._db() as db:
        assert db.execute("SELECT COUNT(*) FROM morrow_users WHERE email IS NULL").fetchone()[0] == 3
    with_email = client.post("/auth/accounts", headers=headers, json={"full_name": "Has mail", "email": "Mail@Acme.example"})
    assert with_email.status_code == 200 and with_email.json()["user"]["email"] == "mail@acme.example"
    assert client.post("/auth/accounts", headers=headers, json={"full_name": "Dup", "email": "mail@acme.example"}).status_code == 409
    assert client.post("/auth/accounts", headers=headers, json={"full_name": "Bad", "email": "not an address"}).status_code == 400
    assert client.post("/auth/accounts", headers=headers, json={"full_name": "Boss", "role": "superuser"}).status_code == 400
    # An empty email never matches an account without one.
    assert client.post("/auth/login", json={"email": "", "password": PASSWORD}).status_code == 400
    assert client.post("/auth/password-reset/request", json={"email": "x@y.z"}).status_code == 200


def test_setup_links_are_admin_only_org_scoped_and_never_take_over_a_used_account(api, mail):
    client, app = api
    headers = admin_headers(client, app)
    viewer = password_account(app, "viewer@acme.example", org="org-acme")
    viewer_login = client.post("/auth/login", json={"email": "viewer@acme.example", "password": PASSWORD}).json()
    assert client.post("/auth/accounts", headers=bearer(viewer_login["access_token"]), json={"full_name": "X"}).status_code == 403
    assert client.post("/auth/accounts", json={"full_name": "X"}).status_code == 401
    # A password account is in use: no setup link for it.
    assert client.post(f"/auth/accounts/{viewer['id']}/setup-link", headers=headers).status_code == 409
    other_admin = admin_headers(client, app, "admin@other.example", org="org-other")
    created = client.post("/auth/accounts", headers=headers, json={"full_name": "Pending"}).json()
    assert client.post(f"/auth/accounts/{created['user']['id']}/setup-link", headers=other_admin).status_code == 404
    # A reissued link replaces the first.
    again = client.post(f"/auth/accounts/{created['user']['id']}/setup-link", headers=headers)
    assert again.status_code == 200
    first, second = setup_token(created["setup_link"]), setup_token(again.json()["setup_link"])
    assert client.post("/auth/passkey/register/begin", json={"kind": "setup", "token": first}).status_code == 404
    assert register(client, SoftAuthenticator(), "setup", second).status_code == 200


def test_setup_link_expires(api, mail, monkeypatch):
    client, app = api
    headers = admin_headers(client, app)
    token = setup_token(client.post("/auth/accounts", headers=headers, json={"full_name": "Late"}).json()["setup_link"])
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 259200 + 60)
    assert client.post("/auth/passkey/register/begin", json={"kind": "setup", "token": token}).status_code == 410


def test_setup_links_need_passkeys(api, mail, monkeypatch):
    client, app = api
    headers = admin_headers(client, app)
    monkeypatch.delenv("MORROW_PUBLIC_BASE_URL", raising=False)
    assert client.post("/auth/accounts", headers=headers, json={"full_name": "X"}).status_code == 404


# ── 3. recovery codes ────────────────────────────────────────────────────────────────────────

def test_recovery_codes_are_shown_once_and_only_keyed_hashes_are_stored(api, mail):
    client, app = api
    _, session = invited_passkey_account(client)
    codes = new_codes(client, session)
    assert len(codes) == 10 and len(set(codes)) == 10 and all(CODE_RE.match(c) for c in codes)
    status = client.get("/auth/recovery-codes", headers=bearer(session["access_token"])).json()
    assert "codes" not in status and status["recovery_codes"]["remaining"] == 10 and status["recovery_codes"]["total"] == 10
    with app._db() as db:
        rows = db.execute("SELECT * FROM morrow_recovery_codes").fetchall()
    assert len(rows) == 10
    dumped = " ".join(str(v) for row in rows for v in tuple(row))
    for code in codes:
        assert code not in dumped and code.replace("-", "") not in dumped
    assert all(re.fullmatch(r"[0-9a-f]{64}", row[0]) for row in rows)
    # Keyed: the stored value is not a plain SHA-256 of the code.
    import hashlib
    assert hashlib.sha256(codes[0].replace("-", "").encode()).hexdigest() not in dumped
    assert events("recovery_codes.generated")


def test_a_recovery_code_buys_only_a_new_passkey_and_signs_everyone_else_out(api, mail):
    client, app = api
    lost, session = invited_passkey_account(client)
    codes = new_codes(client, session)

    redeemed = client.post("/auth/recovery-codes/redeem", json={"code": codes[0].lower().replace("-", " ")})
    assert redeemed.status_code == 200, redeemed.text
    data = redeemed.json()
    assert data["account"] == "r@acme.example" and data["expires_in"] == 600 and data["recovery_codes_remaining"] == 9
    assert "access_token" not in data and "refresh_token" not in data
    ticket = data["recovery_token"]
    # The ticket is not a session.
    assert client.get("/auth/me", headers=bearer(ticket)).status_code == 401
    assert client.get("/auth/passkeys", headers=bearer(ticket)).status_code == 401

    replacement = SoftAuthenticator()
    res = register(client, replacement, "recover", ticket, revoke_other_passkeys=True)
    assert res.status_code == 200, res.text
    assert res.json()["access_token"] and res.json()["other_passkeys_removed"] == 1
    assert passkey_login(client, lost)[0].status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
    assert passkey_login(client, replacement)[0].status_code == 200
    # The ticket worked once.
    assert client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": ticket}).status_code == 410
    assert [e["login_method"] for e in events("recovery_code.used")] == ["recovery_code"]
    assert events("account_recovery.completed")


def test_a_used_code_is_refused_and_the_others_still_work(api, mail):
    client, app = api
    _, session = invited_passkey_account(client)
    codes = new_codes(client, session)
    assert use_code(client, codes[3])[1].status_code == 200
    again = client.post("/auth/recovery-codes/redeem", json={"code": codes[3]})
    assert again.status_code == 401 and "already been used" in again.json()["detail"]
    assert client.post("/auth/recovery-codes/redeem", json={"code": "ABCD-EFGH-JKMN-PQRS"}).status_code == 401
    assert client.post("/auth/recovery-codes/redeem", json={"code": "not a code"}).status_code == 401
    assert len(events("recovery_code.refused")) == 3
    assert use_code(client, codes[4])[1].status_code == 200


def test_the_recovery_ticket_expires(api, mail, monkeypatch):
    client, app = api
    _, session = invited_passkey_account(client)
    ticket = client.post("/auth/recovery-codes/redeem", json={"code": new_codes(client, session)[0]}).json()["recovery_token"]
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 601)
    assert client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": ticket}).status_code == 410


def test_regenerating_invalidates_the_old_codes_and_never_leaves_none(api, mail):
    client, app = api
    _, session = invited_passkey_account(client)
    old = new_codes(client, session)
    new = new_codes(client, session)
    assert not set(old) & set(new)
    assert client.post("/auth/recovery-codes/redeem", json={"code": old[0]}).status_code == 401
    status = client.get("/auth/recovery-codes", headers=bearer(session["access_token"])).json()
    assert status["recovery_codes"]["remaining"] == 10
    assert use_code(client, new[0])[1].status_code == 200


def test_regenerating_needs_a_recent_sign_in(api, mail, monkeypatch):
    client, app = api
    _, session = invited_passkey_account(client)
    monkeypatch.setenv("MORROW_PASSKEY_REAUTH_SECONDS", "60")
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 120)
    assert client.post("/auth/recovery-codes", headers=bearer(session["access_token"])).status_code == 401
    assert client.put("/auth/email-recovery", headers=bearer(session["access_token"]), json={"enabled": False}).status_code == 401
    assert client.post("/auth/recovery-codes").status_code == 401


def test_redeeming_is_rate_limited(api, mail, monkeypatch):
    client, app = api
    monkeypatch.setattr(app.limiter, "enabled", True)
    app.limiter.reset()
    try:
        statuses = [client.post("/auth/recovery-codes/redeem", json={"code": "ABCD-EFGH-JKMN-PQRS"}).status_code
                    for _ in range(25)]
    finally:
        app.limiter.reset()
    assert statuses[0] == 401 and 429 in statuses


def test_an_account_without_email_recovers_with_a_code(api, mail):
    client, app = api
    lost, session = emailless_account(client, app)
    codes = new_codes(client, session)
    redeemed, res = use_code(client, codes[0], revoke_other_passkeys=True)
    assert redeemed.json()["account"] == "Ada Lovelace"
    assert res.status_code == 200 and res.json()["user"]["email"] == ""
    assert passkey_login(client, lost)[0].status_code == 401
    assert not mail


def test_recovery_codes_need_passkeys(api, mail, monkeypatch):
    client, app = api
    _, session = invited_passkey_account(client)
    monkeypatch.delenv("MORROW_PUBLIC_BASE_URL", raising=False)
    assert client.post("/auth/recovery-codes", headers=bearer(session["access_token"])).status_code == 404
    assert client.post("/auth/recovery-codes/redeem", json={"code": "ABCD-EFGH-JKMN-PQRS"}).status_code == 404


# ── 3b. emailed recovery is a per-account switch ──────────────────────────────────────────────

def test_emailed_recovery_stays_on_for_existing_accounts_and_can_be_switched_off_once_codes_exist(api, mail):
    client, app = api
    _, session = invited_passkey_account(client)
    headers = bearer(session["access_token"])
    status = client.get("/auth/recovery-codes", headers=headers).json()
    assert status["email_recovery"] is True and status["has_email"] is True

    client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    assert len(mail) == 1 and "#recover=" in mail[0][2]

    # Not without recovery codes: that would leave no way back in.
    refused = client.put("/auth/email-recovery", headers=headers, json={"enabled": False})
    assert refused.status_code == 409
    new_codes(client, session)
    off = client.put("/auth/email-recovery", headers=headers, json={"enabled": False})
    assert off.status_code == 200 and off.json()["email_recovery"] is False
    answer = client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    assert answer.status_code == 200 and len(mail) == 1  # same answer, nothing sent
    assert client.post("/auth/password-reset/request", json={"email": "nobody@acme.example"}).json() == answer.json()
    assert events("email_recovery.changed")

    assert client.put("/auth/email-recovery", headers=headers, json={"enabled": True}).json()["email_recovery"] is True
    client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    assert len(mail) == 2


def test_password_reset_email_also_respects_the_switch(api, mail):
    client, app = api
    user = password_account(app)
    with app._db() as db:
        app._issuer_set_email_recovery(db, user["id"], False)
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    assert not mail


def test_an_account_without_email_cannot_switch_emailed_recovery_on(api, mail):
    client, app = api
    _, session = emailless_account(client, app)
    res = client.put("/auth/email-recovery", headers=bearer(session["access_token"]), json={"enabled": True})
    assert res.status_code == 409


# ── 4. nobody is locked out ──────────────────────────────────────────────────────────────────

def test_the_bootstrap_admin_still_signs_in_with_its_password(api, mail, monkeypatch):
    client, app = api
    from services import auth_issuer

    monkeypatch.setenv("MORROW_ADMIN_EMAIL", "boot@acme.example")
    monkeypatch.setenv("MORROW_ADMIN_PASSWORD", "Bootstrap-admin-password-2026")
    with app._db() as db:
        db.execute("DELETE FROM morrow_users")  # a fresh deployment: bootstrap runs only with no accounts
        db.commit()
        auth_issuer.init_tables(db)
        auth_issuer.init_tables(db)
    login = client.post("/auth/login", json={"email": "boot@acme.example", "password": "Bootstrap-admin-password-2026"})
    assert login.status_code == 200, login.text
    assert login.json()["user"]["role"] == "admin" and login.json()["access_token"]
    # The admin can make recovery codes and set up accounts without email.
    headers = bearer(login.json()["access_token"])
    assert client.post("/auth/recovery-codes", headers=headers).status_code == 200
    assert client.post("/auth/accounts", headers=headers, json={"full_name": "New person"}).status_code == 200
    # Making codes doesn't touch the password: it still signs in.
    assert client.post("/auth/login", json={"email": "boot@acme.example", "password": "Bootstrap-admin-password-2026"}).status_code == 200


def test_the_last_passkey_still_cant_be_removed(api, mail):
    client, app = api
    _, session = emailless_account(client, app)
    headers = bearer(session["access_token"])
    new_codes(client, session)  # codes don't count as a way to sign in
    only = client.get("/auth/passkeys", headers=headers).json()["passkeys"][0]["id"]
    assert client.delete(f"/auth/passkeys/{only}", headers=headers).status_code == 409


def migrated_users(conn):
    return {r[1]: (r[3], r[4]) for r in conn.execute("PRAGMA table_info(morrow_users)")}


@pytest.mark.parametrize("password_not_null", [True, False], ids=["before-passkeys", "after-passkeys"])
def test_migration_keeps_every_email_bearing_account_and_makes_email_optional(tmp_path, password_not_null):
    from services import auth_issuer, recovery_codes

    conn = sqlite3.connect(str(tmp_path / "old.db"))
    password_column = "password_hash TEXT NOT NULL" if password_not_null else "password_hash TEXT"
    conn.execute(f"""CREATE TABLE morrow_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                    {password_column}, full_name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer', org_id TEXT NOT NULL DEFAULT 'org-alpha',
                    is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_login_at INTEGER)""")
    conn.execute("CREATE INDEX idx_pa_pq_users_org ON morrow_users (org_id)")
    conn.execute("INSERT INTO morrow_users VALUES ('u1','admin@acme.example',?,'Admin','admin','org-acme',1,100,200)",
                 (password_hash_of(PASSWORD),))
    conn.execute("INSERT INTO morrow_users VALUES ('u2','viewer@acme.example',?,'','viewer','org-acme',0,300,NULL)",
                 (password_hash_of(PASSWORD),))
    conn.commit()

    auth_issuer.init_tables(conn)
    auth_issuer.init_tables(conn)  # idempotent
    columns = migrated_users(conn)
    assert columns["email"][0] == 0 and columns["password_hash"][0] == 0 and columns["email_recovery"] == (1, "1")
    assert conn.execute("SELECT id, email, full_name, role, org_id, is_active, created_at, last_login_at, email_recovery "
                        "FROM morrow_users ORDER BY id").fetchall() == [
        ("u1", "admin@acme.example", "Admin", "admin", "org-acme", 1, 100, 200, 1),
        ("u2", "viewer@acme.example", "", "viewer", "org-acme", 0, 300, None, 1)]
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_pa_pq_users_org'").fetchone()
    # Existing accounts keep their password sign-in and their emailed recovery.
    assert auth_issuer.verify_password_login(conn, "admin@acme.example", PASSWORD)["id"] == "u1"
    assert auth_issuer.email_recovery_enabled(conn, "u1") is True
    # Accounts without an email can now exist side by side; addresses stay unique.
    auth_issuer.create_passkey_user(conn, "u3", "", "Three")
    auth_issuer.create_passkey_user(conn, "u4", "", "Four")
    with pytest.raises(ValueError):
        auth_issuer.create_passkey_user(conn, "u5", "ADMIN@acme.example", "Dup")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO morrow_users (id, email, created_at) VALUES ('u6', 'viewer@acme.example', 1)")
    assert auth_issuer.get_user_by_id(conn, "u3")["email"] == "" and auth_issuer.get_user_by_email(conn, "") is None
    assert auth_issuer.email_recovery_enabled(conn, "u3") is False
    assert len(recovery_codes.generate(conn, "u3")) == 10
    conn.close()


def test_a_fresh_database_gets_the_new_schema(tmp_path):
    from services import auth_issuer

    conn = sqlite3.connect(str(tmp_path / "new.db"))
    auth_issuer.init_tables(conn)
    columns = migrated_users(conn)
    assert columns["email"][0] == 0 and columns["email_recovery"] == (1, "1")
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='morrow_recovery_codes'").fetchone()
    conn.close()


# ── Postgres ─────────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against a real Postgres")
def test_postgres_migration_and_recovery_codes(monkeypatch):
    import uuid

    import psycopg2

    from db_feature_store import PostgresConnectionShim
    from services import auth_issuer, recovery_codes

    monkeypatch.setattr(auth_issuer, "_SECRET", "postgres-recovery-code-test-secret")
    schema = "auth_" + uuid.uuid4().hex[:12]
    raw = psycopg2.connect(PG_DSN)
    try:
        cur = raw.cursor()
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(f'SET search_path TO "{schema}"')
        cur.execute("""CREATE TABLE morrow_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                       full_name TEXT, role TEXT NOT NULL DEFAULT 'viewer', org_id TEXT NOT NULL DEFAULT 'org-alpha',
                       is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_login_at INTEGER)""")
        cur.execute("INSERT INTO morrow_users (id, email, password_hash, full_name, role, org_id, is_active, created_at) "
                    "VALUES ('u1', 'admin@acme.example', %s, 'Admin', 'admin', 'org-acme', 1, 100)", (password_hash_of(PASSWORD),))
        raw.commit()
        db = PostgresConnectionShim(raw)
        auth_issuer.init_tables(db)
        auth_issuer.init_tables(db)
        cur.execute("SELECT column_name, is_nullable, column_default FROM information_schema.columns "
                    "WHERE table_schema=%s AND table_name='morrow_users'", (schema,))
        cols = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        assert cols["email"][0] == "YES" and cols["password_hash"][0] == "YES" and cols["email_recovery"][1] == "1"
        assert auth_issuer.email_recovery_enabled(db, "u1") is True
        auth_issuer.create_passkey_user(db, "u2", "", "Two")
        auth_issuer.create_passkey_user(db, "u3", "", "Three")
        assert auth_issuer.get_user_by_id(db, "u2")["email"] == ""
        codes = recovery_codes.generate(db, "u2")
        assert recovery_codes.redeem(db, codes[0]) == "u2"
        with pytest.raises(recovery_codes.RecoveryCodeError):
            recovery_codes.redeem(db, codes[0])
        recovery_codes.generate(db, "u2")
        with pytest.raises(recovery_codes.RecoveryCodeError):
            recovery_codes.redeem(db, codes[1])
        assert recovery_codes.status(db, "u2")["remaining"] == 10
    finally:
        raw.rollback()
        cur = raw.cursor()
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        raw.commit()
        raw.close()
