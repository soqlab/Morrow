"""Passkeys: WebAuthn registration and sign-in, the move off passwords, MORROW_PASSKEYS_ONLY, recovery.

Runs the real ASGI stack (the fixture from test_invite_landing) against SoftAuthenticator, a
software authenticator that builds real WebAuthn responses: CBOR attestation objects with an
EC P-256 COSE key, authenticator data with the RP ID hash, flags and counter, and ES256 signatures
over authenticatorData || SHA-256(clientDataJSON). py_webauthn verifies them exactly as it
verifies a browser's. Mail is captured, never sent.
"""

import base64
import hashlib
import json
import os
import re
import sqlite3
import time

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from test_invite_landing import PASSWORD, api_fixture, invite, make_org  # noqa: F401  (api_fixture registers the "api" fixture)

ORIGIN = "https://app.example"
RP_ID = "app.example"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftAuthenticator:
    """A platform authenticator in software. Holds discoverable credentials, verifies the user."""

    UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40

    def __init__(self, origin=ORIGIN, synced=False):
        self.origin = origin
        self.synced = synced
        self.credentials = {}  # credential id (bytes) -> {"key", "user_handle", "rp_id", "count"}

    def _client_data(self, kind, challenge):
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": False}).encode()

    def create(self, options):
        rp_id = options["rp"]["id"]
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        cred_id = os.urandom(16)
        flags = self.UP | self.UV | self.AT | ((self.BE | self.BS) if self.synced else 0)
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
                     + bytes(16) + len(cred_id).to_bytes(2, "big") + cred_id + cose)
        self.credentials[cred_id] = {"key": key, "user_handle": unb64(options["user"]["id"]), "rp_id": rp_id, "count": 0}
        client_data = self._client_data("webauthn.create", options["challenge"])
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key", "clientExtensionResults": {},
                "authenticatorAttachment": "platform",
                "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation),
                             "transports": ["internal", "hybrid"]}}

    def get(self, options, credential_id=None, count=None, verify_user=True):
        allowed = [unb64(c["id"]) for c in options.get("allowCredentials") or []]
        if credential_id is not None:
            cred_id = credential_id
        elif allowed:
            cred_id = next(c for c in allowed if c in self.credentials)
        else:
            cred_id = next(iter(self.credentials))  # discoverable: the authenticator offers its own
        cred = self.credentials[cred_id]
        cred["count"] = cred["count"] + 1 if count is None else count
        flags = self.UP | (self.UV if verify_user else 0)
        auth_data = hashlib.sha256(options["rpId"].encode()).digest() + bytes([flags]) + cred["count"].to_bytes(4, "big")
        client_data = self._client_data("webauthn.get", options["challenge"])
        signature = cred["key"].sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64(client_data), "authenticatorData": b64(auth_data),
                             "signature": b64(signature), "userHandle": b64(cred["user_handle"])}}


class InlineThread:
    def __init__(self, target=None, **kwargs):
        self.target = target

    def start(self):
        self.target()


# Registered as "mail" but defined as mail_fixture so test_team_join can import it (see api_fixture).
@pytest.fixture(name="mail")
def mail_fixture(api, monkeypatch):
    client, app = api
    from types import SimpleNamespace

    from services import platform_mail

    sent = []
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", ORIGIN)
    monkeypatch.delenv("MORROW_PASSKEYS_ONLY", raising=False)
    monkeypatch.delenv("MORROW_WEBAUTHN_RP_ID", raising=False)
    monkeypatch.delenv("MORROW_WEBAUTHN_ORIGINS", raising=False)
    monkeypatch.setattr(platform_mail, "configured", lambda: True)
    monkeypatch.setattr(platform_mail, "send_text", lambda to, subject, body, timeout=20.0: sent.append((to, subject, body)) or {"ok": True})
    monkeypatch.setattr(app, "threading", SimpleNamespace(Thread=InlineThread))
    return sent


def bearer(token):
    return {"Authorization": "Bearer " + token}


def password_account(app, email="user@acme.example", org="org-acme", role="viewer"):
    with app._db() as db:
        return app._issuer_create_user(db, email, PASSWORD, "", role, org)


def register(client, authn, kind, token="", headers=None, **finish):
    begin = client.post("/auth/passkey/register/begin", json={"kind": kind, "token": token}, headers=headers or {})
    assert begin.status_code == 200, begin.text
    options = begin.json()["options"]
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["rp"]["id"] == RP_ID
    credential = authn.create(options)
    return client.post("/auth/passkey/register/finish", headers=headers or {},
                       json={"challenge_id": begin.json()["challenge_id"], "credential": credential, "token": token, **finish})


def passkey_login(client, authn, email="", **get):
    begin = client.post("/auth/passkey/login/begin", json={"email": email})
    assert begin.status_code == 200, begin.text
    body = begin.json()
    assert body["options"]["userVerification"] == "required"
    credential = authn.get(body["options"], **get)
    res = client.post("/auth/passkey/login/finish", json={"challenge_id": body["challenge_id"], "credential": credential})
    return res, body, credential


def password_hash(app, email):
    with app._db() as db:
        return db.execute("SELECT password_hash FROM morrow_users WHERE email=?", (email,)).fetchone()[0]


def events(event_type):
    from services import security_journal
    return security_journal.auth_events(event_type=event_type)


# ── configuration ─────────────────────────────────────────────────────────────────────────────

def test_passkeys_are_offered_only_with_a_configured_origin(api, monkeypatch):
    client, _ = api
    monkeypatch.delenv("MORROW_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("MORROW_WEBAUTHN_RP_ID", raising=False)
    monkeypatch.delenv("MORROW_WEBAUTHN_ORIGINS", raising=False)
    monkeypatch.setenv("MORROW_PASSKEYS_ONLY", "1")
    cfg = client.get("/auth/config").json()
    # Without a relying party the flag would lock everyone out, so it does nothing.
    assert cfg["passkeys_enabled"] is False and cfg["passkeys_only"] is False
    assert client.post("/auth/passkey/login/begin", json={}).status_code == 404
    # The RP ID never comes from the Host header.
    assert client.post("/auth/passkey/login/begin", json={}, headers={"host": "evil.example"}).status_code in {400, 404}

    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", ORIGIN)
    cfg = client.get("/auth/config").json()
    assert cfg["passkeys_enabled"] is True and cfg["passkeys_only"] is True


# ── invitation → passkey account → passkey sign-in ────────────────────────────────────────────

def test_invite_creates_passkey_account_without_password_and_signs_in(api, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    token = invite(client, "org-acme", "First@Acme.example", "org_admin")["invitation"]["token"]
    authn = SoftAuthenticator(synced=True)

    res = register(client, authn, "invite", token, name="Ada's laptop")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["user"]["email"] == "first@acme.example" and body["user"]["org_id"] == "org-acme"
    assert body["passkey"]["name"] == "Ada's laptop" and body["passkey"]["backed_up"] is True
    assert password_hash(app, "first@acme.example") is None
    me = client.get("/auth/me", headers=bearer(body["access_token"])).json()
    assert me["has_password"] is False and me["passkey_count"] == 1 and me["org_id"] == "org-acme"
    # The invitation is used up.
    assert client.post("/auth/invite/preview", json={"token": token}).json()["status"] == "used"

    # Discoverable sign-in: no email, the authenticator offers the passkey.
    res, begin, _ = passkey_login(client, authn)
    assert begin["options"].get("allowCredentials") in (None, [])
    assert res.status_code == 200, res.text
    assert res.json()["user"]["email"] == "first@acme.example" and res.json()["refresh_token"]
    assert [e["login_method"] for e in events("login.success")][-1] == "passkey"
    # There is no password to sign in with.
    assert client.post("/auth/login", json={"email": "first@acme.example", "password": PASSWORD}).status_code == 401


def test_challenge_is_single_use_and_expires(api, mail, monkeypatch):
    client, app = api
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    assert register(client, authn, "invite", invite(client, "org-acme", "a@acme.example")["invitation"]["token"]).status_code == 200

    res, begin, credential = passkey_login(client, authn)
    assert res.status_code == 200
    replay = client.post("/auth/passkey/login/finish", json={"challenge_id": begin["challenge_id"], "credential": credential})
    assert replay.status_code == 400

    begin = client.post("/auth/passkey/login/begin", json={}).json()
    credential = authn.get(begin["options"])
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3600)
    late = client.post("/auth/passkey/login/finish", json={"challenge_id": begin["challenge_id"], "credential": credential})
    assert late.status_code == 400


def test_email_fallback_lists_credentials_and_unknown_addresses_look_the_same(api, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    assert register(client, authn, "invite", invite(client, "org-acme", "b@acme.example")["invitation"]["token"]).status_code == 200
    res, begin, _ = passkey_login(client, authn, email="B@acme.example")
    assert res.status_code == 200
    assert [unb64(c["id"]) for c in begin["options"]["allowCredentials"]] == list(authn.credentials)

    unknown = client.post("/auth/passkey/login/begin", json={"email": "nobody@acme.example"}).json()
    again = client.post("/auth/passkey/login/begin", json={"email": "nobody@acme.example"}).json()
    assert len(unknown["options"]["allowCredentials"]) == 1
    assert unknown["options"]["allowCredentials"] == again["options"]["allowCredentials"]


def test_assertion_without_user_verification_wrong_origin_or_bad_signature_is_refused(api, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    assert register(client, authn, "invite", invite(client, "org-acme", "c@acme.example")["invitation"]["token"]).status_code == 200
    res, _, _ = passkey_login(client, authn, verify_user=False)
    assert res.status_code == 401

    phish = SoftAuthenticator(origin="https://app.example.evil.test")
    phish.credentials = authn.credentials
    res, _, _ = passkey_login(client, phish)
    assert res.status_code == 401

    begin = client.post("/auth/passkey/login/begin", json={}).json()
    credential = authn.get(begin["options"])
    credential["response"]["signature"] = b64(b"\x30\x06\x02\x01\x01\x02\x01\x01")
    assert client.post("/auth/passkey/login/finish", json={"challenge_id": begin["challenge_id"], "credential": credential}).status_code == 401
    # The good one still works afterwards.
    assert passkey_login(client, authn)[0].status_code == 200


def test_registration_needs_user_verification_and_the_right_origin(api, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    token = invite(client, "org-acme", "d@acme.example")["invitation"]["token"]
    phish = SoftAuthenticator(origin="https://evil.example")
    assert register(client, phish, "invite", token).status_code == 400
    # Nothing was created and the invitation is still usable.
    with app._db() as db:
        assert db.execute("SELECT COUNT(*) FROM morrow_users WHERE email='d@acme.example'").fetchone()[0] == 0
    assert register(client, SoftAuthenticator(), "invite", token).status_code == 200


def test_counter_going_backwards_blocks_the_passkey(api, mail):
    client, app = api
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    assert register(client, authn, "invite", invite(client, "org-acme", "e@acme.example")["invitation"]["token"]).status_code == 200
    assert passkey_login(client, authn, count=5)[0].status_code == 200
    with app._db() as db:
        assert db.execute("SELECT sign_count FROM morrow_passkeys").fetchone()[0] == 5
    cloned, _, _ = passkey_login(client, authn, count=5)
    assert cloned.status_code == 401
    assert events("passkey.clone_suspected")
    # Blocked from then on, even with a higher count.
    assert passkey_login(client, authn, count=9)[0].status_code == 401
    with app._db() as db:
        assert db.execute("SELECT clone_suspected FROM morrow_passkeys").fetchone()[0] == 1


# ── existing password accounts ────────────────────────────────────────────────────────────────

def test_password_user_adds_passkey_and_loses_the_password(api, mail):
    client, app = api
    password_account(app)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["passkey_enrollment_required"] is True and login.json()["access_token"]

    authn = SoftAuthenticator()
    res = register(client, authn, "account", headers=bearer(login.json()["access_token"]))
    assert res.status_code == 200, res.text
    assert res.json()["password_removed"] is True
    assert password_hash(app, "user@acme.example") is None
    assert client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).status_code == 401
    assert passkey_login(client, authn)[0].status_code == 200
    assert events("passkey.registered")


def test_password_login_refused_for_an_account_that_has_a_passkey_even_if_a_hash_remains(api, mail):
    client, app = api
    user = password_account(app)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()
    assert register(client, SoftAuthenticator(), "account", headers=bearer(login["access_token"])).status_code == 200
    with app._db() as db:  # a hash put back by hand, or by an old code path
        db.execute("UPDATE morrow_users SET password_hash=? WHERE id=?", (password_hash_of(PASSWORD), user["id"]))
        db.commit()
    assert client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).status_code == 401


def password_hash_of(password):
    from services import auth_issuer
    return auth_issuer._hash_password(password)


def test_adding_a_second_passkey_needs_a_recent_sign_in(api, mail, monkeypatch):
    client, app = api
    password_account(app)
    # Signed in ten minutes ago (the token's iat); the token itself is still valid for hours.
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() - 600)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()
    monkeypatch.setattr(time, "time", real)
    authn = SoftAuthenticator()
    # The first passkey (moving off the password) doesn't need a fresh sign-in.
    assert register(client, authn, "account", headers=bearer(login["access_token"])).status_code == 200
    monkeypatch.setenv("MORROW_PASSKEY_REAUTH_SECONDS", "60")
    stale = client.post("/auth/passkey/register/begin", json={"kind": "account"}, headers=bearer(login["access_token"]))
    assert stale.status_code == 401
    fresh = passkey_login(client, authn)[0].json()
    assert register(client, SoftAuthenticator(), "account", headers=bearer(fresh["access_token"])).status_code == 200


def test_list_rename_and_remove_but_never_the_last(api, mail):
    client, app = api
    password_account(app)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()
    headers = bearer(login["access_token"])
    first, second = SoftAuthenticator(), SoftAuthenticator()
    assert register(client, first, "account", headers=headers).status_code == 200
    assert register(client, second, "account", headers=headers, name="Backup key").status_code == 200
    listed = client.get("/auth/passkeys", headers=headers).json()
    assert [p["name"] for p in listed["passkeys"]][1] == "Backup key" and listed["has_password"] is False
    pid = listed["passkeys"][0]["id"]
    renamed = client.patch(f"/auth/passkeys/{pid}", json={"name": "Work laptop"}, headers=headers)
    assert renamed.status_code == 200 and renamed.json()["passkeys"][0]["name"] == "Work laptop"
    assert client.delete(f"/auth/passkeys/{pid}", headers=headers).status_code == 200
    last = client.get("/auth/passkeys", headers=headers).json()["passkeys"][0]["id"]
    refused = client.delete(f"/auth/passkeys/{last}", headers=headers)
    assert refused.status_code == 409
    # Someone else's passkey is not found, not removed.
    other = password_account(app, "other@acme.example")
    assert other
    login2 = client.post("/auth/login", json={"email": "other@acme.example", "password": PASSWORD}).json()
    assert client.delete(f"/auth/passkeys/{last}", headers=bearer(login2["access_token"])).status_code == 404
    assert passkey_login(client, second)[0].status_code == 200
    assert passkey_login(client, first)[0].status_code == 401  # removed


# ── MORROW_PASSKEYS_ONLY=1 ────────────────────────────────────────────────────────────────────

def test_passkeys_only_turns_password_sign_in_into_enrollment(api, mail, monkeypatch):
    client, app = api
    monkeypatch.setenv("MORROW_PASSKEYS_ONLY", "1")
    password_account(app)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD})
    assert login.status_code == 200
    data = login.json()
    assert "access_token" not in data and "refresh_token" not in data
    assert data["passkey_enrollment_required"] is True
    ticket = data["enrollment_token"]
    # The ticket buys nothing but a passkey registration.
    assert client.get("/auth/me", headers=bearer(ticket)).status_code == 401

    authn = SoftAuthenticator()
    res = register(client, authn, "enroll", ticket)
    assert res.status_code == 200, res.text
    assert res.json()["access_token"] and res.json()["password_removed"] is True
    assert password_hash(app, "user@acme.example") is None
    # Single use.
    again = client.post("/auth/passkey/register/begin", json={"kind": "enroll", "token": ticket})
    assert again.status_code == 410
    assert client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).status_code == 401
    assert passkey_login(client, authn)[0].status_code == 200


def test_passkeys_only_refuses_every_new_password(api, mail, monkeypatch):
    client, app = api
    make_org(client, "org-acme", "Acme")
    admin = password_account(app, "admin@acme.example", role="admin")
    assert admin
    admin_login = client.post("/auth/login", json={"email": "admin@acme.example", "password": PASSWORD}).json()
    monkeypatch.setenv("MORROW_PASSKEYS_ONLY", "1")
    headers = bearer(admin_login["access_token"])
    created = client.post("/auth/register", headers=headers, json={"email": "new@acme.example", "password": "another-password-1234"})
    assert created.status_code == 403
    token = invite(client, "org-acme", "inv@acme.example")["invitation"]["token"]
    assert client.post("/auth/invite/register", json={"token": token, "password": "another-password-1234"}).status_code == 403
    assert client.post("/auth/change-password", headers=headers, json={"old_password": PASSWORD, "new_password": "another-password-1234"}).status_code == 403
    assert client.post("/auth/password-reset/confirm", json={"token": "x" * 43, "password": "another-password-1234"}).status_code == 403
    # The invitation still works, with a passkey.
    assert register(client, SoftAuthenticator(), "invite", token).status_code == 200


# ── account recovery ──────────────────────────────────────────────────────────────────────────

def recovery_token(body):
    match = re.search(r"https://app\.example/reset-password#recover=([A-Za-z0-9_-]+)", body)
    assert match, body
    return match.group(1)


def passkey_account(client, app, email="r@acme.example"):
    make_org(client, "org-acme", "Acme")
    authn = SoftAuthenticator()
    res = register(client, authn, "invite", invite(client, "org-acme", email)["invitation"]["token"])
    assert res.status_code == 200
    return authn, res.json()


def test_recovery_link_registers_a_new_passkey_once_and_can_revoke_the_others(api, mail):
    client, app = api
    lost, session = passkey_account(client, app)

    assert client.post("/auth/password-reset/request", json={"email": "R@acme.example"}).status_code == 200
    assert len(mail) == 1 and mail[0][1] == "Recover your Morrow account"
    token = recovery_token(mail[0][2])
    assert events("account_recovery.requested")

    replacement = SoftAuthenticator()
    res = register(client, replacement, "recover", token, revoke_other_passkeys=True)
    assert res.status_code == 200, res.text
    assert res.json()["other_passkeys_removed"] == 1 and res.json()["access_token"]
    # The lost device can't sign in; the old session can't be renewed; the new passkey works.
    assert passkey_login(client, lost)[0].status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
    assert passkey_login(client, replacement)[0].status_code == 200
    # Single use.
    assert client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": token}).status_code == 410
    assert events("account_recovery.completed")


def test_recovery_link_expires_and_a_newer_one_replaces_it(api, mail, monkeypatch):
    client, app = api
    passkey_account(client, app)
    client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    first = recovery_token(mail[-1][2])
    client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    second = recovery_token(mail[-1][2])
    assert client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": first}).status_code == 404
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 7200)
    assert client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": second}).status_code == 410


def test_recovery_token_cannot_finish_a_ceremony_started_with_another_link(api, mail):
    client, app = api
    passkey_account(client, app)
    password_account(app, "victim@acme.example")
    client.post("/auth/password-reset/request", json={"email": "r@acme.example"})
    mine = recovery_token(mail[-1][2])
    begin = client.post("/auth/passkey/register/begin", json={"kind": "recover", "token": mine}).json()
    credential = SoftAuthenticator().create(begin["options"])
    res = client.post("/auth/passkey/register/finish", json={"challenge_id": begin["challenge_id"], "credential": credential,
                                                             "token": "y" * 43})
    assert res.status_code == 400


def test_password_reset_stays_for_password_accounts_when_passkeys_are_optional(api, mail):
    client, app = api
    password_account(app)
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    assert "/reset-password#token=" in mail[-1][2]


def test_old_password_reset_link_cannot_give_a_passkey_account_a_password(api, mail):
    client, app = api
    password_account(app)
    client.post("/auth/password-reset/request", json={"email": "user@acme.example"})
    old_link = re.search(r"#token=([A-Za-z0-9_-]+)", mail[-1][2]).group(1)
    login = client.post("/auth/login", json={"email": "user@acme.example", "password": PASSWORD}).json()
    assert register(client, SoftAuthenticator(), "account", headers=bearer(login["access_token"])).status_code == 200
    res = client.post("/auth/password-reset/confirm", json={"token": old_link, "password": "brand-new-password-5512"})
    assert res.status_code == 409
    assert password_hash(app, "user@acme.example") is None


# ── the schema migration ──────────────────────────────────────────────────────────────────────

def test_migration_makes_password_nullable_and_keeps_rows_and_indexes(tmp_path):
    from services import auth_issuer

    conn = sqlite3.connect(str(tmp_path / "old.db"))
    conn.execute("""CREATE TABLE morrow_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    full_name TEXT, role TEXT NOT NULL DEFAULT 'viewer', org_id TEXT NOT NULL DEFAULT 'org-alpha',
                    is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_login_at INTEGER)""")
    conn.execute("CREATE INDEX idx_pa_pq_users_org ON morrow_users (org_id)")
    conn.execute("INSERT INTO morrow_users VALUES ('u1','old@acme.example',?, 'Old', 'admin', 'org-acme', 1, 100, 200)",
                 (password_hash_of(PASSWORD),))
    conn.commit()

    auth_issuer.init_tables(conn)
    auth_issuer.init_tables(conn)  # idempotent
    columns = {r[1]: r[3] for r in conn.execute("PRAGMA table_info(morrow_users)")}
    assert columns["password_hash"] == 0
    assert conn.execute("SELECT id, email, full_name, role, org_id, is_active, created_at, last_login_at FROM morrow_users").fetchall() == [
        ("u1", "old@acme.example", "Old", "admin", "org-acme", 1, 100, 200)]
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_pa_pq_users_org'").fetchone()
    # The existing password still signs in, and the account can now lose it.
    assert auth_issuer.verify_password_login(conn, "old@acme.example", PASSWORD)["id"] == "u1"
    assert auth_issuer.drop_password(conn, "u1") is True
    assert auth_issuer.verify_password_login(conn, "old@acme.example", PASSWORD) is None
    conn.close()
