"""Sign in with SOQLAB (services/soqlab_id.py) against a fake id.soqlab.com.

The fake issuer holds a real ES256 signing key made here, publishes it as a JWKS, verifies Morrow's
ES256 link tickets with the public half of Morrow's link key, checks PKCE and client_secret_basic at
/token, and hands out single-use codes, exactly as the contract in the soqlab-id README says. No
network: services.soqlab_id.fetch is swapped for the fake.
"""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from test_invite_landing import PASSWORD, api_fixture  # noqa: F401  (registers the "api" fixture)
from test_passkeys import bearer, mail_fixture, password_account  # noqa: F401  (registers "mail")

from test_signup import hosted_fixture  # noqa: F401  (registers "hosted")

from services import soqlab_id

ISSUER = "https://id.soqlab.test"
CLIENT_ID = "morrow"
CLIENT_SECRET = "s3cret-for-tests-only"
ORIGIN = "https://app.example"
REDIRECT = ORIGIN + "/auth/soqlab/callback"


def _pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


class FakeIssuer:
    def __init__(self):
        self.signing = ec.generate_private_key(ec.SECP256R1())
        self.link_key = ec.generate_private_key(ec.SECP256R1())   # Morrow's; the issuer keeps only the public half
        self.codes = {}
        self.unlinked = []
        self.tamper = {}
        self.alg = "ES256"
        self.discovery_override = {}
        self.used_jtis = set()

    # -- what the browser does at the issuer --
    def _code(self, sub, nonce, challenge, link_ticket=None):
        code = secrets.token_urlsafe(24)
        self.codes[code] = {"sub": sub, "nonce": nonce, "challenge": challenge, "link_ticket": link_ticket, "used": False}
        return code

    def authorize(self, url, sub):
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert url.startswith(ISSUER + "/authorize?")
        assert q["client_id"] == CLIENT_ID and q["redirect_uri"] == REDIRECT and q["code_challenge_method"] == "S256"
        assert q["response_type"] == "code" and "openid" in q["scope"] and "prompt" not in q
        return self._code(sub, q["nonce"], q["code_challenge"]), q["state"]

    def link(self, url, sub):
        assert url.startswith(ISSUER + "/link?ticket=")
        ticket = parse_qs(urlparse(url).query)["ticket"][0]
        assert jwt.get_unverified_header(ticket)["alg"] == "ES256"
        claims = jwt.decode(ticket, self.link_key.public_key(), algorithms=["ES256"], audience=ISSUER, issuer=CLIENT_ID)
        assert claims["exp"] - claims["iat"] <= 300 and 16 <= len(claims["jti"]) <= 128
        assert claims["redirect_uri"] == REDIRECT
        assert claims["jti"] not in self.used_jtis
        self.used_jtis.add(claims["jti"])
        self.last_ticket = claims
        return self._code(sub, claims.get("nonce"), claims["code_challenge"], link_ticket=claims["jti"]), claims["state"]

    # -- what Morrow's server fetches --
    def __call__(self, method, url, *, data=None, headers=None):
        if url == ISSUER + "/.well-known/openid-configuration":
            return 200, {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
                         "token_endpoint": ISSUER + "/token", "jwks_uri": ISSUER + "/jwks", **self.discovery_override}
        if url == ISSUER + "/jwks":
            jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.signing.public_key()))
            return 200, {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "ES256"}]}
        expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if url == ISSUER + "/unlink":
            assert headers["Authorization"] == expected
            self.unlinked.append(data["sub"])
            return 200, {"unlinked": True}
        assert url == ISSUER + "/token" and method == "POST"
        if headers.get("Authorization") != expected:
            return 401, {"error": "invalid_client"}
        entry = self.codes.get(data["code"])
        if not entry or entry["used"] or data["redirect_uri"] != REDIRECT:
            return 400, {"error": "invalid_grant"}
        entry["used"] = True
        if base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).rstrip(b"=").decode() != entry["challenge"]:
            return 400, {"error": "invalid_grant"}
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": entry["sub"], "aud": CLIENT_ID, "azp": CLIENT_ID, "iat": now, "exp": now + 300,
                  "auth_time": now, "amr": ["passkey"]}
        if entry["nonce"] is not None:
            claims["nonce"] = entry["nonce"]
        if entry["link_ticket"]:
            claims["link_ticket"] = entry["link_ticket"]
        claims.update(self.tamper)
        claims = {k: v for k, v in claims.items() if v is not None}
        if self.alg == "HS256":
            token = jwt.encode(claims, "x" * 32, algorithm="HS256", headers={"kid": "k1"})
        else:
            token = jwt.encode(claims, self.signing, algorithm="ES256", headers={"kid": "k1"})
        return 200, {"id_token": token, "token_type": "Bearer", "access_token": "x", "expires_in": 300}


@pytest.fixture
def fake(api, mail, monkeypatch):
    issuer = FakeIssuer()
    monkeypatch.setenv("MORROW_SOQLAB_ID_ISSUER", ISSUER)
    monkeypatch.setenv("MORROW_SOQLAB_ID_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MORROW_SOQLAB_ID_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("MORROW_SOQLAB_ID_LINK_KEY", _pem(issuer.link_key).replace("\n", "\\n"))
    monkeypatch.delenv("MORROW_PASSKEY_SIGNUP", raising=False)
    monkeypatch.setattr(soqlab_id, "fetch", issuer)
    soqlab_id.reset_cache()
    yield issuer
    soqlab_id.reset_cache()


def come_back(client, start_body, sub, fake, *, via="authorize", headers=None, tamper_query=None, **finish):
    """Start a round trip, go through the fake issuer, come back. -> the POST /auth/soqlab/callback response."""
    started = client.post("/auth/soqlab/start", json=start_body, headers=headers or {})
    assert started.status_code == 200, started.text
    url = started.json()["authorize_url"]
    code, state = (fake.link if via == "link" else fake.authorize)(url, sub)
    query = {"code": code, "state": state, "iss": ISSUER, **(tamper_query or {})}
    back = client.get("/auth/soqlab/callback", params={k: v for k, v in query.items() if v is not None}, follow_redirects=False)
    assert back.status_code == 303
    loc = urlparse(back.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    body = {"code": q.get("soqlab_code", ""), "state": q["soqlab_state"], "iss": q.get("soqlab_iss", ""),
            "flow": started.json()["flow"], **finish}
    res = client.post("/auth/soqlab/callback", json=body, headers=headers or {})
    res.sent = body
    res.path = loc.path
    return res


def signed_in(client, app, email="user@acme.example"):
    password_account(app, email=email)
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    return login.json()


def link(client, app, fake, sub="pairwise-sub-1", email="user@acme.example"):
    session = signed_in(client, app, email)
    res = come_back(client, {"purpose": "link"}, sub, fake, via="link", headers=bearer(session["access_token"]))
    assert res.status_code == 200, res.text
    return session


# ── switched off ────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("missing", ["MORROW_SOQLAB_ID_ISSUER", "MORROW_SOQLAB_ID_CLIENT_ID",
                                     "MORROW_SOQLAB_ID_CLIENT_SECRET", "MORROW_SOQLAB_ID_LINK_KEY", "MORROW_PUBLIC_BASE_URL"])
def test_flag_off_routes_404_and_ui_hidden(fake, api, monkeypatch, missing):
    client, _ = api
    monkeypatch.delenv(missing)
    assert client.get("/auth/config").json()["soqlab_id_enabled"] is False
    assert client.post("/auth/soqlab/start", json={"purpose": "login"}).status_code == 404
    assert client.get("/auth/soqlab/callback?code=a&state=b", follow_redirects=False).status_code == 404
    assert client.post("/auth/soqlab/callback", json={"code": "a", "state": "b" * 20, "flow": "c" * 20}).status_code == 404
    assert client.get("/auth/soqlab/link", headers=bearer("x")).status_code in {401, 404}


def test_flag_off_with_bad_settings(fake, monkeypatch, api):
    client, _ = api
    for issuer in ("http://id.soqlab.test", "https://id.soqlab.test/path", "ftp://id.soqlab.test"):
        monkeypatch.setenv("MORROW_SOQLAB_ID_ISSUER", issuer)
        assert client.get("/auth/config").json()["soqlab_id_enabled"] is False
    monkeypatch.setenv("MORROW_SOQLAB_ID_ISSUER", ISSUER)
    monkeypatch.setenv("MORROW_SOQLAB_ID_LINK_KEY", "not a key")
    assert client.get("/auth/config").json()["soqlab_id_enabled"] is False
    monkeypatch.setenv("MORROW_SOQLAB_ID_LINK_KEY", _pem(ec.generate_private_key(ec.SECP384R1())))
    assert client.get("/auth/config").json()["soqlab_id_enabled"] is False


def test_on_when_configured(fake, api):
    client, _ = api
    assert client.get("/auth/config").json()["soqlab_id_enabled"] is True


# ── link, sign in, unlink ───────────────────────────────────────────────────────────────────────

def test_link_then_sign_in_then_unlink(fake, api):
    client, app = api
    session = link(client, app, fake)
    assert fake.last_ticket["sub"] == session["user"]["id"] and fake.last_ticket["iss"] == CLIENT_ID
    status = client.get("/auth/soqlab/link", headers=bearer(session["access_token"])).json()
    assert status["linked"] is True and "sub" not in status

    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake)
    assert res.status_code == 200, res.text
    assert res.json()["user"]["id"] == session["user"]["id"] and res.json()["refresh_token"]
    assert res.path == "/ui/"
    me = client.get("/auth/me", headers=bearer(res.json()["access_token"]))
    assert me.status_code == 200

    gone = client.delete("/auth/soqlab/link", headers=bearer(session["access_token"]))
    assert gone.status_code == 200 and gone.json()["forgotten_by_soqlab"] is True
    assert fake.unlinked == ["pairwise-sub-1"]
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake)
    assert res.status_code == 404


def test_unlinked_user_is_refused(fake, api):
    client, _ = api
    res = come_back(client, {"purpose": "login"}, "nobody-here", fake)
    assert res.status_code == 404 and "No Morrow account" in res.json()["detail"]


def test_link_needs_recent_sign_in(fake, api, monkeypatch):
    client, app = api
    session = signed_in(client, app)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3600)
    res = client.post("/auth/soqlab/start", json={"purpose": "link"}, headers=bearer(session["access_token"]))
    assert res.status_code == 401


def test_link_needs_the_same_account_on_return(fake, api):
    client, app = api
    first = signed_in(client, app, "a@acme.example")
    second = signed_in(client, app, "b@acme.example")
    started = client.post("/auth/soqlab/start", json={"purpose": "link"}, headers=bearer(first["access_token"]))
    code, state = fake.link(started.json()["authorize_url"], "sub-x")
    res = client.post("/auth/soqlab/callback", json={"code": code, "state": state, "iss": ISSUER, "flow": started.json()["flow"]},
                      headers=bearer(second["access_token"]))
    assert res.status_code == 403


def test_sub_linked_elsewhere_is_refused(fake, api):
    client, app = api
    link(client, app, fake, sub="same", email="a@acme.example")
    other = signed_in(client, app, "b@acme.example")
    res = come_back(client, {"purpose": "link"}, "same", fake, via="link", headers=bearer(other["access_token"]))
    assert res.status_code == 409


def test_unlink_refused_when_it_is_the_only_way_in(fake, hosted):
    client, _ = hosted
    res = come_back(client, {"purpose": "signup", "full_name": "Ada"}, "sub-signup", fake, via="link")
    assert res.status_code == 200, res.text
    assert client.delete("/auth/soqlab/link", headers=bearer(res.json()["access_token"])).status_code == 409


# ── sign-up and recovery ────────────────────────────────────────────────────────────────────────

def test_signup_creates_a_linked_account_with_recovery_codes(fake, hosted):
    client, _ = hosted
    res = come_back(client, {"purpose": "signup", "full_name": "Ada", "organization": "Engines", "return_to": "signup"},
                    "sub-new", fake, via="link")
    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body["recovery_codes"]) == 10 and body["organization"]["name"]
    assert body["user"]["id"] == fake.last_ticket["sub"] and body["user"]["role"] == "admin"
    assert res.path == "/signup"
    again = come_back(client, {"purpose": "login"}, "sub-new", fake)
    assert again.status_code == 200 and again.json()["user"]["id"] == body["user"]["id"]


def test_recovery_code_ends_in_a_soqlab_passkey(fake, api):
    client, app = api
    session = signed_in(client, app)
    codes = client.post("/auth/recovery-codes", json={}, headers=bearer(session["access_token"]))
    assert codes.status_code == 200, codes.text
    ticket = client.post("/auth/recovery-codes/redeem", json={"code": codes.json()["codes"][0]}).json()["recovery_token"]
    res = come_back(client, {"purpose": "recover", "token": ticket}, "sub-rec", fake, via="link", token=ticket)
    assert res.status_code == 200, res.text
    assert res.json()["user"]["id"] == session["user"]["id"]
    # the old session can't be refreshed, and the ticket is used up
    assert client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
    assert client.post("/auth/soqlab/start", json={"purpose": "recover", "token": ticket}).status_code in {400, 404, 410}


# ── refusals ────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tamper,word", [
    ({"aud": "qlab"}, "different site"),
    ({"nonce": "someone-elses"}, "different sign-in"),
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 4000}, "expired"),
    ({"iss": "https://evil.example"}, "check out"),
    ({"amr": ["pwd"]}, "passkey"),
    ({"link_ticket": "x" * 32}, "link"),
])
def test_bad_id_tokens_are_refused(fake, api, tamper, word):
    client, app = api
    link(client, app, fake)
    fake.tamper = tamper
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake)
    assert res.status_code == 401 and word in res.json()["detail"]


def test_wrong_link_ticket_is_refused(fake, api):
    client, app = api
    session = signed_in(client, app)
    fake.tamper = {"link_ticket": "y" * 32}
    res = come_back(client, {"purpose": "link"}, "s", fake, via="link", headers=bearer(session["access_token"]))
    assert res.status_code == 401


def test_other_algorithms_are_refused(fake, api):
    client, app = api
    link(client, app, fake)
    fake.alg = "HS256"
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake)
    assert res.status_code == 401


@pytest.mark.parametrize("iss", [None, "https://evil.example"])
def test_redirect_must_carry_the_issuer(fake, api, iss):
    client, app = api
    link(client, app, fake)
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake, tamper_query={"iss": iss})
    assert res.status_code == 400


def test_replayed_callback_and_code_are_refused(fake, api):
    client, app = api
    link(client, app, fake)
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake)
    assert res.status_code == 200
    again = client.post("/auth/soqlab/callback", json=res.sent)
    assert again.status_code == 400 and "already used" in again.json()["detail"]
    # The same code with a fresh round trip: the issuer refuses it (codes work once).
    started = client.post("/auth/soqlab/start", json={"purpose": "login"}).json()
    state = parse_qs(urlparse(started["authorize_url"]).query)["state"][0]
    third = client.post("/auth/soqlab/callback", json={**res.sent, "state": state, "flow": started["flow"]})
    assert third.status_code == 401


def test_replayed_link_ticket_round_trip_is_refused(fake, api):
    client, app = api
    session = signed_in(client, app)
    res = come_back(client, {"purpose": "link"}, "s1", fake, via="link", headers=bearer(session["access_token"]))
    assert res.status_code == 200
    assert client.post("/auth/soqlab/callback", json=res.sent, headers=bearer(session["access_token"])).status_code == 400


def test_another_tab_cannot_finish(fake, api):
    client, app = api
    link(client, app, fake)
    res = come_back(client, {"purpose": "login"}, "pairwise-sub-1", fake, flow="z" * 43)
    assert res.status_code == 400 and "different browser tab" in res.json()["detail"]


def test_discovery_pointing_elsewhere_is_refused(fake, api):
    client, _ = api
    fake.discovery_override = {"token_endpoint": "http://169.254.169.254/latest"}
    assert client.post("/auth/soqlab/start", json={"purpose": "login"}).status_code == 502


def test_cancel_at_the_issuer_comes_back_with_an_error(fake, api):
    client, _ = api
    started = client.post("/auth/soqlab/start", json={"purpose": "login", "return_to": "signup"}).json()
    state = parse_qs(urlparse(started["authorize_url"]).query)["state"][0]
    back = client.get("/auth/soqlab/callback", params={"error": "interaction_required", "error_description": "not_linked",
                                                       "state": state, "iss": ISSUER}, follow_redirects=False)
    assert back.status_code == 303 and back.headers["location"].startswith("/signup?")
    assert "soqlab_error=interaction_required" in back.headers["location"]
