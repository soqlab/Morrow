"""Operator SSO (OIDC + PKCE), cookie sessions with CSRF, TOTP MFA with step-up, and break-glass.

Runs the real ASGI stack against a throwaway SQLite database. The identity provider is fully mocked:
a local RSA key signs the ID tokens and the discovery document and JWKS are served by monkeypatching
services.operator_auth.http_get_json / http_post_form. No network.
"""

import base64
import hashlib
import json
import logging
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from services import auth_issuer, env_file
from services import operator_auth as oa
from services import platform_analytics as pa

SECRET = "sso-mfa-tests-jwt-signing-key-not-for-deployment-91"
LEGACY = "legacy-shared-platform-key-for-sso-tests-0123456789"
ALICE_KEY = "alice-named-operator-key-for-sso-tests-0123456789"
ISSUER = "https://idp.example.test"
CLIENT_ID = "pqc-admin-portal"
OWNER = "owner@corp.example"
OPS = "ops@corp.example"


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class FakeIdP:
    """Discovery, JWKS and a token endpoint that checks PKCE, all in memory."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = ""
        self.challenge = ""
        self.email = OWNER
        self.overrides = {}
        self.sign_with_other_key = False
        self.token_requests = []

    def jwks(self):
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="k1", use="sig", alg="RS256")
        return {"keys": [jwk]}

    def get_json(self, url):
        if url == ISSUER + "/.well-known/openid-configuration":
            return {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/jwks", "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"]}
        if url == ISSUER + "/jwks":
            return self.jwks()
        raise AssertionError(f"unexpected fetch {url}")

    def post_form(self, url, form, headers=None):
        assert url == ISSUER + "/token"
        self.token_requests.append(dict(form))
        if form.get("grant_type") != "authorization_code" or form.get("code") != "auth-code-1":
            return {"error": "invalid_grant"}
        # PKCE: the verifier must hash to the challenge sent on the authorization request.
        if _b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != self.challenge:
            return {"error": "invalid_grant"}
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "idp-subject-" + self.email, "email": self.email,
                  "email_verified": True, "nonce": self.nonce, "iat": now, "exp": now + 300}
        claims.update(self.overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        key = self.other_key if self.sign_with_other_key else self.key
        return {"id_token": jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"}), "token_type": "Bearer"}


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "sso.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("PQC_ENVIRONMENT", "local")
    monkeypatch.setenv("PQC_PLATFORM_OPERATORS", json.dumps([{"name": "alice", "role": "owner", "key_sha256": _sha(ALICE_KEY)}]))
    monkeypatch.setenv("PQC_ADMIN_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("PQC_ADMIN_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("PQC_ADMIN_OIDC_CLIENT_SECRET", "client-secret-for-tests")
    monkeypatch.setenv("PQC_ADMIN_OIDC_REDIRECT_URI", "https://testserver/vendor-admin/sso/callback")
    monkeypatch.setenv("PQC_ADMIN_OIDC_ALLOWED_DOMAINS", "corp.example")
    monkeypatch.setenv("PQC_ADMIN_OPERATOR_ROLES", f"{OWNER}=owner,{OPS}=operator")
    for name in ("PQC_ADMIN_REQUIRE_MFA", "PQC_ALLOW_BREAK_GLASS_KEY", "PQC_PLATFORM_ADMIN_KEY_ROLE",
                 "PQC_ADMIN_SESSION_IDLE_SECONDS", "PQC_ADMIN_SESSION_ABSOLUTE_SECONDS", "PQC_ADMIN_STEP_UP_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_ISSUER_ENABLED": True, "AUTH_JWT_ALGORITHMS": ["HS256"],
        "AUTH_JWT_SECRET": SECRET, "AUTH_JWT_ISSUER": "pqc-scanner", "AUTH_JWT_AUDIENCE": "pqc-scanner",
        "_PLATFORM_ADMIN_KEY": LEGACY, "API_KEY": "", "PRODUCTION_ENVIRONMENT": False, "RATE_LIMIT_MAX_REQUESTS": 100000,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(auth_issuer, "_SECRET", SECRET)
    monkeypatch.setattr(app.limiter, "enabled", False)
    idp = FakeIdP()
    monkeypatch.setattr(oa, "http_get_json", idp.get_json)
    monkeypatch.setattr(oa, "http_post_form", idp.post_form)
    oa.clear_caches()
    pa.clear_cache()
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    client = TestClient(app.app, base_url="https://testserver", client=("192.0.2.30", 40000))
    yield client, app, idp
    client.close()
    oa.clear_caches()


def legacy(role="owner"):
    return {"x-platform-key": LEGACY, "x-platform-admin-role": role}


def start(client, idp):
    res = client.get("/vendor-admin/sso/start", follow_redirects=False)
    assert res.status_code == 302, res.text
    query = parse_qs(urlparse(res.headers["location"]).query)
    idp.nonce, idp.challenge = query["nonce"][0], query["code_challenge"][0]
    return res, query


def sso_login(client, idp, email=OWNER, **overrides):
    idp.email, idp.overrides = email, overrides
    _, query = start(client, idp)
    return client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]},
                      follow_redirects=False)


def sso_error(res):
    assert res.status_code == 303, res.text
    return parse_qs(urlparse(res.headers["location"]).query).get("sso_error", [""])[0]


def session_state(client_or_raw):
    raw = client_or_raw if isinstance(client_or_raw, str) else client_or_raw.cookies.get(oa.SESSION_COOKIE)
    return oa.load_session(raw, touch=False)[1]


def whoami(client):
    return client.get("/platform/whoami")


def csrf(client):
    res = whoami(client)
    assert res.status_code == 200, res.text
    return {"x-csrf-token": res.json()["csrf_token"]}


def session_row(app):
    with app._db() as conn:
        return dict(conn.execute("SELECT * FROM platform_operator_sessions ORDER BY created_at DESC LIMIT 1").fetchone())


def set_session(app, **fields):
    with app._db() as conn:
        assignments = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE platform_operator_sessions SET {assignments}", tuple(fields.values()))
        conn.commit()
    oa.clear_caches()


def events(app, action):
    app._ensure_platform_admin_schema()
    with app._db() as conn:
        rows = conn.execute("SELECT actor_id, reason, details_json FROM platform_admin_events WHERE action = ?", (action,)).fetchall()
    return [{"actor_id": r[0], "reason": r[1], "details": json.loads(r[2] or "{}")} for r in rows]


def enrol(client, headers=None):
    headers = dict(headers or {})
    res = client.post("/platform/mfa/enroll/start", headers=headers)
    assert res.status_code == 200, res.text
    body = res.json()
    secret = oa.decode_base32_secret(body["secret"])
    res = client.post("/platform/mfa/enroll/confirm", headers=headers, json={"code": oa.totp(secret, time.time())})
    assert res.status_code == 200, res.text
    return secret, body, res.json()["recovery_codes"]


# ── OIDC: state, nonce, PKCE, token claims, roster ───────────────────────────


def test_sso_sign_in_uses_pkce_and_issues_a_strict_httponly_session(api):
    client, app, idp = api
    res, query = start(client, idp)
    assert query["code_challenge_method"] == ["S256"] and query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID] and "openid" in query["scope"][0]
    state_cookie = res.headers["set-cookie"]
    assert "HttpOnly" in state_cookie and "Path=/vendor-admin/sso" in state_cookie

    res = client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    assert res.status_code == 303 and res.headers["location"] == "/vendor-admin/#/dashboard"
    verifier = idp.token_requests[-1]["code_verifier"]
    assert _b64url(hashlib.sha256(verifier.encode()).digest()) == query["code_challenge"][0]
    cookies = {c.split("=", 1)[0]: c for c in res.headers.get_list("set-cookie")}
    session = cookies[oa.SESSION_COOKIE]
    assert "HttpOnly" in session and "Secure" in session and "SameSite=strict" in session and "Path=/" in session
    assert "Max-Age=28800" in session
    assert "HttpOnly" not in cookies[oa.CSRF_COOKIE] and "SameSite=strict" in cookies[oa.CSRF_COOKIE]
    raw = client.cookies.get(oa.SESSION_COOKIE)
    assert session_row(app)["id_hash"] == _sha(raw)  # only a hash of the session id is stored

    body = whoami(client).json()
    assert body["auth_method"] == "sso" and body["operator"] == OWNER and body["email"] == OWNER
    assert body["role"] == "owner" and body["csrf_token"] == client.cookies.get(oa.CSRF_COOKIE)
    assert body["session"]["expires_at"] and body["mfa"]["enrolled"] is False
    assert events(app, "platform.operator_signed_in")[0]["actor_id"] == OWNER


def test_session_cookie_is_not_secure_on_localhost(api):
    _, app, idp = api
    local = TestClient(app.app, base_url="http://127.0.0.1:8012")
    local.cookies.clear()
    idp.email = OWNER
    res = local.get("/vendor-admin/sso/start", follow_redirects=False)
    query = parse_qs(urlparse(res.headers["location"]).query)
    idp.nonce, idp.challenge = query["nonce"][0], query["code_challenge"][0]
    res = local.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    session = [c for c in res.headers.get_list("set-cookie") if c.startswith(oa.SESSION_COOKIE + "=")][0]
    assert "Secure" not in session and "HttpOnly" in session
    local.close()


def test_state_must_match_the_browser_and_is_single_use(api):
    client, app, idp = api
    _, query = start(client, idp)
    assert sso_error(client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": "forged"},
                                follow_redirects=False)) == "sso_state_mismatch"
    # A fresh browser without the state cookie cannot complete someone else's sign-in.
    other = TestClient(app.app, base_url="https://testserver")
    assert sso_error(other.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]},
                               follow_redirects=False)) == "sso_state_mismatch"
    other.close()
    ok = client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    assert ok.headers["location"] == "/vendor-admin/#/dashboard"
    client.cookies.set(oa.SSO_STATE_COOKIE, query["state"][0], domain="testserver.local", path="/vendor-admin/sso")
    replay = client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    assert sso_error(replay) in {"sso_state_unknown", "sso_state_mismatch"}


def test_expired_state_is_rejected(api):
    client, app, idp = api
    _, query = start(client, idp)
    with app._db() as conn:
        conn.execute("UPDATE platform_oidc_states SET expires_at = ?", (time.time() - 1,))
        conn.commit()
    res = client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    assert sso_error(res) == "sso_state_expired"


@pytest.mark.parametrize("overrides, code", [
    ({"nonce": "not-the-nonce"}, "sso_nonce_mismatch"),
    ({"aud": "some-other-client"}, "sso_token_audience"),
    ({"iss": "https://evil.example.test"}, "sso_token_issuer"),
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, "sso_token_expired"),
    ({"email_verified": False}, "sso_email_unverified"),
])
def test_bad_id_tokens_are_rejected(api, overrides, code):
    client, app, idp = api
    assert sso_error(sso_login(client, idp, **overrides)) == code
    assert client.cookies.get(oa.SESSION_COOKIE) is None
    assert events(app, "platform.operator_sign_in_denied")[-1]["details"]["code"] == code


def test_token_signed_by_another_key_is_rejected(api):
    client, _, idp = api
    idp.sign_with_other_key = True
    assert sso_error(sso_login(client, idp)) == "sso_token_invalid"


def test_wrong_pkce_verifier_fails_the_code_exchange(api):
    client, app, idp = api
    _, query = start(client, idp)
    with app._db() as conn:
        conn.execute("UPDATE platform_oidc_states SET code_verifier = 'attacker-supplied-verifier'")
        conn.commit()
    res = client.get("/vendor-admin/sso/callback", params={"code": "auth-code-1", "state": query["state"][0]}, follow_redirects=False)
    assert sso_error(res) == "sso_token_exchange_failed"


def test_unknown_email_is_denied_without_provisioning(api):
    client, app, idp = api
    assert sso_error(sso_login(client, idp, email="stranger@corp.example")) == "sso_operator_unknown"
    assert sso_error(sso_login(client, idp, email="owner@elsewhere.example")) == "sso_operator_unknown"
    with app._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM platform_operator_sessions").fetchone()[0] == 0
    denied = events(app, "platform.operator_sign_in_denied")
    assert len(denied) == 2 and all(e["details"]["auth_method"] == "sso" for e in denied)


def test_auth_config_is_public_and_carries_no_secrets(api, monkeypatch):
    client, _, _ = api
    client.cookies.clear()
    res = client.get("/platform/auth-config")
    assert res.status_code == 200
    body = res.json()
    assert body["sso_enabled"] is True and body["mfa_required"] is False and body["break_glass_allowed"] is True
    assert body["environment"] == "local"
    text = res.text
    for secret in ("client-secret-for-tests", CLIENT_ID, OWNER, ISSUER):
        assert secret not in text


# ── Sessions: expiry, CSRF, logout, revocation ───────────────────────────────


def test_idle_and_absolute_expiry(api):
    client, app, idp = api
    sso_login(client, idp)
    assert whoami(client).status_code == 200
    set_session(app, last_seen_at=time.time() - 31 * 60)
    # With PQC_AUTH_REQUIRED the request middleware already answers 401 for a dead session.
    assert whoami(client).status_code == 401 and session_state(client) == "idle_expired"

    sso_login(client, idp)
    assert whoami(client).status_code == 200
    with app._db() as conn:
        conn.execute("UPDATE platform_operator_sessions SET expires_at = ? WHERE revoked_at = 0", (time.time() - 1,))
        conn.commit()
    oa.clear_caches()
    assert whoami(client).status_code == 401 and session_state(client) == "expired"


def test_cookie_writes_require_the_csrf_token(api):
    client, _, idp = api
    sso_login(client, idp)
    payload = {"organization_id": "org-csrf", "name": "Org Csrf", "reason": "test setup"}
    res = client.post("/platform/customers", json=payload)
    assert res.status_code == 403 and res.json()["detail"]["code"] == "csrf_failed"
    res = client.post("/platform/customers", json=payload, headers={"x-csrf-token": "wrong"})
    assert res.status_code == 403
    res = client.post("/platform/customers", json=payload, headers=csrf(client))
    assert res.status_code == 200, res.text


def test_logout_needs_csrf_and_ends_the_session(api):
    client, app, idp = api
    sso_login(client, idp)
    raw = client.cookies.get(oa.SESSION_COOKIE)
    token = csrf(client)
    assert client.post("/platform/session/logout").status_code == 403
    res = client.post("/platform/session/logout", headers=token)
    assert res.status_code == 200 and res.json()["session_ended"] is True
    client.cookies.set(oa.SESSION_COOKIE, raw, domain="testserver.local", path="/")
    res = client.get("/platform/whoami", headers={"cookie": f"{oa.SESSION_COOKIE}={raw}"})
    assert res.status_code == 401 and session_state(raw) == "revoked"
    assert events(app, "platform.operator_signed_out")[0]["actor_id"] == OWNER


def test_operator_sessions_are_listed_and_revocable(api):
    client, app, idp = api
    sso_login(client, idp, email=OPS)
    raw = client.cookies.get(oa.SESSION_COOKIE)
    admin = TestClient(app.app, base_url="https://testserver")
    listing = admin.get("/platform/sessions", headers=legacy("auditor")).json()
    ops = [s for s in listing["operator_sessions"] if s["operator"] == OPS]
    assert ops and ops[0]["auth_method"] == "sso" and ops[0]["kind"] == "operator"
    res = admin.post(f"/platform/operator-sessions/{ops[0]['session_ref']}/revoke", headers=legacy("operator"),
                     json={"reason": "lost laptop"})
    assert res.status_code == 200, res.text
    admin.close()
    res = client.get("/platform/whoami", headers={"cookie": f"{oa.SESSION_COOKIE}={raw}"})
    assert res.status_code == 401 and session_state(raw) == "revoked"
    event = events(app, "platform.operator_session_revoked")[0]
    assert event["reason"] == "lost laptop" and event["actor_id"] == "platform-admin"


def test_roster_removal_ends_access_and_events_record_email_and_method(api, monkeypatch):
    client, app, idp = api
    sso_login(client, idp, email=OPS)
    res = client.post("/platform/customers", headers=csrf(client),
                      json={"organization_id": "org-audit", "name": "Org Audit", "reason": "audit identity"})
    assert res.status_code == 200, res.text
    created = events(app, "platform.customer_created")[0]
    assert created["actor_id"] == OPS
    assert created["details"]["operator"]["auth_method"] == "sso" and created["details"]["operator"]["email"] == OPS
    monkeypatch.setenv("PQC_ADMIN_OPERATOR_ROLES", f"{OWNER}=owner")
    assert whoami(client).status_code == 401


# ── TOTP ─────────────────────────────────────────────────────────────────────


def test_totp_matches_rfc6238_sha1_vectors():
    secret = b"12345678901234567890"
    vectors = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
               1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
    for t, expected in vectors.items():
        assert oa.totp(secret, t, digits=8) == expected
    # RFC 4226 appendix D (HOTP) for the same secret.
    assert [oa.hotp(secret, i) for i in range(3)] == ["755224", "287082", "359152"]


def test_totp_window_and_replay():
    secret = b"12345678901234567890"
    now = 1_700_000_000
    step = now // 30
    assert oa.match_totp(secret, oa.hotp(secret, step), now=now) == step
    assert oa.match_totp(secret, oa.hotp(secret, step - 1), now=now) == step - 1
    assert oa.match_totp(secret, oa.hotp(secret, step + 1), now=now) == step + 1
    assert oa.match_totp(secret, oa.hotp(secret, step - 2), now=now) is None
    assert oa.match_totp(secret, oa.hotp(secret, step + 2), now=now) is None
    assert oa.match_totp(secret, oa.hotp(secret, step), now=now, last_step=step) is None  # replay
    assert oa.match_totp(secret, "12345", now=now) is None


def test_enrolment_encrypts_the_secret_and_verification_rejects_replay(api):
    client, app, idp = api
    sso_login(client, idp)
    secret, started, codes = enrol(client, csrf(client))
    assert started["otpauth_uri"].startswith("otpauth://totp/") and "issuer=Airlock%20Command" in started["otpauth_uri"]
    assert started["qr_svg_data_uri"].startswith("data:image/svg+xml;base64,")
    assert len(codes) == 10 and len(set(codes)) == 10
    with app._db() as conn:
        row = dict(conn.execute("SELECT secret_enc, recovery_json, status FROM platform_operator_mfa").fetchone())
    assert row["status"] == "active" and started["secret"] not in row["secret_enc"]
    assert not any(code in row["recovery_json"] for code in codes)

    headers = csrf(client)
    future = oa.hotp(secret, int(time.time()) // 30 + 1)
    assert client.post("/platform/mfa/verify", headers=headers, json={"code": future}).status_code == 200
    res = client.post("/platform/mfa/verify", headers=headers, json={"code": future})
    assert res.status_code == 401 and res.json()["detail"]["code"] == "mfa_code_reused"
    assert events(app, "platform.mfa_failed")[-1]["details"]["code"] == "mfa_code_reused"


def test_mfa_rate_limit_is_five_failures_per_five_minutes(api):
    client, app, idp = api
    sso_login(client, idp)
    secret, _, _ = enrol(client, csrf(client))
    headers = csrf(client)
    for _ in range(5):
        assert client.post("/platform/mfa/verify", headers=headers, json={"code": "000000"}).status_code == 401
    good = oa.hotp(secret, int(time.time()) // 30 + 1)
    res = client.post("/platform/mfa/verify", headers=headers, json={"code": good})
    assert res.status_code == 429 and res.json()["detail"]["code"] == "mfa_rate_limited"
    assert events(app, "platform.mfa_rate_limited")[0]["details"]["severity"] == "high"
    with app._db() as conn:
        conn.execute("UPDATE platform_operator_mfa_attempts SET created_at = created_at - 301")
        conn.commit()
    assert client.post("/platform/mfa/verify", headers=headers, json={"code": good}).status_code == 200


def test_recovery_codes_are_single_use_and_can_be_regenerated(api):
    client, _, idp = api
    sso_login(client, idp)
    secret, _, codes = enrol(client, csrf(client))
    headers = csrf(client)
    res = client.post("/platform/mfa/verify", headers=headers, json={"recovery_code": codes[0].upper()})
    assert res.status_code == 200 and res.json()["method"] == "recovery_code" and res.json()["recovery_codes_remaining"] == 9
    res = client.post("/platform/mfa/verify", headers=headers, json={"recovery_code": codes[0]})
    assert res.status_code == 401
    res = client.post("/platform/mfa/recovery-codes/regenerate", headers=headers,
                      json={"code": oa.hotp(secret, int(time.time()) // 30 + 1)})
    assert res.status_code == 200 and len(res.json()["recovery_codes"]) == 10
    assert client.post("/platform/mfa/verify", headers=headers, json={"recovery_code": codes[1]}).status_code == 401


# ── Policy: MFA required, step-up, owner reset ───────────────────────────────


def test_required_mfa_gates_the_session_until_verified(api, monkeypatch):
    client, _, idp = api
    monkeypatch.setenv("PQC_ADMIN_REQUIRE_MFA", "1")
    sso_login(client, idp)
    assert whoami(client).json()["mfa"]["required"] is True
    res = client.get("/platform/customers")
    assert res.status_code == 401 and res.json()["detail"]["code"] == "mfa_enrolment_required"
    secret, _, _ = enrol(client, csrf(client))
    assert client.get("/platform/customers").status_code == 200  # enrolment confirmation elevated the session

    sso_login(client, idp)  # a new session starts unelevated
    res = client.get("/platform/customers")
    assert res.status_code == 401 and res.json()["detail"]["code"] == "mfa_required"
    res = client.post("/platform/mfa/verify", headers=csrf(client), json={"code": oa.hotp(secret, int(time.time()) // 30 + 1)})
    assert res.status_code == 200, res.text
    assert client.get("/platform/customers").status_code == 200


def test_named_operator_key_needs_mfa_when_required(api, monkeypatch):
    client, _, _ = api
    monkeypatch.setenv("PQC_ADMIN_REQUIRE_MFA", "1")
    key = {"x-platform-key": ALICE_KEY}
    res = client.get("/platform/customers", headers=key)
    assert res.status_code == 401 and res.json()["detail"]["code"] == "mfa_enrolment_required"
    assert client.get("/platform/whoami", headers=key).json()["auth_method"] == "operator_key"
    secret, _, _ = enrol(client, key)  # no CSRF: a header credential is not ambient
    assert client.get("/platform/customers", headers=key).status_code == 200


def test_purge_requires_a_recent_mfa_step_up(api):
    client, app, idp = api
    assert client.post("/platform/customers", headers=legacy(),
                       json={"organization_id": "org-purge", "name": "Org Purge", "reason": "setup"}).status_code == 200
    sso_login(client, idp)
    secret, _, _ = enrol(client, csrf(client))
    set_session(app, mfa_verified_at=time.time() - 16 * 60)
    headers = csrf(client)
    body = {"reason": "customer offboarding", "confirm_organization_id": "org-purge"}
    res = client.post("/platform/customers/org-purge/purge", headers=headers, json=body)
    assert res.status_code == 403 and res.json()["detail"]["code"] == "mfa_step_up_required"
    assert client.get("/platform/customers/org-purge", headers=legacy("auditor")).status_code == 200  # nothing deleted
    assert client.post("/platform/mfa/verify", headers=headers,
                       json={"code": oa.hotp(secret, int(time.time()) // 30 + 1)}).status_code == 200
    res = client.post("/platform/customers/org-purge/purge", headers=headers, json=body)
    assert res.status_code == 200, res.text


def test_retention_run_requires_step_up_but_dry_run_does_not(api, monkeypatch):
    client, app, idp = api
    monkeypatch.setattr(app, "_run_platform_retention", lambda req: {"api_version": "v1", "dry_run": req.dry_run, "items": []})
    sso_login(client, idp)
    enrol(client, csrf(client))
    set_session(app, mfa_verified_at=time.time() - 3600)
    headers = csrf(client)
    assert client.post("/platform/retention/run", headers=headers, json={"dry_run": True}).status_code == 200
    res = client.post("/platform/retention/run", headers=headers, json={"dry_run": False})
    assert res.status_code == 403 and res.json()["detail"]["code"] == "mfa_step_up_required"


def test_owner_can_reset_another_operators_mfa_with_reason(api):
    client, app, idp = api
    ops = TestClient(app.app, base_url="https://testserver")
    sso_login(ops, idp, email=OPS)
    enrol(ops, csrf(ops))
    sso_login(client, idp, email=OWNER)
    secret, _, _ = enrol(client, csrf(client))
    headers = csrf(client)
    listing = client.get("/platform/mfa/operators").json()["items"]
    assert {i["identity"] for i in listing} == {f"sso:{OPS}", f"sso:{OWNER}"}
    assert client.post("/platform/mfa/reset", headers=headers, json={"identity": f"sso:{OPS}"}).status_code == 422
    res = client.post("/platform/mfa/reset", headers=headers, json={"identity": f"sso:{OPS}", "reason": "lost phone"})
    assert res.status_code == 200 and res.json()["sessions_revoked"] == 1
    event = events(app, "platform.mfa_reset")[0]
    assert event["reason"] == "lost phone" and event["details"]["target_identity"] == f"sso:{OPS}"
    assert event["actor_id"] == OWNER
    assert whoami(ops).status_code == 401
    # Only owners may reset.
    sso_login(ops, idp, email=OPS)
    res = ops.post("/platform/mfa/reset", headers=csrf(ops), json={"identity": f"sso:{OWNER}", "reason": "takeover"})
    assert res.status_code == 403
    ops.close()


# ── Break-glass ──────────────────────────────────────────────────────────────


def test_shared_key_is_rejected_in_production_without_break_glass(api, monkeypatch):
    client, _, _ = api
    monkeypatch.setenv("PQC_ENVIRONMENT", "production")
    res = client.get("/platform/customers", headers=legacy("auditor"))
    assert res.status_code == 403 and res.json()["detail"]["code"] == "break_glass_disabled"
    monkeypatch.setenv("PQC_ENVIRONMENT", "staging")
    assert client.get("/platform/customers", headers=legacy("auditor")).status_code == 403
    assert client.get("/platform/auth-config").json()["break_glass_allowed"] is False


def test_break_glass_flag_allows_the_shared_key_and_audits_every_use(api, monkeypatch):
    client, app, _ = api
    monkeypatch.setenv("PQC_ENVIRONMENT", "production")
    monkeypatch.setenv("PQC_ALLOW_BREAK_GLASS_KEY", "1")
    monkeypatch.setenv("PQC_ADMIN_REQUIRE_MFA", "0")
    assert client.get("/platform/customers", headers=legacy("auditor")).status_code == 200
    res = client.post("/platform/customers", headers=legacy("owner"),
                      json={"organization_id": "org-glass", "name": "Org Glass", "reason": "incident"})
    assert res.status_code == 200, res.text
    used = events(app, "platform.break_glass_used")
    assert len(used) == 2 and all(e["details"]["severity"] == "high" for e in used)
    assert {e["details"]["method"] for e in used} == {"GET", "POST"}
    assert client.get("/platform/whoami", headers=legacy("auditor")).json()["auth_method"] == "break_glass"
    pa.clear_cache()
    notes = client.get("/platform/notifications", headers=legacy("auditor"))
    assert notes.status_code == 200, notes.text
    critical = [i for i in notes.json()["items"] if i["kind"] == "break_glass"]
    assert critical and critical[0]["severity"] == "critical"


def test_go_live_gate_reports_operator_sign_in_checks(api, monkeypatch):
    client, _, _ = api
    gate = client.get("/platform/go-live-gate", headers=legacy("auditor")).json()
    checks = {c["key"]: c for c in gate["checks"]}
    assert checks["admin_sso"]["status"] == "pass"
    assert checks["admin_mfa_required"]["status"] == "fail"
    assert checks["admin_break_glass_disabled"]["status"] == "pass"
    assert "admin_mfa_required" in {c["key"] for c in gate["failed_required_checks"]}
    monkeypatch.setenv("PQC_ALLOW_BREAK_GLASS_KEY", "1")
    checks = {c["key"]: c for c in client.get("/platform/go-live-gate", headers=legacy("auditor")).json()["checks"]}
    assert checks["admin_break_glass_disabled"]["status"] == "fail"


def test_local_shared_key_behaviour_is_unchanged(api):
    client, _, _ = api
    res = client.get("/platform/whoami", headers={"x-platform-key": LEGACY})
    assert res.status_code == 200 and res.json()["role"] == "auditor" and res.json()["auth_method"] == "shared_key"
    assert client.get("/platform/customers").status_code in {401, 403}


# ── Env robustness and log redaction ─────────────────────────────────────────


def test_bom_env_file_parses_the_first_variable(tmp_path):
    path = tmp_path / "bom.env"
    path.write_bytes(b"\xef\xbb\xbfPQC_VAULT_MASTER_KEY=first-value-123\r\n# comment\r\nexport OTHER='two words'\r\nPLAIN=3 # note\r\n")
    values = env_file.parse_env_file(str(path))
    assert values == {"PQC_VAULT_MASTER_KEY": "first-value-123", "OTHER": "two words", "PLAIN": "3"}
    target = {}
    assert env_file.load_env_file(str(path), environ=target) == ["PQC_VAULT_MASTER_KEY", "OTHER", "PLAIN"]
    assert target["PQC_VAULT_MASTER_KEY"] == "first-value-123"


def test_bom_mangled_environment_names_are_repaired():
    environ = {"﻿PQC_VAULT_MASTER_KEY": "abc123456", "OTHER": "1", "﻿ALREADY": "stale", "ALREADY": "kept"}
    assert env_file.repair_bom_environ(environ) == ["PQC_VAULT_MASTER_KEY"]
    assert environ == {"PQC_VAULT_MASTER_KEY": "abc123456", "OTHER": "1", "ALREADY": "kept"}


def test_secrets_are_redacted_from_messages():
    env = {"PQC_VAULT_MASTER_KEY": "vault-master-key-value-xyz", "PQC_ENVIRONMENT": "production"}
    message = ('invalid dsn: invalid connection option "﻿PQC_VAULT_MASTER_KEY=vault-master-key-value-xyz" '
               "postgresql://app:db-password-777@db.internal/pqc PQC_AUTH_JWT_SECRET=another-secret-abc environment production")
    redacted = env_file.redact_secrets(message, environ=env)
    for secret in ("vault-master-key-value-xyz", "db-password-777", "another-secret-abc"):
        assert secret not in redacted
    assert "production" in redacted and "db.internal" in redacted


def test_vault_startup_warning_does_not_log_the_master_key(api, monkeypatch, caplog):
    _, app, _ = api
    key = "cHFjLXNjYW5uZXItdGVzdC1vbmx5LWtleS0zMmJ5dGU="
    monkeypatch.setenv("PQC_VAULT_MASTER_KEY", key)
    monkeypatch.setenv("DATABASE_URL", "postgresql://pqc:hunter2-db-password@127.0.0.1:1/pqc")

    def boom():
        raise RuntimeError(f'invalid dsn: "﻿PQC_VAULT_MASTER_KEY={key}" and postgresql://pqc:hunter2-db-password@127.0.0.1:1/pqc')

    for name in ("_assert_production_startup_safe", "_init_otel", "init_db"):
        monkeypatch.setattr(app, name, lambda *a, **k: [])
    monkeypatch.setattr(app, "_security_warnings", lambda: [])
    monkeypatch.setattr(app, "ensure_vault_tables", boom)
    with caplog.at_level(logging.WARNING):
        app._startup()
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "Vault table init skipped" in logged
    assert key not in logged and "hunter2-db-password" not in logged

    import db_postgres

    caplog.clear()
    monkeypatch.setattr(db_postgres, "_DEFERRED_SCHEMA_HOOKS", [("vault_credentials", boom)])
    with caplog.at_level(logging.WARNING):
        result = db_postgres.apply_deferred_schemas()
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert key not in logged and key not in json.dumps(result) and "hunter2-db-password" not in logged


def test_guard_explains_why_a_session_stopped_working(api, monkeypatch):
    """Without the JWT middleware in front, the endpoint guard returns a machine-readable reason."""
    client, app, idp = api
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)
    sso_login(client, idp)
    set_session(app, last_seen_at=time.time() - 31 * 60)
    res = whoami(client)
    assert res.status_code == 401 and res.json()["detail"]["code"] == "session_idle_expired"
    sso_login(client, idp)
    set_session(app, revoked_at=time.time())
    assert whoami(client).json()["detail"]["code"] == "session_revoked"


def test_alert_dispatcher_reads_the_gate_without_the_shared_key(api, monkeypatch):
    """The background dispatcher computes the go-live gate in-process: no shared key, no break-glass event."""
    _, app, _ = api
    monkeypatch.setenv("PQC_ENVIRONMENT", "production")
    monkeypatch.delenv("PQC_ALLOW_BREAK_GLASS_KEY", raising=False)
    assert oa.break_glass_allowed() is False
    gate = app._platform_go_live_gate_result()
    assert "failed_required_checks" in gate and "admin_sso" in {c["key"] for c in gate["checks"]}
    pa.clear_cache()
    data = app._alert_notifications_snapshot()
    assert "go_live_blockers" not in json.dumps(data.get("unavailable") or [])
    assert any(i["kind"] == "go_live_blockers" for i in data["items"])
    assert events(app, "platform.break_glass_used") == []
    assert not hasattr(app, "_alert_internal_read_request")


# ── Enrolment is no longer trust-on-first-use (September 2026 review, finding 9) ──────────────


def test_a_second_operator_cannot_enrol_its_own_authenticator_once_an_owner_has_one(api):
    """The attack the review described: a stolen key or hijacked session enrols *itself*.

    /platform/mfa/enroll/start and /enroll/confirm are necessarily exempt from the elevation gate,
    because an operator with no authenticator could never reach them otherwise. That made MFA
    trust-on-first-use: whoever got there first, legitimate holder or intruder, owned the factor.
    Once an owner holds one, a new authenticator takes that owner's single-use approval.
    """
    client, app, idp = api
    sso_login(client, idp, email=OWNER)
    enrol(client, csrf(client))                      # bootstrap: the first owner self-enrols

    ops = TestClient(app.app, base_url="https://testserver")
    sso_login(ops, idp, email=OPS)
    refused = ops.post("/platform/mfa/enroll/start", headers=csrf(ops))
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["code"] == "mfa_enrolment_approval_required"
    # …and it is audited at high severity, not silently refused.
    refusal = events(app, "platform.mfa_enrolment_refused")[-1]
    assert refusal["details"]["severity"] == "high"
    assert refusal["details"]["code"] == "mfa_enrolment_approval_required"

    # An operator cannot approve their own enrolment; only an owner can approve, with a reason.
    assert ops.post("/platform/mfa/enrolment-approvals", headers=csrf(ops),
                    json={"identity": f"sso:{OPS}", "reason": "let me in"}).status_code == 403
    assert client.post("/platform/mfa/enrolment-approvals", headers=csrf(client),
                       json={"identity": f"sso:{OPS}"}).status_code == 422          # reason required
    approved = client.post("/platform/mfa/enrolment-approvals", headers=csrf(client),
                           json={"identity": f"sso:{OPS}", "reason": "new starter, verified on a call"})
    assert approved.status_code == 200, approved.text
    assert events(app, "platform.mfa_enrolment_approved")[-1]["details"]["target_identity"] == f"sso:{OPS}"

    secret, body, _codes = enrol(ops, csrf(ops))
    assert body["approved_by"] == OWNER and body["first_enrolment"] is False

    # The approval is single use: a second attempt needs a new one.
    oa.reset_mfa(f"sso:{OPS}")
    again = ops.post("/platform/mfa/enroll/start", headers=csrf(ops))
    assert again.status_code == 403 and again.json()["detail"]["code"] == "mfa_enrolment_approval_required"
    ops.close()


def test_every_enrolment_is_a_high_severity_event_and_a_notification(api):
    """Enrolment is when an operator account gains a durable second factor. A legitimate onboarding
    and an intruder making stolen access permanent write the same row, so both are raised."""
    client, app, idp = api
    sso_login(client, idp, email=OWNER)
    enrol(client, csrf(client))

    enrolled = events(app, "platform.mfa_enrolled")[-1]
    assert enrolled["details"]["severity"] == "high"
    assert enrolled["details"]["identity"] == f"sso:{OWNER}"
    started = events(app, "platform.mfa_enrolment_started")[-1]
    assert started["details"]["severity"] == "high" and started["details"]["first_enrolment"] is True

    notifications = pa.notifications({}, limit=100)["items"]
    mine = [n for n in notifications if n["kind"] == "mfa_enrolment"]
    assert mine, [n["kind"] for n in notifications]
    assert mine[0]["severity"] == "critical"
    assert f"sso:{OWNER}" in mine[0]["title"]


def test_the_bootstrap_window_closes_on_the_first_owner_not_the_first_operator(api):
    """An operator enrolling first must not lock every owner out.

    Approval needs an owner who has passed step-up, and step-up needs an authenticator. If a
    non-owner enrolment closed the gate there would be nobody able to approve anybody, ever.
    """
    client, app, idp = api
    ops = TestClient(app.app, base_url="https://testserver")
    sso_login(ops, idp, email=OPS)
    enrol(ops, csrf(ops))
    assert oa.enrolment_gate_closed() is False, "a non-owner enrolment must not close the window"

    sso_login(client, idp, email=OWNER)
    enrol(client, csrf(client))                      # the owner can still self-enrol
    assert oa.enrolment_gate_closed() is True
    ops.close()
