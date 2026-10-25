import base64
import hashlib
import hmac
import importlib
import json
import os

import pytest
from fastapi.testclient import TestClient


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _hs256_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))}.{_b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


@pytest.fixture()
def client(tmp_path):
    old_env = {k: os.environ.get(k) for k in (
        "MORROW_SCANNER_DB",
        "MORROW_AUTH_MODE",
        "MORROW_AUTH_REQUIRED",
        "MORROW_AUTH_PROVIDER_NAME",
        "MORROW_AUTH_LOGIN_URL",
        "MORROW_AUTH_LOGOUT_URL",
        "MORROW_AUTH_TOKEN_HELP",
        "MORROW_AUTH_ISSUER_ENABLED",
        "MORROW_AUTH_JWT_SECRET",
        "MORROW_AUTH_JWT_ISSUER",
        "MORROW_AUTH_JWT_AUDIENCE",
        "MORROW_AUTH_JWT_ALGORITHMS",
        "MORROW_AUTH_USER_ID_CLAIM",
        "MORROW_AUTH_ROLE_CLAIM",
        "MORROW_AUTH_ORG_ID_CLAIM",
    )}
    os.environ["MORROW_SCANNER_DB"] = str(tmp_path / "auth.db")
    os.environ["MORROW_AUTH_MODE"] = "jwt"
    os.environ["MORROW_AUTH_REQUIRED"] = "1"
    os.environ["MORROW_AUTH_PROVIDER_NAME"] = "Acme OIDC"
    os.environ["MORROW_AUTH_LOGIN_URL"] = "https://login.example/start"
    os.environ["MORROW_AUTH_LOGOUT_URL"] = "https://login.example/logout"
    os.environ["MORROW_AUTH_TOKEN_HELP"] = "Paste an OIDC access token for local smoke tests."
    os.environ["MORROW_AUTH_ISSUER_ENABLED"] = "1"
    os.environ["MORROW_AUTH_JWT_SECRET"] = "test-secret"
    os.environ["MORROW_AUTH_JWT_ISSUER"] = "https://issuer.example"
    os.environ["MORROW_AUTH_JWT_AUDIENCE"] = "pq-ui"
    os.environ["MORROW_AUTH_JWT_ALGORITHMS"] = "HS256"
    os.environ["MORROW_AUTH_USER_ID_CLAIM"] = "sub"
    os.environ["MORROW_AUTH_ROLE_CLAIM"] = "role"
    os.environ["MORROW_AUTH_ORG_ID_CLAIM"] = "org_id"

    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()

    with TestClient(fastapi_app.app) as c:
        yield c

    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    importlib.reload(fastapi_app)


def test_auth_context_uses_verified_jwt_claims(client):
    token = _hs256_jwt(
        {
            "sub": "alice@example.com",
            "role": "operator",
            "org_id": "org-alpha",
            "iss": "https://issuer.example",
            "aud": "pq-ui",
            "exp": 4102444800,
        },
        "test-secret",
    )
    r = client.get("/auth/context", headers={"authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["authenticated"] is True
    assert body["auth_mode"] == "jwt"
    assert body["actor_id"] == "alice@example.com"
    assert body["actor_role"] == "operator"
    assert body["organization_id"] == "org-alpha"
    assert body["auth_error"] == ""


def test_auth_config_is_public_and_exposes_hosted_mode_settings(client):
    r = client.get("/auth/config")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "jwt"
    assert body["required"] is True
    assert body["provider_name"] == "Acme OIDC"
    assert body["login_url"] == "https://login.example/start"
    assert body["logout_url"] == "https://login.example/logout"
    assert body["token_help"] == "Paste an OIDC access token for local smoke tests."
    assert body["bearer_token_supported"] is True
    assert body["password_login_enabled"] is True
    assert body["manual_actor_supported"] is False


def test_auth_config_and_login_respect_disabled_password_issuer(client, monkeypatch):
    import app as fastapi_app

    monkeypatch.setattr(fastapi_app, "AUTH_ISSUER_ENABLED", False)
    cfg = client.get("/auth/config")
    assert cfg.status_code == 200
    assert cfg.json()["password_login_enabled"] is False

    login = client.post("/auth/login", json={"email": "a@example.com", "password": "secret"})
    assert login.status_code == 404
    assert "disabled" in login.text.lower()


def test_auth_required_rejects_missing_or_invalid_token(client):
    health = client.get("/health")
    assert health.status_code == 200

    missing = client.get("/auth/context")
    assert missing.status_code == 401
    assert "missing bearer token" in missing.text.lower()

    bad_token = _hs256_jwt(
        {
            "sub": "mallory@example.com",
            "role": "admin",
            "org_id": "org-alpha",
            "iss": "https://issuer.example",
            "aud": "pq-ui",
            "exp": 4102444800,
        },
        "wrong-secret",
    )
    bad = client.get("/auth/context", headers={"authorization": f"Bearer {bad_token}"})
    assert bad.status_code == 401
    assert "signature verification failed" in bad.text.lower()
