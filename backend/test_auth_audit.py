"""Authentication and journal failure paths through the actual ASGI middleware."""
import json
import sqlite3
from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from services import auth_issuer, security_journal as journal

PASSWORD = "audit-tests-only-password-197!"
EMAIL = "audit-user@example.test"
KEY = "audit-tests-platform-key"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "auth-audit.db"))
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", "audit-test-jwt-signing-key-197-not-for-deployment")
    monkeypatch.setenv("MORROW_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("MORROW_ADMIN_EMAIL", EMAIL)
    for name, value in {"AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_ISSUER_ENABLED": True,
                        "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": "audit-test-jwt-signing-key-197-not-for-deployment",
                        "AUTH_JWT_ISSUER": "morrow", "AUTH_JWT_AUDIENCE": "morrow",
                        "AUTH_USER_ID_CLAIM": "sub", "AUTH_ROLE_CLAIM": "role", "AUTH_ORG_ID_CLAIM": "org_id",
                        "_PLATFORM_ADMIN_KEY": KEY, "_TRAFFIC_PERSIST_TO_DB": True, "_TRAFFIC_MONITOR_ENABLED": True,
                        "API_KEY": "", "PRODUCTION_ENVIRONMENT": False, "RATE_LIMIT_MAX_REQUESTS": 100000}.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(auth_issuer, "_SECRET", app.AUTH_JWT_SECRET)
    monkeypatch.setattr(auth_issuer, "_ISSUER", "morrow")
    monkeypatch.setattr(auth_issuer, "_AUDIENCE", "morrow")
    monkeypatch.setattr(auth_issuer, "_ENABLED", True)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    app._TRAFFIC_EVENTS.clear()
    app._TRAFFIC_BY_IP.clear()
    # Lifespan schedulers are unnecessary here; the real routes/middleware/DB are used.
    client = TestClient(app.app, client=("192.0.2.10", 12345))
    yield client, app
    client.close()


def sign_in(client):
    result = client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return result.json()


def test_actual_login_outcomes_not_authenticated_page_views(api):
    client, app = api
    for _ in range(2):
        session = sign_in(client)
    auth = {"authorization": "Bearer " + session["access_token"]}
    for _ in range(3):
        assert client.get("/auth/context", headers=auth).json()["authenticated"]
    failed = client.post("/auth/login", json={"email": "not-present@example.test", "password": PASSWORD},
                         headers={"x-org-id": "spoof-org", "x-user-id": "spoof-user", "x-user-role": "admin"})
    assert failed.status_code == 401
    events = journal.auth_events()
    assert [e["event_type"] for e in events] == ["login.failure", "login.success", "login.success"]
    assert events[0]["organization_id"] == events[0]["user_id"] == ""
    assert events[1]["user_id"] == session["user"]["id"]
    assert "spoof" not in json.dumps(journal.request_events())
    assert journal.login_count("2000") == 2


@pytest.mark.parametrize("body,status", [("{", 400), ("[]", 400), ('{"password":123}', 400), ("x" * 9000, 413),
                                        (json.dumps({"email": EMAIL, "password": "\ud800"}), 400),
                                        (json.dumps({"email": "\ud800", "password": PASSWORD}), 400)])
def test_invalid_auth_requests_are_audited(api, body, status):
    client, _ = api
    assert client.post("/auth/login", content=body).status_code == status
    event = journal.auth_events()[0]
    assert event["event_type"] == "login.invalid_request" and event["status_code"] == status


def test_refresh_and_logout_are_not_logins(api):
    client, _ = api
    session = sign_in(client)
    body = {"refresh_token": session["refresh_token"]}
    assert client.post("/auth/refresh", json=body).status_code == 200
    revoked = client.post("/auth/logout", json=body)
    assert revoked.status_code == 200
    assert revoked.json() == {"ok": True, "refresh_token_revoked": True, "access_tokens_revoked": False, "audit_recorded": True}
    assert client.post("/auth/refresh", json=body).status_code == 401
    assert client.post("/auth/logout", json=body).json()["refresh_token_revoked"] is False
    assert journal.login_count("2000") == 1
    assert {r["event_type"] for r in journal.auth_events()} == {"login.success", "refresh.success", "refresh.failure", "logout.revoked", "logout.no_session"}
    raw = json.dumps(journal.auth_events())
    assert session["refresh_token"] not in raw and session["access_token"] not in raw


def test_journal_failure_blocks_issuance_but_not_revocation(api, monkeypatch):
    client, app = api
    session = sign_in(client)
    def broken(*args, **kwargs):
        raise journal.JournalUnavailable("private-internal-detail")
    monkeypatch.setattr(journal, "record_auth", broken)
    failed_login = client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert failed_login.status_code == 503 and "access_token" not in failed_login.json()
    assert "private-internal-detail" not in failed_login.text
    with app._db() as conn:
        assert conn.execute("SELECT count(*) FROM morrow_refresh_tokens").fetchone()[0] == 1
    body = {"refresh_token": session["refresh_token"]}
    assert client.post("/auth/refresh", json=body).status_code == 503
    revoked = client.post("/auth/logout", json=body)
    assert revoked.json()["refresh_token_revoked"] is True and revoked.json()["audit_recorded"] is False
    with app._db() as conn:
        assert conn.execute("SELECT count(*) FROM morrow_refresh_tokens").fetchone()[0] == 0


def test_durable_archive_access_control_filters_and_export(api):
    client, app = api
    client.get("/status?token=never-record-this-query")
    client.get("/unknown/never-record-this-path")
    app._TRAFFIC_EVENTS.clear()
    app._TRAFFIC_BY_IP.clear()
    headers = {"x-platform-key": KEY, "x-platform-admin-role": "auditor"}
    for path in ("/platform/auth-events", "/platform/logging/health", "/platform/traffic/events?source=archive"):
        assert client.get(path).status_code in (401, 403)
        assert client.get(path, headers=headers).status_code == 200
    assert client.post("/platform/traffic/clear", headers=headers).status_code == 403
    history = client.get("/platform/traffic/events?source=archive&path_prefix=/status", headers=headers)
    assert len(history.json()["items"]) == 1
    assert "never-record" not in json.dumps(journal.request_events())
    export = client.get("/platform/traffic/export.ndjson?source=archive&path_prefix=/status", headers=headers)
    assert len(export.text.strip().splitlines()) == 1
    assert export.headers["cache-control"] == "no-store"
    otel = client.get("/platform/traffic/otel?source=archive&path_prefix=/status", headers=headers)
    records = otel.json()["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(records) == 1 and int(records[0]["timeUnixNano"]) > 0
    app._TRAFFIC_PERSIST_TO_DB = False
    assert client.get("/platform/traffic/events?source=archive", headers=headers).status_code == 409


def test_saml_credentials_never_in_redirect_url(api, monkeypatch):
    import saml_auth
    client, _ = api
    monkeypatch.setattr(saml_auth, "process_saml_acs", lambda *args: (True, {"actor_id": "saml-user", "org_id": "saml-org", "actor_role": "viewer", "jwt": "saml-test-token"}))
    response = client.post("/auth/saml/acs", content="test assertion")
    assert response.status_code == 200 and "location" not in response.headers
    assert response.json()["token"] == "saml-test-token" and response.headers["cache-control"] == "no-store"
    assert journal.auth_events()[0]["event_type"] == "saml.success"
    monkeypatch.setattr(saml_auth, "process_saml_acs", lambda *args: (False, {"error": "sensitive-assertion"}))
    response = client.post("/auth/saml/acs", content="test assertion")
    assert response.status_code == 401 and "sensitive-assertion" not in response.text
    assert journal.auth_events()[0]["event_type"] == "saml.failure"


def test_storage_exceptions_are_sanitized(api, monkeypatch):
    client, app = api
    @contextmanager
    def broken_db():
        raise sqlite3.OperationalError("password=private-db-secret")
        yield
    monkeypatch.setattr(app, "_db", broken_db)
    for path, body in (("login", {"email": EMAIL, "password": PASSWORD}), ("refresh", {"refresh_token": "test-token"}), ("logout", {"refresh_token": "test-token"})):
        response = client.post("/auth/" + path, json=body)
        assert response.status_code == 503
        assert "private-db-secret" not in response.text


def test_rejected_and_expired_access_tokens_are_not_logins(api):
    import jwt
    client, app = api
    expired = jwt.encode({"sub": "spoof", "org_id": "spoof", "role": "admin", "exp": 1}, app.AUTH_JWT_SECRET, algorithm="HS256")
    for token in ("invalid-token", expired):
        response = client.get("/assets", headers={"authorization": "Bearer " + token})
        assert response.status_code == 401
    events = journal.auth_events()
    assert len(events) == 2 and all(e["event_type"] == "token.rejected" for e in events)
    assert all(e["user_id"] == e["organization_id"] == "" for e in events)
    assert journal.login_count("2000") == 0


def test_auth_rate_limit_is_audited(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app.limiter, "enabled", True)
    app.limiter.reset()
    statuses = [client.post("/auth/login", content="{").status_code for _ in range(11)]
    assert 429 in statuses
    limited = journal.auth_events(event_type="auth.rate_limited")
    assert limited and limited[0]["status_code"] == 429
    app.limiter.reset()


def test_successful_mutation_audit_omits_query(api, monkeypatch):
    client, app = api
    session = sign_in(client)
    records, original = [], app.append_audit_log
    def capture(**kwargs):
        records.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(app, "append_audit_log", capture)
    response = client.post("/gateway/sites?access_token=secret-query-sentinel",
                           headers={"authorization": "Bearer " + session["access_token"]},
                           json={"website": "www.customer.com", "origin": "origin.customer.com"})
    assert response.status_code == 201, response.text
    http_events = [r for r in records if r["action"] == "http.post"]
    assert http_events and http_events[0]["details"]["path"] == "/gateway/sites"
    assert "secret-query-sentinel" not in json.dumps(records)


def test_production_authorization_fails_closed_if_audit_is_down(api, monkeypatch):
    _, app = api
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(app, "_actor_from_request", lambda request: {"actor_id": "admin-a", "actor_role": "admin"})
    def broken(**kwargs):
        raise sqlite3.OperationalError("secret")
    monkeypatch.setattr(app, "append_audit_log", broken)
    request = Request({"type": "http", "method": "POST", "path": "/test", "headers": []})
    with pytest.raises(HTTPException) as error:
        app._require_role(request, ["admin"], "test.write", "test")
    assert error.value.status_code == 503
    # Post-operation notifications cannot claim a completed mutation was never authorized.
    app._audit_event(request, action="test.completed", resource_type="test")
