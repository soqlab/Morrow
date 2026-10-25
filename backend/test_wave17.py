"""Tests for Wave 17 autonomous-defense endpoints and built-in auth issuer."""
import io
import os
import zipfile

# Must be set before app is imported so auth_issuer._SECRET is populated
os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")

from fastapi.testclient import TestClient

import app as fastapi_app

HEADERS = {"x-user-role": "admin", "x-user-id": "test-admin", "x-org-id": "test-w17-org"}


# ── Drift Sentinel ─────────────────────────────────────────────────────────────

def test_drift_status_returns_expected_keys():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/drift/status", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert "status" in body
    assert "last_snapshot_at" in body


def test_drift_events_returns_list():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/drift/events", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert "events" in body
    assert isinstance(body["events"], list)


# ── Dependency Scanner ─────────────────────────────────────────────────────────

def test_dep_scan_signatures_list():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/dep-scan/signatures", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert body["count"] >= 10
    assert any(p["name"] == "pycryptodome" for p in body["packages"])


def test_dep_scan_detects_classical_package():
    files = {
        "requirements.txt": "pycryptodome==3.18.0\nrequests==2.31.0\n"
    }
    with TestClient(fastapi_app.app) as client:
        res = client.post("/v1/dep-scan", headers=HEADERS, json={"files": files})
    assert res.status_code == 200
    body = res.json()
    assert body["aggregate"]["total_findings"] >= 1
    names = [f["package"] for f in body["findings"]]
    assert "pycryptodome" in names


def test_dep_scan_clean_file_returns_zero_findings():
    files = {"requirements.txt": "requests==2.31.0\nhttpx==0.27.0\n"}
    with TestClient(fastapi_app.app) as client:
        res = client.post("/v1/dep-scan", headers=HEADERS, json={"files": files})
    assert res.status_code == 200
    body = res.json()
    assert body["aggregate"]["total_findings"] == 0


# ── CBOM Webhook ───────────────────────────────────────────────────────────────

def test_cbom_webhook_setup_returns_secret_and_endpoint():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/cbom/webhook/setup", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert body["secret"]
    assert "/cbom/ingest" in body["endpoint"]
    assert "github_actions_step" in body


def test_cbom_ingest_accepts_valid_payload():
    payload = {"components": [{"name": "openssl", "version": "1.1.1", "algorithms": ["RSA-2048"]}]}
    with TestClient(fastapi_app.app) as client:
        res = client.post("/v1/cbom/ingest", headers=HEADERS, json=payload)
    assert res.status_code == 200
    body = res.json()
    assert "id" in body or "ingest_id" in body or body.get("ok") or body.get("status")


def test_cbom_ingests_list():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/cbom/webhook/ingests", headers=HEADERS)
    assert res.status_code == 200
    assert "ingests" in res.json()


# ── Push Notifications ─────────────────────────────────────────────────────────

def test_push_webhook_create_and_list():
    with TestClient(fastapi_app.app) as client:
        create = client.post(
            "/v1/push/webhooks",
            headers=HEADERS,
            json={"channel": "slack", "url": "https://hooks.slack.com/test/fake"},
        )
        assert create.status_code == 200

        lst = client.get("/v1/push/webhooks", headers=HEADERS)
        assert lst.status_code == 200
        assert "webhooks" in lst.json()


def test_push_alert_returns_delivery_summary():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/v1/push/alert",
            headers=HEADERS,
            json={"title": "Test Alert", "body": "RSA detected.", "severity": "HIGH"},
        )
    assert res.status_code == 200
    body = res.json()
    assert "sent" in body or "results" in body or "delivered" in body


def test_push_log_returns_list():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/push/log", headers=HEADERS)
    assert res.status_code == 200
    assert "log" in res.json()


def test_push_subscribe():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/v1/push/subscribe",
            headers=HEADERS,
            json={"email": "test@example.com", "type": "email"},
        )
    assert res.status_code == 200


# ── Evidence Builder ───────────────────────────────────────────────────────────

def test_evidence_frameworks_lists_four():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/evidence/frameworks", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert len(body["frameworks"]) >= 4
    keys = [f["key"] for f in body["frameworks"]]
    assert "nist_sp_800_208" in keys
    assert "fedramp" in keys


def test_evidence_build_returns_zip():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/v1/evidence/build",
            headers=HEADERS,
            json={"framework": "nist_sp_800_208"},
        )
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    # Confirm it is a valid ZIP containing at least the manifest
    zf = zipfile.ZipFile(io.BytesIO(res.content))
    names = zf.namelist()
    assert any("manifest" in n for n in names)


# ── Knowledge Base ─────────────────────────────────────────────────────────────

def test_kb_articles_returns_seeded_articles():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/kb/articles")
    assert res.status_code == 200
    body = res.json()
    assert len(body["articles"]) >= 5
    assert "categories" in body


def test_kb_search_finds_mlkem():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/kb/search?q=ML-KEM")
    assert res.status_code == 200
    body = res.json()
    assert len(body["results"]) >= 1
    assert body["query"] == "ML-KEM"


def test_kb_article_by_slug():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/kb/articles/ml-kem-overview")
    assert res.status_code == 200
    body = res.json()
    assert body["slug"] == "ml-kem-overview"
    assert body["title"]
    assert body["body"]


def test_kb_article_not_found():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/kb/articles/does-not-exist-xyz")
    assert res.status_code == 404


# ── Q-Day Countdown ────────────────────────────────────────────────────────────

def test_qday_countdown_structure():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/v1/qday/countdown", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    # Scenario years come from the Q-Intel model, not fixed constants.
    from services.q_intel import q_day_reference
    ref = q_day_reference("rsa2048")
    assert body["estimates"]["conservative"] == ref["conservative_year"]
    assert body["estimates"]["median"] == ref["expected_year"]
    assert body["estimates"]["optimistic"] == ref["accelerated_year"]
    assert body["estimates"]["optimistic"] <= body["estimates"]["median"] <= body["estimates"]["conservative"]
    assert "countdown_seconds" in body
    assert body["countdown_seconds"]["conservative"] >= 0
    assert len(body["milestones"]) >= 5
    assert body["hndl_risk"] in {"ACTIVE", "RESOLVED"}
    # None when the workspace has no assets: an empty estate is not "0% ready".
    assert body["org_readiness_pct"] is None or 0 <= body["org_readiness_pct"] <= 100
    assert body["org_readiness_basis"]
    assert body["model_basis"]["kind"] == "model"
    # A passed target date is never reported as "complete".
    assert all(m["status"] != "complete" for m in body["milestones"])
    assert "classical algorithms broken" not in res.text


# ── Built-in Auth Issuer ───────────────────────────────────────────────────────

def test_auth_login_default_admin():
    """Default admin created at startup — login must succeed."""
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/auth/login",
            json={"email": "admin@morrow.soqlab.com", "password": "changeme123!"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"
    assert body["user"]["role"] == "admin"


def test_auth_login_wrong_password():
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/auth/login",
            json={"email": "admin@morrow.soqlab.com", "password": "wrongpassword999"},
        )
    assert res.status_code == 401


def test_auth_login_missing_fields():
    with TestClient(fastapi_app.app) as client:
        res = client.post("/auth/login", json={"email": "admin@morrow.soqlab.com"})
    assert res.status_code == 400


def test_auth_register_and_me():
    import uuid
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    with TestClient(fastapi_app.app) as client:
        reg = client.post(
            "/auth/register",
            headers=HEADERS,
            json={"email": email, "password": "securepass99", "full_name": "Test User"},
        )
        assert reg.status_code == 200
        assert reg.json()["user"]["email"] == email

        # login as the new user
        login = client.post("/auth/login", json={"email": email, "password": "securepass99"})
        assert login.status_code == 200
        token = login.json()["access_token"]

        # /auth/me with the token
        me = client.get("/auth/me", headers={"authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["email"] == email


def test_auth_register_duplicate_email():
    with TestClient(fastapi_app.app) as client:
        client.post(
            "/auth/login",
            json={"email": "admin@morrow.soqlab.com", "password": "changeme123!"},
        )
        res = client.post(
            "/auth/register",
            headers=HEADERS,
            json={"email": "admin@morrow.soqlab.com", "password": "changeme123!", "full_name": "Dup"},
        )
    assert res.status_code == 409


def test_auth_refresh_and_logout():
    with TestClient(fastapi_app.app) as client:
        login = client.post(
            "/auth/login",
            json={"email": "admin@morrow.soqlab.com", "password": "changeme123!"},
        )
        assert login.status_code == 200
        refresh_token = login.json()["refresh_token"]

        refresh = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert refresh.status_code == 200
        assert refresh.json()["access_token"]

        logout = client.post("/auth/logout", json={"refresh_token": refresh_token})
        assert logout.status_code == 200
        assert logout.json()["ok"] is True

        # After logout, refresh token is revoked
        second_refresh = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert second_refresh.status_code == 401


def test_auth_me_invalid_token():
    with TestClient(fastapi_app.app) as client:
        res = client.get("/auth/me", headers={"authorization": "Bearer notavalidtoken"})
    assert res.status_code == 401


def test_auth_list_users_admin_only():
    with TestClient(fastapi_app.app) as client:
        login = client.post(
            "/auth/login",
            json={"email": "admin@morrow.soqlab.com", "password": "changeme123!"},
        )
        token = login.json()["access_token"]

        # Default admin lives in org-alpha; query that org
        res = client.get("/auth/users", headers={
            **HEADERS,
            "x-org-id": "org-alpha",
            "authorization": f"Bearer {token}",
        })
        assert res.status_code == 200
        users = res.json()["users"]
        assert any(u["email"] == "admin@morrow.soqlab.com" for u in users)


def test_auth_change_password():
    import uuid
    email = f"pw-{uuid.uuid4().hex[:8]}@example.com"
    old_pw = "oldpassword1"
    new_pw = "newpassword2"
    with TestClient(fastapi_app.app) as client:
        client.post(
            "/auth/register",
            headers=HEADERS,
            json={"email": email, "password": old_pw},
        )
        login = client.post("/auth/login", json={"email": email, "password": old_pw})
        token = login.json()["access_token"]

        change = client.post(
            "/auth/change-password",
            headers={"authorization": f"Bearer {token}"},
            json={"old_password": old_pw, "new_password": new_pw},
        )
        assert change.status_code == 200
        assert change.json()["ok"] is True

        # Old password no longer works
        old_login = client.post("/auth/login", json={"email": email, "password": old_pw})
        assert old_login.status_code == 401

        # New password works
        new_login = client.post("/auth/login", json={"email": email, "password": new_pw})
        assert new_login.status_code == 200
