"""Traffic Lens accepts an operator SSO session (HttpOnly cookie + CSRF), not only a typed platform key.

The API contract runs through TestClient. The browser check starts the app with uvicorn on a free local port
against a throwaway SQLite database, mints sessions directly (services/operator_auth.create_session, as the
SSO tests do; no identity provider) and runs scripts/traffic-lens-session-smoke.js in Chrome. It is skipped
when node or the repository's Playwright install is missing.
"""

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
from fastapi.testclient import TestClient

from services import operator_auth as oa

ROOT = pathlib.Path(__file__).resolve().parent.parent
OPS = "ops@corp.example"
ROSTER = f"{OPS}=operator,auditor@corp.example=auditor"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "traffic-session.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_ENVIRONMENT", "local")
    monkeypatch.setenv("PQC_ADMIN_OPERATOR_ROLES", ROSTER)
    monkeypatch.delenv("PQC_ADMIN_REQUIRE_MFA", raising=False)
    monkeypatch.setattr(app, "_PLATFORM_ADMIN_KEY", "traffic-session-tests-shared-key-0123456789")
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", False)
    monkeypatch.setattr(app, "RATE_LIMIT_MAX_REQUESTS", 100000)
    monkeypatch.setattr(app.limiter, "enabled", False)
    oa.clear_caches()
    app.init_db()
    client = TestClient(app.app, client=("192.0.2.40", 40000))
    yield client, app, monkeypatch
    client.close()
    oa.clear_caches()


def sign_in(client, email=OPS, role="operator", mfa_verified=False):
    raw, _ = oa.create_session(email, role, "sso", email=email, mfa_verified=mfa_verified)
    client.cookies.set(oa.SESSION_COOKIE, raw)
    client.cookies.set(oa.CSRF_COOKIE, oa.csrf_token_for(raw))
    return raw


def test_traffic_endpoints_accept_the_session_cookie_and_writes_need_csrf(api):
    client, _, _ = api
    sign_in(client)
    who = client.get("/platform/whoami")
    assert who.status_code == 200, who.text
    body = who.json()
    assert body["credential_source"] == "operator_session" and body["csrf_token"] and body["mfa"]["elevated"] is False
    assert client.get("/platform/traffic/summary?limit=10").status_code == 200
    assert client.get("/platform/traffic/events?limit=10&source=recent").status_code == 200
    assert client.get("/platform/traffic/export.ndjson?limit=10").status_code == 200
    denied = client.post("/platform/traffic/clear")
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "csrf_failed"
    cleared = client.post("/platform/traffic/clear", headers={"x-csrf-token": body["csrf_token"]})
    assert cleared.status_code == 200, cleared.text


def test_auditor_session_cannot_clear(api):
    client, _, _ = api
    sign_in(client, email="auditor@corp.example", role="auditor")
    token = client.get("/platform/whoami").json()["csrf_token"]
    assert client.get("/platform/traffic/summary").status_code == 200
    assert client.post("/platform/traffic/clear", headers={"x-csrf-token": token}).status_code == 403


def test_pending_mfa_session_is_refused_and_whoami_says_so(api):
    client, _, monkeypatch = api
    monkeypatch.setenv("PQC_ADMIN_REQUIRE_MFA", "1")
    sign_in(client)
    who = client.get("/platform/whoami").json()
    # traffic.js mfaPending(): not elevated and (required or enrolled) -> back to /vendor-admin/.
    assert who["mfa"]["elevated"] is False and who["mfa"]["required"] is True
    res = client.get("/platform/traffic/summary")
    assert res.status_code == 401 and res.json()["detail"]["code"].startswith("mfa_")


def test_traffic_lens_page_wires_cookie_mode():
    js = (ROOT / "backend" / "static_admin" / "traffic.js").read_text(encoding="utf-8")
    for needle in ('"/platform/whoami"', 'credentials:"same-origin"', '"x-csrf-token"', "pqc_admin_csrf=",
                   'location.replace("/vendor-admin/")', '"/platform/session/logout"', "window.TrafficLens"):
        assert needle in js, needle
    shell = (ROOT / "backend" / "static_admin" / "admin-shell.js").read_text(encoding="utf-8")
    assert "window.TrafficLens.api(path)" in shell


PLAYWRIGHT = ROOT / ".tools" / "video" / "node_modules" / "playwright"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(not shutil.which("node") or not PLAYWRIGHT.exists(), reason="needs node and .tools/video Playwright")
def test_traffic_lens_uses_the_session_in_a_real_browser(tmp_path, monkeypatch):
    db = tmp_path / "traffic-browser.db"
    port = _free_port()
    env = {**os.environ, "PQC_SCANNER_DB": str(db), "PQC_MAIN_DB_BACKEND": "sqlite", "PQC_FEATURE_STORE_BACKEND": "sqlite",
           "PQC_ENVIRONMENT": "local", "PQC_ADMIN_OPERATOR_ROLES": ROSTER, "PQC_ADMIN_REQUIRE_MFA": "1",
           "PQC_PLATFORM_ADMIN_KEY": "traffic-browser-tests-shared-key-0123456789", "PQC_ALERT_DISPATCH_ENABLED": "0",
           "PQC_RATE_LIMIT_MAX_REQUESTS": "100000", "PYTHONDONTWRITEBYTECODE": "1"}
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)],
                              cwd=str(ROOT / "backend"), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 120
        while True:
            try:
                with urllib.request.urlopen(base + "/vendor-admin/traffic.html", timeout=5) as res:
                    if res.status == 200:
                        break
            except OSError:
                pass
            assert server.poll() is None, "uvicorn exited during start-up"
            assert time.time() < deadline, "uvicorn did not start"
            time.sleep(1)
        # Mint sessions in the server's database (same SQLite file).
        monkeypatch.setenv("PQC_SCANNER_DB", str(db))
        monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
        monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
        oa.clear_caches()
        verified, _ = oa.create_session(OPS, "operator", "sso", email=OPS, mfa_verified=True)
        pending, _ = oa.create_session(OPS, "operator", "sso", email=OPS, mfa_verified=False)
        run = subprocess.run(["node", str(ROOT / "scripts" / "traffic-lens-session-smoke.js")], cwd=str(ROOT), timeout=240,
                             capture_output=True, text=True,
                             env={**os.environ, "PQC_E2E_BASE_URL": base, "PQC_E2E_OPERATOR_SESSION": verified,
                                  "PQC_E2E_OPERATOR_CSRF": oa.csrf_token_for(verified),
                                  "PQC_E2E_OPERATOR_SESSION_MFA_PENDING": pending})
        assert run.returncode == 0, run.stdout + run.stderr
        assert "session mode passed" in run.stdout and "MFA still pending" in run.stdout
    finally:
        server.terminate()
        try:
            server.wait(timeout=20)
        except subprocess.TimeoutExpired:
            server.kill()
        oa.clear_caches()
