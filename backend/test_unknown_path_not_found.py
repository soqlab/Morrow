"""A path no route answers is a 404 for a signed-out visitor too, not "missing bearer token".

The auth gate asks services/known_routes.py whether any route could answer the path. Only when none
could does it answer 404 itself (the page for a browser, JSON for an API client); every path a route
could answer, in any spelling, still gets the same 401 it always did."""

import os

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import known_routes
from services import public_grade as _grade

HTML = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
API = {"Accept": "application/json"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "notfound.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    _grade._TABLES_READY.clear()
    import app as application

    application.limiter.enabled = False
    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client


UNKNOWN = ["/no/such/page", "/nope", "/no-such-page/", "/a/b/c/d/e", "/console", "/console/settings",
           "/wp-login.php", "/assets/a/b", "/admin/no/such"]


@pytest.mark.parametrize("path", UNKNOWN)
def test_a_browser_gets_the_404_page_for_a_path_nothing_answers(client, path):
    r = client.get(path, headers=HTML)
    assert r.status_code == 404, path
    assert r.headers["content-type"].startswith("text/html")
    assert "<title>Page not found | Morrow</title>" in r.text
    assert "bearer" not in r.text.lower()


@pytest.mark.parametrize("path", UNKNOWN + ["/api/no/such", "/api/nope", "/v1/no/such", "/auth/no-such-thing"])
def test_an_api_client_gets_json_404_for_a_path_nothing_answers(client, path):
    r = client.get(path, headers=API)
    assert r.status_code == 404, path
    assert r.json() == {"detail": "Not Found"}


@pytest.mark.parametrize("path", ["/api/no/such/thing", "/auth/no-such-thing", "/v1/no/such"])
def test_an_unknown_api_path_is_json_even_for_a_browser(client, path):
    r = client.get(path, headers=HTML)
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


def test_the_404_page_keeps_the_security_headers(client):
    r = client.get("/no/such/page", headers={**HTML, "X-Forwarded-Proto": "https"})
    assert r.status_code == 404
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "strict-transport-security" in r.headers


def test_a_bad_token_on_an_unknown_path_is_also_404(client):
    r = client.get("/no/such/page", headers={**API, "Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 404


PROTECTED = ["/auth/me", "/assets", "/assets/some-asset", "/repositories", "/api/v1/compliance/gate"]


@pytest.mark.parametrize("path", PROTECTED)
@pytest.mark.parametrize("headers", [HTML, API], ids=["browser", "api"])
def test_a_real_protected_route_still_answers_401_signed_out(client, path, headers):
    r = client.get(path, headers=headers)
    assert r.status_code == 401, path
    assert r.json() == {"detail": "missing bearer token"}


def test_a_wrong_method_on_a_protected_route_is_still_401(client):
    assert client.delete("/auth/me", headers=API).status_code == 401


@pytest.mark.parametrize("path", [
    "/auth/me/", "/AUTH/ME", "/Auth/Me/", "/auth%2Fme", "/auth%252Fme", "/%61uth/me", "/auth/./me",
    "/x/../auth/me", "/x/%2e%2e/auth/me", "/auth//me", "/./auth/me", "/auth\\me", "/v1/auth/me", "/v1/v1/auth/me",
    "/V1/auth/me", "/auth/me?next=/no/such", "/assets/x%2Ey",
])
def test_no_spelling_of_a_protected_route_slips_past_as_not_found(client, path):
    r = client.get(path, headers=API)
    assert r.status_code == 401, path
    assert r.json() == {"detail": "missing bearer token"}


@pytest.mark.parametrize("path", ["/", "/example.com", "/league", "/trust", "/plain", "/estate/scan/0b6e",
                                  "/healthz", "/auth/config", "/signup", "/legal"])
def test_public_routes_are_unchanged(client, path):
    r = client.get(path, headers=HTML)
    assert r.status_code == 200, path


@pytest.mark.parametrize("path", ["/ui/", "/ui/index.html", "/vendor-admin/"])
def test_the_consoles_are_unchanged(client, path):
    r = client.get(path, headers=HTML)
    assert r.status_code == 200, path
    assert "<title>Page not found" not in r.text


def test_a_missing_console_file_is_the_static_404_not_a_401(client):
    assert client.get("/ui/no-such-file.js").status_code == 404


def test_a_non_domain_single_segment_is_not_the_catch_all(client):
    import app as application

    assert known_routes.exists(application.app, "/example.com")
    assert not known_routes.exists(application.app, "/nope", ignore=application._instrument.is_domain_catch_all)
    assert known_routes.exists(application.app, "/cbom.csv", ignore=application._instrument.is_domain_catch_all)


def test_an_unreadable_route_table_counts_every_path_as_known():
    class _Odd:
        path = None

    class _App:
        routes = [_Odd()]

    assert known_routes.exists(_App(), "/no/such/page")


def test_spellings_cover_the_forms_the_router_collapses():
    forms = known_routes.spellings("/v1/X/../Auth/Me/")
    assert {"/Auth/Me", "/auth/me", "/auth/me/"} <= forms
