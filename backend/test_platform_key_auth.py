"""The platform admin key must authenticate /platform/* -- and nothing else.

The platform key is a standalone vendor-operator credential: the vendor admin portal and
scripts/check-go-live-gate.ps1 present it and have no user token to offer. But /platform/* is not an
auth-public path, so under PQC_AUTH_REQUIRED=1 -- the setting the hardening guide prescribes -- the
auth middleware rejected those requests with 401 before the endpoint's own key check ran. The
go-live gate was unreachable on exactly the configuration it exists to certify.

Widening authentication is the kind of change that must not drift, so these tests pin both halves:
the key works for /platform/*, and it does not authenticate anything else.
"""
import importlib
import os

import pytest
from fastapi.testclient import TestClient

PLATFORM_KEY = "test-platform-key-long-enough-for-production-use"

_ENV_KEYS = (
    "PQC_SCANNER_DB",
    "PQC_AUTH_MODE",
    "PQC_AUTH_REQUIRED",
    "PQC_AUTH_JWT_SECRET",
    "PQC_AUTH_JWT_ISSUER",
    "PQC_AUTH_JWT_AUDIENCE",
    "PQC_AUTH_JWT_ALGORITHMS",
    "PQC_PLATFORM_ADMIN_KEY",
    "PQC_ALLOW_PLATFORM_KEY_QUERY",
)


@pytest.fixture()
def client(tmp_path):
    old_env = {k: os.environ.get(k) for k in _ENV_KEYS}
    os.environ["PQC_SCANNER_DB"] = str(tmp_path / "platform_key_auth.db")
    # Authentication enforced, as in production.
    os.environ["PQC_AUTH_MODE"] = "jwt"
    os.environ["PQC_AUTH_REQUIRED"] = "1"
    os.environ["PQC_AUTH_JWT_SECRET"] = "test-secret"
    os.environ["PQC_AUTH_JWT_ISSUER"] = "https://issuer.example"
    os.environ["PQC_AUTH_JWT_AUDIENCE"] = "pqc-ui"
    os.environ["PQC_AUTH_JWT_ALGORITHMS"] = "HS256"
    os.environ["PQC_PLATFORM_ADMIN_KEY"] = PLATFORM_KEY
    os.environ["PQC_ALLOW_PLATFORM_KEY_QUERY"] = "0"

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


def test_platform_key_reaches_the_go_live_gate(client):
    """The gate must be usable with only the platform key, as check-go-live-gate.ps1 sends it."""
    res = client.get("/platform/go-live-gate", headers={"x-platform-key": PLATFORM_KEY})

    assert res.status_code == 200, res.text
    body = res.json()
    assert "status" in body and "go_live_allowed" in body


def test_platform_key_reaches_readiness(client):
    res = client.get("/platform/readiness", headers={"x-platform-key": PLATFORM_KEY})

    assert res.status_code == 200, res.text


def test_missing_platform_key_is_still_rejected(client):
    res = client.get("/platform/go-live-gate")

    assert res.status_code == 401


def test_wrong_platform_key_is_still_rejected(client):
    res = client.get("/platform/go-live-gate", headers={"x-platform-key": "not-the-key"})

    assert res.status_code == 401


@pytest.mark.parametrize("raw", [b"caf\xe9", b"cl\xe9-priv\xe9e", b"\xea\xeb\xfc\xf7"])
def test_non_ascii_platform_key_is_rejected_not_a_server_error(client, raw):
    """A non-ASCII key must be rejected, not raise.

    Header values are passed as bytes because that is what a raw client can put on the wire: HTTP
    header bytes are decoded as latin-1, so 0xE9 reaches the application as the str "é". Passing a
    non-ASCII str here instead fails inside httpx before the request is ever sent, which tests the
    client rather than the server.

    hmac.compare_digest raises TypeError when given non-ASCII str, and because this comparison now
    runs in the auth middleware, that would have become a 500 triggered by any unauthenticated
    caller. Comparing UTF-8 bytes makes it total.
    """
    res = client.get("/platform/go-live-gate", headers={"x-platform-key": raw})

    assert res.status_code == 401, f"{raw!r} produced {res.status_code}"


def test_platform_key_does_not_authenticate_product_routes(client):
    """The key must not become a general-purpose bypass for tenant data."""
    for path in ("/assets", "/scans", "/organizations", "/remediations"):
        res = client.get(path, headers={"x-platform-key": PLATFORM_KEY})
        assert res.status_code == 401, f"{path} accepted the platform key as user authentication"


def test_platform_key_does_not_authenticate_admin_routes(client):
    """/admin/* is user-role protected, not platform-key protected."""
    res = client.get("/admin/postgres-rls/verify", headers={"x-platform-key": PLATFORM_KEY})

    assert res.status_code == 401


def test_query_string_platform_key_does_not_authenticate(client):
    """Only the header counts. Keys in query strings land in access logs and referrers."""
    res = client.get(f"/platform/go-live-gate?platform_key={PLATFORM_KEY}")

    assert res.status_code == 401


def test_public_status_endpoint_needs_no_credential(client):
    """/status is documented as suitable for a public status page and must stay reachable."""
    res = client.get("/status")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") in {"operational", "degraded"}
    # It must stay minimal: no component internals, which is what /health/deep is for.
    assert set(body.get("checks", {})) <= {"api", "database"}


def test_deep_health_still_requires_authentication(client):
    """/health/deep reports component internals, so making /status public must not expose it."""
    res = client.get("/health/deep")

    assert res.status_code == 401


def test_favicon_is_served_without_authentication(client):
    """The console references /favicon.svg, so it must resolve on a hardened deployment."""
    for path in ("/favicon.svg", "/favicon.ico"):
        res = client.get(path)
        assert res.status_code == 200, f"{path} -> {res.status_code}"
