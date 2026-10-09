"""Gateway routes through the real application's JWT, tenant and audit middleware."""
import importlib
import time

from fastapi.testclient import TestClient

from test_saas_auth_jwt import _hs256_jwt


def test_gateway_authentication_roles_and_tenant_binding(tmp_path, monkeypatch):
    secret = "gateway-jwt-test-only-not-a-deployment-secret"
    for key, value in {
        "PQC_SCANNER_DB": str(tmp_path / "gateway-jwt.db"), "PQC_MAIN_DB_BACKEND": "sqlite",
        "PQC_FEATURE_STORE_BACKEND": "sqlite", "PQC_AUTH_MODE": "jwt", "PQC_AUTH_REQUIRED": "1",
        "PQC_AUTH_JWT_SECRET": secret, "PQC_AUTH_JWT_ISSUER": "https://gateway-test.example",
        "PQC_AUTH_JWT_AUDIENCE": "gateway-test", "PQC_AUTH_JWT_ALGORITHMS": "HS256",
        "PQC_AUTH_USER_ID_CLAIM": "sub", "PQC_AUTH_ROLE_CLAIM": "role", "PQC_AUTH_ORG_ID_CLAIM": "org_id",
    }.items():
        monkeypatch.setenv(key, value)
    import app
    app = importlib.reload(app)
    app.app.router.on_startup.clear()
    app.app.router.on_shutdown.clear()
    app.init_db()

    def headers(org="gateway-org-a", role="admin", signing_key=secret):
        token = _hs256_jwt({"sub": "gateway-" + role + "-" + org, "role": role, "org_id": org,
                            "iss": "https://gateway-test.example", "aud": "gateway-test", "exp": int(time.time()) + 300}, signing_key)
        return {"Authorization": "Bearer " + token}

    with TestClient(app.app) as client:
        for prefix in ("", "/v1"):
            assert client.get(prefix + "/gateway/sites").status_code == 401
            assert client.get(prefix + "/gateway/sites", headers=headers(signing_key="wrong-key")).status_code == 401
        body = {"website": "www.customer.com", "origin": "origin.customer.com"}
        created = client.post("/gateway/sites", headers=headers(), json=body)
        assert created.status_code == 201, created.text
        site_id = created.json()["id"]
        assert client.get("/v1/gateway/sites", headers=headers()).json()["items"][0]["id"] == site_id
        viewer = {**headers(role="viewer"), "x-user-role": "admin"}
        assert client.post("/gateway/sites", headers=viewer, json=body).status_code == 403
        assert client.post(f"/gateway/sites/{site_id}/bootstrap", headers=viewer).status_code == 403
        assert client.get("/gateway/sites", headers=headers("gateway-org-b")).json()["items"] == []
        assert client.get(f"/gateway/sites/{site_id}", headers=headers("gateway-org-b")).status_code == 404
        spoof = {**headers("gateway-org-b"), "x-org-id": "gateway-org-a"}
        assert client.get(f"/gateway/sites/{site_id}", headers=spoof).status_code in (403, 404)
