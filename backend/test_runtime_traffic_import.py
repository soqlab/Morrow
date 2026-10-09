import os
import tempfile
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

import app as fastapi_app
from db import get_asset, init_db, reset_current_organization_id, set_current_organization_id
from services.runtime_observations import parse_runtime_log_line


def _setup_tmp_db():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    tmp_db.close()
    os.environ["PQC_MAIN_DB_BACKEND"] = ""
    os.environ["PQC_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    @asynccontextmanager
    async def _test_lifespan(_app):
        yield

    fastapi_app.app.router.lifespan_context = _test_lifespan
    init_db()
    return tmp_db


def _headers(role="operator"):
    return {"x-user-role": role, "x-user-id": f"{role}-user"}


def test_runtime_traffic_import_creates_observed_assets_and_history():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        payload = {
            "source": "cloudflare-logpush",
            "provider": "cloudflare",
            "create_assets": True,
            "default_owner": "platform",
            "default_team": "edge",
            "default_environment": "prod",
            "default_criticality": "high",
            "default_confidentiality_lifetime": "10y+",
            "records": [
                {
                    "url": "https://portal.example.com/patient/login",
                    "method": "GET",
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "status_code": 200,
                    "count": 17,
                    "timestamp": "2026-05-23T10:00:00Z",
                },
                {
                    "host": "api.example.com",
                    "port": 443,
                    "path": "/v1/records",
                    "protocol": "https",
                    "tls_version": "TLSv1.2",
                    "count": 3,
                    "timestamp": "2026-05-23T10:01:00Z",
                },
            ],
        }
        headers = {**_headers("operator"), "Idempotency-Key": "runtime-import-1"}
        with TestClient(fastapi_app.app) as client:
            imported = client.post("/v1/runtime/traffic/import", headers=headers, json=payload)
            assert imported.status_code == 200
            body = imported.json()
            assert body["valid"] == 2
            assert body["stored"] == 2
            assert body["assets_upserted"] == 2
            assert body["summary"]["asset_count"] == 2

            replay = client.post("/v1/runtime/traffic/import", headers=headers, json=payload)
            assert replay.status_code == 200
            assert replay.json() == body

            observations = client.get(
                "/v1/runtime/traffic/observations",
                headers=_headers("viewer"),
                params={"asset_key": "portal.example.com:443"},
            )
            assert observations.status_code == 200
            items = observations.json()["items"]
            assert len(items) == 1
            assert items[0]["source"] == "cloudflare-logpush"
            assert items[0]["provider"] == "cloudflare"
            assert items[0]["observed_count"] == 17

            assets = client.get("/v1/runtime/assets", headers=_headers("viewer"))
            assert assets.status_code == 200
            assert assets.json()["count"] == 2

        asset = get_asset("portal.example.com:443")
        assert asset is not None
        assert asset["owner"] == "platform"
        assert "runtime-observed" in asset["tags"]
        assert asset["metadata"]["observed_from_runtime"] is True
        assert asset["metadata"]["runtime_observed_count"] == 17
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_runtime_traffic_import_rejects_invalid_reused_idempotency_key():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        headers = {**_headers("operator"), "Idempotency-Key": "runtime-import-conflict"}
        first_payload = {"records": [{"host": "one.example.com", "port": 443}]}
        second_payload = {"records": [{"host": "two.example.com", "port": 443}]}
        with TestClient(fastapi_app.app) as client:
            first = client.post("/v1/runtime/traffic/import", headers=headers, json=first_payload)
            assert first.status_code == 200
            conflict = client.post("/v1/runtime/traffic/import", headers=headers, json=second_payload)
            assert conflict.status_code == 409
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_runtime_log_parser_supports_cloudflare_json_and_text_logs():
    cf = parse_runtime_log_line(
        '{"ClientRequestHost":"portal.example.com","ClientRequestURI":"/login","ClientRequestMethod":"GET","ClientSSLProtocol":"TLSv1.3","ClientSSLCipher":"TLS_AES_256_GCM_SHA384","EdgeResponseStatus":200}',
        source="cloudflare-logpush",
        provider="cloudflare",
        log_format="cloudflare_json",
    )
    assert cf["ok"] is True
    assert cf["asset_key"] == "portal.example.com:443"
    assert cf["path"] == "/login"
    assert cf["tls_version"] == "TLSv1.3"
    text = parse_runtime_log_line(
        '2026-05-23T10:00:00Z GET https://api.example.com/v1/patients 200 TLSv1.2',
        source="envoy-access",
        provider="envoy",
        log_format="text",
    )
    assert text["ok"] is True
    assert text["asset_key"] == "api.example.com:443"
    assert text["method"] == "GET"
    assert text["status_code"] == 200


def test_runtime_traffic_import_accepts_raw_log_lines():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        payload = {
            "source": "cloudflare-logpush",
            "provider": "cloudflare",
            "log_format": "cloudflare_json",
            "create_assets": True,
            "raw_logs": [
                '{"ClientRequestHost":"portal.example.com","ClientRequestURI":"/login","ClientRequestMethod":"GET","ClientSSLProtocol":"TLSv1.3","ClientSSLCipher":"TLS_AES_256_GCM_SHA384","EdgeResponseStatus":200}',
                "not a useful traffic line",
            ],
        }
        with TestClient(fastapi_app.app) as client:
            imported = client.post("/v1/runtime/traffic/import", headers=_headers("operator"), json=payload)
            assert imported.status_code == 200
            body = imported.json()
            assert body["raw_logs_received"] == 2
            assert body["raw_logs_parsed"] == 1
            assert body["valid"] == 1
            assert body["invalid"] == 1
            assert body["assets_upserted"] == 1
        asset = get_asset("portal.example.com:443")
        assert asset is not None
        assert asset["metadata"]["runtime_sources"] == ["cloudflare-logpush"]
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_runtime_traffic_topology_flags_legacy_crypto_flows():
    tmp_db = _setup_tmp_db()
    token = set_current_organization_id(fastapi_app.DEFAULT_ORG_ID)
    try:
        payload = {
            "source": "mesh-access",
            "provider": "envoy",
            "records": [
                {
                    "host": "legacy.internal.example",
                    "port": 443,
                    "protocol": "https",
                    "path": "/orders",
                    "tls_version": "TLSv1.0",
                    "cipher": "RC4-SHA",
                    "count": 9,
                    "timestamp": "2026-05-23T10:00:00Z",
                },
                {
                    "host": "api.example.com",
                    "port": 443,
                    "protocol": "https",
                    "path": "/health",
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "count": 5,
                    "timestamp": "2026-05-23T10:01:00Z",
                },
            ],
        }
        with TestClient(fastapi_app.app) as client:
            imported = client.post("/v1/runtime/traffic/import", headers=_headers("operator"), json=payload)
            assert imported.status_code == 200
            topology = client.get("/v1/runtime/traffic/topology", headers=_headers("viewer"))
            assert topology.status_code == 200
            body = topology.json()
            assert body["summary"]["edges"] == 2
            assert body["summary"]["risky_edges"] >= 1
            assert body["summary"]["legacy_tls_edges"] == 1
            legacy = next(edge for edge in body["edges"] if edge["asset_key"] == "legacy.internal.example:443")
            assert legacy["risk"] == "critical"
            assert "legacy_tls" in legacy["reasons"]
            assert "weak_cipher" in legacy["reasons"]
    finally:
        reset_current_organization_id(token)
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
