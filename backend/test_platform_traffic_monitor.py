from fastapi.testclient import TestClient

import app as fastapi_app


def _reset_traffic_buffers():
    fastapi_app._TRAFFIC_EVENTS.clear()
    fastapi_app._TRAFFIC_BY_IP.clear()


def test_access_policy_and_vendor_admin_shell_are_public_under_required_jwt(monkeypatch):
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "jwt")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", True)

    with TestClient(fastapi_app.app) as client:
        policy = client.get("/auth/access-policy")
        traffic_page = client.get("/vendor-admin/traffic.html")

    assert policy.status_code == 200
    assert policy.json()["production_requirements"]["auth_required"] is True
    assert traffic_page.status_code == 200
    assert "Traffic Monitor" in traffic_page.text


def test_platform_traffic_monitor_requires_platform_key(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    _reset_traffic_buffers()

    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/traffic/summary")

    assert res.status_code == 403


def test_platform_traffic_monitor_records_metadata_without_query_or_payload(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(fastapi_app, "_TRAFFIC_MONITOR_ENABLED", True)
    monkeypatch.setattr(fastapi_app, "_TRUST_PROXY_HEADERS", True)
    _reset_traffic_buffers()

    with TestClient(fastapi_app.app) as client:
        public = client.get(
            "/status?api_key=do-not-store",
            headers={"x-forwarded-for": "203.0.113.10, 10.0.0.1", "user-agent": "traffic-test"},
        )
        summary = client.get("/platform/traffic/summary", headers={"x-platform-key": "test-key"})
        events = client.get(
            "/platform/traffic/events?source_ip=203.0.113.10",
            headers={"x-platform-key": "test-key"},
        )

    assert public.status_code == 200
    assert summary.status_code == 200
    body = summary.json()
    assert body["privacy_boundary"]["request_bodies_stored"] is False
    assert body["privacy_boundary"]["query_strings_stored"] is False
    assert any(item["source_ip"] == "203.0.113.10" for item in body["top_ips"])
    matching_events = [item for item in events.json()["items"] if item["path"] == "/status"]
    assert matching_events
    assert all("api_key" not in item["path"] for item in matching_events)
    assert matching_events[0]["user_agent"] == "traffic-test"


def test_platform_traffic_clear_empties_in_memory_buffer(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    _reset_traffic_buffers()

    with TestClient(fastapi_app.app) as client:
        client.get("/status")
        before = client.get("/platform/traffic/summary", headers={"x-platform-key": "test-key"})
        # Clearing is a write: a shared-key caller must request the operator or owner role explicitly.
        cleared = client.post("/platform/traffic/clear", headers={"x-platform-key": "test-key", "x-platform-admin-role": "operator"})
        after = client.get("/platform/traffic/summary", headers={"x-platform-key": "test-key"})

    assert before.status_code == 200
    assert before.json()["totals"]["events_in_buffer"] >= 1
    assert cleared.status_code == 200
    assert cleared.json()["cleared"]["events"] >= 1
    assert after.status_code == 200
    # The summary request after the clear records itself, so only that one event should remain.
    assert after.json()["totals"]["events_in_buffer"] <= 1


def test_platform_admin_auditor_can_read_but_not_clear_traffic(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    _reset_traffic_buffers()

    with TestClient(fastapi_app.app) as client:
        read = client.get(
            "/platform/traffic/summary",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "auditor"},
        )
        clear = client.post(
            "/platform/traffic/clear",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "auditor"},
        )

    assert read.status_code == 200
    assert clear.status_code == 403
    assert "not allowed" in clear.json()["detail"]


def test_platform_traffic_exports_ndjson_and_otel(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    _reset_traffic_buffers()

    with TestClient(fastapi_app.app) as client:
        client.get("/status", headers={"user-agent": "export-test"})
        ndjson = client.get("/platform/traffic/export.ndjson", headers={"x-platform-key": "test-key"})
        otel = client.get("/platform/traffic/otel", headers={"x-platform-key": "test-key"})

    assert ndjson.status_code == 200
    assert "/status" in ndjson.text
    assert otel.status_code == 200
    assert "resourceLogs" in otel.json()


def test_platform_state_coverage_and_migrate_are_protected(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(fastapi_app, "postgres_main_db_requested", lambda: False)

    with TestClient(fastapi_app.app) as client:
        coverage = client.get("/platform/state/coverage", headers={"x-platform-key": "test-key"})
        auditor_migrate = client.post(
            "/platform/state/migrate",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "auditor"},
            json={"dry_run": True},
        )
        owner_migrate = client.post(
            "/platform/state/migrate",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={"dry_run": True},
        )

    assert coverage.status_code == 200
    assert "sqlite_auxiliary_table_count" in coverage.json()
    assert auditor_migrate.status_code == 403
    assert owner_migrate.status_code == 409
