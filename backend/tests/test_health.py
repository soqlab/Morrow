"""Tests for health + platform endpoints."""


def test_healthz(client, auth):
    r = client.get("/healthz", headers=auth)
    assert r.status_code == 200


def test_health_basic(client, auth):
    r = client.get("/health", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "status" in data


def test_health_full(client, auth):
    r = client.get("/v1/health/full", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "services" in data or "status" in data


def test_root_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
