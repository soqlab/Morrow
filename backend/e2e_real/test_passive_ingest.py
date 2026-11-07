"""Passive TLS discovery from real proxy logs: nginx logs shipped by Fluent Bit and Envoy logs shipped
by Vector, each with its own ingest token, into POST /v1/runtime/passive/ingest."""
from __future__ import annotations

import pytest

from .conftest import CLASSIC_GROUPS, compose, set_nginx_groups, wait_for

NGINX = "nginx.e2e.morrow.test"
ENVOY = "envoy.e2e.morrow.test"


@pytest.fixture(scope="module")
def shippers(api):
    set_nginx_groups(CLASSIC_GROUPS)  # the kill-switch and proof tests leave nginx on hybrid groups
    nginx_token = api.post("/v1/runtime/passive/tokens", json={"name": "e2e fluent-bit", "default_format": "nginx"})
    envoy_token = api.post("/v1/runtime/passive/tokens", json={"name": "e2e vector", "default_format": "envoy"})
    assert nginx_token["secret"].startswith("mpi_") and envoy_token["secret"].startswith("mpi_")
    env = {"MORROW_E2E_NGINX_INGEST_TOKEN": nginx_token["secret"],
           "MORROW_E2E_ENVOY_INGEST_TOKEN": envoy_token["secret"]}
    compose("--profile", "shippers", "up", "-d", "--force-recreate", "fluent-bit", "vector", env=env)
    yield {"nginx": nginx_token, "envoy": envoy_token}
    compose("--profile", "shippers", "rm", "-sf", "fluent-bit", "vector", env=env)


def _endpoints(api, host):
    return api.get("/v1/runtime/passive/endpoints", params={"host": host})["items"]


def _find(items, port, group):
    return next((i for i in items if int(i["port"]) == port
                 and str(i.get("key_exchange_group") or "").lower() == group.lower()), None)


def test_ingest_refuses_a_missing_or_wrong_token(api):
    r = api.http.post("/v1/runtime/passive/ingest?format=nginx", content=b"{}")
    assert r.status_code == 401
    r = api.http.post("/v1/runtime/passive/ingest?format=nginx", content=b"{}",
                      headers={"Authorization": "Bearer mpi_not-a-real-token"})
    assert r.status_code == 401


def test_nginx_logs_through_fluent_bit(api, shippers):
    # nginx is classical-only at session start (X25519:prime256v1), so modern clients land on X25519.
    row = wait_for(lambda: _find(_endpoints(api, NGINX), 443, "X25519"), 120, what="nginx endpoint from Fluent Bit")
    assert row["tls_version"] == "TLSv1.3"
    assert row["cipher"].startswith("TLS_AES_")
    assert row["pq_status"] == "quantum_vulnerable"
    assert row["source_format"] == "nginx"


def test_envoy_logs_through_vector(api, shippers):
    pq = wait_for(lambda: _find(_endpoints(api, ENVOY), 11443, "X25519MLKEM768"), 120,
                  what="Envoy hybrid listener from Vector")
    assert pq["tls_version"] == "TLSv1.3" and pq["pq_status"] == "pq_safe_key_exchange"
    assert pq["source_format"] == "envoy"
    classic = wait_for(lambda: _find(_endpoints(api, ENVOY), 10443, "X25519"), 60, what="Envoy classic listener")
    assert classic["pq_status"] == "quantum_vulnerable"


def test_passive_assets_land_in_the_inventory(api, shippers):
    def asset():
        a = api.get(f"/assets/{ENVOY}:11443", expect=None)
        return a if isinstance(a, dict) and "passive-discovered" in (a.get("tags") or []) else None

    found = wait_for(asset, 120, what="inventory asset with source passive")
    assert "passive" in ((found.get("metadata") or {}).get("discovery_sources") or [])
