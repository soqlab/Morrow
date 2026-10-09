import base64
import hashlib
import hmac
import io
import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from routers.gateway import create_gateway_router
from services import gateway
from services import gateway_network as network
from services.e2e_readiness import build_e2e_readiness


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "gateway.db"))
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_VAULT_MASTER_KEY", Fernet.generate_key().decode())
    app = FastAPI()

    def role(request, allowed_roles, **kwargs):
        if request.headers.get("x-user-role", "viewer") not in allowed_roles:
            raise HTTPException(403)
        request.state.org_id = request.headers.get("x-org-id", "org-a")
        return {"actor_id": "test-user"}

    app.include_router(create_gateway_router(role))
    with TestClient(app) as value:
        yield value


ADMIN = {"x-user-role": "admin", "x-org-id": "org-a"}
OPERATOR = {**ADMIN, "x-user-role": "operator"}


def create(client):
    response = client.post("/gateway/sites", headers=ADMIN,
                           json={"website": "https://www.customer.com", "origin": "https://origin.customer.com"})
    assert response.status_code == 201, response.text
    return response.json()


def owned(client, monkeypatch):
    site = create(client)
    monkeypatch.setattr(network, "txt_values", lambda host: [site["challenge"]])
    result = client.post(f"/gateway/sites/{site['id']}/ownership", headers=ADMIN)
    assert result.json()["coverage"]["ownership"] == "verified"
    return result.json()


def setup_runtime(client, monkeypatch):
    site = owned(client, monkeypatch)
    result = client.post(f"/gateway/sites/{site['id']}/bootstrap", headers=ADMIN)
    assert result.status_code == 200, result.text
    secret = result.json()["secret"]
    runtime = {"policy": site["policy"], "bad_signature": False, "replayed": False, "puts": 0, "fail": False}

    def request(host, path, **kwargs):
        if runtime["fail"]:
            raise network.CheckError("HTTPS check failed")
        if path.startswith("/__airlock/challenge"):
            payload = {"nonce": parse_qs(urlsplit(path).query)["nonce"][0], "time": time.time(),
                       "site_id": site["id"], "mode": runtime["policy"]["mode"], "config_hash": gateway.digest(runtime["policy"]),
                       "instance": "fixture-node", "waf_self_test": True}
            if runtime["replayed"]:
                payload["nonce"] = "old_nonce"
            payload.update(runtime.get("proof_override", {}))
            raw = gateway.canonical(payload).encode()
            signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            return {"status": 200, "body": json.dumps({"payload": base64.b64encode(raw).decode(), "signature": "bad" if runtime["bad_signature"] else signature}).encode()}
        if path == "/__airlock/policy":
            assert kwargs["headers"]["Authorization"] == "Bearer " + secret
            runtime["puts"] += 1
            runtime["policy"] = json.loads(kwargs["body"])
            return {"status": 200, "body": b"{}"}
        if path == "/__airlock/statistics":
            assert kwargs["headers"]["Authorization"] == "Bearer " + secret
            if kwargs.get("method") == "DELETE":
                return {"status": 204, "body": b""}
            return {"status": 200, "body": json.dumps({"requests": 12, "matched": 3, "blocked": 0, "rule_counts": {"941100": 3}, "password": "SHOULD_NOT_BE_RETAINED",
                    "instance": "fixture-node", "config_hash": gateway.digest(runtime["policy"]), **runtime.get("stats_override", {})}).encode()}
        return {"status": 200, "body": b"private response discarded", "latency_ms": 12.5}

    monkeypatch.setattr(network, "request", request)
    return site, secret, runtime


def clear_cooldown(site):
    with gateway.connection("org-a") as conn:
        value = gateway._read(conn, "org-a", site["id"])
        for key in list(value):
            if key.startswith("last_"):
                value[key] = 0
        gateway._save(conn, "org-a", value)
        conn.commit()


def test_onboarding_is_not_active_protection_and_is_tenant_isolated(client, monkeypatch):
    site = create(client)
    assert site["coverage"]["filtering"] == "unknown"
    assert site["coverage"]["visitor_pqc"] == "unknown"
    assert len(site["dns_records"]) == 2
    assert client.get("/gateway/sites", headers={**ADMIN, "x-org-id": "org-b"}).json()["items"] == []
    for suffix, method in [("", "get"), ("/history", "get"), ("/ownership", "post"), ("/bootstrap", "post"), ("/probe", "post")]:
        response = getattr(client, method)(f"/gateway/sites/{site['id']}" + suffix, headers={**ADMIN, "x-org-id": "org-b"})
        assert response.status_code == 404
    monkeypatch.setattr(network, "request", lambda *a, **k: pytest.fail("unverified site caused an HTTP request"))
    assert client.post(f"/gateway/sites/{site['id']}/probe", headers=ADMIN).status_code == 409
    assert client.post(f"/gateway/sites/{site['id']}/bootstrap", headers=ADMIN).status_code == 409
    assert client.post("/gateway/sites", json={"website": "other.customer.com", "origin": "origin.customer.com"}).status_code == 403


def test_ownership_checks_both_domains_and_does_not_trust_client_booleans(client, monkeypatch):
    site = create(client)
    monkeypatch.setattr(network, "txt_values", lambda host: [site["challenge"]] if host.startswith("_airlock-gateway.www.") else [])
    response = client.post(f"/gateway/sites/{site['id']}/ownership", headers=ADMIN)
    assert response.json()["ownership_verified_at"] is None
    assert client.post("/gateway/sites", headers=ADMIN, json={"website": "fake.customer.com", "origin": "origin.customer.com", "verified": True}).status_code == 422


def test_provisioning_is_admin_only_encrypted_and_not_repeated_on_reads(client, monkeypatch):
    site, secret, _ = setup_runtime(client, monkeypatch)
    assert client.post(f"/gateway/sites/{site['id']}/bootstrap", headers=OPERATOR).status_code == 403
    response = client.get(f"/gateway/sites/{site['id']}", headers=ADMIN)
    assert response.headers["cache-control"] == "no-store"
    assert secret not in response.text and "sealed_key" not in response.text
    with gateway.connection("org-a") as conn:
        raw = conn.execute("SELECT data FROM gateway_sites WHERE id=?", (site["id"],)).fetchone()[0]
        assert secret not in raw and "sealed_key" in raw


def test_signed_probe_freshness_failure_and_no_sensitive_statistics(client, monkeypatch):
    site, _, runtime = setup_runtime(client, monkeypatch)
    base = f"/gateway/sites/{site['id']}"
    result = client.post(base + "/probe", headers=ADMIN).json()
    assert result["coverage"]["filtering"] == "observe"
    assert result["statistics"]["requests"] == 12
    assert "SHOULD_NOT_BE_RETAINED" not in json.dumps(result)
    for field in ("bad_signature", "replayed", "fail"):
        clear_cooldown(site)
        runtime[field] = True
        result = client.post(base + "/probe", headers=ADMIN).json()
        assert result["coverage"]["filtering"] == "unknown"
        assert "statistics" not in result
        runtime[field] = False
    clear_cooldown(site)
    client.post(base + "/probe", headers=ADMIN)
    with gateway.connection("org-a") as conn:
        value = gateway._read(conn, "org-a", site["id"])
        value["runtime"]["checked_at"] -= 301
        gateway._save(conn, "org-a", value); conn.commit()
    assert client.get(base, headers=ADMIN).json()["coverage"]["filtering"] == "unknown"


def test_enforcement_requires_reviews_then_actual_apply_and_rollback(client, monkeypatch):
    site, _, runtime = setup_runtime(client, monkeypatch)
    base = f"/gateway/sites/{site['id']}"
    change = {"expected_version": 1, "mode": "enforce", "reason": "Approved pilot deployment"}
    assert client.put(base + "/policy", headers=ADMIN, json=change).status_code == 409
    assert client.put(base + "/policy", headers=OPERATOR, json=change).status_code == 403
    checks = {"approved": True, "cases": [{"name": "Homepage", "path": "/", "expected_status": 200}]}
    assert client.post(base + "/compatibility", headers=OPERATOR, json=checks).json()["compatibility"]["passed"]
    journeys = {"checks": [{"kind": kind, "result": "passed", "evidence": "Customer staging report #123"} for kind in ("login", "forms", "uploads", "websocket")]}
    assert client.post(base + "/journeys", headers=OPERATOR, json=journeys).status_code == 200
    assert client.post(base + "/probe", headers=OPERATOR).json()["coverage"]["filtering"] == "observe"
    published = client.put(base + "/policy", headers=ADMIN, json=change)
    assert published.status_code == 200, published.text
    assert published.json()["coverage"]["filtering"] == "unknown"
    assert runtime["policy"]["mode"] == "observe"
    assert client.put(base + "/policy", headers=ADMIN, json=change).status_code == 409
    clear_cooldown(site)
    applied = client.post(base + "/apply", headers=ADMIN).json()
    assert runtime["puts"] == 1 and applied["coverage"]["filtering"] == "enforce"
    rolled = client.post(base + "/rollback", headers=ADMIN, json={"expected_version": 2, "version": 1, "reason": "Restore reviewed observation policy"}).json()
    assert rolled["policy"]["version"] == 3 and rolled["policy"]["mode"] == "observe"
    assert rolled["coverage"]["filtering"] == "unknown"
    clear_cooldown(site)
    assert client.post(base + "/apply", headers=ADMIN).json()["coverage"]["filtering"] == "observe"
    assert len(client.get(base + "/history", headers=ADMIN).json()["items"]) == 3


def test_remote_apply_does_not_send_credential_before_gateway_authentication(client, monkeypatch):
    site, _, runtime = setup_runtime(client, monkeypatch)
    runtime["bad_signature"] = True
    response = client.post(f"/gateway/sites/{site['id']}/apply", headers=ADMIN)
    assert response.json()["coverage"]["filtering"] == "unknown"
    assert runtime["puts"] == 0


@pytest.mark.parametrize("override", [{"config_hash": []}, {"instance": "secret?url=private"}, {"mode": "protected"}, {"waf_self_test": "true"}, {"time": float("inf")}])
def test_malformed_signed_proof_never_becomes_coverage(client, monkeypatch, override):
    site, _, runtime = setup_runtime(client, monkeypatch)
    runtime["proof_override"] = override
    response = client.post(f"/gateway/sites/{site['id']}/probe", headers=ADMIN)
    assert response.status_code == 200
    assert response.json()["coverage"]["filtering"] == "unknown"
    assert "statistics" not in response.json()


@pytest.mark.parametrize("override", [{"config_hash": "0" * 64}, {"requests": -1}, {"requests": True}, {"requests": 10001}, {"rule_counts": []}, {"rule_counts": {"secret-name": 1}}])
def test_malformed_or_wrong_replica_policy_statistics_are_rejected(client, monkeypatch, override):
    site, _, runtime = setup_runtime(client, monkeypatch)
    runtime["stats_override"] = override
    result = client.post(f"/gateway/sites/{site['id']}/probe", headers=ADMIN).json()
    assert "statistics" not in result
    assert result["coverage"]["filtering"] == "unknown"


def test_stale_network_result_cannot_overwrite_concurrent_policy_edit(client):
    site = create(client)
    snapshot = gateway._snapshot("org-a", site["id"], "runtime_check")
    gateway.change_policy("org-a", site["id"], {"retention_hours": 0}, "other-admin", "Stop aggregate retention", 1)
    snapshot["runtime"] = {"checked_at": time.time()}
    with pytest.raises(gateway.GatewayError, match="Site changed"):
        gateway._store_snapshot("org-a", snapshot)
    assert gateway.get_site("org-a", site["id"])["policy"]["retention_hours"] == 0


@pytest.mark.parametrize("url", ["http://customer.com", "https://127.0.0.1", "https://[::1]", "https://user:pass@customer.com", "https://customer.com:8443", "https://customer.com/?token=x", "https://customer.com/#x", "https://metadata.google.internal", "https://foo.local", "https://customer.com\\@evil.com"])
def test_unsafe_origins_rejected(url):
    with pytest.raises(network.CheckError):
        network.origin_url(url)


def test_mixed_dns_answers_rejected_before_connecting(monkeypatch):
    class Resolver:
        def resolve(self, host, kind):
            return ["8.8.8.8", "169.254.169.254"] if kind == "A" else []
    monkeypatch.setattr(network.dns.resolver, "Resolver", Resolver)
    with pytest.raises(network.CheckError):
        network.public_ips("www.customer.com")


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "100.64.0.1", "192.88.99.1", "::1", "::ffff:8.8.8.8", "64:ff9b::a9fe:a9fe", "2001::1", "2002::1", "3fff::1"])
def test_special_and_transition_addresses_are_not_public_origins(address):
    assert not network.public_address(address)


def test_global_addresses_remain_available():
    assert network.public_address("8.8.8.8")
    assert network.public_address("2606:4700:4700::1111")


def test_https_pins_dns_checks_certificates_and_does_not_follow_redirects(monkeypatch):
    called = []
    monkeypatch.setattr(network, "public_ips", lambda host: ["8.8.8.8"])
    class Pool:
        def __init__(self, ip, **kwargs):
            assert ip == "8.8.8.8"
            assert kwargs["server_hostname"] == kwargs["assert_hostname"] == "www.customer.com"
            assert kwargs["cert_reqs"] == "CERT_REQUIRED"
        def urlopen(self, method, path, **kwargs):
            called.append(path)
            assert kwargs["redirect"] is False and kwargs["retries"] is False
            value = io.BytesIO(b"redirect body")
            value.status = 302
            return value
        def close(self):
            pass
    monkeypatch.setattr(network.urllib3, "HTTPSConnectionPool", Pool)
    result = network.request("www.customer.com", "/")
    assert result["status"] == 302 and called == ["/"]


def test_inert_inventory_cannot_prove_security_controls():
    report = build_e2e_readiness(auth_configured=True, repositories=[{}], github_installations=[{}], scans=[{}],
                                assets=[{}], remediations=[{}], validations=[], pr_events=[], audit_events=[{}], webhook_events=[])
    for item in report["items"]:
        if item["id"] in {"regression", "rbac", "multi_tenancy", "vault", "persistence", "security_negative"}:
            assert not item["ready"]
