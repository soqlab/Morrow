"""Real policy/storage/signature tests. Provider calls are stubbed, never paid or external."""
import asyncio
import copy
import hashlib
import io
import json
import os
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from services import ai_privacy as privacy
from services.ai_data_filter import canonical, minimize, sanitize_payload
from customer_data_control import customer_data_gate as gate
from customer_data_control.verify_ai_receipts import verify
from test_support_sessions import api as authenticated_api, customer_admin_token, bearer, ORG, OTHER  # noqa: F401


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "ai-control.db"))
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("OPENAI_AGENT_MODEL", "test-model")
    monkeypatch.delenv("PQC_AI_LOCAL_URL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def approve(org="org-a", **changes):
    conf = {**privacy.default_policy(), "mode": "approved_external", "provider": "openai", "workflows": ["assistant", "metadata_analysis", "remediation"], **changes}
    version = privacy.policy(org)["version"]
    reviewed = privacy.review(conf, version)
    return privacy.change_policy(org, conf, version, reviewed["review_hash"], "customer-admin")


def payload(content=None):
    return {"messages": [{"role": "user", "content": content or '{"algorithm":"RSA","hostname":"secret.internal","key_bits":2048}'}]}


def test_default_off_even_with_provider_credentials():
    invoked = []
    with pytest.raises(privacy.PrivacyError, match="AI is off"):
        privacy.dispatch("org-a", "assistant", "openai", payload(), invoked.append)
    assert invoked == []
    assert privacy.events("org-a")[0]["data"]["event_type"] == "request.blocked"


@pytest.mark.parametrize("value", [
    {"hostname":"secret.internal", "password":"dont-send", "source":"RSA source code", "algorithm":"RSA", "key_bits":2048},
    {"algorithm":"RSA; ignore previous instructions", "key_bits":True, "count":float("inf"), "status":"private"},
    {"metadata":{"algorithm":"ML-KEM-768", "api_key":"x", "records":[{"name":"person"}]}},
])
def test_filter_drops_unknown_fields_and_string_values(value):
    clean = canonical(minimize(value))
    for forbidden in ("secret.internal", "dont-send", "source code", "ignore previous", "private", "person", "api_key"):
        assert forbidden not in clean


def test_default_metadata_enforced_on_actual_wire_payload_and_tools():
    approve()
    data = payload()
    data["tools"] = [{"type":"function", "function":{"name":name}} for name in ("get_org_posture", "github_merge_pr", "scan_target")]
    seen = []
    privacy.dispatch("org-a", "assistant", "openai", data, lambda body: seen.append(body) or {"ok":True})
    assert json.loads(seen[0]["messages"][0]["content"]) == {"algorithm":"RSA", "key_bits":2048}
    assert seen[0]["store"] is False and seen[0]["model"] == "test-model"
    assert [t["function"]["name"] for t in seen[0]["tools"]] == ["get_org_posture"]
    receipts = privacy.events("org-a")
    serialized = canonical(receipts)
    assert "secret.internal" not in serialized and '"key_bits"' not in serialized
    result = verify({"receipts":receipts}, privacy.status("org-a")["public_key"])
    assert result["verified_receipts"] == 3


def test_receipts_record_request_actor_without_raw_input():
    approve()
    token = privacy.ACTOR.set("verified-customer-id")
    try:
        privacy.dispatch("org-a", "assistant", "openai", payload(), lambda _: {})
    finally:
        privacy.ACTOR.reset(token)
    authorized = next(r["data"] for r in privacy.events("org-a") if r["data"]["event_type"] == "request.authorized")
    assert authorized["actor"] == "verified-customer-id"
    assert "secret.internal" not in canonical(authorized)


@pytest.mark.parametrize("content", ["password=let-me-in", '{"api_key":"secret-value"}', "Bearer abcdef", "-----BEGIN PRIVATE KEY-----\nxxx", "sk-12345678901234567890"])
def test_explicit_free_text_still_blocks_recognized_credentials(content):
    approve(free_text=True)
    seen = []
    with pytest.raises(privacy.PrivacyError, match="credential"):
        privacy.dispatch("org-a", "assistant", "openai", payload(content), seen.append)
    assert not seen


def test_receipts_tamper_cross_tenant_and_key_pinning():
    approve(); approve("org-b")
    a, b = privacy.status("org-a"), privacy.status("org-b")
    receipt = privacy.events("org-a")[0]
    assert privacy.receipt_valid(receipt, a["public_key"])
    assert not privacy.receipt_valid(receipt, b["public_key"])
    changed = copy.deepcopy(receipt); changed["data"]["provider"] = "different"
    assert not privacy.receipt_valid(changed, a["public_key"])
    assert all(r["data"]["organization_id"] == "org-b" for r in privacy.events("org-b"))
    assert a["public_key"] != b["public_key"]


def test_policy_cas_and_destination_change_require_reapproval(monkeypatch):
    original = approve()
    conf = {key:original[key] for key in privacy.default_policy()}
    review = privacy.review(conf, 0)
    with pytest.raises(privacy.PrivacyError, match="Policy changed"):
        privacy.change_policy("org-a", conf, 0, review["review_hash"], "admin")
    monkeypatch.setenv("OPENAI_AGENT_MODEL", "different-model")
    with pytest.raises(privacy.PrivacyError, match="reapproval"):
        privacy.authorize("org-a", "assistant")
    with pytest.raises(privacy.PrivacyError, match="Review"):
        privacy.change_policy("org-a", conf, 1, privacy.review(conf, 0)["review_hash"], "admin")


def test_no_fallback_no_unapproved_workflow():
    approve(workflows=["assistant"])
    with pytest.raises(privacy.PrivacyError, match="fallback"):
        privacy.authorize("org-a", "assistant", "anthropic")
    with pytest.raises(privacy.PrivacyError, match="workflow"):
        privacy.authorize("org-a", "remediation")


def test_signing_outage_prevents_send_but_not_stop(monkeypatch):
    approve()
    def broken(*args):
        raise RuntimeError("signing unavailable")
    monkeypatch.setattr(privacy, "_private", broken)
    seen = []
    with pytest.raises(RuntimeError):
        privacy.dispatch("org-a", "assistant", "openai", payload(), seen.append)
    assert not seen
    stopped = privacy.stop("org-a", "admin")
    assert stopped["policy"]["mode"] == "off" and stopped["receipt_recorded"] is False


def test_stop_cancels_queued_request_at_dispatch_boundary(monkeypatch):
    approve()
    original = privacy.connection
    writes = 0
    @contextmanager
    def connection(org, write=False):
        nonlocal writes
        if write:
            writes += 1
        if writes == 2:
            writes += 1
            privacy.stop(org, "admin")
        with original(org, write) as conn:
            yield conn
    monkeypatch.setattr(privacy, "connection", connection)
    seen = []
    with pytest.raises(privacy.PrivacyError, match="cancelled"):
        privacy.dispatch("org-a", "assistant", "openai", payload(), seen.append)
    assert not seen


def test_stop_cannot_recall_already_dispatching_request():
    approve()
    entered, release = threading.Event(), threading.Event()
    def send(body):
        entered.set(); assert release.wait(5); return {"ok":True}
    with ThreadPoolExecutor() as pool:
        future = pool.submit(privacy.dispatch, "org-a", "assistant", "openai", payload(), send)
        assert entered.wait(5)
        try:
            assert privacy.stop("org-a", "admin")["policy"]["mode"] == "off"
            with pytest.raises(privacy.PrivacyError):
                privacy.dispatch("org-a", "assistant", "openai", payload(), lambda _: pytest.fail("must not send"))
        finally:
            release.set()
        assert future.result() == {"ok":True}


def test_response_secrets_withheld_and_outcome_not_misreported():
    approve()
    with pytest.raises(privacy.PrivacyError, match="withheld"):
        privacy.dispatch("org-a", "assistant", "openai", payload(), lambda _: {"content":"password=bad-output"})
    assert privacy.events("org-a")[0]["data"]["event_type"] == "request.output_blocked"
    assert "bad-output" not in canonical(privacy.events("org-a"))


def test_retention_hides_then_prunes_expired_rows(monkeypatch):
    approve(receipt_retention_days=1)
    now = privacy.time.time()
    monkeypatch.setattr(privacy.time, "time", lambda: now + 86401)
    assert privacy.events("org-a") == []
    privacy.prune("org-a")
    with privacy.connection("org-a") as conn:
        assert conn.execute("SELECT count(*) FROM ai_privacy_events").fetchone()[0] == 0


def test_equal_clock_ticks_still_have_verifiable_order_and_pagination(monkeypatch):
    monkeypatch.setattr(privacy.time, "time", lambda: 10000)
    approve()
    for _ in range(2):
        privacy.dispatch("org-a", "assistant", "openai", payload(), lambda _: {})
    receipts = privacy.events("org-a")
    assert verify({"receipts":receipts}, privacy.status("org-a")["public_key"])["verified_receipts"] == 5
    page = privacy.events("org-a", 2)
    next_page = privacy.events("org-a", 10, page[-1]["data"]["created_at"])
    assert len(page + next_page) == 5


def test_customer_hosted_requires_deployment_and_safe_url(monkeypatch):
    monkeypatch.setenv("PQC_AI_LOCAL_URL", "https://model.customer.test/v1/chat/completions")
    monkeypatch.setenv("PQC_AI_LOCAL_MODEL", "customer-model")
    with pytest.raises(privacy.PrivacyError, match="customer deployment"):
        approve(mode="customer_hosted", provider="local")
    monkeypatch.setenv("PQC_AI_DEPLOYMENT_LOCATION", "customer")
    assert approve(mode="customer_hosted", provider="local")["provider"] == "local"
    monkeypatch.setenv("PQC_AI_LOCAL_URL", "https://user:never-display@model.test/path")
    assert "never-display" not in canonical(privacy.status("org-a"))


def test_offline_filter_digest_and_no_network_without_approval(tmp_path, monkeypatch):
    path = tmp_path / "input.json"; path.write_text('{"algorithm":"RSA","key_bits":2048,"hostname":"internal"}')
    proposal = gate.prepare(path, "https://platform.example", 2)
    assert proposal["payload"]["metadata"] == {"algorithm":"RSA", "key_bits":2048}
    monkeypatch.setattr(gate.urllib.request, "build_opener", lambda *a: pytest.fail("network forbidden"))
    with pytest.raises(ValueError, match="Approval"):
        gate.send(proposal, "wrong")
    digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
    proposal["payload"]["expected_version"] = 3
    with pytest.raises(ValueError, match="Approval"):
        gate.send(proposal, digest)
    with pytest.raises(ValueError):
        gate.prepare(path, "http://external.example", 2, True)


def test_prompt_injection_cannot_select_a_write_tool():
    approve()
    from services import ai_agent
    result, _ = asyncio.run(ai_agent._dispatch_tool("github_merge_pr", {"repo":"private"}, "org-a"))
    assert "not allowed" in result["error"]


def test_unknown_blocks_and_oversized_payloads_rejected():
    with pytest.raises(ValueError):
        sanitize_payload({"messages":[{"role":"user","content":[{"type":"image","source":{}}]}]})
    with pytest.raises(ValueError):
        sanitize_payload(payload("x" * 64001))


@pytest.fixture
def client():
    from routers.ai_privacy import create_ai_privacy_router
    app = FastAPI()
    def require_role(request, allowed_roles, **kwargs):
        if request.headers.get("test-role", "viewer") not in allowed_roles:
            raise HTTPException(403)
        # Test harness only. Production uses app._require_role and verified request.state.org_id.
        request.state.org_id = request.headers.get("test-org", "org-a")
        return {"actor_id":"test-admin"}
    app.include_router(create_ai_privacy_router(require_role))
    with TestClient(app) as c:
        yield c


def test_api_approval_preview_export_download_and_read_only_roles(client):
    conf = {**privacy.default_policy(), "mode":"approved_external", "provider":"openai", "workflows":["metadata_analysis"]}
    proposal = {"policy":conf, "expected_version":0}
    assert client.post("/ai-control/policy/review",json=proposal).status_code == 403
    headers = {"test-role":"admin"}
    review = client.post("/ai-control/policy/review",json=proposal,headers=headers).json()
    approved = client.put("/ai-control/policy",json={**proposal,"review_hash":review["review_hash"]},headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.headers["cache-control"] == "no-store"
    preview = client.post("/ai-control/preview",json={"metadata":{"algorithm":"RSA","hostname":"secret"}}).json()
    assert preview["sent"] is False and "secret" not in canonical(preview)
    assert client.get("/ai-control/status",headers={"test-org":"org-b"}).json()["policy"]["mode"] == "off"
    exported = client.get("/ai-control/export").json()
    assert verify(exported, exported["public_key"])["verified_receipts"] == 1
    kit = client.get("/ai-control/customer-kit")
    assert kit.status_code == 200
    with zipfile.ZipFile(io.BytesIO(kit.content)) as archive:
        assert set(archive.namelist()) == {"ai_data_filter.py","customer_data_gate.py","verify_ai_receipts.py","README.md"}
    assert client.post("/ai-control/stop").status_code == 403
    assert client.post("/ai-control/stop",headers=headers).json()["policy"]["mode"] == "off"


def test_expected_policy_version_is_checked_again_before_dispatch():
    approve(); approve(free_text=True)
    with pytest.raises(privacy.PrivacyError, match="changed"):
        privacy.openai_completion("org-a", "metadata_analysis", payload(), expected_version=1)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize("free_text", [False, True])
def test_metadata_preview_matches_dispatch_even_with_free_text(client, monkeypatch, provider, free_text):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    approve(provider=provider, free_text=free_text)
    metadata = {"algorithm": "RSA", "key_bits": 2048, "hostname": "never-send.internal"}
    preview = client.post("/ai-control/preview", json={"metadata": metadata})
    assert preview.status_code == 200, preview.text
    seen = []
    dispatch = privacy.dispatch
    def capture(org, purpose, destination, body, send, **kwargs):
        return dispatch(org, purpose, destination, body, lambda clean: seen.append(clean) or {}, **kwargs)
    monkeypatch.setattr(privacy, "dispatch", capture)
    response = client.post("/ai-control/analyze-metadata", json={"metadata": metadata, "expected_version": preview.json()["policy_version"]})
    assert response.status_code == 200, response.text
    assert seen == [preview.json()["payload"]]
    assert seen[0]["max_tokens"] == 2000
    assert "never-send.internal" not in canonical(seen)
    assert any(r["data"]["event_type"] == "request.response_received" for r in privacy.events("org-a"))


def test_metadata_preview_rejects_empty_facts_and_unrepresentative_workflows(client):
    approve(free_text=True)
    for path in ("preview", "analyze-metadata"):
        body = {"metadata": {"hostname": "not-cryptographic-metadata"}}
        if path == "analyze-metadata":
            body["expected_version"] = 1
        assert client.post("/ai-control/" + path, json=body).status_code == 422
    assert client.post("/ai-control/preview", json={"purpose": "assistant", "metadata": {"algorithm": "RSA"}}).status_code == 422


def test_new_org_support_is_opt_in():
    from services import support_sessions
    assert support_sessions.support_access("new-org")["allowed"] is False




def test_real_jwt_routes_reject_anonymous_and_cross_tenant_overrides(authenticated_api):  # noqa: F811
    client, app = authenticated_api
    token = customer_admin_token(client, app)
    other = customer_admin_token(client, app, org=OTHER, email="other-privacy@example.test")
    assert client.get("/ai-control/status").status_code == 401
    current = client.get("/ai-control/status", headers=bearer(token))
    assert current.status_code == 200, current.text
    assert current.json()["policy"]["organization_id"] == ORG
    forged = client.get("/ai-control/status", headers=bearer(token, OTHER))
    assert forged.status_code == 403 or forged.json()["policy"]["organization_id"] == ORG
    conf = {**privacy.default_policy(), "mode":"approved_external", "provider":"openai", "workflows":["metadata_analysis"]}
    proposal = {"policy":conf, "expected_version":0}
    reviewed = client.post("/ai-control/policy/review",headers=bearer(token),json=proposal)
    assert reviewed.status_code == 200, reviewed.text
    approved = client.put("/v1/ai-control/policy",headers=bearer(token),json={**proposal,"review_hash":reviewed.json()["review_hash"]})
    assert approved.status_code == 200, approved.text
    assert client.get("/ai-control/status",headers=bearer(other)).json()["policy"]["mode"] == "off"
    stopped = client.post("/ai-control/stop",headers=bearer(token))
    assert stopped.status_code == 200 and stopped.json()["policy"]["mode"] == "off"


def test_chunked_oversized_api_body_rejected_before_json_parsing(client):
    def chunks():
        for _ in range(6):
            yield b"x" * 65536
    assert client.post("/ai-control/preview", content=chunks(), headers={"Content-Type":"application/json"}).status_code == 413


def test_real_loopback_model_exchange_filters_and_refuses_redirects(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    received = []
    class Model(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            if self.path == "/redirect":
                self.send_response(307); self.send_header("Location", "/unapproved"); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"choices":[{"message":{"content":"RSA observed"}}]}')
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setenv("PQC_AI_DEPLOYMENT_LOCATION", "customer")
        monkeypatch.setenv("PQC_AI_LOCAL_URL", base + "/v1/chat/completions")
        monkeypatch.setenv("PQC_AI_LOCAL_MODEL", "local-test-model")
        approve(mode="customer_hosted", provider="local")
        reply = privacy.openai_completion("org-a", "assistant", payload())
        assert reply["choices"][0]["message"]["content"] == "RSA observed"
        assert "secret.internal" not in canonical(received)
        monkeypatch.setenv("PQC_AI_LOCAL_URL", base + "/redirect")
        approve(mode="customer_hosted", provider="local")
        with pytest.raises(privacy.PrivacyError, match="redirect"):
            privacy.openai_completion("org-a", "assistant", payload())
        assert len(received) == 2  # No replay to the redirected destination.
    finally:
        server.shutdown(); server.server_close(); worker.join(5)


@pytest.mark.skipif(not os.getenv("PQC_TEST_PG_DSN"), reason="Requires disposable PostgreSQL server")
def test_postgres_restricted_runtime_is_tenant_scoped(monkeypatch):
    import uuid
    import psycopg2
    from psycopg2.extensions import make_dsn
    from services.postgres_rls import build_rls_sql
    suffix = uuid.uuid4().hex
    name, role = "ai_test_" + suffix, "ai_role_" + suffix
    admin = psycopg2.connect(os.environ["PQC_TEST_PG_DSN"]); admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    admin.cursor().execute(f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS")
    original = privacy.store.feature_conn
    try:
        monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "postgres")
        monkeypatch.setattr(privacy.store, "_feature_dsn", lambda: make_dsn(os.environ["PQC_TEST_PG_DSN"], dbname=name))
        privacy.init_tables()
        owner = psycopg2.connect(privacy.store._feature_dsn())
        try:
            with owner.cursor() as cur:
                cur.execute(build_rls_sql(app_role=role))
            owner.commit()
        finally:
            owner.close()
        @contextmanager
        def restricted():
            with original() as conn:
                conn.execute(f"SET ROLE {role}")
                yield conn
        monkeypatch.setattr(privacy.store, "feature_conn", restricted)
        privacy._ready.clear()  # Runtime startup cannot require DDL permissions.
        approve(); approve("org-b")
        assert privacy.events("org-a")[0]["data"]["organization_id"] == "org-a"
        with privacy.connection("org-a") as conn:
            rows = conn.execute("SELECT organization_id FROM ai_privacy_policy").fetchall()
            assert [r[0] for r in rows] == ["org-a"]
        with restricted() as conn:
            assert conn.execute("SELECT count(*) FROM ai_privacy_policy").fetchone()[0] == 0
        privacy.dispatch("org-a", "assistant", "openai", payload(), lambda _: {})
        assert privacy.stop("org-a", "admin")["policy"]["mode"] == "off"
        assert privacy.policy("org-b")["mode"] == "approved_external"
    finally:
        monkeypatch.setattr(privacy.store, "feature_conn", original)
        from db_postgres import close_pools
        close_pools()
        admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
        admin.cursor().execute(f"DROP ROLE {role}")
        admin.close()
