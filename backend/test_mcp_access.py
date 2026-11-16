"""AI assistants over MCP: services/mcp_access.py on the server, tools/morrow_mcp on the user's machine.

The server half: off unless MORROW_MCP_ENABLED=1 (so off on the hosted service), a read-only key
only, GET only, every call journaled in the hash-chained audit log with the tool and key id. The
client half runs against this app through FastAPI's TestClient, so each tool is checked end to end.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import time

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from services import api_keys, audit_chain, mcp_access, org_rate_limits, security_journal

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "tools" / "morrow_mcp"))
from morrow_mcp import tools as mt  # noqa: E402

SECRET = "mcp-tests-jwt-secret-0123456789-abcdefghijklmnopqrstuvwxyz"
ORG = "org-mcp"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "mcp.db"))
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("MORROW_MCP_ENABLED", "1")
    for name in ("REDIS_URL", "CELERY_BROKER_URL", "MORROW_ORG_DEFAULT_API_CALLS_PER_MIN", "MORROW_ORG_DEFAULT_SCANS_PER_HOUR",
                 "MORROW_ORG_RATE_LIMITS_ENABLED", "MORROW_ORG_RATE_LIMIT_CACHE_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": SECRET,
        "AUTH_JWT_ISSUER": "", "AUTH_JWT_AUDIENCE": "", "API_KEY": "", "PRODUCTION_ENVIRONMENT": False,
        "RATE_LIMIT_MAX_REQUESTS": 100000,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    security_journal.init_tables()
    api_keys.init_tables()
    org_rate_limits.reset()
    client = TestClient(app.app, client=("192.0.2.41", 41000))
    yield client
    client.close()
    org_rate_limits.reset()


def key(scopes, org=ORG):
    record, secret = api_keys.create_key(org, "assistant", scopes)
    return record, secret


def mcp(secret, tool="inventory_summary"):
    return {"authorization": "Bearer " + secret, "x-client": f"mcp/{tool}"}


def journal(org=ORG):
    return [e for e in audit_chain.iter_entries(org) if e["action"] == "mcp.tool_call"]


# ── the server ─────────────────────────────────────────────────────────────────────────────────


def test_off_unless_enabled_as_on_the_hosted_service(api, monkeypatch):
    _, secret = key(["read"])
    for value in ("", "0", "true", "yes"):
        monkeypatch.setenv("MORROW_MCP_ENABLED", value)
        res = api.get("/assets", headers=mcp(secret))
        assert res.status_code == 403 and res.json()["detail"] == mcp_access.OFF
    monkeypatch.delenv("MORROW_MCP_ENABLED")
    assert api.get("/assets", headers=mcp(secret)).status_code == 403
    # The same key without the marker is an ordinary read-only API key, unaffected by the flag.
    assert api.get("/assets", headers={"authorization": "Bearer " + secret}).status_code == 200
    assert journal() == []


def test_read_only_key_reads_and_each_call_is_journaled(api):
    record, secret = key(["read"])
    res = api.get("/assets?limit=5", headers=mcp(secret, "inventory_summary"))
    assert res.status_code == 200, res.text
    entries = journal()
    assert len(entries) == 1
    entry = entries[0]
    details = json.loads(entry["details_json"])
    assert entry["actor_id"] == f"apikey:{record['id']}" and entry["decision"] == "allow"
    assert entry["resource_type"] == "mcp_tool" and entry["resource_id"] == "inventory_summary"
    assert details == {"tool": "inventory_summary", "api_key_id": record["id"], "method": "GET",
                       "path": "/assets", "status": 200, "client": "mcp"}
    assert secret not in json.dumps(entries) and "limit=5" not in json.dumps(entries)
    assert audit_chain.verify_chain(ORG)["ok"]


@pytest.mark.parametrize("scopes", [["write"], ["admin"], ["read", "write"], ["sign"]])
def test_broader_keys_are_refused_with_a_clear_message(api, scopes):
    record, secret = key(scopes)
    res = api.get("/assets", headers=mcp(secret))
    assert res.status_code == 403
    assert res.json()["detail"] == mcp_access.BROAD_KEY and "only the read scope" in mcp_access.BROAD_KEY
    entries = journal()
    assert [(e["decision"], e["resource_id"]) for e in entries] == [("deny", "inventory_summary")]
    assert json.loads(entries[0]["details_json"])["api_key_id"] == record["id"]


def test_other_credentials_are_refused(api):
    session = jwt.encode({"sub": "u1", "org_id": ORG, "role": "admin", "exp": int(time.time()) + 3600},
                         SECRET, algorithm="HS256")
    for headers in ({"authorization": "Bearer " + session}, {}, {"x-user-id": "u1", "x-user-role": "admin"}):
        res = api.get("/assets", headers={**headers, "x-client": "mcp/inventory_summary"})
        assert res.status_code == 403 and res.json()["detail"] == mcp_access.NEEDS_READ_KEY
    res = api.get("/assets", headers=mcp("pq_000000000000_" + "x" * 40))
    assert res.status_code == 401
    assert journal() == []


def test_header_identity_mode_refuses_too(api, monkeypatch):
    import app

    monkeypatch.setattr(app, "AUTH_MODE", "headers")
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)
    res = api.get("/assets", headers={"x-client": "mcp/inventory_summary", "x-user-role": "admin"})
    assert res.status_code == 403 and res.json()["detail"] == mcp_access.NEEDS_READ_KEY


@pytest.mark.parametrize("method,path", [("POST", "/assets/import-csv"), ("PUT", "/instrument/watch/example.com"),
                                         ("DELETE", "/instrument/watch/example.com"), ("POST", "/scans"),
                                         ("PATCH", "/assets/example.com:443")])
def test_write_endpoints_are_unreachable(api, method, path):
    record, secret = key(["read"])
    res = api.request(method, path, headers=mcp(secret, "sneaky"), json={})
    assert res.status_code == 403 and res.json()["detail"] == mcp_access.WRITE_REFUSED
    entry = journal()[-1]
    assert entry["decision"] == "deny" and json.loads(entry["details_json"])["method"] == method
    # Without the marker the read scope refuses it as well.
    assert api.request(method, path, headers={"authorization": "Bearer " + secret}, json={}).status_code == 403


def test_tool_names_are_plain():
    assert mcp_access.tool_name("") is None
    assert mcp_access.tool_name("morrow-sign/0.1") is None
    assert mcp_access.tool_name("mcp/harvest_clock") == "harvest_clock"
    assert mcp_access.tool_name("mcp/../../x") == "unknown"
    assert mcp_access.tool_name("mcp/" + "a" * 70) == "unknown"


def test_stored_grade_never_runs_a_check(api, monkeypatch):
    from services import public_grade

    def no_check(*a, **k):
        raise AssertionError("an assistant's question must not start a check")

    monkeypatch.setattr(public_grade, "check", no_check)
    _, secret = key(["read"])
    res = api.get("/api/public/grade/example.com?stored=1", headers=mcp(secret, "risk_sentence"))
    assert res.status_code == 404 and res.json()["error"] == "not_graded"
    stored = {"domain": "example.com", "grade": "C", "scanned_at": "2026-11-01T00:00:00Z",
              "exposure": {"recorded_traffic_at_risk": True, "decrypt_year_low": 2035},
              "key_exchange": {"post_quantum": False}, "tls": {"negotiated": True}}
    monkeypatch.setattr(public_grade, "latest", lambda host, max_age_seconds=None: dict(stored))
    res = api.get("/api/public/grade/example.com?stored=1", headers=mcp(secret, "risk_sentence"))
    assert res.status_code == 200 and res.json()["grade"] == "C"
    assert "could be read from about" in res.json()["risk"]["sentence"]


# ── the client, end to end through this app ────────────────────────────────────────────────────


def tool_client(api, secret):
    return mt.ReadOnlyClient(mt.Config(url="http://localhost:8000", api_key=secret), http=api)


def test_tools_end_to_end(api, monkeypatch):
    from services import public_grade

    monkeypatch.setattr(public_grade, "check", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no checks")))
    stored = {"domain": "example.com", "grade": "B", "scanned_at": "2026-11-01T00:00:00Z",
              "exposure": {"recorded_traffic_at_risk": True, "decrypt_year_low": 2035},
              "key_exchange": {"post_quantum": False}, "tls": {"negotiated": True}}
    monkeypatch.setattr(public_grade, "latest", lambda host, max_age_seconds=None: dict(stored))
    _, secret = key(["read"])
    client = tool_client(api, secret)

    _, inv = mt.inventory_summary(client)
    assert inv["assets"] == 0 and inv["recent_scans"] == []
    _, work = mt.findings_needing_action(client, limit=500)
    assert work["cards"] == []
    _, risk = mt.risk_sentence(client, "Example.com.")
    assert risk["grade"] == "B" and "could be read" in risk["risk"]["sentence"]
    _, clock = mt.harvest_clock(client, "example.com", data="personal-data-general", jurisdiction="EU")
    assert clock["clock"]["state"] == "at_risk" and clock["clock"]["readable_from"]
    _, history = mt.watch_changes(client, "example.com")
    assert isinstance(history, list)
    _, safe = mt.make_safe_status(client, "example.com")
    assert set(safe) == {"domain", "plan", "recheck", "proof"}

    tools = [json.loads(e["details_json"])["tool"] for e in journal()]
    assert set(tools) >= {"inventory_summary", "findings_needing_action", "risk_sentence", "harvest_clock",
                          "watch_changes", "make_safe_status"}
    assert all(json.loads(e["details_json"])["method"] == "GET" for e in journal())
    assert audit_chain.verify_chain(ORG)["ok"]


def test_a_broad_key_gets_the_servers_words(api):
    _, secret = key(["write"])
    with pytest.raises(mt.MorrowMCPError) as err:
        mt.inventory_summary(tool_client(api, secret))
    assert "only the read scope" in str(err.value)


# ── the client on its own ──────────────────────────────────────────────────────────────────────


def recorder(handler=None):
    seen = []

    def respond(request):
        seen.append(request)
        return handler(request) if handler else httpx.Response(200, json={})

    return seen, mt.ReadOnlyClient(mt.Config("https://morrow.example.com", "pq_aaaaaaaaaaaa_" + "b" * 40),
                                   transport=httpx.MockTransport(respond))


def test_client_sends_only_gets_and_has_no_write_method():
    assert {n for n in dir(mt.ReadOnlyClient) if not n.startswith("_")} == {"get", "close"}
    seen, client = recorder()
    mt.watch_changes(client)
    mt.make_safe_status(client, "example.com")
    assert [r.method for r in seen] == ["GET"] * 4
    assert all(r.headers["x-client"].startswith("mcp/") and r.headers["authorization"].startswith("Bearer pq_")
               for r in seen)


@pytest.mark.parametrize("call", [
    lambda c: mt.risk_sentence(c, "http://example.com/x"),
    lambda c: mt.risk_sentence(c, "../admin"),
    lambda c: mt.make_safe_status(c, "localhost"),
    lambda c: mt.harvest_clock(c, "example.com", data="../x"),
    lambda c: mt.harvest_clock(c, "example.com", jurisdiction="E U"),
])
def test_bad_arguments_are_not_sent(call):
    seen, client = recorder()
    with pytest.raises(mt.ToolInputError):
        call(client)
    assert seen == []


def test_output_is_bounded_and_cleaned():
    big = {"cards": [{"title": "t" * 5000, "i": i} for i in range(400)], "x": "a‮b\x00c\x1b"}
    text = mt.render("GET /x", big)
    assert len(text) <= mt.MAX_OUTPUT_CHARS and json.loads(text)["truncated"] is True
    small, cut = mt.clean(big)
    assert cut and small["x"] == "abc" and len(small["cards"]) == mt.MAX_ITEMS + 1


def test_redirects_big_answers_and_bad_config_are_refused(monkeypatch):
    seen, client = recorder(lambda r: httpx.Response(302, headers={"location": "https://elsewhere.example"}))
    with pytest.raises(mt.MorrowMCPError, match="redirect"):
        mt.watch_changes(client)
    assert len(seen) == 1
    _, client = recorder(lambda r: httpx.Response(200, content=b"[" + b"1," * mt.MAX_RESPONSE_BYTES + b"1]"))
    with pytest.raises(mt.MorrowMCPError, match="too large"):
        mt.watch_changes(client)
    assert mt.Config("http://morrow.internal.example", "pq_x").problems()
    monkeypatch.setenv("MORROW_MCP_ALLOW_HTTP", "1")
    assert not mt.Config("http://morrow.internal.example", "pq_x").problems()
    assert mt.Config("https://m.example", "").problems()


def test_descriptions_describe_and_do_not_instruct():
    for spec in mt.TOOLS:
        low = spec.description.lower()
        for word in ("you must", "always", "ignore", "instruction", "do not", "never", "call this"):
            assert word not in low, (spec.name, word)


def test_mcp_sdk_lists_read_only_tools():
    pytest.importorskip("mcp.server.mcpserver")
    from mcp import Client

    from morrow_mcp import server

    seen, client = recorder(lambda r: httpx.Response(403, json={"detail": mcp_access.OFF}))

    async def go():
        async with Client(server.build_server(client)) as c:
            return (await c.list_tools()).tools, await c.call_tool("watch_changes", {})

    tools, refused = asyncio.run(go())
    assert {t.name for t in tools} == {s.name for s in mt.TOOLS}
    assert all(t.annotations.read_only_hint and t.annotations.destructive_hint is False for t in tools)
    assert refused.is_error and "turned off" in refused.content[0].text
