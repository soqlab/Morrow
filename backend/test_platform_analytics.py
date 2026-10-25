"""Vendor admin portal analytics: overview, customer 360, usage, search, notifications and jobs.

Runs the real ASGI stack against a throwaway SQLite database (never backend/morrow.db), with the
same operator credentials as test_platform_admin_portal.py. Every number asserted here is seeded by the
test itself, so the checks prove the endpoints count real rows: nothing more, nothing less, and never
another tenant's.
"""

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from services import api_keys, auth_issuer
from services import platform_analytics as pa

SECRET = "analytics-tests-jwt-signing-key-not-for-deployment-19"
LEGACY = "legacy-shared-platform-key-for-analytics-tests-0123456789"
SAM = "sam-support-operator-key-for-analytics-tests-0123456789"
PASSWORD = "analytics-tests-password-731"
RANGES = {"24h": 24, "7d": 7, "30d": 30, "90d": 90}


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    db_path = str(tmp_path / "analytics.db")
    monkeypatch.setenv("MORROW_SCANNER_DB", db_path)
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("MORROW_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("MORROW_PLATFORM_OPERATORS", json.dumps([{"name": "sam", "role": "support", "key_sha256": _sha(SAM)}]))
    monkeypatch.delenv("MORROW_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    monkeypatch.delenv("MORROW_TRAFFIC_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("MORROW_AUTH_LOG_RETENTION_DAYS", raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_ISSUER_ENABLED": True,
        "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": SECRET,
        "AUTH_JWT_ISSUER": "morrow", "AUTH_JWT_AUDIENCE": "morrow",
        "_PLATFORM_ADMIN_KEY": LEGACY, "API_KEY": "", "PRODUCTION_ENVIRONMENT": False,
        "RATE_LIMIT_MAX_REQUESTS": 100000,
        # The traffic middleware journals every test request; keep the seeded request counts exact.
        "_TRAFFIC_PERSIST_TO_DB": False,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(auth_issuer, "_SECRET", SECRET)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    with app._db() as conn:
        auth_issuer.init_tables(conn)
    app._ensure_platform_admin_schema()
    from services import feedback, security_journal, sla_engine
    security_journal.init_tables()
    feedback.init_tables()
    api_keys.init_tables()
    with closing(sqlite3.connect(db_path)) as conn:
        sla_engine.init_tables(conn)
    pa.clear_cache()
    client = TestClient(app.app, client=("192.0.2.30", 40000))
    yield client, app, db_path
    client.close()
    pa.clear_cache()


def owner():
    return {"x-platform-key": LEGACY, "x-platform-admin-role": "owner"}


def auditor():
    return {"x-platform-key": LEGACY}  # the shared key without a role resolves to auditor


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def now():
    return datetime.now(timezone.utc)


def execute(db_path, sql, params=()):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(sql, params)
        conn.commit()


def make_org(client, org_id, name=None):
    res = client.post("/platform/customers", headers=owner(),
                      json={"organization_id": org_id, "name": name or org_id.title(), "reason": "test setup"})
    assert res.status_code == 200, res.text


def add_scan(db_path, org, at):
    execute(db_path, "INSERT INTO scans (id, status, created_at, progress_json, error_text, results_json, summary_json, "
                     "job_id, job_state, job_started_at, job_finished_at, organization_id) "
                     "VALUES (?, 'completed', ?, '{}', '', '[]', '{}', '', '', '', '', ?)",
            (str(uuid.uuid4()), iso(at), org))


def add_auth(db_path, org, user, event, at):
    execute(db_path, "INSERT INTO platform_auth_events (id, created_at, organization_id, user_id, actor_role, event_type, "
                     "login_method, ip_address, user_agent, subject_ref, status_code) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, iso(at), org, user, "viewer", event, "password", "192.0.2.1", "Other", "",
             200 if event.endswith("success") else 401))


def add_request(db_path, org, status, duration, at, actor="", path="/assets"):
    execute(db_path, "INSERT INTO platform_request_events (id, created_at, organization_id, actor_id, actor_role, source_ip, "
                     "method, path, status_code, duration_ms, user_agent, authenticated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, iso(at), org, actor, "viewer", "192.0.2.1", "GET", path, status, duration, "Other",
             1 if actor else 0))


def add_audit(db_path, org, actor, action, at):
    execute(db_path, "INSERT INTO audit_logs (organization_id, actor_id, actor_role, action, resource_type, resource_id, "
                     "decision, reason, details_json, prev_hash, entry_hash, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (org, actor, "viewer", action, "organization", org, "allow", "", "{}", "", "", iso(at)))


def add_feedback(db_path, org, message, at, status="new"):
    execute(db_path, "INSERT INTO feedback (organization_id, user_id, email, category, rating, message, page, user_agent, "
                     "status, admin_note, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (org, "u", "", "bug", 4, message, "", "", status, "", iso(at), iso(at)))


# ── Auth ─────────────────────────────────────────────────────────────────────

ENDPOINTS = ["/platform/analytics/overview", "/platform/analytics/usage", "/platform/search?q=ab",
             "/platform/notifications", "/platform/jobs"]


def test_every_endpoint_requires_a_platform_credential(api):
    client, _, _ = api
    make_org(client, "org-alpha")
    for path in ENDPOINTS + ["/platform/analytics/customers/org-alpha"]:
        assert client.get(path).status_code in (401, 403), path
        assert client.get(path, headers={"x-platform-key": "wrong-key-" + "x" * 40}).status_code in (401, 403), path


def test_auditor_and_support_can_read_every_endpoint(api):
    client, _, _ = api
    make_org(client, "org-alpha")
    for headers in (auditor(), {"x-platform-key": SAM}):
        for path in ENDPOINTS + ["/platform/analytics/customers/org-alpha"]:
            res = client.get(path, headers=headers)
            assert res.status_code == 200, (path, res.text)
            assert res.headers.get("cache-control") == "no-store"
            assert res.json()["api_version"] == "v1"


# ── Shapes ───────────────────────────────────────────────────────────────────

KPI_KEYS = {"organizations", "new_organizations", "active_organizations", "users", "new_users", "active_users", "logins",
            "failed_logins", "scans", "assets", "open_remediations", "api_requests", "error_rate_pct", "p95_latency_ms",
            "rate_limited_requests", "open_feedback", "pending_autopatches", "active_api_keys", "active_sessions",
            "admin_actions"}
CUSTOMER_KPIS = {"members", "active_users", "logins", "failed_logins", "scans", "assets", "open_remediations",
                 "closed_remediations", "api_requests", "error_rate_pct", "active_api_keys", "active_sessions",
                 "feature_flags_overridden", "feedback"}


def _assert_kpi(item):
    assert set(item) >= {"value", "previous", "delta_pct", "label", "source"}
    assert item["label"]


def _assert_series(points, count, fields, bucket):
    assert len(points) == count
    stamps = [p["t"] for p in points]
    assert stamps == sorted(stamps) and len(set(stamps)) == count
    for p in points:
        assert set(p) == {"t", *fields}
        parsed = datetime.fromisoformat(p["t"].replace("Z", "+00:00"))
        assert parsed.minute == 0 and parsed.second == 0 and parsed.tzinfo is not None
        if bucket == "day":
            assert parsed.hour == 0


@pytest.mark.parametrize("range_key", list(RANGES))
def test_overview_shape_for_every_range(api, range_key):
    client, _, _ = api
    res = client.get(f"/platform/analytics/overview?range={range_key}", headers=owner())
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["range"] == range_key and body["bucket"] == ("hour" if range_key == "24h" else "day")
    assert datetime.fromisoformat(body["generated_at"].replace("Z", "+00:00"))
    assert set(body["kpis"]) == KPI_KEYS
    for item in body["kpis"].values():
        _assert_kpi(item)
    fields = {"signups": {"organizations", "users"}, "active_users": {"value"}, "logins": {"success", "failed"},
              "scans": {"value"}, "requests": {"total", "client_errors", "server_errors", "rate_limited"},
              "latency": {"p50", "p95"}, "feedback": {"value"}, "admin_actions": {"value"}}
    assert set(body["series"]) == set(fields)
    for name, cols in fields.items():
        _assert_series(body["series"][name], RANGES[range_key], cols, body["bucket"])
    assert set(body["top"]) >= {"organizations_by_activity", "routes_by_errors", "plans"}
    assert isinstance(body["sources"], dict) and isinstance(body["unavailable"], list)
    for u in body["unavailable"]:
        assert set(u) == {"metric", "reason"} and u["reason"]


@pytest.mark.parametrize("range_key", list(RANGES))
def test_customer_and_usage_shape_for_every_range(api, range_key):
    client, _, db_path = api
    make_org(client, "org-alpha")
    res = client.get(f"/platform/analytics/customers/org-alpha?range={range_key}", headers=owner())
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["organization"]["organization_id"] == "org-alpha"
    assert body["organization"]["status"] in ("active", "suspended", "archived")
    assert set(body["kpis"]) == CUSTOMER_KPIS
    for item in body["kpis"].values():
        _assert_kpi(item)
    _assert_series(body["series"]["logins"], RANGES[range_key], {"success", "failed"}, body["bucket"])
    _assert_series(body["series"]["requests"], RANGES[range_key], {"total", "client_errors", "server_errors"}, body["bucket"])
    _assert_series(body["series"]["scans"], RANGES[range_key], {"value"}, body["bucket"])
    assert set(body["last_activity"]) == {"at", "kind"}
    assert isinstance(body["members"], list) and isinstance(body["recent_events"], list)

    usage = client.get(f"/platform/analytics/usage?range={range_key}", headers=owner())
    assert usage.status_code == 200, usage.text
    u = usage.json()
    with closing(sqlite3.connect(db_path)) as conn:
        assert u["organizations_total"] == conn.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]
    keys = [f["key"] for f in u["features"]]
    assert "tls_scans" in keys and "ai_assistant" in keys
    assert {a["feature"] for a in body["adoption"]} == set(keys)
    for f in u["features"]:
        assert set(f) == {"key", "label", "organizations_using", "events", "previous_events", "delta_pct", "last_used_at",
                          "source", "series"}
        _assert_series(f["series"], RANGES[range_key], {"value"}, u["bucket"])


def test_unknown_range_is_rejected(api):
    client, _, _ = api
    assert client.get("/platform/analytics/overview?range=1y", headers=owner()).status_code == 400


def test_unknown_organization_is_404(api):
    client, _, _ = api
    res = client.get("/platform/analytics/customers/no-such-org", headers=owner())
    assert res.status_code == 404


# ── Buckets and deltas ───────────────────────────────────────────────────────


def test_buckets_are_zero_filled_and_delta_is_null_when_previous_is_zero(api):
    client, _, db_path = api
    make_org(client, "org-alpha")
    add_scan(db_path, "org-alpha", now() - timedelta(minutes=5))
    pa.clear_cache()
    body = client.get("/platform/analytics/overview?range=7d", headers=owner()).json()
    scans = body["kpis"]["scans"]
    assert scans["value"] == 1 and scans["previous"] == 0 and scans["delta_pct"] is None
    points = body["series"]["scans"]
    assert [p["value"] for p in points] == [0, 0, 0, 0, 0, 0, 1]
    assert body["series"]["feedback"] == [{"t": p["t"], "value": 0} for p in points]
    # organization was created in range and none existed before
    assert body["kpis"]["organizations"]["previous"] == 0 and body["kpis"]["organizations"]["delta_pct"] is None


def test_delta_compares_with_the_previous_equal_length_period(api):
    client, _, db_path = api
    make_org(client, "org-alpha")
    add_scan(db_path, "org-alpha", now() - timedelta(days=9))
    add_scan(db_path, "org-alpha", now() - timedelta(minutes=2))
    add_scan(db_path, "org-alpha", now() - timedelta(minutes=1))
    add_scan(db_path, "org-alpha", now() - timedelta(days=40))  # outside both periods
    pa.clear_cache()
    scans = client.get("/platform/analytics/overview?range=7d", headers=owner()).json()["kpis"]["scans"]
    assert (scans["value"], scans["previous"], scans["delta_pct"]) == (2, 1, 100.0)


def test_request_metrics_and_latency_from_journal_rows(api):
    client, _, db_path = api
    t = now() - timedelta(minutes=3)
    for status, duration in ((200, 10.0), (200, 20.0), (404, 30.0), (429, 40.0), (500, 50.0)):
        add_request(db_path, "", status, duration, t, path="/boom" if status == 500 else "/ok")
    pa.clear_cache()
    body = client.get("/platform/analytics/overview?range=24h", headers=owner()).json()
    k = body["kpis"]
    assert k["api_requests"]["value"] == 5
    assert k["error_rate_pct"]["value"] == 20.0
    assert k["rate_limited_requests"]["value"] == 1
    assert k["p95_latency_ms"]["value"] == 50.0
    # The bucket holding the seeded rows (robust when the test runs just after an hour boundary).
    label = t.strftime("%Y-%m-%dT%H:00:00Z")
    last = next(p for p in body["series"]["requests"] if p["t"] == label)
    assert (last["total"], last["client_errors"], last["server_errors"], last["rate_limited"]) == (5, 1, 1, 1)
    assert next(p for p in body["series"]["latency"] if p["t"] == label) == {"t": label, "p50": 30.0, "p95": 50.0}
    assert body["series"]["latency"][0]["p95"] is None  # no requests in that hour: unknown, not 0
    assert body["top"]["routes_by_errors"][0]["route"] == "/boom"
    # 30d reaches past the 7-day request journal retention: those buckets are unknown, not zero.
    month = client.get("/platform/analytics/overview?range=30d", headers=owner()).json()
    assert month["series"]["requests"][0]["total"] is None
    assert month["kpis"]["api_requests"]["previous"] is None
    assert any(u["metric"] == "api_requests.previous" for u in month["unavailable"])


def test_error_rate_is_null_not_zero_without_requests(api):
    client, _, _ = api
    body = client.get("/platform/analytics/overview?range=24h", headers=owner()).json()
    assert body["kpis"]["api_requests"]["value"] == 0
    assert body["kpis"]["error_rate_pct"]["value"] is None
    assert body["kpis"]["p95_latency_ms"]["value"] is None


# ── Tenant scoping ───────────────────────────────────────────────────────────


def test_customer_360_never_includes_another_organizations_rows(api):
    client, app, db_path = api
    make_org(client, "org-gamma", "Gamma Co")
    make_org(client, "org-beta", "Beta Co")
    recent = now() - timedelta(minutes=10)
    with app._db() as conn:
        a_user = auth_issuer.create_user(conn, "alice@gamma.test", PASSWORD, "Alice", "viewer", "org-gamma")
        auth_issuer.create_user(conn, "bob@beta.test", PASSWORD, "Bob", "viewer", "org-beta")
    for org, n in (("org-gamma", 2), ("org-beta", 5)):
        tag = org.split("-")[1]
        for i in range(n):
            add_scan(db_path, org, recent)
            add_auth(db_path, org, f"{tag}-user-{i}", "login.success", recent)
            add_request(db_path, org, 500 if tag == "beta" else 200, 5.0, recent, actor=f"{tag}-actor-{i}")
            add_audit(db_path, org, f"{tag}-auditor", "assistant.chat", recent)
            add_feedback(db_path, org, f"{tag} feedback {i}", recent)
        add_auth(db_path, org, f"{tag}-intruder", "login.failure", recent)
        execute(db_path, "INSERT INTO platform_admin_events (organization_id, action, actor_id, reason, details_json, created_at) "
                         "VALUES (?, 'platform.note', 'op', ?, '{}', ?)", (org, f"{tag} admin note", iso(recent)))
        execute(db_path, "INSERT INTO platform_feature_flags (organization_id, flag_key, enabled, reason, updated_at) "
                         "VALUES (?, ?, 1, '', ?)", (org, f"{tag}_flag", iso(recent)))
    pa.clear_cache()

    res = client.get("/platform/analytics/customers/org-gamma?range=7d", headers=owner())
    assert res.status_code == 200, res.text
    body = res.json()
    assert "beta" not in res.text.lower(), "customer 360 for org-gamma leaked org-beta data"
    k = body["kpis"]
    assert k["scans"]["value"] == 2
    assert k["logins"]["value"] == 2 and k["failed_logins"]["value"] == 1
    assert k["api_requests"]["value"] == 2 and k["error_rate_pct"]["value"] == 0.0
    assert k["active_users"]["value"] == 4  # 2 login users + 2 authenticated request actors
    assert k["feedback"]["value"] == 2
    assert k["feature_flags_overridden"]["value"] == 1
    assert k["members"]["value"] == 1
    assert [m["user_id"] for m in body["members"]] == [a_user["id"]]
    ai = next(a for a in body["adoption"] if a["feature"] == "ai_assistant")
    assert ai["used"] is True and ai["events"] == 2
    tls = next(a for a in body["adoption"] if a["feature"] == "tls_scans")
    assert tls["events"] == 2
    kinds = {e["kind"] for e in body["recent_events"]}
    assert {"audit", "admin", "auth"} <= kinds

    beta = client.get("/platform/analytics/customers/org-beta?range=7d", headers=owner())
    assert "gamma" not in beta.text.lower()
    assert beta.json()["kpis"]["scans"]["value"] == 5
    assert beta.json()["kpis"]["error_rate_pct"]["value"] == 100.0

    overview = client.get("/platform/analytics/overview?range=7d", headers=owner()).json()
    ranked = [o["organization_id"] for o in overview["top"]["organizations_by_activity"]]
    assert ranked == ["org-beta", "org-gamma"]
    usage = client.get("/platform/analytics/usage?range=7d", headers=owner()).json()
    ai_usage = next(f for f in usage["features"] if f["key"] == "ai_assistant")
    assert ai_usage["events"] == 7 and ai_usage["organizations_using"] == 2


# ── Search ───────────────────────────────────────────────────────────────────


def test_search_requires_two_characters(api):
    client, _, _ = api
    assert client.get("/platform/search?q=a", headers=owner()).status_code == 400
    assert client.get("/platform/search?q=%20a%20", headers=owner()).status_code == 400
    assert client.get("/platform/search", headers=owner()).status_code == 400


def test_search_escapes_like_wildcards(api):
    client, _, _ = api
    make_org(client, "org-percent", "Acme%Corp")
    make_org(client, "org-plain", "AcmeXCorp")
    make_org(client, "org-under", "Beta_Labs")
    make_org(client, "org-letter", "BetaZLabs")
    def titles(q):
        res = client.get("/platform/search", params={"q": q}, headers=owner()).json()["results"]
        return {r["title"] for r in res}
    assert titles("e%c") == {"Acme%Corp"}
    assert titles("a_l") == {"Beta_Labs"}
    assert titles("ACME") == {"Acme%Corp", "AcmeXCorp"}  # case-insensitive
    body = client.get("/platform/search", params={"q": "acme"}, headers=owner()).json()
    first = body["results"][0]
    assert set(first) == {"type", "id", "title", "subtitle", "organization_id", "route"}
    assert first["route"].startswith("#/customers/")


def test_search_api_keys_expose_no_secret_or_hash(api):
    client, _, db_path = api
    make_org(client, "org-alpha")
    created = client.post("/platform/customers/org-alpha/api-keys", headers=owner(),
                          json={"name": "ci-deployer", "scopes": ["read"], "reason": "test setup"})
    assert created.status_code == 200, created.text
    secret, key = created.json()["secret"], created.json()["key"]
    with closing(sqlite3.connect(db_path)) as conn:
        salt, key_hash = conn.execute("SELECT salt, key_hash FROM platform_api_keys WHERE id = ?", (key["id"],)).fetchone()
    res = client.get("/platform/search", params={"q": "deployer"}, headers=owner())
    assert res.status_code == 200
    hits = [r for r in res.json()["results"] if r["type"] == "api_key"]
    assert len(hits) == 1 and hits[0]["route"] == f"#/api-keys?id={key['id']}"
    assert set(hits[0]) == {"type", "id", "title", "subtitle", "organization_id", "route"}
    for value in (secret, salt, key_hash, secret.split("_")[-1]):
        assert value not in res.text


def test_search_limit_and_operator_visibility(api):
    client, _, _ = api
    for i in range(8):
        make_org(client, f"org-many-{i}", f"Many Org {i}")
    res = client.get("/platform/search", params={"q": "many", "limit": 3}, headers=owner())
    assert len(res.json()["results"]) == 3
    assert client.get("/platform/search", params={"q": "many", "limit": 500}, headers=owner()).status_code == 200
    # Named operator "sam" exists: only an owner may find operators.
    as_owner = client.get("/platform/search", params={"q": "sam"}, headers=owner()).json()["results"]
    as_auditor = client.get("/platform/search", params={"q": "sam"}, headers=auditor()).json()["results"]
    assert any(r["type"] == "operator" and r["route"] == "#/operators" for r in as_owner)
    assert not any(r["type"] == "operator" for r in as_auditor)


# ── Notifications ────────────────────────────────────────────────────────────


def _kinds(client):
    pa.clear_cache()
    res = client.get("/platform/notifications", headers=owner())
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body["counts"]) == {"critical", "warn", "info", "total"}
    assert body["counts"]["total"] == body["counts"]["critical"] + body["counts"]["warn"] + body["counts"]["info"]
    for item in body["items"]:
        assert set(item) == {"id", "severity", "kind", "title", "detail", "created_at", "route"}
        assert item["severity"] in ("critical", "warn", "info") and item["route"].startswith("#/")
    stamps = [i["created_at"] or "" for i in body["items"]]
    assert stamps == sorted(stamps, reverse=True)
    return body


def test_notifications_are_derived_from_real_state(api):
    client, _, db_path = api
    make_org(client, "org-alpha")
    clean = _kinds(client)
    assert not {"sla_breach", "autopatch_pending", "feedback", "org_suspended", "failed_login_spike",
                "api_key_expiring"} & {i["kind"] for i in clean["items"]}

    execute(db_path, "INSERT INTO sla_breaches (organization_id, remediation_id, severity, opened_at, breached_at, days_overdue, "
                     "status, notified) VALUES ('org-alpha', '7', 'critical', ?, ?, 4, 'open', 0)",
            (iso(now() - timedelta(days=10)), iso(now() - timedelta(days=4))))
    execute(db_path, "INSERT INTO sla_breaches (organization_id, remediation_id, severity, opened_at, breached_at, days_overdue, "
                     "status, notified) VALUES ('org-alpha', '8', 'low', ?, ?, 1, 'resolved', 0)",
            (iso(now() - timedelta(days=10)), iso(now() - timedelta(days=1))))
    patch = client.post("/platform/autopatches", headers=owner(), json={"title": "Fix flaky check"})
    assert patch.status_code == 200, patch.text
    rejected = client.post("/platform/autopatches", headers=owner(), json={"title": "Already handled"}).json()
    assert client.post(f"/platform/autopatches/{rejected['id']}/reject", headers=owner(), json={"reason": "no"}).status_code == 200

    body = _kinds(client)
    breaches = [i for i in body["items"] if i["kind"] == "sla_breach"]
    assert len(breaches) == 1 and breaches[0]["severity"] == "critical" and breaches[0]["id"].startswith("sla_breach:")
    pending = [i for i in body["items"] if i["kind"] == "autopatch_pending"]
    assert [i["id"] for i in pending] == [f"autopatch:{patch.json()['id']}"]
    assert pending[0]["route"] == f"#/autopatch?id={patch.json()['id']}"


def test_failed_login_spike_rule(api):
    client, _, db_path = api
    for i in range(12):
        add_auth(db_path, "org-alpha", f"u{i}", "login.failure", now() - timedelta(minutes=5))
    body = _kinds(client)
    spike = [i for i in body["items"] if i["kind"] == "failed_login_spike"]
    assert len(spike) == 1 and spike[0]["severity"] == "critical" and "3x" in spike[0]["detail"]
    # 12 in the last hour is below 3x an hourly average of 5 (120 failures in the previous 24h).
    for i in range(120):
        add_auth(db_path, "org-alpha", f"p{i}", "login.failure", now() - timedelta(hours=2 + (i % 20)))
    assert not [i for i in _kinds(client)["items"] if i["kind"] == "failed_login_spike"]


def test_suspended_org_and_expiring_key_notifications(api):
    client, _, db_path = api
    make_org(client, "org-alpha")
    assert client.post("/platform/customers/org-alpha/suspend", headers=owner(), json={"reason": "unpaid invoice"}).status_code == 200
    created = client.post("/platform/customers/org-alpha/api-keys", headers=owner(),
                          json={"name": "short-lived", "scopes": ["read"], "expires_in_days": 3, "reason": "test"})
    assert created.status_code == 200, created.text
    kinds = {i["kind"] for i in _kinds(client)["items"]}
    assert {"org_suspended", "api_key_expiring"} <= kinds
    body = client.get("/platform/analytics/customers/org-alpha", headers=owner()).json()
    assert body["organization"]["status"] == "suspended"
    assert body["organization"]["suspended_reason"] == "unpaid invoice"


# ── Jobs ─────────────────────────────────────────────────────────────────────


def test_jobs_shape(api):
    client, _, db_path = api
    execute(db_path, "INSERT INTO validation_jobs (organization_id, remediation_id, validator_type, status, git_ref, job_id, "
                     "stdout, stderr, exit_code, details_json, created_at, updated_at, finished_at) "
                     "VALUES ('org-alpha', 1, 'terraform', 'failed', 'main', 'j1', '', 'boom', 1, '{}', ?, ?, ?)",
            (iso(now()), iso(now()), iso(now())))
    res = client.get("/platform/jobs", headers=auditor())
    assert res.status_code == 200 and res.headers["cache-control"] == "no-store"
    body = res.json()
    assert body["api_version"] == "v1" and body["generated_at"]
    jobs = {j["key"]: j for j in body["jobs"]}
    assert {"scan_scheduler", "validation_jobs", "digest", "retention", "traffic_journal", "webhook_deliveries",
            "maintenance_cache"} <= set(jobs)
    for job in body["jobs"]:
        assert set(job) >= {"key", "label", "kind", "status", "last_run_at", "next_run_at", "last_error", "runs_24h", "source"}
        assert job["status"] in ("ok", "error", "idle", "unknown")
        if job["status"] == "unknown":
            assert job["detail"]
    assert jobs["validation_jobs"]["status"] == "error" and jobs["validation_jobs"]["last_error"] == "boom"
    assert jobs["validation_jobs"]["runs_24h"] == 1
    assert jobs["retention"]["status"] == "idle"
