"""Per-customer usage attribution in the traffic journal, and per-organization rate limits.

Runs the real ASGI middleware stack against a throwaway SQLite database. No network calls: the scan
endpoint is exercised with an invalid body (422) so no host is ever contacted.
"""

import json
import pathlib
import sqlite3
import time
from contextlib import closing

import jwt
import pytest
from fastapi.testclient import TestClient

from services import api_keys, org_rate_limits, security_journal

SECRET = "usage-tests-jwt-signing-key-not-for-deployment-0042"
KEY = "usage-tests-platform-key-0123456789-abcdefghijklmnop"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app

    db_path = str(tmp_path / "usage.db")
    monkeypatch.setenv("PQC_SCANNER_DB", db_path)
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_AUTH_JWT_SECRET", SECRET)
    for name in ("REDIS_URL", "CELERY_BROKER_URL", "PQC_ORG_DEFAULT_API_CALLS_PER_MIN", "PQC_ORG_DEFAULT_SCANS_PER_HOUR",
                 "PQC_ORG_RATE_LIMITS_ENABLED", "PQC_ORG_RATE_LIMIT_CACHE_SECONDS", "PQC_PLATFORM_OPERATORS",
                 "PQC_PLATFORM_ADMIN_KEY_ROLE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "AUTH_MODE": "jwt", "AUTH_REQUIRED": True, "AUTH_JWT_ALGORITHMS": ["HS256"], "AUTH_JWT_SECRET": SECRET,
        "AUTH_JWT_ISSUER": "", "AUTH_JWT_AUDIENCE": "", "_PLATFORM_ADMIN_KEY": KEY, "API_KEY": "",
        "PRODUCTION_ENVIRONMENT": False, "RATE_LIMIT_MAX_REQUESTS": 100000, "_TRAFFIC_PERSIST_TO_DB": True,
        "_TRAFFIC_MONITOR_ENABLED": True,
    }.items():
        monkeypatch.setattr(app, name, value)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    app._ensure_platform_admin_schema()
    security_journal.init_tables()
    api_keys.init_tables()
    from services import admin_console
    admin_console._init_tables()
    app._TRAFFIC_EVENTS.clear()
    app._TRAFFIC_BY_IP.clear()
    app._RATE_LIMIT_OBSERVATIONS.clear()
    org_rate_limits.reset()
    client = TestClient(app.app, client=("192.0.2.40", 41000))
    yield client, app, db_path
    client.close()
    org_rate_limits.reset()


def token(org, sub="user-1", role="viewer"):
    return jwt.encode({"sub": sub, "org_id": org, "role": role, "exp": int(time.time()) + 3600}, SECRET, algorithm="HS256")


def bearer(org, sub="user-1"):
    return {"authorization": "Bearer " + token(org, sub)}


def owner():
    return {"x-platform-key": KEY, "x-platform-admin-role": "owner"}


def journal(path):
    return [e for e in security_journal.request_events(limit=5000) if e["path"] == path]


def set_override(db_path, org, api_per_min, scans_per_hour):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("INSERT OR REPLACE INTO admin_rate_limits (org_id, scans_per_hour, api_calls_per_min, updated_at) "
                     "VALUES (?, ?, ?, '2026-01-01T00:00:00Z')", (org, scans_per_hour, api_per_min))
        conn.commit()


# ── Attribution ──────────────────────────────────────────────────────────────


def test_jwt_request_journals_organization_and_actor_but_anonymous_does_not(api):
    client, _, _ = api
    assert client.get("/assets?token=do-not-store", headers=bearer("org-jwt", "alice")).status_code == 200
    assert client.get("/status").status_code == 200
    rows = journal("/assets")
    assert len(rows) == 1
    assert (rows[0]["organization_id"], rows[0]["actor_id"], rows[0]["authenticated"]) == ("org-jwt", "alice", True)
    anonymous = journal("/status")
    assert anonymous and all(e["organization_id"] == "" and e["actor_id"] == "" and not e["authenticated"] for e in anonymous)
    dumped = json.dumps(security_journal.request_events(limit=5000))
    assert "do-not-store" not in dumped and token("org-jwt", "alice") not in dumped


def test_rejected_jwt_is_not_attributed(api):
    client, _, _ = api
    forged = jwt.encode({"sub": "mallory", "org_id": "org-victim", "exp": int(time.time()) + 60}, "wrong-secret-" * 4, algorithm="HS256")
    assert client.get("/assets", headers={"authorization": "Bearer " + forged, "x-org-id": "org-victim"}).status_code == 401
    assert all(e["organization_id"] == "" and not e["authenticated"] for e in journal("/assets"))


def test_headers_mode_identity_is_attributed(api, monkeypatch):
    client, app, _ = api
    monkeypatch.setattr(app, "AUTH_MODE", "headers")
    assert client.get("/assets", headers={"x-org-id": "org-hdr", "x-user-id": "bob", "x-user-role": "viewer"}).status_code == 200
    assert client.get("/status").status_code == 200
    # Vendor-operator traffic is not customer usage, even when it carries an org header.
    client.get("/platform/traffic/summary", headers={**owner(), "x-org-id": "org-hdr"})
    rows = journal("/assets")
    assert [(e["organization_id"], e["actor_id"], e["authenticated"]) for e in rows] == [("org-hdr", "bob", True)]
    assert all(e["organization_id"] == "" for e in journal("/status"))
    assert all(e["organization_id"] == "" for e in journal("/platform/traffic/summary"))


@pytest.mark.parametrize("mode", ["jwt", "headers"])
def test_api_key_request_journals_the_keys_organization(api, monkeypatch, mode):
    client, app, _ = api
    monkeypatch.setattr(app, "AUTH_MODE", mode)
    record, secret = api_keys.create_key("org-key", "usage-test", ["read"])
    # x-org-id cannot redirect a key to another tenant, in the journal either.
    res = client.get("/assets", headers={"authorization": "Bearer " + secret, "x-org-id": "org-other", "x-user-id": "spoof"})
    assert res.status_code == 200, res.text
    rows = journal("/assets")
    assert [(e["organization_id"], e["actor_id"], e["authenticated"]) for e in rows] == [("org-key", f"apikey:{record['id']}", True)]
    assert secret not in json.dumps(security_journal.request_events(limit=5000))


def test_customer_360_counts_attributed_requests(api):
    client, _, _ = api
    assert client.post("/platform/customers", headers=owner(), json={"organization_id": "org-c360", "name": "C360", "reason": "test"}).status_code == 200
    for _ in range(3):
        assert client.get("/assets", headers=bearer("org-c360", "carol")).status_code == 200
    client.get("/assets", headers=bearer("org-elsewhere", "dave"))
    from services import platform_analytics as pa
    pa.clear_cache()
    body = client.get("/platform/analytics/customers/org-c360?range=24h", headers=owner()).json()
    assert body["kpis"]["api_requests"]["value"] == 3
    assert body["kpis"]["active_users"]["value"] == 1


# ── Rate limits ──────────────────────────────────────────────────────────────


def test_override_is_enforced_with_429_and_headers(api):
    client, _, db_path = api
    set_override(db_path, "org-a", 3, 100)
    seen = [client.get("/assets", headers=bearer("org-a")) for _ in range(4)]
    assert [r.status_code for r in seen] == [200, 200, 200, 429]
    assert [r.headers.get("x-ratelimit-remaining") for r in seen[:3]] == ["2", "1", "0"]
    limited = seen[3]
    assert limited.headers["x-ratelimit-limit"] == "3" and limited.headers["x-ratelimit-remaining"] == "0"
    assert 1 <= int(limited.headers["retry-after"]) <= 60
    detail = limited.json()["detail"]
    assert "3 requests per minute" in detail and "org-a" in detail


def test_limits_are_isolated_between_organizations_and_skip_orgs_without_override(api):
    client, _, db_path = api
    set_override(db_path, "org-a", 1, 100)
    assert client.get("/assets", headers=bearer("org-a")).status_code == 200
    assert client.get("/assets", headers=bearer("org-a")).status_code == 429
    for _ in range(5):
        res = client.get("/assets", headers=bearer("org-b"))
        assert res.status_code == 200 and "x-ratelimit-limit" not in res.headers
    set_override(db_path, "org-c", 2, 100)
    org_rate_limits.invalidate()
    assert client.get("/assets", headers=bearer("org-c")).status_code == 200


def test_exempt_routes_and_anonymous_requests_are_never_limited(api, monkeypatch):
    client, app, db_path = api
    set_override(db_path, "org-a", 1, 1)
    auth = bearer("org-a")
    for _ in range(3):
        assert client.get("/status", headers=auth).status_code == 200
        assert client.get("/health", headers=auth).status_code == 200
        assert client.get("/auth/access-policy", headers=auth).status_code == 200
        assert client.get("/ui/", headers=auth).status_code in (200, 404)
        assert client.get("/platform/traffic/summary", headers={**auth, **owner()}).status_code == 200
    assert client.get("/assets", headers=auth).status_code == 200  # the first counted request
    monkeypatch.setattr(app, "AUTH_REQUIRED", False)
    for _ in range(3):
        assert client.get("/assets").status_code == 200  # anonymous: per-IP limits only


def test_scans_per_hour_limits_scan_starts_only(api):
    client, _, db_path = api
    set_override(db_path, "org-scan", 1000, 2)
    auth = bearer("org-scan")
    codes = [client.post("/scan", headers=auth, json={"targets": "not-a-list"}).status_code for _ in range(3)]
    assert codes[:2] == [422, 422] and codes[2] == 429  # invalid body: validated after admission, no host contacted
    limited = client.post("/v1/scan", headers=auth, json={"targets": "not-a-list"})
    assert limited.status_code == 429 and limited.headers["x-ratelimit-limit"] == "2"
    assert "2 scans per hour" in limited.json()["detail"]
    assert 60 < int(limited.headers["retry-after"]) <= 3600
    assert client.get("/assets", headers=auth).status_code == 200  # other calls keep working


def test_429_is_journaled_with_the_org_and_shown_in_abuse_view(api):
    client, _, db_path = api
    set_override(db_path, "org-noisy", 1, 100)
    client.get("/assets", headers=bearer("org-noisy"))
    assert client.get("/assets", headers=bearer("org-noisy")).status_code == 429
    limited = [e for e in journal("/assets") if e["status_code"] == 429]
    # journal("/assets") filters on the route template, which the limiter records even though routing never ran.
    assert [(e["organization_id"], e["authenticated"]) for e in limited] == [("org-noisy", True)]
    abuse = client.get("/platform/abuse", headers=owner()).json()
    assert abuse["rate_limited_by_org"].get("org-noisy") == 1
    assert abuse["rate_limited_events"][-1]["source"] == "org_api_calls_per_min"


def test_override_cache_refreshes_after_ttl(api, monkeypatch):
    client, _, db_path = api
    clock = {"t": 1_900_000_000.0}
    monkeypatch.setattr(org_rate_limits, "_clock", lambda: clock["t"])
    set_override(db_path, "org-a", 100, 100)
    assert client.get("/assets", headers=bearer("org-a")).headers["x-ratelimit-limit"] == "100"
    set_override(db_path, "org-a", 1, 100)  # written by another replica: not seen until the cache expires
    clock["t"] += 5
    assert client.get("/assets", headers=bearer("org-a")).status_code == 200
    clock["t"] += 11  # 16 s after the load
    res = client.get("/assets", headers=bearer("org-a"))
    assert res.status_code == 429 and res.headers["x-ratelimit-limit"] == "1"


def test_admin_api_reports_enforcement_and_applies_immediately(api):
    client, _, _ = api
    assert client.post("/platform/customers", headers=owner(), json={"organization_id": "org-admin", "name": "Admin", "reason": "test"}).status_code == 200
    before = client.get("/platform/customers/org-admin/rate-limits", headers=owner()).json()
    assert before["override"] is False and before["enforced"] is False and "No override" in before["note"]
    assert client.get("/assets", headers=bearer("org-admin")).status_code == 200  # caches "no override"
    saved = client.put("/platform/customers/org-admin/rate-limits", headers=owner(),
                       json={"scans_per_hour": 5, "api_calls_per_min": 1, "reason": "abuse test"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["enforced"] is True and saved.json()["override"] is True
    assert client.get("/assets", headers=bearer("org-admin")).status_code == 200
    assert client.get("/assets", headers=bearer("org-admin")).status_code == 429


def test_platform_defaults_apply_without_override(api, monkeypatch):
    client, _, _ = api
    monkeypatch.setenv("PQC_ORG_DEFAULT_API_CALLS_PER_MIN", "2")
    assert [client.get("/assets", headers=bearer("org-default")).status_code for _ in range(3)] == [200, 200, 429]
    monkeypatch.setenv("PQC_ORG_RATE_LIMITS_ENABLED", "0")
    assert client.get("/assets", headers=bearer("org-default")).status_code == 200











def test_admin_api_and_portal_name_the_real_limit_source(api, monkeypatch):
    """The Rate limits note and the Customer 360 drawer must name where a limit came from.

    There used to be a billing-plan tier between the override and the platform default, and both
    surfaces reported a plan limit as "platform default". The platform is free now and the tier is
    gone, so the sources are override, default and none -- but naming them correctly still matters,
    because an operator reading "platform default" when an override is in force changes the wrong
    thing.
    """
    client, _, db_path = api
    for org in ("org-over", "org-default", "org-free"):
        assert client.post("/platform/customers", headers=owner(), json={"organization_id": org, "name": org, "reason": "test"}).status_code == 200

    set_override(db_path, "org-over", 10, 10)
    org_rate_limits.invalidate()
    over = client.get("/platform/customers/org-over/rate-limits", headers=owner()).json()
    assert over["limit_source"] == "override" and over["limit_source_label"] == "operator override" and "operator override" in over["note"]

    monkeypatch.setenv("PQC_ORG_DEFAULT_SCANS_PER_HOUR", "50")
    default = client.get("/platform/customers/org-default/rate-limits", headers=owner()).json()
    assert default["limit_source"] == "default" and default["limit_source_label"] == "platform default"
    assert "PQC_ORG_DEFAULT_" in default["note"]

    monkeypatch.delenv("PQC_ORG_DEFAULT_SCANS_PER_HOUR")
    free = client.get("/platform/customers/org-free/rate-limits", headers=owner()).json()
    assert free["limit_source"] == "none" and free["limit_source_label"] == "not limited" and free["enforced"] is False

    js = (pathlib.Path(__file__).resolve().parent / "static_admin" / "index.js").read_text(encoding="utf-8")
    assert "enforced (platform default)" not in js and "limit_source_label" in js and "rateEnforcement(rate.data)" in js
    # And no longer offers a billing-plan label it can never be given.
    assert "billing plan" not in js


class _FakePipeline:
    def __init__(self, store):
        self.store, self.ops = store, []

    def __getattr__(self, name):
        return lambda *a, **k: self.ops.append((name, a, k))

    def execute(self):
        out = []
        for name, a, k in self.ops:
            out.append(getattr(self.store, name)(*a, **k))
        return out


class _FakeRedis:
    def __init__(self):
        self.z = {}

    def pipeline(self, transaction=True):
        return _FakePipeline(self)

    def zremrangebyscore(self, key, lo, hi):
        before = dict(self.z.get(key, {}))
        self.z[key] = {m: s for m, s in before.items() if not (lo <= s <= hi)}
        return len(before) - len(self.z[key])

    def zadd(self, key, mapping):
        self.z.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zcard(self, key):
        return len(self.z.get(key, {}))

    def zrange(self, key, start, stop, withscores=False):
        items = sorted(self.z.get(key, {}).items(), key=lambda kv: kv[1])[start:stop + 1]
        return items if withscores else [m for m, _ in items]

    def expire(self, key, seconds):
        return True

    def zrem(self, key, member):
        return 1 if self.z.get(key, {}).pop(member, None) is not None else 0

    def register_script(self, _source):
        """Emulates org_rate_limits._SLIDING_WINDOW_LUA (the real script runs in test_redis_integration.py)."""
        def run(keys, args):
            key, (now, window, limit, member, _ttl) = keys[0], args
            now, window, limit = float(now), float(window), int(limit)
            self.zremrangebyscore(key, float("-inf"), now - window)
            count = self.zcard(key)
            if count >= limit:
                oldest = self.zrange(key, 0, 0, withscores=True)
                return [0, count, str(oldest[0][1]) if oldest else str(now)]
            self.zadd(key, {member: now})
            return [1, count + 1, ""]
        return run


def test_redis_sliding_window_when_configured(api, monkeypatch):
    client, _, db_path = api
    fake = _FakeRedis()
    monkeypatch.setenv("REDIS_URL", "redis://fake:6379/0")
    monkeypatch.setattr(org_rate_limits, "_redis_client", lambda url: fake)
    set_override(db_path, "org-r", 2, 100)
    codes = [client.get("/assets", headers=bearer("org-r")).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert len(fake.z["pqc:orglimit:api:org-r"]) == 2  # the rejected hit is removed again
    # A broken Redis falls back to the in-process window rather than failing requests.
    monkeypatch.setattr(org_rate_limits, "_redis_client", lambda url: (_ for _ in ()).throw(ConnectionError("down")))
    assert client.get("/assets", headers=bearer("org-r2")).status_code == 200
