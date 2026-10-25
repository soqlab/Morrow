"""The operator-console services against a real Postgres: analytics, rollups, support access, alert
routing, operator SSO/MFA, API keys, token revocation, announcements, invitations and vault key rotation.

Everything else in the suite runs these modules on SQLite. This file runs the real functions with
MORROW_MAIN_DB_BACKEND=postgres and MORROW_FEATURE_STORE_BACKEND=postgres against a private database created for the
run (and dropped afterwards), including the concurrency paths SQLite cannot show: claim races, the dispatcher
lease, and webhook claims. Skipped unless MORROW_TEST_PG_DSN names a disposable server whose role may create
databases:

    MORROW_TEST_PG_DSN=postgresql://morrow:pqtest@127.0.0.1:55432/pq_test python -m pytest -q test_postgres_integration.py
"""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
pytestmark = pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against a real Postgres")

BACKEND = pathlib.Path(__file__).resolve().parent
UTC = timezone.utc


def _admin_conn():
    import psycopg2

    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = True
    return conn


def _reset_module_caches():
    from services import (alert_routing, announcements, api_keys, operator_auth, org_rate_limits,
                          platform_analytics, security_journal, session_revocation, support_sessions, usage_rollups)

    for module in (support_sessions, session_revocation, operator_auth, alert_routing, api_keys, announcements):
        module._TABLES_READY.clear()
    usage_rollups._ready.clear()
    security_journal._ready.clear()
    api_keys._VERIFY_CACHE.clear()
    support_sessions._SESSION_CACHE.clear()
    operator_auth.clear_caches()
    announcements._MAINT_CACHE.update(loaded_at=0.0, db=None, state=None)
    session_revocation._CACHE.update(loaded_at=0.0, db=None, cutoffs={})
    org_rate_limits.reset()
    platform_analytics.clear_cache()
    platform_analytics.clear_meta_cache()


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    from psycopg2.extensions import make_dsn

    name = "pq_it_" + uuid.uuid4().hex[:10]
    admin = _admin_conn()
    admin.cursor().execute(f"CREATE DATABASE {name}")
    admin.close()
    dsn = make_dsn(PG_DSN, dbname=name)
    mp = pytest.MonkeyPatch()
    sqlite_path = str(tmp_path_factory.mktemp("pg-it") / "sqlite-side.db")
    for key, value in {"MORROW_MAIN_DB_BACKEND": "postgres", "MORROW_FEATURE_STORE_BACKEND": "postgres", "DATABASE_URL": dsn,
                       "MORROW_PRODUCT_DATABASE_URL": dsn, "MORROW_SCANNER_DB": sqlite_path, "MORROW_ENVIRONMENT": "local",
                       "MORROW_SUPPORT_SESSION_CACHE_SECONDS": "0", "MORROW_API_KEY_CACHE_SECONDS": "0"}.items():
        mp.setenv(key, value)
    _reset_module_caches()
    import db
    import db_postgres

    db_postgres.ensure_postgres_core_schema(dsn)
    db.init_db()
    try:
        yield dsn
    finally:
        mp.undo()
        _reset_module_caches()
        for key in list(db_postgres._pools):
            try:
                db_postgres._pools.pop(key).closeall()
            except Exception:
                pass
        admin = _admin_conn()
        cur = admin.cursor()
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()", (name,))
        cur.execute(f"DROP DATABASE IF EXISTS {name}")
        admin.close()


def pg_exec(dsn, sql, params=None, fetch=False):
    import psycopg2

    conn = psycopg2.connect(dsn)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows
    finally:
        conn.close()


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def run_threads(n, fn):
    barrier, results = threading.Barrier(n), []

    def worker(i):
        barrier.wait()
        try:
            results.append(("ok", fn(i)))
        except Exception as exc:  # noqa: BLE001 - the test inspects what each racer got
            results.append(("error", exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


# ── platform_analytics: every timestamp kind, every range, percentile_disc ──────────────────────────────────


PROBES = {"probe_tstz": "TIMESTAMPTZ", "probe_ts": "TIMESTAMP", "probe_epoch": "BIGINT", "probe_iso": "TEXT", "probe_space": "TEXT"}


def _probe_value(table, dt):
    if table == "probe_tstz":
        return dt
    if table == "probe_ts":
        return dt.astimezone(UTC).replace(tzinfo=None)
    if table == "probe_epoch":
        return int(dt.timestamp())
    if table == "probe_space":
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return iso(dt)


def test_analytics_buckets_every_timestamp_kind_for_every_range(pg, monkeypatch):
    from services import platform_analytics as pa

    monkeypatch.setattr(pa, "CORE_TABLES", pa.CORE_TABLES | set(PROBES))
    monkeypatch.setattr(pa, "SPACE_FORMAT", pa.SPACE_FORMAT | {("probe_space", "created_at")})
    now = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=2)
    # Every 5h17m for ~100 days: several rows per day, rows in most hours of the last day, previous periods too.
    stamps = [now - timedelta(minutes=317 * i) for i in range(460)]
    for table, col_type in PROBES.items():
        pg_exec(pg, f"CREATE TABLE {table} (id SERIAL PRIMARY KEY, organization_id TEXT NOT NULL, created_at {col_type} NOT NULL)")
        import psycopg2

        conn = psycopg2.connect(pg)
        cur = conn.cursor()
        for i, dt in enumerate(stamps):
            cur.execute(f"INSERT INTO {table} (organization_id, created_at) VALUES (%s, %s)", ("org-a" if i % 3 else "org-b", _probe_value(table, dt)))
        conn.commit()
        conn.close()
    pa.clear_meta_cache()
    expected_kind = {"probe_tstz": "tstz", "probe_ts": "ts", "probe_epoch": "epoch", "probe_iso": "iso", "probe_space": "space"}
    with pa.Reader() as r:
        for table in PROBES:
            assert r.ts_kind(table, "created_at") == expected_kind[table]
            for range_key in pa.RANGES:
                win = pa.Window(range_key, now=now)
                got = pa.bucket_agg(r, table, "created_at", win, {"n": "COUNT(*)", "orgs": "COUNT(DISTINCT organization_id)"},
                                    "organization_id <> ?", ["nobody"])
                want = {}
                for dt in stamps:
                    if win.start <= dt < win.end:
                        floor = dt.replace(minute=0, second=0) if win.bucket == "hour" else dt.replace(hour=0, minute=0, second=0)
                        want[pa.iso(floor)] = want.get(pa.iso(floor), 0) + 1
                assert {k: int(v["n"]) for k, v in got.items()} == want, (table, range_key)
                assert set(got) <= set(win.labels)
                period = pa.period_agg(r, table, "created_at", win.prev_start, win.prev_end, {"n": "COUNT(*)"})
                assert int(period["n"]) == sum(1 for dt in stamps if win.prev_start <= dt < win.prev_end), (table, range_key)
                assert pa.count_before(r, table, "created_at", win.start) == sum(1 for dt in stamps if dt < win.start)


def _add_request(dsn, org, status, duration, at, actor="", path="/assets"):
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        conn.execute("INSERT INTO platform_request_events (id, created_at, organization_id, actor_id, actor_role, source_ip, method, "
                     "path, status_code, duration_ms, user_agent, authenticated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (uuid.uuid4().hex, iso(at), org, actor, "viewer", "192.0.2.1", "GET", path, status, duration, "Other",
                      1 if actor else 0))
        conn.commit()


def _add_auth(org, user, event_type, at):
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        conn.execute("INSERT INTO platform_auth_events (id, created_at, organization_id, user_id, actor_role, event_type, login_method, "
                     "ip_address, user_agent, subject_ref, status_code) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (uuid.uuid4().hex, iso(at), org, user, "viewer", event_type, "password", "192.0.2.1", "Other", "",
                      200 if event_type.endswith("success") else 401))
        conn.commit()


def test_latency_percentile_disc_matches_nearest_rank(pg):
    from services import platform_analytics as pa
    from services import security_journal

    security_journal.init_tables()
    now = datetime.now(UTC).replace(microsecond=0)
    base = now - timedelta(hours=30)
    samples = {}
    for i in range(157):
        at = base + timedelta(minutes=11 * i)
        duration = float((i * 37) % 101) + 0.25
        org = "lat-a" if i % 4 else "lat-b"
        _add_request(pg, org, 200, duration, at, actor=f"u{i % 5}")
        samples.setdefault(org, []).append((at, duration))
    end = now + timedelta(seconds=1)
    with pa.Reader() as r:
        for org in (None, "lat-a", "lat-b"):
            rows = [x for o, xs in samples.items() if org in (None, o) for x in xs]
            for bucket in ("hour", "day"):
                p95, per_bucket = pa.latency_stats(r, base, end, bucket=bucket, org=org)
                assert p95 == pa._nearest_rank(sorted(d for _, d in rows), 95)
                groups = {}
                for at, d in rows:
                    floor = at.replace(minute=0, second=0) if bucket == "hour" else at.replace(hour=0, minute=0, second=0)
                    groups.setdefault(pa.iso(floor), []).append(d)
                assert per_bucket == {k: {"p50": pa._nearest_rank(sorted(v), 50), "p95": pa._nearest_rank(sorted(v), 95)}
                                      for k, v in groups.items()}


class _Hooks(dict):
    def __missing__(self, key):
        return lambda: {}


def _query_failures(body):
    return [u for u in body.get("unavailable") or [] if "failed" in str(u.get("reason", "")).lower()]


def test_analytics_views_run_on_postgres(pg):
    import db
    from services import api_keys, feedback, platform_analytics as pa, security_journal, usage_rollups

    security_journal.init_tables()
    feedback.init_tables()
    api_keys.init_tables()
    usage_rollups.init_tables()
    pg_exec(pg, "DELETE FROM platform_request_events")  # the latency test's rows would otherwise count here
    # The platform admin journal, as app._ensure_platform_admin_schema creates it on Postgres (avoids importing app).
    pg_exec(pg, "CREATE TABLE IF NOT EXISTS platform_admin_events (id BIGSERIAL PRIMARY KEY, organization_id TEXT NOT NULL DEFAULT '', "
                "action TEXT NOT NULL DEFAULT '', actor_id TEXT NOT NULL DEFAULT 'platform-admin', reason TEXT NOT NULL DEFAULT '', "
                "details_json JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
    pg_exec(pg, "INSERT INTO platform_admin_events (organization_id, action, reason) VALUES ('org-alpha', 'customer.note', 'hello')")
    db.upsert_organization("org-alpha", "Alpha 100% _Corp")
    db.upsert_organization("org-beta", "Beta Co")
    now = datetime.now(UTC)
    for minutes, org in ((3, "org-alpha"), (4, "org-alpha"), (60 * 26, "org-alpha"), (60 * 24 * 9, "org-beta")):
        pg_exec(pg, "INSERT INTO scans (id, organization_id, status, created_at) VALUES (%s, %s, 'completed', %s)",
                (str(uuid.uuid4()), org, now - timedelta(minutes=minutes)))
    for status, duration in ((200, 10.0), (200, 20.0), (404, 30.0), (429, 40.0), (500, 50.0)):
        _add_request(pg, "org-alpha", status, duration, now - timedelta(minutes=3), actor="alice", path="/boom" if status == 500 else "/ok")
    _add_auth("org-alpha", "alice", "login.success", now - timedelta(minutes=2))
    _add_auth("org-alpha", "alice", "login.failure", now - timedelta(minutes=2))
    api_keys.create_key("org-alpha", "CI", ["read"], 5, "tester")
    pa.clear_cache()

    for range_key in pa.RANGES:
        overview = pa.overview(range_key)
        assert not _query_failures(overview), overview["unavailable"]
        customer = pa.customer("org-alpha", range_key)
        assert customer and not _query_failures(customer), customer and customer["unavailable"]
        usage = pa.usage(range_key)
        assert not _query_failures(usage), usage["unavailable"]
        assert usage["organizations_total"] >= 2
        pa.clear_cache()
    day = pa.overview("24h")
    assert day["kpis"]["api_requests"]["value"] == 5
    assert day["kpis"]["error_rate_pct"]["value"] == 20.0
    assert day["kpis"]["p95_latency_ms"]["value"] == 50.0
    assert day["kpis"]["scans"]["value"] == 2
    week = pa.overview("7d")
    assert (week["kpis"]["scans"]["value"], week["kpis"]["scans"]["previous"]) == (3, 1)
    assert pa.customer("org-alpha", "24h")["kpis"]["api_requests"]["value"] == 5

    found = pa.search("100%", 10, False, lambda: [])
    assert [x for x in found["results"] if "org-alpha" in json.dumps(x)]
    assert not [x for x in pa.search("0%_c", 10, False, lambda: [])["results"] if "org-beta" in json.dumps(x)]
    notes = pa.notifications(_Hooks(), now=now)
    assert isinstance(notes.get("items"), list) and not _query_failures(notes)
    jobs = pa.jobs(_Hooks(), now=now)
    assert isinstance(jobs, dict) and not _query_failures(jobs)


# ── usage_rollups: rollup, backfill, idempotency, concurrent replicas ────────────────────────────────────────


def test_usage_rollups_backfill_idempotent_and_concurrent(pg, monkeypatch):
    from db_feature_store import feature_conn
    from services import security_journal, usage_rollups

    monkeypatch.setenv("MORROW_TRAFFIC_RETENTION_DAYS", "30")
    monkeypatch.setenv("MORROW_AUTH_LOG_RETENTION_DAYS", "30")
    security_journal.init_tables()
    usage_rollups.init_tables()
    with feature_conn() as conn:
        for table in ("platform_request_events", "platform_auth_events", "platform_usage_daily", "platform_active_users_daily",
                      "platform_usage_rollup_days", "platform_usage_routes_daily"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    day20 = (datetime.now(UTC) - timedelta(days=20)).replace(hour=12, minute=0, second=0, microsecond=0)
    midnight = day20.replace(hour=0)
    for i in range(4):
        _add_request(pg, "roll-a", 200, 10.0 + i, day20, actor=f"a-{i % 2}")
    _add_request(pg, "roll-a", 500, 900.0, day20, actor="a-0")
    _add_request(pg, "roll-a", 429, 5.0, day20, actor="a-0")
    _add_request(pg, "roll-b", 404, 30.0, day20, actor="b-0")
    _add_request(pg, "roll-a", 200, 1.0, midnight + timedelta(microseconds=500000))  # first second of the day
    _add_request(pg, "roll-a", 200, 1.0, midnight - timedelta(microseconds=1))  # last instant of the previous day
    _add_auth("roll-a", "login-a", "login.success", day20)
    _add_auth("roll-a", "login-a", "login.failure", day20)
    pg_exec(pg, "INSERT INTO scans (id, organization_id, status, created_at) VALUES (%s, 'roll-a', 'completed', %s)",
            (str(uuid.uuid4()), day20))

    first = usage_rollups.run()
    assert first["error"] is None and len(first["rolled"]) >= 25
    key = day20.strftime("%Y-%m-%d")

    def snapshot():
        with feature_conn() as conn:
            daily = [dict(r) for r in conn.execute("SELECT * FROM platform_usage_daily WHERE day >= ? ORDER BY day, organization_id",
                                                   (usage_rollups.day_key(midnight - timedelta(days=1)),)).fetchall()]
            actors = [tuple(r) for r in conn.execute("SELECT day, organization_id, actor_hash FROM platform_active_users_daily "
                                                     "ORDER BY 1, 2, 3").fetchall()]
            days = [tuple(r)[:4] for r in conn.execute("SELECT day, requests, p50_ms, p95_ms FROM platform_usage_rollup_days ORDER BY day").fetchall()]
        for row in daily:
            row.pop("rolled_at", None)
        return daily, actors, days

    daily, actors, days = snapshot()
    alpha = next(r for r in daily if r["day"] == key and r["organization_id"] == "roll-a")
    assert (alpha["requests"], alpha["server_errors"], alpha["rate_limited"], alpha["authenticated_requests"]) == (7, 1, 1, 6)
    assert (alpha["logins_success"], alpha["logins_failed"], alpha["scans"]) == (1, 1, 1)
    assert alpha["p95_ms"] == 900.0 and float(alpha["duration_max_ms"]) == 900.0
    assert all("a-0" not in h and "login-a" not in h for _, _, h in actors)
    previous = next(r for r in daily if r["organization_id"] == "roll-a" and r["day"] == usage_rollups.day_key(midnight - timedelta(days=1)))
    assert previous["requests"] == 1

    assert usage_rollups.run()["rolled"] == []  # idempotent: nothing new
    rebuilt = usage_rollups.run(rebuild=True)
    assert rebuilt["error"] is None and snapshot() == (daily, actors, days)

    # Two replicas re-rolling the same day at once: the advisory lock serializes them, neither fails.
    results = run_threads(4, lambda i: usage_rollups.roll_day(day20))
    assert all(kind == "ok" for kind, _ in results), results
    assert snapshot() == (daily, actors, days)
    assert usage_rollups.state().get("last_error") == ""


# ── org_rate_limits: override loading ─────────────────────────────────────────────────────────────────────────


def test_org_rate_limit_overrides_load_from_postgres(pg):
    from db_feature_store import feature_conn
    from services import admin_console, org_rate_limits

    admin_console._init_tables()
    with feature_conn() as conn:
        conn.execute("INSERT INTO admin_rate_limits (org_id, scans_per_hour, api_calls_per_min, updated_at) VALUES (?, ?, ?, ?)",
                     ("limited-org", 7, 42, iso(datetime.now(UTC))))
        conn.commit()
    assert org_rate_limits.load_overrides()["limited-org"] == (42, 7)
    org_rate_limits.refresh_overrides()
    assert org_rate_limits.stored_override("limited-org") == (42, 7)
    assert org_rate_limits.limits_for("limited-org") == (42, 7)


# ── support sessions ──────────────────────────────────────────────────────────────────────────────────────────


def test_support_sessions_lifecycle_and_launch_code_race(pg, monkeypatch):
    from services import support_sessions as ss

    monkeypatch.setenv("MORROW_AUTH_JWT_SECRET", "pg-integration-support-signing-key-0123456789")
    ss.set_support_access("sup-org", True, "customer-admin-test")
    created = ss.create_session(organization_id="sup-org", operator_id="sam", operator_role="support", operator_display="Sam",
                                reason="Investigating a customer ticket", minutes=30, ticket_ref="T-1")
    results = run_threads(8, lambda i: ss.exchange_code(created["code"]))
    wins = [v for kind, v in results if kind == "ok"]
    assert len(wins) == 1 and all(getattr(v, "status_code", None) == 409 for kind, v in results if kind == "error"), [(k, repr(v)[:200]) for k, v in results]
    sid = created["session"]["id"]
    ss.record_request(sid, "sup-org", "GET", "/assets", 200)
    assert [s["id"] for s in ss.list_sessions("sup-org", active=True)] == [sid]
    assert ss.list_sessions("sup-org", active=True)[0]["request_count"] == 1
    assert ss.support_access("sup-org")["allowed"] is True
    ss.set_support_access("sup-org", False, "admin@sup")
    assert ss.support_access("sup-org")["allowed"] is False
    ss.set_support_access("sup-org", True, "admin@sup")
    revoked = run_threads(4, lambda i: ss.revoke_session(sid, revoked_by="owner", reason="done"))
    assert all(kind == "ok" and v["status"] == "revoked" for kind, v in revoked)
    assert ss.list_sessions("sup-org", active=False)[0]["status"] == "revoked"
    assert ss.list_requests(sid)[0]["path"] == "/assets"


# ── alert routing ─────────────────────────────────────────────────────────────────────────────────────────────


_LEASE_WORKER = r"""
import os, sys
sys.path.insert(0, os.environ["MORROW_BACKEND_DIR"])
from datetime import datetime, timezone
import time
from services import alert_routing as ar
ar.init_tables()
start = float(sys.argv[1])
while time.time() < start:
    time.sleep(0.002)
print("LEASE", ar._acquire_lease(datetime.now(timezone.utc), 120.0))
"""


def test_alert_routing_channels_ledger_deliveries_and_lease(pg, monkeypatch):
    from db_feature_store import feature_conn
    from services import alert_routing as ar

    monkeypatch.setattr(ar, "resolve_host", lambda host, port: ["93.184.216.34"])
    ar.init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM platform_alert_dispatcher")
        conn.commit()
    channel = ar.create_channel({"kind": "slack_webhook", "name": "Ops", "target": "https://hooks.slack.com/services/T0/B0/xyz",
                                 "min_severity": "warn", "kinds": [], "quiet_hours": None}, "tester")
    assert channel["enabled"] in (1, True) and ar.unseal(channel["target_sealed"]).startswith("https://hooks.slack.com/")
    updated, changed = ar.update_channel(channel["id"], {"enabled": False, "name": "Ops 2"}, "tester")
    assert changed == ["enabled", "name"] and not updated["enabled"]
    ar.update_channel(channel["id"], {"enabled": True}, "tester")

    sent = []
    monkeypatch.setattr(ar, "send", lambda ch, plain, ev, items, base_url="", **k: sent.append((ev, [i["id"] for i in items])) or
                        {"ok": True, "http_status": 200, "latency_ms": 5})
    now = datetime.now(UTC).replace(microsecond=0)
    items = [{"id": f"n{i}", "severity": "critical", "kind": "sla_breach", "title": f"Alert {i}", "created_at": iso(now)} for i in range(2)]
    snap = lambda: {"items": items, "counts": {"total": len(items)}, "unavailable": []}  # noqa: E731
    first = ar.run_once(snap, now=now)
    assert first["status"] == "ok" and first["sent"] == 2, first
    assert ar.run_once(snap, now=now + timedelta(minutes=1))["sent"] == 0  # the ledger remembers
    items.pop()
    resolved = ar.run_once(snap, now=now + timedelta(minutes=2))
    assert resolved["resolved"] == 1
    deliveries = ar.list_deliveries(channel["id"], status="sent", event="trigger")
    assert len(deliveries) == 2 and all(isinstance(d["id"], int) for d in deliveries)
    state = ar.job_state(now=now + timedelta(minutes=3))
    assert state

    # The lease: one holder at a time across processes, re-entrant for the holder, taken over once expired.
    with feature_conn() as conn:
        conn.execute("DELETE FROM platform_alert_dispatcher")
        conn.commit()
    env = {**os.environ, "MORROW_BACKEND_DIR": str(BACKEND)}
    start = time.time() + 6.0
    procs = [subprocess.Popen([sys.executable, "-c", _LEASE_WORKER, str(start)], cwd=str(BACKEND), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    outcomes = []
    for proc in procs:
        out, err = proc.communicate(timeout=180)
        assert proc.returncode == 0, err[-2000:]
        outcomes.append(next(line for line in out.splitlines() if line.startswith("LEASE")))
    assert sorted(outcomes) == ["LEASE False"] * 3 + ["LEASE True"]
    assert ar._acquire_lease(datetime.now(UTC), 120.0) is False
    with feature_conn() as conn:
        conn.execute("UPDATE platform_alert_dispatcher SET lease_expires_at = ?", (iso(datetime.now(UTC) - timedelta(seconds=5)),))
        conn.commit()
    assert ar._acquire_lease(datetime.now(UTC), 120.0) is True
    assert ar._acquire_lease(datetime.now(UTC), 120.0) is True  # the holder renews

    removed = ar.delete_channel(channel["id"])
    assert removed["channel"]["id"] == channel["id"] and ar.get_channel(channel["id"]) is None


# ── operator auth: sessions, TOTP, recovery codes, SSO state ─────────────────────────────────────────────────


def test_operator_sessions_mfa_and_sso_state_on_postgres(pg, monkeypatch):
    from services import operator_auth as oa

    raw, row = oa.create_session("alice", "owner", "sso", email="alice@corp.example", subject="sub-1", mfa_verified=False)
    loaded, state = oa.load_session(raw)
    assert state == "active" and loaded["operator"] == "alice" and isinstance(loaded["created_at"], float)
    assert oa.session_valid_cached(raw)
    oa.mark_session_mfa(raw)
    assert float(oa.load_session(raw)[0]["mfa_verified_at"]) > 0
    assert [s["session_ref"] for s in oa.list_sessions()] == [row["ref"]]
    raw2, _ = oa.create_session("alice", "owner", "operator_key")
    assert oa.revoke_operator_sessions("alice", "owner", "rotation") == 2
    assert oa.load_session(raw)[1] == "revoked" and oa.load_session(raw2)[1] == "revoked"

    identity = "sso:alice@corp.example"
    enrol = oa.begin_enrolment(identity, "alice@corp.example")
    secret = oa.decode_base32_secret(enrol["secret"])
    assert oa.mfa_record(identity)["secret_enc"] != enrol["secret"]
    now = time.time()
    confirmed = oa.verify_mfa(identity, oa.totp(secret, now), confirm_pending=True, now=now)
    assert len(confirmed["recovery_codes"]) >= 8
    later = now + 60
    racers = run_threads(5, lambda i: oa.verify_mfa(identity, oa.totp(secret, later), now=later))
    assert [k for k, _ in racers].count("ok") == 1  # one TOTP step is accepted once
    code = confirmed["recovery_codes"][0]
    racers = run_threads(5, lambda i: oa.verify_mfa(identity, recovery_code=code))
    assert [k for k, _ in racers].count("ok") == 1
    assert oa.mfa_status(identity)["recovery_codes_remaining"] == len(confirmed["recovery_codes"]) - 1
    assert oa.list_mfa_identities()[0]["identity"] == identity
    assert len(oa.regenerate_recovery_codes(identity)) == len(confirmed["recovery_codes"])
    assert oa.reset_mfa(identity) is True and oa.mfa_record(identity) is None

    monkeypatch.setattr(oa, "sso_enabled", lambda: True)
    monkeypatch.setattr(oa, "oidc_settings", lambda: {"issuer": "https://idp.example", "client_id": "c", "scopes": "openid email"})
    monkeypatch.setattr(oa, "discovery", lambda issuer, force=False: {"authorization_endpoint": "https://idp.example/auth"})
    _, sso_state = oa.start_sso("https://admin.example/vendor-admin/sso/callback")
    consumed = run_threads(6, lambda i: oa._consume_state(sso_state, sso_state))
    assert [k for k, _ in consumed].count("ok") == 1  # a state is single use, even under a race
    _, stale = oa.start_sso("https://admin.example/vendor-admin/sso/callback")
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        conn.execute("UPDATE platform_oidc_states SET expires_at = ?", (time.time() - 1,))
        conn.commit()
    with pytest.raises(oa.OperatorAuthError) as expired:
        oa._consume_state(stale, stale)
    assert expired.value.code == "sso_state_expired"


# ── API keys, token revocation, announcements and maintenance, invitations ────────────────────────────────────


def test_api_keys_revocation_announcements_and_invitations(pg):
    from services import admin_console, announcements, api_keys, invite_links, platform_access, session_revocation

    record, token = api_keys.create_key("key-org", "CI reader", ["read"], 30, "tester")
    assert api_keys.verify_token(token)[2] == 200 and api_keys.organization_for_token(token) == "key-org"
    new, new_token, previous = api_keys.rotate_key(record["id"], "tester", "rotation", 30, grace_seconds=60)
    assert previous["status"] == "active" and api_keys.verify_token(new_token)[2] == 200
    assert api_keys.revoke_organization_keys("key-org", "tester", "offboarding") == 2
    assert api_keys.verify_token(token)[1] == "API key has been revoked."
    assert [k["status"] for k in api_keys.list_keys("key-org")] == ["revoked", "revoked"]

    cutoff = session_revocation.revoke("user", "u-1", revoked_by="owner", reason="lost laptop")
    session_revocation.revoke("user", "u-1", revoked_by="owner", reason="again")  # upsert path
    session_revocation._CACHE.update(loaded_at=0.0)
    assert session_revocation.is_revoked({"sub": "u-1", "iat": cutoff - 5})
    assert not session_revocation.is_revoked({"sub": "u-1", "iat": cutoff + 5})
    assert [r["subject"] for r in session_revocation.list_revocations()] == ["user:u-1"]

    first = announcements.create_announcement({"title": "Maintenance", "body": "Tonight", "severity": "warn", "audience": "all"}, "ops")
    second = announcements.create_announcement({"title": "For you", "body": "Hi", "severity": "info", "audience": "orgs",
                                                "organization_ids": ["key-org"]}, "ops")
    assert isinstance(first["id"], int) and second["id"] > first["id"]
    assert [a["id"] for a in announcements.active_for("key-org")] == [first["id"], second["id"]]
    assert announcements.delete_announcement(second["id"]) is True
    assert announcements.set_maintenance(True, "Upgrading", "", "ops")["enabled"] is True
    assert announcements.set_maintenance(False, "", "", "ops")["enabled"] is False
    assert announcements.get_maintenance(use_cache=False)["enabled"] is False

    admin_console._init_tables()
    org = admin_console.create_org(name="Invite Org", actor="ops")["org_id"]
    invite = admin_console.invite_user(org, "new.user@invite.example", role="analyst", invited_by="ops")
    assert invite_links.preview(invite["token"])["status"] == "valid"
    results = run_threads(6, lambda i: platform_access.accept_invitation_for_user(
        invite["token"], user_id=f"user-{i}", email="new.user@invite.example"))
    oks = [v for k, v in results if k == "ok"]
    assert len(oks) == 1, results
    assert all(getattr(v, "status_code", None) == 409 for k, v in results if k == "error"), [(k, repr(v)[:200]) for k, v in results]
    assert invite_links.preview(invite["token"])["status"] == "used"
    assert [u["email"] for u in admin_console.list_users(org)] == ["new.user@invite.example"]


# ── scripts/rotate-vault-master-key.py against Postgres tables ─────────────────────────────────────────────────


def test_vault_key_rotation_against_postgres(pg, tmp_path, monkeypatch, capsys):
    import sqlite3

    from cryptography.fernet import Fernet

    spec = importlib.util.spec_from_file_location("rotate_vault_master_key_pg", BACKEND.parent / "scripts" / "rotate-vault-master-key.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", old_key)
    monkeypatch.delenv("MORROW_VAULT_MASTER_KEY_NEW", raising=False)
    old = Fernet(old_key.encode())

    import vault_db
    from services import alert_routing, gateway, operator_auth

    vault_db.ensure_vault_tables()
    gateway.init_tables()
    operator_auth.init_tables()
    alert_routing.init_tables()
    pg_exec(pg, "INSERT INTO credentials (organization_id, name, provider, secret_enc, created_at, updated_at, last_rotated_at) "
                "VALUES ('org', 'aws-prod', 'aws', %s, now(), now(), now())", (old.encrypt(b"AKIA-secret").decode(),))
    pg_exec(pg, "INSERT INTO gateway_sites (id, organization_id, hostname, revision, data) VALUES ('site-1', 'org', 'a.example', 1, %s)",
            (json.dumps({"id": "site-1", "sealed_key": old.encrypt(b"gateway-secret").decode()}, sort_keys=True, separators=(",", ":")),))
    pg_exec(pg, "INSERT INTO platform_operator_mfa (identity, secret_enc, status, created_at, updated_at) VALUES ('sso:rot@corp', %s, 'active', '', '')",
            (old.encrypt(b"JBSWY3DPEHPK3PXP").decode(),))
    pg_exec(pg, "DELETE FROM platform_alert_channels")
    pg_exec(pg, "INSERT INTO platform_alert_channels (id, kind, name, target_sealed, created_at, updated_at) VALUES "
                "('rot1', 'pagerduty', 'PD', %s, '', ''), ('rot2', 'email', 'Mail', 'plain:[\"x@example.com\"]', '', '')",
            ("fernet:" + old.encrypt(b"ROUTINGKEY").decode(),))
    sqlite_db = tmp_path / "main.db"
    with sqlite3.connect(sqlite_db) as conn:
        conn.execute("CREATE TABLE github_tokens (id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, access_token TEXT NOT NULL)")
        conn.execute("INSERT INTO github_tokens VALUES ('t1', 'org', 'u1', ?)", (module.github_fernet(old_key).encrypt(b"gho_x").decode(),))

    def values():
        return {
            "cred": pg_exec(pg, "SELECT secret_enc FROM credentials WHERE name = 'aws-prod'", fetch=True)[0][0],
            "site": json.loads(pg_exec(pg, "SELECT data FROM gateway_sites WHERE id = 'site-1'", fetch=True)[0][0])["sealed_key"],
            "mfa": pg_exec(pg, "SELECT secret_enc FROM platform_operator_mfa WHERE identity = 'sso:rot@corp'", fetch=True)[0][0],
            "alert": pg_exec(pg, "SELECT target_sealed FROM platform_alert_channels WHERE id = 'rot1'", fetch=True)[0][0],
            "plain": pg_exec(pg, "SELECT target_sealed FROM platform_alert_channels WHERE id = 'rot2'", fetch=True)[0][0],
        }

    before = values()
    assert module.main(["--sqlite", str(sqlite_db)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "dry-run", report
    targets = report["targets"]
    assert targets["vault_credentials"]["rotated"] == 1 and targets["operator_mfa_secrets"]["rotated"] == 1
    assert targets["alert_channel_targets"]["rotated"] == 1 and targets["gateway_sealed_keys"]["rotated"] == 1
    assert report["verified"] == 5 and values() == before

    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", new_key)
    assert module.main(["--sqlite", str(sqlite_db), "--apply"]) == 0
    out = capsys.readouterr()
    assert new_key not in out.out + out.err and old_key not in out.out + out.err
    after, fresh = values(), Fernet(new_key.encode())
    assert fresh.decrypt(after["cred"].encode()) == b"AKIA-secret"
    assert fresh.decrypt(after["site"].encode()) == b"gateway-secret"
    assert fresh.decrypt(after["mfa"].encode()) == b"JBSWY3DPEHPK3PXP"
    assert fresh.decrypt(after["alert"][len("fernet:"):].encode()) == b"ROUTINGKEY"
    assert after["plain"] == before["plain"]
