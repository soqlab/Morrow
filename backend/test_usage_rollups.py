"""Daily usage rollups: long-term trends beyond raw journal retention, previous periods for 30d/90d, and
truthful coverage. Uses the analytics test fixture (throwaway SQLite database, real ASGI stack)."""

import json
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest

from services import platform_analytics as pa
from services import security_journal, usage_rollups
from test_platform_analytics import add_auth, add_request, add_scan, api, execute, make_org, now, owner  # noqa: F401


def day_at(days_ago, hour=12):
    return (now() - timedelta(days=days_ago)).replace(hour=hour, minute=0, second=0, microsecond=0)


def label(days_ago):
    return day_at(days_ago).strftime("%Y-%m-%dT00:00:00Z")


def rows(db_path, sql, params=()):
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(sql, params).fetchall()


@pytest.fixture
def seeded(api, monkeypatch):  # noqa: F811  (api is the imported pytest fixture)
    """Raw rows 20 and 10 days old, rolled up while they were still retained, then expired (7-day retention)."""
    client, app, db_path = api
    make_org(client, "org-alpha")
    make_org(client, "org-beta")
    monkeypatch.setenv("PQC_TRAFFIC_RETENTION_DAYS", "30")
    for i in range(4):
        add_request(db_path, "org-alpha", 200, 10.0 + i, day_at(20), actor=f"alpha-{i % 2}")
    add_request(db_path, "org-alpha", 500, 900.0, day_at(20), actor="alpha-0")
    add_request(db_path, "org-alpha", 429, 5.0, day_at(20), actor="alpha-0")
    add_request(db_path, "org-beta", 404, 30.0, day_at(20), actor="beta-0")
    add_request(db_path, "", 200, 2.0, day_at(20))
    for i in range(3):
        add_request(db_path, "org-alpha", 200, 40.0, day_at(10), actor="alpha-2")
    add_auth(db_path, "org-alpha", "alpha-login", "login.success", day_at(20))
    add_auth(db_path, "org-alpha", "alpha-login", "login.failure", day_at(20))
    add_scan(db_path, "org-alpha", day_at(20))
    first = usage_rollups.run()
    assert first["error"] is None and len(first["rolled"]) >= 25
    # Recent raw traffic, still inside the 7-day window.
    add_request(db_path, "org-alpha", 200, 20.0, now() - timedelta(minutes=5), actor="alpha-0")
    monkeypatch.setenv("PQC_TRAFFIC_RETENTION_DAYS", "7")
    security_journal.prune()
    pa.clear_cache()
    return client, app, db_path


def test_rollup_is_idempotent_and_stores_no_raw_actor_ids(seeded):
    client, _, db_path = seeded
    snapshot = rows(db_path, "SELECT * FROM platform_usage_daily ORDER BY day, organization_id")
    assert usage_rollups.run()["rolled"] == []  # nothing new to roll
    alpha = rows(db_path, "SELECT requests, client_errors, server_errors, rate_limited, authenticated_requests, logins_success, "
                          "logins_failed, scans, p95_ms FROM platform_usage_daily WHERE day = ? AND organization_id = 'org-alpha'",
                 (label(20)[:10],))
    assert alpha == [(6, 0, 1, 1, 6, 1, 1, 1, 900.0)]
    hashes = rows(db_path, "SELECT organization_id, actor_hash FROM platform_active_users_daily WHERE day = ?", (label(20)[:10],))
    assert sorted(o for o, _ in hashes) == ["org-alpha", "org-alpha", "org-alpha", "org-beta"]  # alpha-0, alpha-1, alpha-login
    dump = json.dumps(rows(db_path, "SELECT * FROM platform_active_users_daily"))
    for raw_id in ("alpha-0", "alpha-1", "alpha-login", "beta-0"):
        assert raw_id not in dump
    # A forced rebuild re-rolls every whole day the journal still holds completely -- which is what
    # lets a restored or over-retained journal become answerable at all -- and never changes a
    # value. A day that is only partly retained is still excluded: see
    # test_a_partially_retained_day_is_not_rolled_up and usage_rollups._complete_from.
    rebuilt = usage_rollups.run(rebuild=True)
    assert all(r["day"] >= usage_rollups.day_key(usage_rollups.rollup_start()) for r in rebuilt["rolled"])
    assert rows(db_path, "SELECT * FROM platform_usage_daily WHERE day <= ? ORDER BY day, organization_id", (label(8)[:10],)) == \
        [r for r in snapshot if r[0] <= label(8)[:10]]


def test_a_partially_retained_day_is_not_rolled_up(api, monkeypatch):  # noqa: F811
    client, _, db_path = api
    usage_rollups.run()
    days = {r[0] for r in rows(db_path, "SELECT day FROM platform_usage_rollup_days")}
    cutoff_day = (now() - timedelta(days=7)).strftime("%Y-%m-%d")
    assert cutoff_day not in days
    assert now().strftime("%Y-%m-%d") not in days  # today is not closed
    assert len(days) in (5, 6)  # the closed days fully inside the retention window


def test_overview_30d_reads_rollups_beyond_raw_retention(seeded):
    client, _, db_path = seeded
    body = client.get("/platform/analytics/overview?range=30d", headers=owner()).json()
    points = {p["t"]: p for p in body["series"]["requests"]}
    assert (points[label(20)]["total"], points[label(20)]["client_errors"], points[label(20)]["server_errors"],
            points[label(20)]["rate_limited"]) == (8, 1, 1, 1)
    assert points[label(10)]["total"] == 3
    assert points[label(15)]["total"] == 0  # rolled up and empty: a real zero
    assert body["series"]["requests"][0]["total"] == 0  # rolled up while fully retained (30-day retention then)
    assert body["kpis"]["api_requests"]["value"] == 12
    assert body["series"]["latency"][[p["t"] for p in body["series"]["latency"]].index(label(20))]["p95"] == 900.0
    assert body["kpis"]["p95_latency_ms"]["value"] is not None
    logins = {p["t"]: p for p in body["series"]["logins"]}
    assert (logins[label(20)]["success"], logins[label(20)]["failed"]) == (1, 1)
    active = {p["t"]: p["value"] for p in body["series"]["active_users"]}
    assert active[label(20)] == 4 and active[label(10)] == 1
    assert body["kpis"]["active_users"]["value"] == 5  # alpha-0/1/2, alpha-login, beta-0 (hash-distinct)
    cov = body["coverage"]
    assert cov["platform_request_events"]["range_complete"] is True  # raw rows plus rollups cover every day
    assert cov["platform_request_events"]["previous_complete"] is False
    assert cov["platform_request_events"]["rollups_used"] is True
    assert cov["platform_usage_daily"]["days_rolled"] >= 25 and cov["platform_usage_daily"]["range_days_rolled"] >= 25
    ranked = {o["organization_id"]: o for o in body["top"]["organizations_by_activity"]}
    assert ranked["org-alpha"]["requests"] == 10 and ranked["org-beta"]["requests"] == 1


def test_previous_period_deltas_use_rollups(seeded):
    client, _, db_path = seeded
    week = client.get("/platform/analytics/overview?range=7d", headers=owner()).json()
    api_requests = week["kpis"]["api_requests"]
    assert api_requests["value"] == 1 and api_requests["previous"] == 3  # the day-10 rows are in the previous week
    assert api_requests["delta_pct"] == round((1 - 3) / 3 * 100, 1)
    assert not any(u["metric"] == "api_requests.previous" for u in week["unavailable"])
    assert week["coverage"]["platform_request_events"]["previous_complete"] is True
    month = client.get("/platform/analytics/overview?range=30d", headers=owner()).json()
    assert month["kpis"]["api_requests"]["previous"] is None  # 30-60 days ago was never rolled up
    assert any(u["metric"] == "api_requests.previous" for u in month["unavailable"])
    quarter = client.get("/platform/analytics/overview?range=90d", headers=owner()).json()
    assert quarter["series"]["requests"][0]["total"] is None  # 89 days ago: neither raw nor rolled up, so unknown
    assert quarter["coverage"]["platform_request_events"]["range_complete"] is False
    assert {p["t"]: p for p in quarter["series"]["requests"]}[label(20)]["total"] == 8


def test_customer_360_uses_rollups_and_stays_tenant_scoped(seeded):
    client, _, db_path = seeded
    res = client.get("/platform/analytics/customers/org-alpha?range=30d", headers=owner())
    assert res.status_code == 200, res.text
    body = res.json()
    assert "org-beta" not in res.text
    assert body["kpis"]["api_requests"]["value"] == 10
    points = {p["t"]: p for p in body["series"]["requests"]}
    assert (points[label(20)]["total"], points[label(20)]["client_errors"], points[label(20)]["server_errors"]) == (6, 1, 1)
    assert body["kpis"]["active_users"]["value"] == 4
    assert body["kpis"]["logins"]["value"] == 1
    beta = client.get("/platform/analytics/customers/org-beta?range=30d", headers=owner()).json()
    assert beta["kpis"]["api_requests"]["value"] == 1 and beta["kpis"]["active_users"]["value"] == 1

    week = client.get("/platform/analytics/customers/org-alpha?range=7d", headers=owner()).json()
    assert week["kpis"]["api_requests"]["previous"] == 3


def test_jobs_report_usage_rollups(seeded):
    client, _, _ = seeded
    jobs = {j["key"]: j for j in client.get("/platform/jobs", headers=owner()).json()["jobs"]}
    assert jobs["usage_rollups"]["status"] == "ok" and jobs["usage_rollups"]["last_run_at"]


def _without_timestamp(payload):
    payload = json.loads(json.dumps(payload))
    payload.pop("generated_at")
    return payload


@pytest.fixture
def retained(api):  # noqa: F811  (api is the imported pytest fixture)
    """Raw traffic on every retained day (including the first microseconds after midnight), rolled up."""
    client, app, db_path = api
    for org in ("org-alpha", "org-beta", "org-gamma"):
        make_org(client, org)
    midnight = now().replace(hour=0, minute=0, second=0, microsecond=0)
    for k in range(0, 6):
        day = midnight - timedelta(days=k)
        for i, (org, status, duration) in enumerate((("org-alpha", 200, 12.0), ("org-beta", 500, 480.0), ("org-alpha", 404, 35.5),
                                                     ("org-gamma", 429, 7.0), ("", 200, 2600.0))):
            add_request(db_path, org, status, duration + k, day + timedelta(hours=1 + 2 * i), actor=f"{org or 'anon'}-{k % 3}",
                        path=f"/route-{i % 3}")
        add_request(db_path, "org-beta", 503, 90.0, day + timedelta(microseconds=250), actor="beta-midnight", path="/midnight")
        add_request(db_path, "org-gamma", 200, 15.0, day - timedelta(microseconds=250), actor="gamma-late", path="/midnight")
        add_auth(db_path, "org-alpha", f"alpha-login-{k % 2}", "login.success", day + timedelta(microseconds=100))
        add_auth(db_path, "org-beta", "beta-login", "login.failure", day + timedelta(hours=5))
    assert usage_rollups.run()["error"] is None
    pa.clear_cache()
    return client, app, db_path


def test_overview_reads_retained_rolled_days_with_identical_results(retained, monkeypatch):
    _, _, db_path = retained
    assert rows(db_path, "SELECT state_value FROM platform_usage_rollup_state WHERE state_key = 'format_version'") == \
        [(usage_rollups.ROLLUP_FORMAT,)]
    assert rows(db_path, "SELECT COUNT(*) FROM platform_usage_routes_daily")[0][0] > 0
    # The first microseconds after midnight belong to that day (bounds match the raw created_at format).
    day = label(1)[:10]
    assert rows(db_path, "SELECT requests FROM platform_usage_routes_daily WHERE day = ? AND path = '/midnight'", (day,)) == [(2,)]
    frozen = now()
    monkeypatch.setattr(pa, "now_utc", lambda: frozen)  # both passes must see the same retention cut-off
    for range_key in ("24h", "7d", "30d", "90d"):
        monkeypatch.setattr(pa, "FAST_OVERVIEW", True)
        fast = pa.overview(range_key)
        monkeypatch.setattr(pa, "FAST_OVERVIEW", False)
        raw = pa.overview(range_key)
        assert _without_timestamp(fast) == _without_timestamp(raw), range_key
    assert fast["kpis"]["api_requests"]["value"] > 0 and fast["top"]["routes_by_errors"]


def test_fast_overview_waits_for_the_current_rollup_format(retained):
    _, _, db_path = retained
    win = pa.Window("7d")
    with pa.Reader() as r:
        jv = pa.JournalView(r, win, pa.Collector())
        jv.fast = True
        assert jv.fast_ok() and jv.fast_plan(win.start, win.end, jv.traffic_cut).retained
    execute(db_path, "UPDATE platform_usage_rollup_state SET state_value = '1' WHERE state_key = 'format_version'")
    with pa.Reader() as r:
        jv = pa.JournalView(r, win, pa.Collector())
        jv.fast = True
        assert not jv.fast_ok() and jv.fast_plan(win.start, win.end, jv.traffic_cut).retained is None
    # The next run re-rolls every retained day and restores the format marker.
    assert len(usage_rollups.run()["rolled"]) >= 5
    assert rows(db_path, "SELECT state_value FROM platform_usage_rollup_state WHERE state_key = 'format_version'") == \
        [(usage_rollups.ROLLUP_FORMAT,)]


def test_overview_snapshots_cover_every_range(retained, monkeypatch):
    """The overview is precomputed into platform_analytics_snapshots and served from there.

    It used to be aggregated on the request behind a 20-second cache that could never hold an
    answer the computation took longer than to produce; see services/analytics_snapshots.
    """
    from services import analytics_snapshots as snaps

    client, _, _ = retained
    monkeypatch.setattr(pa, "WARM_ENABLED", True)
    res = client.get("/platform/analytics/overview?range=30d", headers=owner())
    assert res.status_code == 200
    body = res.json()
    # The console reads "as of", not "when your browser asked".
    assert body["as_of"] and body["snapshot"]["state"] == "fresh"
    assert body["snapshot"]["computed_at"] == body["as_of"]
    assert snaps.read("30d") is not None

    snaps.run_once()  # the scheduled pass fills the ranges nobody has asked for yet
    assert all(snaps.read(key) is not None for key in pa.RANGES)
    stored = snaps.read("7d")["payload"]
    served = client.get("/platform/analytics/overview?range=7d", headers=owner()).json()
    assert served["kpis"] == stored["kpis"] and served["series"] == stored["series"]

    # Clearing the cache means "the rows underneath may have changed": a snapshot computed before
    # that must never be served after it.
    pa.clear_cache()
    assert all(snaps.read(key) is None for key in pa.RANGES)


def test_histogram_percentile_estimate():
    hist = {c: 0 for c in usage_rollups.LATENCY_COLUMNS}
    hist["lat_le_10"], hist["lat_le_100"] = 90, 10
    assert usage_rollups.histogram_percentile(hist, 50) <= 10
    assert 50 < usage_rollups.histogram_percentile(hist, 95) <= 100
    assert usage_rollups.histogram_percentile({}, 95) is None
