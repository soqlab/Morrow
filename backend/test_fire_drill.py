"""Quantum fire drill (services/fire_drill.py, routers/fire_drill.py).

Pure tests cover the time-to-safe calculation case by case. API tests run the real stack (the
crypto kill switch's fixture) with every outward path replaced by a recorder, to prove that a drill
changes nothing outside its own record.
"""

from datetime import datetime, timedelta, timezone

import pytest

from test_invite_landing import api_fixture  # noqa: F401  (registers the "api" fixture)
from test_crypto_switch import ASSETS, FACTS, add_scan, bearer, stack  # noqa: F401  (stack is a fixture)

from services import crypto_switch as ks
from services import fire_drill as fd
from services import postgres_rls

NOW = datetime(2026, 11, 15, 9, 0, tzinfo=timezone.utc)


def plan(broken="ML-KEM", fallback="X25519", facts=FACTS, assets=ASSETS):
    return ks.build_plan(broken, fallback, facts, assets)


def no_history():
    return fd.response_model([])


def lane(est, label):
    return next(x for x in est["lanes"] if x["label"] == label)


# ── The calculation ─────────────────────────────────────────────────────────────────────────────


def test_without_history_every_lane_uses_the_stated_assumption_and_says_so():
    est = fd.estimate(plan(), ASSETS, has_code_host=False, response=no_history())
    assert est["affected"] == 4 and est["paths"]["manual"] == 4 and est["paths"]["automated"] == 0
    pay = lane(est, "payments@acme.example")
    # nginx playbook: 2-4 hours hands-on; response assumed 1/7/30 days.
    assert pay["days"] == {"low": 1.2, "likely": 7.4, "high": 30.5}
    assert pay["measured"] is False and "assumed" in pay["basis"] and "nginx" in pay["basis"].lower()
    assert any("no merged fix" in a.lower() or "to merge or apply" in a for a in est["assumptions"])
    assert any("No fix has been merged through Morrow yet" in g for g in est["gaps"])
    # The unowned wiki asset adds the triage time and is the slowest lane.
    assert est["slowest"] == "No owner named"
    wiki = lane(est, "No owner named")
    assert wiki["days"]["high"] > pay["days"]["high"]
    assert est["days"]["likely"] == max(x["days"]["likely"] for x in est["lanes"])
    assert est["days"]["high"] == max(x["days"]["high"] for x in est["lanes"])
    assert any("no owner" in g for g in est["gaps"])


def test_an_owners_own_merge_history_replaces_the_assumption():
    samples = [{"owner": "payments@acme.example", "days": 2.0, "source": "remediation"},
               {"owner": "payments@acme.example", "days": 4.0, "source": "remediation"}]
    est = fd.estimate(plan(), ASSETS, has_code_host=False, response=fd.response_model(samples))
    pay = lane(est, "payments@acme.example")
    assert pay["measured"] is True and "2 merged fixes by this owner" in pay["basis"]
    assert pay["days"] == {"low": 2.2, "likely": 3.4, "high": 4.5}
    # Two samples are enough for that owner, not for the organization: others stay assumed.
    assert lane(est, "api@acme.example")["measured"] is False


def test_organization_wide_history_covers_owners_without_their_own():
    samples = [{"owner": "", "days": d, "source": "remediation"} for d in (1.0, 2.0, 3.0, 10.0)]
    model = fd.response_model(samples)
    assert model["org"]["likely"] == 2.5 and model["owners"] == {}
    est = fd.estimate(plan(), ASSETS, has_code_host=False, response=model)
    api = lane(est, "api@acme.example")
    assert api["measured"] is True and "4 merged fixes across your organization" in api["basis"]
    assert not any("No fix has been merged" in g for g in est["gaps"])


def test_merge_samples_read_remediations_and_kill_switch_requests():
    rems = [{"asset_key": "pay.acme.example:443", "created_at": "2026-10-01T00:00:00Z", "merged_at": "2026-10-03T12:00:00Z"},
            {"asset_key": "pay.acme.example:443", "created_at": "2026-10-01T00:00:00Z", "merged_at": ""},
            {"asset_key": "x", "created_at": "2026-10-05T00:00:00Z", "merged_at": "2026-10-01T00:00:00Z"}]   # merged before created: ignored
    items = [{"asset_key": "api.acme.example:443", "owner": "", "opened_at": "2026-10-01T00:00:00Z", "merged_at": "2026-10-02T00:00:00Z"}]
    owners = {"pay.acme.example:443": "payments@acme.example", "api.acme.example:443": "api@acme.example"}
    samples = fd.merge_samples(rems, items, lambda k: owners.get(k, ""))
    assert [(s["owner"], s["days"], s["source"]) for s in samples] == [
        ("payments@acme.example", 2.5, "remediation"), ("api@acme.example", 1.0, "kill_switch")]


def test_a_linked_repository_and_a_code_host_make_the_path_automated():
    assets = [dict(a, repository_name="acme/edge") if a["asset_key"].startswith("pay.") else a for a in ASSETS]
    est = fd.estimate(plan(assets=assets), assets, has_code_host=True, response=no_history())
    pay = lane(est, "payments@acme.example")
    assert pay["automated"] == 1 and pay["manual"] == 0
    assert pay["days"] == {"low": 1.0, "likely": 7.0, "high": 30.0}            # response only, no hands-on
    assert est["paths"] == {"automated": 1, "manual": 3, "vendor_setting": 0, "vendor_wait": 0}
    # Without a code host the same asset is manual.
    assert fd.estimate(plan(assets=assets), assets, has_code_host=False, response=no_history())["paths"]["automated"] == 0


def test_manual_changes_for_one_owner_add_up():
    assets = [dict(a, owner="ops@acme.example") for a in ASSETS]
    est = fd.estimate(plan(assets=assets), assets, has_code_host=False, response=no_history())
    assert len(est["lanes"]) == 1 and est["lanes"][0]["manual"] == 4
    one = fd.estimate(plan(facts=FACTS[:1], assets=assets), assets, has_code_host=False, response=no_history())
    assert est["days"]["likely"] > one["days"]["likely"]


def test_a_vendor_that_does_not_offer_the_fallback_is_its_own_wide_lane():
    assets = [dict(a, metadata={"tls_terminator": "Cloudflare"}) if a["asset_key"].startswith("pay.") else a for a in ASSETS]
    est = fd.estimate(plan("RSA-2048", "ML-DSA-65", assets=assets), assets, has_code_host=False, response=no_history())
    vendor = lane(est, "Cloudflare")
    assert vendor["kind"] == "vendor_wait" and vendor["days"] == {"low": 7.0, "likely": 30.0, "high": 180.0}
    assert est["paths"]["vendor_wait"] == 1 and est["days"]["high"] == 180.0
    assert any("widest guess" in a for a in est["assumptions"])


def test_a_vendor_that_already_offers_the_fallback_is_a_setting_for_the_owner():
    facts = [dict(f, key_exchange="X25519") for f in FACTS]
    assets = [dict(a, tags=["cloudflare"]) if a["asset_key"].startswith("pay.") else a for a in ASSETS]
    est = fd.estimate(plan("X25519", "X25519MLKEM768", facts=facts, assets=assets), assets, has_code_host=False,
                      response=no_history())
    assert est["paths"]["vendor_setting"] == 1 and est["paths"]["vendor_wait"] == 0
    assert "Cloudflare setting" in lane(est, "payments@acme.example")["basis"]


def test_never_scanned_assets_widen_only_the_top_of_the_range():
    base = fd.estimate(plan(), ASSETS, has_code_host=False, response=no_history())
    wide = fd.estimate(plan(), ASSETS, has_code_host=False, response=no_history(), unscanned=3)
    assert wide["days"]["likely"] == base["days"]["likely"] and wide["days"]["low"] == base["days"]["low"]
    assert wide["days"]["high"] > base["days"]["high"]
    assert any("never been scanned" in g for g in wide["gaps"])


def test_nothing_affected_is_zero_days_and_a_plain_sentence():
    old = [f for f in FACTS if f["asset_key"].startswith("old.")]
    data = {"facts": old, "assets": [a for a in ASSETS if a["asset_key"].startswith("old.")]}
    out = fd.compute("ML-KEM", "X25519", data, NOW)
    assert out["status"] == "ok" and out["affected"] == 0 and out["days"] == {"low": 0.0, "likely": 0.0, "high": 0.0}
    assert out["summary"].startswith("Nothing Morrow has scanned depends on ML-KEM")
    # The four other inventory assets were never scanned: still zero in the middle, but not at the top.
    unsure = fd.compute("ML-KEM", "X25519", {"facts": old, "assets": ASSETS}, NOW)
    assert unsure["days"]["likely"] == 0.0 and unsure["days"]["high"] > 0 and unsure["unscanned_assets"] == 4


def test_compute_says_when_there_is_no_scan_or_the_policy_refuses():
    assert fd.compute("X25519", "", {"facts": [], "assets": []}, NOW)["status"] == "no_data"
    blocked = fd.compute("ML-KEM", "X25519", {"facts": FACTS, "assets": ASSETS,
                                              "policy": {"kill_switch_allow_classical_fallback": False}}, NOW)
    assert blocked["status"] == "blocked" and blocked["days"] is None and blocked["refusals"]
    with pytest.raises(fd.DrillError):
        fd.compute("no-such-algorithm", "", {"facts": FACTS, "assets": ASSETS}, NOW)


def test_compute_flags_stale_scans_and_picks_the_kill_switch_fallback():
    out = fd.compute("RSA-2048", "", {"facts": FACTS, "assets": ASSETS}, NOW + timedelta(days=200))
    assert out["fallback"] == "ML-DSA-65"                                          # crypto_switch.default_fallback
    assert any("last scanned over 90 days ago" in g for g in out["gaps"])
    assert "would be on ML-DSA-65 in about" in out["summary"]


def test_the_sentence_and_headline_round_up():
    est = {"affected": 3, "days": {"low": 2.1, "likely": 8.2, "high": 22.6}}
    assert fd.headline_days(est["days"]) == 9
    assert fd.sentence("X25519", "X25519MLKEM768", est) == (
        "If X25519 were broken this morning, the 3 systems that depend on it would be on X25519MLKEM768 in about "
        "9 days (somewhere between 3 and 23 days).")


# ── Storage, trend and schedule (service level, sqlite) ─────────────────────────────────────────


@pytest.fixture
def store(tmp_path, monkeypatch):
    import db

    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "fd.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    fd.init_tables()
    token = db.set_current_organization_id("org-a")
    yield
    db.reset_current_organization_id(token)


ADMIN = {"actor_id": "admin-1", "actor_role": "admin"}


def _data(days_owner_merge):
    samples = [{"asset_key": "pay.acme.example:443", "created_at": "2026-01-01T00:00:00Z",
                "merged_at": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")}
               for d in days_owner_merge]
    one_asset = [a for a in ASSETS if a["asset_key"].startswith("pay.")]
    return {"facts": [f for f in FACTS if f["asset_key"].startswith("pay.")], "assets": one_asset,
            "remediations": samples, "switch_items": [], "has_code_host": False}


def test_each_drill_is_stored_and_the_trend_compares_with_last_quarter(store):
    first = fd.run_drill("org-a", ADMIN, "ML-KEM", "X25519", trigger="scheduled", data=_data([22, 23, 24]), now=NOW - timedelta(days=91))
    assert first["time_to_safe_days"] == 24 and first["trend"] is None and first["dry_run"] is True
    fd.run_drill("org-a", ADMIN, "ML-KEM", "X25519", trigger="scheduled", data=_data([11, 12]), now=NOW - timedelta(days=20))
    latest = fd.run_drill("org-a", ADMIN, "ML-KEM", "X25519", data=_data([8, 9, 10]), now=NOW)
    assert latest["time_to_safe_days"] == 10
    assert latest["trend"]["label"] == "down from 24 days last quarter" and latest["trend"]["direction"] == "down"
    other = fd.run_drill("org-a", ADMIN, "RSA-2048", "", trigger="scheduled", data=_data([1, 1, 1]), now=NOW)
    assert other["trend"] is None                                                  # compared only with the same algorithm
    assert len(fd.list_drills("org-a")) == 4
    view = fd.overview("org-a")
    assert len(view["history"]) == 4 and view["latest"]["lanes"]


def test_a_second_manual_drill_straight_away_is_refused(store):
    fd.run_drill("org-a", ADMIN, "ML-KEM", "X25519", data=_data([1, 2, 3]), now=NOW)
    with pytest.raises(fd.DrillError) as exc:
        fd.run_drill("org-a", ADMIN, "ML-KEM", "X25519", data=_data([1, 2, 3]), now=NOW + timedelta(seconds=5))
    assert exc.value.status_code == 429


def test_schedule_cadences_and_the_due_runner(store):
    assert fd.get_schedule("org-a")["cadence"] == "off"
    with pytest.raises(fd.DrillError):
        fd.set_schedule("org-a", ADMIN, "weekly")
    sched = fd.set_schedule("org-a", ADMIN, "quarterly", "RSA-2048", now=NOW)
    assert sched["cadence"] == "quarterly" and sched["next_run_at"] == "2027-02-15T09:00:00Z" and sched["broken"] == "RSA-2048"
    assert fd.set_schedule("org-a", ADMIN, "monthly", "ECDSA-P256", now=datetime(2026, 1, 31, tzinfo=timezone.utc))["next_run_at"] \
        == "2026-02-28T00:00:00Z"
    fd.set_schedule("org-a", ADMIN, "monthly", "X25519", now=NOW)
    calls = []

    def runner(org_id, actor, broken, fallback, trigger, now):
        calls.append((org_id, broken, trigger))
        return {"id": "fdr_x"}

    assert fd.run_due(now=NOW + timedelta(days=10), runner=runner)["due"] == 0
    out = fd.run_due(now=NOW + timedelta(days=31), runner=runner)
    assert out["due"] == 1 and calls == [("org-a", "X25519", "scheduled")]
    after = fd.get_schedule("org-a")
    assert after["last_run_at"] == "2026-12-16T09:00:00Z" and after["next_run_at"] == "2027-01-16T09:00:00Z"
    fd.set_schedule("org-a", ADMIN, "off", now=NOW)
    assert fd.run_due(now=NOW + timedelta(days=400), runner=runner)["due"] == 0 and len(calls) == 1


def test_the_tables_are_in_the_rls_plan():
    for table in ("fire_drills", "fire_drill_schedules"):
        assert table in postgres_rls.ORG_SCOPED_TABLES
        assert postgres_rls.TENANT_COLUMNS[table] == "org_id"
    sql = postgres_rls.build_rls_sql(tables=["fire_drills", "fire_drill_schedules"])
    assert "fire_drills" in sql and "fire_drill_schedules" in sql and "org_id" in sql


def test_scheduled_drills_run_from_celery_beat():
    tasks = pytest.importorskip("tasks")
    beat = tasks.celery_app.conf.beat_schedule or {}
    assert beat["fire-drill-due-hourly"]["task"] == "morrow.fire_drill_due"
    assert "morrow.fire_drill_due" in tasks.celery_app.tasks


# ── Over the API ────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def outward(stack, monkeypatch):  # noqa: F811  (pytest fixture injection)
    """Every way a drill could reach outside Morrow, recorded."""
    calls = []

    def rec(name):
        def _f(*a, **k):
            calls.append(name)
            raise AssertionError(f"a fire drill called {name}")
        return _f

    from services import code_hosts, push_notify, smtp_notify, webhooks

    monkeypatch.setattr(code_hosts, "open_change_request", rec("code_hosts.open_change_request"))
    monkeypatch.setattr(code_hosts, "change_request_state", rec("code_hosts.change_request_state"))
    monkeypatch.setattr(webhooks, "deliver_event", rec("webhooks.deliver_event"))
    for name in ("send_email", "send_slack", "notify_all"):
        monkeypatch.setattr(smtp_notify, name, rec("smtp_notify." + name))
    monkeypatch.setattr(push_notify, "send_alert", rec("push_notify.send_alert"))
    monkeypatch.setattr(stack["app"], "_create_scan_and_start", rec("rescan"))
    for name in ("create_incident", "execute_batch", "approve_incident", "go_live", "refresh_incident"):
        monkeypatch.setattr(ks, name, rec("crypto_switch." + name))
    return calls


def _switch_rows(org="org-acme"):
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        return (conn.execute("SELECT COUNT(*) AS n FROM crypto_switch_incidents WHERE org_id = ?", (org,)).fetchone()["n"],
                conn.execute("SELECT COUNT(*) AS n FROM crypto_switch_items WHERE org_id = ?", (org,)).fetchone()["n"])


def test_a_drill_over_the_api_is_a_dry_run_with_no_side_effects(stack, outward):  # noqa: F811  (pytest fixture injection)
    c, admin = stack["client"], stack["admin"]
    ks._init()
    before = _switch_rows()
    res = c.post("/fire-drills", headers=admin, json={"broken": "ML-KEM", "fallback": "X25519"})
    assert res.status_code == 200, res.text
    drill = res.json()
    assert drill["dry_run"] is True and drill["status"] == "ok" and drill["affected"] == 4
    assert drill["time_to_safe_days"] >= 1 and drill["days"]["low"] <= drill["days"]["likely"] <= drill["days"]["high"]
    assert drill["summary"].startswith("If ML-KEM were broken this morning, the 4 systems")
    assert {x["label"] for x in drill["lanes"]} >= {"payments@acme.example", "No owner named"}
    # Nothing left Morrow, nothing was declared, nothing was notified.
    assert outward == [] and stack["host"].opened == [] and stack["rescans"] == [] and stack["notified"] == []
    assert _switch_rows() == before == (0, 0)
    from test_crypto_switch import audit_actions

    assert "fire_drill.run" in audit_actions()
    assert not [a for a in audit_actions() if a.startswith("crypto_switch.")]
    # The scheduled path goes through the same dry run.
    import db

    token = db.set_current_organization_id("org-acme")
    try:
        fd.set_schedule("org-acme", ADMIN, "monthly", "RSA-2048")
    finally:
        db.reset_current_organization_id(token)
    assert fd.run_due(now=datetime.now(timezone.utc) + timedelta(days=40))["results"][0]["ok"] is True
    assert outward == [] and _switch_rows() == (0, 0)
    listed = c.get("/fire-drills", headers=stack["viewer"]).json()
    assert [d["trigger"] for d in listed["history"]] == ["scheduled", "manual"] and listed["latest"]["broken"] == "RSA-2048"


def test_only_admins_run_or_schedule_and_members_can_view(stack, outward):  # noqa: F811  (pytest fixture injection)
    c = stack["client"]
    for who in ("operator", "viewer"):
        assert c.post("/fire-drills", headers=stack[who], json={"broken": "X25519"}).status_code == 403
        assert c.put("/fire-drills/schedule", headers=stack[who], json={"cadence": "monthly"}).status_code == 403
    assert c.get("/fire-drills", headers=stack["viewer"]).json()["can_run"] is False
    assert c.get("/fire-drills", headers=stack["admin"]).json()["can_run"] is True
    put = c.put("/fire-drills/schedule", headers=stack["admin"], json={"cadence": "quarterly", "broken": "ECDSA-P256"})
    assert put.status_code == 200 and put.json()["cadence"] == "quarterly" and put.json()["next_run_at"]
    assert c.put("/fire-drills/schedule", headers=stack["admin"], json={"cadence": "hourly"}).status_code == 400
    assert c.get("/fire-drills/schedule", headers=stack["operator"]).json()["broken"] == "ECDSA-P256"
    drill = c.post("/v1/fire-drills", headers=stack["admin"], json={"broken": "X25519"}).json()
    assert c.get(f"/fire-drills/{drill['id']}", headers=stack["viewer"]).status_code == 200
    assert c.post("/fire-drills", headers=stack["admin"], json={"broken": "X25519"}).status_code == 429


def test_drills_are_isolated_per_organization(stack, outward):  # noqa: F811  (pytest fixture injection)
    from test_invite_landing import make_org

    c = stack["client"]
    make_org(c, "org-beta", "Beta")
    beta = bearer(stack["app"], c, "admin", "org-beta")
    drill = c.post("/fire-drills", headers=stack["admin"], json={"broken": "ML-KEM", "fallback": "X25519"}).json()
    assert c.get(f"/fire-drills/{drill['id']}", headers=beta).status_code == 404
    assert c.get("/fire-drills", headers=beta).json()["history"] == []
    # Beta's own drill sees Beta's (empty) inventory, not Acme's.
    own = c.post("/fire-drills", headers=beta, json={"broken": "ML-KEM", "fallback": "X25519"}).json()
    assert own["status"] == "no_data" and own["time_to_safe_days"] is None


def test_the_console_loads_the_drill_and_both_copies_match():
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "static", "index.html"), "rb") as fh:
        console = fh.read()
    with open(os.path.join(here, "..", "frontend", "index.html"), "rb") as fh:
        assert fh.read() == console
    assert b'src="/ui/fire-drill.js' in console and b'id="fireDrill"' in console
    with open(os.path.join(here, "static", "fire-drill.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert "/fire-drills" in js and "Run a drill now" in js and "trial" not in js.lower()
