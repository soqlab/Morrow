"""Migration deadlines per organization (services/migration_milestones, routers/migration_milestones)
and the per-milestone projection in services/migration_velocity."""

import json
import math
from datetime import datetime, timedelta, timezone

import pytest

from test_invite_landing import PASSWORD, api_fixture, make_org  # noqa: F401  (api_fixture registers the "api" fixture)

from services import migration_milestones as mm
from services.migration_velocity import build_velocity_report

NOW = datetime(2027, 3, 1, 12, 0, tzinfo=timezone.utc)


def _estate(vulnerable=10, closures=8, now=NOW):
    scans = [{"host": f"h{i}.example", "port": 443, "algorithm": "RSA-2048", "scan_time": now.isoformat()}
             for i in range(vulnerable)]
    rems = [{"status": "verified_closed", "updated_at": (now - timedelta(days=i * 3)).isoformat()}
            for i in range(closures)]
    return scans, rems


def bearer(client, app, email, org="org-acme", role="admin"):
    with app._db() as db:
        app._issuer_create_user(db, email, PASSWORD, "", role, org)
    token = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
    return {"Authorization": "Bearer " + token}


@pytest.fixture
def store(api, monkeypatch):
    monkeypatch.setattr(mm, "_ready", set())  # each test has its own database file
    return api


# ── Defaults ──────────────────────────────────────────────────────────────────


def test_defaults_are_the_nist_ir_8547_2030_and_2035_milestones_with_sources():
    ds = mm.defaults()
    assert [m["date"] for m in ds] == ["2030-12-31", "2035-12-31"]
    for m in ds:
        assert "NIST IR 8547" in m["source"] and m["source_url"].startswith("https://doi.org/10.6028/NIST.IR.8547")
        assert m["name"] and m["scope"]
    # Handing out a copy: a caller editing the list must not change the defaults.
    ds[0]["date"] = "1999-01-01"
    assert mm.defaults()[0]["date"] == "2030-12-31"


def test_an_organization_that_never_saved_a_list_gets_the_defaults(store):
    got = mm.get("org-new")
    assert got["source"] == "default" and got["milestones"] == mm.defaults()


def test_report_without_milestones_uses_the_defaults():
    scans, rems = _estate()
    report = build_velocity_report(scans, rems, now=NOW)
    assert [m["date"] for m in report["projection"]["milestones"]] == ["2030-12-31", "2035-12-31"]
    assert report["projection"]["next_milestone"] == "nist-ir-8547-deprecated"


# ── Per-organization isolation ───────────────────────────────────────────────


def test_each_organization_has_its_own_list(store):
    mm.save("org-a", [{"name": "Board target", "date": "2028-06-30"}], actor="alice")
    assert [m["name"] for m in mm.get("org-a")["milestones"]] == ["Board target"]
    assert mm.get("org-a")["source"] == "organization" and mm.get("org-a")["updated_by"] == "alice"
    assert mm.get("org-b")["source"] == "default"
    mm.reset("org-a")
    assert mm.get("org-a")["source"] == "default"


def test_the_wildcard_and_empty_organization_are_refused(store):
    for org in ("*", "", None):
        with pytest.raises(mm.MilestoneError):
            mm.save(org, [{"name": "x", "date": "2030-01-01"}])
    assert mm.milestones_for("*") == mm.defaults()  # the report never breaks on it


def test_api_isolation_between_tenants(store):
    client, app = store
    make_org(client, "org-acme", "Acme")
    make_org(client, "org-beta", "Beta")
    acme = bearer(client, app, "admin@acme.example", org="org-acme")
    beta = bearer(client, app, "admin@beta.example", org="org-beta")
    res = client.put("/migration-velocity/milestones", headers=acme,
                     json={"milestones": [{"name": "Acme internal", "date": "2029-01-01"}]})
    assert res.status_code == 200, res.text
    assert client.get("/migration-velocity/milestones", headers=beta).json()["source"] == "default"
    # An x-org-id header does not reach into another tenant once authenticated.
    other = client.get("/migration-velocity/milestones", headers={**beta, "x-org-id": "org-acme"}).json()
    assert other["source"] == "default"
    # The velocity report of each organization measures against its own deadlines.
    names = [m["name"] for m in client.get("/migration-velocity", headers=acme).json()["projection"]["milestones"]]
    assert names == ["Acme internal"]
    names = [m["name"] for m in client.get("/v1/migration-velocity", headers=beta).json()["projection"]["milestones"]]
    assert len(names) == 2


# ── Update validation ────────────────────────────────────────────────────────


@pytest.mark.parametrize("milestones,needle", [
    ([], "at least one"),
    ([{"name": "x", "date": "31/12/2030"}], "YYYY-MM-DD"),
    ([{"name": "x", "date": "2030-02-30"}], "YYYY-MM-DD"),
    ([{"name": "x", "date": "2030-12-31T00:00:00"}], "YYYY-MM-DD"),
    ([{"name": "x", "date": "1999-12-31"}], "between"),
    ([{"name": "x", "date": "2101-01-01"}], "between"),
    ([{"name": "  ", "date": "2030-01-01"}], "name"),
    ([{"name": "x" * 121, "date": "2030-01-01"}], "at most"),
    ([{"name": "Dup", "date": "2030-01-01"}, {"name": "dup", "date": "2031-01-01"}], "both called"),
    ([{"name": f"m{i}", "date": "2030-01-01"} for i in range(13)], "up to"),
    ([{"name": "x", "date": "2030-01-01", "source_url": "javascript:alert(1)"}], "http"),
])
def test_validation_refuses(milestones, needle):
    with pytest.raises(mm.MilestoneError) as exc:
        mm.validate(milestones)
    assert needle in exc.value.detail


def test_validation_allows_future_and_past_dates_and_sorts_by_date():
    clean = mm.validate([
        {"name": "Late", "date": "2099-12-31", "scope": "  all \n systems "},
        {"name": "Missed", "date": "2020-01-01"},
    ])
    assert [m["name"] for m in clean] == ["Missed", "Late"]
    assert clean[1]["scope"] == "all systems"
    assert clean[1]["id"] == "late"


def test_api_update_is_admin_only_validated_and_audited(store):
    client, app = store
    make_org(client, "org-acme", "Acme")
    admin = bearer(client, app, "admin@acme.example")
    viewer = bearer(client, app, "viewer@acme.example", role="viewer")
    body = {"milestones": [{"name": "CNSA 2.0 software signing", "date": "2030-12-31", "scope": "Firmware"}],
            "reason": "We ship to NSS customers"}

    got = client.get("/migration-velocity/milestones", headers=viewer)
    assert got.status_code == 200 and got.json()["can_edit"] is False
    assert client.put("/migration-velocity/milestones", headers=viewer, json=body).status_code == 403
    assert client.delete("/migration-velocity/milestones", headers=viewer).status_code == 403

    bad = client.put("/migration-velocity/milestones", headers=admin,
                     json={"milestones": [{"name": "x", "date": "2200-01-01"}]})
    assert bad.status_code == 422 and "between" in bad.json()["detail"]
    assert client.get("/migration-velocity/milestones", headers=admin).json()["source"] == "default"

    res = client.put("/migration-velocity/milestones", headers=admin, json=body)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["can_edit"] is True and data["source"] == "organization"
    assert [m["name"] for m in data["milestones"]] == ["CNSA 2.0 software signing"]

    from db import list_audit_logs, reset_current_organization_id, set_current_organization_id
    token = set_current_organization_id("org-acme")
    try:
        entries = [e for e in list_audit_logs(limit=500) if e.get("action") == "velocity.milestones.updated"]
    finally:
        reset_current_organization_id(token)
    assert entries, "the change was not audited"
    details = entries[0].get("details") or entries[0].get("details_json")
    details = json.loads(details) if isinstance(details, str) else details
    assert [m["date"] for m in details["before"]] == ["2030-12-31", "2035-12-31"]
    assert details["before_source"] == "default"
    assert details["after"][0]["name"] == "CNSA 2.0 software signing"
    assert entries[0].get("reason") == "We ship to NSS customers"

    reset = client.delete("/v1/migration-velocity/milestones", headers=admin)
    assert reset.status_code == 200 and reset.json()["source"] == "default"


# ── Report per milestone ─────────────────────────────────────────────────────


def test_report_measures_each_milestone():
    scans, rems = _estate(vulnerable=10, closures=8)  # 8 closures in the last 4 weeks: 2/week, 5 weeks
    milestones = [
        {"id": "soon", "name": "Soon", "date": (NOW + timedelta(weeks=3)).strftime("%Y-%m-%d")},
        {"id": "later", "name": "Later", "date": (NOW + timedelta(days=365)).strftime("%Y-%m-%d")},
        {"id": "gone", "name": "Gone", "date": (NOW - timedelta(days=10)).strftime("%Y-%m-%d")},
    ]
    report = build_velocity_report(scans, rems, milestones=milestones, now=NOW)
    proj = report["projection"]
    assert proj["weeks_to_completion"] == 5
    by = {m["id"]: m for m in proj["milestones"]}
    assert [m["id"] for m in proj["milestones"]] == ["gone", "soon", "later"]  # date order

    soon = by["soon"]
    assert soon["status"] == "behind" and soon["on_track"] is False
    assert soon["velocity_needed"] == 4 and soon["velocity_gap"] == 2.0   # ceil(10 / ~3.07 weeks)
    assert soon["days_left"] == 21 and soon["passed"] is False
    assert soon["projected_completion_date"] == proj["completion_date"]
    assert soon["projected_margin_days"] < 0

    later = by["later"]
    assert later["status"] == "on_track" and later["on_track"] is True
    assert later["velocity_gap"] == 0 and later["projected_margin_days"] > 300

    gone = by["gone"]
    assert gone["status"] == "missed" and gone["on_track"] is False and gone["passed"] is True
    assert gone["velocity_needed"] is None and gone["days_left"] < 0

    assert proj["next_milestone"] == "soon"
    assert "Soon" in report["recommendation"]


def test_milestone_is_met_by_work_finished_on_its_date():
    scans, rems = _estate(vulnerable=10, closures=8)
    done = NOW + timedelta(weeks=5)
    report = build_velocity_report(scans, rems, now=NOW,
                                   milestones=[{"name": "Exact", "date": done.strftime("%Y-%m-%d")}])
    assert report["projection"]["milestones"][0]["on_track"] is True
    assert report["projection"]["milestones"][0]["projected_margin_days"] == 0


def test_no_velocity_and_complete_states():
    scans, _ = _estate(vulnerable=3)
    m = [{"name": "Target", "date": "2031-01-01"}]
    stalled = build_velocity_report(scans, [], milestones=m, now=NOW)["projection"]["milestones"][0]
    assert stalled["status"] == "no_velocity" and stalled["on_track"] is False
    assert stalled["velocity_needed"] == 1 and stalled["projected_completion_date"] is None

    safe = [{"host": "a", "port": 443, "algorithm": "ML-KEM-768", "scan_time": NOW.isoformat()}]
    done = build_velocity_report(safe, [], milestones=m, now=NOW)["projection"]["milestones"][0]
    assert done["status"] == "complete" and done["on_track"] is True and done["velocity_needed"] == 0


def test_empty_workspace_lists_milestones_without_a_verdict():
    report = build_velocity_report([], [], milestones=[{"name": "T", "date": "2030-12-31"}], now=NOW)
    assert report["available"] is False
    row = report["projection"]["milestones"][0]
    assert row["status"] == "not_measured" and row["on_track"] is None and row["velocity_needed"] is None
    assert row["days_left"] == (datetime(2031, 1, 1, tzinfo=timezone.utc) - NOW).days


# ── The old single-deadline keys ─────────────────────────────────────────────


def test_legacy_2030_keys_keep_their_original_meaning():
    scans, rems = _estate(vulnerable=10, closures=8)
    # Custom milestones must not change what the legacy keys mean: 1 January 2030.
    report = build_velocity_report(scans, rems, now=NOW, milestones=[{"name": "Other", "date": "2027-03-10"}])
    proj = report["projection"]
    days = (datetime(2030, 1, 1, tzinfo=timezone.utc) - NOW).days
    assert proj["days_to_2030"] == days
    assert proj["velocity_needed_for_2030"] == math.ceil(10 / (days / 7))
    assert proj["on_track_for_2030"] is True
    assert proj["velocity_gap"] == max(0, proj["velocity_needed_for_2030"] - 2.0)

    empty = build_velocity_report([], [], now=NOW)["projection"]
    assert empty["on_track_for_2030"] is None and empty["velocity_needed_for_2030"] is None
    assert empty["velocity_gap"] is None and empty["days_to_2030"] == days


def test_rls_plan_covers_the_milestones_table():
    from services.postgres_rls import ORG_SCOPED_TABLES, tenant_column
    assert mm.TABLE in ORG_SCOPED_TABLES and tenant_column(mm.TABLE) == "org_id"
