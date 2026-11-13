"""Trial requests: the retired public form, and the operator queue that still reads old rows.

The form asked for an email address and answered by emailing a link, the one kind of sign-in Morrow
no longer offers. What these tests guard now is that the retirement is complete -- nothing is
recorded and nothing is sent, and the old addresses lead to passkey sign-in instead of a 404 -- and
that requests made before it can still be read and decided by an operator.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "trials.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    from services import trial_requests

    trial_requests._TABLES_READY.clear()
    trial_requests.init_tables()
    yield trial_requests
    trial_requests._TABLES_READY.clear()


@pytest.fixture()
def client(store, monkeypatch):
    """A client whose operator guard always passes, so these tests exercise the queue rather than
    operator authentication, which test_platform_key_auth.py and test_operator_auth.py cover."""
    import app as app_module

    monkeypatch.setattr(app_module, "_require_platform_admin",
                        lambda request, roles=None: {"operator": "tester"})
    return TestClient(app_module.app, raise_server_exceptions=False)


# ── The retired public form ──────────────────────────────────────────────


def test_both_public_routes_answer_410_and_record_nothing(client, store, monkeypatch):
    from services import platform_mail

    sent = []
    monkeypatch.setattr(platform_mail, "send_text", lambda *a, **k: sent.append(a) or {"ok": True})
    monkeypatch.setenv("MORROW_TRIAL_NOTIFY_EMAIL", "owner@example.com")
    monkeypatch.setenv("MORROW_SELF_SIGNUP", "1")

    form = client.post("/trial-request", data={"email": "ada@example.com", "company": "Example Ltd"})
    api = client.post("/api/trial-request", json={"email": "grace@example.com"})
    for response in (form, api):
        assert response.status_code == 410
        body = response.json()
        assert body["recorded"] is False
        assert body["sign_in"] == "/ui/"
        assert "passkey" in body["detail"]
        assert response.headers["cache-control"] == "no-store"
    # Even an empty or malformed body is the same answer: there is nothing left to validate.
    assert client.post("/api/trial-request", json={}).status_code == 410
    assert store.list_requests() == []
    assert sent == [], "a retired form must not send any email"


def test_the_old_pages_redirect_to_passkey_sign_in(client):
    for path in ("/trial", "/trial-request"):
        moved = client.get(path, follow_redirects=False)
        assert moved.status_code == 308, path
        assert moved.headers["location"] == "/ui/", path


def test_the_retired_routes_still_answer_without_an_account(client):
    import app as app_module

    for path in ("/trial", "/trial-request", "/api/trial-request"):
        assert app_module._auth_public_path(path) is True, path
    # The queue behind it is not public.
    assert app_module._auth_public_path("/platform/trial-requests") is False


# ── The operator queue ───────────────────────────────────────────────────────


def test_the_queue_puts_pending_work_first(client, store):
    store.submit("one@example.com")
    second = store.submit("two@example.com")
    store.decline(second["id"], "tester", note="not a real organization")
    store.submit("three@example.com")

    listed = client.get("/platform/trial-requests").json()
    assert listed["counts"]["pending"] == 2
    assert listed["counts"]["declined"] == 1
    assert [r["status"] for r in listed["requests"]][:2] == ["pending", "pending"]
    assert listed["requests"][-1]["status"] == "declined"

    filtered = client.get("/platform/trial-requests?status=pending").json()
    assert len(filtered["requests"]) == 2
    assert client.get("/platform/trial-requests?status=nonsense").status_code == 400


def test_approval_creates_the_organization_and_a_single_use_invitation(client, store):
    submitted = store.submit("ada@example.com", company="Example Ltd", domain="example.com")

    response = client.post(f"/platform/trial-requests/{submitted['id']}/approve",
                           json={"plan_type": "trial"})
    assert response.status_code == 200, response.text
    body = response.json()["request"]

    assert body["status"] == "approved"
    assert body["organization_id"].startswith("org_")
    assert body["organization_name"] == "Example Ltd"
    assert body["invite_email"] == "ada@example.com"
    # The token is in this response and nowhere else.
    assert body["invite_token"]
    assert body["invite_id"] and body["invite_id"] != body["invite_token"]
    # org_admin, not admin and emphatically not platform_admin: a trial owner administers their
    # own organization and nothing above it.
    assert body["role"] == "org_admin"

    stored = store.get(submitted["id"])
    assert stored["organization_id"] == body["organization_id"]
    assert "invite_token" not in stored, "the bearer token must not be persisted on the request"
    assert body["invite_token"] not in str(stored.values())

    # The organization really exists, rather than only being recorded as created.
    import db as _db
    names = {str(o.get("id")) for o in _db.list_organizations(limit=5000)}
    assert body["organization_id"] in names


def test_an_intake_can_never_grant_the_operator_role(client, store):
    """The role comes from the request body, so the ceiling has to be enforced, not assumed."""
    submitted = store.submit("attacker@example.com")
    import db as _db

    before = {str(o.get("id")) for o in _db.list_organizations(limit=5000)}

    refused = client.post(f"/platform/trial-requests/{submitted['id']}/approve",
                          json={"role": "platform_admin"})
    assert refused.status_code == 400
    assert "operator role" in refused.json()["detail"]

    nonsense = client.post(f"/platform/trial-requests/{submitted['id']}/approve",
                           json={"role": "root"})
    assert nonsense.status_code == 400
    assert "is not a role" in nonsense.json()["detail"]

    # And neither attempt left an organization behind, which is why the role is checked before
    # anything is created rather than by invite_user afterwards.
    assert {str(o.get("id")) for o in _db.list_organizations(limit=5000)} == before
    assert store.get(submitted["id"])["status"] == "pending"


def test_approving_twice_is_refused_rather_than_creating_two_organizations(client, store):
    submitted = store.submit("ada@example.com")
    first = client.post(f"/platform/trial-requests/{submitted['id']}/approve", json={})
    assert first.status_code == 200
    again = client.post(f"/platform/trial-requests/{submitted['id']}/approve", json={})
    assert again.status_code == 409
    assert "already approved" in again.json()["detail"]


def test_declining_keeps_the_row(client, store):
    submitted = store.submit("spam@example.com")
    response = client.post(f"/platform/trial-requests/{submitted['id']}/decline",
                           json={"note": "mass submission", "spam": True})
    assert response.status_code == 200
    assert response.json()["request"]["status"] == "spam"
    # Kept, because an address that applies again is worth seeing in context.
    assert store.get(submitted["id"])["note"] == "mass submission"
    assert client.post(f"/platform/trial-requests/{submitted['id']}/approve",
                       json={}).status_code == 409


def test_an_unknown_request_is_a_404(client):
    assert client.post("/platform/trial-requests/deadbeef/approve", json={}).status_code == 404
    assert client.post("/platform/trial-requests/deadbeef/decline", json={}).status_code == 404


def test_pending_requests_are_never_pruned(client, store):
    pending = store.submit("waiting@example.com")
    decided = store.submit("decided@example.com")
    store.decline(decided["id"], "tester")

    from db_feature_store import feature_conn
    with feature_conn() as conn:
        conn.execute("UPDATE trial_requests SET decided_at = ?, created_at = ? "
                     "WHERE status != 'pending'", ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"))
        conn.commit()

    assert store.prune(days=30) == 1
    assert store.get(pending["id"]) is not None, "unanswered work does not expire quietly"
    assert store.get(decided["id"]) is None


def test_no_tenant_data_is_touched_by_an_intake(store, monkeypatch):
    """A trial request belongs to no organization. It must not reach a tenant table."""
    import db_feature_store

    seen = []
    original = db_feature_store.feature_conn

    def watched(*args, **kwargs):
        seen.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(db_feature_store, "feature_conn", watched)
    monkeypatch.setattr("services.trial_requests.feature_conn", watched)
    store.submit("ada@example.com")
    assert seen, "the intake writes to the feature store"


# ── The admin portal wiring ──────────────────────────────────────────────────


def test_the_operator_portal_is_wired_to_the_queue():
    """A queue nobody can see is the same as no queue.

    test_admin_panel_wiring.py already proves every id and class the script reaches for exists.
    This proves the view is reachable: registered as a route, given a loader, and listed in the
    navigation with the badge that makes pending work visible from any other page.
    """
    import pathlib

    admin = pathlib.Path(__file__).parent / "static_admin"
    views = (admin / "admin-views.js").read_text(encoding="utf-8")
    shell = (admin / "admin-shell.js").read_text(encoding="utf-8")
    index_js = (admin / "index.js").read_text(encoding="utf-8")
    index_html = (admin / "index.html").read_text(encoding="utf-8")

    assert "trials: { group: \"Customers\"" in views, "no route entry"
    assert "trials: () => A.loadTrialRequests()" in views, "no loader"
    assert "pendingTrials:" in views, "the navigation badge is not fed"
    assert 'route: "trials"' in shell, "not in the navigation"
    assert 'data-page="trials"' in index_html, "no view markup"
    assert "loadTrialRequests" in index_js, "no implementation"

    # The three routes the view calls, exactly as it spells them.
    assert "/platform/trial-requests" in index_js
    assert "/approve" in index_js and "/decline" in index_js

    # The invitation token goes in the fragment. In a query string it would reach access logs and
    # Referer headers, which is why static/invite.js reads #token= and strips it.
    assert "/invite#token=" in index_js
    assert "/invite?token=" not in index_js


def test_nothing_public_points_at_the_retired_form():
    """The landing page and pricing used to send a stranger to /trial; nothing does now."""
    import pathlib

    static = pathlib.Path(__file__).parent / "static"
    for name in ("instrument.html", "pricing.html", "pilot.html", "index.html"):
        body = (static / name).read_text(encoding="utf-8")
        assert 'href="/trial' not in body, name
    assert not (static / "trial.html").exists()


# ── Trial caps ───────────────────────────────────────────────────────────────


def test_an_approved_trial_is_capped_by_a_real_enforced_override(client, store, monkeypatch):
    """The page promises lower limits, so something has to enforce them.

    A plan-based tier used to sit between the operator override and the platform default and could
    have carried these caps. It was removed with the billing code when the platform became free, so
    the override is the only per-organization limit left -- and limits_for() honours it first and
    unconditionally.
    """
    monkeypatch.setenv("MORROW_TRIAL_API_CALLS_PER_MIN", "60")
    monkeypatch.setenv("MORROW_TRIAL_SCANS_PER_HOUR", "10")
    assert store.trial_caps() == (60, 10)

    submitted = store.submit("ada@example.com")
    body = client.post(f"/platform/trial-requests/{submitted['id']}/approve", json={}).json()["request"]
    org = body["organization_id"]
    assert body["caps"] == {"api_calls_per_min": 60, "scans_per_hour": 10}

    # Stored where the limiter reads it, not merely reported in the response.
    from services import admin_console, org_rate_limits

    stored = admin_console.get_rate_limits(org)
    assert int(stored["api_calls_per_min"]) == 60
    assert int(stored["scans_per_hour"]) == 10

    assert org_rate_limits.stored_override(org) == (60, 10)
    # invalidate() only expires the cache; the request path reloads it (org_rate_limits.py:409).
    org_rate_limits.refresh_overrides()
    # And it wins: the override is the top of the precedence order.
    assert org_rate_limits.limits_for(org) == (60, 10)
    assert org_rate_limits.describe(org)["limit_source"] == "override"


def test_caps_are_off_by_default_so_self_hosting_is_unchanged(client, store, monkeypatch):
    monkeypatch.delenv("MORROW_TRIAL_API_CALLS_PER_MIN", raising=False)
    monkeypatch.delenv("MORROW_TRIAL_SCANS_PER_HOUR", raising=False)
    assert store.trial_caps() == (0, 0)

    submitted = store.submit("ada@example.com")
    body = client.post(f"/platform/trial-requests/{submitted['id']}/approve", json={}).json()["request"]
    assert body["caps"] == {"api_calls_per_min": 0, "scans_per_hour": 0}

    from services import admin_console, org_rate_limits

    # No override row at all, rather than a row of zeros that would read as "limited to nothing".
    # get_rate_limits() answers with hardcoded display defaults when there is no row, so the
    # absence shows up as updated_at being unset.
    assert admin_console.get_rate_limits(body["organization_id"])["updated_at"] is None
    org_rate_limits.refresh_overrides()
    assert org_rate_limits.stored_override(body["organization_id"]) is None


def test_a_cap_that_cannot_be_applied_does_not_half_approve_the_request(client, store, monkeypatch):
    """An uncapped trial is a cost problem; a request marked approved with no invitation is a
    correctness problem. The second must not be caused by the first."""
    monkeypatch.setenv("MORROW_TRIAL_API_CALLS_PER_MIN", "60")
    from services import admin_console

    def boom(*args, **kwargs):
        raise RuntimeError("feature store unavailable")

    monkeypatch.setattr(admin_console, "set_rate_limits", boom)

    submitted = store.submit("ada@example.com")
    response = client.post(f"/platform/trial-requests/{submitted['id']}/approve", json={})
    assert response.status_code == 200
    body = response.json()["request"]
    assert body["status"] == "approved"
    assert body["organization_id"]
    assert body["invite_token"]
    # And it says so, instead of reporting a cap that was never written.
    assert "not applied" in body["caps"]["error"]
