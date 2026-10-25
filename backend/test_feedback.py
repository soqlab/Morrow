"""Feedback capture and triage.

The platform had no way for a user to say anything back: no bug report, no
request, no rating. Everything in the admin console was inferred from telemetry,
which records what people did and never why.

Tenant scoping is the part worth guarding hardest. Feedback carries free text a
customer typed, so one organization reading another's would be a disclosure, not
just a bug.
"""

import os
import tempfile

import pytest

ORG_A = "00000000-0000-0000-0000-000000000001"
ORG_B = "11111111-1111-1111-1111-111111111111"


@pytest.fixture()
def client():
    os.environ["MORROW_SCANNER_DB"] = os.path.join(tempfile.mkdtemp(), "feedback.db")
    os.environ["MORROW_FEATURE_STORE_BACKEND"] = "sqlite"
    os.environ.setdefault("MORROW_AUTH_MODE", "header")
    os.environ.setdefault("MORROW_DEFAULT_ROLE", "admin")

    import importlib
    import db
    importlib.reload(db)
    import db_feature_store
    importlib.reload(db_feature_store)
    import services.feedback as feedback_mod
    importlib.reload(feedback_mod)

    import app as application
    from fastapi.testclient import TestClient

    application._feedback = feedback_mod
    was_key = application._PLATFORM_ADMIN_KEY
    was_limit = getattr(application.limiter, "enabled", True)
    application._PLATFORM_ADMIN_KEY = "fb-key"
    application.limiter.enabled = False

    with TestClient(application.app, raise_server_exceptions=False) as c:
        yield c

    application._PLATFORM_ADMIN_KEY = was_key
    application.limiter.enabled = was_limit


def _user(org=ORG_A, actor="alice@corp"):
    return {"x-org-id": org, "x-actor-role": "admin", "x-user-id": actor}


def _admin(org=ORG_A):
    return {**_user(org), "x-platform-key": "fb-key", "x-platform-admin-role": "owner"}


def test_a_user_can_submit_and_read_back_their_feedback(client):
    posted = client.post("/feedback", headers=_user(), json={
        "message": "Blast radius is slow above 5000 assets",
        "category": "bug", "rating": 4, "page": "/#graph",
    })
    assert posted.status_code == 200, posted.text
    created = posted.json()["feedback"]
    assert created["category"] == "bug"
    assert created["rating"] == 4
    assert created["status"] == "new"

    items = client.get("/feedback", headers=_user()).json()["items"]
    assert len(items) == 1
    assert items[0]["message"].startswith("Blast radius is slow")
    assert items[0]["user_id"] == "alice@corp", "the submitter must be recorded"


def test_feedback_is_scoped_to_the_submitting_organization(client):
    client.post("/feedback", headers=_user(ORG_A), json={"message": "secret roadmap gripe from A"})
    client.post("/feedback", headers=_user(ORG_B, "bob@other"), json={"message": "from B"})

    a_items = client.get("/feedback", headers=_user(ORG_A)).json()["items"]
    b_items = client.get("/feedback", headers=_user(ORG_B)).json()["items"]

    assert [i["message"] for i in a_items] == ["secret roadmap gripe from A"]
    assert [i["message"] for i in b_items] == ["from B"]
    # Free text one customer typed must not reach another.
    assert "secret roadmap gripe" not in str(b_items)


def test_an_empty_message_is_rejected(client):
    for body in ({"message": "   "}, {"message": ""}):
        response = client.post("/feedback", headers=_user(), json=body)
        assert response.status_code in (400, 422), f"{body} was accepted"


def test_a_rating_outside_one_to_five_is_rejected(client):
    for score in (0, 6, 99):
        response = client.post("/feedback", headers=_user(), json={"message": "x", "rating": score})
        assert response.status_code == 422, f"rating {score} was accepted"


def test_an_unknown_category_falls_back_rather_than_failing(client):
    """A new console version sending an unknown category should not lose the
    message; the text matters more than the label."""
    response = client.post("/feedback", headers=_user(), json={
        "message": "still worth keeping", "category": "not-a-real-category",
    })
    assert response.status_code == 200
    assert response.json()["feedback"]["category"] == "other"


def test_the_operator_sees_every_tenant_and_a_summary(client):
    client.post("/feedback", headers=_user(ORG_A), json={"message": "a1", "category": "bug", "rating": 2})
    client.post("/feedback", headers=_user(ORG_B, "bob@other"), json={"message": "b1", "category": "idea", "rating": 4})

    payload = client.get("/platform/feedback", headers=_admin()).json()
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["by_category"] == {"bug": 1, "idea": 1}
    assert payload["summary"]["average_rating"] == 3.0
    orgs = {i["organization_id"] for i in payload["items"]}
    assert orgs == {ORG_A, ORG_B}, "the operator view must span tenants"


def test_platform_feedback_requires_the_admin_key(client):
    client.post("/feedback", headers=_user(), json={"message": "hello"})
    assert client.get("/platform/feedback", headers=_user()).status_code == 403


def test_triage_moves_an_item_and_records_the_note(client):
    client.post("/feedback", headers=_user(), json={"message": "needs triage"})
    item_id = client.get("/platform/feedback", headers=_admin()).json()["items"][0]["id"]

    updated = client.patch(f"/platform/feedback/{item_id}", headers=_admin(),
                           json={"status": "resolved", "admin_note": "shipped in 1.4"})
    assert updated.status_code == 200
    body = updated.json()["feedback"]
    assert body["status"] == "resolved"
    assert body["admin_note"] == "shipped in 1.4"

    summary = client.get("/platform/feedback", headers=_admin()).json()["summary"]
    assert summary["by_status"].get("resolved") == 1
    assert summary["open"] == 0


def test_an_invalid_status_is_rejected_and_a_missing_item_is_not_found(client):
    client.post("/feedback", headers=_user(), json={"message": "x"})
    item_id = client.get("/platform/feedback", headers=_admin()).json()["items"][0]["id"]

    assert client.patch(f"/platform/feedback/{item_id}", headers=_admin(),
                        json={"status": "nonsense"}).status_code == 400
    assert client.patch("/platform/feedback/999999", headers=_admin(),
                        json={"status": "resolved"}).status_code == 404


# ---------------------------------------------------------------------------
# GET /platform/feedback/{id}. The admin portal deep-links to one item; without a
# read of that item alone it could only select what happened to be in the page it
# had loaded, so an older item and a deleted one looked identical.
# ---------------------------------------------------------------------------


def test_one_item_reads_back_exactly_as_the_list_entry(client):
    long_message = "x" * 900 + " tail that the list truncates nowhere"
    client.post("/feedback", headers=_user(), json={
        "message": long_message, "category": "bug", "rating": 3, "page": "/#graph",
    })
    listed = client.get("/platform/feedback", headers=_admin()).json()["items"][0]

    response = client.get(f"/platform/feedback/{listed['id']}", headers=_admin())
    assert response.status_code == 200, response.text
    single = response.json()["feedback"]

    assert single == listed, "the single read must carry the same fields as the list entry"
    assert single["message"] == long_message, "the full message text must come back"


def test_a_missing_item_is_a_real_not_found(client):
    client.post("/feedback", headers=_user(), json={"message": "present"})
    assert client.get("/platform/feedback/999999", headers=_admin()).status_code == 404


def test_reading_one_item_requires_the_platform_admin_key(client):
    client.post("/feedback", headers=_user(), json={"message": "private text"})
    item_id = client.get("/platform/feedback", headers=_admin()).json()["items"][0]["id"]

    denied = client.get(f"/platform/feedback/{item_id}", headers=_user())
    assert denied.status_code == 403
    assert "private text" not in denied.text


def test_an_organization_filter_scopes_the_single_read(client):
    """Feedback is free text a customer typed. Asking for one tenant's item by id
    must not answer with another tenant's."""
    client.post("/feedback", headers=_user(ORG_A), json={"message": "gripe from A"})
    item_id = client.get("/platform/feedback", headers=_admin()).json()["items"][0]["id"]

    same = client.get(f"/platform/feedback/{item_id}?organization_id={ORG_A}", headers=_admin())
    assert same.status_code == 200
    assert same.json()["feedback"]["organization_id"] == ORG_A

    other = client.get(f"/platform/feedback/{item_id}?organization_id={ORG_B}", headers=_admin())
    assert other.status_code == 404
    assert "gripe from A" not in other.text


def test_the_portal_reads_one_item_when_the_deep_link_is_not_in_the_list():
    """The console half of the same story: the deep link must fall back to the
    single-item route, and must only claim an item is gone on a real 404."""
    views = (pathlib.Path(__file__).parent / "static_admin" / "admin-views.js").read_text(encoding="utf-8")
    index = (pathlib.Path(__file__).parent / "static_admin" / "index.js").read_text(encoding="utf-8")

    links = views[views.index("const DEEP_LINKS"):]
    block = links[links.index("feedback: {"):links.index('"api-keys": {')]
    assert "A.loadFeedbackItem(" in block, "the feedback deep link no longer reads the item itself"
    assert "err.status !== 404" in block, "a failed read would be reported as a deleted item"

    assert "async function loadFeedbackItem(" in index, "the single-item loader is gone"
    assert "/platform/feedback/${enc(id)}" in index, "the loader no longer calls the single-item route"
    assert "loadFeedbackItem," in index, "the loader is not exported to the router"


def test_filters_narrow_the_operator_view(client):
    client.post("/feedback", headers=_user(), json={"message": "b", "category": "bug"})
    client.post("/feedback", headers=_user(), json={"message": "i", "category": "idea"})

    bugs = client.get("/platform/feedback?category=bug", headers=_admin()).json()["items"]
    assert [i["category"] for i in bugs] == ["bug"]

    new_only = client.get("/platform/feedback?status=new", headers=_admin()).json()["items"]
    assert len(new_only) == 2


# ---------------------------------------------------------------------------
# The console is where feedback actually comes from.
#
# The API existed for a week before anything could reach it: the console had no
# entry point at all, so /platform/feedback would have shown an empty list
# forever and read as "our users have nothing to say". These guard the wiring
# between the two — a renamed action or a dropped button is a silent outage of
# the only channel users have.
# ---------------------------------------------------------------------------

import pathlib
import re

CONSOLE = pathlib.Path(__file__).parent / "static" / "index.html"


def test_the_console_offers_a_way_to_send_feedback():
    html = CONSOLE.read_text(encoding="utf-8")
    assert 'data-act="openFeedback"' in html, "the topbar entry point is gone"
    assert "ACTIONS.openFeedback" in html, "the topbar button points at nothing"
    assert "ACTIONS.sendFeedback" in html, "the submit button points at nothing"
    assert 'Send feedback", hint:' in html, "the command-palette entry is gone"


def test_the_console_posts_to_the_endpoint_that_exists():
    html = CONSOLE.read_text(encoding="utf-8")
    call = re.search(r'safe\("(/[a-z-]+)", \{ method: "POST", body: \{\s*\n\s*message,', html)
    assert call, "the submit handler no longer posts a message"
    assert call.group(1) == "/feedback", f"posts to {call.group(1)}, which is not the feedback route"


def test_the_console_offers_only_categories_the_server_accepts():
    """An unknown category is coerced to 'other' server-side, so a mismatch here
    loses the label silently rather than erroring — worth pinning."""
    import services.feedback as feedback_mod

    html = CONSOLE.read_text(encoding="utf-8")
    block = html[html.index("const FEEDBACK_KINDS"):html.index("ACTIONS.openFeedback")]
    offered = set(re.findall(r'\["(\w+)",', block))
    assert offered, "the console's category list could not be read"
    assert offered <= set(feedback_mod.CATEGORIES), (
        f"the console offers {offered - set(feedback_mod.CATEGORIES)}, which the server would rewrite to 'other'"
    )


def test_the_rating_control_stays_inside_its_own_box():
    """The rating radios are hidden with position:absolute. Without a positioned
    wrapper they escape to the page's top-left corner and sit invisibly over
    whatever is there, swallowing clicks on unrelated controls."""
    html = CONSOLE.read_text(encoding="utf-8")
    rule = re.search(r"\.fbRate\{([^}]*)\}", html)
    assert rule, "the rating control's rule is gone"
    assert "position:relative" in rule.group(1), "hidden radios would escape the control"
