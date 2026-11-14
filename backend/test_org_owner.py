"""The organization's owner: who may change whose role, remove whom, and hand ownership on.

Rules (services/member_policy.py): in an organization with a recorded owner (morrow_org_owners, the
account that signed up), only the owner changes an admin's role, makes someone an admin or removes an
admin; other admins manage members who aren't admins; nobody changes their own role; the owner is
never removed or demoted from inside the organization and hands ownership to another admin instead.
An organization without a recorded owner keeps the old rules, except that nobody changes their own
role. Platform operators act through /platform routes, with an MFA step-up for admins and owners.

Runs the real ASGI stack with real passkey ceremonies (the fixtures of test_signup).
"""

import pytest

from test_invite_landing import api_fixture, op  # noqa: F401  (registers the "api" fixture)
from test_passkeys import bearer, events, mail_fixture  # noqa: F401  (registers "mail")
from test_signup import _join_by_invite, _session_as, signed_up
from test_signup import hosted_fixture  # noqa: F401  (registers the "hosted" fixture)


@pytest.fixture
def denials(hosted, monkeypatch):
    """Audit entries written with decision deny, as (action, reason)."""
    _, app_module = hosted
    seen = []
    original = app_module._audit_event

    def capture(request, **kwargs):
        if kwargs.get("decision") == "deny":
            seen.append((kwargs.get("action"), kwargs.get("reason")))
        return original(request, **kwargs)
    monkeypatch.setattr(app_module, "_audit_event", capture)
    return seen


def _org(client, organization="Acme"):
    """An organization with its owner, two more admins and two viewers, all but the owner invite-joined."""
    owner, _ = signed_up(client, organization=organization)
    owner_headers = bearer(owner["access_token"])
    people = {"owner": owner}
    for name in ("admin_a", "admin_b", "viewer_a", "viewer_b"):
        people[name] = _join_by_invite(client, owner_headers)
    for name in ("admin_a", "admin_b"):
        res = client.put(f"/auth/users/{people[name]['user']['id']}/role", headers=owner_headers, json={"role": "admin"})
        assert res.status_code == 200, res.text
    headers = {name: bearer(_session_as(account)["access_token"]) for name, account in people.items()}
    ids = {name: account["user"]["id"] for name, account in people.items()}
    return headers, ids


def _role(client, headers, user_id, role):
    return client.put(f"/auth/users/{user_id}/role", headers=headers, json={"role": role})


def _off(client, headers, user_id):
    return client.post(f"/auth/users/{user_id}/deactivate", headers=headers)


def _roles(app_module, org_id):
    with app_module._db() as db:
        return {u["id"]: (u["role"], bool(u["is_active"])) for u in app_module._issuer_list_users(db, org_id)}


def _owner(app_module, org_id):
    from services import signup
    with app_module._db() as db:
        return signup.owner_of(db, org_id)


def test_an_admin_who_isnt_the_owner_manages_only_members_who_arent_admins(hosted, mail, denials):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    before = len(events("member_change.refused"))

    for target, role in ((ids["owner"], "viewer"), (ids["admin_b"], "viewer"), (ids["viewer_a"], "admin"),
                         (ids["admin_a"], "viewer")):
        refused = _role(client, h["admin_a"], target, role)
        assert refused.status_code == 403, (target, refused.text)
        assert refused.json()["detail"]
    for target in (ids["owner"], ids["admin_b"]):
        assert _off(client, h["admin_a"], target).status_code == 403

    # Members who aren't admins are still theirs to manage.
    assert _role(client, h["admin_a"], ids["viewer_a"], "operator").status_code == 200
    assert _off(client, h["admin_a"], ids["viewer_b"]).status_code == 200

    roles = _roles(app_module, org_id)
    assert roles[ids["owner"]] == ("admin", True)
    assert roles[ids["admin_b"]] == ("admin", True)
    assert roles[ids["admin_a"]] == ("admin", True)
    assert roles[ids["viewer_a"]] == ("operator", True)
    assert roles[ids["viewer_b"]][1] is False
    assert _owner(app_module, org_id) == ids["owner"]

    # Each refusal is journaled and audited with decision deny.
    assert len(events("member_change.refused")) - before == 6
    reasons = [reason for action, reason in denials if str(action).startswith("auth.member.")]
    assert reasons.count("owner_required") == 3 and reasons.count("owner_protected") == 2
    assert reasons.count("own_role") == 1


def test_the_owner_manages_admins_but_not_their_own_role_or_account(hosted, mail, denials):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]

    own = _role(client, h["owner"], ids["owner"], "viewer")
    assert own.status_code == 403 and "transfer ownership" in own.json()["detail"]
    assert _off(client, h["owner"], ids["owner"]).status_code == 403
    assert _role(client, h["owner"], ids["admin_a"], "viewer").status_code == 200
    assert _role(client, h["owner"], ids["viewer_a"], "admin").status_code == 200
    assert _off(client, h["owner"], ids["admin_b"]).status_code == 200

    roles = _roles(app_module, org_id)
    assert roles[ids["owner"]] == ("admin", True)
    assert roles[ids["admin_a"]][0] == "viewer"
    assert roles[ids["viewer_a"]][0] == "admin"
    assert roles[ids["admin_b"]][1] is False
    assert {reason for _, reason in denials} >= {"own_role", "owner_protected"}


def test_an_admin_of_another_organization_reaches_nobody_here(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client, organization="Acme")
    other, _ = signed_up(client, organization="Globex")
    other_headers = bearer(other["access_token"])
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]

    for target in (ids["owner"], ids["admin_a"], ids["viewer_a"]):
        assert _role(client, other_headers, target, "viewer").status_code == 404
        assert _off(client, other_headers, target).status_code == 404
    assert client.post("/auth/organization/owner/transfer", headers=other_headers,
                       json={"user_id": ids["admin_a"]}).status_code == 404
    # And the owner of this one can't hand it to someone in the other.
    assert client.post("/auth/organization/owner/transfer", headers=h["owner"],
                       json={"user_id": other["user"]["id"]}).status_code == 404
    roles = _roles(app_module, org_id)
    assert all(active for _, active in roles.values())
    assert roles[ids["admin_a"]][0] == "admin"
    assert _owner(app_module, org_id) == ids["owner"]


def test_without_a_recorded_owner_admins_manage_admins_but_not_their_own_role(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    with app_module._db() as db:
        db.execute("DELETE FROM morrow_org_owners")
        db.commit()

    assert _role(client, h["admin_a"], ids["admin_a"], "viewer").status_code == 403
    assert _role(client, h["owner"], ids["owner"], "viewer").status_code == 403
    # As before owners were recorded: any admin manages the other admins.
    assert _role(client, h["admin_a"], ids["viewer_a"], "admin").status_code == 200
    assert _role(client, h["admin_a"], ids["admin_b"], "viewer").status_code == 200
    assert _off(client, h["admin_a"], ids["viewer_b"]).status_code == 200
    roles = _roles(app_module, org_id)
    assert roles[ids["viewer_a"]][0] == "admin" and roles[ids["admin_b"]][0] == "viewer"
    # Nobody owns it, so nobody can transfer it.
    assert client.post("/auth/organization/owner/transfer", headers=h["owner"],
                       json={"user_id": ids["admin_a"]}).status_code == 403


def test_a_platform_operator_records_the_owner_of_an_organization_without_one(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    with app_module._db() as db:
        db.execute("DELETE FROM morrow_org_owners")
        db.commit()
    url = f"/platform/customers/{org_id}/owner"
    body = {"user_id": ids["admin_a"], "reason": "owner requested by the customer"}

    assert client.put(url, json=body).status_code in (401, 403)
    assert client.put(url, headers=op("auditor"), json=body).status_code == 403
    assert client.put(url, headers=op("operator"), json={**body, "user_id": ids["viewer_a"]}).status_code == 409
    other, _ = signed_up(client, organization="Globex")
    assert client.put(url, headers=op("operator"), json={**body, "user_id": other["user"]["id"]}).status_code == 404
    assert _owner(app_module, org_id) == ""

    set_ = client.put(url, headers=op("operator"), json=body)
    assert set_.status_code == 200, set_.text
    assert set_.json()["owner_id"] == ids["admin_a"] and set_.json()["previous_owner_id"] == ""
    assert _owner(app_module, org_id) == ids["admin_a"]
    assert len(events("org_owner.set")) == 1

    # Now the owner rules apply: the account that signed up is an admin like any other.
    assert _role(client, h["owner"], ids["admin_b"], "viewer").status_code == 403
    assert _role(client, h["admin_a"], ids["owner"], "viewer").status_code == 200


def test_the_operators_step_up_guards_changes_to_admins_and_the_owner(hosted, mail, monkeypatch):
    """Operators may change or remove an admin or the owner, after an MFA step-up; a viewer needs none."""
    from services import operator_auth

    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    asked = []
    monkeypatch.setattr(operator_auth, "require_step_up", lambda actor=None, action="": asked.append(action))

    base = f"/platform/customers/{org_id}"
    assert client.patch(f"{base}/members/{ids['viewer_a']}", headers=op("operator"),
                        json={"role": "operator", "reason": "customer request"}).status_code == 200
    assert asked == []
    assert client.patch(f"{base}/members/{ids['viewer_b']}", headers=op("operator"),
                        json={"role": "admin", "reason": "customer request"}).status_code == 200
    assert client.patch(f"{base}/members/{ids['owner']}", headers=op("operator"),
                        json={"role": "viewer", "reason": "customer request"}).status_code == 200
    assert client.post(f"{base}/users/{ids['admin_b']}/deactivate", headers=op("operator"),
                       json={"reason": "customer request"}).status_code == 200
    assert len(asked) == 3
    roles = _roles(app_module, org_id)
    assert roles[ids["owner"]][0] == "viewer" and roles[ids["viewer_b"]][0] == "admin"
    assert roles[ids["admin_b"]][1] is False

    # A refused step-up stops the change.
    from fastapi import HTTPException

    def refuse(actor=None, action=""):
        raise HTTPException(403, "step up")
    monkeypatch.setattr(operator_auth, "require_step_up", refuse)
    assert client.patch(f"{base}/members/{ids['admin_a']}", headers=op("operator"),
                        json={"role": "viewer", "reason": "customer request"}).status_code == 403
    assert client.put(f"{base}/owner", headers=op("operator"),
                      json={"user_id": ids["admin_a"], "reason": "customer request"}).status_code == 403
    assert _roles(app_module, org_id)[ids["admin_a"]][0] == "admin"
    assert _owner(app_module, org_id) == ids["owner"]


def test_the_owner_transfers_ownership_to_another_admin(hosted, mail, monkeypatch, denials):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    url = "/auth/organization/owner/transfer"

    assert client.post(url, headers=h["admin_a"], json={"user_id": ids["admin_b"]}).status_code == 403
    assert client.post(url, headers=h["viewer_a"], json={"user_id": ids["viewer_a"]}).status_code == 403
    assert client.post(url, headers=h["owner"], json={"user_id": ids["viewer_a"]}).status_code == 403
    assert client.post(url, headers=h["owner"], json={"user_id": ids["owner"]}).status_code == 403
    assert client.post(url, headers=h["owner"], json={"user_id": "nobody"}).status_code == 404
    with monkeypatch.context() as m:
        m.setattr(app_module, "_recent_sign_in", lambda payload: False)
        stale = client.post(url, headers=h["owner"], json={"user_id": ids["admin_a"]})
    assert stale.status_code == 401 and "sign in again" in stale.json()["detail"]
    assert _owner(app_module, org_id) == ids["owner"]
    # The viewer is turned away before anything is looked at, and "nobody" doesn't exist: four refusals.
    assert len(events("org_owner.refused")) == 4
    assert sum(1 for action, _ in denials if action == "auth.org_owner.transferred") == 4

    done = client.post(url, headers=h["owner"], json={"user_id": ids["admin_a"]})
    assert done.status_code == 200, done.text
    assert done.json() == {"ok": True, "owner_id": ids["admin_a"], "previous_owner_id": ids["owner"]}
    assert _owner(app_module, org_id) == ids["admin_a"]
    assert len(events("org_owner.transferred")) == 1

    # The previous owner is now an admin like the others; the new owner manages them.
    assert _role(client, h["owner"], ids["admin_b"], "viewer").status_code == 403
    assert _role(client, h["owner"], ids["admin_a"], "viewer").status_code == 403
    assert client.post(url, headers=h["owner"], json={"user_id": ids["owner"]}).status_code == 403
    assert _role(client, h["admin_a"], ids["admin_a"], "viewer").status_code == 403
    assert _role(client, h["admin_a"], ids["owner"], "viewer").status_code == 200
    assert _roles(app_module, org_id)[ids["owner"]][0] == "viewer"


def test_membership_and_invitation_routes_follow_the_same_rules(hosted, mail):
    """The older membership and invitation routes can't be used to get around the owner."""
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]
    members = f"/organizations/{org_id}/members"
    # Their memberships say admin too (an invite link joins as a viewer), which these routes read.
    for name in ("admin_a", "admin_b"):
        assert client.patch(f"{members}/{ids[name]}", headers=h["owner"], json={"role": "admin"}).status_code == 200
    before = len(events("member_change.refused"))

    def refused(res):
        return res.status_code == 403 and "owner" in res.json()["detail"]

    assert refused(client.patch(f"{members}/{ids['owner']}", headers=h["admin_a"], json={"role": "viewer"}))
    assert refused(client.patch(f"{members}/{ids['admin_b']}", headers=h["admin_a"], json={"role": "viewer"}))
    assert refused(client.patch(f"{members}/{ids['viewer_a']}", headers=h["admin_a"], json={"role": "admin"}))
    assert refused(client.patch(f"{members}/{ids['admin_b']}", headers=h["admin_a"],
                                json={"role": "admin", "status": "disabled"}))
    assert refused(client.delete(f"{members}/{ids['owner']}", headers=h["admin_a"]))
    assert refused(client.delete(f"{members}/{ids['admin_b']}", headers=h["admin_a"]))
    assert refused(client.delete(f"{members}/{ids['owner']}", headers=h["owner"]))
    assert refused(client.post(members, headers=h["admin_a"], json={"user_id": "someone-new", "role": "admin"}))
    assert refused(client.post(members, headers=h["admin_a"], json={"user_id": ids["admin_b"], "role": "viewer"}))
    own = client.patch(f"{members}/{ids['admin_a']}", headers=h["admin_a"], json={"role": "viewer"})
    assert own.status_code == 403 and "your own role" in own.json()["detail"]
    invite = {"org_id": org_id, "email": "new.admin@acme.example", "role": "org_admin", "invited_by": "admin_a"}
    assert refused(client.post(f"/admin/orgs/{org_id}/invite", headers=h["admin_a"], json=invite))
    assert len(events("member_change.refused")) - before == 11

    # Members who aren't admins stay manageable, and the owner manages admins here too.
    assert client.patch(f"{members}/{ids['viewer_a']}", headers=h["admin_a"], json={"role": "operator"}).status_code == 200
    assert client.delete(f"{members}/{ids['viewer_b']}", headers=h["admin_a"]).status_code == 200
    assert client.post(f"/admin/orgs/{org_id}/invite", headers=h["admin_a"],
                       json={**invite, "email": "new.viewer@acme.example", "role": "viewer"}).status_code == 200
    assert client.post(f"/admin/orgs/{org_id}/invite", headers=h["owner"], json=invite).status_code == 200
    assert client.patch(f"{members}/{ids['admin_b']}", headers=h["owner"], json={"role": "viewer"}).status_code == 200
    assert _owner(app_module, org_id) == ids["owner"]


def test_the_console_learns_who_owns_the_organization(hosted, mail):
    client, _ = hosted
    h, ids = _org(client)
    listed = client.get("/auth/users", headers=h["admin_a"]).json()
    assert listed["owner_id"] == ids["owner"] and listed["you"] == ids["admin_a"]
    assert {u["id"] for u in listed["users"]} >= set(ids.values())
