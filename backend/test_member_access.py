"""A role change, deactivation or removal moves the account and the membership together and takes the
person's tokens with it (services/member_access.py).

Demotions, deactivations and removals apply on the very next request: the person's access tokens are
revoked, a deactivated or removed person's refresh sessions are deleted, and the API keys they created
above their new role are revoked. A promotion revokes nothing and applies on the next request, because
authorization reads the membership, not the token's role claim. Startup reconciliation brings old
mismatches into line toward the lesser access. Nobody deactivates or removes themselves when that
would leave the organization without an active admin.

Runs the real ASGI stack with real passkey ceremonies (the fixtures of test_signup and test_org_owner).
"""

import logging

from test_invite_landing import api_fixture, op  # noqa: F401  (registers the "api" fixture)
from test_org_owner import _org, _owner, denials  # noqa: F401  (registers "denials")
from test_passkeys import bearer, events, mail_fixture  # noqa: F401  (registers "mail")
from test_signup import _session_as, signed_up
from test_signup import hosted_fixture  # noqa: F401  (registers the "hosted" fixture)


def _org_id(ids):
    return _session_as({"user": {"id": ids["owner"]}})["user"]["org_id"]


def _records(app_module, org_id, user_id):
    """(account role, account active, membership role, membership status) for one person."""
    from db import get_organization_member

    with app_module._db() as db:
        account = app_module._issuer_get_user(db, user_id)
    member = get_organization_member(org_id, user_id) or {}
    return (account["role"], bool(account["is_active"]), member.get("role"), member.get("status"))


def _agree(app_module, org_id, user_id, role, active=True):
    account_role, account_on, member_role, status = _records(app_module, org_id, user_id)
    assert account_role == role and member_role == role, (account_role, member_role)
    assert account_on is active and status == ("active" if active else "disabled"), (account_on, status)


def _fresh(ids, name):
    return bearer(_session_as({"user": {"id": ids[name]}})["access_token"])


def test_a_demoted_admin_loses_admin_rights_on_their_next_request(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    assert client.get("/auth/users", headers=h["admin_a"]).status_code == 200
    assert client.get(f"/organizations/{org_id}/members", headers=h["admin_a"]).status_code == 200

    res = client.put(f"/auth/users/{ids['admin_a']}/role", headers=h["owner"], json={"role": "viewer"})
    assert res.status_code == 200, res.text
    assert res.json()["access_tokens_revoked"] is True and res.json()["role"] == "viewer"
    _agree(app_module, org_id, ids["admin_a"], "viewer")

    # The token they held is refused outright, on the console's admin routes and on every other.
    assert client.get("/auth/users", headers=h["admin_a"]).status_code == 401
    assert client.get(f"/organizations/{org_id}/members", headers=h["admin_a"]).status_code == 401
    assert client.put(f"/auth/users/{ids['viewer_a']}/role", headers=h["admin_a"],
                      json={"role": "operator"}).status_code == 401
    # Signing in again straight away works, as a viewer.
    again = _fresh(ids, "admin_a")
    assert client.get("/auth/users", headers=again).status_code == 403
    assert client.get(f"/organizations/{org_id}/members", headers=again).status_code == 403
    assert client.get("/auth/memberships", headers=again).status_code == 200
    # Nobody else was signed out.
    assert client.get("/auth/users", headers=h["admin_b"]).status_code == 200
    applied = events("member_change.applied")
    assert any(e.get("user_id") == ids["admin_a"] for e in applied)


def test_a_deactivated_users_token_is_refused(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    assert client.get("/auth/memberships", headers=h["viewer_a"]).status_code == 200
    assert client.get("/auth/memberships", headers=h["admin_b"]).status_code == 200

    res = client.post(f"/auth/users/{ids['viewer_a']}/deactivate", headers=h["admin_a"])
    assert res.status_code == 200, res.text
    _agree(app_module, org_id, ids["viewer_a"], "viewer", active=False)
    assert client.get("/auth/memberships", headers=h["viewer_a"]).status_code == 401

    res = client.post(f"/auth/users/{ids['admin_b']}/deactivate", headers=h["owner"])
    assert res.status_code == 200, res.text
    _agree(app_module, org_id, ids["admin_b"], "admin", active=False)
    assert client.get("/auth/users", headers=h["admin_b"]).status_code == 401
    # Even a token minted afterwards gets nothing: the records say no.
    assert client.get("/auth/users", headers=_fresh(ids, "admin_b")).status_code == 403


def test_refresh_sessions_and_api_keys_go_with_lowered_access(hosted, mail, monkeypatch):
    from services import api_keys, auth_issuer

    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    with app_module._db() as db:
        refresh = auth_issuer.issue_refresh_token(db, ids["admin_a"])
        assert auth_issuer.refresh_token_owner(db, refresh)
    signing, _ = api_keys.create_key(org_id, "release", ["sign"], 30, ids["admin_a"])
    admin_key, _ = api_keys.create_key(org_id, "automation", ["admin"], 30, ids["admin_a"])
    others, _ = api_keys.create_key(org_id, "someone else's", ["admin"], 30, ids["admin_b"])

    # admin -> operator: the admin-scope key goes, the signing key (operator level) stays.
    res = client.put(f"/auth/users/{ids['admin_a']}/role", headers=h["owner"], json={"role": "operator"})
    assert res.status_code == 200 and res.json()["api_keys_revoked"] == [admin_key["id"]]
    assert api_keys.get_key(signing["id"])["status"] == "active"
    with app_module._db() as db:  # a demotion keeps the session; its next token carries the new role
        assert auth_issuer.refresh_token_owner(db, refresh)
        assert auth_issuer.verify_access_token(auth_issuer.refresh_access_token(db, refresh))["role"] == "operator"

    # Deactivated: every key they made and every session.
    res = client.post(f"/auth/users/{ids['admin_a']}/deactivate", headers=h["owner"])
    assert res.status_code == 200 and res.json()["api_keys_revoked"] == [signing["id"]]
    assert res.json()["refresh_sessions_revoked"] >= 1
    with app_module._db() as db:
        assert auth_issuer.refresh_token_owner(db, refresh) is None
    assert api_keys.get_key(others["id"])["status"] == "active"


def test_promotions_apply_on_the_next_request_without_revoking_anything(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    assert client.get("/auth/users", headers=h["viewer_a"]).status_code == 403

    res = client.put(f"/auth/users/{ids['viewer_a']}/role", headers=h["owner"], json={"role": "admin"})
    assert res.status_code == 200 and res.json()["access_tokens_revoked"] is False
    _agree(app_module, org_id, ids["viewer_a"], "admin")
    # The token they already hold still says viewer, but what they may do is read from the records.
    assert client.get("/auth/users", headers=h["viewer_a"]).status_code == 200
    assert client.get(f"/organizations/{org_id}/members", headers=h["viewer_a"]).status_code == 200


def test_every_path_keeps_the_account_and_the_membership_in_agreement(hosted, mail, monkeypatch):
    from services import operator_auth

    client, app_module = hosted
    monkeypatch.setattr(operator_auth, "require_step_up", lambda actor=None, action="": None)
    h, ids = _org(client)
    org_id = _org_id(ids)
    members = f"/organizations/{org_id}/members"
    owner = h["owner"]

    assert client.patch(f"{members}/{ids['viewer_a']}", headers=owner, json={"role": "operator"}).status_code == 200
    _agree(app_module, org_id, ids["viewer_a"], "operator")
    assert client.post(members, headers=owner, json={"user_id": ids["viewer_a"], "role": "admin"}).status_code == 200
    _agree(app_module, org_id, ids["viewer_a"], "admin")
    assert client.patch(f"{members}/{ids['viewer_a']}", headers=owner,
                        json={"role": "admin", "status": "disabled"}).status_code == 200
    _agree(app_module, org_id, ids["viewer_a"], "admin", active=False)
    assert client.patch(f"{members}/{ids['viewer_a']}", headers=owner,
                        json={"role": "admin", "status": "active"}).status_code == 200
    _agree(app_module, org_id, ids["viewer_a"], "admin")
    assert client.put(f"/auth/users/{ids['viewer_a']}/role", headers=owner, json={"role": "viewer"}).status_code == 200
    _agree(app_module, org_id, ids["viewer_a"], "viewer")

    # Removing the membership of someone whose account is bound here, with nowhere else to go, ends
    # the account's access too: it can't keep minting tokens for an organization it left.
    assert client.delete(f"{members}/{ids['viewer_b']}", headers=owner).status_code == 200
    account_role, account_on, member_role, _ = _records(app_module, org_id, ids["viewer_b"])
    assert member_role is None and account_on is False
    assert client.get("/auth/memberships", headers=h["viewer_b"]).status_code == 401

    # The invitation-workflow routes (by email) move the same records.
    email = "admin.b@acme.example"
    with app_module._db() as db:
        db.execute("UPDATE morrow_users SET email=? WHERE id=?", (email, ids["admin_b"]))
        db.commit()
    res = client.put("/admin/users/role", headers=owner, json={"org_id": org_id, "email": email, "new_role": "analyst"})
    assert res.status_code == 200 and res.json()["ok"], res.text
    _agree(app_module, org_id, ids["admin_b"], "operator")
    assert client.get("/auth/memberships", headers=h["admin_b"]).status_code == 401
    res = client.request("DELETE", "/admin/users", headers=owner, json={"org_id": org_id, "email": email})
    assert res.status_code == 200 and res.json()["ok"], res.text
    _agree(app_module, org_id, ids["admin_b"], "operator", active=False)
    res = client.put("/admin/users/role", headers=owner, json={"org_id": org_id, "email": "nobody@acme.example",
                                                               "new_role": "viewer"})
    assert res.status_code == 200 and res.json() == {"api_version": "v1", "ok": False, "error": "User not found"}

    # Platform operators.
    base = f"/platform/customers/{org_id}"
    assert client.patch(f"{base}/members/{ids['admin_a']}", headers=op("operator"),
                        json={"role": "operator", "reason": "customer request"}).status_code == 200
    _agree(app_module, org_id, ids["admin_a"], "operator")
    assert client.get("/auth/memberships", headers=h["admin_a"]).status_code == 401
    assert client.post(f"{base}/users/{ids['admin_a']}/deactivate", headers=op("operator"),
                       json={"reason": "customer request", "revoke_sessions": False}).status_code == 200
    _agree(app_module, org_id, ids["admin_a"], "operator", active=False)
    assert client.post(f"{base}/users/{ids['admin_a']}/reactivate", headers=op("operator"),
                       json={"reason": "customer request"}).status_code == 200
    _agree(app_module, org_id, ids["admin_a"], "operator")
    assert client.delete(f"{base}/members/{ids['admin_a']}", headers=op("operator"),
                         params={"reason": "customer request"}).status_code == 200
    assert _records(app_module, org_id, ids["admin_a"])[1:3] == (False, None)
    assert client.post(f"{base}/members", headers=op("operator"),
                       json={"user_id": ids["admin_a"], "role": "viewer", "reason": "back again"}).status_code == 200
    _agree(app_module, org_id, ids["admin_a"], "viewer")


def test_removal_moves_the_account_to_another_organization_it_belongs_to(hosted, mail):
    from db import upsert_organization_member

    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    other, _ = signed_up(client, organization="Globex")
    upsert_organization_member(other["user"]["org_id"], ids["viewer_a"], role="operator", status="active")

    assert client.delete(f"/organizations/{org_id}/members/{ids['viewer_a']}", headers=h["owner"]).status_code == 200
    with app_module._db() as db:
        account = app_module._issuer_get_user(db, ids["viewer_a"])
    assert account["is_active"] and account["org_id"] == other["user"]["org_id"] and account["role"] == "operator"
    assert client.get("/auth/memberships", headers=h["viewer_a"]).status_code == 401


def test_the_last_active_admin_cant_deactivate_themselves(hosted, mail, denials):  # noqa: F811
    client, app_module = hosted
    owner, _ = signed_up(client, organization="Solo")
    org_id = owner["user"]["org_id"]
    me = owner["user"]["id"]
    headers = bearer(owner["access_token"])
    with app_module._db() as db:
        db.execute("DELETE FROM morrow_org_owners")
        db.commit()
    assert _owner(app_module, org_id) == ""

    for res in (client.post(f"/auth/users/{me}/deactivate", headers=headers),
                client.delete(f"/organizations/{org_id}/members/{me}", headers=headers),
                client.patch(f"/organizations/{org_id}/members/{me}", headers=headers,
                             json={"role": "admin", "status": "disabled"})):
        assert res.status_code == 403 and "only active admin" in res.json()["detail"], res.text
    assert ("auth.member.remove", "last_admin") in denials
    _agree(app_module, org_id, me, "admin")
    assert client.get("/auth/users", headers=headers).status_code == 200


def test_a_self_deactivation_that_leaves_another_admin_goes_through(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    with app_module._db() as db:
        db.execute("DELETE FROM morrow_org_owners")
        db.commit()
    # admin_b is gone already; admin_a and the former owner remain.
    assert client.post(f"/auth/users/{ids['admin_b']}/deactivate", headers=h["admin_a"]).status_code == 200
    assert client.post(f"/auth/users/{ids['admin_a']}/deactivate", headers=h["admin_a"]).status_code == 200
    _agree(app_module, org_id, ids["admin_a"], "admin", active=False)
    # Now the former owner is the last one.
    res = client.post(f"/auth/users/{ids['owner']}/deactivate", headers=h["owner"])
    assert res.status_code == 403 and "only active admin" in res.json()["detail"]


def test_someone_in_another_organization_still_gets_404(hosted, mail):
    client, app_module = hosted
    h, ids = _org(client, organization="Acme")
    org_id = _org_id(ids)
    other, _ = signed_up(client, organization="Globex")
    other_headers = bearer(other["access_token"])
    for target in (ids["admin_a"], ids["viewer_a"]):
        assert client.put(f"/auth/users/{target}/role", headers=other_headers, json={"role": "viewer"}).status_code == 404
        assert client.post(f"/auth/users/{target}/deactivate", headers=other_headers).status_code == 404
    _agree(app_module, org_id, ids["admin_a"], "admin")
    _agree(app_module, org_id, ids["viewer_a"], "viewer")
    assert client.get("/auth/users", headers=h["admin_a"]).status_code == 200


def test_startup_reconciliation_fixes_a_mismatch_toward_less_access(hosted, mail, caplog):
    from db import get_organization_member, upsert_organization_member
    from services import member_access

    client, app_module = hosted
    h, ids = _org(client)
    org_id = _org_id(ids)
    # Seed what the old routes left behind: the account demoted, the membership still admin; and a
    # membership disabled while the account is active; and an account with no membership at all.
    with app_module._db() as db:
        db.execute("UPDATE morrow_users SET role='viewer' WHERE id=?", (ids["admin_a"],))
        db.commit()
    upsert_organization_member(org_id, ids["viewer_a"], role="viewer", status="disabled")
    with app_module._db() as db:
        db.execute("DELETE FROM organization_memberships WHERE user_id=?", (ids["viewer_b"],))
        db.commit()
    assert get_organization_member(org_id, ids["admin_a"])["role"] == "admin"

    with caplog.at_level(logging.WARNING):
        fixes = member_access.reconcile()
    fixed = {f["user_id"]: f for f in fixes}
    assert set(fixed) >= {ids["admin_a"], ids["viewer_a"], ids["viewer_b"]}
    _agree(app_module, org_id, ids["admin_a"], "viewer")
    _agree(app_module, org_id, ids["viewer_a"], "viewer", active=False)
    _agree(app_module, org_id, ids["viewer_b"], "viewer")
    # The admin the old route meant to demote is no longer an admin anywhere, token included.
    assert client.get("/auth/users", headers=h["admin_a"]).status_code == 401
    assert client.get("/auth/users", headers=_fresh(ids, "admin_a")).status_code == 403
    # Logged by id, without names or addresses.
    lines = [r.getMessage() for r in caplog.records if "[access-reconcile]" in r.getMessage()]
    assert any(ids["admin_a"] in line for line in lines)
    assert not any("@" in line for line in lines)
    # Idempotent.
    assert member_access.reconcile() == []


def test_a_token_minted_just_after_a_revocation_is_not_caught_by_it(hosted):
    import time

    from services import session_revocation

    cutoff = session_revocation.revoke("user", "precision-check", reason="test")
    before = {"sub": "precision-check", "iat": cutoff, "iat_ms": cutoff * 1000}
    assert session_revocation.is_revoked(before)
    time.sleep(0.01)
    now = time.time()
    after = {"sub": "precision-check", "iat": int(now), "iat_ms": int(now * 1000)}
    assert not session_revocation.is_revoked(after)
    # Without milliseconds the whole second counts as revoked, as before.
    assert session_revocation.is_revoked({"sub": "precision-check", "iat": cutoff})
    session_revocation.refresh()
    assert session_revocation.is_revoked(before) and not session_revocation.is_revoked(after)
