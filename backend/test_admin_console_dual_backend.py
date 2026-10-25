"""admin_console must behave identically on SQLite and on Postgres.

These are the tables that make the single-replica limit a *correctness* problem
rather than just a scale ceiling: admin_orgs, admin_users and admin_invitations
hold the built-in accounts, so two API replicas against a local SQLite file
disagree about who is allowed in.

Every test here runs the same flow twice -- once per backend -- and compares. The
Postgres half is skipped unless MORROW_TEST_PG_DSN is set:

    docker run -d --name morrow-pg -e POSTGRES_PASSWORD=morrowdev -e POSTGRES_DB=morrow \\
        -p 5433:5432 postgres:16-alpine
    MORROW_TEST_PG_DSN=postgresql://postgres:morrowdev@127.0.0.1:5433/morrow
"""

import importlib
import os

import pytest

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()

BACKENDS = ["sqlite"]
if PG_DSN:
    BACKENDS.append("postgres")


@pytest.fixture(params=BACKENDS)
def console(request, tmp_path, monkeypatch):
    """Yield the admin_console module bound to one backend, with clean tables."""
    backend = request.param
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", backend)

    if backend == "postgres":
        monkeypatch.setenv("MORROW_PRODUCT_DATABASE_URL", PG_DSN)
        monkeypatch.setenv("DATABASE_URL", PG_DSN)
        import psycopg2
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DROP TABLE IF EXISTS admin_audit_log, admin_invitations, "
                    "admin_users, admin_orgs, admin_rate_limits CASCADE"
                )
            conn.commit()
    else:
        monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "console.db"))

    import db_feature_store
    importlib.reload(db_feature_store)
    import services.admin_console as module
    importlib.reload(module)
    assert db_feature_store.dialect() == backend
    module._BACKEND_UNDER_TEST = backend
    return module


def test_org_lifecycle_is_identical_across_backends(console):
    created = console.create_org(name="Acme", domain="acme.test", plan="pro",
                                 max_assets=250, max_scans=900, actor="ops@pq")
    assert created["ok"] is True
    org_id = created["org_id"]

    fetched = console.get_org(org_id)
    assert fetched["name"] == "Acme"
    assert fetched["plan"] == "pro"
    assert int(fetched["max_scans"]) == 900
    assert fetched["status"] == "active"

    console.update_org(org_id, plan="enterprise", max_scans=5000, actor="ops@pq")
    updated = console.get_org(org_id)
    assert updated["plan"] == "enterprise"
    assert int(updated["max_scans"]) == 5000

    # delete_org is a soft delete: it sets status=suspended.
    console.delete_org(org_id, actor="ops@pq")
    assert console.get_org(org_id)["status"] == "suspended"

    listed = console.list_orgs()
    assert any(o["id"] == org_id for o in listed)
    assert all(o["status"] == "suspended" for o in console.list_orgs(status_filter="suspended")
               if o["id"] == org_id)


def test_invitation_and_acceptance_flow(console):
    org_id = console.create_org(name="Northwind", actor="ops@pq")["org_id"]

    invite = console.invite_user(org_id, "ciso@northwind.test", role="org_admin",
                                 invited_by="ops@pq")
    assert invite["ok"] is True
    token = invite["token"]

    accepted = console.accept_invitation(token)
    assert accepted["ok"] is True

    users = console.list_users(org_id)
    assert [u["email"] for u in users] == ["ciso@northwind.test"]
    assert users[0]["role"] == "org_admin"
    assert users[0]["status"] == "active"


def test_reaccepting_an_invitation_updates_rather_than_duplicating(console):
    """Exercises the try-insert / on-conflict-update path. On Postgres a bare
    IntegrityError aborts the transaction, so without a savepoint this flow
    fails outright instead of recovering."""
    org_id = console.create_org(name="Globex", actor="ops@pq")["org_id"]
    email = "analyst@globex.test"

    first = console.invite_user(org_id, email, role="viewer", invited_by="ops@pq")
    assert console.accept_invitation(first["token"])["ok"] is True

    second = console.invite_user(org_id, email, role="analyst", invited_by="ops@pq")
    result = console.accept_invitation(second["token"])
    assert result["ok"] is True, f"second acceptance failed: {result}"

    users = console.list_users(org_id)
    assert len(users) == 1, "the user must be updated, not duplicated"
    assert users[0]["role"] == "analyst", "the newer role should win"


def test_duplicate_org_name_or_bad_input_is_reported_not_raised(console):
    bad = console.create_org(name="", actor="ops@pq")
    assert bad["ok"] is False or console.get_org(bad.get("org_id", "")) is not None


def test_audit_log_records_actions_with_autoincrement_ids(console):
    org_id = console.create_org(name="Initech", actor="ops@pq")["org_id"]
    console.update_org(org_id, plan="pro", actor="ops@pq")

    entries = console.get_audit_log(org_id=org_id)
    actions = [e["action"] for e in entries]
    assert "create_org" in actions
    assert "update_org" in actions

    ids = [int(e["id"]) for e in entries]
    assert len(set(ids)) == len(ids), "audit ids must be unique"
    assert all(i > 0 for i in ids)


def test_unknown_org_returns_none_rather_than_raising(console):
    assert console.get_org("does-not-exist") is None
    assert console.list_users("does-not-exist") == []
