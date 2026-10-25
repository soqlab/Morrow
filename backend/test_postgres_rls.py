"""Row-level security as a real tenant boundary, proved against a real Postgres.

Every other test in the suite runs on SQLite, where RLS does not exist, so nothing there can tell the
difference between "isolated by policy" and "isolated by the WHERE clause the query happened to
have". This file builds a disposable database with the full schema, applies the generated plan,
connects as a NOSUPERUSER NOBYPASSRLS role -- the only kind of role the policies constrain -- and
checks the boundary from the outside.

Skipped unless MORROW_TEST_PG_DSN names a disposable server whose role may create databases and roles:

    MORROW_TEST_PG_DSN=postgresql://morrow:pqtest@127.0.0.1:55432/pq_test \
        python -m pytest -q test_postgres_rls.py
"""

from __future__ import annotations

import os
import pathlib
import sys
import uuid

import pytest

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
pytestmark = pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against a real Postgres")

BACKEND = pathlib.Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

ORG_A = "11111111-1111-1111-1111-111111111111"
ORG_B = "22222222-2222-2222-2222-222222222222"


def _admin_conn(dsn=None):
    import psycopg2

    conn = psycopg2.connect(dsn or PG_DSN)
    conn.autocommit = True
    return conn


# --------------------------------------------------------------------------- #
# Seeding
#
# The covered-table list is long and still growing, and a hand-written INSERT per table would rot the
# day someone adds a column. These build one from the live catalogue instead: supply organization_id,
# supply every other column that is NOT NULL with no default, and let the rest default. Foreign keys
# are switched off for the duration (session_replication_role), because the point of the seed is to
# put one row per tenant in each table, not to build a referentially coherent product state.
# --------------------------------------------------------------------------- #

def _columns(cur, table):
    cur.execute(
        """
        SELECT column_name, data_type, is_nullable, column_default, is_identity
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table,),
    )
    return cur.fetchall()


def _dummy(data_type, org, column):
    kind = str(data_type or "").lower()
    if kind in ("integer", "bigint", "smallint", "numeric", "double precision", "real"):
        return 0
    if kind == "boolean":
        return False
    if kind in ("timestamp with time zone", "timestamp without time zone", "date"):
        return "2026-01-01T00:00:00+00:00"
    if kind in ("json", "jsonb"):
        return "{}"
    if kind == "bytea":
        return b""
    if kind == "uuid":
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{org}:{column}"))
    # Text-ish. Derive from the tenant so two tenants never collide on a unique or primary key that
    # does not itself include organization_id.
    return f"rls-{org[:8]}-{column}"[:80]


def _tenant_col(table):
    """The column that carries the tenant for this table.

    Not every tenant table spells it organization_id: the four admin-console tables spell it
    org_id, which is how they stayed outside the plan and outside the coverage audit at the same
    time. Reading the mapping from the plan means this file cannot drift from it.
    """
    from services.postgres_rls import tenant_column

    return tenant_column(table)


def _seed_row(cur, table, org):
    tenant = _tenant_col(table)
    cols, vals = [], []
    for name, data_type, nullable, default, identity in _columns(cur, table):
        if str(identity or "").upper() == "YES" or (default and "nextval" in str(default)):
            continue
        if name == tenant:
            cols.append(name)
            vals.append(org)
        elif str(nullable).upper() == "NO" and default is None:
            cols.append(name)
            vals.append(_dummy(data_type, org, name))
    placeholders = ", ".join(["%s"] * len(cols))
    quoted = ", ".join(f'"{c}"' for c in cols)
    cur.execute(f'INSERT INTO "{table}" ({quoted}) VALUES ({placeholders})', vals)


@pytest.fixture(scope="module")
def rls(tmp_path_factory):
    """A database with the full schema, the plan applied, and a role the policies actually bind."""
    from psycopg2.extensions import make_dsn

    db_name = "pq_rls_" + uuid.uuid4().hex[:10]
    role = "pq_rls_app_" + uuid.uuid4().hex[:8]
    password = "rls-test-" + uuid.uuid4().hex[:12]

    admin = _admin_conn()
    admin.cursor().execute(f"CREATE DATABASE {db_name}")
    admin.close()

    owner_dsn = make_dsn(PG_DSN, dbname=db_name)
    app_dsn = make_dsn(owner_dsn, user=role, password=password)

    mp = pytest.MonkeyPatch()
    sqlite_side = str(tmp_path_factory.mktemp("rls") / "sqlite-side.db")
    for key, value in {
        "MORROW_MAIN_DB_BACKEND": "postgres",
        "MORROW_FEATURE_STORE_BACKEND": "postgres",
        "DATABASE_URL": owner_dsn,
        "MORROW_PRODUCT_DATABASE_URL": owner_dsn,
        "MORROW_SCANNER_DB": sqlite_side,
        "MORROW_ENVIRONMENT": "local",
    }.items():
        mp.setenv(key, value)

    import db
    import db_postgres

    db_postgres.ensure_postgres_core_schema(owner_dsn)
    db.init_db()
    import app as app_module  # registers the deferred schema hooks  # noqa: F401

    db_postgres.apply_deferred_schemas()

    from services.postgres_rls import ORG_SCOPED_TABLES, build_rls_sql

    owner = _admin_conn(owner_dsn)
    cur = owner.cursor()
    cur.execute(
        f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %s",
        (password,),
    )
    cur.execute(f"GRANT CONNECT ON DATABASE {db_name} TO {role}")

    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    present = {r[0] for r in cur.fetchall()}
    covered = [t for t in ORG_SCOPED_TABLES if t in present]
    assert covered, "no covered tables materialised; the schema build failed"

    # Seed before applying the plan: the owner is a superuser and therefore exempt anyway, but
    # seeding first also means the isolation assertions run against rows that predate the policies,
    # which is the situation a real deployment is in when it applies this migration.
    cur.execute("SET session_replication_role = 'replica'")
    for table in covered:
        for org in (ORG_A, ORG_B):
            _seed_row(cur, table, org)
    cur.execute("SET session_replication_role = 'origin'")

    cur.execute(build_rls_sql(app_role=role))
    owner.close()

    yield {
        "db": db_name,
        "role": role,
        "owner_dsn": owner_dsn,
        "app_dsn": app_dsn,
        "covered": covered,
        "monkeypatch": mp,
    }

    mp.undo()
    try:
        db_postgres.close_pools()
    except Exception:
        pass
    admin = _admin_conn()
    admin.cursor().execute(f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")
    admin.cursor().execute(f"DROP ROLE IF EXISTS {role}")
    admin.close()


@pytest.fixture()
def app_conn(rls):
    """A connection as the runtime role, with no tenant and no privilege set."""
    import psycopg2

    conn = psycopg2.connect(rls["app_dsn"])
    conn.autocommit = True
    yield conn
    conn.close()


def _set_tenant(conn, org):
    conn.cursor().execute("SELECT set_config('app.current_organization_id', %s, false)", (org,))


def _set_platform(conn, on):
    conn.cursor().execute("SELECT set_config('app.platform_scope', %s, false)", ("on" if on else "",))


def _count(conn, table, where="", params=()):
    cur = conn.cursor()
    cur.execute(f'SELECT COUNT(*) FROM "{table}" {where}', params)
    return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- #
# The boundary itself
# --------------------------------------------------------------------------- #

def test_the_role_the_policies_bind_cannot_bypass_them(rls, app_conn):
    """If this fails nothing else in the file means anything: a superuser or BYPASSRLS role is
    exempt from every policy, so the rest of the suite would pass against zero enforcement."""
    cur = app_conn.cursor()
    cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
    superuser, bypass = cur.fetchone()
    assert not superuser and not bypass


def _truth(rls, org):
    """Rows per covered table for one tenant, read from outside every policy.

    The assertions compare against this rather than against a hard-coded 1, because other tests in
    the file legitimately add rows (an API key, a rollup) and the property being checked -- "the
    tenant sees its own rows and only its own" -- must not depend on the order they ran in.
    """
    owner = _admin_conn(rls["owner_dsn"])
    counts = {t: _count(owner, t, f'WHERE "{_tenant_col(t)}" = %s', (org,)) for t in rls["covered"]}
    owner.close()
    return counts


def test_tenant_a_cannot_see_tenant_b_in_any_covered_table(rls, app_conn):
    expected = _truth(rls, ORG_A)
    _set_tenant(app_conn, ORG_A)
    leaked = []
    for table in rls["covered"]:
        total = _count(app_conn, table)
        others = _count(app_conn, table, f'WHERE "{_tenant_col(table)}" <> %s', (ORG_A,))
        if others or total != expected[table]:
            leaked.append((table, total, others, expected[table]))
    assert not leaked, f"(table, seen, foreign, own) with cross-tenant visibility: {leaked}"


def test_tenant_a_cannot_update_or_delete_tenant_b_rows(rls, app_conn):
    """A read-only boundary is not a boundary: a write that silently crosses tenants is worse than
    a read that does, because it is not recoverable by looking again."""
    before = _truth(rls, ORG_B)
    _set_tenant(app_conn, ORG_A)
    damage = []
    for table in rls["covered"]:
        col = _tenant_col(table)
        cur = app_conn.cursor()
        cur.execute(f'UPDATE "{table}" SET "{col}" = %s WHERE "{col}" = %s', (ORG_A, ORG_B))
        updated = cur.rowcount
        cur.execute(f'DELETE FROM "{table}" WHERE "{col}" = %s', (ORG_B,))
        deleted = cur.rowcount
        if updated or deleted:
            damage.append((table, updated, deleted))
    assert not damage, f"tenant A modified tenant B's rows: {damage}"

    # And B's rows are all still there, seen from outside the policy.
    after = _truth(rls, ORG_B)
    assert after == before, "tenant B lost rows to tenant A's writes"
    assert all(v >= 1 for v in after.values()), f"seeding gap: {[k for k, v in after.items() if not v]}"


def test_tenant_a_cannot_insert_rows_belonging_to_tenant_b(rls, app_conn):
    """WITH CHECK, not just USING: otherwise a tenant can write into another tenant's namespace and
    the victim sees rows they never created."""
    import psycopg2

    _set_tenant(app_conn, ORG_A)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        _seed_row(app_conn.cursor(), "assets", ORG_B)


def test_a_connection_with_no_tenant_sees_nothing_at_all(rls, app_conn):
    """Unset must mean zero rows, including the organization_id='' rows that the usage tables use
    for anonymous traffic. "I could not work out the tenant" must never resolve to "some rows"."""
    owner = _admin_conn(rls["owner_dsn"])
    _seed_row(owner.cursor(), "platform_usage_daily", "")
    owner.close()

    # Nothing set at all.
    assert _count(app_conn, "platform_usage_daily") == 0
    assert _count(app_conn, "assets") == 0
    # Explicitly set to the empty string, which is what the application writes when it cannot
    # resolve a tenant.
    _set_tenant(app_conn, "")
    assert _count(app_conn, "platform_usage_daily") == 0
    assert _count(app_conn, "assets") == 0


# --------------------------------------------------------------------------- #
# Pooling
# --------------------------------------------------------------------------- #

def test_a_pooled_connection_cannot_carry_a_tenant_between_requests(rls):
    """The failure this guards against is invisible in single-threaded testing: request 2 borrows the
    physical connection request 1 used, and inherits its tenant. A pool of exactly one connection
    makes the reuse certain rather than likely."""
    import db
    import db_postgres
    from services import tenant_scope

    db_postgres.close_pools()
    saved = (db_postgres._POOL_MIN, db_postgres._POOL_MAX)
    db_postgres._POOL_MIN, db_postgres._POOL_MAX = 1, 1
    try:
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["app_dsn"]

        token = db.set_current_organization_id(ORG_A)
        try:
            with db_postgres.pg_product_conn(rls["app_dsn"]) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM assets")
                    assert int(cur.fetchone()[0]) == 1
                    cur.execute("SELECT current_setting('app.current_organization_id', true)")
                    assert cur.fetchone()[0] == ORG_A
        finally:
            db.reset_current_organization_id(token)

        # Same physical connection, different tenant: it must see B's row and only B's row.
        token = db.set_current_organization_id(ORG_B)
        try:
            with db_postgres.pg_product_conn(rls["app_dsn"]) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT organization_id FROM assets")
                    rows = [r[0] for r in cur.fetchall()]
                    assert rows == [ORG_B]
        finally:
            db.reset_current_organization_id(token)

        # And once released, the connection is carrying nothing: anything that reaches it without
        # going through the checkout path sees no rows rather than the last borrower's.
        pool = db_postgres._get_pool(rls["app_dsn"])
        raw = pool.getconn()
        try:
            with raw.cursor() as cur:
                cur.execute("SELECT current_setting('app.current_organization_id', true),"
                            " current_setting('app.platform_scope', true)")
                org, platform = cur.fetchone()
            assert org in ("", None)
            assert platform in ("", None)
            with raw.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM assets")
                assert int(cur.fetchone()[0]) == 0
        finally:
            raw.rollback()
            pool.putconn(raw)

        # A failed transaction must not leave the tenant behind either: set_config is transactional,
        # so a rollback undoes the checkout's own setting.
        token = db.set_current_organization_id(ORG_A)
        try:
            try:
                with db_postgres.pg_product_conn(rls["app_dsn"]) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT COUNT(*) FROM assets")
                    raise RuntimeError("request blew up")
            except RuntimeError:
                pass
        finally:
            db.reset_current_organization_id(token)

        raw = pool.getconn()
        try:
            with raw.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM assets")
                assert int(cur.fetchone()[0]) == 0, "a rolled-back request left its tenant on the pool"
        finally:
            raw.rollback()
            pool.putconn(raw)
        assert tenant_scope.current_scope()["scope"] == "tenant"
    finally:
        db_postgres.close_pools()
        db_postgres._POOL_MIN, db_postgres._POOL_MAX = saved
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["owner_dsn"]


# --------------------------------------------------------------------------- #
# The operator escape hatch
# --------------------------------------------------------------------------- #

def test_platform_scope_reads_across_tenants_and_is_audited(rls, app_conn):
    from services import tenant_scope

    tenant_scope.reset_audit_log()
    with tenant_scope.platform_scope("test: operator console", actor="ops@example.com"):
        assert tenant_scope.is_platform_scope()
        tenant_scope.apply_to_connection(app_conn)
        orgs = set()
        cur = app_conn.cursor()
        cur.execute("SELECT DISTINCT organization_id FROM assets")
        orgs.update(r[0] for r in cur.fetchall())
        assert orgs == {ORG_A, ORG_B}

    # Audited: the escape hatch is only defensible if its use is countable and attributable.
    events = tenant_scope.escape_events()
    assert len(events) == 1
    assert events[0]["reason"] == "test: operator console"
    assert events[0]["actor"] == "ops@example.com"
    assert tenant_scope.escape_count() == 1

    # And it is gone the moment the block ends -- on the same connection.
    assert not tenant_scope.is_platform_scope()
    tenant_scope.apply_to_connection(app_conn)
    assert _count(app_conn, "assets") == 0


def test_platform_scope_does_not_survive_into_the_next_request(rls, app_conn):
    from services import tenant_scope
    import db

    with tenant_scope.platform_scope("test: operator console"):
        pass
    token = db.set_current_organization_id(ORG_A)
    try:
        tenant_scope.apply_to_connection(app_conn)
        cur = app_conn.cursor()
        cur.execute("SELECT current_setting('app.platform_scope', true)")
        assert cur.fetchone()[0] in ("", None)
        assert _count(app_conn, "assets") == 1
    finally:
        db.reset_current_organization_id(token)


def test_tenant_scope_closes_the_hatch_inside_an_operator_request(rls, app_conn):
    """An operator endpoint that serves one customer's data should be held to that customer."""
    from services import tenant_scope
    import db

    token = db.set_current_organization_id(ORG_A)
    try:
        with tenant_scope.platform_scope("test: operator console"):
            with tenant_scope.tenant_scope():
                tenant_scope.apply_to_connection(app_conn)
                assert _count(app_conn, "assets") == 1
    finally:
        db.reset_current_organization_id(token)


# --------------------------------------------------------------------------- #
# Background writers
# --------------------------------------------------------------------------- #

def test_background_writers_still_work_under_forced_rls(rls):
    """The journal flusher and the rollups write rows for every tenant from a thread that has none.
    Under RLS they only work because they take the privileged path; this is what proves they do."""
    import db_postgres
    from services import security_journal, tenant_scope, usage_rollups

    os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["app_dsn"]
    os.environ["DATABASE_URL"] = rls["app_dsn"]
    db_postgres.close_pools()
    tenant_scope.reset_audit_log()
    try:
        security_journal._ready.clear()
        usage_rollups._ready.clear()

        for org in (ORG_A, ORG_B, ""):
            security_journal.enqueue_request({
                "created_at": "2026-01-01T00:00:00Z", "organization_id": org, "method": "GET",
                "path": "/assets", "status_code": 200, "duration_ms": 5.0, "actor_id": "u",
                "actor_role": "viewer", "authenticated": bool(org), "source_ip": "127.0.0.1",
                "ip_hash": "h", "user_agent": "t", "error": "",
            })
        written = security_journal.flush_pending()
        assert written == 3, "the journal writer could not commit a cross-tenant batch"

        result = usage_rollups.run()
        assert result.get("error") is None, result

        # Both took the privileged path deliberately, and said why.
        reasons = " | ".join(e["reason"] for e in tenant_scope.escape_events())
        assert "security-journal writer" in reasons
        assert "usage rollups" in reasons
    finally:
        db_postgres.close_pools()
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["owner_dsn"]
        os.environ["DATABASE_URL"] = rls["owner_dsn"]


def test_api_key_verification_works_before_a_tenant_is_known(rls):
    """The one lookup that cannot be tenant-scoped, because the tenant is what it returns."""
    import db
    import db_postgres
    from services import api_keys, tenant_scope

    os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["app_dsn"]
    os.environ["DATABASE_URL"] = rls["app_dsn"]
    db_postgres.close_pools()
    api_keys._VERIFY_CACHE.clear()
    api_keys._TABLES_READY.clear()
    try:
        # Creating a key is an ordinary tenant-scoped write, and is isolated like any other.
        token_ctx = db.set_current_organization_id(ORG_B)
        try:
            _record, token = api_keys.create_key(ORG_B, "rls-test", ["read"], 30, "tester")
        finally:
            db.reset_current_organization_id(token_ctx)
        api_keys._VERIFY_CACHE.clear()
        # No tenant context at all, exactly as during authentication.
        verified, error, status = api_keys.verify_token(token)
        assert status == 200, error
        assert verified["organization_id"] == ORG_B
        assert any("api-key verification" in e["reason"] for e in tenant_scope.escape_events())
    finally:
        db_postgres.close_pools()
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["owner_dsn"]
        os.environ["DATABASE_URL"] = rls["owner_dsn"]


# --------------------------------------------------------------------------- #
# The thing operators actually see
# --------------------------------------------------------------------------- #

def test_the_startup_warning_is_silent_once_the_plan_is_applied(rls):
    """The warning is the product's own claim about its isolation. Once the plan is applied and the
    role is right, it has to stop talking -- a warning that never clears is one operators learn to
    ignore, including on the day it is telling the truth."""
    import app as app_module
    from services.rls_verify import verify_postgres_rls

    result = verify_postgres_rls(rls["app_dsn"])
    assert result["status"] == "pass", result["failures"]
    assert result["missing_tables"] == []
    assert result["missing_rls"] == []
    assert result["uncovered_tables"] == [], "an org-scoped table exists that the plan does not cover"
    assert result["inert_policy"] == []

    saved = os.environ.get("MORROW_PRODUCT_DATABASE_URL")
    os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["app_dsn"]
    app_module._RLS_POSTURE_CACHE.update(expires_at=0.0, warnings=[])
    try:
        assert app_module._rls_posture_warnings_uncached() == []
    finally:
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = saved or rls["owner_dsn"]
        app_module._RLS_POSTURE_CACHE.update(expires_at=0.0, warnings=[])


def test_the_startup_warning_is_specific_when_the_role_can_bypass_rls(rls):
    """Connecting as the owner is the real-world misconfiguration: everything is applied, and none
    of it does anything. The message has to name that, not just say "not fully enforced"."""
    import app as app_module

    saved = os.environ.get("MORROW_PRODUCT_DATABASE_URL")
    os.environ["MORROW_PRODUCT_DATABASE_URL"] = rls["owner_dsn"]
    app_module._RLS_POSTURE_CACHE.update(expires_at=0.0, warnings=[])
    try:
        warnings = app_module._rls_posture_warnings_uncached()
        assert warnings
        assert any("BYPASSRLS" in w for w in warnings)
    finally:
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = saved or rls["owner_dsn"]
        app_module._RLS_POSTURE_CACHE.update(expires_at=0.0, warnings=[])


def test_applying_the_plan_twice_changes_nothing(rls):
    """It ships as a migration, so it has to survive being run again -- after a schema change, or by
    a deploy that retried."""
    from services.postgres_rls import build_rls_sql
    from services.rls_verify import verify_postgres_rls

    owner = _admin_conn(rls["owner_dsn"])
    owner.cursor().execute(build_rls_sql(app_role=rls["role"]))
    owner.close()
    assert verify_postgres_rls(rls["app_dsn"])["status"] == "pass"


# --------------------------------------------------------------------------- #
# The admin-console tables (September 2026 review, finding 4)
#
# admin_users, admin_invitations, admin_audit_log and admin_rate_limits spell the
# tenant `org_id`. The plan listed tables by name and the verifier discovered them
# by looking for an `organization_id` column, so these four were both uncovered and
# invisible to the audit -- the one place the database would have contained the
# cross-tenant takeover in findings 1 and 2 is the place the audit was blind.
# --------------------------------------------------------------------------- #

ADMIN_TENANT_TABLES = ("admin_users", "admin_invitations", "admin_audit_log", "admin_rate_limits")


def test_the_admin_console_tables_are_in_the_plan_and_present(rls):
    """They have to be covered, and they have to actually exist, or "covered" proves nothing."""
    from services.postgres_rls import ORG_SCOPED_TABLES, tenant_column

    for table in ADMIN_TENANT_TABLES:
        assert table in ORG_SCOPED_TABLES, f"{table} is not in the RLS plan"
        assert tenant_column(table) == "org_id", table
        assert table in rls["covered"], (
            f"{table} did not materialise in the Postgres schema, so its isolation is unproved"
        )


def test_the_admin_console_tables_isolate_by_org_id(rls, app_conn):
    """The real assertion: tenant A, connected as the restricted role, sees only its own rows."""
    _set_tenant(app_conn, ORG_A)
    leaked = {}
    for table in ADMIN_TENANT_TABLES:
        foreign = _count(app_conn, table, 'WHERE "org_id" <> %s', (ORG_A,))
        own = _count(app_conn, table, 'WHERE "org_id" = %s', (ORG_A,))
        if foreign or not own:
            leaked[table] = (own, foreign)
    assert not leaked, f"(own, foreign) rows visible to tenant A: {leaked}"


def test_an_admin_console_table_refuses_a_cross_tenant_write(rls, app_conn):
    """WITH CHECK on org_id: inviting a user into another tenant is refused by the database too.

    This is the database half of finding 1. Even with the application check removed, the row could
    not be written -- which is the property the commit message claimed for "all 40 customer tables"
    and did not have for these four.
    """
    import psycopg2

    _set_tenant(app_conn, ORG_A)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        _seed_row(app_conn.cursor(), "admin_invitations", ORG_B)

    cur = app_conn.cursor()
    cur.execute('UPDATE "admin_users" SET "role" = %s WHERE "org_id" = %s', ("platform_admin", ORG_B))
    assert cur.rowcount == 0
    cur.execute('DELETE FROM "admin_audit_log" WHERE "org_id" = %s', (ORG_B,))
    assert cur.rowcount == 0


def test_the_registry_tables_are_recorded_exceptions_not_oversights(rls, app_conn):
    """`organizations` and `admin_orgs` key the tenant on `id` and hold no tenant's data.

    Neither can carry a per-row policy, so both are named in postgres_rls.TENANT_REGISTRY_TABLES
    with the reason written down, and the verifier excludes them explicitly rather than failing to
    see them.
    """
    from services.postgres_rls import ORG_SCOPED_TABLES, TENANT_REGISTRY_TABLES

    assert "admin_orgs" in TENANT_REGISTRY_TABLES and "organizations" in TENANT_REGISTRY_TABLES
    for table in TENANT_REGISTRY_TABLES:
        assert table not in ORG_SCOPED_TABLES
    owner = _admin_conn(rls["owner_dsn"])
    cur = owner.cursor()
    cur.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'admin_orgs'
          AND column_name IN ('organization_id', 'org_id')
        """
    )
    assert cur.fetchall() == [], "admin_orgs grew a tenant column; it now belongs in the plan"
    owner.close()


def test_the_verifier_reports_a_tenant_table_that_the_plan_forgot(rls):
    """The audit's own failure mode, reproduced and then fixed.

    A table with a tenant column under either spelling, in no policy and in no exception list, must
    come back as uncovered. Before this change the verifier looked only for `organization_id`, so a
    table spelling it `org_id` was reported as fully covered while being readable across tenants.
    """
    from services.rls_verify import verify_postgres_rls

    owner = _admin_conn(rls["owner_dsn"])
    cur = owner.cursor()
    cur.execute('CREATE TABLE "rls_forgotten_tenant_table" (id serial PRIMARY KEY, org_id text NOT NULL)')
    try:
        result = verify_postgres_rls(rls["app_dsn"])
        assert "rls_forgotten_tenant_table" in result["uncovered_tables"], result["uncovered_tables"]
        assert result["status"] == "fail"
        assert any("not covered by the RLS plan" in f for f in result["failures"]), result["failures"]
    finally:
        cur.execute('DROP TABLE "rls_forgotten_tenant_table"')
        owner.close()

    # …and with it gone, the plan verifies clean again, including the four admin tables.
    assert verify_postgres_rls(rls["app_dsn"])["status"] == "pass"


