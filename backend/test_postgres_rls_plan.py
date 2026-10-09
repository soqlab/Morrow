import pytest

from services.postgres_rls import (
    ORG_SCOPED_TABLES,
    SQLITE_ONLY_ORG_TABLES,
    TENANT_COLUMN_NAMES,
    TENANT_COLUMNS,
    TENANT_REGISTRY_TABLES,
    build_rls_plan,
    build_rls_sql,
    quote_ident,
    tenant_column,
)
from services.rls_verify import evaluate_rls_state


def test_build_rls_sql_covers_org_scoped_tables():
    sql = build_rls_sql(app_role="pqc_app")

    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    # Statements are nested inside EXECUTE, so literals appear with doubled quotes.
    assert "current_setting(''app.current_organization_id'', true)" in sql
    for table in ORG_SCOPED_TABLES:
        assert f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in sql
        assert f'{table}_org_isolation' in sql


def test_policy_is_created_before_rls_is_forced():
    """A table must never end up with FORCE RLS and no policy -- that returns zero rows forever."""
    sql = build_rls_sql(app_role="pqc_app", tables=["assets"])

    create_policy = sql.index("CREATE POLICY")
    enable_rls = sql.index("ENABLE ROW LEVEL SECURITY")
    force_rls = sql.index("FORCE ROW LEVEL SECURITY")
    assert create_policy < enable_rls < force_rls


def test_each_table_is_guarded_on_existence_and_org_column():
    """A schema missing an optional table must not abort the script and skip the rest."""
    sql = build_rls_sql(app_role="pqc_app", tables=["assets", "scans"])

    assert sql.count("to_regclass") == 2
    assert sql.count("column_name = 'organization_id'") == 2
    # Guarded statements run inside DO blocks, so a NOTICE replaces a hard failure.
    assert sql.count("RAISE NOTICE") == 4


def test_sql_refuses_a_role_that_would_make_policies_inert():
    """Postgres exempts superusers and BYPASSRLS roles from RLS, so applying policies over such a
    role silently protects nothing. The script must refuse rather than appear to succeed."""
    sql = build_rls_sql(app_role="pqc_app")

    assert "rolsuper OR rolbypassrls" in sql
    assert "RAISE EXCEPTION" in sql
    # The guard has to come before any table is altered.
    assert sql.index("rolbypassrls") < sql.index("ENABLE ROW LEVEL SECURITY")


def test_sqlite_only_tables_are_not_rls_targets():
    """These tables never exist in Postgres; listing them made the verifier permanently fail."""
    assert SQLITE_ONLY_ORG_TABLES
    for table in SQLITE_ONLY_ORG_TABLES:
        assert table not in ORG_SCOPED_TABLES


def test_rls_plan_explains_operator_steps():
    plan = build_rls_plan(app_role="pqc_app")

    assert plan["status"] == "ready"
    assert plan["org_setting"] == "app.current_organization_id"
    assert "sql" in plan
    assert any("BYPASSRLS" in step for step in plan["operator_steps"])
    # The application sets the org setting itself; operators must not be told to do it.
    assert plan["app_sets_org_setting"] is True


def test_an_unset_tenant_matches_nothing_rather_than_the_empty_organization():
    """`organization_id = current_setting(...)` alone is not enough: several tables use '' as the
    anonymous/unattributed bucket, so a connection that resolved no tenant would read those rows."""
    sql = build_rls_sql(app_role="pqc_app", tables=["assets"])

    assert "NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL" in sql


def test_the_cross_tenant_escape_hatch_is_in_the_policy_not_in_the_role():
    """A session flag can be audited and is off by default; BYPASSRLS on the role cannot and is not."""
    sql = build_rls_sql(app_role="pqc_app", tables=["assets"])

    assert "current_setting(''app.platform_scope'', true) = ''on''" in sql
    plan = build_rls_plan(app_role="pqc_app")
    assert plan["platform_setting"] == "app.platform_scope"
    assert "NOBYPASSRLS" in plan["operator_access_rule"]


def test_the_plan_grants_the_runtime_role_its_privileges():
    """RLS restricts what a role may see; it never grants access. A role created purely for the
    runtime has no rights at all until these run, so leaving them out means the hardening step
    locks the application out of its own database."""
    sql = build_rls_sql(app_role="pqc_app", tables=["assets"])

    assert 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "pqc_app"' in sql
    assert sql.index("GRANT USAGE ON SCHEMA public") < sql.index("ENABLE ROW LEVEL SECURITY")


def test_the_feature_store_tenant_tables_are_covered():
    """These were isolated by query filters alone: support access, usage rollups, API keys and
    feedback all carry a per-customer organization_id.

    The billing tables used to be in this list and are not any more: the billing code was removed
    when the platform became free, and revision 0009 drops the tables. A policy on a table that no
    longer exists is not protection, it is a claim that cannot be checked.
    """
    for table in ("feedback", "platform_api_keys",
                  "platform_support_sessions", "platform_usage_daily", "platform_active_users_daily",
                  "platform_traffic_events", "platform_feature_state_records", "gateway_sites"):
        assert table in ORG_SCOPED_TABLES


def test_no_policy_names_a_billing_table():
    """The removal has to be complete in the policy set, not only in the code.

    A leftover billing_* entry would make the RLS build fail on a database that never had those
    tables, or quietly claim coverage for something absent. Either way the plan would be lying.
    """
    from services.postgres_rls import ORG_SCOPED_TABLES, PLATFORM_SCOPED_TABLES

    leftovers = sorted(t for t in list(ORG_SCOPED_TABLES) + list(PLATFORM_SCOPED_TABLES)
                       if t.startswith("billing_"))
    assert not leftovers, f"billing tables still in the row-level-security plan: {leftovers}"


def test_quote_ident_rejects_unsafe_identifiers():
    with pytest.raises(ValueError):
        quote_ident("pqc_app; drop table assets")


def test_scope_state_is_off_by_default_and_restores_on_exit():
    from services import tenant_scope

    tenant_scope.reset_audit_log()
    assert not tenant_scope.is_platform_scope()
    with tenant_scope.platform_scope("unit test", actor="me"):
        assert tenant_scope.is_platform_scope()
        assert tenant_scope.current_scope() == {"scope": "platform", "reason": "unit test", "actor": "me"}
    assert not tenant_scope.is_platform_scope()
    assert tenant_scope.escape_count() == 1
    assert tenant_scope.escape_events()[-1]["reason"] == "unit test"


def test_scope_restores_the_previous_state_not_merely_off():
    """Nested privileged calls are normal -- an operator endpoint calling a background helper. The
    inner block must not close the hatch the outer one legitimately opened."""
    from services import tenant_scope

    with tenant_scope.platform_scope("outer"):
        with tenant_scope.platform_scope("inner"):
            pass
        assert tenant_scope.is_platform_scope()
    assert not tenant_scope.is_platform_scope()


def test_applying_the_scope_is_a_no_op_without_a_postgres_connection():
    """SQLite deployments run every one of these code paths; none of them may raise there."""
    from services import tenant_scope

    class NotAConnection:
        def cursor(self):
            raise AssertionError("SQLite has no session settings to write")

        def rollback(self):
            pass

    tenant_scope.apply_to_connection(NotAConnection())
    tenant_scope.reset_on_release(NotAConnection())


def _table_row(name, rls=True, force=True):
    return {"relname": name, "relrowsecurity": rls, "relforcerowsecurity": force}


SAFE_ROLE = {"role_name": "pqc_app", "rolsuper": False, "rolbypassrls": False}


def _healthy_policies():
    """One correct-looking policy row per covered table, using that table's own tenant column."""
    return [
        {"tablename": t,
         "qual": f"({tenant_column(t)} = current_setting('app.current_organization_id'::text, true))"}
        for t in ORG_SCOPED_TABLES
    ]


def test_verifier_passes_when_every_table_is_protected():
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = [{"tablename": t} for t in ORG_SCOPED_TABLES]

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                              org_scoped_in_db=ORG_SCOPED_TABLES, policy_rows=policies)

    assert state["status"] == "pass", state["failures"]


def test_verifier_flags_a_superuser_app_role():
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = [{"tablename": t} for t in ORG_SCOPED_TABLES]

    state = evaluate_rls_state(rows, {"role_name": "postgres", "rolsuper": True, "rolbypassrls": True},
                               ORG_SCOPED_TABLES, org_scoped_in_db=ORG_SCOPED_TABLES,
                               policy_rows=policies)

    assert state["status"] == "fail"
    assert any("inert" in f for f in state["failures"])


def test_verifier_flags_an_org_scoped_table_the_plan_does_not_cover():
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = [{"tablename": t} for t in ORG_SCOPED_TABLES]
    live = list(ORG_SCOPED_TABLES) + ["a_new_tenant_table"]

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                               org_scoped_in_db=live, policy_rows=policies)

    assert state["status"] == "fail"
    assert state["uncovered_tables"] == ["a_new_tenant_table"]


def test_verifier_flags_rls_enabled_with_no_policy():
    """The worst state: the table is locked down and nothing can read it, including the app."""
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = [{"tablename": t} for t in ORG_SCOPED_TABLES if t != "assets"]

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                               org_scoped_in_db=ORG_SCOPED_TABLES, policy_rows=policies)

    assert state["status"] == "fail"
    assert state["missing_policy"] == ["assets"]


def test_verifier_flags_a_policy_that_does_not_read_the_tenant_setting():
    """The commonest way to lose the boundary while keeping every appearance of it: someone replaces
    a policy with `USING (true)` to unbreak a query. Everything else still reports healthy."""
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = _healthy_policies()
    policies[0] = {"tablename": ORG_SCOPED_TABLES[0], "qual": "true"}

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                               org_scoped_in_db=ORG_SCOPED_TABLES, policy_rows=policies)

    assert state["status"] == "fail"
    assert state["inert_policy"] == [ORG_SCOPED_TABLES[0]]


def test_verifier_flags_a_policy_that_matches_the_wrong_column():
    """Reading the tenant setting is not enough; it has to be compared with THIS table's tenant
    column. A policy on admin_users that matched `organization_id` would reference a column the
    table does not have -- or, worse, one it grew later -- and isolate nothing."""
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    policies = _healthy_policies()
    wrong = next(t for t in ORG_SCOPED_TABLES if tenant_column(t) == "org_id")
    for policy in policies:
        if policy["tablename"] == wrong:
            policy["qual"] = "(organization_id = current_setting('app.current_organization_id'::text, true))"

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                               org_scoped_in_db=ORG_SCOPED_TABLES, policy_rows=policies)

    assert state["inert_policy"] == [wrong]
    assert state["status"] == "fail"


def test_verifier_does_not_claim_zero_rows_when_rls_is_simply_off():
    """On a database where RLS was never enabled, a missing policy is the expected state.

    Reporting "these tables return no rows" there is both wrong and alarming; missing_rls already
    says what actually needs doing.
    """
    rows = [_table_row(t, rls=False, force=False) for t in ORG_SCOPED_TABLES]

    state = evaluate_rls_state(rows, SAFE_ROLE, ORG_SCOPED_TABLES,
                               org_scoped_in_db=ORG_SCOPED_TABLES, policy_rows=[])

    assert state["missing_policy"] == []
    assert state["missing_rls"] == list(ORG_SCOPED_TABLES)
    assert state["status"] == "fail"  # still not enforced, just described correctly
    assert not any("return no rows" in f for f in state["failures"])


# --------------------------------------------------------------------------- #
# September 2026 review, finding 4: the admin-console tables spell the tenant
# org_id, so they were outside the plan AND invisible to the coverage audit.
# --------------------------------------------------------------------------- #

ADMIN_TENANT_TABLES = ("admin_users", "admin_invitations", "admin_audit_log", "admin_rate_limits")


def test_the_admin_console_tables_are_covered_under_their_own_tenant_column():
    for table in ADMIN_TENANT_TABLES:
        assert table in ORG_SCOPED_TABLES, table
        assert TENANT_COLUMNS[table] == "org_id", table


def test_the_generated_policy_uses_each_tables_own_tenant_column():
    sql = build_rls_sql(app_role="pqc_app")
    for table in ORG_SCOPED_TABLES:
        column = tenant_column(table)
        assert f'CREATE POLICY "{table}_org_isolation" ON "{table}"' in sql, table
        # The predicate for this table must compare the setting with this table's column.
        block = sql.split(f"-- {table}\n", 1)[1].split("END $$;", 1)[0]
        assert f'"{column}" = current_setting' in block, (table, column)
        assert f"AND column_name = '{column}'" in block, (table, column)


def test_the_audit_looks_for_every_tenant_column_spelling():
    """The fix that stops the next table hiding the same way.

    A table with a tenant column under any known spelling, in no policy and in no exception list,
    has to come back as uncovered. Before this, the audit asked only for organization_id, so a
    table spelling it org_id was reported as covered while being readable across tenants.
    """
    assert set(TENANT_COLUMN_NAMES) >= {"organization_id", "org_id"}
    rows = [_table_row(t) for t in ORG_SCOPED_TABLES]
    state = evaluate_rls_state(
        rows, SAFE_ROLE, ORG_SCOPED_TABLES,
        org_scoped_in_db=list(ORG_SCOPED_TABLES) + ["a_new_tenant_table"],
        policy_rows=_healthy_policies(),
    )
    assert state["uncovered_tables"] == ["a_new_tenant_table"]
    assert state["status"] == "fail"


def test_the_registry_tables_are_named_exceptions_with_no_policy():
    """`organizations` and `admin_orgs` key the tenant on `id` and hold no tenant's data.

    Neither can carry a per-row policy. They are excluded by name, with the reason recorded in
    services/postgres_rls.py, rather than by the audit failing to notice them.
    """
    assert TENANT_REGISTRY_TABLES == ["organizations", "admin_orgs"]
    for table in TENANT_REGISTRY_TABLES:
        assert table not in ORG_SCOPED_TABLES
        assert f'ON "{table}"' not in build_rls_sql(app_role="pqc_app")
    state = evaluate_rls_state(
        [_table_row(t) for t in ORG_SCOPED_TABLES], SAFE_ROLE, ORG_SCOPED_TABLES,
        org_scoped_in_db=list(ORG_SCOPED_TABLES) + list(TENANT_REGISTRY_TABLES),
        policy_rows=_healthy_policies(),
    )
    assert state["uncovered_tables"] == []
    assert state["status"] == "pass"


def test_the_published_plan_reports_the_tenant_column_of_every_table():
    plan = build_rls_plan(app_role="pqc_app")
    assert plan["tenant_columns"]["admin_users"] == "org_id"
    assert plan["tenant_columns"]["assets"] == "organization_id"
    assert plan["tenant_registry_tables"] == TENANT_REGISTRY_TABLES
    assert set(plan["tenant_column_names"]) == set(TENANT_COLUMN_NAMES)
