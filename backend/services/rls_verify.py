from __future__ import annotations

import json
import os
from contextlib import closing
from typing import Any, Dict, Iterable, List, Mapping

import psycopg2
from psycopg2.extras import RealDictCursor

from services.postgres_rls import (
    ORG_SCOPED_TABLES,
    ORG_SETTING,
    PLATFORM_SCOPED_TABLES,
    TENANT_COLUMN_NAMES,
    TENANT_REGISTRY_TABLES,
    tenant_column,
)


def evaluate_rls_state(
    table_rows: Iterable[Mapping[str, Any]],
    role_row: Mapping[str, Any] | None,
    expected_tables: Iterable[str] = ORG_SCOPED_TABLES,
    org_scoped_in_db: Iterable[str] | None = None,
    policy_rows: Iterable[Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Evaluate Postgres RLS/FORCE status, policy coverage, and app-role safety.

    `org_scoped_in_db` is the set of tables the live schema shows carrying a tenant column -- any of
    postgres_rls.TENANT_COLUMN_NAMES, not just `organization_id`. Comparing it against
    `expected_tables` catches the coverage gap that matters: a tenant table that exists in Postgres
    but appears in no policy, and so is readable across tenants even after the operator has run
    every documented step.

    Looking for one column name was itself the gap. The four admin-console tables spell the tenant
    `org_id`, so they were missing from the plan AND reported as fully covered -- the audit was
    blind in exactly the place the application bug lived. Adding a spelling here is the only thing
    that has to happen for a new tenant table to be *noticed*; covering it still means adding it to
    ORG_SCOPED_TABLES.
    """
    seen = {
        str(row.get("relname") or ""): {
            "rls_enabled": bool(row.get("relrowsecurity")),
            "force_rls": bool(row.get("relforcerowsecurity")),
        }
        for row in table_rows
    }
    expected = [str(t) for t in expected_tables]
    with_policy = {str(row.get("tablename") or "") for row in (policy_rows or [])}
    # A policy whose predicate does not read the tenant setting is not an isolation policy. The
    # commonest way to end up with one is a hand-written `USING (true)` added to unbreak a query --
    # it satisfies every other check here while isolating nothing, so the presence of a policy is
    # not on its own evidence that the boundary exists.
    inert_policy = sorted(
        {
            str(row.get("tablename") or "")
            for row in (policy_rows or [])
            if row.get("qual") is not None
            and (ORG_SETTING not in str(row.get("qual") or "")
                 # …and it must compare the tenant setting against THIS table's tenant column. A
                 # policy that reads the setting but matches it to some other column isolates
                 # nothing either.
                 or tenant_column(str(row.get("tablename") or "")) not in str(row.get("qual") or ""))
        }
        & set(expected)
    )
    missing_tables = [table for table in expected if table not in seen]
    missing_rls = [
        table
        for table in expected
        if table in seen and not (seen[table]["rls_enabled"] and seen[table]["force_rls"])
    ]
    # RLS enabled with no policy is worse than no RLS: the table returns zero rows to the app. That
    # only applies where RLS is actually on -- on a database where it was never enabled, having no
    # policy is the expected state, and reporting "these tables return no rows" there is both wrong
    # and alarming, sending an operator after a problem that does not exist. missing_rls already
    # covers the not-yet-enabled case.
    missing_policy = [
        table for table in expected
        if table in seen
        and seen[table]["rls_enabled"]
        and policy_rows is not None
        and table not in with_policy
    ]
    # Platform-admin tables carry a tenant column but are cross-tenant by design, and the two
    # registry tables key the tenant on `id` and hold no tenant's data, so both sets are excluded
    # here rather than counted as gaps. They stay in explicit lists in services/postgres_rls.py so
    # that a tenant table someone genuinely forgot still surfaces as a failure.
    uncovered_tables = sorted(
        set(str(t) for t in (org_scoped_in_db or []))
        - set(expected)
        - set(PLATFORM_SCOPED_TABLES)
        - set(TENANT_REGISTRY_TABLES)
    )
    role_ok = bool(role_row) and not bool(role_row.get("rolsuper")) and not bool(role_row.get("rolbypassrls"))
    failures: List[str] = []
    if missing_tables:
        failures.append(f"missing tables: {', '.join(missing_tables[:10])}")
    if missing_rls:
        failures.append(f"missing RLS/FORCE: {', '.join(missing_rls[:10])}")
    if missing_policy:
        failures.append(
            "RLS enabled with no isolation policy (these tables return no rows): "
            f"{', '.join(missing_policy[:10])}"
        )
    if uncovered_tables:
        failures.append(
            "org-scoped tables not covered by the RLS plan: "
            f"{', '.join(uncovered_tables[:10])}"
        )
    if inert_policy:
        failures.append(
            f"policies that never read {ORG_SETTING}, so they isolate nothing: "
            f"{', '.join(inert_policy[:10])}"
        )
    if not role_ok:
        failures.append("current DB role is superuser or has BYPASSRLS, so RLS policies are inert")
    return {
        "status": "pass" if not failures else "fail",
        "missing_tables": missing_tables,
        "missing_rls": missing_rls,
        "missing_policy": missing_policy,
        "inert_policy": inert_policy,
        "uncovered_tables": uncovered_tables,
        "role_ok": role_ok,
        "role": dict(role_row or {}),
        "tables_checked": len(expected),
        "failures": failures,
    }


def verify_postgres_rls(dsn: str, expected_tables: Iterable[str] = ORG_SCOPED_TABLES) -> Dict[str, Any]:
    if not str(dsn or "").strip():
        return {"status": "fail", "failures": ["DATABASE_URL/PQC_PRODUCT_DATABASE_URL is not set"]}
    expected = [str(t) for t in expected_tables]
    # closing(), not just `with conn`: psycopg2's connection context manager commits or rolls back
    # the transaction and leaves the connection OPEN. This function is called from the health path
    # and from the startup posture check, so leaving the socket behind each time slowly consumed the
    # server's connection slots until new connections started timing out -- a check for a security
    # property taking the database down with it.
    with closing(psycopg2.connect(dsn, connect_timeout=5)) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT relname, relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = ANY(%s)
                """,
                (expected,),
            )
            table_rows = cur.fetchall()
            cur.execute(
                """
                SELECT DISTINCT c.table_name AS tablename
                FROM information_schema.columns c
                JOIN pg_tables t ON t.schemaname = 'public' AND t.tablename = c.table_name
                WHERE c.table_schema = 'public' AND c.column_name = ANY(%s)
                """,
                (list(TENANT_COLUMN_NAMES),),
            )
            org_scoped_in_db = [str(r.get("tablename") or "") for r in cur.fetchall()]
            # `qual` is the USING expression as Postgres re-rendered it, which is how a policy that
            # was replaced by hand with something permissive is caught.
            cur.execute(
                "SELECT tablename, qual FROM pg_policies WHERE schemaname = 'public' AND tablename = ANY(%s)",
                (expected,),
            )
            policy_rows = cur.fetchall()
            cur.execute("SELECT current_user AS role_name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            role_row = cur.fetchone()
    return evaluate_rls_state(
        table_rows,
        role_row,
        expected,
        org_scoped_in_db=org_scoped_in_db,
        policy_rows=policy_rows,
    )


def main() -> int:
    dsn = os.getenv("PQC_PRODUCT_DATABASE_URL") or os.getenv("DATABASE_URL") or ""
    result = verify_postgres_rls(dsn)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
