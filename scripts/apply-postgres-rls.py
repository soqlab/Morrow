#!/usr/bin/env python
"""Apply (or preview) the Postgres row-level-security plan that isolates tenants.

    python scripts/apply-postgres-rls.py                      # print the SQL, change nothing
    python scripts/apply-postgres-rls.py --apply              # run it, then verify
    python scripts/apply-postgres-rls.py --verify-only        # report the live state and exit
    python scripts/apply-postgres-rls.py --create-role --apply  # also create the app role

Dry run is the default and has to be turned off explicitly. This script runs DDL against a
production database; the failure mode of a mistyped DSN is a locked-out application, so the safe
action is the one you get by accident.

Two DSNs are involved and they are not interchangeable:

    --dsn         the *owner / migration* role. Only this role can ALTER TABLE ... ENABLE ROW LEVEL
                  SECURITY and CREATE POLICY. Defaults to MORROW_RLS_MIGRATION_DSN, then
                  MORROW_PRODUCT_DATABASE_URL, then DATABASE_URL.
    --app-role    the *runtime* role the application connects as. It must be NOSUPERUSER
                  NOBYPASSRLS: Postgres exempts superusers and BYPASSRLS roles from every policy, so
                  applying this plan over such a role protects nothing while looking like it worked.
                  The generated SQL refuses to run in that case rather than appear to succeed.

Applying is idempotent. Re-run it after any migration that adds a tenant table; the verify step at
the end is what tells you whether the new table was picked up.

Tenant column names. Most tables spell the tenant `organization_id`; the four admin-console tables
(`admin_users`, `admin_invitations`, `admin_audit_log`, `admin_rate_limits`) spell it `org_id`. Both
are covered: the per-table column lives in backend/services/postgres_rls.TENANT_COLUMNS and the
generated policy uses it. The verifier looks for either spelling when it hunts for tenant tables the
plan has missed, so a new table cannot escape the audit by choosing a different name -- which is
exactly how those four escaped it before.

Two registry tables have no tenant column at all and are deliberately outside the plan:
`organizations` and `admin_orgs`. They are the list of customers, not any customer's data, and the
application reads them across tenants on purpose. Both are named in
postgres_rls.TENANT_REGISTRY_TABLES with the reason recorded there.

Nothing here prints a password: DSNs are redacted in all output.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def redact(dsn: str) -> str:
    """postgresql://user:secret@host/db -> postgresql://user:***@host/db."""
    return re.sub(r"://([^:/@]+):([^@]*)@", r"://\1:***@", str(dsn or ""))


def resolve_dsn(explicit: str) -> str:
    for candidate in (
        explicit,
        os.getenv("MORROW_RLS_MIGRATION_DSN"),
        os.getenv("MORROW_PRODUCT_DATABASE_URL"),
        os.getenv("DATABASE_URL"),
    ):
        if str(candidate or "").strip():
            return str(candidate).strip()
    return ""


def create_role_sql(app_role: str, password_env: str) -> str:
    """SQL that creates the runtime role with the attributes that make the policies real.

    NOSUPERUSER NOBYPASSRLS is the whole point; LOGIN is what makes it usable as a connection role.
    The password comes from the environment so it is never an argument in shell history or `ps`.
    """
    from services.postgres_rls import quote_ident

    password = os.getenv(password_env, "")
    if not password:
        raise SystemExit(
            f"--create-role needs the new role's password in ${password_env} "
            "(never pass it as an argument)."
        )
    role = quote_ident(app_role)
    literal = "'" + password.replace("'", "''") + "'"
    return (
        "DO $$\nBEGIN\n"
        f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{app_role}') THEN\n"
        f"    EXECUTE 'CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE "
        f"PASSWORD ' || quote_literal({literal});\n"
        "  ELSE\n"
        f"    EXECUTE 'ALTER ROLE {role} NOSUPERUSER NOBYPASSRLS';\n"
        "  END IF;\n"
        "END $$;\n"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dsn", default="", help="owner/migration DSN (see module docstring)")
    parser.add_argument("--app-role", default=os.getenv("MORROW_APP_DB_ROLE", "morrow_app"),
                        help="runtime role the policies are written for (default: morrow_app)")
    parser.add_argument("--apply", action="store_true",
                        help="actually execute the statements; without it nothing is changed")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="explicit no-op form of the default behaviour")
    parser.add_argument("--verify-only", action="store_true", help="report the live state and exit")
    parser.add_argument("--create-role", action="store_true",
                        help="also create/repair the runtime role (password from $MORROW_APP_DB_PASSWORD)")
    parser.add_argument("--password-env", default="MORROW_APP_DB_PASSWORD",
                        help="environment variable holding the role password for --create-role")
    parser.add_argument("--verify-dsn", default="",
                        help="DSN to verify with; defaults to --dsn. Point it at the *app* role to "
                             "check the runtime's own view, which is the one that matters.")
    args = parser.parse_args(argv)

    from services.postgres_rls import build_rls_sql

    dsn = resolve_dsn(args.dsn)
    if not dsn:
        print("No DSN. Pass --dsn or set MORROW_RLS_MIGRATION_DSN / MORROW_PRODUCT_DATABASE_URL / DATABASE_URL.",
              file=sys.stderr)
        return 2
    verify_dsn = str(args.verify_dsn or "").strip() or dsn

    if args.verify_only:
        return report(verify(verify_dsn), verify_dsn)

    sql = build_rls_sql(app_role=args.app_role)
    if args.create_role:
        sql = create_role_sql(args.app_role, args.password_env) + "\n" + sql

    if not args.apply:
        print(f"-- DRY RUN. Target: {redact(dsn)}")
        print(f"-- Runtime role: {args.app_role}")
        print("-- Nothing has been changed. Re-run with --apply to execute the following.\n")
        print(sql)
        return 0

    import psycopg2

    print(f"Applying RLS plan to {redact(dsn)} for role {args.app_role} ...")
    conn = psycopg2.connect(dsn)
    # One transaction: the plan must not be able to land half-applied, because a table left with
    # FORCE ROW LEVEL SECURITY and no policy returns zero rows to the application.
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                for notice in conn.notices[-200:]:
                    print("  " + notice.rstrip())
    except Exception as exc:
        print(f"FAILED, nothing applied: {exc}", file=sys.stderr)
        return 3
    finally:
        conn.close()
    print("Applied.\n")
    return report(verify(verify_dsn), verify_dsn)


def verify(dsn: str) -> dict:
    """Verification must never mask the apply step's result with a stack trace.

    The commonest reason it cannot connect is a --verify-dsn whose password does not match the role,
    which says nothing about whether the plan applied. Report it as what it is.
    """
    from services.rls_verify import verify_postgres_rls

    try:
        return verify_postgres_rls(dsn)
    except Exception as exc:
        return {"status": "unknown", "failures": [f"could not connect to verify: {exc.__class__.__name__}"]}


def report(result: dict, dsn: str) -> int:
    print(f"Verification against {redact(dsn)}: {result.get('status')}")
    role = result.get("role") or {}
    if role:
        print(f"  role={role.get('role_name')} superuser={role.get('rolsuper')} bypassrls={role.get('rolbypassrls')}")
    print(f"  tables checked: {result.get('tables_checked')}")
    for failure in result.get("failures") or []:
        print(f"  FAIL: {failure}")
    if result.get("status") == "pass":
        print("  Every org-scoped table has RLS + FORCE and a tenant policy, and the connected role "
              "cannot bypass it.")
        return 0
    if not result.get("role_ok", True):
        print("\nNote: verifying with the owner/migration role always reports the role check as "
              "failing, because that role is a superuser. Re-run with --verify-dsn pointing at the "
              "application role to see what the runtime actually sees.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
