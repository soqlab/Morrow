from __future__ import annotations

from typing import Any, Dict, List


# Org-scoped tables that live in Postgres (every one carries an organization_id column).
# Keep this in sync with the Postgres schema in db_postgres.py: a tenant table missing from this
# list gets no isolation policy, which is the failure mode that matters. services/rls_verify.py
# cross-checks the live schema and reports any org-scoped table that is not covered here.
ORG_SCOPED_TABLES: List[str] = [
    # Core product tables (db_postgres.py schema).
    "assets",
    "asset_tags",
    "baselines",
    "collections",
    "credentials",
    "scan_results",
    "scans",
    "schedules",
    "repositories",
    "github_installations",
    "github_pr_events",
    "github_status_publishes",
    "remediations",
    "migration_tasks",
    "validation_jobs",
    "audit_logs",
    "external_findings",
    "flight_recorder_events",
    "organization_memberships",
    "webhooks",
    "webhook_events",
    "event_rules",
    "event_rule_fires",
    "runtime_traffic_observations",
    "gateway_sites",
    "gateway_history",
    "ai_privacy_policy",
    "ai_privacy_events",
    "ai_privacy_jobs",
    # Feature-store tables (db_feature_store.py). Each of these carries a per-customer
    # organization_id and was previously isolated by query filters alone. Column names were checked
    # against a live schema build rather than assumed: every one of them spells it organization_id.
    "feedback",
    "platform_api_keys",
    "platform_support_access",
    "platform_support_requests",
    "platform_support_sessions",
    "platform_usage_daily",
    "platform_active_users_daily",
    "platform_traffic_events",
    "platform_feature_state_records",
    # Admin-console tables (services/admin_console.py). These spell the tenant `org_id`, not
    # `organization_id`, which is why they were outside the plan AND invisible to the coverage
    # audit: the audit looked for one column name. They hold the tenant's user list, its pending
    # invitations and its administrative audit trail -- the tables the cross-tenant takeover in the
    # September 2026 review wrote to. See TENANT_COLUMNS below.
    "admin_users",
    "admin_invitations",
    "admin_audit_log",
    "admin_rate_limits",
    # Verified domains (services/domain_verification.py): which hosts a tenant may scan.
    "org_verified_domains",
]

#: The column that carries the tenant, per table. Anything absent here uses ``organization_id``.
#:
#: Two spellings exist in this schema and both are real, so the plan, the generated policy and the
#: coverage audit all have to know about both. A table whose tenant column is spelled some third
#: way must be added here, or it gets no policy -- and rls_verify.TENANT_COLUMN_NAMES must learn
#: the name too, or it will not even be reported as uncovered.
TENANT_COLUMNS: Dict[str, str] = {
    "admin_users": "org_id",
    "admin_invitations": "org_id",
    "admin_audit_log": "org_id",
    "admin_rate_limits": "org_id",
    "org_verified_domains": "org_id",
}

#: Every column name that means "this row belongs to that tenant".
TENANT_COLUMN_NAMES: List[str] = ["organization_id", "org_id"]


def tenant_column(table: str) -> str:
    """The tenant column for a table: the exception, or the default spelling."""
    return TENANT_COLUMNS.get(str(table), "organization_id")

# Org-scoped tables that are still SQLite-backed and therefore never exist in Postgres. They were
# previously listed as RLS targets, which made the generated script abort partway through (the
# statements were unguarded) and made services/rls_verify.py permanently report them as missing.
SQLITE_ONLY_ORG_TABLES: List[str] = [
    "vendor_attestation_invites",
    "vendor_attestation_submissions",
]

# Tables that carry an organization_id but are deliberately cross-tenant: they back the /platform/*
# endpoints, which exist so the operator of the platform can see every customer, and are gated by
# x-platform-key rather than by a user role. Applying org-isolation policies here would break
# platform administration.
#
# Each entry is a record of the operator's own activity or of the platform's view of a customer --
# never the customer's data. A customer request has no route to any of them: they are read and
# written only from /platform/* and /vendor-admin handlers and from the journal writer.
#
# This list is deliberate rather than incidental: services/rls_verify.py reports any org-scoped
# table it finds that is neither an RLS target nor named here, so a genuinely forgotten tenant table
# still shows up as a failure instead of hiding among these.
PLATFORM_SCOPED_TABLES: List[str] = [
    "platform_admin_events",     # what an operator did, keyed by the customer they did it to
    "platform_customer_notes",   # the vendor's CRM notes about a customer
    "platform_feature_flags",    # vendor-set entitlement overrides
    "platform_autopatches",      # vendor-initiated remediation campaigns
    "platform_auth_events",      # the security journal's auth trail, read by the operator console
    "platform_request_events",   # the security journal's request trail, input to the usage rollups
]

# The tenant registry. `organizations` keys the tenant on `id`, not `organization_id`, so it is
# invisible to the column audit that finds every other tenant table -- which is exactly why it is
# named here rather than left to be noticed.
#
# It is deliberately NOT under an isolation policy. It is the list of tenants, not any tenant's data:
# a row holds an id, a display name, a plan and a subscription status. Several paths that run inside
# an ordinary customer request read it across tenants on purpose -- most importantly the suspension
# cache (app._customer_request_blocked_for_suspension), which refreshes a process-wide snapshot of
# every organization's status. Under a per-tenant policy that snapshot would be built from whichever
# tenant happened to trigger the refresh, and suspension would stop being enforced for everyone else.
#
# The exposure this leaves is the tenant roster (names and plans), reachable only through endpoints
# that already require an authenticated session and that filter to the caller's memberships. It is
# recorded here so the decision is reviewable rather than accidental.
#
# `admin_orgs` (services/admin_console.py) is the same kind of table and is here for the same
# reason: it keys the tenant on `id` and has no tenant column at all, so no per-row policy can be
# written for it. Its rows are the registry entry for a customer -- id, display name, domain, plan,
# status and the two usage ceilings -- not that customer's data. The application reads it across
# tenants on purpose (services/invite_links.organization_name resolves the org name for an invitee
# who is not yet a member of it, from a request that has no tenant of its own), and the routes that
# serve it are now scoped in the application: GET /admin/orgs returns only the caller's own row, and
# every /admin/orgs/{org_id}/… route refuses an organization the caller is not acting for.
#
# What this leaves exposed, if the application layer were bypassed, is the customer roster. That is
# the same residual exposure as `organizations`, recorded here for the same reason: so it is a
# decision on the record rather than a table nobody looked at.
TENANT_REGISTRY_TABLES: List[str] = ["organizations", "admin_orgs"]

ORG_SETTING = "app.current_organization_id"

#: Session setting that opens the audited, cross-tenant escape hatch. See services/tenant_scope.py:
#: it is 'on' only inside an explicitly privileged code path (an authenticated vendor-operator
#: request, or a background writer that spans tenants by design) and is cleared when that path ends.
#: Putting the exemption in the policy text -- rather than granting the application role BYPASSRLS --
#: keeps it visible in `\d+ <table>`, countable, and switchable per statement.
PLATFORM_SETTING = "app.platform_scope"

#: The only value of PLATFORM_SETTING that opens the escape hatch.
PLATFORM_ON = "on"


def quote_ident(identifier: str) -> str:
    value = str(identifier or "").strip()
    if not value.replace("_", "").isalnum() or not value:
        raise ValueError(f"unsafe identifier: {identifier!r}")
    return f'"{value}"'


def _lit(value: str) -> str:
    """Quote a string as a Postgres literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _nested(sql: str) -> str:
    """Quote a statement for use inside EXECUTE within a DO block."""
    return _lit(sql)


def build_rls_sql(*, app_role: str = "morrow_app", tables: List[str] | None = None) -> str:
    """Generate Postgres row-level-security SQL for org-scoped SaaS tables.

    Three properties matter more than brevity here:

    1. The policy is created BEFORE ROW LEVEL SECURITY is enabled and forced. The reverse order
       leaves a window -- and, if CREATE POLICY fails, a permanent state -- where the table has
       FORCE RLS and no policy, so every query against it returns zero rows.
    2. Each table is guarded on existence and on having an organization_id column, so a schema
       that is missing an optional table produces a NOTICE instead of aborting the script and
       leaving the remaining tables unprotected.
    3. The policy has exactly two branches: the tenant match, and the audited platform escape hatch
       (PLATFORM_SETTING). An unset or empty tenant matches nothing at all -- note the NULLIF, which
       is what stops a connection with no tenant resolved from reading the rows whose
       organization_id is itself the empty string (the anonymous-traffic bucket).

    Re-running this script is safe: every policy is dropped and recreated, and ENABLE/FORCE are
    no-ops when already set. That is what makes it usable as a migration rather than a one-shot.

    The application publishes both settings via services/tenant_scope.apply_to_connection, called on
    every connection checkout (db_postgres._PooledConn and db_feature_store.feature_conn) and cleared
    on release. Service/admin roles can still be granted BYPASSRLS outside this generated plan -- but
    the *application* role must not be, or the policies are inert.
    """
    role = quote_ident(app_role)
    selected_tables = list(tables or ORG_SCOPED_TABLES)
    setting = _lit(ORG_SETTING)
    platform_setting = _lit(PLATFORM_SETTING)
    statements: List[str] = [
        "-- Morrow multi-tenant RLS plan",
        f"-- The application sets this per connection: SELECT set_config({setting}, '<org-id>', false);",
        f"-- and opens the audited cross-tenant path with set_config({platform_setting}, 'on', false).",
        "-- Policies are created before RLS is enabled so no table is ever forced without a policy.",
        "-- Idempotent: policies are dropped and recreated, ENABLE/FORCE are no-ops when already set.",
        "",
        "-- Fail fast if the application role is missing or can bypass RLS, before altering anything.",
        "DO $$",
        "BEGIN",
        f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {_lit(app_role)}) THEN",
        f"    RAISE EXCEPTION 'application role %s does not exist; create it before applying RLS', {_lit(app_role)};",
        "  END IF;",
        f"  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {_lit(app_role)} AND (rolsuper OR rolbypassrls)) THEN",
        f"    RAISE EXCEPTION 'application role %s is SUPERUSER or has BYPASSRLS; RLS policies would be inert', {_lit(app_role)};",
        "  END IF;",
        "END $$;",
        "",
        "-- Baseline privileges. RLS restricts what a role may see; it never grants access, so a role",
        "-- created purely for the runtime has no rights at all until these run. Re-running is a no-op.",
        f"GRANT USAGE ON SCHEMA public TO {role};",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role};",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role};",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role};",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role};",
        "",
    ]

    for table in selected_tables:
        tbl = quote_ident(table)
        policy = quote_ident(f"{table}_org_isolation")
        # Not every tenant table spells the column organization_id; see TENANT_COLUMNS.
        column = tenant_column(table)
        col = quote_ident(column)
        predicate = (
            "("
            f"current_setting({platform_setting}, true) = {_lit(PLATFORM_ON)}"
            f" OR (NULLIF(current_setting({setting}, true), '') IS NOT NULL"
            f" AND {col} = current_setting({setting}, true))"
            ")"
        )
        create_policy = (
            f"CREATE POLICY {policy} ON {tbl} FOR ALL TO {role} "
            f"USING {predicate} WITH CHECK {predicate}"
        )
        statements.extend(
            [
                f"-- {table}",
                "DO $$",
                "BEGIN",
                f"  IF to_regclass({_lit('public.' + table)}) IS NULL THEN",
                f"    RAISE NOTICE 'skipping %: table not present in this schema', {_lit(table)};",
                "  ELSIF NOT EXISTS (",
                "      SELECT 1 FROM information_schema.columns",
                "      WHERE table_schema = 'public'",
                f"        AND table_name = {_lit(table)}",
                f"        AND column_name = {_lit(column)}",
                "  ) THEN",
                f"    RAISE NOTICE 'skipping %: no % column', {_lit(table)}, {_lit(column)};",
                "  ELSE",
                f"    EXECUTE {_nested(f'DROP POLICY IF EXISTS {policy} ON {tbl}')};",
                f"    EXECUTE {_nested(create_policy)};",
                f"    EXECUTE {_nested(f'ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY')};",
                f"    EXECUTE {_nested(f'ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY')};",
                "  END IF;",
                "END $$;",
                "",
            ]
        )
    return "\n".join(statements) + "\n"


def build_rls_plan(*, app_role: str = "morrow_app") -> Dict[str, Any]:
    sql = build_rls_sql(app_role=app_role)
    return {
        # "ready" means the generated SQL is safe to run and the application cooperates with it:
        # db_postgres._PooledConn sets the org setting on every borrowed connection. It does NOT
        # mean RLS is currently active -- call /admin/postgres-rls/verify (services/rls_verify.py)
        # for the live state.
        "status": "ready",
        "app_role": app_role,
        "org_setting": ORG_SETTING,
        "platform_setting": PLATFORM_SETTING,
        "app_sets_org_setting": True,
        "tables": ORG_SCOPED_TABLES,
        "tenant_columns": {t: tenant_column(t) for t in ORG_SCOPED_TABLES},
        "tenant_column_names": TENANT_COLUMN_NAMES,
        "platform_scoped_tables": PLATFORM_SCOPED_TABLES,
        "tenant_registry_tables": TENANT_REGISTRY_TABLES,
        "sqlite_only_tables": SQLITE_ONLY_ORG_TABLES,
        "sql": sql,
        "apply_with": "python scripts/apply-postgres-rls.py --apply   (default is --dry-run)",
        # The rule, in one place, so it can be quoted verbatim in the runbook and in review.
        "operator_access_rule": (
            "Cross-tenant reads are allowed only while "
            f"{PLATFORM_SETTING} = '{PLATFORM_ON}'. Exactly three things may turn it on: (1) a "
            "/platform/* or /vendor-admin request that has already authenticated against the "
            "platform credential or an operator SSO session, set by app._require_platform_admin "
            "after the credential is validated and never before; (2) a named background writer that "
            "spans tenants by design -- the security-journal flusher, the usage rollups, and the "
            "alert dispatcher; (3) API-key verification, which must find the key row before any "
            "tenant is known. Every entry is recorded by services/tenant_scope (INFO log line plus a "
            "bounded in-process ledger, and the durable operator audit trail for case 1). The "
            "application role stays NOSUPERUSER NOBYPASSRLS, so this flag is the only way across the "
            "boundary and its use is countable."
        ),
        "operator_steps": [
            "Create a dedicated application role (this plan assumes "
            f"'{app_role}') that is NOT a superuser and does NOT have BYPASSRLS. Postgres exempts "
            "both from row-level security, so policies applied over such a role are silently inert. "
            "Grant it only CONNECT, USAGE on schema public, and DML on the org-scoped tables. "
            "Managed-Postgres default users are frequently superusers -- check before assuming.",
            "Point MORROW_PRODUCT_DATABASE_URL / DATABASE_URL at that role, not the owner/migration role.",
            "Run this SQL with a Postgres owner/migration role -- `python scripts/apply-postgres-rls.py "
            "--apply` does it and re-verifies afterwards; without --apply it only prints. It aborts "
            "up front if the application role is missing or can bypass RLS, and skips tables that "
            "are absent from the schema with a NOTICE rather than leaving later tables unprotected. "
            "It is idempotent, so re-run it after every schema migration that adds a tenant table.",
            f"The application sets {ORG_SETTING} on every pooled connection and clears it on release, "
            "so no operator action is needed for that; the policies read it via current_setting(..., true).",
            f"{PLATFORM_SETTING} is the audited cross-tenant escape hatch. Do not set it by hand and "
            "do not grant the application role BYPASSRLS as a shortcut: see operator_access_rule.",
            "Run tenant-isolation regression tests after enabling FORCE ROW LEVEL SECURITY, and "
            "confirm same-tenant reads still return data -- an unset org setting makes every "
            "policy match nothing, which looks like an empty product rather than an error.",
            "Verify the live state with services/rls_verify.py (or GET /admin/postgres-rls/verify), "
            "which reports uncovered org-scoped tables as well as missing RLS.",
        ],
    }
