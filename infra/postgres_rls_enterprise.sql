-- GENERATED FILE. Do not edit by hand: it is regenerated from the table list in
-- backend/services/postgres_rls.py, which is what the application, the verifier and the tests all
-- read. A hand-edit here would silently disagree with every one of them.
--
-- Regenerate:  python -c "import sys; sys.path.insert(0, 'backend'); from services.postgres_rls
--              import build_rls_sql; print(build_rls_sql(app_role='morrow_app'))"
-- Apply:       python scripts/apply-postgres-rls.py --dsn <owner-dsn> --apply --verify-dsn <app-dsn>
--
-- Prefer the script over running this file: it generates the same SQL from the current table list,
-- runs it in one transaction, and verifies the result through the runtime role afterwards.
-- See "4a. Row-level security" in docs/PRODUCTION_DEPLOYMENT_RUNBOOK.md.

-- Morrow multi-tenant RLS plan
-- The application sets this per connection: SELECT set_config('app.current_organization_id', '<org-id>', false);
-- and opens the audited cross-tenant path with set_config('app.platform_scope', 'on', false).
-- Policies are created before RLS is enabled so no table is ever forced without a policy.
-- Idempotent: policies are dropped and recreated, ENABLE/FORCE are no-ops when already set.

-- Fail fast if the application role is missing or can bypass RLS, before altering anything.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'morrow_app') THEN
    RAISE EXCEPTION 'application role %s does not exist; create it before applying RLS', 'morrow_app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'morrow_app' AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'application role %s is SUPERUSER or has BYPASSRLS; RLS policies would be inert', 'morrow_app';
  END IF;
END $$;

-- Baseline privileges. RLS restricts what a role may see; it never grants access, so a role
-- created purely for the runtime has no rights at all until these run. Re-running is a no-op.
GRANT USAGE ON SCHEMA public TO "morrow_app";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "morrow_app";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "morrow_app";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "morrow_app";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "morrow_app";

-- assets
DO $$
BEGIN
  IF to_regclass('public.assets') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'assets';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'assets'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'assets', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "assets_org_isolation" ON "assets"';
    EXECUTE 'CREATE POLICY "assets_org_isolation" ON "assets" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "assets" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "assets" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- asset_tags
DO $$
BEGIN
  IF to_regclass('public.asset_tags') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'asset_tags';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'asset_tags'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'asset_tags', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "asset_tags_org_isolation" ON "asset_tags"';
    EXECUTE 'CREATE POLICY "asset_tags_org_isolation" ON "asset_tags" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "asset_tags" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "asset_tags" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- baselines
DO $$
BEGIN
  IF to_regclass('public.baselines') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'baselines';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'baselines'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'baselines', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "baselines_org_isolation" ON "baselines"';
    EXECUTE 'CREATE POLICY "baselines_org_isolation" ON "baselines" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "baselines" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "baselines" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- collections
DO $$
BEGIN
  IF to_regclass('public.collections') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'collections';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'collections'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'collections', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "collections_org_isolation" ON "collections"';
    EXECUTE 'CREATE POLICY "collections_org_isolation" ON "collections" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "collections" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "collections" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- credentials
DO $$
BEGIN
  IF to_regclass('public.credentials') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'credentials';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'credentials'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'credentials', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "credentials_org_isolation" ON "credentials"';
    EXECUTE 'CREATE POLICY "credentials_org_isolation" ON "credentials" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "credentials" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "credentials" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- scan_results
DO $$
BEGIN
  IF to_regclass('public.scan_results') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'scan_results';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'scan_results'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'scan_results', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "scan_results_org_isolation" ON "scan_results"';
    EXECUTE 'CREATE POLICY "scan_results_org_isolation" ON "scan_results" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "scan_results" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "scan_results" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- scans
DO $$
BEGIN
  IF to_regclass('public.scans') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'scans';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'scans'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'scans', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "scans_org_isolation" ON "scans"';
    EXECUTE 'CREATE POLICY "scans_org_isolation" ON "scans" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "scans" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "scans" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- schedules
DO $$
BEGIN
  IF to_regclass('public.schedules') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'schedules';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'schedules'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'schedules', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "schedules_org_isolation" ON "schedules"';
    EXECUTE 'CREATE POLICY "schedules_org_isolation" ON "schedules" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "schedules" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "schedules" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- repositories
DO $$
BEGIN
  IF to_regclass('public.repositories') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'repositories';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'repositories'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'repositories', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "repositories_org_isolation" ON "repositories"';
    EXECUTE 'CREATE POLICY "repositories_org_isolation" ON "repositories" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "repositories" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "repositories" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- github_installations
DO $$
BEGIN
  IF to_regclass('public.github_installations') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'github_installations';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'github_installations'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'github_installations', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "github_installations_org_isolation" ON "github_installations"';
    EXECUTE 'CREATE POLICY "github_installations_org_isolation" ON "github_installations" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "github_installations" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "github_installations" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- github_pr_events
DO $$
BEGIN
  IF to_regclass('public.github_pr_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'github_pr_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'github_pr_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'github_pr_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "github_pr_events_org_isolation" ON "github_pr_events"';
    EXECUTE 'CREATE POLICY "github_pr_events_org_isolation" ON "github_pr_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "github_pr_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "github_pr_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- github_status_publishes
DO $$
BEGIN
  IF to_regclass('public.github_status_publishes') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'github_status_publishes';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'github_status_publishes'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'github_status_publishes', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "github_status_publishes_org_isolation" ON "github_status_publishes"';
    EXECUTE 'CREATE POLICY "github_status_publishes_org_isolation" ON "github_status_publishes" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "github_status_publishes" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "github_status_publishes" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- remediations
DO $$
BEGIN
  IF to_regclass('public.remediations') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'remediations';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'remediations'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'remediations', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "remediations_org_isolation" ON "remediations"';
    EXECUTE 'CREATE POLICY "remediations_org_isolation" ON "remediations" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "remediations" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "remediations" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- migration_tasks
DO $$
BEGIN
  IF to_regclass('public.migration_tasks') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'migration_tasks';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'migration_tasks'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'migration_tasks', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "migration_tasks_org_isolation" ON "migration_tasks"';
    EXECUTE 'CREATE POLICY "migration_tasks_org_isolation" ON "migration_tasks" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "migration_tasks" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "migration_tasks" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- validation_jobs
DO $$
BEGIN
  IF to_regclass('public.validation_jobs') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'validation_jobs';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'validation_jobs'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'validation_jobs', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "validation_jobs_org_isolation" ON "validation_jobs"';
    EXECUTE 'CREATE POLICY "validation_jobs_org_isolation" ON "validation_jobs" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "validation_jobs" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "validation_jobs" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- audit_logs
DO $$
BEGIN
  IF to_regclass('public.audit_logs') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'audit_logs';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'audit_logs'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'audit_logs', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "audit_logs_org_isolation" ON "audit_logs"';
    EXECUTE 'CREATE POLICY "audit_logs_org_isolation" ON "audit_logs" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "audit_logs" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "audit_logs" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- external_findings
DO $$
BEGIN
  IF to_regclass('public.external_findings') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'external_findings';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'external_findings'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'external_findings', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "external_findings_org_isolation" ON "external_findings"';
    EXECUTE 'CREATE POLICY "external_findings_org_isolation" ON "external_findings" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "external_findings" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "external_findings" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- flight_recorder_events
DO $$
BEGIN
  IF to_regclass('public.flight_recorder_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'flight_recorder_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'flight_recorder_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'flight_recorder_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "flight_recorder_events_org_isolation" ON "flight_recorder_events"';
    EXECUTE 'CREATE POLICY "flight_recorder_events_org_isolation" ON "flight_recorder_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "flight_recorder_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "flight_recorder_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- organization_memberships
DO $$
BEGIN
  IF to_regclass('public.organization_memberships') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'organization_memberships';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'organization_memberships'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'organization_memberships', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "organization_memberships_org_isolation" ON "organization_memberships"';
    EXECUTE 'CREATE POLICY "organization_memberships_org_isolation" ON "organization_memberships" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "organization_memberships" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "organization_memberships" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- webhooks
DO $$
BEGIN
  IF to_regclass('public.webhooks') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'webhooks';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'webhooks'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'webhooks', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "webhooks_org_isolation" ON "webhooks"';
    EXECUTE 'CREATE POLICY "webhooks_org_isolation" ON "webhooks" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "webhooks" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "webhooks" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- webhook_events
DO $$
BEGIN
  IF to_regclass('public.webhook_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'webhook_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'webhook_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'webhook_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "webhook_events_org_isolation" ON "webhook_events"';
    EXECUTE 'CREATE POLICY "webhook_events_org_isolation" ON "webhook_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "webhook_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "webhook_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- event_rules
DO $$
BEGIN
  IF to_regclass('public.event_rules') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'event_rules';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'event_rules'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'event_rules', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "event_rules_org_isolation" ON "event_rules"';
    EXECUTE 'CREATE POLICY "event_rules_org_isolation" ON "event_rules" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "event_rules" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "event_rules" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- event_rule_fires
DO $$
BEGIN
  IF to_regclass('public.event_rule_fires') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'event_rule_fires';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'event_rule_fires'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'event_rule_fires', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "event_rule_fires_org_isolation" ON "event_rule_fires"';
    EXECUTE 'CREATE POLICY "event_rule_fires_org_isolation" ON "event_rule_fires" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "event_rule_fires" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "event_rule_fires" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- runtime_traffic_observations
DO $$
BEGIN
  IF to_regclass('public.runtime_traffic_observations') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'runtime_traffic_observations';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'runtime_traffic_observations'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'runtime_traffic_observations', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "runtime_traffic_observations_org_isolation" ON "runtime_traffic_observations"';
    EXECUTE 'CREATE POLICY "runtime_traffic_observations_org_isolation" ON "runtime_traffic_observations" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "runtime_traffic_observations" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "runtime_traffic_observations" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- gateway_sites
DO $$
BEGIN
  IF to_regclass('public.gateway_sites') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'gateway_sites';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'gateway_sites'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'gateway_sites', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "gateway_sites_org_isolation" ON "gateway_sites"';
    EXECUTE 'CREATE POLICY "gateway_sites_org_isolation" ON "gateway_sites" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "gateway_sites" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "gateway_sites" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- gateway_history
DO $$
BEGIN
  IF to_regclass('public.gateway_history') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'gateway_history';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'gateway_history'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'gateway_history', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "gateway_history_org_isolation" ON "gateway_history"';
    EXECUTE 'CREATE POLICY "gateway_history_org_isolation" ON "gateway_history" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "gateway_history" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "gateway_history" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- feedback
DO $$
BEGIN
  IF to_regclass('public.feedback') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'feedback';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'feedback'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'feedback', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "feedback_org_isolation" ON "feedback"';
    EXECUTE 'CREATE POLICY "feedback_org_isolation" ON "feedback" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "feedback" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "feedback" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- billing_customers
DO $$
BEGIN
  IF to_regclass('public.billing_customers') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'billing_customers';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'billing_customers'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'billing_customers', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "billing_customers_org_isolation" ON "billing_customers"';
    EXECUTE 'CREATE POLICY "billing_customers_org_isolation" ON "billing_customers" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "billing_customers" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "billing_customers" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- billing_subscriptions
DO $$
BEGIN
  IF to_regclass('public.billing_subscriptions') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'billing_subscriptions';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'billing_subscriptions'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'billing_subscriptions', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "billing_subscriptions_org_isolation" ON "billing_subscriptions"';
    EXECUTE 'CREATE POLICY "billing_subscriptions_org_isolation" ON "billing_subscriptions" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "billing_subscriptions" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "billing_subscriptions" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- billing_invoices
DO $$
BEGIN
  IF to_regclass('public.billing_invoices') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'billing_invoices';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'billing_invoices'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'billing_invoices', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "billing_invoices_org_isolation" ON "billing_invoices"';
    EXECUTE 'CREATE POLICY "billing_invoices_org_isolation" ON "billing_invoices" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "billing_invoices" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "billing_invoices" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- billing_events
DO $$
BEGIN
  IF to_regclass('public.billing_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'billing_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'billing_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'billing_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "billing_events_org_isolation" ON "billing_events"';
    EXECUTE 'CREATE POLICY "billing_events_org_isolation" ON "billing_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "billing_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "billing_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- billing_mrr_events
DO $$
BEGIN
  IF to_regclass('public.billing_mrr_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'billing_mrr_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'billing_mrr_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'billing_mrr_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "billing_mrr_events_org_isolation" ON "billing_mrr_events"';
    EXECUTE 'CREATE POLICY "billing_mrr_events_org_isolation" ON "billing_mrr_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "billing_mrr_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "billing_mrr_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_api_keys
DO $$
BEGIN
  IF to_regclass('public.platform_api_keys') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_api_keys';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_api_keys'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_api_keys', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_api_keys_org_isolation" ON "platform_api_keys"';
    EXECUTE 'CREATE POLICY "platform_api_keys_org_isolation" ON "platform_api_keys" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_api_keys" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_api_keys" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_support_access
DO $$
BEGIN
  IF to_regclass('public.platform_support_access') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_support_access';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_support_access'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_support_access', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_support_access_org_isolation" ON "platform_support_access"';
    EXECUTE 'CREATE POLICY "platform_support_access_org_isolation" ON "platform_support_access" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_support_access" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_support_access" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_support_requests
DO $$
BEGIN
  IF to_regclass('public.platform_support_requests') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_support_requests';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_support_requests'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_support_requests', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_support_requests_org_isolation" ON "platform_support_requests"';
    EXECUTE 'CREATE POLICY "platform_support_requests_org_isolation" ON "platform_support_requests" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_support_requests" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_support_requests" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_support_sessions
DO $$
BEGIN
  IF to_regclass('public.platform_support_sessions') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_support_sessions';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_support_sessions'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_support_sessions', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_support_sessions_org_isolation" ON "platform_support_sessions"';
    EXECUTE 'CREATE POLICY "platform_support_sessions_org_isolation" ON "platform_support_sessions" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_support_sessions" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_support_sessions" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_usage_daily
DO $$
BEGIN
  IF to_regclass('public.platform_usage_daily') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_usage_daily';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_usage_daily'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_usage_daily', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_usage_daily_org_isolation" ON "platform_usage_daily"';
    EXECUTE 'CREATE POLICY "platform_usage_daily_org_isolation" ON "platform_usage_daily" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_usage_daily" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_usage_daily" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_active_users_daily
DO $$
BEGIN
  IF to_regclass('public.platform_active_users_daily') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_active_users_daily';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_active_users_daily'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_active_users_daily', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_active_users_daily_org_isolation" ON "platform_active_users_daily"';
    EXECUTE 'CREATE POLICY "platform_active_users_daily_org_isolation" ON "platform_active_users_daily" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_active_users_daily" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_active_users_daily" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_traffic_events
DO $$
BEGIN
  IF to_regclass('public.platform_traffic_events') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_traffic_events';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_traffic_events'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_traffic_events', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_traffic_events_org_isolation" ON "platform_traffic_events"';
    EXECUTE 'CREATE POLICY "platform_traffic_events_org_isolation" ON "platform_traffic_events" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_traffic_events" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_traffic_events" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- platform_feature_state_records
DO $$
BEGIN
  IF to_regclass('public.platform_feature_state_records') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'platform_feature_state_records';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'platform_feature_state_records'
        AND column_name = 'organization_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'platform_feature_state_records', 'organization_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "platform_feature_state_records_org_isolation" ON "platform_feature_state_records"';
    EXECUTE 'CREATE POLICY "platform_feature_state_records_org_isolation" ON "platform_feature_state_records" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "organization_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "platform_feature_state_records" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "platform_feature_state_records" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- admin_users
DO $$
BEGIN
  IF to_regclass('public.admin_users') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'admin_users';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'admin_users'
        AND column_name = 'org_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'admin_users', 'org_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "admin_users_org_isolation" ON "admin_users"';
    EXECUTE 'CREATE POLICY "admin_users_org_isolation" ON "admin_users" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "admin_users" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "admin_users" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- admin_invitations
DO $$
BEGIN
  IF to_regclass('public.admin_invitations') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'admin_invitations';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'admin_invitations'
        AND column_name = 'org_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'admin_invitations', 'org_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "admin_invitations_org_isolation" ON "admin_invitations"';
    EXECUTE 'CREATE POLICY "admin_invitations_org_isolation" ON "admin_invitations" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "admin_invitations" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "admin_invitations" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- admin_audit_log
DO $$
BEGIN
  IF to_regclass('public.admin_audit_log') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'admin_audit_log';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'admin_audit_log'
        AND column_name = 'org_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'admin_audit_log', 'org_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "admin_audit_log_org_isolation" ON "admin_audit_log"';
    EXECUTE 'CREATE POLICY "admin_audit_log_org_isolation" ON "admin_audit_log" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "admin_audit_log" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "admin_audit_log" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

-- admin_rate_limits
DO $$
BEGIN
  IF to_regclass('public.admin_rate_limits') IS NULL THEN
    RAISE NOTICE 'skipping %: table not present in this schema', 'admin_rate_limits';
  ELSIF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'admin_rate_limits'
        AND column_name = 'org_id'
  ) THEN
    RAISE NOTICE 'skipping %: no % column', 'admin_rate_limits', 'org_id';
  ELSE
    EXECUTE 'DROP POLICY IF EXISTS "admin_rate_limits_org_isolation" ON "admin_rate_limits"';
    EXECUTE 'CREATE POLICY "admin_rate_limits_org_isolation" ON "admin_rate_limits" FOR ALL TO "morrow_app" USING (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true))) WITH CHECK (current_setting(''app.platform_scope'', true) = ''on'' OR (NULLIF(current_setting(''app.current_organization_id'', true), '''') IS NOT NULL AND "org_id" = current_setting(''app.current_organization_id'', true)))';
    EXECUTE 'ALTER TABLE "admin_rate_limits" ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE "admin_rate_limits" FORCE ROW LEVEL SECURITY';
  END IF;
END $$;

