# Backup And Restore Runbook

## Scope

Covers product Postgres data, the cluster-level roles the application connects as, the SQLite file
that still holds a number of features, Redis transient queues, and secret recovery expectations.

A Morrow deployment is **four** things, and restoring one of them is not a restore:

| Artefact | What it holds | Taken with |
| --- | --- | --- |
| Product Postgres database | assets, scans, scan_results, remediations, organizations, audit_logs, invitations, operator MFA enrolments — and the tenant-isolation policies | `pg_dump --format=custom` |
| Cluster globals | the runtime role (`pqc_app`) the GRANTs in that dump refer to | `pg_dumpall --globals-only` |
| SQLite state file (`PQC_SCANNER_DB`, `/data/pqc_scanner.db` in the container) | TLS observatory, canaries, QTISN, maturity model, regulatory filings, autopilot, ZK proofs, **built-in password accounts** | `VACUUM INTO` (see `scripts/backup-restore-drill.ps1`) |
| Secrets | `PQC_VAULT_MASTER_KEY`, `PQC_AUTH_JWT_SECRET`, `PQC_EVIDENCE_SIGNING_KEY`, `PQC_USAGE_ACTOR_SALT` | Secret Manager |

Restoring the database without the vault master key leaves every sealed value — scanner
credentials, operator MFA secrets and recovery codes, alert channel targets, gateway site secrets —
permanently unreadable. Restoring it without the SQLite file signs every built-in password account
out of existence.

## Backup Policy

- Use managed Postgres automated backups and keep point-in-time recovery per the customer contract.
- Take `pg_dumpall --globals-only` on the same schedule. It is small, and without it a restore into a
  new cluster fails on the first `GRANT ... TO pqc_app`.
- Back up the SQLite state file while the API is running with `VACUUM INTO`, never with a file copy:
  a plain copy of a live SQLite database can capture a torn page or miss the `-wal` file.
- Redis is transient queue/cache data; do not treat it as system of record.
- Store Secret Manager secrets with restricted IAM and rotation history.

## Automated Drill

`scripts/backup-restore-drill.ps1` performs the whole thing unattended and is the check the go-live
gate's "backup and restore drill completed" criterion refers to:

```powershell
# Owner/migration DSN: the drill creates and drops a scratch database, so it needs CREATEDB.
.\scripts\backup-restore-drill.ps1 -Dsn $OWNER_DSN
.\scripts\backup-restore-drill.ps1 -Dsn $OWNER_DSN -SkipSqlite   # Postgres only
```

It dumps, restores into a scratch database, and compares **tables, isolation policies, FORCE flags
and the runtime role's table grants** before dropping the scratch database again. It does not take
`pg_dumpall --globals-only`; do that alongside it.

It does not replace the manual drill below, which is the only thing that proves the *application*
comes back.

## Restore Drill

Run before production launch, after major schema changes, and after any migration that adds a tenant
table. Time every step and record the numbers.

### 1. Record what "correct" looks like, before touching anything

```powershell
docker exec <pg> psql -U <owner> -d <db> -c "
SELECT 'assets' t, count(*) n FROM assets
UNION ALL SELECT 'scans', count(*) FROM scans
UNION ALL SELECT 'scan_results', count(*) FROM scan_results
UNION ALL SELECT 'organizations', count(*) FROM organizations
UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs
UNION ALL SELECT 'rls_policies', count(*) FROM pg_policies WHERE schemaname='public'
UNION ALL SELECT 'rls_forced', count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='public' AND c.relforcerowsecurity
ORDER BY 1;" > rowcounts-before.txt
```

### 2. Back up

```powershell
pg_dump --format=custom --file=pqc.dump $OWNER_DSN
pg_dumpall --globals-only --file=globals.sql $OWNER_ADMIN_DSN
```

Do **not** pass `--no-privileges`. It strips every GRANT, and the result restores into a database
that has all its tables, all its policies and none of the access the application needs: the first
query answers `permission denied for table assets`. Row counts and table counts are identical, so
nothing short of connecting as the runtime role notices.

### 3. Restore into a fresh target

```powershell
psql -d postgres -f globals.sql          # first, on a new cluster: creates pqc_app
psql -d postgres -c "CREATE DATABASE pqc_restored;"
pg_restore --no-owner --exit-on-error -d pqc_restored pqc.dump
```

`--exit-on-error` is not optional. Without it `pg_restore` reports a successful restore after
skipping every statement that failed, including the GRANTs.

Restore the SQLite state file to the path `PQC_SCANNER_DB` points at (the `/data` volume in
`docker-compose.prod.yml`) in the same window.

### 4. Point the application at it and start api, worker and beat

Set `DATABASE_URL` and `PQC_PRODUCT_DATABASE_URL` to the restored database, as the **runtime**
role, not the owner.

### 5. Verify — in this order, because each step can pass while the next one fails

| Check | How | What a failure means |
| --- | --- | --- |
| Row counts match | re-run step 1 against the restored database and `diff` | data loss in the dump |
| Policies, FORCE and grants match | same query; `rls_policies` and `rls_forced` must equal the source | the tenant boundary did not survive |
| App boots | `/healthz`, then `/health/deep` (postgres, redis, celery, disk all `ok`) | wrong DSN, missing role, missing grants |
| Sign-in works | `POST /auth/login`, or an IdP token | SQLite state was not restored, or the JWT secret changed |
| Customer data is intact | `GET /assets`, `GET /assets/<key>/history`, `GET /scans/<id>/results` | partial restore |
| Isolation still holds | `GET /admin/postgres-rls/verify` must be `pass` with `role_ok: true`; `POST /platform/tenant-isolation/verify` must be `pass` | **the step most restores get wrong** |
| Isolation holds in the database, not just the API | connect as the runtime role and run `SELECT count(*) FROM assets` with no `app.current_organization_id` set: it must return **0** | policies exist but are inert (superuser/BYPASSRLS role) |
| Operator console | `/platform/customers`, Customer 360 counts | cross-tenant read path |

If the restore target is a **new cluster**, `pqc_app`'s password comes from `globals.sql`. If you
recreate the role by hand instead, it must again be `NOSUPERUSER NOBYPASSRLS` (see
`docs/PRODUCTION_DEPLOYMENT_RUNBOOK.md` section 4a) — a restore is the easiest place to accidentally
hand the application a superuser and lose every policy silently.

### 6. Record restore duration and issues

## Emergency Restore

1. Freeze writes if data corruption is suspected (maintenance mode).
2. Snapshot current database state for forensics.
3. Restore to a new database instance, following the drill above including the globals.
4. Validate integrity and tenant isolation with the table in step 5 before any traffic.
5. Shift runtime `DATABASE_URL`/`PQC_PRODUCT_DATABASE_URL` to the restored instance.
6. Keep the old instance read-only until incident review is complete.

## Evidence To Keep

- Backup schedule configuration, including the globals dump.
- Last successful restore drill timestamp.
- Restore duration, per step.
- Operator who performed the drill.
- Validation notes: the before/after row counts and the isolation verification output.
