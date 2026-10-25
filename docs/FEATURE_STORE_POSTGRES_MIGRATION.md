# Auxiliary feature state: SQLite → Postgres

## Why this exists

The core tables (assets, scans, scan_results, remediations, organizations,
audit_logs, …) already have a Postgres implementation in `backend/db_postgres.py`.
Everything else does not. At the time of writing `/platform/state/coverage`
reports **66 auxiliary tables** still on SQLite, spread across **32 service
modules** holding roughly **965 raw SQL statements**.

That is not merely untidy. SQLite is not a network database, so while those
tables carry state the platform is limited to **one API replica** — the readiness
check pins `MORROW_API_REPLICA_COUNT=1` and `/platform/go-live-gate` surfaces it.
One replica means no horizontal scale, no HA, and no zero-downtime deploy.

For `admin_orgs`, `admin_users` and `admin_invitations` it is worse than a scale
ceiling: those hold the built-in accounts, so two replicas against a local file
would disagree about who is allowed in. That slice was migrated first for exactly
that reason.

## Why not the `db_postgres.py` pattern

`db_postgres.py` hand-writes one function per operation (`pg_upsert_asset`,
`pg_list_assets`, …). Repeating that for 965 statements is neither reviewable nor
safe, and it doubles every future change.

The statements themselves are almost entirely portable. What is not portable is
the **dialect**: parameter markers, a few DDL spellings, SQLite's upsert
shorthands, and SQLite's date functions. So `backend/db_feature_store.py`
presents the slice of the `sqlite3.Connection` API these modules actually use,
backed by either engine, and translates at the boundary.

A module migrates by changing **where it gets its connection**, not its SQL. That
is what keeps each module's diff reviewable.

## Switching backends

`MORROW_FEATURE_STORE_BACKEND` — `postgres` | `sqlite`. Unset, it follows the core
database (`postgres_main_db_requested()`). It is a separate switch on purpose:
the core tables can be on Postgres while auxiliary state is migrated module by
module, and an operator needs to move one without the other.

## The recipe

For each module, in one commit per module:

1. **Swap the connection.**
   ```python
   # before
   from contextlib import closing
   import sqlite3
   with closing(sqlite3.connect(_get_db_path())) as conn:

   # after
   from db_feature_store import feature_conn
   with feature_conn() as conn:
   ```
   Delete the module's now-dead `_get_db_path()`. Leave the SQL alone.

2. **Drop `conn.row_factory = sqlite3.Row`.** `feature_conn()` sets it for
   SQLite, and the Postgres shim always yields rows addressable by name *and*
   position, so `row["email"]` and `row[0]` both keep working.

3. **Replace `except sqlite3.IntegrityError`** with `except INTEGRITY_ERRORS`.
   The two drivers' classes share no base, so the original clause silently stops
   catching anything the moment the module moves — turning a handled duplicate
   into a 500.

4. **Wrap any statement that is *expected* to be able to fail a constraint** in
   `with atomic(conn):`. This is the one place the engines genuinely differ:
   SQLite lets a connection carry on after a failed statement; Postgres marks the
   whole transaction aborted, so every subsequent statement fails with
   `InFailedSqlTransaction` until rollback. `atomic()` is a SAVEPOINT on Postgres
   and a no-op on SQLite.

   ```python
   try:
       with atomic(conn):
           conn.execute(insert_sql, params)
   except INTEGRITY_ERRORS:
       conn.execute(update_sql, params)
   ```

5. **Add a dual-backend test**, parametrised over both engines, asserting the
   same flow produces the same result. Copy
   `backend/test_admin_console_dual_backend.py`. This is not optional: step 4's
   bug passes on SQLite and fails only on Postgres, so a single-backend test
   proves nothing.

## What the shim translates

| SQLite | Postgres | Notes |
|---|---|---|
| `?` | `%s` | Skips string literals — a `?` inside a LIKE pattern is data |
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` | |
| `DATETIME` / `BLOB` / `REAL` | `TIMESTAMPTZ` / `BYTEA` / `DOUBLE PRECISION` | `DATETIME` only as a type, never the `datetime()` function |
| `IFNULL(` | `COALESCE(` | |
| `INSERT OR IGNORE` | `… ON CONFLICT DO NOTHING` | |
| `INSERT OR REPLACE` | `… ON CONFLICT (pk) DO UPDATE SET …` | Conflict target read from the live catalog |
| `datetime('now')`, `datetime('now','-7 days')` | `now()`, `(now() - interval '7 days')` | |
| `strftime('%Y-%m-%d'/'%Y-%m'/'%s', x)` | `to_char(...)` / `extract(epoch …)` | |
| `cursor.lastrowid` | `SELECT lastval()` | Session-scoped, so it cannot pick up another writer's id |

Anything unrecognised **passes through unchanged**, so an unsupported construct
surfaces as a loud Postgres syntax error during that module's migration rather
than as silently wrong data.

## Verifying

```bash
docker run -d --name morrow-pg -e POSTGRES_PASSWORD=morrowdev -e POSTGRES_DB=morrow \
    -p 5433:5432 postgres:16-alpine

cd backend
MORROW_TEST_PG_DSN=postgresql://postgres:morrowdev@127.0.0.1:5433/morrow \
    python -m pytest test_db_feature_store.py test_admin_console_dual_backend.py -q
```

Without `MORROW_TEST_PG_DSN` the Postgres halves skip and only the SQLite paths and
the pure translation tests run. CI sets it (`.github/workflows/ci.yml`, pointed at
the workflow's existing `postgres:16` service), so those tests run there. **Keep
it set** — unset, CI goes green on precisely the bugs these tests exist to catch,
because every one of them passes on SQLite.

## Status

| | |
|---|---|
| Migrated | `services/admin_console.py` — `admin_orgs`, `admin_users`, `admin_invitations`, `admin_audit_log`, `admin_rate_limits` |
| Remaining | 26 service modules / ~61 tables |

Order the rest by blast radius, not by size: anything that gates access or holds
evidence first (`dev_portal`, `github_oauth`, `canary`, `qtisn`), reporting and
cache-like tables last.

`MORROW_API_REPLICA_COUNT` must stay at 1 until `/platform/state/coverage` reports
no auxiliary tables holding rows.
