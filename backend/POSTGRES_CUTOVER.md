# Postgres Cutover Groundwork

This repo still defaults the main product state to SQLite in `backend/db.py`.

The Postgres cutover now has two layers:

- a Postgres schema bootstrap + SQLite -> Postgres migration utility in `backend/db_postgres.py`
- a runtime switch in `backend/db.py` for the first migrated surface behind `MORROW_MAIN_DB_BACKEND=postgres`

## Current scope

Covered tables:

- `organizations`
- `repositories`
- `assets`
- `asset_tags`
- `baselines`
- `scans`
- `scan_results`
- `remediations`
- `audit_logs`
- `github_installations`
- `webhooks`
- `webhook_events`
- `collections`
- `schedules`
- `integrations_settings`
- `event_rules`
- `event_rule_fires`

Runtime-switched behind `MORROW_MAIN_DB_BACKEND=postgres`:

- `organizations`
- `repositories`
- `assets`
- `asset_tags`
- `baselines`
- `scans`
- `scan_results`
- `github_installations`
- `remediations`
- `audit_logs`
- `webhooks`
- `webhook_events`
- `collections`
- `schedules`
- `integrations_settings`
- `event_rules`
- `event_rule_fires`

The remaining work is no longer table coverage. It is runtime cleanup:

- removing SQLite bootstrap assumptions from startup paths like `init_db()`
- flipping the default runtime away from `MORROW_SCANNER_DB`
- validating the full app/worker/beat stack end-to-end against Cloud SQL with `MORROW_MAIN_DB_BACKEND=postgres`

## Environment

The migration utility uses:

- `MORROW_SCANNER_DB` for the source SQLite path unless `--sqlite-path` is passed
- `MORROW_PRODUCT_DATABASE_URL` or `DATABASE_URL` for the target Postgres DSN unless `--dsn` is passed

The runtime switch is now active for the migrated surface:

```powershell
$env:MORROW_MAIN_DB_BACKEND = 'postgres'
$env:MORROW_PRODUCT_DATABASE_URL = 'postgresql://user:pass@host:5432/morrow'
```

## Bootstrap the Postgres schema

You can call the schema helper directly from Python:

```powershell
cd C:\Users\Samsung\Desktop\morrow\backend
.\.venv\Scripts\python.exe -c "from db_postgres import ensure_postgres_core_schema; ensure_postgres_core_schema()"
```

## Copy the core SQLite data into Postgres

```powershell
cd C:\Users\Samsung\Desktop\morrow\backend
$env:MORROW_SCANNER_DB = 'C:\path\to\morrow.db'
$env:MORROW_PRODUCT_DATABASE_URL = 'postgresql://user:pass@host:5432/morrow'
.\.venv\Scripts\python.exe .\migrate_main_db_to_postgres.py
```

Optional flags:

```powershell
.\.venv\Scripts\python.exe .\migrate_main_db_to_postgres.py `
  --sqlite-path C:\path\to\morrow.db `
  --dsn postgresql://user:pass@host:5432/morrow `
  --batch-size 1000
```

The script prints per-table copy counts as JSON.

## Why this is not the final cutover

The remaining runtime query layer in `backend/db.py` still assumes SQLite behavior:

- `sqlite3.Row`
- `PRAGMA table_info`
- `INSERT OR REPLACE`
- `BEGIN IMMEDIATE`
- `lastrowid`

Those assumptions still exist in the unported surfaces and must be removed before API/worker/beat can run fully on Postgres.
