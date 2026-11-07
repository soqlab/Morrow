# How Morrow behaves at 10,000 and 100,000 assets

Until this test the only load script was `scripts/load-smoke.ps1`: 50 requests to three health
endpoints. `backend/test_load_regressions.py` recorded limits found by a sustained-traffic test
(connection pool, N+1 on `/hndl/dashboard`, the reporting read), but nothing had measured the
console against a large inventory. This page records the method, the numbers before and after the
fixes on branch `scale-test`, and what is still slow.

## Method

`scripts/scale/` holds the harness. Nothing in it writes rows by hand except one documented
back-dating step.

| Script | What it does |
|---|---|
| `seed.py` | Seeds the default organization with N assets through `backend/db.py`, the same helpers the app uses. A scan is saved the way `POST /scans/synthetic` saves one (`save_scan_row`, then `save_scan_results`, then `save_scan_asset_summaries`). Inventory context goes through `upsert_asset`, the `PUT /assets/{key}` path. Remediations go through `create_remediation` and migration tasks through `create_migration_task`. Scan facts and findings come from the platform's own policy pipeline (`services.demo_estate.build_facts`, which calls `policy.evaluate_policies`). Remediation lifecycle stamps are back-dated with one `UPDATE`, as `demo/seed-demo-data.py` does. `--postgres DSN` seeds Postgres. `--start/--stop` writes one slice of the estate. |
| `seed-100k.ps1` | Writes 100,000 assets as five 20,000-asset runs of about 6 minutes each. Together they are identical to one full run. |
| `bench.py` | Drives the real FastAPI app in-process (`TestClient`, full middleware stack, header auth as an admin). It calls every endpoint the console's main views load. The list comes from `backend/static/index.html`: `VIEWS.overview`, inventory, scans/findings, CBOM, HNDL, remediation, board, and the `/search` box. |
| `profile_endpoint.py` | Runs `cProfile` on one endpoint and counts its SQLite statements. An N+1 shows up as a statement count that grows with the inventory. |

### Realistic ratios (per asset, the `seed.py` defaults)

- 2 scans of every asset, 14 days apart, at 100 endpoints per scan. That gives 200 scans and 20,000 endpoint results at 10k, and 2,000 scans and 200,000 results at 100k.
- About 2.6 findings per endpoint result, produced by the policy pipeline (52,036 findings at 10k).
- 1 remediation per 10 assets, spread across suggested, approved, pr_created, merged, verified_closed and rejected.
- 1 migration task per 30 assets.
- 1 repository per 100 assets.
- 1–3 tags per asset from a vocabulary of 24.

The SQLite database is 163 MB at 10k and 1.55 GB at 100k. Most of that is the per-scan
`results_json` blob, about 400 KB for a 100-endpoint scan.

### What is measured

For each endpoint, `bench.py` records:

- **Cold call:** the first call, with in-process caches empty. It runs under `tracemalloc` to get the
  **peak** Python heap of that call. Tracing slows Python down, so this call's latency is kept out of p50/p95. SQLite's
  page cache is C memory and is not included in the peak.
- **p50/p95:** taken over the following untraced calls. An endpoint stops being sampled at `--samples` calls or after
  `--budget` seconds, whichever comes first. With only 2–5 samples, p95 is close to the maximum.
- **Response size and status.** All endpoints answered 200 in every run.

### Machine

The machine is a Windows 11 laptop with an Intel i5-1135G7 (4 cores, 8 threads), 7.7 GB of RAM and an NVMe SSD. It runs Python
3.14 from the test venv; production runs 3.11. Postgres 16 ran in Docker on the same laptop
(`postgres:16-alpine`, `shared_buffers=256MB`, `synchronous_commit=off` to speed up seeding; reads are
unaffected). The laptop was shared with other work during every run, so treat single numbers as
±30% and compare orders of magnitude, not percentages. The before/after gaps below are 10× to 1000×.

### Reproduce

```powershell
cd backend
$py = "..\..\morrow-archive\backend\.venv\Scripts\python.exe"   # any venv with requirements.txt
& $py ..\scripts\scale\seed.py --assets 10000 --db $env:TEMP\scale-10k.db              # ~10 min
& $py ..\scripts\scale\bench.py --db $env:TEMP\scale-10k.db --out ..\scripts\scale\results\mine.json
powershell -File ..\scripts\scale\seed-100k.ps1 -Database $env:TEMP\scale-100k.db -Python $py  # ~30 min
& $py ..\scripts\scale\bench.py --db $env:TEMP\scale-100k.db --samples 4 --budget 15 --out ...
# Postgres:
docker run -d --name morrow-scale-pg -e POSTGRES_PASSWORD=scale -e POSTGRES_USER=scale -e POSTGRES_DB=scale -p 127.0.0.1:55432:5432 postgres:16-alpine
& $py ..\scripts\scale\seed.py --assets 10000 --postgres postgresql://scale:scale@127.0.0.1:55432/scale
& $py ..\scripts\scale\bench.py --postgres postgresql://scale:scale@127.0.0.1:55432/scale --out ...
```

The bench writes into the database it measures (audit log, security journal). Bench a copy of the
seeded file if you want to compare runs. The raw JSON for every run below is in
`scripts/scale/results/`.

## Results

All times are p50 in milliseconds over warm calls. Peak memory is in MB for the cold call. **Before** means
`origin/main` at `55900e9`; **after** means this branch. The 100k "intermediate" column has the first
two commits applied (the `/scans`, `/assets` and `/search` fixes). The original code needed 69 s for a single
`list_scan_rows(limit=1)` at 100k (0.8 s after), so a full "before" run at 100k was not feasible
within the time limit for one run.

| Endpoint | SQLite 10k before | SQLite 10k after | Peak MB 10k (before / after) | Postgres 10k † | SQLite 100k (intermediate / after) | Peak MB 100k |
|---|---:|---:|---|---:|---|---:|
| /executive-dashboard | 2,838 | 1,099 | 20 / 11 | 2,384 | 23,479 / 660 | 11 |
| /qday/countdown | 2,464 | 760 | 11 / 11 | 2,642 | 24,777 / 1,797 | 57 |
| /board-risk/weather | 4,240 | 2,626 | 11 / 11 | 1,799 | 24,049 / 903 | 11 |
| /telemetry/kpis | 11,948 | 11,592 | 1 / 1 | 335 | 244,791 / 13,958 | 8 |
| /crypto-agility | 11,624 | 1,454 | 18 / 19 | 29,372 | 88,623 / 1,262 | 19 |
| /migration-velocity | 11,913 | 1,362 | 13 / 13 | 30,700 | 46,022 / 1,484 | 14 |
| /hndl/dashboard | 2,722 | 605 | 5 / 5 | 891 | 1,667 / 370 | 5 |
| /board-risk | 2,665 | 827 | 11 / 11 | 1,222 | 25,190 / 738 | 11 |
| /compliance-mapping | 12,133 | 1,761 | 5 / 5 | 1,739 | 25,566 / 1,703 | 5 |
| /assets (inventory) | 6,841 | 1,484 | 7 / 7 | 1,306 | 2,102 / 696 | 7 |
| /governance/certificates | 111,110 | 3,914–18,261 ‡ | 95 / 95 | 11,269 | 102,922 / 11,750 | 95 |
| /blast-radius/graph | 59,657 | 6,432 | 37 / 37 | 5,662 | 4,946 / 3,433 | 37 |
| /scans?limit=25 | 14,280 | 260 | 0 / 0 | 240 | 220 / 270 | 0 |
| /scans/{id}/results (findings) | 648 | 182 | 3 / 3 | 6,990 | 1,364 / 583 | 3 |
| /fix-next (findings) | 10,089 | 117 | 3 / 3 | 11,007 | 949 / 631 | 3 |
| /heatmap | 1,980 | 180 | 1 / 1 | 1,678 | 21,163 / 191 | 1 |
| /cbom | 5,789 | 3,282 | 12 / 12 | 3,181 | 36,450 / 1,934 | 12 |
| /cbom.csv | 3,316 | 1,761 | 11 / 12 | 2,324 | 138,884 / 1,356 | 11 |
| /hndl/timeline | 13,151 | 1,305 | 5 / 5 | 1,380 | 2,792 / 2,107 | 5 |
| /dark-matter/map | 14,950 | 4,258 | 52 / 52 | 10,048 | 4,564 / 3,207 | 52 |
| /remediations | 515 | 224 | 1 / 1 | 9,727 | 578 / 220 | 1 |
| /remediation-feed | 1,941 | 1,265 | 2 / 2 | 11,662 | 3,363 / 1,332 | 2 |
| /migration-tasks | 275 | 133 | 1 / 1 | 218 | 532 / 264 | 1 |
| /board-risk/leaderboard | 2,820 | 1,079 | 11 / 11 | 682 | 38,789 / 1,199 | 11 |
| /board-risk/regulatory | 4,751 | 1,046 | 11 / 11 | 2,235 | 148,562 / 916 | 11 |
| /search?q=svc00012 (rare term) | 3,580 | 773 | 11 / 0 | 1,306 | 33,686 / 7,870 | 1 |
| /search?q=rsa (common term) | 8,209 | 136 | 11 / 1 | 1,570 | 49,522 / 299 | 0 |

Cheap endpoints are omitted from the table: tags, collections, repositories, baselines, canaries, sbom imports and q-intel stay under 300 ms
at every size. All per-endpoint data, including cold and p95, is in `scripts/scale/results/*.json`.

- † Postgres was measured with the first three commits applied, before the last fix commit (`4bedaa5`). That commit batches the
  repository lookup in `pg_list_remediations` and the per-result enrichment. Those Postgres-only N+1s
  were why crypto-agility, migration-velocity, /remediations, /scans/{id}/results and /fix-next were slow
  there (one pooled round trip per row through Docker Desktop on Windows). A rerun after that commit
  (`postgres-10k-after-noisy.json`) coincided with heavy load from other work on the laptop, and every
  endpoint in it is slower, cheap ones included. It is kept but not quoted. The Postgres numbers after
  `4bedaa5` therefore still need a quiet rerun.
- ‡ This endpoint moved between 3.9 s and 18 s across reruns on the same database. Its cost is
  dominated by reading and parsing the 100 newest scans' JSON, so it depends on the OS file cache.

## What was wrong, and what changed

1. **Picking the newest scan read every result blob the tenant had stored.** `list_scan_rows`
   sorted all scans with `summary_json` selected. SQLite stores that column after `results_json`
   (about 400 KB per scan), so the sort walked the overflow pages of every scan: 34 s for `LIMIT 1`
   at 10k, 69 s at 100k. Every view starts with this call: `/scans`, `/fix-next`, the telemetry KPIs,
   `/blast-radius/graph`, `/dark-matter/map` and the certificate report. The sort now selects only
   rowids (`db._NEWEST_SCAN_ROWIDS_SQL`).
2. **The newest row per asset ranked the whole history.** Every report (executive dashboard, board
   risk, heatmap, CBOM, crypto agility, velocity, compliance) used a `ROW_NUMBER()` window over all
   `scan_results` before `LIMIT`. That took 30 s per report at 100k. It is now a newest-first walk of the new
   `idx_scan_results_org_scanned` index with a `NOT EXISTS` check on
   `idx_scan_results_org_asset_scanned`, which stops at the limit (0.3 s, and returns identical rows).
3. **`list_assets` was an N+1.** It ran a tags query and a repository query per row, and the repository lookup
   re-ran the repositories DDL each time: about 25,000 statements for one 5,000-asset page. It is now one
   SELECT. `GET /assets` gains a stable keyset cursor: `?cursor=` takes the `next_cursor` from the previous
   page, ordered by `(updated_at, asset_key)` and backed by `idx_assets_org_updated`. `items` is unchanged, so the console
   needed no change and `backend/static/index.html` is untouched. `_ensure_sprint11_tables` is
   memoized, which also speeds up `PUT /assets` and the CSV import (seeding went from 40 to 9 ms per asset).
4. **`/search` filtered the newest 5,000 assets in Python.** At 10k it could not find most of the
   estate. The term is now matched in SQL on the newest row per asset, in both dialects.
5. **Per-row lookups on list endpoints.** `list_remediations` (both dialects) now batches the
   repository lookup. `/scans/{id}/results` and `/fix-next` enrich a scan's results with two
   statements instead of 3–4 per result. The certificate and shadow-IT reports pass
   `fallback_keys`, so assets missing from recent scans are resolved by one batched query.
6. **Capped reports now state their coverage.** `/hndl/dashboard` and `/hndl/timeline` price the newest 1,000 assets,
   and `/cbom` and `/cbom.csv` export the newest 2,000 and 5,000. They now say so:
   `inventory_coverage: {assets_in_report, inventory_assets, complete}` on the HNDL views, and
   `X-Morrow-Assets-In-Report` / `X-Morrow-Inventory-Assets` headers on the CBOM exports, which keeps
   the document valid CycloneDX.

`backend/test_load_regressions.py` section 15 pins each of these:

- the statement count for a page of assets, a list of remediations and a scan's enrichment;
- the rowid-only sort;
- a query plan with no temporary sort for the newest-row read;
- search applied before the limit;
- cursor walks that visit every asset exactly once, even across ties;
- the indexes, in both schemas;
- the coverage fields.

## Known limits after the first pass

These were the open items when the sections above were written; the next section says what became
of each: reports capped at 1,000–5,000 assets, `/telemetry/kpis` at 10–14 s, the certificate view and
the key map at 4–18 s and 95 / 52 MB, a rare `/search` term at 8 s, `list_scan_rows(2000)` walking
result blobs, Postgres seeding through Docker Desktop at about 0.3 s per asset, and concurrency and
100k on Postgres not measured.

## 100,000 assets: the second pass (branch `perf-100k`)

### What changed

1. **`asset_scan_latest`: one row per asset, written at scan time.** It holds each asset's newest
   `scan_results` row (newest by `scanned_at`, then `id`, the order every newest-row read already
   used) plus the few fields of the full scan result that only `scans.results_json` carried: the
   certificate's expiry (raw, and normalized to fixed-width UTC so SQL can compare it), issuer and
   subject, and the key-map facts (key type and size as the map reads them, TLS version, ccTLD
   country, heuristic risk score, whether the result carried an error). `services/asset_posture.py`
   defines those fields once, for the write path and the backfill.
   - The `scan_results` half is maintained **by triggers** in both dialects (SQLite triggers;
     PL/pgSQL functions on Postgres): an insert replaces the asset's row only when it is newer, an
     update of the current row is copied, and deleting the current row (retention) promotes the next
     newest. Raw SQL writers and retention cannot leave it stale.
   - The full-result half is written by `save_scan_asset_summaries` in the same transaction
     (`RETURNING id` on Postgres); a newer row clears it until then.
   - **Upgrade.** The schema step fills the `scan_results` half with one `INSERT … SELECT`; the startup
     backfill (`db.backfill_asset_scan_latest`, run once from `init_db` and recorded in
     `morrow_backfills`) reads each asset's newest scan once for the rest. On the 100k SQLite file the
     first start after upgrading took **658 s** on the loaded laptop: 353 s for the backfill (1,000
     scans read), the rest for the `scan_headers` copy (item 6) and index builds. Run
     `python -c "import db; db.init_db()"` once before switching traffic, as with a migration.
   - The table is in both tenant purge lists and in `services/postgres_rls.ORG_SCOPED_TABLES`.
2. **Reads moved onto it.** `latest_scan_facts_for_org` (executive dashboard, board risk, heatmap,
   CBOM, crypto agility, velocity, compliance, search) reads one row per asset through
   `idx_asset_scan_latest_org_scanned` instead of walking 200,000 history rows with a `NOT EXISTS`
   (SQLite) or a `DISTINCT ON` (Postgres) per request.
3. **Search uses trigram indexes.** SQLite: an FTS5 table with the `trigram` tokenizer over
   `search_text` (the lower-cased search columns joined by `char(31)`, so a term cannot straddle two
   fields), kept in sync by triggers. A quoted phrase query is the same case-insensitive "contains"
   the per-column `LIKE` was. A selective term reads only its matches; a term with more than 2,000
   matches, or under three characters, walks the newest-first index and stops at `limit`. Postgres:
   `pg_trgm` and a GIN index on `search_text` (skipped, with a log line, where the extension cannot be
   created).
4. **Certificate lifecycle and key map are SQL over the whole estate.** `/governance/certificates`
   counts every inventory asset and lists the `asset_limit` most urgent in the old order (severity,
   days remaining, asset key). On SQLite that order is assembled from three index ranges (expired or
   expiring, unknown, healthy), so it reads indexes plus the listed rows only. A new
   `inventory_coverage` field says how many assets the list holds. `/dark-matter/map` aggregates `meta`
   and `country_summary` over every asset's newest scan in SQL and lists the newest 3,000 keys, with a
   `coverage` field. Neither reads scan JSON any more. **Behaviour change:** both used to describe only
   the newest 100 / 30 scans; an asset outside them was "unknown" in the certificate view and absent
   from the map. Shadow-IT now reads only the runtime endpoints' own inventory rows and scan evidence
   (it called any runtime endpoint outside the newest 5,000 assets "not in asset inventory").
5. **`/telemetry/kpis` is windowed `COUNT`s.** Each KPI is a `COUNT … WHERE <time> >= ?` over its
   source (scan headers, `scan_results`, flight-recorder events, the canary and alert tables) plus the
   in-process event bus. **Behaviour change:** the counts are exact within their windows; the old code
   counted only what fell inside the newest 5,000 merged events. The old implementation is kept as
   `_telemetry_real_kpis_from_events`, and a test checks the two agree on a small database.
6. **`scan_headers` (SQLite only).** Every `scans` column except `results_json`, kept by triggers.
   `summary_json` and the `job_*` columns sit after the 400 KB result blob in a `scans` row, so reading
   them walked its overflow chain: `list_scan_rows(2000)` read 800 MB. Postgres stores large values
   out of line and needs no copy.
7. **HNDL covers the estate.** `/hndl/dashboard` and `/hndl/timeline` price every asset instead of the
   newest 1,000: the estate is grouped by its distinct pricing inputs in SQL (`db.hndl_input_groups`),
   each group is scored once, and only the priority queue's assets are read (`db.hndl_group_members`,
   one tie of equal exposure at a time, so the queue holds the same assets in the same order as a
   per-asset sort). The output equals the per-asset model's on the same inputs (test), except that
   totals are summed per group and can differ from a per-asset sum in the last cent.
8. **Cutover tool fixes**, found loading this estate into Postgres: `migrate_sqlite_core_to_postgres`
   passed JSON columns to psycopg2 as raw dicts and failed on the first table with one, and it read
   each table whole, which ran out of memory on `scans`. It now wraps them in `Json` and streams in
   batches.

Regression tests: `backend/test_scale_reads.py` checks each new read against the read it replaced, on
a database built through the scan path (out-of-order scans, duplicates within a scan, ties, raw-SQL
inserts, updates and retention deletes, two tenants, the upgrade backfill, every certificate state and
several page sizes, both search paths), and has a Postgres class (`MORROW_TEST_PG_DSN`) for the
triggers, trigram search and the cutover tool. `test_load_regressions.py` now pins the
one-row-per-asset plan.

### Measurements, and how far to trust them

**The laptop was not usable as a benchmark host during this work**, and the numbers must be read
that way. It is the machine described above (i5-1135G7, 4 cores / 8 threads, 7.7 GB RAM), and it ran
other agents' test suites, Docker image builds and an end-to-end container stack the whole time: CPU
at 100%, free memory between 60 MB and 1 GB, so SQLite's page reads went to disk instead of the OS
cache. One example: aggregating 100,000 rows of `asset_scan_latest` through an index took 68 s cold
and 0.4 s with a warm 400 MB page cache. Wall-clock latency here mostly measures memory pressure.

`bench.py` therefore now also records **`cpu50`**: the median CPU time the benchmark process spent per
call (`time.process_time`). It leaves out waiting for a core or for evicted pages, so it compares
across noisy runs where wall time cannot. It does include the app's own background threads
(schedulers, the analytics snapshot refresh) when they run during a call, so a single high value can be
one of those; it does not include a database server's CPU (irrelevant on SQLite). The two runs below were taken back to back on copies of one seeded 100k file, "before" with
`bench.py --backend` pointing at a worktree of `6135688`. Times in ms.

| Endpoint | p50 before | p50 after | CPU before | CPU after | Peak MB before / after |
|---|---:|---:|---:|---:|---|
| /executive-dashboard | 23,859 | 2,685 | 13,531 | 1,594 | 11.0 / 94.5 |
| /qday/countdown | 1,241 | 2,144 | 844 | 922 | 11.2 / 11.1 |
| /board-risk/weather | 1,749 | 2,421 | 1,250 | 1,406 | 11.0 / 11.0 |
| /telemetry/kpis | 35,992 | 134 | 14,547 | 109 | 5.0 / 0.3 |
| /observatory/dashboard | 48 | 49 | 47 | 47 | 0.4 / 0.4 |
| /crypto-agility | 2,420 | 2,952 | 1,516 | 1,562 | 18.8 / 18.8 |
| /migration-velocity | 3,058 | 2,990 | 1,516 | 1,422 | 14.4 / 14.4 |
| /hndl/dashboard | 1,027 | 35,485 | 594 | 12,031 | 4.8 / 120.5 |
| /board-risk | 1,254 | 1,339 | 844 | 766 | 11.4 / 11.0 |
| /compliance-mapping | 2,658 | 4,165 | 1,750 | 1,641 | 4.8 / 4.8 |
| /hndl-canaries | 57 | 55 | 62 | 62 | 0.4 / 0.4 |
| /assets | 1,516 | 1,983 | 828 | 953 | 6.8 / 7.1 |
| /tags | 1,734 | 1,923 | 953 | 984 | 0.3 / 0.3 |
| /collections | 98 | 134 | 62 | 47 | 0.3 / 0.3 |
| /repositories | 355 | 328 | 203 | 219 | 1.3 / 1.3 |
| /baselines | 72 | 71 | 62 | 62 | 0.3 / 0.3 |
| /governance/certificates | 14,723 | 16,171 | 5,641 | 7,547 | 95.2 / 13.4 |
| /blast-radius/graph | 5,904 | 5,619 | 3,031 | 3,000 | 37.3 / 37.4 |
| /scans?limit=25 | 564 | 273 | 531 | 125 | 0.4 / 0.3 |
| /scans/{scan}/results | 274 | 324 | 203 | 172 | 3.4 / 3.4 |
| /fix-next | 310 | 352 | 156 | 172 | 2.6 / 2.6 |
| /heatmap | 464 | 364 | 219 | 234 | 1.4 / 1.4 |
| /cbom | 5,462 | 3,756 | 1,578 | 1,734 | 11.5 / 11.9 |
| /cbom.csv | 2,588 | 2,268 | 1,109 | 1,203 | 11.1 / 11.2 |
| /sbom/imports | 117 | 130 | 94 | 78 | 0.2 / 0.2 |
| /cbom/webhook/ingests | 59 | 86 | 62 | 62 | 0.4 / 0.4 |
| /hndl/timeline | 2,085 | 27,468 | 1,234 | 12,359 | 4.6 / 107.6 |
| /dark-matter/map | 3,626 | 2,363 | 2,422 | 1,312 | 52.0 / 5.6 |
| /q-intel/model | 107 | 113 | 94 | 94 | 0.4 / 0.4 |
| /remediations | 548 | 1,218 | 344 | 391 | 1.3 / 1.2 |
| /remediation-feed | 1,806 | 2,237 | 1,453 | 1,484 | 1.7 / 1.7 |
| /migration-tasks | 314 | 692 | 188 | 234 | 0.8 / 0.8 |
| /board-risk/leaderboard | 1,357 | 1,735 | 984 | 1,328 | 11.0 / 11.1 |
| /board-risk/regulatory | 1,344 | 1,131 | 906 | 953 | 11.0 / 11.0 |
| /search?q=svc00012 | 10,072 | 838 | 6,859 | 672 | 0.7 / 0.3 |
| /search?q=rsa | 642 | 697 | 359 | 281 | 0.5 / 0.5 |

Raw runs: `scripts/scale/results/sqlite-100k-{before,after}-paired.json`. How to read it:

- **Fixed and confirmed by CPU time:** `/telemetry/kpis` (14.5 s → 0.1 s CPU), the rare search term
  (6.9 s → 0.7 s), `/scans?limit=25` (0.53 → 0.13 s), the executive dashboard (13.5 → 1.6 s), the key
  map (2.4 → 1.3 s, and 52 → 5.6 MB peak) and the certificate view's memory (95 → 13 MB peak).
- **Not faster:** the certificate view's CPU (5.6 → 7.5 s) and wall time. It now covers all 100,000
  assets instead of the newest 5,000 and returns the 5,000 most urgent of them; on this file every
  asset has an expiry, so all 100,000 are ranked, and the 2.4 MB response is built from 5,000 rows read
  one by one. A profile (`profile_endpoint.py`) puts 1.6 s of it in classifying the 5,000 listed rows.
  Paging `items` (it is a list a person reads) is the next step.
- **HNDL in this table is the first, per-asset version** (35 s, 12 s CPU, 120 MB): pricing 100,000
  assets in Python. It was replaced by the grouped version (item 7); re-measured on the same file
  (`sqlite-100k-after-hndl.json`): `/hndl/dashboard` 19 s wall / 9.6 s CPU for one sample,
  `/hndl/timeline` 5.2 s / 3.9 s, against 1.0 s / 0.6 s and 2.1 s / 1.2 s before for the newest 1,000
  assets. A cProfile of the handlers alone shows 1.3 s and 1.6 s; the rest of the measured CPU is the
  app's background threads (the analytics snapshot refresh ran during those calls). Complete coverage
  costs more than a 1 % sample did, and this is the endpoint pair furthest from the 1 s target.
- Everything else moved within the noise of this machine (±50 % wall between runs of the same code).


### Not measured, and why

- **100,000 assets on Postgres.** The estate was not loaded. Seeding through the app's helpers from a
  container on the Docker network ran at about 100 scans per 12 minutes (about 8 hours for 100k); the
  cutover tool, the faster route, failed on JSON columns and then ran out of memory (both fixed, item
  8); then Docker Desktop stopped responding and went down. The Postgres paths are covered by the
  gated tests, not by a 100k measurement. On a quiet machine:

  ```powershell
  docker run -d --name morrow-scale-pg -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=scale -e POSTGRES_USER=scale -e POSTGRES_DB=scale postgres:16 -c shared_buffers=256MB
  cd backend
  $env:MORROW_PRODUCT_DATABASE_URL = "postgresql://scale:scale@127.0.0.1:55432/scale"
  & $py -c "import db_postgres as p; p.migrate_sqlite_core_to_postgres(r'C:\path\scale-100k.db', batch_size=2000)"
  & $py -c "import db; db.init_db()"     # asset_scan_latest and its one-time backfill
  & $py ..\scripts\scale\bench.py --postgres $env:MORROW_PRODUCT_DATABASE_URL --samples 7 --out ..\scripts\scale\results\postgres-100k.json
  ```

  Bench from a container on Postgres's Docker network (or a Linux host) if possible: through Docker
  Desktop's port forwarding every round trip pays a Windows-to-VM hop.

- **Concurrent users.** `scripts/scale/locustfile.py` (Locust, dev-only: `scripts/scale/requirements-load.txt`
  in its own virtualenv) signs in N users through `POST /auth/login` with accounts made by
  `scripts/scale/load_users.py`, spread round robin over several organizations, and opens console
  views with 2–6 s of think time; at the end it prints p50, p95 and error rate per view. A run with 50
  users against `uvicorn --workers 4` on the 100k SQLite file plus three 500-asset organizations was
  abandoned: in four minutes the server completed 68 requests and the median sign-in took 134 s
  (bcrypt on a CPU already at 100%). That describes the laptop, not Morrow, and is not quoted as a
  result; 100 and 200 users were not run. What the attempt did show:
  - With 4 workers each worker imports the app itself; on a loaded host that takes minutes, and
    uvicorn's default 5 s worker health check kills and restarts them in a loop. Pass
    `--timeout-worker-healthcheck` when running several workers (the Helm chart runs `--workers 4`;
    the Docker image runs one).
  - **Rate limits.** All virtual users share one source IP, so the per-org-and-IP limit
    (`MORROW_RATE_LIMIT_MAX_REQUESTS`, default 240 a minute), slowapi's per-IP default
    (`MORROW_RATE_LIMIT_DEFAULT`, 300/minute) and the sign-in limit (`MORROW_RATE_LIMIT_AUTH`,
    10/minute) would turn most of a run into 429s. The run set them to 1000000, 1000000/minute and
    100000/minute. Real users arrive from their own addresses; a run that should exercise the limits
    keeps the defaults and spreads users over several source IPs.

  On a quiet machine:

  ```powershell
  & $py ..\scripts\scale\seed.py --assets 500 --db $db --org org-load-b --host-prefix bsvc    # more orgs: repeat
  & $py ..\scripts\scale\load_users.py --db $db --orgs 00000000-0000-0000-0000-000000000001,org-load-b --per-org 50 --out users.json
  # server env: MORROW_SCANNER_DB=$db MORROW_AUTH_MODE=jwt MORROW_AUTH_ISSUER_ENABLED=1 MORROW_AUTH_JWT_SECRET=<random>
  #             MORROW_AUTH_JWT_ALGORITHMS=HS256 MORROW_AUTH_ORG_ID_CLAIM=org_id and the rate limits above
  & $py -m uvicorn app:app --port 8765 --workers 4 --timeout-worker-healthcheck 600
  $env:MORROW_LOAD_USERS = "users.json"
  locust -f ..\scripts\scale\locustfile.py --headless -u 100 -r 5 -t 5m --host http://127.0.0.1:8765 --csv out\run-100
  ```

### What is still slow or capped, and why

- **CBOM and CSV exports stay capped** at 2,000 / 5,000 assets (stated in the `X-Morrow-*` headers).
  They are documents, not aggregates: a complete CycloneDX file for 100,000 assets is on the order of
  100 MB and belongs in a streamed or paginated export, not a console call.
- **Crypto agility, velocity, compliance mapping and the board-risk reports** still describe the newest
  5,000 (or fewer) assets. Their read is now one row per asset, but their models are per-asset
  Python; making them complete is the "score each distinct input once" treatment HNDL got, report by
  report.
- **`/blast-radius/graph`** still parses the newest scans' full results; the edges it draws would have
  to be stored at scan time, as the certificate fields now are.
- **Whole-estate joins on SQLite are bounded by the page cache.** Joining 100,000 assets to their
  latest rows (HNDL, the certificate summary) took seconds of CPU and tens of seconds of wall time on
  the loaded laptop, against a fraction of a second with the file in memory. At this size on SQLite,
  give connections a larger `cache_size`, or use Postgres.
- **The first start after upgrading** runs the backfill (item 1).
- **The 1 s target is not shown to be met.** CPU per call is below a second for the endpoints the
  table marks; wall time on this laptop is not evidence either way.
