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

## Known limits (not fixed here)

- **Reports are capped, not complete.** HNDL covers 1,000 assets, CBOM 2,000, CSV, crypto agility and velocity
  5,000. Above that size the figures describe the newest part of the estate, and the response now
  says so. Making them complete means aggregating in SQL, or walking the asset cursor, inside each
  report's model.
- **`/telemetry/kpis`: 10–14 s.** It loads up to 5,000 telemetry events from four sources and counts them in
  Python. Its cost grows with request volume (the security journal), not inventory. It should be a set of
  `COUNT(*) ... WHERE created_at >= ?` queries.
- **`/governance/certificates` and `/dark-matter/map`: 4–18 s, 95 MB / 52 MB peak.** They load and
  parse the full JSON of the newest 100 or 30 scans, because certificate details live only in
  `scans.results_json`. The cost is bounded by scan size, not inventory, but it is the largest memory peak
  in the console. A per-asset certificate table would remove it.
- **Rare-term `/search` at 100k: 8 s.** A term that matches few assets walks most of the 200,000
  rows. An FTS or trigram index on the newest row per asset would fix it.
- **SQLite file layout.** Scan blobs and `scan_results` pages are interleaved, so cold reads of
  `scan_results` touch pages across a 1.5 GB file, and cold numbers depend heavily on the OS cache.
  Moving `summary_json` ahead of `results_json`, or into its own table, would also make
  `list_scan_rows(limit=2000)` (the telemetry path) cheap.
- **Postgres writes from Windows Docker: about 0.3 s per `upsert_asset`.** Seeding 10k assets took 50 minutes.
  This was not investigated, and production Postgres is not on Docker Desktop.
- **Not measured:** concurrency (every number here is one request at a time), 100k on Postgres,
  and the console's own rendering time.
