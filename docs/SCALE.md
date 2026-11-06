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

RESULTS_PLACEHOLDER
