"""Measure the console's read endpoints against a seeded database.

Drives the real FastAPI app in-process (fastapi.testclient), with the full middleware stack, as
the default organization's admin. For every endpoint the console calls on its main views
(backend/static/index.html -> VIEWS.overview / inventory / scans / cbom / hndl / remediation /
board / search) it records:

  * cold    the first call (in-process caches empty), run under tracemalloc; its latency is
            inflated by tracing and is not part of p50/p95
  * peak    tracemalloc's peak Python heap during that cold call, minus the heap before it (MB).
            SQLite's own page cache is C memory and is not included.
  * p50/p95 over the remaining (untraced) calls
  * bytes   response body size, and the HTTP status

Sampling stops at --samples calls or when an endpoint has used --budget seconds, whichever is
first (at least one untraced call is always made), so one pathological endpoint cannot hold the
laptop for an hour. Endpoints that cache their answer show it as cold >> p50.

Usage (from backend/, after seed.py):
    python ../scripts/scale/bench.py --db %TEMP%/morrow-scale-10k.db --out ../scripts/scale/results/sqlite-10k.json
    python ../scripts/scale/bench.py --postgres postgresql://... --out ...
    python ../scripts/scale/bench.py --db ... --only /assets,/cbom      # re-measure a few
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import pathlib
import platform
import statistics
import sys
import time
import tracemalloc

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
ORG_ID = "00000000-0000-0000-0000-000000000001"

# (view, path) in the order the console loads them. {scan} is the newest scan's id.
ENDPOINTS = [
    ("overview", "/executive-dashboard"), ("overview", "/qday/countdown"),
    ("overview", "/board-risk/weather"), ("overview", "/telemetry/kpis"),
    ("overview", "/observatory/dashboard"), ("overview", "/crypto-agility"),
    ("overview", "/migration-velocity"), ("overview", "/hndl/dashboard"),
    ("overview", "/board-risk"), ("overview", "/compliance-mapping"),
    ("overview", "/hndl-canaries"),
    ("inventory", "/assets"), ("inventory", "/tags"), ("inventory", "/collections"),
    ("inventory", "/repositories"), ("inventory", "/baselines"),
    ("inventory", "/governance/certificates"), ("inventory", "/blast-radius/graph"),
    ("findings", "/scans?limit=25"), ("findings", "/scans/{scan}/results"),
    ("findings", "/fix-next"), ("findings", "/heatmap"),
    ("cbom", "/cbom"), ("cbom", "/cbom.csv"), ("cbom", "/sbom/imports"),
    ("cbom", "/cbom/webhook/ingests"),
    ("hndl", "/hndl/timeline"), ("hndl", "/dark-matter/map"), ("hndl", "/q-intel/model"),
    ("remediation", "/remediations"), ("remediation", "/remediation-feed"),
    ("remediation", "/migration-tasks"),
    ("reports", "/board-risk/leaderboard"), ("reports", "/board-risk/regulatory"),
    ("search", "/search?q=svc00012"), ("search", "/search?q=rsa"),
]


def pct(values, p):
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db")
    ap.add_argument("--postgres")
    ap.add_argument("--samples", type=int, default=7)
    ap.add_argument("--budget", type=float, default=20.0, help="seconds per endpoint")
    ap.add_argument("--only", default="", help="comma-separated path prefixes")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()
    if bool(args.db) == bool(args.postgres):
        ap.error("give exactly one of --db or --postgres")

    os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "scale-bench-only-secret-0123456789abcdefghij")
    os.environ.setdefault("MORROW_VAULT_MASTER_KEY", "cHFjLXNjYW5uZXItdGVzdC1vbmx5LWtleS0zMmJ5dGU=")
    os.environ["MORROW_AUTH_MODE"] = "header"
    os.environ["MORROW_DEFAULT_ROLE"] = "admin"
    if args.db:
        os.environ["MORROW_SCANNER_DB"] = os.path.abspath(args.db)
        os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
    else:
        os.environ.setdefault("MORROW_SCANNER_DB", os.path.join(
            os.environ.get("TEMP", "/tmp"), "morrow-scale-pg-sidecar.db"))
        os.environ["MORROW_MAIN_DB_BACKEND"] = "postgres"
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = args.postgres
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    import app as application  # noqa: E402
    from fastapi.testclient import TestClient  # noqa: E402
    import db  # noqa: E402

    import logging
    logging.disable(logging.WARNING)  # one INFO line per request would dominate the output
    application.limiter.enabled = False
    application.RATE_LIMIT_MAX_REQUESTS = 10_000_000
    headers = {"x-org-id": ORG_ID, "x-actor-role": "admin", "x-user-id": "scale@example.com"}

    token = db.set_current_organization_id(ORG_ID)
    try:
        newest = (db.list_scan_rows(limit=1) or [{}])[0].get("id", "none")
        asset_count = len(db.list_assets(limit=5000))
    finally:
        db.reset_current_organization_id(token)

    only = [p for p in args.only.split(",") if p]
    report = {"label": args.label, "backend": "postgres" if args.postgres else "sqlite",
              "python": sys.version.split()[0], "machine": platform.processor() or platform.machine(),
              "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "samples": args.samples,
              "budget_s": args.budget, "endpoints": []}
    seen = set()
    with TestClient(application.app, raise_server_exceptions=False) as client:
        # The first API request pays one-off process costs (OpenTelemetry flattens the route table,
        # the drift sentinel takes its startup snapshot). Spend them on a cheap request so they are
        # not charged to whichever endpoint happens to be measured first.
        t0 = time.perf_counter()
        client.get("/sbom/imports", headers=headers)
        report["warmup_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        for view, template in ENDPOINTS:
            path = template.replace("{scan}", newest)
            if template in seen or (only and not any(template.startswith(o) for o in only)):
                continue
            seen.add(template)
            times, status, size = [], None, 0

            def call():
                t0 = time.perf_counter()
                res = client.get(path, headers=headers)
                body = res.content
                return time.perf_counter() - t0, res.status_code, len(body)

            # The first call is the cold one (in-process caches empty), so it is the one that shows
            # what the endpoint really materialises. It runs under tracemalloc, which slows Python
            # code, so its latency is reported separately and kept out of p50/p95.
            gc.collect()
            tracemalloc.start()
            base = tracemalloc.get_traced_memory()[0]
            cold, status, size = call()
            peak = (tracemalloc.get_traced_memory()[1] - base) / 1e6
            tracemalloc.stop()
            spent = cold

            while len(times) < args.samples - 1 and spent < args.budget or not times:
                elapsed, status, size = call()
                times.append(elapsed)
                spent += elapsed
            row = {"view": view, "path": template, "status": status, "bytes": size,
                   "calls": len(times) + 1, "cold_traced_ms": round(cold * 1000, 1),
                   "p50_ms": round(pct(times, 50) * 1000, 1), "p95_ms": round(pct(times, 95) * 1000, 1),
                   "peak_mb": round(peak, 1)}
            report["endpoints"].append(row)
            print("%-12s %-28s %3s %9d B  cold %8.1f  p50 %8.1f  p95 %8.1f ms  peak %7.1f MB  (n=%d)" % (
                view, template, status, size, row["cold_traced_ms"], row["p50_ms"], row["p95_ms"], peak,
                len(times)), flush=True)

    report["assets_visible_in_first_page"] = asset_count
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
