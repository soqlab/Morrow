"""Seed one organization with N assets, their scan history, findings and remediations.

Every row is written through the helpers the application itself uses (backend/db.py): a scan is
saved the way POST /scans/synthetic saves one (save_scan_row -> save_scan_results ->
save_scan_asset_summaries), the inventory context the way PUT /assets/{key} does (upsert_asset),
and remediations / migration tasks through create_remediation / create_migration_task. Scan
facts and findings come from the platform's own policy pipeline (services.demo_estate.build_facts
-> policy.evaluate_policies), so findings counts and risk levels are what a real scan of such an
estate would produce.

Ratios (per asset, defaults; see --help):
  * scan history     2 scans of every asset, 14 days apart, 100 endpoints per scan
  * findings         whatever the policy pipeline raises (about 2.6 per endpoint on this estate)
  * remediations     1 per 10 assets, statuses spread across the lifecycle
  * migration tasks  1 per 30 assets
  * repositories     1 per 100 assets
  * tags             1-3 per asset from a vocabulary of 24

The estate and every random choice derive from --seed, so a large seed can be written as several
bounded runs (--start/--stop) that together equal one full run.

Usage (from backend/, with the test venv):
    python ../scripts/scale/seed.py --assets 10000 --db %TEMP%/morrow-scale-10k.db
    python ../scripts/scale/seed.py --assets 100000 --db big.db --stop 50000
    python ../scripts/scale/seed.py --assets 100000 --db big.db --start 50000
    python ../scripts/scale/seed.py --assets 10000 --postgres postgresql://u:p@127.0.0.1:55432/scale
"""
from __future__ import annotations

import argparse
import os
import pathlib
import random
import sys
import time
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
ORG_ID = "00000000-0000-0000-0000-000000000001"
NOW = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)

ENVS = [("prod", 5), ("staging", 3), ("dev", 2)]
CRITS = [("tier-1", 2), ("tier-2", 4), ("tier-3", 4)]
LIFETIMES = ["1y", "3y", "5y", "10y+"]
KEYS = [(("RSA", 2048, ""), 55), (("RSA", 3072, ""), 10), (("RSA", 4096, ""), 5),
        (("EC", 256, "secp256r1"), 25), (("EC", 384, "secp384r1"), 5)]
TAG_VOCAB = ["internet", "public-web", "customer-data", "pci", "api", "internal", "legacy",
             "partner", "mobile", "batch", "payments", "identity", "hr", "treasury", "logging",
             "ldap", "vpn", "mail", "edge", "gdpr", "sox", "hipaa", "shared", "critical-path"]
REMEDIATION_STATUSES = [("suggested", 30), ("approved", 20), ("pr_created", 20), ("merged", 10),
                        ("verified_closed", 15), ("rejected", 5)]
TASK_STATUSES = [("open", 50), ("planned", 20), ("in_progress", 15), ("done", 10), ("accepted_risk", 5)]


def pick(rng: random.Random, weighted):
    values, weights = zip(*weighted)
    return rng.choices(values, weights=weights, k=1)[0]


def build_estate(n: int, rng: random.Random):
    """Entry tuples in the shape services.demo_estate.build_facts takes."""
    teams = ["team-%02d" % i for i in range(40)]
    repos = max(1, n // 100)
    estate = []
    for i in range(n):
        internal = rng.random() < 0.6
        host = ("svc%06d.internal.example" if internal else "svc%06d.example.com") % i
        team = rng.choice(teams)
        estate.append((
            host, 443 if rng.random() < 0.85 else rng.choice((8443, 636, 993, 5432)),
            pick(rng, ENVS), team, "owner-" + team, pick(rng, CRITS), rng.choice(LIFETIMES),
            "repo-%04d" % rng.randrange(repos), rng.sample(TAG_VOCAB, rng.randint(1, 3)),
            pick(rng, KEYS), "13" if rng.random() < 0.55 else "12", 0,
        ))
    return estate, repos


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--assets", type=int, required=True, help="size of the whole estate")
    ap.add_argument("--db", help="SQLite file (must not exist unless --start > 0)")
    ap.add_argument("--postgres", help="Postgres DSN of an empty database")
    ap.add_argument("--start", type=int, default=0, help="first asset index this run writes")
    ap.add_argument("--stop", type=int, default=0, help="one past the last index (default: --assets)")
    ap.add_argument("--scans-per-asset", type=int, default=2)
    ap.add_argument("--endpoints-per-scan", type=int, default=100)
    ap.add_argument("--remediation-ratio", type=float, default=0.10)
    ap.add_argument("--task-ratio", type=float, default=1 / 30)
    ap.add_argument("--seed", type=int, default=20261101)
    args = ap.parse_args()
    if bool(args.db) == bool(args.postgres):
        ap.error("give exactly one of --db or --postgres")
    per_scan = max(1, min(args.endpoints_per_scan, 200))  # 200 is the API's MAX_TARGETS
    lo, hi = args.start, (args.stop or args.assets)
    if lo % per_scan or not (0 <= lo < hi <= args.assets):
        ap.error("--start must be a multiple of --endpoints-per-scan and below --stop")

    if args.db:
        if os.path.exists(args.db) and lo == 0:
            ap.error("%s already exists; seed a fresh file" % args.db)
        os.environ["MORROW_SCANNER_DB"] = os.path.abspath(args.db)
        os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
    else:
        os.environ.setdefault("MORROW_SCANNER_DB", os.path.join(
            os.environ.get("TEMP", "/tmp"), "morrow-scale-pg-sidecar.db"))
        os.environ["MORROW_MAIN_DB_BACKEND"] = "postgres"
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = args.postgres
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    import db  # noqa: E402  (after the environment names the database)
    from services.demo_estate import build_facts  # noqa: E402
    from policy import summarize_results  # noqa: E402

    if args.postgres:
        import db_postgres
        db_postgres.ensure_postgres_core_schema(args.postgres)
    db.init_db()
    # The server pools SQLite connections for the database it serves (app._lifespan); without the
    # pool every helper call opens a connection and re-parses the schema (~50 ms on this laptop).
    db.enable_connection_pool()
    db.set_current_organization_id(ORG_ID)
    started = time.monotonic()

    def log(msg):
        print("[%7.1fs] %s" % (time.monotonic() - started, msg), flush=True)

    rng = random.Random(args.seed)
    estate, repo_count = build_estate(args.assets, rng)
    pick_rng = random.Random(args.seed + 1)
    remediated = sorted(pick_rng.sample(range(len(estate)), int(len(estate) * args.remediation_ratio)))
    tasked = sorted(pick_rng.sample(range(len(estate)), int(len(estate) * args.task_ratio)))

    if lo == 0:
        for r in range(repo_count):
            name = "example/repo-%04d" % r
            db.upsert_repository(name, "https://git.example.com/" + name)
    repo_ids = {row["name"].split("/", 1)[1]: int(row["id"]) for row in db.list_repositories(limit=5000)}
    log("repositories: %d; writing assets %d..%d of %d" % (len(repo_ids), lo, hi, len(estate)))

    # Scan history: round 0 is the oldest. Each round scans the slice in batches.
    rounds = max(1, args.scans_per_asset)
    scans = results_rows = findings = 0
    for rnd in range(rounds):
        base = NOW - timedelta(days=14 * (rounds - 1 - rnd))
        for start in range(lo, hi, per_scan):
            chunk = estate[start:min(start + per_scan, hi)]
            created = base + timedelta(seconds=start)
            results = [build_facts(e, rnd + 3, created) for e in chunk]
            summary = summarize_results(results)
            scan_id = "scale-r%d-%06d" % (rnd, start)
            db.save_scan_row(scan_id, "completed", created, {"total": len(results), "done": len(results),
                                                            "percent": 100}, "", results, summary)
            db.save_scan_results(scan_id, results=results, summary=summary, status="completed")
            db.save_scan_asset_summaries(scan_id, created.isoformat().replace("+00:00", "Z"), results)
            scans += 1
            results_rows += len(results)
            findings += sum(len(r.get("findings") or []) for r in results)
            if scans % 100 == 0:
                log("scans: %d (%d endpoint results, %d findings)" % (scans, results_rows, findings))
    log("scans: %d, endpoint results: %d, findings: %d" % (scans, results_rows, findings))

    # Inventory context, as an operator (or the CSV import) would set it.
    for i in range(lo, hi):
        host, port, env, team, owner, crit, lifetime, repo, tags = estate[i][:9]
        db.upsert_asset("%s:%d" % (host, port), owner=owner, team=team, environment=env,
                        criticality=crit, confidentiality_lifetime=lifetime, tags=tags,
                        notes="scale-test asset", metadata={"business_service": team},
                        repository_id=repo_ids.get(repo, 0))
        if (i + 1 - lo) % 5000 == 0:
            log("assets: %d" % (i + 1 - lo))
    log("assets: %d" % (hi - lo))

    # Remediations and migration tasks, spread over the last 180 days.
    stamps = []
    life = random.Random(args.seed + 2 + lo)
    mine = [i for i in remediated if lo <= i < hi]
    for i in mine:
        e = estate[i]
        status = pick(life, REMEDIATION_STATUSES)
        row = db.create_remediation(
            "%s:%d" % (e[0], e[1]), repo_ids.get(e[7], 0), "infra/tls/%s.tf" % e[0].split(".")[0],
            "RSA key exchange on a long-lived data path", "Move to TLS 1.3 with a hybrid ML-KEM group.",
            original_content='min_tls_version = "1.2"\n', suggested_content='min_tls_version = "1.3"\n',
            status=status, origin_kind="scan_finding")
        created = NOW - timedelta(days=life.randint(1, 180), minutes=i % 1440)
        closed = created + timedelta(days=life.randint(3, 40)) if status in ("merged", "verified_closed") else None
        stamps.append((int(row.get("id") or 0), created, closed, status))
    log("remediations: %d" % len(mine))
    mine = [i for i in tasked if lo <= i < hi]
    for i in mine:
        e = estate[i]
        db.create_migration_task(asset_key_str="%s:%d" % (e[0], e[1]), repository_name="example/" + e[7],
                                 repo_id=repo_ids.get(e[7], 0), file_path="src/crypto.py",
                                 rule_id="PY-RSA-KEYGEN", legacy_dependency="cryptography.rsa",
                                 migration_target="ML-KEM-768 hybrid", status=pick(life, TASK_STATUSES))
    log("migration tasks: %d" % len(mine))

    # Back-date the lifecycle so velocity charts have a history. There is no API for this; the
    # demo seeder does the same.
    def iso(d):
        return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""

    params = [(iso(c), iso(cl or c), iso(cl) if s in ("merged", "verified_closed") else "",
               iso(cl) if s == "verified_closed" else "", rid) for rid, c, cl, s in stamps]
    sql = "UPDATE remediations SET created_at=?, updated_at=?, merged_at=?, closed_at=? WHERE id=?"
    if args.postgres:
        import db_postgres
        # The lifecycle columns are TIMESTAMPTZ there: "not yet" is NULL, not ''.
        params = [tuple(v or None for v in p[:4]) + (p[4],) for p in params]
        with db_postgres.pg_product_conn(args.postgres) as conn:
            with conn.cursor() as cur:
                cur.executemany(sql.replace("?", "%s"), params)
    else:
        import sqlite3
        conn = sqlite3.connect(os.environ["MORROW_SCANNER_DB"])
        conn.executemany(sql, params)
        conn.commit()
        conn.close()  # no ANALYZE: production never runs one, so the planner has no statistics
    db.disable_connection_pool()
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
