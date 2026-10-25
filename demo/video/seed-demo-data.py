"""Seed the demo-video database with a fictional customer estate.

Everything here belongs to "Example Financial Group", an invented company.
Every hostname is under example.com or internal.example (reserved example
domains), every certificate issuer is an invented internal CA, and no real
third party is named anywhere.

Scan results are built with the platform's own evaluation pipeline
(policy.evaluate_policies -> derive_risk_and_score -> derive_pq_relevance ->
derive_quantum_readiness) and then posted through POST /scans/synthetic, so the
stored scans, asset summaries, CBOM, HNDL model and compliance report are
internally consistent with what a real scan of such an estate would produce.

Usage (with demo\\video\\run-demo-server.py already running on 8049):

    backend/.venv/Scripts/python.exe demo/video/seed-demo-data.py
"""
from __future__ import annotations

import json
import os
import pathlib
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests

ROOT = pathlib.Path(__file__).resolve().parents[2]
# MORROW_BACKEND_DIR exists because this script is also the quick-start seeder, and in the
# container the backend lives at /app with no repo root above it -- ROOT/"backend" is only
# correct when running from a checkout. The container mounts demo/ and points this at /app.
BACKEND = pathlib.Path(os.environ.get("MORROW_BACKEND_DIR") or (ROOT / "backend"))
DEMO_DB = pathlib.Path(os.environ.get("MORROW_DEMO_DB") or (ROOT / "demo" / "video" / "demo.db"))
BASE = os.environ.get("MORROW_DEMO_BASE", "http://127.0.0.1:8049")
# The account the seeded workspace belongs to. The server creates it at startup from
# MORROW_ADMIN_EMAIL / MORROW_ADMIN_PASSWORD, so these must match whatever started the server
# (demo/video/run-demo-server.py, or the app service in docker-compose.yml).
EMAIL = os.environ.get("MORROW_DEMO_EMAIL") or "avery.chen@example.com"
PASSWORD = os.environ.get("MORROW_DEMO_PASSWORD") or "Airlock-Demo-Recording-8049"

os.environ["MORROW_SCANNER_DB"] = str(DEMO_DB)   # before anything imports db
sys.path.insert(0, str(BACKEND))

# The estate is shared with the public demo workspace (services/demo_mode.py).
from services.demo_estate import (  # noqa: E402
    CANARIES, COLLECTIONS, COMPANY, ESTATE, HNDL_TOKEN_ASSETS, MIGRATION_TASKS, POLICY,
    REMEDIATION_PLAN, REPOS, SCAN_COUNT, SCAN_SPACING_DAYS, build_facts,
)

random.seed(20260923)

NOW = datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc)


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------- http helpers
class Api:
    def __init__(self):
        self.s = requests.Session()
        r = self.s.post(f"{BASE}/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=30)
        r.raise_for_status()
        data = r.json()
        self.token = data["access_token"]
        self.user = data["user"]
        self.s.headers.update({"Authorization": f"Bearer {self.token}"})

    def post(self, path, body=None, ok=(200, 201)):
        r = self.s.post(f"{BASE}{path}", json=body, timeout=180)
        if r.status_code not in ok:
            log(f"  ! POST {path} -> {r.status_code} {r.text[:200]}")
        return r

    def put(self, path, body=None):
        r = self.s.put(f"{BASE}{path}", json=body, timeout=60)
        if r.status_code >= 300:
            log(f"  ! PUT {path} -> {r.status_code} {r.text[:200]}")
        return r

    def get(self, path):
        return self.s.get(f"{BASE}{path}", timeout=120)


# ---------------------------------------------------------------- direct rows
def brand_tenant(org_id: str) -> None:
    """Name the workspace after the fictional company and give the signed-in
    operator a human name. There is no API for either, and both are cosmetic."""
    conn = sqlite3.connect(str(DEMO_DB), timeout=30)
    try:
        conn.execute("UPDATE organizations SET name=? WHERE id=?", (COMPANY, org_id))
        conn.execute("UPDATE morrow_users SET full_name=?, org_id=? WHERE email=?",
                     ("Avery Chen", org_id, EMAIL))
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    default_org = "00000000-0000-0000-0000-000000000001"
    brand_tenant(default_org)

    api = Api()
    org_id = api.user.get("org_id")
    log(f"signed in; workspace={org_id}")

    # ---------------------------------------------------------- repositories
    import db as dbmod  # imported late: MORROW_SCANNER_DB is already set above
    dbmod.set_current_organization_id(org_id)
    repo_ids = {}
    for slug, name in REPOS.items():
        row = dbmod.upsert_repository(name, f"https://github.com/{name}")
        repo_ids[slug] = int(row.get("id") or 0)
    log(f"repositories: {len(repo_ids)}")

    # ---------------------------------------------------------- scan history
    scan_ids = []
    for i in range(SCAN_COUNT):
        scanned_at = NOW - timedelta(days=SCAN_SPACING_DAYS * (SCAN_COUNT - 1 - i), hours=random.randint(0, 6))
        targets = [e for e in ESTATE if e[11] <= min(i, 4)]
        results = [build_facts(e, i, scanned_at) for e in targets]
        scan_id = f"scan-{scanned_at.strftime('%Y%m%d')}-estate"
        r = api.post("/scans/synthetic", {
            "scan_id": scan_id,
            "created_at": scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "results": results,
            "auto_close_merged": False,
        })
        if r.status_code == 200:
            scan_ids.append(scan_id)
            log(f"scan {i + 1}/{SCAN_COUNT} {scanned_at.date()} -> {len(results)} endpoints")

    # ---------------------------------------------------------- asset context
    for entry in ESTATE:
        host, port, env, team, owner, crit, lifetime, repo, tags, key, tls, first = entry
        api.put(f"/assets/{host}:{port}", {
            "owner": owner,
            "team": team,
            "environment": env,
            "criticality": crit,
            "confidentiality_lifetime": lifetime,
            "tags": tags,
            "notes": f"{COMPANY} demo estate record (fictional).",
            "metadata": {"business_service": team, "data_classification":
                         "restricted" if "restricted" in tags or "customer-data" in tags else "internal"},
            "repository_id": repo_ids.get(repo, 0),
        })
    log(f"assets: {len(ESTATE)} with owner, team, environment, criticality and data lifetime")

    # ---------------------------------------------------------- collections
    for name, tag in COLLECTIONS:
        api.post("/collections", {
            "name": name,
            "description": f"{COMPANY} demo estate",
            "targets_text": "\n".join(f"{e[0]}:{e[1]}" for e in ESTATE if tag in e[8]),
        })

    # ---------------------------------------------------------- remediations
    made = []
    for asset_key, repo, path, title, fix, status in REMEDIATION_PLAN:
        original = f"# {path}\nmin_tls_version = \"1.2\"\nkey_algorithm   = \"rsa-2048\"\ncrypto_owner    = \"\"\n"
        suggested = f"# {path}\nmin_tls_version = \"1.3\"\nkey_algorithm   = \"rsa-3072\"\ncrypto_owner    = \"platform-security\"\npq_stage       = \"hybrid-group-pending\"\n"
        row = dbmod.create_remediation(
            asset_key, repo_ids.get(repo, 0), path, title, fix,
            original_content=original, suggested_content=suggested,
            status=status, review_note="Reviewed in the weekly crypto migration forum.",
            origin_kind="scan_finding",
        )
        made.append((int(row.get("id") or 0), status))
        if status in {"pr_created", "verified_closed"}:
            v = dbmod.create_validation_job(
                int(row.get("id") or 0), validator_type="terraform", git_ref="main",
                status="passed", job_id=f"val-{row.get('id')}",
                details={"commands": [
                    {"cmd": "terraform fmt -check", "exit_code": 0},
                    {"cmd": "terraform validate", "exit_code": 0},
                ], "iac_policy": {"status": "passed", "findings": []}},
            )
            dbmod.update_validation_job(int(v.get("id") or 0), status="passed",
                                        stdout="Validation passed.\n", stderr="", exit_code=0, finished=True)
    log(f"remediations: {len(made)} across suggested / approved / pr_created / verified_closed")

    # Give the estate a history: an asset was first seen at the scan that found
    # it, and a fix was raised, reviewed and closed over the weeks that followed.
    conn = sqlite3.connect(str(DEMO_DB), timeout=30)
    try:
        for entry in ESTATE:
            host, port, *_rest = entry
            first = entry[11]
            seen = NOW - timedelta(days=SCAN_SPACING_DAYS * (SCAN_COUNT - 1 - min(first, 4)))
            conn.execute("UPDATE assets SET updated_at=? WHERE asset_key=?",
                         (seen.strftime("%Y-%m-%dT%H:%M:%SZ"), f"{host}:{port}"))
        ages = {"suggested": 6, "approved": 19, "pr_created": 33, "verified_closed": 61}
        for rid, status in made:
            created = NOW - timedelta(days=ages.get(status, 10), hours=rid)
            fields = {"created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "updated_at": (created + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            if status in {"pr_created", "verified_closed"}:
                fields["pr_url"] = f"https://github.com/example-financial/repo/pull/{100 + rid}"
                fields["pr_branch"] = f"morrow/remediation-{rid}"
                fields["pr_base_branch"] = "main"
            if status == "verified_closed":
                merged = created + timedelta(days=9)
                fields["merged_at"] = merged.strftime("%Y-%m-%dT%H:%M:%SZ")
                fields["closed_at"] = (merged + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
                fields["verification_scan_id"] = scan_ids[-1] if scan_ids else ""
                fields["drift_status"] = "clear"
                fields["last_drift_checked_at"] = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
            sets = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE remediations SET {sets} WHERE id=?", (*fields.values(), rid))
        conn.commit()
    finally:
        conn.close()

    # ---------------------------------------------------------- migration tasks
    for title, asset, status, owner in MIGRATION_TASKS:
        api.post("/migration-tasks", {"title": title, "asset_key": asset, "status": status,
                                      "owner": owner, "priority": "high"})

    # ---------------------------------------------------------- canaries
    for tier, asset in CANARIES:
        api.post("/canaries/deploy", {"tier": tier, "asset_key": asset,
                                      "notes": f"{COMPANY} demo estate tripwire"})
    for asset in HNDL_TOKEN_ASSETS:
        api.post("/hndl-canary-tokens", {"asset_key": asset, "label": f"HNDL canary for {asset}"})

    # ---------------------------------------------------------- policy
    api.post("/policies", POLICY)

    log("seed complete")


if __name__ == "__main__":
    main()
