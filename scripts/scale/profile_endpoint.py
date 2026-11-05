"""cProfile one console endpoint against a seeded database, and count its SQL statements.

    python ../scripts/scale/profile_endpoint.py --db big.db /executive-dashboard [/cbom ...]

Prints the top functions by cumulative time and how many statements the SQLite connections
executed during the call (an N+1 shows up as a statement count proportional to the inventory).
"""
from __future__ import annotations

import argparse
import cProfile
import io
import os
import pathlib
import pstats
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
ORG_ID = "00000000-0000-0000-0000-000000000001"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--warm", action="store_true", help="call once before profiling")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "scale-bench-only-secret-0123456789abcdefghij")
    os.environ.setdefault("MORROW_VAULT_MASTER_KEY", "cHFjLXNjYW5uZXItdGVzdC1vbmx5LWtleS0zMmJ5dGU=")
    os.environ["MORROW_AUTH_MODE"] = "header"
    os.environ["MORROW_DEFAULT_ROLE"] = "admin"
    os.environ["MORROW_SCANNER_DB"] = os.path.abspath(args.db)
    os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    import logging
    import app as application
    from fastapi.testclient import TestClient

    logging.disable(logging.WARNING)
    application.limiter.enabled = False
    application.RATE_LIMIT_MAX_REQUESTS = 10_000_000
    headers = {"x-org-id": ORG_ID, "x-actor-role": "admin", "x-user-id": "scale@example.com"}

    statements = {"n": 0}

    def counting_connect(*a, **k):
        conn = real_connect(*a, **k)
        try:
            conn.set_trace_callback(lambda _s: statements.__setitem__("n", statements["n"] + 1))
        except Exception:
            pass
        return conn

    real_connect = sqlite3.connect
    sqlite3.connect = counting_connect

    with TestClient(application.app, raise_server_exceptions=False) as client:
        for path in args.paths:
            if args.warm:
                client.get(path, headers=headers)
            statements["n"] = 0
            prof = cProfile.Profile()
            t0 = time.perf_counter()
            prof.enable()
            res = client.get(path, headers=headers)
            prof.disable()
            elapsed = time.perf_counter() - t0
            print("=" * 100)
            print("%s -> %s, %d bytes, %.0f ms, %d SQL statements (incl. pooled connections opened before)" % (
                path, res.status_code, len(res.content), elapsed * 1000, statements["n"]))
            out = io.StringIO()
            pstats.Stats(prof, stream=out).sort_stats("cumulative").print_stats(args.top)
            print(out.getvalue()[-12000:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
