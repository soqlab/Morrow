"""Create the signed-in users a concurrency run logs in as, spread over several organizations.

Users are built-in accounts (services/auth_issuer), so each virtual user of locustfile.py signs in
through POST /auth/login and calls the API with its own bearer token, scoped to its organization by
the token's org_id claim -- the same path a browser session takes.

    python ../scripts/scale/load_users.py --db big.db --orgs ORG_A,ORG_B --per-org 50 --out users.json
    python ../scripts/scale/load_users.py --postgres postgresql://... --orgs ... --out users.json

The users table lives in the SQLite file next to the product database on both backends, so --db is
the file the server is started with (MORROW_SCANNER_DB). Writes a JSON list of
{"email", "password", "org_id"} for the locustfile. Idempotent: existing users are kept.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, help="the SQLite file the server uses (MORROW_SCANNER_DB)")
    ap.add_argument("--postgres", help="product database DSN, when the server runs on Postgres")
    ap.add_argument("--orgs", required=True, help="comma-separated organization ids")
    ap.add_argument("--per-org", type=int, default=50)
    ap.add_argument("--role", default="admin", help="admin reaches every console view")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.environ["MORROW_SCANNER_DB"] = os.path.abspath(args.db)
    if args.postgres:
        os.environ["MORROW_MAIN_DB_BACKEND"] = "postgres"
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = args.postgres
    else:
        os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)
    import db  # noqa: E402
    from services import auth_issuer  # noqa: E402

    db.init_db()
    password = "Load-" + secrets.token_urlsafe(18) + "-9!"
    users = []
    from contextlib import closing

    with closing(db.get_connection()) as conn:
        auth_issuer.init_tables(conn)
        for org in [o.strip() for o in args.orgs.split(",") if o.strip()]:
            if org != db.DEFAULT_ORG_ID:
                db.upsert_organization(org, name="Load test " + org)
            for n in range(args.per_org):
                email = "load-%s-%03d@example.test" % (org[:8], n)
                conn.execute("DELETE FROM morrow_users WHERE email = ?", (email,))
                auth_issuer.create_user(conn, email, password, "Load user %d" % n, args.role, org)
                users.append({"email": email, "password": password, "org_id": org})
        conn.commit()
    pathlib.Path(args.out).write_text(json.dumps(users, indent=1), encoding="utf-8")
    print("wrote %d users to %s" % (len(users), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
