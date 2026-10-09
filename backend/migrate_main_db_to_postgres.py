from __future__ import annotations

import argparse
import json
import os

from db_postgres import migrate_sqlite_core_to_postgres, product_database_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy the core SQLite product tables into Postgres.")
    parser.add_argument(
        "--sqlite-path",
        default=str(os.getenv("PQC_SCANNER_DB") or "").strip(),
        help="Path to the source SQLite database. Defaults to PQC_SCANNER_DB.",
    )
    parser.add_argument(
        "--dsn",
        default=product_database_url(),
        help="Target Postgres DSN. Defaults to PQC_PRODUCT_DATABASE_URL or DATABASE_URL.",
    )
    parser.add_argument("--batch-size", type=int, default=500, help="Rows per batch insert.")
    args = parser.parse_args()

    if not args.sqlite_path:
        raise SystemExit("--sqlite-path is required (or set PQC_SCANNER_DB)")
    if not args.dsn:
        raise SystemExit("--dsn is required (or set PQC_PRODUCT_DATABASE_URL / DATABASE_URL)")

    stats = migrate_sqlite_core_to_postgres(
        sqlite_path=args.sqlite_path,
        dsn=args.dsn,
        batch_size=int(args.batch_size),
    )
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
