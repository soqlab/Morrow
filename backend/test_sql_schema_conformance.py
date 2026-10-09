"""Every SQL literal in the codebase must match the real schema.

This exists because a whole class of defect was invisible: a query naming
columns that do not exist, wrapped in a bare `except`, failing silently forever.
Thirty-two statements across app.py, ai_agent, admin_console, drift_sentinel,
red_team_sim and sla_engine were in that state. Nothing failed, no test caught
them, and no log line was written -- the features simply answered from nothing.

Two conventions coexist and both are legitimate: the core tables use
organization_id, service-owned tables use org_id. So this does not lint for a
naming rule. It builds the real schema and lets SQLite judge each statement,
which is the only check that cannot drift from reality.

Only statically-known SQL is checked. An f-string's runtime value is unknowable
here, so dynamic queries stay the caller's responsibility.
"""

import ast
import importlib
import io
import os
import re
import sqlite3

import pytest

BACKEND = os.path.dirname(os.path.abspath(__file__))
SQL_START = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE)\b", re.I)
NO_SUCH_COLUMN = re.compile(r"no such column: ([A-Za-z_0-9.]+)")
NO_SUCH_TABLE = re.compile(r"no such table: ([A-Za-z_0-9]+)")


@pytest.fixture(scope="module")
def schema(tmp_path_factory, monkeypatch_module=None):
    """A database carrying the core schema plus every service's own tables."""
    path = str(tmp_path_factory.mktemp("schema") / "conformance.db")
    old_db = os.environ.get("PQC_SCANNER_DB")
    old_backend = os.environ.get("PQC_FEATURE_STORE_BACKEND")
    os.environ["PQC_SCANNER_DB"] = path
    os.environ["PQC_FEATURE_STORE_BACKEND"] = "sqlite"
    try:
        import db
        importlib.reload(db)
        db.init_db()

        # Services create their tables lazily on first use; run those so a table
        # that would exist at runtime is not reported as missing here.
        for entry in sorted(os.listdir(os.path.join(BACKEND, "services"))):
            if not entry.endswith(".py") or entry == "__init__.py":
                continue
            try:
                module = importlib.import_module("services." + entry[:-3])
            except Exception:
                continue
            for name in ("_init_tables", "_ensure_tables", "init_tables", "_ensure_schema"):
                fn = getattr(module, name, None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass

        conn = sqlite3.connect(path)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        yield conn, tables
        conn.close()
    finally:
        for key, value in (("PQC_SCANNER_DB", old_db), ("PQC_FEATURE_STORE_BACKEND", old_backend)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _sql_literals():
    """(path, lineno, sql) for every statically-known SQL string."""
    targets = [os.path.join(BACKEND, "app.py")]
    services = os.path.join(BACKEND, "services")
    targets += [os.path.join(services, f) for f in sorted(os.listdir(services))
                if f.endswith(".py") and f != "__init__.py"]

    for path in targets:
        try:
            source = io.open(path, encoding="utf-8-sig").read()
            tree = ast.parse(source)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            sql = node.value
            if not SQL_START.match(sql):
                continue
            # Postgres-dialect statements are executed against Postgres, not here.
            if "%s" in sql or "pg_" in sql:
                continue
            yield os.path.relpath(path, BACKEND), node.lineno, sql


def test_no_sql_statement_references_a_missing_column(schema):
    conn, tables = schema
    offenders = []

    for path, lineno, sql in _sql_literals():
        try:
            conn.execute(sql, tuple([None] * sql.count("?")))
            conn.rollback()
        except sqlite3.OperationalError as exc:
            message = str(exc)
            conn.rollback()

            missing_table = NO_SUCH_TABLE.search(message)
            if missing_table and missing_table.group(1) not in tables:
                # Nothing in the codebase creates this table; not a column defect.
                continue
            if NO_SUCH_COLUMN.search(message):
                offenders.append(f"{path}:{lineno}  {message}\n      {' '.join(sql.split())[:150]}")
        except Exception:
            # Syntax errors here are almost always a docstring that happens to
            # begin with "Update ..." or an f-string fragment, not a real query.
            conn.rollback()

    assert not offenders, (
        "SQL referencing columns that do not exist. These fail at runtime and are "
        "usually swallowed by a surrounding try/except, so the feature returns "
        "nothing and reports success:\n\n  " + "\n  ".join(offenders)
    )


def test_the_audit_actually_inspects_a_meaningful_number_of_statements(schema):
    """A guard that silently stops finding statements would pass forever."""
    count = sum(1 for _ in _sql_literals())
    assert count > 150, f"only {count} SQL literals discovered; the extractor is probably broken"


def test_core_and_service_org_column_conventions_both_exist(schema):
    """Documents why this file executes SQL instead of linting for a column name."""
    _, tables = schema
    conn, _ = schema
    core, service = [], []
    for table in tables:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if "organization_id" in cols:
            core.append(table)
        elif "org_id" in cols:
            service.append(table)

    assert core, "expected core tables keyed by organization_id"
    assert service, "expected service tables keyed by org_id"
    assert "scan_results" in core


# --------------------------------------------------------------------------- #
# Postgres dialect
# --------------------------------------------------------------------------- #
# The checks above skip anything using %s or pg_catalog, which is 121 statements
# -- and that is the dialect production actually runs. This covers them against a
# real server, because the schema is what decides and only a server knows it.
#
#   docker run -d --name pqc-pg -e POSTGRES_PASSWORD=pqcdev -e POSTGRES_DB=pqc \
#       -p 5433:5432 postgres:16-alpine
#   PQC_TEST_PG_DSN=postgresql://postgres:pqcdev@127.0.0.1:5433/pqc

PG_DSN = os.environ.get("PQC_TEST_PG_DSN", "").strip()


def _pg_sql_literals():
    """Postgres-dialect statements: the half the SQLite pass deliberately skips."""
    targets = [os.path.join(BACKEND, "app.py"), os.path.join(BACKEND, "db_postgres.py")]
    services = os.path.join(BACKEND, "services")
    targets += [os.path.join(services, f) for f in sorted(os.listdir(services))
                if f.endswith(".py") and f != "__init__.py"]
    for path in targets:
        try:
            tree = ast.parse(io.open(path, encoding="utf-8-sig").read())
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            sql = node.value
            if not SQL_START.match(sql):
                continue
            if "%s" not in sql and "pg_" not in sql:
                continue
            yield os.path.relpath(path, BACKEND), node.lineno, sql


@pytest.mark.skipif(not PG_DSN, reason="set PQC_TEST_PG_DSN to audit the Postgres dialect")
def test_no_postgres_statement_references_a_missing_column(monkeypatch):
    psycopg2 = pytest.importorskip("psycopg2")
    # monkeypatch, not os.environ: these were left set for the rest of the pytest process, so every
    # later module wrote to Postgres while reading its own SQLite file (the webhook contract tests
    # then saw "no such table"). Skipped runs hid it until PQC_TEST_PG_DSN was set.
    for key, value in (("PQC_MAIN_DB_BACKEND", "postgres"),
                       ("DATABASE_URL", PG_DSN),
                       ("PQC_PRODUCT_DATABASE_URL", PG_DSN)):
        monkeypatch.setenv(key, value)

    import db_postgres
    # Importing app registers the platform and security-truth deferred schemas,
    # exactly as backend/entrypoint.sh does before applying them. Without it the
    # audit silently skips every statement against those tables.
    import app  # noqa: F401
    db_postgres.ensure_postgres_core_schema(PG_DSN)
    db_postgres.apply_deferred_schemas()

    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
    tables = {r[0] for r in cur.fetchall()}

    offenders, checked = [], 0
    for index, (path, lineno, sql) in enumerate(_pg_sql_literals()):
        savepoint = f"audit_sp_{index}"
        try:
            cur.execute(f"SAVEPOINT {savepoint}")
            cur.execute(sql, tuple([None] * sql.count("%s")) or None)
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            checked += 1
        except psycopg2.Error as exc:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            code = exc.pgcode or ""
            if code == "42703":  # undefined_column
                offenders.append(f"{path}:{lineno}  {' '.join(str(exc).split())[:120]}")
            elif code == "42P01":  # undefined_table
                match = re.search(r'relation "([a-z_0-9.]+)" does not exist', str(exc))
                if match and match.group(1).split(".")[-1] in tables:
                    offenders.append(f"{path}:{lineno}  {' '.join(str(exc).split())[:120]}")
            elif code == "23502":
                # not_null_violation: the statement parsed and every column
                # resolved. Only the all-NULL parameters failed the constraint,
                # which is exactly what we want to see.
                checked += 1
    conn.rollback()
    conn.close()

    assert checked > 80, f"only {checked} Postgres statements verified; the extractor is probably broken"
    assert not offenders, (
        "Postgres SQL referencing columns that do not exist:\n\n  " + "\n  ".join(offenders)
    )
