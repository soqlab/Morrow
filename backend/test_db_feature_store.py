"""Tests for the dual-dialect feature-store connection.

Two layers:

  * Pure translation tests, which always run.
  * Round-trip tests against a REAL Postgres, which run when MORROW_TEST_PG_DSN is
    set and skip otherwise. These are the ones that matter -- a translator that
    only satisfies its own regexes proves nothing. They execute the translated
    SQL against a live server and compare the result to the SQLite behaviour the
    services were written against.

Start a server for the Postgres half with:
    docker run -d --name morrow-pg -e POSTGRES_PASSWORD=morrowdev -e POSTGRES_DB=morrow \\
        -p 5433:5432 postgres:16-alpine
    MORROW_TEST_PG_DSN=postgresql://postgres:morrowdev@127.0.0.1:5433/morrow
"""

import os
import sqlite3
import uuid

import pytest

from db_feature_store import (
    PostgresConnectionShim,
    is_or_replace,
    needs_do_nothing,
    parse_insert,
    translate,
    _split_statements,
)

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
requires_pg = pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against real Postgres")


# --------------------------------------------------------------------------- #
# Translation
# --------------------------------------------------------------------------- #

def test_parameter_markers_are_converted():
    assert translate("SELECT * FROM t WHERE a=? AND b=?") == "SELECT * FROM t WHERE a=%s AND b=%s"


def test_question_marks_inside_string_literals_are_left_alone():
    """A '?' in a LIKE pattern or a JSON default is data. Rewriting it to %s
    corrupts the query, and does so silently -- the statement still runs."""
    sql = "SELECT * FROM t WHERE name LIKE 'who? what?' AND a=?"
    out = translate(sql)
    assert "'who? what?'" in out, "literal was rewritten"
    assert out.endswith("a=%s")
    assert out.count("%s") == 1


def test_autoincrement_primary_keys_become_serial():
    out = translate("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)")
    assert "BIGSERIAL PRIMARY KEY" in out
    assert "AUTOINCREMENT" not in out.upper()


def test_type_spellings_are_mapped():
    out = translate("CREATE TABLE t (a BLOB, b DATETIME, c REAL)")
    assert "BYTEA" in out and "TIMESTAMPTZ" in out and "DOUBLE PRECISION" in out


def test_sqlite_date_functions_are_translated():
    assert "now()" in translate("SELECT datetime('now')")
    assert "interval '7 days'" in translate("SELECT datetime('now', '-7 days')")
    assert "-" in translate("SELECT datetime('now', '-7 days')")
    assert "+" in translate("SELECT datetime('now', '+1 hour')")
    assert "to_char" in translate("SELECT strftime('%Y-%m-%d', created_at) FROM t")


def test_insert_variants_are_recognised():
    assert needs_do_nothing("INSERT OR IGNORE INTO t (a) VALUES (?)")
    assert is_or_replace("INSERT OR REPLACE INTO t (a) VALUES (?)")
    assert not is_or_replace("INSERT INTO t (a) VALUES (?)")
    assert parse_insert("INSERT OR REPLACE INTO admin_orgs (id, name) VALUES (?,?)") == (
        "admin_orgs", ["id", "name"]
    )


def test_script_splitting_ignores_semicolons_in_literals():
    parts = _split_statements("CREATE TABLE a (x TEXT DEFAULT 'p;q'); CREATE TABLE b (y TEXT);")
    assert len(parts) == 2
    assert "'p;q'" in parts[0]


# --------------------------------------------------------------------------- #
# Round trip against real Postgres
# --------------------------------------------------------------------------- #

@pytest.fixture()
def pg_shim():
    psycopg2 = pytest.importorskip("psycopg2")
    from psycopg2.extras import DictCursor
    conn = psycopg2.connect(PG_DSN, cursor_factory=DictCursor)
    shim = PostgresConnectionShim(conn)
    yield shim
    shim.rollback()
    shim.close()


@pytest.fixture()
def sqlite_conn(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


SCHEMA = """
    CREATE TABLE IF NOT EXISTS fs_orgs (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        plan        TEXT NOT NULL DEFAULT 'free',
        max_scans   INTEGER NOT NULL DEFAULT 500,
        created_at  TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS fs_audit (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id      TEXT,
        action      TEXT NOT NULL,
        created_at  TEXT NOT NULL
    );
"""


@requires_pg
def test_schema_and_crud_behave_identically_on_both_backends(pg_shim, sqlite_conn):
    """The same statements, unmodified, against both engines."""
    pg_shim.execute("DROP TABLE IF EXISTS fs_audit")
    pg_shim.execute("DROP TABLE IF EXISTS fs_orgs")
    pg_shim.commit()

    for conn in (pg_shim, sqlite_conn):
        conn.executescript(SCHEMA)
        conn.commit()

    org_id = uuid.uuid4().hex[:8]
    insert = "INSERT INTO fs_orgs (id,name,plan,max_scans,created_at) VALUES (?,?,?,?,?)"
    params = (org_id, "Acme", "pro", 900, "2026-01-01T00:00:00Z")

    results = []
    for conn in (pg_shim, sqlite_conn):
        conn.execute(insert, params)
        conn.commit()
        row = conn.execute("SELECT * FROM fs_orgs WHERE id=?", (org_id,)).fetchone()
        # Addressable by name AND by position, like sqlite3.Row.
        results.append((row["id"], row["name"], row["plan"], int(row["max_scans"]), row[0]))

    assert results[0] == results[1], "Postgres and SQLite disagreed on a plain round trip"
    assert results[0][0] == org_id


@requires_pg
def test_insert_or_replace_upserts_on_the_primary_key(pg_shim, sqlite_conn):
    pg_shim.execute("DROP TABLE IF EXISTS fs_orgs")
    pg_shim.commit()
    for conn in (pg_shim, sqlite_conn):
        conn.executescript(SCHEMA)
        conn.commit()

    org_id = uuid.uuid4().hex[:8]
    stmt = "INSERT OR REPLACE INTO fs_orgs (id,name,plan,max_scans,created_at) VALUES (?,?,?,?,?)"

    for conn in (pg_shim, sqlite_conn):
        conn.execute(stmt, (org_id, "First", "free", 100, "2026-01-01T00:00:00Z"))
        conn.execute(stmt, (org_id, "Second", "pro", 900, "2026-01-02T00:00:00Z"))
        conn.commit()

    for conn in (pg_shim, sqlite_conn):
        rows = conn.execute("SELECT name, plan FROM fs_orgs WHERE id=?", (org_id,)).fetchall()
        assert len(rows) == 1, "OR REPLACE must not leave a duplicate"
        assert rows[0]["name"] == "Second"
        assert rows[0]["plan"] == "pro"


@requires_pg
def test_insert_or_ignore_keeps_the_first_write(pg_shim, sqlite_conn):
    pg_shim.execute("DROP TABLE IF EXISTS fs_orgs")
    pg_shim.commit()
    for conn in (pg_shim, sqlite_conn):
        conn.executescript(SCHEMA)
        conn.commit()

    org_id = uuid.uuid4().hex[:8]
    stmt = "INSERT OR IGNORE INTO fs_orgs (id,name,plan,max_scans,created_at) VALUES (?,?,?,?,?)"

    for conn in (pg_shim, sqlite_conn):
        conn.execute(stmt, (org_id, "First", "free", 100, "2026-01-01T00:00:00Z"))
        conn.execute(stmt, (org_id, "Second", "pro", 900, "2026-01-02T00:00:00Z"))
        conn.commit()
        row = conn.execute("SELECT name FROM fs_orgs WHERE id=?", (org_id,)).fetchone()
        assert row["name"] == "First", "OR IGNORE must not overwrite"


@requires_pg
def test_autoincrement_ids_and_lastrowid_work(pg_shim, sqlite_conn):
    pg_shim.execute("DROP TABLE IF EXISTS fs_audit")
    pg_shim.commit()
    for conn in (pg_shim, sqlite_conn):
        conn.executescript(SCHEMA)
        conn.commit()

    for conn in (pg_shim, sqlite_conn):
        cur = conn.execute(
            "INSERT INTO fs_audit (org_id,action,created_at) VALUES (?,?,?)",
            ("o1", "created", "2026-01-01T00:00:00Z"),
        )
        first_id = cur.lastrowid
        conn.commit()
        assert isinstance(first_id, int) and first_id >= 1

        cur = conn.execute(
            "INSERT INTO fs_audit (org_id,action,created_at) VALUES (?,?,?)",
            ("o1", "updated", "2026-01-02T00:00:00Z"),
        )
        assert cur.lastrowid == first_id + 1, "ids must increment"
        conn.commit()


@requires_pg
def test_executescript_is_idempotent_so_services_can_call_it_per_request(pg_shim):
    """Services call _init_tables() on every operation; running the DDL twice
    must be harmless on Postgres as it is on SQLite."""
    pg_shim.execute("DROP TABLE IF EXISTS fs_orgs")
    pg_shim.execute("DROP TABLE IF EXISTS fs_audit")
    pg_shim.commit()

    pg_shim.executescript(SCHEMA)
    pg_shim.commit()
    pg_shim.executescript(SCHEMA)  # must not raise
    pg_shim.commit()

    row = pg_shim.execute("SELECT count(*) AS n FROM fs_orgs").fetchone()
    assert int(row["n"]) == 0


@requires_pg
def test_translated_date_functions_actually_execute_on_postgres(pg_shim):
    """Matching a regex is not evidence the output is valid SQL. These run."""
    pg_shim.execute("DROP TABLE IF EXISTS fs_orgs")
    pg_shim.executescript(SCHEMA)
    pg_shim.commit()
    pg_shim.execute(
        "INSERT INTO fs_orgs (id,name,plan,max_scans,created_at) VALUES (?,?,?,?,?)",
        ("d1", "Acme", "free", 10, "2026-01-15T00:00:00Z"),
    )
    pg_shim.commit()

    # datetime('now', '-N days') as a comparison bound
    row = pg_shim.execute(
        "SELECT count(*) AS n FROM fs_orgs WHERE created_at::timestamptz > datetime('now', '-10000 days')"
    ).fetchone()
    assert int(row["n"]) == 1

    # strftime month/day bucketing
    row = pg_shim.execute(
        "SELECT strftime('%Y-%m-%d', created_at) AS d FROM fs_orgs WHERE id=?", ("d1",)
    ).fetchone()
    assert row["d"] == "2026-01-15"

    row = pg_shim.execute(
        "SELECT strftime('%Y-%m', created_at) AS m FROM fs_orgs WHERE id=?", ("d1",)
    ).fetchone()
    assert row["m"] == "2026-01"
