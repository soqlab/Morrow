"""Dual-dialect connection for the auxiliary feature tables.

Background
----------
The core tables (assets, scans, remediations, organizations, ...) have a
hand-written Postgres layer in db_postgres.py -- one function per operation. That
approach does not scale to the rest of the product: ~66 auxiliary tables live
across 32 service modules with roughly 965 raw SQL statements between them, and
every one of those modules opens its own sqlite3 connection. While they stay on
SQLite the platform is limited to a single API replica (see
/platform/state/coverage and the readiness gate), because SQLite is not a network
database -- which rules out horizontal scale, HA, and zero-downtime deploys.

Rewriting 965 statements by hand is neither safe nor necessary. The statements
themselves are almost entirely portable; what is not portable is the *dialect*:
parameter markers, a handful of DDL spellings, the SQLite-only upsert forms, and
the SQLite date functions. So this module presents the small slice of the
sqlite3.Connection API those services actually use, backed by either SQLite or
Postgres, and translates at the boundary.

A service migrates by changing where it gets its connection. Its SQL is untouched,
which is what keeps each module's migration reviewable.

Surveyed API surface this must cover (counts across services/ at time of writing):
    conn.execute 239 | fetchone/fetchall 212 | row_factory 49 | cursor() 27
    AUTOINCREMENT 22 | strftime/datetime() 24 | INSERT OR REPLACE/IGNORE 13
    executescript 6 | lastrowid 3 | executemany 1

Rows
----
Both backends yield rows addressable by column name *and* by position, matching
sqlite3.Row, so `row["email"]` and `row[0]` keep working either way.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = __import__("logging").getLogger(__name__)


# --------------------------------------------------------------------------- #
# Dialect selection
# --------------------------------------------------------------------------- #

def postgres_enabled() -> bool:
    """True when auxiliary feature state should live in Postgres.

    Deliberately a separate switch from the core-table backend: the core tables
    can be on Postgres while auxiliary state is still being migrated module by
    module, and an operator needs to be able to move one without the other.
    """
    flag = (os.getenv("PQC_FEATURE_STORE_BACKEND") or "").strip().lower()
    if flag in ("postgres", "postgresql", "pg"):
        return True
    if flag in ("sqlite", "file"):
        return False
    try:
        from db_postgres import postgres_main_db_requested
        return bool(postgres_main_db_requested())
    except Exception:
        return False


def dialect() -> str:
    return "postgres" if postgres_enabled() else "sqlite"


def _feature_dsn() -> str:
    from db_postgres import product_database_url
    return product_database_url()


def _sqlite_path() -> str:
    from db import DB_PATH
    return os.environ.get("PQC_SCANNER_DB", DB_PATH)


# --------------------------------------------------------------------------- #
# SQL translation
# --------------------------------------------------------------------------- #

_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")


def _split_outside_literals(sql: str) -> List[Tuple[str, bool]]:
    """Split SQL into (chunk, is_string_literal) parts.

    Every rewrite below must skip string literals: a '?' inside a LIKE pattern or
    a JSON blob is data, not a parameter marker, and rewriting it corrupts the
    query silently.
    """
    parts: List[Tuple[str, bool]] = []
    last = 0
    for match in _STRING_LITERAL.finditer(sql):
        if match.start() > last:
            parts.append((sql[last:match.start()], False))
        parts.append((match.group(0), True))
        last = match.end()
    if last < len(sql):
        parts.append((sql[last:], False))
    return parts


def _map_outside_literals(sql: str, fn) -> str:
    return "".join(chunk if is_lit else fn(chunk) for chunk, is_lit in _split_outside_literals(sql))


# DDL type and keyword spellings that differ. Order matters: the AUTOINCREMENT
# rule must run before the bare INTEGER rule would otherwise see it.
_DDL_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.I), "BIGSERIAL PRIMARY KEY"),
    (re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\b(?!\s*\()", re.I), "BIGSERIAL PRIMARY KEY"),
    (re.compile(r"\bAUTOINCREMENT\b", re.I), ""),
    # Negative lookahead for "(": DATETIME is a column type, datetime(...) is a
    # SQLite function handled below. Without it, `datetime('now')` was rewritten
    # to `TIMESTAMPTZ('now')` -- a cast that happens to parse, so the damage
    # showed up as wrong data rather than an error.
    (re.compile(r"\bDATETIME\b(?!\s*\()", re.I), "TIMESTAMPTZ"),
    (re.compile(r"\bBLOB\b", re.I), "BYTEA"),
    (re.compile(r"\bIFNULL\s*\(", re.I), "COALESCE("),
    # SQLite tolerates these; Postgres does not need them and REAL is a distinct
    # (lower precision) type there, so use double precision.
    (re.compile(r"\bREAL\b", re.I), "DOUBLE PRECISION"),
]

# SQLite date/time functions -> Postgres equivalents.
_DATETIME_RULES: List[Tuple[re.Pattern, Any]] = [
    # datetime('now') / datetime('now', '-7 days') / datetime('now','+1 hour')
    (re.compile(r"\bdatetime\s*\(\s*'now'\s*\)", re.I), "now()"),
    (re.compile(r"\bdatetime\s*\(\s*'now'\s*,\s*'([+-]?\d+)\s+(\w+)'\s*\)", re.I),
     lambda m: f"(now() {'-' if m.group(1).startswith('-') else '+'} interval '{m.group(1).lstrip('+-')} {m.group(2)}')"),
    (re.compile(r"\bstrftime\s*\(\s*'%Y-%m-%d'\s*,\s*([^)]+)\)", re.I),
     lambda m: f"to_char(({m.group(1)})::timestamptz, 'YYYY-MM-DD')"),
    (re.compile(r"\bstrftime\s*\(\s*'%Y-%m'\s*,\s*([^)]+)\)", re.I),
     lambda m: f"to_char(({m.group(1)})::timestamptz, 'YYYY-MM')"),
    (re.compile(r"\bstrftime\s*\(\s*'%s'\s*,\s*([^)]+)\)", re.I),
     lambda m: f"extract(epoch from ({m.group(1)})::timestamptz)::bigint"),
]


def translate(sql: str) -> str:
    """Rewrite a SQLite statement into its Postgres equivalent.

    Handles only what the surveyed statements actually use. Anything it does not
    recognise passes through unchanged, so an unsupported construct surfaces as a
    loud Postgres syntax error during that module's migration rather than as
    silently wrong data.
    """
    # Pass 1: the SQLite date/time functions, over the whole statement.
    #
    # These must NOT be literal-aware, because the thing that identifies them is
    # itself a literal -- datetime('now'), strftime('%Y-%m-%d', ...). Running
    # them per non-literal chunk means the pattern straddles a chunk boundary and
    # never matches, which is a silent no-op: the statement is handed to Postgres
    # still containing a SQLite-only function.
    for pattern, repl in _DATETIME_RULES:
        sql = pattern.sub(repl, sql)

    # Pass 2: type spellings and parameter markers, skipping string literals so a
    # '?' or a type name appearing inside data is left alone. Literals introduced
    # by pass 1 (interval '7 days') are correctly skipped here.
    def _rewrite(chunk: str) -> str:
        for pattern, repl in _DDL_RULES:
            chunk = pattern.sub(repl, chunk)
        # Parameter markers last, so the rules above see the original text.
        return chunk.replace("?", "%s")

    sql = _map_outside_literals(sql, _rewrite)

    # SQLite's upsert shorthands have no direct Postgres spelling.
    sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.I)
    return sql


def needs_do_nothing(original_sql: str) -> bool:
    return bool(re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", original_sql, re.I))


def is_or_replace(original_sql: str) -> bool:
    return bool(re.search(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", original_sql, re.I))


_INSERT_TARGET = re.compile(
    r"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.I
)


def parse_insert(sql: str) -> Optional[Tuple[str, List[str]]]:
    """Return (table, [columns]) for an INSERT, or None if it is not one."""
    match = _INSERT_TARGET.search(sql)
    if not match:
        return None
    columns = [c.strip().strip('"') for c in match.group(2).split(",") if c.strip()]
    return match.group(1), columns


# --------------------------------------------------------------------------- #
# Postgres connection shim
# --------------------------------------------------------------------------- #

class _PgCursorShim:
    """Presents the parts of sqlite3.Cursor the services use."""

    def __init__(self, cursor, conn):
        self._cursor = cursor
        self._conn = conn

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size=None):
        return self._cursor.fetchmany(size) if size else self._cursor.fetchmany()

    def __iter__(self):
        return iter(self._cursor)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    @property
    def lastrowid(self):
        """SQLite exposes the new rowid directly; Postgres needs the sequence.

        lastval() is session-scoped, and this shim holds one connection per
        session, so it cannot pick up another writer's value.
        """
        try:
            self._cursor.execute("SELECT lastval()")
            row = self._cursor.fetchone()
            return int(row[0]) if row else None
        except Exception:
            return None

    def execute(self, sql: str, params: Sequence[Any] = ()):
        return self._conn.execute(sql, params, cursor=self)

    def close(self):
        try:
            self._cursor.close()
        except Exception:
            pass


class PostgresConnectionShim:
    """sqlite3.Connection-shaped facade over a psycopg2 connection."""

    def __init__(self, conn):
        self._conn = conn
        self._pk_cache: Dict[str, List[str]] = {}
        # Accepted and ignored: rows are always name- and index-addressable here,
        # so a service setting `conn.row_factory = sqlite3.Row` still works.
        self.row_factory = None

    # -- helpers ---------------------------------------------------------- #

    def _primary_key(self, table: str) -> List[str]:
        if table in self._pk_cache:
            return self._pk_cache[table]
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT a.attname
            FROM pg_index i
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = %s::regclass AND i.indisprimary
            ORDER BY a.attnum
            """,
            (table,),
        )
        keys = [r[0] for r in cur.fetchall()]
        cur.close()
        self._pk_cache[table] = keys
        return keys

    def _apply_upsert(self, original_sql: str, translated: str) -> str:
        """Give the SQLite upsert shorthands a Postgres conflict clause."""
        if needs_do_nothing(original_sql):
            return translated.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

        if not is_or_replace(original_sql):
            return translated

        parsed = parse_insert(original_sql)
        if not parsed:
            raise ValueError(f"cannot translate INSERT OR REPLACE: {original_sql[:120]}")
        table, columns = parsed
        keys = self._primary_key(table)
        if not keys:
            # No primary key means SQLite's REPLACE would have inserted a new row
            # anyway, so a plain INSERT preserves the behaviour.
            return re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "INSERT INTO", translated, flags=re.I)
        updates = [c for c in columns if c not in keys]
        translated = re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "INSERT INTO", translated, flags=re.I)
        conflict = ", ".join(f'"{k}"' for k in keys)
        if not updates:
            return translated.rstrip().rstrip(";") + f" ON CONFLICT ({conflict}) DO NOTHING"
        assignments = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in updates)
        return translated.rstrip().rstrip(";") + f" ON CONFLICT ({conflict}) DO UPDATE SET {assignments}"

    # -- sqlite3.Connection surface --------------------------------------- #

    def execute(self, sql: str, params: Sequence[Any] = (), cursor: Optional[_PgCursorShim] = None):
        translated = self._apply_upsert(sql, translate(sql))
        target = cursor._cursor if cursor is not None else self._conn.cursor()
        target.execute(translated, tuple(params) if params else None)
        return cursor if cursor is not None else _PgCursorShim(target, self)

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]):
        translated = self._apply_upsert(sql, translate(sql))
        cur = self._conn.cursor()
        cur.executemany(translated, [tuple(p) for p in seq_of_params])
        return _PgCursorShim(cur, self)

    def executescript(self, script: str):
        """Run a multi-statement DDL script.

        Each statement is executed separately and CREATE TABLE / CREATE INDEX
        failures are tolerated the way `IF NOT EXISTS` would be, because a
        least-privilege runtime role may legitimately lack DDL rights -- the
        schema is then expected to have been applied by the migration role.
        """
        cur = self._conn.cursor()
        for statement in _split_statements(script):
            translated = translate(statement)
            if not translated.strip():
                continue
            try:
                cur.execute(translated)
            except Exception as exc:  # noqa: BLE001 - see docstring
                self._conn.rollback()
                if _is_ddl(translated) and _is_benign_ddl_error(exc):
                    logger.debug("feature store DDL skipped: %s", str(exc)[:160])
                    continue
                cur.close()
                raise
        cur.close()
        return self

    def cursor(self):
        return _PgCursorShim(self._conn.cursor(), self)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        return False


_DDL_START = re.compile(r"^\s*(CREATE|DROP|ALTER)\b", re.I)


def _is_ddl(sql: str) -> bool:
    return bool(_DDL_START.match(sql))


def _is_benign_ddl_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "already exists" in text
        or "permission denied" in text
        or "must be owner" in text
    )


def _split_statements(script: str) -> List[str]:
    """Split a DDL script on semicolons that are not inside string literals."""
    statements: List[str] = []
    current: List[str] = []
    for chunk, is_lit in _split_outside_literals(script):
        if is_lit:
            current.append(chunk)
            continue
        buffer = ""
        for char in chunk:
            if char == ";":
                current.append(buffer)
                statements.append("".join(current))
                current, buffer = [], ""
            else:
                buffer += char
        current.append(buffer)
    tail = "".join(current)
    if tail.strip():
        statements.append(tail)
    return [s for s in statements if s.strip()]


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

_LOCAL = threading.local()


def integrity_errors() -> Tuple[type, ...]:
    """Exception classes meaning "a constraint rejected this write".

    sqlite3.IntegrityError and psycopg2.IntegrityError share no common base, so
    `except sqlite3.IntegrityError` silently stops catching anything the moment a
    module is moved to Postgres -- turning a handled duplicate into a 500.
    """
    errors: List[type] = [sqlite3.IntegrityError]
    try:
        import psycopg2
        errors.append(psycopg2.IntegrityError)
    except Exception:
        pass
    return tuple(errors)


INTEGRITY_ERRORS = integrity_errors()


@contextmanager
def atomic(conn):
    """Scope a statement that is *expected* to be able to fail a constraint.

    The try-insert / on-error-update idiom is portable in spirit but not in
    behaviour: SQLite lets the connection carry on after a failed statement,
    while Postgres marks the whole transaction aborted, so every following
    statement fails with "current transaction is aborted" until a rollback. A
    SAVEPOINT confines the damage to the failed statement.

    On SQLite this is a no-op, so callers write one code path:

        try:
            with atomic(conn):
                conn.execute(insert, params)
        except INTEGRITY_ERRORS:
            conn.execute(update, params)
    """
    if isinstance(conn, PostgresConnectionShim):
        name = f"sp_{uuid.uuid4().hex[:12]}"
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except Exception:
            conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            raise
        else:
            conn.execute(f"RELEASE SAVEPOINT {name}")
    else:
        yield conn


@contextmanager
def feature_conn():
    """Yield a connection for auxiliary feature state, in whichever dialect is active.

    Callers use it exactly as they used `closing(sqlite3.connect(path))`:

        with feature_conn() as conn:
            conn.execute("INSERT INTO admin_orgs (...) VALUES (?, ?)", (a, b))
            conn.commit()
    """
    if postgres_enabled():
        import psycopg2
        from psycopg2.extras import DictCursor
        conn = psycopg2.connect(_feature_dsn(), cursor_factory=DictCursor)
        # Several feature tables (billing, support access, usage rollups, API keys, feedback) carry
        # a per-customer organization_id and are covered by the row-level-security plan. Publishing
        # the caller's tenant here is what lets those policies evaluate; without it every one of
        # them would return zero rows the moment the plan was applied. See services/tenant_scope.py.
        from services.tenant_scope import apply_to_connection

        apply_to_connection(conn)
        shim = PostgresConnectionShim(conn)
        try:
            yield shim
        finally:
            shim.close()
    else:
        path = _sqlite_path()
        conn = None
        try:
            from db import pooled_sqlite_connection
            conn = pooled_sqlite_connection(path)  # the server's connection pool, when it serves this file
        except ImportError:
            conn = None
        if conn is None:
            conn = sqlite3.connect(path, timeout=5.0)
            try:
                # Same settings as db.get_connection() uses on this file. The journal is already WAL (a
                # property of the file); FULL made every journal/audit commit fsync while holding the
                # single write lock, which queued every other writer behind it.
                conn.execute("PRAGMA synchronous=NORMAL")
            except sqlite3.Error:
                pass
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
