"""
Pytest session-level configuration.
Sets required environment variables before any test module imports app.py,
so module-level constants (e.g. auth_issuer._SECRET) are populated correctly.
"""
import os

import pytest

# Must be set before app.py / services/auth_issuer.py are imported.
os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")

# Bootstrap creates no account when MORROW_ADMIN_PASSWORD is unset. Tests that sign in as the
# seeded admin explicitly supply a throwaway secret, never a deployment credential.
os.environ.setdefault("MORROW_ADMIN_PASSWORD", "changeme123!")

# Vault operations require a valid Fernet key (32 url-safe base64 bytes). Without it, anything that
# stores an integration secret raises "MORROW_VAULT_MASTER_KEY is required for Vault operations".
# This is a fixed throwaway key so the vault-backed tests are deterministic — never a real one.
# base64url of b"morrow-test-only-key-32byte" (exactly 32 bytes, as Fernet requires).
os.environ.setdefault("MORROW_VAULT_MASTER_KEY", "cHFjLXNjYW5uZXItdGVzdC1vbmx5LWtleS0zMmJ5dGU=")


def _isolate_test_database():
    """Run the suite against a private copy of backend/morrow.db, never the file itself.

    Without this, every suite that does not pick its own temp database wrote into the same SQLite file
    a locally running server (port 8001) serves -- the smoke test alone sends a request to every write
    endpoint -- so a test run held that file's single write lock for minutes and the console stalled.
    A copy keeps the data tests have always seen. Set MORROW_SCANNER_DB to choose a database explicitly.
    """
    if os.environ.get("MORROW_SCANNER_DB"):
        return
    import atexit
    import shutil
    import sqlite3
    import tempfile
    from contextlib import closing

    workdir = tempfile.mkdtemp(prefix="pq-pytest-db-")
    target = os.path.join(workdir, "morrow.db")
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "morrow.db")
    if os.path.exists(source):
        with closing(sqlite3.connect(source, timeout=30)) as src, closing(sqlite3.connect(target)) as dst:
            src.backup(dst)  # consistent snapshot even while a server is writing
    os.environ["MORROW_SCANNER_DB"] = target
    atexit.register(shutil.rmtree, workdir, True)


_isolate_test_database()


def _reload(*names):
    import importlib
    import sys
    for name in names:
        module = sys.modules.get(name)
        if module is not None:
            try:
                importlib.reload(module)
            except Exception:
                pass


# Module-level constants that several suites clobber by reloading app.py under a temporary
# environment. Their values are the fingerprint we compare before and after each test.
_APP_STATE_KEYS = (
    "DEFAULT_ORG_ID", "AUTH_MODE", "AUTH_REQUIRED", "DEFAULT_USER_ROLE",
    "_PLATFORM_ADMIN_KEY", "AUTH_JWT_ALGORITHMS",
)


def _module_fingerprint():
    """Snapshot the global state that leaks between suites, or None if app is not imported yet."""
    import sys
    app_mod = sys.modules.get("app")
    if app_mod is None:
        return None
    db_mod = sys.modules.get("db")
    return (
        tuple(repr(getattr(app_mod, key, None)) for key in _APP_STATE_KEYS),
        repr(getattr(db_mod, "DB_PATH", None)) if db_mod is not None else "",
        os.environ.get("MORROW_SCANNER_DB", ""),
    )


#: Every environment variable that decides which database the process talks to. A test module that
#: changes one of these and does not put it back hands the next module its private database.
_DATABASE_ENV_KEYS = (
    "MORROW_SCANNER_DB", "MORROW_MAIN_DB_BACKEND", "MORROW_FEATURE_STORE_BACKEND",
    "MORROW_PRODUCT_DATABASE_URL", "DATABASE_URL",
)


@pytest.fixture(autouse=True, scope="module")
def _restore_database_selection_between_modules():
    """Put the database selection back at the end of every test module.

    The per-test fixture below cannot reach this. A module-scoped fixture is finalized *after* the
    last test's function-scoped fixtures, so a module fixture that does

        tmp_db = tempfile.NamedTemporaryFile(delete=False)
        os.environ["MORROW_SCANNER_DB"] = tmp_db.name
        ...
        yield client
        os.remove(tmp_db.name)          # the file goes; the environment variable stays

    leaves MORROW_SCANNER_DB pointing at its private database (often one that has just been deleted)
    for every module that runs after it. Half a dozen modules do exactly that. The next module
    then runs against a database the copy isolation above never seeded, which is why
    test_wave17.py failed with "no such table: morrow_users" depending only on what ran before it.

    This fixture is module-scoped, so it is set up before anything in the module and torn down
    after everything in it, including those fixtures. It restores the selection and, when the
    database actually changed, clears the schema-creation memo in db -- which is keyed by path, so
    a path whose file was deleted and recreated would otherwise be treated as already migrated.
    """
    before = {key: os.environ.get(key) for key in _DATABASE_ENV_KEYS}

    yield

    import sys
    changed = False
    for key, value in before.items():
        if os.environ.get(key) != value:
            changed = True
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    db_module = sys.modules.get("db")
    if not changed and db_module is not None:
        # A module that restored the variable itself may still have deleted the file it pointed
        # at. The memo is keyed by path, so a later module that happens to reuse that path would
        # be told its schema is already there.
        memo = getattr(db_module, "_schema_initialized_db_path", None)
        changed = bool(memo) and not os.path.exists(memo)
    if not changed:
        return
    if db_module is not None:
        # The memo says "this path already has the schema". After a module has pointed the process
        # at another file (and possibly deleted it), that is no longer something to believe.
        db_module._schema_initialized.clear()
        db_module._schema_initialized_db_path = None
        db_module._SCHEMA_ONCE.clear()
        db_module._WEBHOOK_CLAIM_COLUMNS_READY.clear()
        try:
            db_module.disable_connection_pool()
        except Exception:
            pass
    _reload("db", "events", "app")


@pytest.fixture(autouse=True)
def _restore_global_module_state():
    """Undo process-global state that a test leaves behind, so it cannot cascade into other suites.

    Two distinct leaks are covered:

    1. MORROW_SCANNER_DB. db.get_connection() re-reads it on every call, so a test that points it at a
       temp file and does not put it back leaves the rest of the pytest process talking to a database
       that no longer exists ("sqlite3.OperationalError: unable to open database file").

    2. importlib.reload(app) under temporary env vars. monkeypatch faithfully restores the
       environment, but the reloaded module keeps the constants it computed from the temporary
       values (DEFAULT_ORG_ID, AUTH_MODE, _PLATFORM_ADMIN_KEY, db.DB_PATH, ...). Any later module
       that imports app then sees another suite's configuration.

    Being autouse, this fixture is set up before the test's own fixtures and therefore torn down
    after them — including after monkeypatch has already restored the environment, which is what
    makes reloading here resolve the ambient values rather than the temporary ones.

    Tests that mutate this state should still clean up after themselves; this is a backstop, and it
    only pays the cost of reloading when it detects an actual change.
    """
    sentinel = object()
    env_before = os.environ.get("MORROW_SCANNER_DB", sentinel)
    fp_before = _module_fingerprint()

    yield

    if os.environ.get("MORROW_SCANNER_DB", sentinel) != env_before:
        if env_before is sentinel:
            os.environ.pop("MORROW_SCANNER_DB", None)
        else:
            os.environ["MORROW_SCANNER_DB"] = env_before

    if fp_before is None:
        return
    if _module_fingerprint() == fp_before:
        return
    # Rebuild from the ambient environment. db/events first so app picks up their fresh state.
    _reload("db", "events", "app")
