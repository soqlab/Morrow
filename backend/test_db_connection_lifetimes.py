"""SQLite transaction scopes must also release the underlying connection."""

import ast
from pathlib import Path
import sqlite3

import pytest


def test_db_helpers_never_use_bare_connection_transaction_contexts():
    tree = ast.parse(Path(__file__).with_name("db.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                assert not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                            and call.func.id == "get_connection"), (
                    f"db.py:{node.lineno}: sqlite3 context exit commits but does not close; "
                    "use closing(get_connection()) plus a transaction scope"
                )


@pytest.mark.parametrize("pooled", [False, True])
def test_webhook_connections_release_on_success_and_error(monkeypatch, tmp_path, pooled):
    import db

    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "lifetimes.db"))
    monkeypatch.setenv("MORROW_SQLITE_POOL", "1")
    db.disable_connection_pool()
    db.init_db()
    if pooled:
        db.enable_connection_pool()
    original = db.get_connection
    held = []

    def tracked():
        connection = original()
        held.append(connection)  # Retain it: garbage collection must not hide a leak.
        return connection

    def assert_released():
        assert held
        for connection in held:
            if pooled:
                assert connection._pool_idle
            else:
                with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                    connection.execute("SELECT 1")
        held.clear()

    monkeypatch.setattr(db, "get_connection", tracked)
    try:
        saved = db.upsert_webhook(name="lifetime", url="https://example.invalid/hook")
        assert_released()
        assert db.list_webhooks()[0]["id"] == saved["id"]
        assert_released()
        with pytest.raises(RuntimeError, match="failed to upsert"):
            db.upsert_webhook(name="absent", url="https://example.invalid/hook", webhook_id=999999)
        assert_released()
        db.delete_webhook(saved["id"])
        assert_released()
        assert db.list_webhooks() == []
        assert_released()
    finally:
        db.disable_connection_pool()
