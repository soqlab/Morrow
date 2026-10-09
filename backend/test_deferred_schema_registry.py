"""Reloading the application must not multiply deferred migration callbacks."""

import db_postgres


def test_repeated_registration_replaces_callback_without_reordering(monkeypatch):
    monkeypatch.setattr(db_postgres, "_DEFERRED_SCHEMA_HOOKS", [])
    calls = []
    db_postgres.register_deferred_schema("first", lambda: calls.append("stale"))
    db_postgres.register_deferred_schema("second", lambda: calls.append("second"))
    for _ in range(100):
        db_postgres.register_deferred_schema("first", lambda: calls.append("current"))
    result = db_postgres.apply_deferred_schemas()
    assert calls == ["current", "second"]
    assert result == {"applied": ["first", "second"], "failed": [], "count": 2}


def test_replacement_failure_is_reported_and_other_hooks_still_run(monkeypatch):
    monkeypatch.setattr(db_postgres, "_DEFERRED_SCHEMA_HOOKS", [])
    calls = []

    def unavailable():
        raise RuntimeError("test schema unavailable")

    db_postgres.register_deferred_schema("first", lambda: calls.append("stale"))
    db_postgres.register_deferred_schema("second", lambda: calls.append("second"))
    db_postgres.register_deferred_schema("first", unavailable)
    result = db_postgres.apply_deferred_schemas()
    assert calls == ["second"]
    assert result["applied"] == ["second"]
    assert result["count"] == 2
    assert [item["name"] for item in result["failed"]] == ["first"]
