"""The real migration entrypoint must fail if any deferred schema failed."""

import json
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("failed,expected_exit", [
    ([], 0),
    ([{"name": "unavailable_schema", "error": "test failure"}], 1),
])
def test_migration_exit_matches_deferred_schema_result(monkeypatch, capsys, failed, expected_exit):
    entrypoint = Path(__file__).with_name("entrypoint.sh").read_text(encoding="utf-8")
    commands = [shlex.split(line.strip()) for line in entrypoint.splitlines()
                if line.strip().startswith("exec python3 -c")]
    assert len(commands) == 1
    result = {"applied": ["available_schema"], "failed": failed, "count": 1 + len(failed)}
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "db_postgres", SimpleNamespace(apply_deferred_schemas=lambda: result))
    with pytest.raises(SystemExit) as stopped:
        exec(compile(commands[0][3], "entrypoint.sh migration command", "exec"), {})
    assert stopped.value.code == expected_exit
    output = capsys.readouterr().out
    assert json.loads(output.split("deferred schemas: ", 1)[1]) == result
