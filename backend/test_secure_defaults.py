"""A Morrow nobody configured must not hand out admin, and the quick start must stay on this machine."""
import os
import pathlib
import subprocess
import sys

import yaml

BACKEND = pathlib.Path(__file__).resolve().parent
ROOT = BACKEND.parent


def _default_role_at_startup(**env):
    clean = {k: v for k, v in os.environ.items() if k not in ("MORROW_DEFAULT_ROLE",)}
    clean.update(env)
    out = subprocess.run(
        [sys.executable, "-c", "import app; print(app.DEFAULT_USER_ROLE, app._DEFAULT_ROLE_FALLBACK)"],
        cwd=BACKEND, env=clean, capture_output=True, text=True, timeout=600,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.split()[-2:]


def test_unset_default_role_is_viewer_and_readiness_agrees():
    runtime, readiness_fallback = _default_role_at_startup()
    assert runtime == "viewer"
    assert readiness_fallback == runtime


def test_readiness_reports_the_role_the_app_actually_uses(monkeypatch):
    import app

    monkeypatch.delenv("MORROW_DEFAULT_ROLE", raising=False)
    check = next(c for c in app._platform_readiness_result()["checks"] if c["key"] == "default_role")
    assert check["detail"] == f"MORROW_DEFAULT_ROLE={app._DEFAULT_ROLE_FALLBACK}"


def test_quick_start_is_reachable_only_from_this_machine():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for name, service in compose["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} on every network interface"
    env = compose["services"]["app"]["environment"]
    assert str(env["MORROW_CORS_ALLOW_ALL"]) == "0"
