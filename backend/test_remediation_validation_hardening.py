import io
import os
import sys
import tempfile
import zipfile

import pytest

import remediation_validation as rv


def test_safe_relative_path_rejects_traversal():
    assert rv._safe_relative_path("/infra/main.tf") == "infra/main.tf"
    with pytest.raises(RuntimeError):
        rv._safe_relative_path("../secrets.tf")
    with pytest.raises(RuntimeError):
        rv._safe_relative_path("infra/../../secrets.tf")


def test_repository_archive_rejects_zip_slip(monkeypatch):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as zf:
        zf.writestr("../evil.txt", "owned")

    monkeypatch.setattr(
        rv,
        "_github_api",
        lambda *_args, **_kwargs: {"ok": True, "raw_bytes": raw.getvalue()},
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(RuntimeError):
            rv._download_repo_archive("acme", "demo", "main", "token", tmpdir)
        assert not os.path.exists(os.path.join(tmpdir, "..", "evil.txt"))


def test_validation_subprocess_environment_scrubs_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    with tempfile.TemporaryDirectory() as tmpdir:
        result = rv._run_command(
            [sys.executable, "-c", "import os; print(os.getenv('OPENAI_API_KEY', ''))"],
            cwd=tmpdir,
            timeout_s=10,
        )
    assert result["exit_code"] == 0
    assert "must-not-leak" not in result["stdout"]
