"""Execute report scripts against controlled HTTP failures, never a real deployment."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("pwsh") or shutil.which("powershell")
SCRIPTS = ["go-live-report.ps1", "release-evidence-bundle.ps1"]
pytestmark = pytest.mark.skipif(not SHELL, reason="PowerShell is required for report contract tests")


def run_script(script, *args):
    env = {key: value for key, value in os.environ.items()
           if key not in {"PQC_PLATFORM_ADMIN_KEY", "PQC_OPERATOR_SESSION"}}
    return subprocess.run([SHELL, "-NoProfile", "-File", str(ROOT / "scripts" / script), *args],
                          cwd=ROOT, env=env, capture_output=True, timeout=60)


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("credential", [False, True])
def test_reports_reject_missing_auth_or_remote_plaintext(script, credential):
    args = ["-BaseUrl", "http://deployment.invalid" if credential else "https://deployment.invalid"]
    if credential:
        args += ["-OperatorSession", "test-only-session"]
    result = run_script(script, *args)
    assert result.returncode != 0
    assert (b"require HTTPS" if credential else b"authentication is required") in result.stderr


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("scenario", ["pass", "contradictory_gate", "tenant_failure", "redirect"])
def test_report_evidence_is_session_authenticated_and_fail_closed(script, scenario, tmp_path):
    check_report(script, scenario, tmp_path)


@pytest.mark.parametrize("scenario", ["child_verifier_failure", "traffic_failure"])
def test_bundle_cannot_ignore_failed_collections_or_child_commands(scenario, tmp_path):
    check_report("release-evidence-bundle.ps1", scenario, tmp_path)


def check_report(script, scenario, tmp_path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.do_GET()

        def do_GET(self):
            requests.append((self.path, self.headers.get("Cookie")))
            result = {"status": "ok", "mode": "production", "defaults": {"dry_run": True}}
            if self.path == "/platform/go-live-gate":
                if scenario == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "/untrusted")
                    self.end_headers()
                    return
                result = {"go_live_allowed": True, "status": "go", "required_failed": 0,
                          "failed_required_checks": [], "warnings": []}
                if scenario == "contradictory_gate":
                    result.update(required_failed=1, failed_required_checks=[{"key": "unsafe"}])
            elif self.path == "/platform/tenant-isolation/verify":
                result = {"status": "fail" if scenario == "tenant_failure" else "pass"}
            elif self.path == "/platform/retention/policy" and scenario == "child_verifier_failure":
                result = {"defaults": {"dry_run": False}}
            elif self.path.startswith("/platform/traffic/export") and scenario == "traffic_failure":
                self.send_response(503)
                self.end_headers()
                return
            self.send_response(200)
            for name in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                         "Permissions-Policy", "Content-Security-Policy"):
                self.send_header(name, "present")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = run_script(script, "-BaseUrl", f"http://127.0.0.1:{server.server_port}",
                            "-OperatorSession", "test-only-session", "-OutDir", str(tmp_path))
        assert (result.returncode == 0) == (scenario == "pass"), result.stderr.decode(errors="replace")
        assert ("/platform/readiness", "pqc_admin_session=test-only-session") in requests
        assert all(cookie == "pqc_admin_session=test-only-session" for path, cookie in requests
                   if path.startswith("/platform/"))
        assert not any(cookie for path, cookie in requests if path in {"/status", "/health"})
        assert not any(path == "/untrusted" for path, _ in requests)
        if scenario != "redirect":
            reports = list(tmp_path.glob("go-live-*.json")) if script == SCRIPTS[0] else list(tmp_path.glob("*/summary.json"))
            assert len(reports) == 1
            summary = json.loads(reports[0].read_text(encoding="utf-8-sig"))
            assert summary["go_live_allowed"] is (scenario == "pass")
            assert summary["status"] == ("go" if scenario == "pass" else "no_go")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
