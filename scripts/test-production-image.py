"""Smoke-test an existing Linux image without production credentials or network egress.

Requires Docker only. This validates packaging/startup, not a production deployment.
Every container is disposable; no host directories or published ports are used.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

API_CHECK = r'''
import json, os, secrets, socket, threading, time, urllib.request
assert os.geteuid() != 0, "The API image must not run as root"
os.environ.update(
    PYTHON_DOTENV_DISABLED="1", MORROW_ENVIRONMENT="test", WORKER_ROLE="api",
    MORROW_MAIN_DB_BACKEND="sqlite", MORROW_FEATURE_STORE_BACKEND="sqlite",
    MORROW_SCANNER_DB="/tmp/image-check.db", DATABASE_URL="", MORROW_PRODUCT_DATABASE_URL="",
    REDIS_URL="", CELERY_BROKER_URL="", CELERY_RESULT_BACKEND="",
    MORROW_AUTH_MODE="headers", MORROW_AUTH_REQUIRED="0", MORROW_DEFAULT_ROLE="viewer",
    MORROW_AUTH_JWT_SECRET=secrets.token_hex(32), MORROW_ADMIN_PASSWORD="",
    OPENAI_API_KEY="", ANTHROPIC_API_KEY="",
)
import uvicorn
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
base = "http://127.0.0.1:" + str(sock.getsockname()[1])
server = uvicorn.Server(uvicorn.Config("app:app", log_level="error", access_log=False))
thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
thread.start()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    deadline = time.monotonic() + 180
    while not server.started:
        assert thread.is_alive(), "API exited before startup completed"
        assert time.monotonic() < deadline, "API startup timed out"
        time.sleep(0.2)
    checked = []
    for path in ("/health", "/status", "/ui/ai-trust.html"):
        with opener.open(base + path, timeout=20) as response:
            assert response.status == 200, path
            body = response.read(2_000_001)
            assert len(body) <= 2_000_000, "Unexpected response size"
            assert response.headers.get("X-Content-Type-Options") == "nosniff", path
            assert response.headers.get("X-Frame-Options") == "DENY", path
            assert response.headers.get("Content-Security-Policy"), path
            if path == "/health":
                assert json.loads(body)["status"] == "ok"
            elif path == "/status":
                assert isinstance(json.loads(body), dict)
            else:
                assert b"Your data is not" in body
            checked.append(path)
    print(json.dumps({"checks": checked, "non_root": True}), flush=True)
finally:
    server.should_exit = True
    thread.join(timeout=30)
    sock.close()
    assert not thread.is_alive(), "API shutdown did not complete"
'''


def run(image, output_dir=None):
    directory = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="pq-image-check-"))
    directory.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"status": "running", "image": image, "artifacts": str(directory)}), flush=True)
    containers = []
    report = {"status": "fail", "image": image, "checks": [], "artifacts": str(directory),
              "scope": "Isolated container packaging/startup; not production launch approval"}

    def docker(*args, data=None, timeout=120):
        return subprocess.run(["docker", *args], input=data, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)

    def check(name, args, expected_exit=0, expected_text=None, data=None):
        created = docker("create", "--interactive", "--name", "pq-image-check-" + uuid.uuid4().hex,
                         "--label", "pq.purpose=disposable-image-check", "--network", "none",
                         "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *args)
        container = created.stdout.strip()
        if created.returncode or not re.fullmatch(r"[a-f0-9]{64}", container):
            raise RuntimeError("Could not create smoke-check container: " + name)
        containers.append(container)
        result = docker("start", "--attach", "--interactive", container, data=data, timeout=300)
        output = result.stdout + result.stderr
        (directory / (name + ".log")).write_text(output, encoding="utf-8")
        if result.returncode != expected_exit or (expected_text and expected_text not in output):
            raise RuntimeError("Image check failed: " + name)
        report["checks"].append(name)

    try:
        inspected = docker("image", "inspect", image, "--format", "{{.Id}}")
        image_id = inspected.stdout.strip()
        if inspected.returncode or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise RuntimeError("Image unavailable; build it before running this check")
        report["image_id"] = image_id
        check("dependency-consistency", [image_id, "python", "-m", "pip", "check"])
        for mode in ("production", "prod"):
            check("missing-config-" + mode, ["--env", "MORROW_ENVIRONMENT=" + mode, image_id],
                  expected_exit=1, expected_text="Required environment variable DATABASE_URL is not set")
        check("api-startup-and-shutdown", [image_id, "python", "-"], data=API_CHECK)
        report["status"] = "pass"
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    finally:
        for container in reversed(containers):
            try:
                if docker("rm", "--force", "--volumes", container).returncode:
                    raise RuntimeError("cleanup failed")
            except (OSError, RuntimeError, subprocess.SubprocessError):
                report["status"] = "fail"
                report.setdefault("cleanup_failed", []).append(container)
        (directory / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report), flush=True)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="An already-built Linux image tag or ID")
    parser.add_argument("--output-dir", help="Directory for logs and the JSON result (default: temporary directory)")
    options = parser.parse_args()
    raise SystemExit(run(options.image, options.output_dir))
