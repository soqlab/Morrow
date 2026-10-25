"""Run isolated regressions on disposable, loopback-only PostgreSQL and Redis.

Never connects to a configured production DSN. Requires Docker and this Python's
backend test dependencies. Only containers created by this run are removed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PG_TESTS = ["test_db_feature_store.py", "test_postgres_rls.py", "test_postgres_integration.py",
            "test_gateway_postgres.py", "test_sql_schema_conformance.py", "test_ai_data_control.py"]
SERVICE_TESTS = ["test_integration_secrets.py", "test_redis_integration.py"]


def run(suite="postgres"):
    directory = Path(tempfile.mkdtemp(prefix="pq-production-check-"))
    containers = []
    password = secrets.token_urlsafe(32)
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("MORROW_", "OPENAI_", "ANTHROPIC_", "CELERY_", "SENTRY_", "OTEL_",
                                          "GITHUB_", "AWS_", "AZURE_", "GOOGLE_", "GCLOUD_", "CLOUDSDK_", "PG"))}
    env.update({"POSTGRES_PASSWORD": password, "PYTHON_DOTENV_DISABLED": "1", "DATABASE_URL": "",
                "REDIS_URL": "", "MORROW_PRODUCT_DATABASE_URL": "", "MORROW_ENVIRONMENT": "test",
                "MORROW_MAIN_DB_BACKEND": "sqlite", "MORROW_FEATURE_STORE_BACKEND": "sqlite",
                "MORROW_SCANNER_DB": str(directory / "unit-tests.db"), "MORROW_AUTH_MODE": "headers",
                "MORROW_AUTH_REQUIRED": "0", "OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""})
    print(json.dumps({"suite": suite, "artifacts": str(directory), "status": "running"}), flush=True)

    def docker(*args, timeout=120):
        try:
            result = subprocess.run(["docker", *args], env=env, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Docker operation timed out: " + args[0]) from exc
        if result.returncode:
            raise RuntimeError("Docker operation failed: " + args[0])
        return result.stdout.decode("utf-8").strip()

    try:
        docker("info", "--format", "{{.ServerVersion}}")
        container = docker("run", "--detach", "--name", "pq-check-" + uuid.uuid4().hex,
                           "--label", "pq.purpose=disposable-production-check", "--publish", "127.0.0.1::5432",
                           "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=pq_check", "postgres:16-alpine")
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise RuntimeError("Unexpected Docker container ID; manual cleanup may be needed")
        containers.append(container)
        port = docker("port", container, "5432/tcp").split(":")[-1]
        for attempt in range(10):
            try:
                probe = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "pq_check"],
                                       capture_output=True, timeout=30, check=False)
                if not probe.returncode:
                    break
            except subprocess.TimeoutExpired:
                pass
            if attempt == 9:
                raise RuntimeError("Disposable PostgreSQL did not become ready")
            time.sleep(1)
        env["MORROW_TEST_PG_DSN"] = f"postgresql://postgres:{password}@127.0.0.1:{port}/pq_check?connect_timeout=10"
        if suite == "services":
            env.update({"DATABASE_URL": env["MORROW_TEST_PG_DSN"], "MORROW_DEFAULT_ROLE": "admin",
                        "REDIS_PASSWORD": secrets.token_urlsafe(32)})
            redis_container = docker("run", "--detach", "--name", "pq-redis-check-" + uuid.uuid4().hex,
                                     "--label", "pq.purpose=disposable-production-check",
                                     "--publish", "127.0.0.1::6379", "--env", "REDIS_PASSWORD",
                                     "redis:7-alpine", "sh", "-c",
                                     'exec redis-server --requirepass "$REDIS_PASSWORD" --save "" --appendonly no')
            if not re.fullmatch(r"[a-f0-9]{64}", redis_container):
                raise RuntimeError("Unexpected Redis container ID; manual cleanup may be needed")
            containers.append(redis_container)
            redis_port = docker("port", redis_container, "6379/tcp").split(":")[-1]
            env["REDISCLI_AUTH"] = env["REDIS_PASSWORD"]
            for attempt in range(10):
                try:
                    if docker("exec", "--env", "REDISCLI_AUTH", redis_container, "redis-cli", "ping", timeout=30) == "PONG":
                        break
                except RuntimeError:
                    pass
                if attempt == 9:
                    raise RuntimeError("Disposable Redis did not become ready")
                time.sleep(1)
            env["MORROW_TEST_REDIS_URL"] = f"redis://:{env['REDIS_PASSWORD']}@127.0.0.1:{redis_port}/1"
        tests = PG_TESTS if suite == "postgres" else SERVICE_TESTS if suite == "services" else []
        xml = directory / "tests.xml"
        with (directory / "pytest.log").open("wb") as output:
            result = subprocess.run([sys.executable, "-m", "pytest", *tests, "-q", "--tb=short", "--maxfail=12",
                                     "--junitxml=" + str(xml)], cwd=ROOT / "backend", env=env,
                                    stdout=output, stderr=subprocess.STDOUT, check=False,
                                    timeout=7200 if suite == "all" else 1800)
        tree = ET.parse(xml)
        cases = tree.findall(".//testcase")
        skipped = sum(case.find("skipped") is not None for case in cases)
        failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
        # Dedicated integration checks must actually run, not skip for missing services.
        passed = result.returncode == 0 and bool(cases) and (suite == "all" or skipped == 0)
        report = {"status": "pass" if passed else "fail", "suite": suite, "tests": len(cases),
                  "failed": failed, "skipped": skipped, "artifacts": str(directory),
                  "scope": "Disposable service regression evidence, not approval of a production deployment"}
        (directory / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report), flush=True)
        return 0 if passed else 1
    finally:
        cleanup_failed = False
        for container in reversed(containers):
            try:
                docker("rm", "--force", "--volumes", container)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                cleanup_failed = True
                print("Disposable container cleanup failed: " + container, file=sys.stderr)
        if cleanup_failed:
            raise RuntimeError("Disposable service cleanup did not complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["postgres", "services", "all"], default="postgres")
    try:
        sys.exit(run(parser.parse_args().suite))
    except (OSError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("Production check did not complete: " + detail, file=sys.stderr)
        sys.exit(1)
