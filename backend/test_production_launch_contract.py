"""Production launch checks must reject unsafe settings and missing evidence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("pwsh") or shutil.which("powershell")


def test_pyjwt_unverified_inspection_cannot_mutate_claim_verification_options():
    secret = "test-only-jwt-signing-key-not-for-deployment"
    token = jwt.encode({"sub": "test-user", "exp": 1}, secret, algorithm="HS256")
    options = {"verify_signature": False}
    assert jwt.decode(token, options=options)["sub"] == "test-user"
    assert options == {"verify_signature": False}
    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, secret, algorithms=["HS256"], options=options)


def test_pyjwt_accepts_signature_padding_but_rejects_non_alphabet_junk():
    secret = "test-only-jwt-signing-key-not-for-deployment"
    token = jwt.encode({"sub": "test-user", "exp": 4102444800}, secret, algorithm="HS256")
    header, payload, signature = token.split(".")
    padded = ".".join((header, payload, signature + "=" * (-len(signature) % 4)))
    assert jwt.decode(padded, secret, algorithms=["HS256"])["sub"] == "test-user"
    with pytest.raises(jwt.DecodeError):
        jwt.decode(token + "!!!!", secret, algorithms=["HS256"])


def test_ai_off_deployment_needs_no_external_provider_key(monkeypatch):
    import app
    from test_platform_admin_readiness import test_production_startup_guard_allows_safe_config
    test_production_startup_guard_allows_safe_config(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert app._assert_production_startup_safe() == []


@pytest.mark.parametrize("name,value,expected", [
    ("DEFAULT_USER_ROLE", "operator", "must be viewer"),
    ("AUTH_JWT_JWKS_URL", "http://login.invalid/keys", "HTTPS"),
    ("AUTH_JWT_JWKS_URL", "https://secret:password@login.invalid/keys", "credential-free"),
    ("AUTH_JWT_ALGORITHMS", ["none"], "implemented JWT algorithms"),
])
def test_production_startup_rejects_unsafe_auth(monkeypatch, name, value, expected):
    import app
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(app, name, value)
    assert any(expected in item for item in app._production_startup_blockers())


def test_no_expiry_escape_hatch_cannot_bypass_production(monkeypatch):
    import app
    secret = "test-signing-only-not-for-production-" * 2
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(app, "AUTH_JWT_ALGORITHMS", ["HS256"])
    monkeypatch.setattr(app, "AUTH_JWT_SECRET", secret)
    monkeypatch.setenv("MORROW_JWT_ALLOW_NO_EXP", "1")
    token = jwt.encode({"sub": "test-admin", "role": "admin"}, secret, algorithm="HS256")
    payload, error = app._verified_jwt_payload_from_auth_header("Bearer " + token)
    assert payload == {} and "expiry" in error
    assert any("MORROW_JWT_ALLOW_NO_EXP" in item for item in app._production_startup_blockers())


def test_launch_gate_includes_startup_safety_and_override(monkeypatch):
    import app
    monkeypatch.setattr(app, "_platform_readiness_result", lambda: {"checks": []})
    monkeypatch.setattr(app._operator_auth, "go_live_checks", lambda: [])
    monkeypatch.setattr(app, "_gate_blocking_warnings", lambda: [])
    monkeypatch.setattr(app, "_production_startup_blockers", lambda: ["Test unsafe setting"])
    assert not app._platform_go_live_gate_result()["go_live_allowed"]
    monkeypatch.setattr(app, "_production_startup_blockers", lambda: [])
    monkeypatch.setenv("MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP", "1")
    assert not app._platform_go_live_gate_result()["go_live_allowed"]


def test_jwks_size_and_redirect_controls(monkeypatch):
    import app
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(app, "AUTH_JWT_JWKS_URL", "https://login.invalid/keys")
    monkeypatch.setattr(app, "_JWKS_CACHE", {"url": "", "loaded_at": 0, "keys": []})
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, size):
            assert size == 1048577
            return b"x" * size
        def open(self, *args, **kwargs):
            return self
    monkeypatch.setattr(app.urllib.request, "build_opener", lambda *args: Response())
    with pytest.raises(ValueError, match="size limit"):
        app._jwks_keys()
    with pytest.raises(ValueError, match="redirect"):
        app._JWTNoRedirect().redirect_request(None)


def _ps(script, *args):
    env = {k: v for k, v in os.environ.items() if k not in {"MORROW_PLATFORM_ADMIN_KEY", "MORROW_OPERATOR_SESSION"}}
    return subprocess.run([SHELL, "-NoProfile", "-File", str(ROOT / "scripts" / script), *args],
                          cwd=ROOT, env=env, capture_output=True, timeout=45)


@pytest.mark.skipif(not SHELL, reason="PowerShell is required to execute launch scripts")
def test_deployment_verification_fails_before_network_without_operator_auth():
    result = _ps("verify-cloud-deployment.ps1", "-BaseUrl", "https://deployment.invalid")
    assert result.returncode != 0
    assert b"authentication is required" in result.stderr


@pytest.mark.skipif(not SHELL, reason="PowerShell is required to execute launch scripts")
def test_deployment_verification_refuses_plaintext_remote_credentials():
    result = _ps("verify-cloud-deployment.ps1", "-BaseUrl", "http://deployment.invalid", "-PlatformKey", "not-real")
    assert result.returncode != 0
    assert b"require HTTPS" in result.stderr


@pytest.mark.skipif(not SHELL, reason="PowerShell is required to execute launch scripts")
@pytest.mark.parametrize("redirect", [False, True])
def test_deployment_verification_uses_session_and_fails_closed(redirect):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            requests.append((self.path, self.headers.get("Cookie")))
            if self.path == "/platform/go-live-gate":
                if redirect:
                    self.send_response(302)
                    self.send_header("Location", "/untrusted")
                    self.end_headers()
                    return
                result = {"go_live_allowed": True, "status": "go", "required_failed": 1,
                          "failed_required_checks": [{"key": "unsafe"}], "warnings": []}
            else:
                result = {"status": "ok", "mode": "production", "defaults": {"dry_run": True}}
            self.send_response(200)
            for header in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Content-Security-Policy"):
                self.send_header(header, "present")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = _ps("verify-cloud-deployment.ps1", "-BaseUrl", f"http://127.0.0.1:{server.server_port}",
                     "-OperatorSession", "throwaway-test-session")
        assert result.returncode != 0
        assert ("/platform/readiness", "morrow_admin_session=throwaway-test-session") in requests
        assert not any(path == "/untrusted" for path, _ in requests)
        assert not any(cookie for path, cookie in requests if path in {"/status", "/health"})
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)


@pytest.mark.skipif(not shutil.which("docker"), reason="Docker CLI is required for Compose interpolation")
def test_production_compose_passes_customer_claims_operator_sso_and_ai_settings(tmp_path):
    envfile = tmp_path / "compose.env"
    values = {"MORROW_AUTH_ROLE_CLAIM": "https://tenant.invalid/role", "MORROW_AUTH_ORG_ID_CLAIM": "https://tenant.invalid/org",
              "MORROW_ADMIN_OIDC_ISSUER": "https://staff.invalid", "MORROW_ADMIN_OIDC_CLIENT_ID": "test-client",
              "MORROW_ADMIN_OPERATOR_ROLES": "test@staff.invalid=owner", "MORROW_PUBLIC_BASE_URL": "https://app.invalid",
              "MORROW_AI_LOCAL_URL": "https://model.invalid/v1/chat/completions", "MORROW_AI_LOCAL_MODEL": "test-local",
              "MORROW_AI_DEPLOYMENT_LOCATION": "customer", "OPENAI_AGENT_MODEL": "test-approved-model"}
    envfile.write_text("\n".join(f"{key}={value}" for key, value in values.items()), encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith(("MORROW_", "OPENAI_", "ANTHROPIC_"))}
    result = subprocess.run(["docker", "compose", "--env-file", str(envfile), "-f", str(ROOT / "docker-compose.prod.yml"), "config", "--format", "json"],
                            env=env, capture_output=True, timeout=30)
    assert result.returncode == 0
    services = json.loads(result.stdout)["services"]
    for name in ("api", "worker", "beat"):
        config = services[name]["environment"]
        assert all(config[key] == value for key, value in values.items())
        assert config["MORROW_ADMIN_REQUIRE_MFA"] == "1"
        assert config["MORROW_ALLOW_BREAK_GLASS_KEY"] == "0"
    assert services["api"]["ports"][0]["host_ip"] == "127.0.0.1"


@pytest.mark.skipif(not SHELL, reason="PowerShell is required to execute launch scripts")
@pytest.mark.parametrize("change,expected", [
    ({}, None),
    ({"MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP": "1"}, "startup_override"),
    ({"MORROW_ADMIN_REQUIRE_MFA": "0"}, "operator_mfa"),
    ({"CELERY_RESULT_BACKEND": "rediss://:password@cache.invalid:6379/1?ssl_cert_reqs=none"}, "redis_tls:CELERY_RESULT_BACKEND"),
    ({"SENTRY_DSN": ""}, "sentry"),
])
def test_strict_preflight_supports_ai_off_and_verified_redis_tls(tmp_path, change, expected):
    conf = {
        "MORROW_ENVIRONMENT": "production", "MORROW_VAULT_MASTER_KEY": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        "MORROW_PLATFORM_ADMIN_KEY": "b" * 64, "MORROW_AUTH_REQUIRED": "1", "MORROW_AUTH_MODE": "jwt",
        "MORROW_AUTH_ISSUER_ENABLED": "0", "MORROW_DEFAULT_ROLE": "viewer", "MORROW_ALLOWED_HOSTS": "app.invalid",
        "MORROW_AIRLOCK_SIGNING_KEY": "c" * 64, "MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE": "1",
        "MORROW_AUTH_JWT_ISSUER": "https://login.invalid/", "MORROW_AUTH_JWT_AUDIENCE": "airlock",
        "MORROW_AUTH_JWT_JWKS_URL": "https://login.invalid/keys", "MORROW_CORS_ORIGINS": "https://app.invalid",
        "DATABASE_URL": "postgresql://runtime:password@db.invalid:5432/app?sslmode=require",
        "CELERY_BROKER_URL": "rediss://:password@cache.invalid:6379/0?ssl_cert_reqs=required",
        "CELERY_RESULT_BACKEND": "rediss://:password@cache.invalid:6379/1?ssl_cert_reqs=required",
        "MORROW_CSP_VALUE": "default-src 'self'", "SENTRY_DSN": "https://public@monitor.invalid/1",
        "MORROW_TRAFFIC_PERSIST_TO_DB": "1", "MORROW_PUBLIC_BASE_URL": "https://app.invalid",
        "MORROW_ADMIN_OIDC_ISSUER": "https://staff.invalid", "MORROW_ADMIN_OIDC_CLIENT_ID": "staff-client",
        "MORROW_ADMIN_OPERATOR_ROLES": "owner@company.invalid=owner", **change,
    }
    target = tmp_path / "launch.env"
    target.write_text("\n".join(f"{key}={value}" for key, value in conf.items()), encoding="utf-8")
    # The preflight accepts paths relative to the repository root.
    result = _ps("prod-preflight.ps1", "-EnvFile", os.path.relpath(target, ROOT), "-Strict", "-Json")
    report = json.loads(result.stdout.decode("utf-8-sig"))
    assert "ai_provider" not in {item["check"] for item in report["checks"]}
    if expected:
        assert result.returncode != 0
        assert any(item["check"] == expected and item["severity"] in {"blocker", "warning"} for item in report["checks"])
    else:
        # A machine without Docker may report a tooling warning; never call that a clean pass.
        assert not report["blockers"]
        assert result.returncode == (1 if report["warnings"] else 0)
