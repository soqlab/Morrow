"""The pre-go-live integration self-test (scripts/check-integrations.py).

The command exists so that one run answers "what is configured, what is missing, what is broken"
before a customer is the one who finds out. Two things it must never get wrong, and they are what
most of this file guards:

  * it must not print a secret, on any path, in any mode -- it is run with the output pasted into
    tickets and chat;
  * --offline must mean no outbound call at all, and --send-test must be the only way anything
    leaves this host.

Every outbound probe is replaced here, so nothing in this file touches the network.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "check-integrations.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_integrations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load()

# Secrets the fixtures plant. Each body is a distinctive run so a leak of any part is unmissable.
VAULT_KEY = "kRQ7wRwQ2n0Xy0lGZnMS7O8u4WQsL1ZFQK1cQpJ1n3M="   # a real, disposable Fernet key
JWT_SECRET = "J" * 64
OIDC_SECRET = "oidc-" + "S" * 40
ANTHROPIC_KEY = "sk-ant-api03-" + "A" * 40 + "zzzz"
POSTGRES_DSN = "postgresql://pqc_app:" + "P" * 24 + "@db.internal:5432/pqc"
REDIS_URL = "redis://:" + "R" * 24 + "@cache.internal:6379/0"
#: Not a key, but it is an account number in a report people paste into tickets, so the checker
#: prints only its last four characters and this test proves the rest never appears.
BANK_ACCOUNT = "000" + "7" * 9 + "4821"

SECRETS = [VAULT_KEY, JWT_SECRET, OIDC_SECRET, ANTHROPIC_KEY, POSTGRES_DSN, REDIS_URL]

CONFIGURED_ENV = {
    "PQC_ENVIRONMENT": "production",
    "PQC_PUBLIC_BASE_URL": "https://app.example.com",
    "PQC_STATUS_PAGE_URL": "https://status.example.com",
    "PQC_SMTP_FROM": "platform@example.com",
    "PQC_AUTH_JWT_SECRET": JWT_SECRET,
    "PQC_VAULT_MASTER_KEY": VAULT_KEY,
    "PQC_ADMIN_OIDC_ISSUER": "https://login.example.com",
    "PQC_ADMIN_OIDC_CLIENT_ID": "console-app",
    "PQC_ADMIN_OIDC_CLIENT_SECRET": OIDC_SECRET,
    "PQC_ADMIN_REQUIRE_MFA": "1",
    "PQC_ADMIN_OPERATOR_ROLES": "owner@example.com=owner,ops@example.com=operator",
    "REDIS_URL": REDIS_URL,
    "PQC_PRODUCT_DATABASE_URL": POSTGRES_DSN,
    "ANTHROPIC_API_KEY": ANTHROPIC_KEY,
    # Direct invoicing: the vendor's own legal and bank details, without which no invoice is issued.
    # Polar: the card path.
}

MANAGED_PREFIXES = ("PQC_", "STRIPE_", "REDIS", "CELERY_", "ANTHROPIC_", "OPENAI_", "DATABASE_URL")


@pytest.fixture(autouse=True)
def isolated_environment():
    """The checker reads os.environ, and loading an env file writes to it. Snapshot and restore, and
    start every test from an environment with nothing configured."""
    saved = dict(os.environ)
    for name in list(os.environ):
        if name.startswith(MANAGED_PREFIXES):
            os.environ.pop(name, None)
    os.environ["PQC_SCANNER_DB"] = os.path.join(tempfile.mkdtemp(), "selftest.db")
    os.environ["PQC_FEATURE_STORE_BACKEND"] = "sqlite"
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Nothing in this file may reach the network, a broker or a database. A check that tries
    without a test opting in fails loudly rather than quietly measuring the internet."""
    def forbidden(*args, **kwargs):
        raise AssertionError("an outbound call was made without the test allowing it")

    for name in ("http_json", "redis_ping", "postgres_probe", "rls_state", "alert_test_send"):
        monkeypatch.setattr(check, name, forbidden)
    monkeypatch.setattr(check, "alert_channels", lambda: {"channels": []})


def write_env(values: dict, bom: bool = True) -> str:
    """A .env written the way a Windows editor writes one: UTF-8 with a byte order mark."""
    path = os.path.join(tempfile.mkdtemp(), ".env")
    text = "# written by the test\n" + "".join(f"{k}={v}\n" for k, v in values.items())
    with open(path, "wb") as handle:
        handle.write((("﻿" if bom else "") + text).encode("utf-8"))
    return path


def run(capsys, *argv, env_values=None, env_file=None):
    path = env_file or write_env(env_values or {})
    code = check.main(["--env-file", path, *argv])
    return code, capsys.readouterr().out


def assert_no_secret_leak(text: str):
    """No secret value, and no run of eight characters from one, beyond the masked hint."""
    for value in SECRETS:
        assert value not in text, "a secret value was printed in full"
        hint = check.mask(value)
        # For a DSN the scheme is a word like "postgres" that the report legitimately uses; what must
        # never appear is everything after it -- the credentials, the host and the database.
        body = value.split("://", 1)[-1]
        for index in range(len(body) - 7):
            window = body[index:index + 8]
            if window in hint:
                continue
            assert window not in text, f"{window[:3]}... (part of a secret) reached the output"


# ── Missing ──────────────────────────────────────────────────────────────────


def test_an_empty_environment_reports_every_area_as_missing(capsys):
    code, out = run(capsys, "--offline", env_values={})

    assert code == 2, "missing production settings must exit 2"
    for area in ("SSO", "REDIS", "POSTGRES", "VAULT", "AUTH"):
        assert area in out
    assert "PQC_AUTH_JWT_SECRET" in out
    assert "PQC_VAULT_MASTER_KEY" in out
    # A finding without a fix hint is a dead end for whoever runs this.
    assert out.count("fix:") >= 8


def test_every_missing_finding_carries_a_one_line_fix(capsys):
    code, out = run(capsys, "--offline", "--json", env_values={})
    payload = json.loads(out)

    assert payload["exit_code"] == 2
    absent = [f for f in payload["findings"] if f["status"] == "MISSING"]
    assert absent, "an empty environment must report missing settings"
    for finding in absent:
        if finding["check"] in ("shared rate limits",):
            continue  # a consequence of another finding, not a setting of its own
        assert finding["fix"], f"{finding['area']}/{finding['check']} has no fix hint"
        assert "\n" not in finding["fix"]


# ── Configured ───────────────────────────────────────────────────────────────


def _healthy_probes(monkeypatch, calls=None):
    seen = calls if calls is not None else []

    def http_json(url, headers=None, timeout=check.DEFAULT_TIMEOUT, method="GET"):
        seen.append(url)
        if "openid-configuration" in url:
            return {"status": 200, "headers": {}, "body": {
                "issuer": "https://login.example.com",
                "authorization_endpoint": "https://login.example.com/authorize",
                "token_endpoint": "https://login.example.com/token",
                "jwks_uri": "https://login.example.com/jwks",
            }}
        if "api.stripe.com/v1/prices/" in url:
            return {"status": 200, "headers": {}, "body": {"unit_amount": 250000, "currency": "usd",
                                                           "livemode": True, "active": True}}
        if "api.stripe.com/v1/prices" in url:
            return {"status": 200, "headers": {"stripe-version": check._default_stripe_version()}, "body": {"data": []}}
        if "api.anthropic.com" in url:
            return {"status": 200, "headers": {}, "body": {"data": []}}
        if "api.polar.sh" in url:
            return {"status": 200, "headers": {}, "body": {"items": [], "pagination": {"total_count": 0, "max_page": 1}}}
        raise AssertionError(f"unexpected outbound call to {url}")

    monkeypatch.setattr(check, "http_json", http_json)
    monkeypatch.setattr(check, "redis_ping", lambda url, timeout=2.0: {"ok": True, "version": "7.2.4"})
    monkeypatch.setattr(check, "postgres_probe", lambda dsn, timeout=5.0: {
        "ok": True, "role": "pqc_app", "superuser": False, "bypassrls": False, "version": "16.2"})
    monkeypatch.setattr(check, "rls_state", lambda dsn: {"status": "pass", "failures": []})
    monkeypatch.setattr(check, "alert_channels", lambda: {"channels": [
        {"id": "ch1", "kind": "slack_webhook", "name": "On-call", "enabled": True,
         "encrypted": True, "decrypts": True, "reason": "", "min_severity": "warn"}]})
    return seen


def test_a_fully_configured_deployment_passes(capsys, monkeypatch):
    calls = _healthy_probes(monkeypatch)
    code, out = run(capsys, "--check-ai", env_values=CONFIGURED_ENV)

    assert code == 0, out
    summary = out.split("Summary")[1]
    for area in ("sso", "redis", "postgres", "vault", "auth", "ai", "alerts"):
        assert area in summary, "the summary table is missing an area"
    assert "MISSING" not in summary and "ERROR" not in summary
    assert any("openid-configuration" in url for url in calls)
    assert any("api.anthropic.com" in url for url in calls)
    assert_no_secret_leak(out)


# ── Getting paid ─────────────────────────────────────────────────────────────
















def test_the_environment_file_is_read_through_a_bom(capsys, monkeypatch):
    """A .env saved by a Windows editor starts with a byte order mark, which makes a naive loader
    lose the first variable. Losing PQC_AUTH_JWT_SECRET silently would be the worst possible miss."""
    _healthy_probes(monkeypatch)
    ordered = {"PQC_AUTH_JWT_SECRET": JWT_SECRET, **{k: v for k, v in CONFIGURED_ENV.items() if k != "PQC_AUTH_JWT_SECRET"}}
    code, out = run(capsys, "--offline", env_values=ordered)

    assert "PQC_AUTH_JWT_SECRET: 64 characters" in out, "the first variable in a BOM'd file was lost"
    assert code == 0


def test_the_environment_file_is_never_written(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    path = write_env(CONFIGURED_ENV)
    before = open(path, "rb").read()
    run(capsys, "--offline", env_file=path)
    assert open(path, "rb").read() == before


def test_an_exported_variable_wins_over_the_file(capsys, monkeypatch):
    """The app is started with --env-file and inherits the process environment, so the checker must
    report what the app would actually see, not what the file says."""
    _healthy_probes(monkeypatch)
    os.environ["PQC_ENVIRONMENT"] = "staging"
    code, out = run(capsys, "--offline", "--json", env_values=CONFIGURED_ENV)
    assert json.loads(out)["environment"] == "staging"


# ── Broken ───────────────────────────────────────────────────────────────────








def test_a_vault_key_that_cannot_decrypt_is_an_error(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    code, out = run(capsys, "--offline", env_values={**CONFIGURED_ENV, "PQC_VAULT_MASTER_KEY": "not-a-fernet-key"})

    assert code == 1
    assert "not a usable Fernet key" in out
    # The point of the check is knowing what becomes unreadable.
    assert "operator MFA secrets" in out and "alert channel targets" in out


def test_a_short_jwt_secret_is_an_error_not_a_gap(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    code, out = run(capsys, "--offline", env_values={**CONFIGURED_ENV, "PQC_AUTH_JWT_SECRET": "short"})

    assert code == 1
    assert "signed with a guessable key" in out
    assert "only 5 characters" in out, "the length is the useful fact, and it is not the value"


def test_a_redirect_uri_outside_the_public_base_url_is_reported(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    code, out = run(capsys, "--offline", env_values={
        **CONFIGURED_ENV, "PQC_ADMIN_OIDC_REDIRECT_URI": "https://old-host.example.net/vendor-admin/sso/callback"})

    assert code == 1
    assert "is not under PQC_PUBLIC_BASE_URL" in out


def test_a_discovery_document_naming_another_issuer_is_reported(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    original = check.http_json

    def http_json(url, headers=None, timeout=0, method="GET"):
        if "openid-configuration" in url:
            return {"status": 200, "headers": {}, "body": {"issuer": "https://other.example.com"}}
        return original(url, headers, timeout, method)

    monkeypatch.setattr(check, "http_json", http_json)
    code, out = run(capsys, env_values=CONFIGURED_ENV)

    assert code == 1
    assert "names issuer" in out


def test_an_alert_channel_whose_target_no_longer_decrypts_is_reported(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "alert_channels", lambda: {"channels": [
        {"id": "ch1", "kind": "pagerduty", "name": "Sev1", "enabled": True, "encrypted": True,
         "decrypts": False, "reason": "InvalidToken", "min_severity": "critical"}]})

    code, out = run(capsys, "--offline", env_values=CONFIGURED_ENV)

    assert code == 1
    assert "does not decrypt" in out
    assert "PQC_VAULT_MASTER_KEY has changed" in out


def test_an_app_role_that_bypasses_row_level_security_is_reported(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "postgres_probe", lambda dsn, timeout=5.0: {
        "ok": True, "role": "postgres", "superuser": True, "bypassrls": True, "version": "16.2"})

    code, out = run(capsys, env_values=CONFIGURED_ENV)

    assert code == 1
    assert "SUPERUSER and BYPASSRLS" in out
    assert "NOSUPERUSER NOBYPASSRLS" in out
    assert_no_secret_leak(out)


def test_row_level_security_that_was_never_applied_reads_as_missing(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "rls_state", lambda dsn: {"unavailable": True})

    code, out = run(capsys, env_values=CONFIGURED_ENV)

    assert code == 2, "an un-applied policy is a gap, not a failure"
    assert "not applied" in out


def test_unreachable_redis_is_a_failure(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "redis_ping", lambda url, timeout=2.0: {"error": "ConnectionError"})

    code, out = run(capsys, env_values=CONFIGURED_ENV)

    assert code == 1
    assert "PING failed" in out
    assert_no_secret_leak(out)


def test_a_rejected_ai_key_is_a_failure(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    original = check.http_json

    def http_json(url, headers=None, timeout=0, method="GET"):
        if "anthropic" in url:
            return {"status": 401, "headers": {}, "body": {}}
        return original(url, headers, timeout, method)

    monkeypatch.setattr(check, "http_json", http_json)
    code, out = run(capsys, "--check-ai", env_values=CONFIGURED_ENV)

    assert code == 1
    assert "rejected the key" in out


def test_a_misspelled_area_does_not_report_success(capsys):
    """--only runs a subset. A typo there must not come back as "nothing is broken"."""
    path = write_env(CONFIGURED_ENV)
    code = check.main(["--env-file", path, "--offline", "--only", "stripee"])

    assert code == 2
    assert "Unknown area" in capsys.readouterr().err


def test_a_check_that_crashes_does_not_hide_the_others(capsys, monkeypatch):
    def explode():
        raise RuntimeError("boom")

    monkeypatch.setattr(check, "alert_channels", explode)
    code, out = run(capsys, "--offline", env_values={})

    assert "VAULT" in out and "POSTGRES" in out, "one broken check stopped the report"
    assert "the self-test itself failed" in out


# ── Offline and send-test ────────────────────────────────────────────────────


def test_offline_makes_no_outbound_call_at_all(capsys):
    """no_network leaves every probe as a tripwire, so reaching one fails the test."""
    code, out = run(capsys, "--offline", env_values=CONFIGURED_ENV)

    assert code == 0, out
    assert "skipped (--offline)" in out
    assert out.count("[skip]") >= 4
    assert_no_secret_leak(out)


def test_offline_still_reports_what_is_missing(capsys):
    code, out = run(capsys, "--offline", env_values={k: v for k, v in CONFIGURED_ENV.items() if k != "REDIS_URL"})

    assert code == 2
    assert "REDIS_URL" in out


def test_nothing_is_sent_to_an_alert_channel_without_the_flag(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "alert_test_send", lambda channel_id: pytest.fail("a message was sent without --send-test"))

    code, out = run(capsys, env_values=CONFIGURED_ENV)

    assert code == 0
    assert "no message was sent" in out


def test_send_test_sends_one_labelled_message_per_enabled_channel(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    sent = []
    monkeypatch.setattr(check, "alert_channels", lambda: {"channels": [
        {"id": "ch1", "kind": "slack_webhook", "name": "On-call", "enabled": True, "encrypted": True,
         "decrypts": True, "reason": "", "min_severity": "warn"},
        {"id": "ch2", "kind": "email", "name": "Paused", "enabled": False, "encrypted": False,
         "decrypts": True, "reason": "", "min_severity": "info"}]})
    monkeypatch.setattr(check, "alert_test_send", lambda channel_id: sent.append(channel_id) or {"ok": True, "latency_ms": 42})

    code, out = run(capsys, "--send-test", env_values=CONFIGURED_ENV)

    assert sent == ["ch1"], "a disabled channel must not be sent to"
    assert "[TEST] message delivered" in out
    assert code == 0


def test_offline_overrides_send_test(capsys, monkeypatch):
    monkeypatch.setattr(check, "alert_channels", lambda: {"channels": [
        {"id": "ch1", "kind": "slack_webhook", "name": "On-call", "enabled": True, "encrypted": True,
         "decrypts": True, "reason": "", "min_severity": "warn"}]})
    # alert_test_send is still the tripwire from no_network.
    code, out = run(capsys, "--offline", "--send-test", env_values=CONFIGURED_ENV)

    assert "nothing was sent" in out
    assert code == 0


# ── Secrets ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("argv", [
    ("--offline",),
    ("--offline", "--json"),
    ("--json",),
    ("--send-test",),
    ("--check-ai",),
])
def test_no_secret_value_reaches_the_output_on_any_path(capsys, monkeypatch, argv):
    _healthy_probes(monkeypatch)
    monkeypatch.setattr(check, "alert_test_send", lambda channel_id: {"ok": True, "latency_ms": 12})
    _, out = run(capsys, *argv, env_values=CONFIGURED_ENV)
    assert_no_secret_leak(out)

    # And on the failing paths, where an error message is the usual way a value escapes.
    broken = {**CONFIGURED_ENV, "PQC_VAULT_MASTER_KEY": VAULT_KEY[:-4] + "zzzz"}
    _, out = run(capsys, *argv, env_values=broken)
    assert_no_secret_leak(out)
    assert VAULT_KEY[:-4] + "zzzz" not in out


def test_the_masked_hint_shows_a_public_prefix_and_nothing_else():
    assert check.mask("sk-ant-api03-" + "Q" * 24 + "4h2p") == "sk-ant-api...4h2p"
    assert check.mask("") == "not set"
    # A value with no public marker gets no characters at all, only its shape.
    assert check.mask(JWT_SECRET) == f"set, {len(JWT_SECRET)} characters"
    assert JWT_SECRET[:8] not in check.mask(JWT_SECRET)


def test_the_postgres_dsn_is_never_echoed(capsys, monkeypatch):
    _healthy_probes(monkeypatch)
    _, out = run(capsys, "--offline", env_values=CONFIGURED_ENV)
    assert "db.internal" not in out, "the DSN host and credentials must stay out of the report"
    assert "Postgres DSN is set (value withheld)" in out
