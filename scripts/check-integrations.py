#!/usr/bin/env python3
"""Integration self-test: what is configured, what is missing, what is broken.

Going live means wiring this deployment to accounts nobody but the operator holds: a way of getting
paid, an identity provider, an on-call channel, Redis, Postgres, an AI provider. Every one of them
fails in its own way and most of them fail silently -- a JWKS URL that resolves but serves the
wrong keys, a
redirect URI that does not match the public URL, a vault key that no longer decrypts what it sealed,
an alert route nobody reads. This command answers all of it in one pass, before a
customer is the one who finds out.


    python scripts/check-integrations.py                # everything, including outbound probes
    python scripts/check-integrations.py --offline      # configuration only, no network at all
    python scripts/check-integrations.py --send-test    # also send ONE labelled alert test message
    python scripts/check-integrations.py --check-ai     # also spend one cheap AI provider call
    python scripts/check-integrations.py --json         # machine-readable, same exit codes

Exit codes
    0   nothing is broken
    1   something that is configured is failing (a rejected key, an unreachable service)
    2   a required production setting is missing
    (1 wins over 2: a broken integration is the more urgent fact.)

Safety rules this file keeps
    * Nothing is ever sent to a customer. The only outbound writes are the alert test message,
      which needs the explicit --send-test flag, and it is labelled as a test.
    * No secret value is printed. A masked hint (sk-ant-api...4h2p) is shown only for values whose
      leading marker is public by design; everything else is reported as "set, N characters".
    * backend/.env is read, never written, and is loaded the same way the app loads it: BOM-tolerant
      (services/env_file.py), and it never overrides a variable already in the environment.
    * Every outbound call has a short timeout, and --offline skips all of them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(REPO_ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

DEFAULT_TIMEOUT = 6.0
STRICT_ENVIRONMENTS = frozenset({"production", "prod", "staging", "stage"})
SSO_CALLBACK_PATH = "/vendor-admin/sso/callback"

CONFIGURED = "CONFIGURED"
MISSING = "MISSING"
ERROR = "ERROR"
SKIPPED = "SKIPPED"

#: Prefixes that the issuing service itself treats as public labels, so showing them plus the last
#: four characters matches how that service's own dashboard displays the value.
PUBLIC_PREFIXES = ("sk-ant-api", "sk-proj-", "sk-")


# ── Findings ─────────────────────────────────────────────────────────────────


class Finding:
    """One line of the report. `required` marks a setting production cannot go without."""

    def __init__(self, area: str, check: str, status: str, detail: str, fix: str = "", required: bool = False):
        self.area = area
        self.check = check
        self.status = status
        self.detail = detail
        self.fix = fix
        self.required = required

    def as_dict(self) -> Dict[str, Any]:
        return {"area": self.area, "check": self.check, "status": self.status,
                "detail": self.detail, "fix": self.fix, "required": self.required}


class Report:
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def add(self, area: str, check: str, status: str, detail: str, fix: str = "", required: bool = False) -> Finding:
        finding = Finding(area, check, status, detail, fix, required)
        self.findings.append(finding)
        return finding

    def area_status(self, area: str) -> str:
        rows = [f for f in self.findings if f.area == area]
        if any(f.status == ERROR for f in rows):
            return ERROR
        if any(f.status == MISSING for f in rows):
            return MISSING
        if rows and all(f.status == SKIPPED for f in rows):
            return SKIPPED
        return CONFIGURED if rows else SKIPPED

    def areas(self) -> List[str]:
        seen: List[str] = []
        for finding in self.findings:
            if finding.area not in seen:
                seen.append(finding.area)
        return seen

    def exit_code(self) -> int:
        if any(f.status == ERROR for f in self.findings):
            return 1
        if any(f.status == MISSING and f.required for f in self.findings):
            return 2
        return 0


# ── Secret handling ──────────────────────────────────────────────────────────


def mask(value: str) -> str:
    """A hint, never the value. Recognised public prefixes keep four trailing characters (the way
    a dashboard shows a key); anything else reports only that it is set, and its length."""
    text = str(value or "")
    if not text:
        return "not set"
    for prefix in PUBLIC_PREFIXES:
        if text.startswith(prefix) and len(text) > len(prefix) + 8:
            return f"{prefix}...{text[-4:]}"
    return f"set, {len(text)} characters"


# ── Environment ──────────────────────────────────────────────────────────────


def load_environment(env_path: str) -> Tuple[bool, List[str]]:
    """Load backend/.env the way the app is started with it: BOM-tolerant, without overriding
    anything already exported. Returns (file existed, names loaded) -- never any value."""
    from services.env_file import load_env_file, repair_bom_environ

    repair_bom_environ()
    if not os.path.exists(env_path):
        return False, []
    loaded = load_env_file(env_path, override=False)
    repair_bom_environ()
    return True, loaded


def env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or default).strip()


def flag(name: str) -> Optional[bool]:
    raw = env(name).lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return None


def environment_name() -> str:
    return env("PQC_ENVIRONMENT", "local").lower() or "local"


def strict_environment() -> bool:
    return environment_name() in STRICT_ENVIRONMENTS


# ── Probes (each one is replaced wholesale by the tests) ─────────────────────


def http_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = DEFAULT_TIMEOUT,
              method: str = "GET") -> Dict[str, Any]:
    """One outbound read. Returns {"status": int, "body": dict, "headers": dict} or {"error": str}.

    Every network check in this file goes through here, so --offline and the tests have exactly one
    place to cut.
    """
    request = urllib.request.Request(url, method=method, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoints
            raw = response.read(1_000_000).decode("utf-8", errors="replace")
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                body = {}
            return {"status": int(response.status), "body": body if isinstance(body, dict) else {},
                    "headers": {k.lower(): v for k, v in response.headers.items()}}
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read(1_000_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            body = {}
        return {"status": int(exc.code), "body": body if isinstance(body, dict) else {},
                "headers": {k.lower(): v for k, v in (exc.headers or {}).items()}}
    except Exception as exc:
        return {"error": f"{exc.__class__.__name__}: {exc}"}


def redis_ping(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    try:
        import redis  # noqa: PLC0415 - optional dependency
    except Exception as exc:
        return {"error": f"the redis client is not installed ({exc.__class__.__name__})"}
    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=timeout, socket_timeout=timeout)
        client.ping()
        info = {}
        try:
            info = client.info("server") or {}
        except Exception:
            info = {}
        return {"ok": True, "version": str(info.get("redis_version") or "")}
    except Exception as exc:
        return {"error": f"{exc.__class__.__name__}"}


def postgres_probe(dsn: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Connect as the app role and report who we are and what that role may bypass."""
    try:
        import psycopg2  # noqa: PLC0415 - optional dependency
    except Exception as exc:
        return {"error": f"psycopg2 is not installed ({exc.__class__.__name__})"}
    try:
        conn = psycopg2.connect(dsn, connect_timeout=int(timeout))
    except Exception as exc:
        return {"error": f"{exc.__class__.__name__}"}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            row = cur.fetchone() or ("", None, None)
            cur.execute("SHOW server_version")
            version = (cur.fetchone() or [""])[0]
        return {"ok": True, "role": str(row[0] or ""), "superuser": bool(row[1]), "bypassrls": bool(row[2]),
                "version": str(version)}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rls_state(dsn: str) -> Dict[str, Any]:
    """Row-level security status, through the app's own verifier when it is present."""
    try:
        from services.rls_verify import verify_postgres_rls  # noqa: PLC0415 - optional, added with RLS
    except Exception:
        return {"unavailable": True}
    try:
        return verify_postgres_rls(dsn)
    except Exception as exc:
        return {"error": f"{exc.__class__.__name__}"}


def alert_channels() -> Dict[str, Any]:
    """Configured alert destinations, read from the database the app uses."""
    try:
        from services import alert_routing  # noqa: PLC0415 - needs the backend on sys.path
    except Exception as exc:
        return {"error": f"alert routing could not be loaded ({exc.__class__.__name__})"}
    try:
        channels = alert_routing.list_channels()
    except Exception as exc:
        return {"error": f"the alert channel table could not be read ({exc.__class__.__name__})"}
    out = []
    for channel in channels:
        sealed = str(channel.get("target_sealed") or "")
        decrypts, reason = True, ""
        if sealed.startswith("fernet:"):
            try:
                alert_routing.unseal(sealed)
            except Exception as exc:
                decrypts, reason = False, exc.__class__.__name__
        out.append({"id": channel.get("id"), "kind": channel.get("kind"), "name": channel.get("name"),
                    "enabled": bool(channel.get("enabled")), "encrypted": sealed.startswith("fernet:"),
                    "decrypts": decrypts, "reason": reason,
                    "min_severity": channel.get("min_severity")})
    return {"channels": out}


def alert_test_send(channel_id: str) -> Dict[str, Any]:
    try:
        from services import alert_routing  # noqa: PLC0415
        return alert_routing.test_send(channel_id)
    except Exception as exc:
        return {"ok": False, "error": f"{exc.__class__.__name__}"}


# ── Checks ───────────────────────────────────────────────────────────────────


def check_deployment(report: Report, offline: bool) -> None:
    area = "deployment"
    name = environment_name()
    report.add(area, "PQC_ENVIRONMENT", CONFIGURED if env("PQC_ENVIRONMENT") else MISSING,
               f"environment is {name}" + ("" if env("PQC_ENVIRONMENT") else " (defaulted)"),
               "Set PQC_ENVIRONMENT=production so the strict defaults (MFA, break-glass) switch on.",
               required=True)

    base = env("PQC_PUBLIC_BASE_URL").rstrip("/")
    if not base:
        report.add(area, "PQC_PUBLIC_BASE_URL", MISSING,
                   "no public base URL, so generated links and the SSO redirect have nowhere to point",
                   "Set PQC_PUBLIC_BASE_URL=https://app.your-domain.com.", required=True)
    elif not base.startswith("https://") and "localhost" not in base and "127.0.0.1" not in base:
        report.add(area, "PQC_PUBLIC_BASE_URL", ERROR, f"{base} is not https",
                   "Use an https URL; cookies are issued Secure everywhere but localhost.")
    else:
        report.add(area, "PQC_PUBLIC_BASE_URL", CONFIGURED, base)

    status = env("PQC_STATUS_PAGE_URL")
    sender = env("PQC_SMTP_FROM")
    if status or sender:
        report.add(area, "public contact", CONFIGURED,
                   "; ".join(filter(None, [f"status page {status}" if status else "",
                                           f"outbound sender {sender}" if sender else ""])))
    else:
        report.add(area, "public contact", MISSING,
                   "incident templates and platform email carry no address customers can reach",
                   "Set PQC_STATUS_PAGE_URL and PQC_SMTP_FROM to the addresses you actually watch.")


def check_auth_secret(report: Report) -> None:
    area = "auth"
    secret = env("PQC_AUTH_JWT_SECRET")
    if not secret:
        report.add(area, "PQC_AUTH_JWT_SECRET", MISSING,
                   "support sessions and issued tokens cannot be signed or verified",
                   "Generate 32+ random bytes: python -c \"import secrets;print(secrets.token_hex(32))\".",
                   required=True)
    elif len(secret) < 32:
        report.add(area, "PQC_AUTH_JWT_SECRET", ERROR,
                   f"only {len(secret)} characters; tokens are signed with a guessable key",
                   "Replace it with 32+ random characters and restart every replica.")
    else:
        report.add(area, "PQC_AUTH_JWT_SECRET", CONFIGURED,
                   f"{len(secret)} characters; support sessions and issued tokens can be signed")

    issuer_on = flag("PQC_AUTH_ISSUER_ENABLED")
    if issuer_on and strict_environment() and not flag("PQC_ALLOW_HS256_IN_PRODUCTION"):
        report.add(area, "built-in issuer", ERROR,
                   "PQC_AUTH_ISSUER_ENABLED=1 needs HS256, which production does not allow",
                   "Prefer PQC_AUTH_ISSUER_ENABLED=0 with your IdP's RS256/JWKS.")


def check_vault(report: Report) -> None:
    area = "vault"
    stores = ("customer scanner credentials (vault_credentials), operator MFA secrets and recovery "
              "codes, alert channel targets, website gateway site secrets")
    key = env("PQC_VAULT_MASTER_KEY")
    if not key:
        report.add(area, "PQC_VAULT_MASTER_KEY", MISSING,
                   f"nothing can be sealed or unsealed: {stores}",
                   "python -c \"from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())\".",
                   required=True)
        return
    try:
        from cryptography.fernet import Fernet  # noqa: PLC0415
    except Exception as exc:
        report.add(area, "PQC_VAULT_MASTER_KEY", ERROR, f"the cryptography package is unavailable ({exc.__class__.__name__})",
                   "pip install -r backend/requirements.txt.")
        return
    try:
        fernet = Fernet(key.encode("utf-8"))
        probe = "pqc-integration-self-test"
        if fernet.decrypt(fernet.encrypt(probe.encode("utf-8"))).decode("utf-8") != probe:
            raise ValueError("round trip did not return the probe value")
    except Exception as exc:
        report.add(area, "PQC_VAULT_MASTER_KEY", ERROR,
                   f"not a usable Fernet key ({exc.__class__.__name__}); these stores are unreadable: {stores}",
                   "It must be a 32-byte urlsafe-base64 key. Rotating it needs scripts/rotate-vault-master-key.py.")
        return
    report.add(area, "PQC_VAULT_MASTER_KEY", CONFIGURED,
               f"valid Fernet key, probe encrypted and decrypted; it protects {stores}")










def check_sso(report: Report, offline: bool) -> None:
    area = "sso"
    issuer = env("PQC_ADMIN_OIDC_ISSUER").rstrip("/")
    client_id = env("PQC_ADMIN_OIDC_CLIENT_ID")
    base = env("PQC_PUBLIC_BASE_URL").rstrip("/")
    redirect = env("PQC_ADMIN_OIDC_REDIRECT_URI") or (f"{base}{SSO_CALLBACK_PATH}" if base else "")

    if not issuer and not client_id:
        report.add(area, "PQC_ADMIN_OIDC_ISSUER", MISSING,
                   "operators sign in with the shared platform key only; there is no per-person identity",
                   "Register the console with your IdP and set PQC_ADMIN_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET.",
                   required=True)
    else:
        if not issuer:
            report.add(area, "PQC_ADMIN_OIDC_ISSUER", MISSING, "a client id is set but no issuer",
                       "Set PQC_ADMIN_OIDC_ISSUER to the IdP's issuer URL.", required=True)
        if not client_id:
            report.add(area, "PQC_ADMIN_OIDC_CLIENT_ID", MISSING, "no client id, so the sign-in flow cannot start",
                       "Copy the application (client) id from the IdP.", required=True)
        else:
            report.add(area, "PQC_ADMIN_OIDC_CLIENT_ID", CONFIGURED, client_id)
        if not env("PQC_ADMIN_OIDC_CLIENT_SECRET"):
            report.add(area, "PQC_ADMIN_OIDC_CLIENT_SECRET", MISSING, "the token exchange cannot be authenticated",
                       "Copy the client secret from the IdP.", required=True)

        if not redirect:
            report.add(area, "redirect URI", MISSING, "nothing to register with the IdP",
                       f"Set PQC_PUBLIC_BASE_URL (the callback is {SSO_CALLBACK_PATH}).", required=True)
        elif base and not redirect.startswith(base + "/"):
            report.add(area, "redirect URI", ERROR,
                       f"{redirect} is not under PQC_PUBLIC_BASE_URL ({base}); the IdP will refuse the callback",
                       f"Set PQC_ADMIN_OIDC_REDIRECT_URI={base}{SSO_CALLBACK_PATH} or clear it to use the default.")
        elif not redirect.endswith(SSO_CALLBACK_PATH):
            report.add(area, "redirect URI", ERROR, f"{redirect} does not end in {SSO_CALLBACK_PATH}",
                       f"The console only serves the callback at {SSO_CALLBACK_PATH}.")
        else:
            report.add(area, "redirect URI", CONFIGURED, f"{redirect} (register this exact value with the IdP)")

        if issuer and not offline:
            _check_discovery(report, area, issuer)
        elif issuer:
            report.add(area, "discovery", SKIPPED, "--offline: the issuer was not contacted",
                       "Re-run without --offline before go-live.")

    _check_roster(report, area)

    required = flag("PQC_ADMIN_REQUIRE_MFA")
    effective = strict_environment() if required is None else required
    report.add(area, "MFA policy", CONFIGURED if effective else MISSING,
               "operators must pass TOTP" if effective else f"MFA is off in this {environment_name()} environment",
               "" if effective else "Set PQC_ADMIN_REQUIRE_MFA=1 before go-live.",
               required=not effective)

    if not strict_environment():
        detail = f"the shared platform key is accepted (this is a {environment_name()} environment, not production)"
    elif flag("PQC_ALLOW_BREAK_GLASS_KEY"):
        detail = "PQC_ALLOW_BREAK_GLASS_KEY=1: the shared platform key still works, and every use is audited at severity high"
    else:
        detail = "the shared platform key is refused; SSO or a named operator key only"
    report.add(area, "break-glass key", CONFIGURED, detail)


def _check_discovery(report: Report, area: str, issuer: str) -> None:
    if not issuer.startswith("https://"):
        report.add(area, "discovery", ERROR, f"{issuer} is not https",
                   "An OIDC issuer must be https.")
        return
    result = http_json(issuer + "/.well-known/openid-configuration")
    if result.get("error"):
        report.add(area, "discovery", ERROR, f"{issuer} is unreachable ({result['error']})",
                   "Check the issuer URL and outbound HTTPS from this host.")
        return
    if int(result.get("status") or 0) >= 400:
        report.add(area, "discovery", ERROR, f"{issuer} answered HTTP {result.get('status')} for its discovery document",
                   "The issuer URL is wrong, or the tenant does not publish OIDC discovery.")
        return
    doc = result.get("body") or {}
    if str(doc.get("issuer") or "").rstrip("/") != issuer:
        report.add(area, "discovery", ERROR,
                   f"the document names issuer {doc.get('issuer')!r}, not {issuer}",
                   "Set PQC_ADMIN_OIDC_ISSUER to exactly the issuer value the document returns.")
        return
    missing = [f for f in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(f)]
    if missing:
        report.add(area, "discovery", ERROR, "the discovery document has no " + ", ".join(missing),
                   "This issuer cannot drive an authorization-code flow.")
        return
    report.add(area, "discovery", CONFIGURED, f"{issuer} is reachable and its document is valid")


def _check_roster(report: Report, area: str) -> None:
    raw = env("PQC_ADMIN_OPERATOR_ROLES")
    domains = [d.strip().lower().lstrip("@") for d in env("PQC_ADMIN_OIDC_ALLOWED_DOMAINS").split(",") if d.strip()]
    if not raw:
        if domains:
            role = env("PQC_ADMIN_OIDC_DOMAIN_ROLE", "auditor")
            report.add(area, "operator roster", CONFIGURED,
                       f"no roster; anyone at {', '.join(domains)} signs in as {role}")
        else:
            report.add(area, "operator roster", MISSING,
                       "no operator is allowed in by SSO, so a successful sign-in would still be denied",
                       'Set PQC_ADMIN_OPERATOR_ROLES="you@corp.com=owner,colleague@corp.com=operator".',
                       required=True)
        return
    try:
        from services.platform_operators import normalize_role  # noqa: PLC0415
    except Exception:
        normalize_role = None  # type: ignore[assignment]
    good, bad = {}, []
    for part in raw.replace(";", ",").replace("\n", ",").split(","):
        if not part.strip():
            continue
        email, _, role = part.partition("=")
        email = email.strip().lower()
        normalized = normalize_role(role) if normalize_role else role.strip().lower()
        if email and "@" in email and normalized:
            good[email] = normalized
        else:
            bad.append(email or part.strip())
    if bad:
        report.add(area, "operator roster", ERROR,
                   f"{len(good)} entries parsed, {len(bad)} ignored (bad address or unknown role)",
                   "Each entry is email=role with role one of owner, operator, support, auditor.")
    elif not good:
        report.add(area, "operator roster", ERROR, "the roster is set but no entry parsed",
                   'Use PQC_ADMIN_OPERATOR_ROLES="you@corp.com=owner".')
    else:
        counts: Dict[str, int] = {}
        for role in good.values():
            counts[role] = counts.get(role, 0) + 1
        report.add(area, "operator roster", CONFIGURED,
                   f"{len(good)} operators: " + ", ".join(f"{n} {r}" for r, n in sorted(counts.items())))
        if not any(r == "owner" for r in good.values()):
            report.add(area, "operator roster owner", ERROR, "no operator has the owner role",
                       "At least one entry must be email=owner, or nobody can administer the platform.")


def check_alerts(report: Report, offline: bool, send_test: bool) -> None:
    area = "alerts"
    state = alert_channels()
    if state.get("error"):
        report.add(area, "channels", ERROR, str(state["error"]),
                   "Start the app once so the platform tables exist, then re-run.")
        return
    channels = state.get("channels") or []
    if not channels:
        report.add(area, "channels", MISSING,
                   "no alert destination, so operator notifications stay inside the admin portal",
                   "Add one in the admin portal under Alert routing (Slack, PagerDuty, email or a webhook).")
        return
    enabled = [c for c in channels if c.get("enabled")]
    report.add(area, "channels", CONFIGURED if enabled else MISSING,
               f"{len(channels)} configured, {len(enabled)} enabled",
               "" if enabled else "Every channel is disabled; nothing will be delivered.")
    for channel in channels:
        label = f"{channel.get('kind')} \"{channel.get('name')}\""
        if channel.get("encrypted") and not channel.get("decrypts"):
            report.add(area, f"channel:{channel.get('id')}", ERROR,
                       f"{label}: the stored target does not decrypt ({channel.get('reason')})",
                       "PQC_VAULT_MASTER_KEY has changed. Re-enter the target, or restore the key it was sealed with.")
        else:
            report.add(area, f"channel:{channel.get('id')}", CONFIGURED,
                       f"{label}: {'enabled' if channel.get('enabled') else 'DISABLED'}"
                       f", min severity {channel.get('min_severity')}"
                       f", target {'sealed and decrypts' if channel.get('encrypted') else 'stored in the clear (not a secret kind)'}")

    if not send_test:
        report.add(area, "test send", SKIPPED, "no message was sent (pass --send-test to send one labelled test)")
        return
    if offline:
        report.add(area, "test send", SKIPPED, "--offline overrides --send-test; nothing was sent")
        return
    for channel in enabled:
        result = alert_test_send(str(channel.get("id")))
        if result.get("ok"):
            report.add(area, f"test:{channel.get('id')}", CONFIGURED,
                       f"{channel.get('kind')} \"{channel.get('name')}\": [TEST] message delivered in {result.get('latency_ms')} ms")
        else:
            report.add(area, f"test:{channel.get('id')}", ERROR,
                       f"{channel.get('kind')} \"{channel.get('name')}\": {result.get('error') or 'delivery failed'}",
                       "Check the destination URL/key in the admin portal and that this host may reach it.")


def check_redis(report: Report, offline: bool) -> None:
    area = "redis"
    url = env("REDIS_URL") or env("CELERY_BROKER_URL")
    source = "REDIS_URL" if env("REDIS_URL") else "CELERY_BROKER_URL"
    if not url:
        report.add(area, "REDIS_URL", MISSING,
                   "rate limits and background work are per process: with more than one API replica "
                   "each replica enforces its own limits and counts",
                   "Set REDIS_URL (and CELERY_BROKER_URL) to your managed Redis.",
                   required=True)
        report.add(area, "shared rate limits", MISSING, "no; counters are in memory, one set per process")
        return
    report.add(area, "shared rate limits", CONFIGURED, f"yes; counters are shared through {source}")
    if "@" not in url and strict_environment():
        report.add(area, "authentication", ERROR, "the Redis URL carries no password",
                   "Use redis://:PASSWORD@host:6379/0.")
    if offline:
        report.add(area, "reachability", SKIPPED, "--offline: Redis was not contacted",
                   "Re-run without --offline before go-live.")
        return
    result = redis_ping(url)
    if result.get("error"):
        report.add(area, "reachability", ERROR, f"PING failed ({result['error']})",
                   "Check the host, port, password and that this host may reach Redis.")
    else:
        report.add(area, "reachability", CONFIGURED,
                   "PING answered" + (f" (server {result['version']})" if result.get("version") else ""))


def check_postgres(report: Report, offline: bool) -> None:
    area = "postgres"
    dsn = env("PQC_PRODUCT_DATABASE_URL") or env("DATABASE_URL")
    if not dsn:
        report.add(area, "PQC_PRODUCT_DATABASE_URL", MISSING,
                   "the product database is SQLite, which one process may hold and no replica may share",
                   "Point PQC_PRODUCT_DATABASE_URL at managed Postgres before go-live.", required=True)
        return
    if not dsn.startswith(("postgres://", "postgresql://")):
        report.add(area, "PQC_PRODUCT_DATABASE_URL", ERROR, "the DSN is not a Postgres URL",
                   "Use postgresql://user:password@host:5432/database.")
        return
    report.add(area, "PQC_PRODUCT_DATABASE_URL", CONFIGURED, "Postgres DSN is set (value withheld)")
    if offline:
        report.add(area, "connection", SKIPPED, "--offline: Postgres was not contacted",
                   "Re-run without --offline before go-live.")
        return
    probe = postgres_probe(dsn)
    if probe.get("error"):
        report.add(area, "connection", ERROR, f"could not connect ({probe['error']})",
                   "Check the DSN, the network path and that the role may log in.")
        return
    report.add(area, "connection", CONFIGURED, f"connected as {probe.get('role')} (server {probe.get('version')})")
    if probe.get("superuser") or probe.get("bypassrls"):
        which = " and ".join(filter(None, ["SUPERUSER" if probe.get("superuser") else "",
                                           "BYPASSRLS" if probe.get("bypassrls") else ""]))
        report.add(area, "app role", ERROR,
                   f"the app role {probe.get('role')} has {which}, so row-level security never applies to it",
                   f"ALTER ROLE {probe.get('role')} NOSUPERUSER NOBYPASSRLS;")
    else:
        report.add(area, "app role", CONFIGURED, f"{probe.get('role')} is NOSUPERUSER NOBYPASSRLS")

    state = rls_state(dsn)
    if state.get("unavailable"):
        report.add(area, "row-level security", MISSING, "not applied: this build has no RLS verifier",
                   "Apply the tenant isolation policies (scripts/apply-postgres-rls.py), then re-run.",
                   required=True)
    elif state.get("error"):
        report.add(area, "row-level security", ERROR, f"could not be read ({state['error']})",
                   "Check that the app role may read pg_class and pg_policies.")
    elif state.get("status") == "pass":
        report.add(area, "row-level security", CONFIGURED, "enabled and forced on every tenant table")
    else:
        failures = state.get("failures") or []
        head = "; ".join(str(f) for f in failures[:3]) or "policies are incomplete"
        report.add(area, "row-level security", MISSING, f"not applied: {head}",
                   "python scripts/apply-postgres-rls.py --dsn $OWNER_DSN --apply --verify-dsn $APP_DSN",
                   required=True)


#: Which env variable each provider takes its credential from, and whether it needs one.
_AI_KEY_VARS = {
    "anthropic": ("ANTHROPIC_API_KEY", True),
    "openai": ("OPENAI_API_KEY", True),
    "azure-openai": ("PQC_LLM_API_KEY", True),
    "gemini": ("PQC_LLM_API_KEY", True),
    "openai-compatible": ("PQC_LLM_API_KEY", False),
    "ollama": ("PQC_LLM_API_KEY", False),
    "builtin": ("", False),
    "custom": ("PQC_LLM_API_KEY", False),
}

_AI_ALIASES = {
    "claude": "anthropic", "gpt": "openai", "azure": "azure-openai",
    "azureopenai": "azure-openai", "azure_openai": "azure-openai",
    "google": "gemini", "google-gemini": "gemini",
    "compatible": "openai-compatible", "openai_compatible": "openai-compatible",
    "local": "openai-compatible", "groq": "openai-compatible", "openrouter": "openai-compatible",
    "together": "openai-compatible", "vllm": "openai-compatible", "lmstudio": "openai-compatible",
    "lm-studio": "openai-compatible", "llamacpp": "openai-compatible",
    "none": "builtin", "off": "builtin", "rules": "builtin", "disabled": "builtin",
}


def _ai_provider() -> Tuple[str, str]:
    """Which provider this environment selects, and why.

    Mirrors services/llm/config.py's precedence so the self-test tells the
    operator what the running platform would actually do.
    """
    if env("PQC_LLM_DISABLED") in ("1", "true", "yes", "on"):
        return "builtin", "PQC_LLM_DISABLED=1"
    chosen = env("PQC_LLM_PROVIDER").lower().replace(" ", "")
    if chosen:
        return _AI_ALIASES.get(chosen, chosen), "PQC_LLM_PROVIDER"
    if env("ANTHROPIC_API_KEY"):
        return "anthropic", "ANTHROPIC_API_KEY is set"
    if env("OPENAI_API_KEY"):
        return "openai", "OPENAI_API_KEY is set"
    return "builtin", "no provider configured"


def _ai_reachability_probe(provider: str, key: str) -> Tuple[str, Dict[str, str]]:
    """A cheap read that proves the credential and the endpoint, per provider."""
    base = env("PQC_LLM_BASE_URL").rstrip("/")
    if provider == "anthropic":
        return "https://api.anthropic.com/v1/models?limit=1", {
            "x-api-key": key, "anthropic-version": "2023-06-01"}
    if provider == "openai":
        return "https://api.openai.com/v1/models", {"Authorization": f"Bearer {key}"}
    if provider == "gemini":
        return ((base or "https://generativelanguage.googleapis.com/v1beta") + "/models",
                {"x-goog-api-key": key})
    if provider == "azure-openai":
        version = env("PQC_LLM_API_VERSION") or "2024-10-21"
        return f"{base}/openai/models?api-version={version}", {"api-key": key}
    if provider == "ollama":
        return ((base or "http://127.0.0.1:11434").removesuffix("/v1") + "/api/tags", {})
    # openai-compatible, and anything a custom module points at.
    return (base + "/models" if base else ""), ({"Authorization": f"Bearer {key}"} if key else {})


def check_ai(report: Report, offline: bool, check_ai_call: bool) -> None:
    area = "ai"
    provider, why = _ai_provider()
    model = env("PQC_LLM_MODEL") or env("ANTHROPIC_AGENT_MODEL") or env("OPENAI_AGENT_MODEL") or env("OPENAI_MODEL")
    base = env("PQC_LLM_BASE_URL")
    key_var, key_required = _AI_KEY_VARS.get(provider, ("PQC_LLM_API_KEY", False))
    key = env(key_var) if key_var else ""
    if provider in ("azure-openai", "gemini", "openai-compatible", "ollama", "custom") and not key:
        key = env("PQC_LLM_API_KEY") or env("PQC_AI_LOCAL_API_KEY")

    if provider == "builtin":
        status = CONFIGURED if why == "PQC_LLM_DISABLED=1" else MISSING
        report.add(area, "provider", status,
                   "CipherLens answers from built-in rules; no model call leaves this deployment"
                   + (" (deliberately disabled)" if why == "PQC_LLM_DISABLED=1" else f" ({why})"),
                   "" if why == "PQC_LLM_DISABLED=1" else
                   "Set PQC_LLM_PROVIDER and its settings, or ANTHROPIC_API_KEY / OPENAI_API_KEY. "
                   "See docs/AI_PROVIDERS.md.",
                   required=why != "PQC_LLM_DISABLED=1")
        report.add(area, "reachability", SKIPPED, "nothing to reach: the built-in answerer is local")
        return

    known = set(_AI_KEY_VARS)
    if provider not in known:
        report.add(area, "provider", ERROR, f"PQC_LLM_PROVIDER={provider!r} is not a provider this build ships",
                   "Choose one of: " + ", ".join(sorted(known)) + ". See docs/AI_PROVIDERS.md.", required=True)
        return

    # What is missing, named exactly.
    missing: List[str] = []
    if key_required and not key:
        missing.append(key_var)
    if provider in ("azure-openai", "openai-compatible") and not base:
        missing.append("PQC_LLM_BASE_URL")
    if provider == "azure-openai" and not (env("PQC_LLM_AZURE_DEPLOYMENT") or model):
        missing.append("PQC_LLM_AZURE_DEPLOYMENT")
    if provider == "openai-compatible" and not model:
        missing.append("PQC_LLM_MODEL")
    if provider == "custom" and not env("PQC_LLM_CUSTOM_MODULE"):
        missing.append("PQC_LLM_CUSTOM_MODULE")

    detail = f"CipherLens will use {provider}" + (f" / {model}" if model else "")
    if base:
        detail += f" at {base}"
    if key:
        detail += f" ({mask(key)})"
    detail += f" [selected by {why}]"
    if missing:
        report.add(area, "provider", MISSING, detail + "; missing " + ", ".join(missing),
                   "Set " + ", ".join(missing) + ". See docs/AI_PROVIDERS.md.", required=True)
    else:
        report.add(area, "provider", CONFIGURED, detail
                   + ("; OPENAI_API_KEY is also set but unused" if provider == "anthropic" and env("OPENAI_API_KEY") else ""))

    if not check_ai_call:
        report.add(area, "reachability", SKIPPED, "not verified (pass --check-ai to spend one cheap call)")
        return
    if offline:
        report.add(area, "reachability", SKIPPED, "--offline overrides --check-ai")
        return
    if missing:
        report.add(area, "reachability", SKIPPED, "not attempted: the configuration is incomplete")
        return

    url, headers = _ai_reachability_probe(provider, key)
    if not url:
        report.add(area, "reachability", SKIPPED,
                   f"{provider} has no configuration-only probe; use the console's "
                   "Data Control > Model provider > Send a test prompt")
        return
    result = http_json(url, headers)
    if result.get("error"):
        report.add(area, "reachability", ERROR, f"{provider} is unreachable ({result['error']})",
                   "Check the base URL, DNS and outbound HTTPS from this host.")
    elif int(result.get("status") or 0) in (401, 403):
        report.add(area, "reachability", ERROR, f"{provider} rejected the key (HTTP {result.get('status')})",
                   f"Issue a new key in {key_var} and make sure the account has credit.")
    elif int(result.get("status") or 0) == 404:
        report.add(area, "reachability", ERROR, f"{provider} answered HTTP 404 for the model listing",
                   "Check PQC_LLM_BASE_URL: it should be the API root, for example .../v1.")
    elif int(result.get("status") or 0) >= 400:
        report.add(area, "reachability", ERROR, f"{provider} answered HTTP {result.get('status')}",
                   "Check the provider's status page, then re-run.")
    else:
        report.add(area, "reachability", CONFIGURED, f"{provider} accepted the credential and answered")


# ── Report ───────────────────────────────────────────────────────────────────

_MARK = {CONFIGURED: "[ OK ]", MISSING: "[MISS]", ERROR: "[FAIL]", SKIPPED: "[skip]"}


def render(report: Report, env_loaded: bool, env_path: str, offline: bool) -> str:
    lines: List[str] = []
    lines.append("Integration self-test")
    lines.append(f"  environment file : {env_path}" + ("" if env_loaded else "  (NOT FOUND)"))
    lines.append(f"  environment      : {environment_name()}")
    lines.append(f"  outbound checks  : {'skipped (--offline)' if offline else 'enabled'}")
    lines.append("")
    for area in report.areas():
        lines.append(f"{area.upper()}  -> {report.area_status(area)}")
        for finding in [f for f in report.findings if f.area == area]:
            lines.append(f"  {_MARK.get(finding.status, '[    ]')} {finding.check}: {finding.detail}")
            if finding.fix and finding.status in (MISSING, ERROR, SKIPPED):
                lines.append(f"         fix: {finding.fix}")
        lines.append("")

    width = max([len(a) for a in report.areas()] + [4])
    lines.append("Summary")
    lines.append(f"  {'AREA'.ljust(width)}  STATUS       DETAIL")
    for area in report.areas():
        status = report.area_status(area)
        rows = [f for f in report.findings if f.area == area]
        broken = len([f for f in rows if f.status == ERROR])
        absent = len([f for f in rows if f.status == MISSING])
        note = ", ".join(filter(None, [f"{broken} failing" if broken else "", f"{absent} missing" if absent else ""])) or "ready"
        lines.append(f"  {area.ljust(width)}  {status.ljust(11)}  {note}")
    code = report.exit_code()
    lines.append("")
    lines.append({
        0: "Result: nothing is broken and nothing required is missing (exit 0).",
        1: "Result: something that is configured is failing (exit 1). Fix the [FAIL] lines first.",
        2: "Result: required production settings are missing (exit 2). Expected on a machine that is not going live yet.",
    }[code])
    return "\n".join(lines)


# ── Entry point ──────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check-integrations.py",
        description="Report what is configured, what is missing and what is broken, without sending anything to customers.")
    parser.add_argument("--env-file", default=os.path.join(BACKEND, ".env"),
                        help="environment file to read (default: backend/.env). It is never written.")
    parser.add_argument("--offline", action="store_true", help="skip every outbound call")
    parser.add_argument("--send-test", action="store_true",
                        help="send ONE clearly labelled test message to each enabled alert channel")
    parser.add_argument("--check-ai", action="store_true", help="spend one cheap call to validate the AI provider key")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--only", default="",
                        help="comma-separated areas to run (deployment,auth,vault,"
                             "sso,alerts,redis,postgres,ai)")
    return parser


AREAS = ("deployment", "auth", "vault", "sso", "alerts",
         "redis", "postgres", "ai")


def run_checks(report: Report, offline: bool, send_test: bool, check_ai_call: bool, only: List[str]) -> None:
    order = [
        ("deployment", lambda: check_deployment(report, offline)),
        ("auth", lambda: check_auth_secret(report)),
        ("vault", lambda: check_vault(report)),
        ("sso", lambda: check_sso(report, offline)),
        ("alerts", lambda: check_alerts(report, offline, send_test)),
        ("redis", lambda: check_redis(report, offline)),
        ("postgres", lambda: check_postgres(report, offline)),
        ("ai", lambda: check_ai(report, offline, check_ai_call)),
    ]
    for name, run in order:
        if only and name not in only:
            continue
        try:
            run()
        except Exception as exc:  # a check that crashes must not hide the others
            report.add(name, "check", ERROR, f"this check could not run ({exc.__class__.__name__})",
                       "Report this: the self-test itself failed, which is not a statement about your configuration.")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    env_path = os.path.abspath(args.env_file)
    env_loaded, _ = load_environment(env_path)

    report = Report()
    only = [a.strip() for a in str(args.only or "").split(",") if a.strip()]
    unknown = [a for a in only if a not in AREAS]
    if unknown:
        # Reporting "nothing is broken" because a name was misspelled would be the worst answer here.
        print(f"Unknown area(s): {', '.join(unknown)}. Choose from: {', '.join(AREAS)}.", file=sys.stderr)
        return 2
    run_checks(report, args.offline, args.send_test, args.check_ai, only)

    if args.json:
        print(json.dumps({
            "environment": environment_name(),
            "env_file": env_path,
            "env_file_found": env_loaded,
            "offline": bool(args.offline),
            "areas": {area: report.area_status(area) for area in report.areas()},
            "findings": [f.as_dict() for f in report.findings],
            "exit_code": report.exit_code(),
        }, indent=2))
    else:
        print(render(report, env_loaded, env_path, args.offline))
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
