"""Enterprise sign-in for the vendor admin portal: operator SSO (OIDC), sessions, CSRF, TOTP MFA,
step-up for destructive actions, and the break-glass policy for the shared platform key.

Credential model (see also services/platform_operators.py):

  * SSO operator session (auth_method "sso"). OpenID Connect authorization code flow with PKCE
    against PQC_ADMIN_OIDC_ISSUER. The ID token is verified against the issuer's JWKS (RS/PS/ES
    algorithms only), with iss, aud, exp, nonce and email_verified checked. The email must be on the
    operator roster (PQC_ADMIN_OPERATOR_ROLES="alice@corp.com=owner,...") or, when no roster is set,
    in PQC_ADMIN_OIDC_ALLOWED_DOMAINS (role PQC_ADMIN_OIDC_DOMAIN_ROLE, default auditor). Nothing is
    provisioned: unknown emails are denied. The role is re-read from the roster on every request, so
    removing someone from the roster ends their access immediately.
    A successful sign-in creates a server-side session row (only a SHA-256 of the session id is
    stored) carried in an HttpOnly, SameSite=Strict cookie, Secure except on localhost, with an
    absolute and an idle expiry. Cookie-authenticated writes require the x-csrf-token header
    (double submit: the token is HMAC(session id), also set as a readable cookie and returned by
    /platform/whoami).
  * Named operator key (auth_method "operator_key"): unchanged, plus MFA when required.
  * Shared PQC_PLATFORM_ADMIN_KEY: in production and staging it is break-glass only. It is refused
    unless PQC_ALLOW_BREAK_GLASS_KEY=1, and every use is audited with severity high.

MFA is TOTP (RFC 6238, SHA-1, 30 s, 6 digits) implemented with the standard library. Secrets are
encrypted at rest with the platform vault key (vault_crypto: Fernet over PQC_VAULT_MASTER_KEY);
recovery codes are stored as SHA-256 hashes and are single use. Verification accepts one step either
side, refuses a step that was already used, and allows 5 failed attempts per 5 minutes per identity.

Policy: PQC_ADMIN_REQUIRE_MFA (default on in production/staging, off elsewhere). When MFA is
required, or the identity has enrolled, a session is "elevated" only after a TOTP check; until then
only the identity, MFA and sign-out endpoints answer. Destructive actions call require_step_up(),
which needs a TOTP check in the last PQC_ADMIN_STEP_UP_SECONDS (default 900).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn
from services import platform_operators as _operators

logger = logging.getLogger(__name__)

SESSION_COOKIE = "pqc_admin_session"
CSRF_COOKIE = "pqc_admin_csrf"
SSO_STATE_COOKIE = "pqc_admin_sso"
CSRF_HEADER = "x-csrf-token"
SSO_CALLBACK_PATH = "/vendor-admin/sso/callback"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: A break-glass use is refused when it cannot be recorded; retry across a momentary
#: database outage first, so a blink does not lock an operator out of the emergency path.
BREAK_GLASS_AUDIT_ATTEMPTS = 3
BREAK_GLASS_AUDIT_BACKOFF_SECONDS = 0.25
STRICT_ENVIRONMENTS = frozenset({"production", "prod", "staging", "stage"})
ALLOWED_ID_TOKEN_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
MFA_MAX_ATTEMPTS = 5
MFA_ATTEMPT_WINDOW = 300
RECOVERY_CODE_COUNT = 10
STATE_TTL_SECONDS = 600
ISSUER_LABEL = "Airlock Command"

#: Paths an authenticated but not yet MFA-elevated caller may still use.
MFA_EXEMPT_PATHS = frozenset({
    "/platform/whoami",
    "/platform/auth-config",
    "/platform/session/logout",
    "/platform/mfa/status",
    "/platform/mfa/enroll/start",
    "/platform/mfa/enroll/confirm",
    "/platform/mfa/verify",
})

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_LOCK = threading.Lock()
_TABLES_READY: set = set()
_DISCOVERY_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_JWKS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_SESSION_CACHE: Dict[str, float] = {}
_BREAK_GLASS_SEEN: Dict[Tuple[str, str], float] = {}


class OperatorAuthError(Exception):
    """An authentication failure with an HTTP status and a stable machine-readable code."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message

    def detail(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


def _http_error(exc: OperatorAuthError):
    from fastapi import HTTPException

    return HTTPException(status_code=exc.status_code, detail=exc.detail())


# ── Configuration ────────────────────────────────────────────────────────────


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _flag(name: str) -> Optional[bool]:
    raw = _env(name).lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return None


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(_env(name, str(default))))
    except ValueError:
        return default


def environment() -> str:
    return _env("PQC_ENVIRONMENT", "local").lower() or "local"


def strict_environment() -> bool:
    return environment() in STRICT_ENVIRONMENTS


def mfa_required() -> bool:
    explicit = _flag("PQC_ADMIN_REQUIRE_MFA")
    return strict_environment() if explicit is None else explicit


def break_glass_allowed() -> bool:
    return (not strict_environment()) or bool(_flag("PQC_ALLOW_BREAK_GLASS_KEY"))


def session_absolute_seconds() -> int:
    return _int_env("PQC_ADMIN_SESSION_ABSOLUTE_SECONDS", 8 * 3600, 60)


def session_idle_seconds() -> int:
    return _int_env("PQC_ADMIN_SESSION_IDLE_SECONDS", 30 * 60, 30)


def step_up_seconds() -> int:
    return _int_env("PQC_ADMIN_STEP_UP_SECONDS", 15 * 60, 30)


def operator_roster() -> Dict[str, str]:
    """PQC_ADMIN_OPERATOR_ROLES="alice@corp.com=owner,bob@corp.com=operator" -> {email: role}."""
    roster: Dict[str, str] = {}
    for part in _env("PQC_ADMIN_OPERATOR_ROLES").replace(";", ",").replace("\n", ",").split(","):
        if "=" not in part:
            continue
        email, _, role = part.partition("=")
        email = email.strip().lower()
        normalized = _operators.normalize_role(role)
        if email and "@" in email and normalized:
            roster[email] = normalized
        elif email:
            logger.warning("[operator-auth] ignoring roster entry with an unknown role")
    return roster


def allowed_domains() -> List[str]:
    return [d.strip().lower().lstrip("@") for d in _env("PQC_ADMIN_OIDC_ALLOWED_DOMAINS").split(",") if d.strip()]


def oidc_settings() -> Dict[str, Any]:
    base = _env("PQC_PUBLIC_BASE_URL").rstrip("/")
    return {
        "issuer": _env("PQC_ADMIN_OIDC_ISSUER").rstrip("/"),
        "client_id": _env("PQC_ADMIN_OIDC_CLIENT_ID"),
        "client_secret": _env("PQC_ADMIN_OIDC_CLIENT_SECRET"),
        "redirect_uri": _env("PQC_ADMIN_OIDC_REDIRECT_URI") or (f"{base}{SSO_CALLBACK_PATH}" if base else ""),
        "scopes": _env("PQC_ADMIN_OIDC_SCOPES", "openid email profile"),
        "email_claim": _env("PQC_ADMIN_OIDC_EMAIL_CLAIM", "email") or "email",
        "require_email_verified": _flag("PQC_ADMIN_OIDC_REQUIRE_EMAIL_VERIFIED") is not False,
        "domain_role": _operators.normalize_role(_env("PQC_ADMIN_OIDC_DOMAIN_ROLE", "auditor")) or "auditor",
    }


def sso_enabled() -> bool:
    cfg = oidc_settings()
    return bool(cfg["issuer"] and cfg["client_id"] and (operator_roster() or allowed_domains()))


def public_auth_config() -> Dict[str, Any]:
    """Safe to serve without authentication: no secrets, no roster, no issuer internals."""
    return {
        "api_version": "v1",
        "sso_enabled": sso_enabled(),
        "sso_start_url": "/vendor-admin/sso/start" if sso_enabled() else "",
        "mfa_required": mfa_required(),
        "break_glass_allowed": break_glass_allowed(),
        "environment": environment(),
    }


def role_for_email(email: str) -> Optional[str]:
    """Roster role, or the domain role when no roster is configured. None means denied."""
    email = str(email or "").strip().lower()
    if not email or email.count("@") != 1:
        return None
    domain = email.split("@", 1)[1]
    domains = allowed_domains()
    if domains and domain not in domains:
        return None
    roster = operator_roster()
    if roster:
        return roster.get(email)
    return oidc_settings()["domain_role"] if domains else None


# ── Storage ──────────────────────────────────────────────────────────────────


def _db_identity() -> str:
    return f"{os.getenv('PQC_FEATURE_STORE_BACKEND', '')}|{os.getenv('PQC_MAIN_DB_BACKEND', '')}|{os.getenv('PQC_SCANNER_DB', '')}"


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with feature_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS platform_operator_sessions (
                id_hash         TEXT PRIMARY KEY,
                ref             TEXT NOT NULL,
                operator        TEXT NOT NULL,
                email           TEXT NOT NULL DEFAULT '',
                role            TEXT NOT NULL,
                auth_method     TEXT NOT NULL,
                idp_subject     TEXT NOT NULL DEFAULT '',
                created_at      REAL NOT NULL,
                last_seen_at    REAL NOT NULL,
                expires_at      REAL NOT NULL,
                mfa_verified_at REAL NOT NULL DEFAULT 0,
                revoked_at      REAL NOT NULL DEFAULT 0,
                revoked_by      TEXT NOT NULL DEFAULT '',
                revoke_reason   TEXT NOT NULL DEFAULT '',
                ip              TEXT NOT NULL DEFAULT '',
                user_agent      TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_platform_operator_sessions_ref ON platform_operator_sessions(ref);
            CREATE INDEX IF NOT EXISTS idx_platform_operator_sessions_operator ON platform_operator_sessions(operator);
            CREATE TABLE IF NOT EXISTS platform_oidc_states (
                state_hash    TEXT PRIMARY KEY,
                nonce         TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                created_at    REAL NOT NULL,
                expires_at    REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platform_operator_mfa (
                identity         TEXT PRIMARY KEY,
                secret_enc       TEXT NOT NULL,
                status           TEXT NOT NULL,
                last_step        INTEGER NOT NULL DEFAULT 0,
                recovery_json    TEXT NOT NULL DEFAULT '[]',
                last_verified_at REAL NOT NULL DEFAULT 0,
                created_at       TEXT NOT NULL,
                confirmed_at     TEXT NOT NULL DEFAULT '',
                updated_at       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platform_operator_mfa_attempts (
                id         TEXT PRIMARY KEY,
                identity   TEXT NOT NULL,
                success    INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_platform_operator_mfa_attempts_identity ON platform_operator_mfa_attempts(identity, created_at);
            CREATE TABLE IF NOT EXISTS platform_operator_mfa_approvals (
                identity    TEXT PRIMARY KEY,
                granted_by  TEXT NOT NULL,
                reason      TEXT NOT NULL DEFAULT '',
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                used_at     REAL NOT NULL DEFAULT 0
            );
            """
        )
        conn.commit()
    _TABLES_READY.add(identity)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ── OIDC ─────────────────────────────────────────────────────────────────────


def http_get_json(url: str) -> Dict[str, Any]:
    """Fetch JSON. Tests replace this function; production uses urllib with a short timeout."""
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "pqc-scanner-admin-sso"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - https issuer configured by the operator
        return json.loads(resp.read().decode("utf-8") or "{}")


def http_post_form(url: str, form: Dict[str, str], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    body = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "pqc-scanner-admin-sso", **(headers or {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            payload = {}
        return {"error": str(payload.get("error") or f"http_{exc.code}")}


def discovery(issuer: str, force: bool = False) -> Dict[str, Any]:
    now = time.time()
    hit = _DISCOVERY_CACHE.get(issuer)
    if hit and hit[0] > now and not force:
        return hit[1]
    doc = http_get_json(issuer + "/.well-known/openid-configuration")
    if not isinstance(doc, dict):
        raise OperatorAuthError(502, "sso_discovery_failed", "The identity provider discovery document is invalid.")
    if str(doc.get("issuer") or "").rstrip("/") != issuer:
        raise OperatorAuthError(502, "sso_discovery_issuer_mismatch", "The discovery document names a different issuer.")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(doc.get(field) or "").startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise OperatorAuthError(502, "sso_discovery_failed", f"The discovery document has no usable {field}.")
    _DISCOVERY_CACHE[issuer] = (now + 3600, doc)
    return doc


def jwks(uri: str, force: bool = False) -> Dict[str, Any]:
    now = time.time()
    hit = _JWKS_CACHE.get(uri)
    if hit and hit[0] > now and not force:
        return hit[1]
    doc = http_get_json(uri)
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise OperatorAuthError(502, "sso_jwks_failed", "The identity provider signing keys are unavailable.")
    _JWKS_CACHE[uri] = (now + 600, doc)
    return doc


def clear_caches() -> None:
    _DISCOVERY_CACHE.clear()
    _JWKS_CACHE.clear()
    _SESSION_CACHE.clear()
    _BREAK_GLASS_SEEN.clear()


def start_sso(redirect_uri: str) -> Tuple[str, str]:
    """Return (authorization URL, raw state). The caller binds the state to the browser in a cookie."""
    if not sso_enabled():
        raise OperatorAuthError(404, "sso_not_configured", "Operator SSO is not configured.")
    cfg = oidc_settings()
    doc = discovery(cfg["issuer"])
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    now = time.time()
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM platform_oidc_states WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO platform_oidc_states (state_hash, nonce, code_verifier, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (_sha256(state), nonce, verifier, now, now + STATE_TTL_SECONDS),
        )
        conn.commit()
    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    endpoint = str(doc["authorization_endpoint"])
    return endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(params), state


def _consume_state(state: str, bound_state: str) -> Dict[str, Any]:
    if not state or not bound_state or not hmac.compare_digest(str(state).encode(), str(bound_state).encode()):
        raise OperatorAuthError(400, "sso_state_mismatch", "The sign-in response does not belong to this browser. Start again.")
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT state_hash, nonce, code_verifier, expires_at FROM platform_oidc_states WHERE state_hash = ?",
            (_sha256(state),),
        ).fetchone()
        # Single use: remove before anything else can fail. Only the caller whose DELETE removed the row may use
        # it: two callbacks racing with the same state could both read it before either deleted it (on Postgres
        # the second DELETE waits for the first and then removes nothing).
        deleted = conn.execute("DELETE FROM platform_oidc_states WHERE state_hash = ?", (_sha256(state),))
        if int(deleted.rowcount or 0) != 1:
            row = None
        conn.commit()
    if not row:
        raise OperatorAuthError(400, "sso_state_unknown", "The sign-in attempt is unknown or was already used. Start again.")
    row = dict(row)
    if float(row["expires_at"]) < time.time():
        raise OperatorAuthError(400, "sso_state_expired", "The sign-in attempt expired. Start again.")
    return row


def verify_id_token(id_token: str, nonce: str) -> Dict[str, Any]:
    import jwt  # PyJWT, already a dependency

    cfg = oidc_settings()
    doc = discovery(cfg["issuer"])
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise OperatorAuthError(401, "sso_token_invalid", "The identity token is malformed.") from None
    alg = str(header.get("alg") or "")
    supported = doc.get("id_token_signing_alg_values_supported") or ["RS256"]
    if alg not in ALLOWED_ID_TOKEN_ALGS or alg not in supported:
        raise OperatorAuthError(401, "sso_token_alg", "The identity token uses an algorithm that is not allowed.")
    kid = str(header.get("kid") or "")

    def find_key(force: bool):
        keys = [k for k in jwks(str(doc["jwks_uri"]), force=force).get("keys", []) if isinstance(k, dict)]
        if kid:
            keys = [k for k in keys if str(k.get("kid") or "") == kid]
        keys = [k for k in keys if str(k.get("use") or "sig") == "sig"]
        return keys

    candidates = find_key(False) or find_key(True)  # a new kid means the IdP rotated keys
    if not candidates:
        raise OperatorAuthError(401, "sso_token_key", "The identity token was signed by an unknown key.")
    claims: Optional[Dict[str, Any]] = None
    last_error = "signature"
    for jwk_dict in candidates:
        try:
            key = jwt.PyJWK.from_dict(jwk_dict, algorithm=alg).key
            claims = jwt.decode(
                id_token, key=key, algorithms=[alg], audience=cfg["client_id"], issuer=str(doc["issuer"]),
                leeway=60, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            break
        except jwt.ExpiredSignatureError:
            raise OperatorAuthError(401, "sso_token_expired", "The identity token has expired.") from None
        except jwt.InvalidAudienceError:
            raise OperatorAuthError(401, "sso_token_audience", "The identity token was issued for a different application.") from None
        except jwt.InvalidIssuerError:
            raise OperatorAuthError(401, "sso_token_issuer", "The identity token was issued by a different provider.") from None
        except jwt.PyJWTError as exc:
            last_error = exc.__class__.__name__
            continue
    if claims is None:
        logger.warning("[operator-auth] id token rejected: %s", last_error)
        raise OperatorAuthError(401, "sso_token_invalid", "The identity token signature could not be verified.")
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != cfg["client_id"]:
        raise OperatorAuthError(401, "sso_token_audience", "The identity token was issued for a different application.")
    if not nonce or not hmac.compare_digest(str(claims.get("nonce") or "").encode(), str(nonce).encode()):
        raise OperatorAuthError(401, "sso_nonce_mismatch", "The identity token does not match this sign-in attempt.")
    return claims


def complete_sso(code: str, state: str, bound_state: str, redirect_uri: str) -> Dict[str, Any]:
    """Validate the callback and return {email, role, subject, claims}. Raises OperatorAuthError."""
    if not sso_enabled():
        raise OperatorAuthError(404, "sso_not_configured", "Operator SSO is not configured.")
    row = _consume_state(state, bound_state)
    if not code:
        raise OperatorAuthError(400, "sso_code_missing", "The identity provider did not return an authorization code.")
    cfg = oidc_settings()
    doc = discovery(cfg["issuer"])
    form = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": cfg["client_id"], "code_verifier": row["code_verifier"],
    }
    headers: Dict[str, str] = {}
    if cfg["client_secret"]:
        methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if "client_secret_basic" in methods:
            pair = f"{urllib.parse.quote(cfg['client_id'], safe='')}:{urllib.parse.quote(cfg['client_secret'], safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        else:
            form["client_secret"] = cfg["client_secret"]
    tokens = http_post_form(str(doc["token_endpoint"]), form, headers)
    id_token = str((tokens or {}).get("id_token") or "")
    if not id_token:
        raise OperatorAuthError(401, "sso_token_exchange_failed", "The identity provider refused the authorization code.")
    claims = verify_id_token(id_token, row["nonce"])
    email = str(claims.get(cfg["email_claim"]) or "").strip().lower()
    if not email:
        raise OperatorAuthError(403, "sso_email_missing", "The identity token carries no email address.")
    if cfg["require_email_verified"] and claims.get("email_verified") not in (True, "true", "True"):
        raise OperatorAuthError(403, "sso_email_unverified", "The identity provider has not verified this email address.")
    role = role_for_email(email)
    if not role:
        raise OperatorAuthError(403, "sso_operator_unknown", "This account is not an authorized platform operator.")
    return {"email": email, "role": role, "subject": str(claims.get("sub") or ""), "claims": claims}


# ── Sessions ─────────────────────────────────────────────────────────────────


def cookie_secure(request: Any) -> bool:
    host = str(getattr(getattr(request, "url", None), "hostname", "") or "").lower()
    return host not in {"localhost", "127.0.0.1", "::1", "[::1]"}


def csrf_token_for(raw_session_id: str) -> str:
    return hmac.new(str(raw_session_id).encode("utf-8"), b"pqc-admin-csrf-v1", hashlib.sha256).hexdigest()


def create_session(operator: str, role: str, auth_method: str, *, email: str = "", subject: str = "",
                   ip: str = "", user_agent: str = "", mfa_verified: bool = False) -> Tuple[str, Dict[str, Any]]:
    raw = secrets.token_urlsafe(48)
    now = time.time()
    row = {
        "id_hash": _sha256(raw), "ref": uuid.uuid4().hex[:20], "operator": operator[:320], "email": email[:320],
        "role": role, "auth_method": auth_method, "idp_subject": subject[:200], "created_at": now, "last_seen_at": now,
        "expires_at": now + session_absolute_seconds(), "mfa_verified_at": now if mfa_verified else 0.0,
        "revoked_at": 0.0, "revoked_by": "", "revoke_reason": "", "ip": str(ip or "")[:64], "user_agent": str(user_agent or "")[:300],
    }
    init_tables()
    columns = list(row)
    with feature_conn() as conn:
        conn.execute(
            f"INSERT INTO platform_operator_sessions ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            tuple(row[c] for c in columns),
        )
        conn.commit()
    return raw, row


def _session_row(raw: str) -> Optional[Dict[str, Any]]:
    if not raw or len(raw) > 200:
        return None
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT id_hash, ref, operator, email, role, auth_method, idp_subject, created_at, last_seen_at, expires_at, "
            "mfa_verified_at, revoked_at, revoked_by, revoke_reason, ip, user_agent "
            "FROM platform_operator_sessions WHERE id_hash = ?",
            (_sha256(raw),),
        ).fetchone()
    return dict(row) if row else None


def session_state(row: Optional[Dict[str, Any]], now: Optional[float] = None) -> str:
    if not row:
        return "missing"
    now = time.time() if now is None else now
    if float(row.get("revoked_at") or 0):
        return "revoked"
    if now >= float(row.get("expires_at") or 0):
        return "expired"
    if now - float(row.get("last_seen_at") or 0) > session_idle_seconds():
        return "idle_expired"
    return "active"


def load_session(raw: str, touch: bool = True) -> Tuple[Optional[Dict[str, Any]], str]:
    row = _session_row(raw)
    state = session_state(row)
    if state != "active":
        _SESSION_CACHE.pop(_sha256(raw), None)
        return None, state
    now = time.time()
    if touch and now - float(row["last_seen_at"]) >= 15:
        with feature_conn() as conn:
            conn.execute("UPDATE platform_operator_sessions SET last_seen_at = ? WHERE id_hash = ? AND revoked_at = 0",
                         (now, row["id_hash"]))
            conn.commit()
        row["last_seen_at"] = now
    _SESSION_CACHE[row["id_hash"]] = now
    return row, state


def session_valid_cached(raw: str) -> bool:
    """Cheap check for the request middleware; the endpoint guard performs the full check."""
    key = _sha256(raw)
    seen = _SESSION_CACHE.get(key)
    if seen and time.time() - seen < 5:
        return True
    row, _ = load_session(raw, touch=False)
    return row is not None


def revoke_session_by_ref(ref: str, revoked_by: str, reason: str) -> Optional[Dict[str, Any]]:
    init_tables()
    now = time.time()
    with feature_conn() as conn:
        row = conn.execute("SELECT id_hash, operator, auth_method, revoked_at FROM platform_operator_sessions WHERE ref = ?",
                           (str(ref or ""),)).fetchone()
        if not row:
            return None
        row = dict(row)
        if not float(row["revoked_at"] or 0):
            conn.execute("UPDATE platform_operator_sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE ref = ?",
                         (now, str(revoked_by)[:160], str(reason)[:500], ref))
            conn.commit()
    _SESSION_CACHE.pop(row["id_hash"], None)
    return {"ref": ref, "operator": row["operator"], "auth_method": row["auth_method"]}


def revoke_session_raw(raw: str, revoked_by: str, reason: str) -> bool:
    row = _session_row(raw)
    if not row:
        return False
    return bool(revoke_session_by_ref(row["ref"], revoked_by, reason))


def revoke_operator_sessions(operator: str, revoked_by: str, reason: str) -> int:
    init_tables()
    now = time.time()
    with feature_conn() as conn:
        cur = conn.execute(
            "UPDATE platform_operator_sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
            "WHERE operator = ? AND revoked_at = 0 AND expires_at > ?",
            (now, str(revoked_by)[:160], str(reason)[:500], str(operator), now),
        )
        count = int(cur.rowcount or 0)
        conn.commit()
    _SESSION_CACHE.clear()
    return count


def list_sessions(include_inactive: bool = False, limit: int = 200) -> List[Dict[str, Any]]:
    init_tables()
    now = time.time()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT ref, operator, email, role, auth_method, created_at, last_seen_at, expires_at, mfa_verified_at, "
            "revoked_at, revoked_by, revoke_reason, ip, user_agent FROM platform_operator_sessions "
            "ORDER BY created_at DESC LIMIT ?",
            (max(1, min(int(limit), 1000)),),
        ).fetchall()
    out = []
    for raw_row in rows:
        row = dict(raw_row)
        row["last_seen_at"] = float(row["last_seen_at"] or 0)
        state = session_state({**row, "last_seen_at": row["last_seen_at"]}, now)
        if state != "active" and not include_inactive:
            continue
        out.append({
            "session_ref": row["ref"], "kind": "operator", "operator": row["operator"], "email": row["email"],
            "role": row["role"], "auth_method": row["auth_method"], "status": state,
            "created_at": _iso(row["created_at"]), "last_seen_at": _iso(row["last_seen_at"]),
            "expires_at": _iso(min(float(row["expires_at"]), row["last_seen_at"] + session_idle_seconds())),
            "absolute_expires_at": _iso(row["expires_at"]), "mfa_verified_at": _iso(row["mfa_verified_at"]),
            "revoked_at": _iso(row["revoked_at"]), "revoked_by": row["revoked_by"], "ip": row["ip"],
            "user_agent": row["user_agent"][:120],
        })
    return out


def mark_session_mfa(raw: str) -> None:
    with feature_conn() as conn:
        conn.execute("UPDATE platform_operator_sessions SET mfa_verified_at = ?, last_seen_at = ? WHERE id_hash = ?",
                     (time.time(), time.time(), _sha256(raw)))
        conn.commit()


# ── TOTP (RFC 6238) ──────────────────────────────────────────────────────────


def hotp(secret: bytes, counter: int, digits: int = TOTP_DIGITS, digest: str = "sha1") -> str:
    mac = hmac.new(secret, struct.pack(">Q", int(counter)), getattr(hashlib, digest)).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, for_time: float, digits: int = TOTP_DIGITS, step: int = TOTP_STEP, digest: str = "sha1") -> str:
    return hotp(secret, int(for_time) // step, digits, digest)


def new_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def base32_secret(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def decode_base32_secret(text: str) -> bytes:
    clean = str(text or "").replace(" ", "").upper()
    return base64.b32decode(clean + "=" * (-len(clean) % 8))


def otpauth_uri(account: str, secret: bytes) -> str:
    label = urllib.parse.quote(f"{ISSUER_LABEL}:{account}", safe="")
    query = urllib.parse.urlencode({"secret": base32_secret(secret), "issuer": ISSUER_LABEL, "algorithm": "SHA1",
                                    "digits": TOTP_DIGITS, "period": TOTP_STEP}, quote_via=urllib.parse.quote)
    return f"otpauth://totp/{label}?{query}"


def match_totp(secret: bytes, code: str, now: Optional[float] = None, last_step: int = 0, window: int = TOTP_WINDOW) -> Optional[int]:
    """Return the matching time step (greater than last_step), or None."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    current = int(time.time() if now is None else now) // TOTP_STEP
    matched = None
    for step in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(secret, step), code) and step > int(last_step or 0) and matched is None:
            matched = step
    return matched


# ── MFA storage and verification ─────────────────────────────────────────────


def _encrypt(secret: bytes) -> str:
    from vault_crypto import encrypt_secret

    try:
        return encrypt_secret(base32_secret(secret))
    except Exception as exc:
        raise OperatorAuthError(503, "mfa_vault_unavailable",
                                "MFA needs PQC_VAULT_MASTER_KEY (a Fernet key) to encrypt enrolment secrets.") from exc


def _decrypt(token: str) -> str:
    from vault_crypto import decrypt_secret

    try:
        return decrypt_secret(token)
    except Exception as exc:
        raise OperatorAuthError(503, "mfa_vault_unavailable", "The MFA secret cannot be decrypted with the current vault key.") from exc


def _decrypt_secret(token: str) -> bytes:
    return decode_base32_secret(_decrypt(token))


def identity_for(actor: Dict[str, Any]) -> str:
    method = str(actor.get("auth_method") or "")
    if method == "sso":
        return "sso:" + str(actor.get("email") or actor.get("actor_id") or "").lower()
    if method == "operator_key":
        return "key:" + str(actor.get("actor_id") or "")
    return ""


def mfa_record(identity: str) -> Optional[Dict[str, Any]]:
    if not identity:
        return None
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT identity, secret_enc, status, last_step, recovery_json, last_verified_at, created_at, confirmed_at, updated_at "
            "FROM platform_operator_mfa WHERE identity = ?", (identity,)).fetchone()
    return dict(row) if row else None


def mfa_status(identity: str) -> Dict[str, Any]:
    record = mfa_record(identity)
    active = bool(record and record["status"] == "active")
    try:
        remaining = len(json.loads(record["recovery_json"] or "[]")) if active else 0
    except ValueError:
        remaining = 0
    return {
        "identity": identity, "enrolled": active, "pending": bool(record and record["status"] == "pending"),
        "confirmed_at": (record or {}).get("confirmed_at") or "", "recovery_codes_remaining": remaining,
        "last_verified_at": _iso(float((record or {}).get("last_verified_at") or 0)),
        "required": mfa_required(),
    }


#: How long an owner's approval to enrol stays usable.
ENROLMENT_APPROVAL_SECONDS = int(os.getenv("PQC_ADMIN_ENROLMENT_APPROVAL_SECONDS", "3600") or 3600)


def enrolled_identities(exclude: str = "") -> List[str]:
    """Identities with a confirmed authenticator, other than `exclude`."""
    return [row["identity"] for row in list_mfa_identities()
            if row["status"] == "active" and row["identity"] != str(exclude or "")]


def identity_is_owner(identity: str) -> bool:
    """True for an SSO identity the roster gives an owner role. Key identities never count.

    Deliberately conservative: counting a named key as an owner would let an enrolled key-holder
    close the bootstrap window before any human owner had a second factor, and there would then be
    nobody able to approve one.
    """
    kind, _, name = str(identity or "").partition(":")
    if kind != "sso" or not name:
        return False
    return str(role_for_email(name) or "") in _operators.OWNER_ROLES


def enrolment_gate_closed(exclude: str = "") -> bool:
    """True once at least one owner holds an authenticator: from then on, enrolment needs approval.

    Before that the platform is in bootstrap and self-enrolment is the only way anyone can get a
    first factor -- there is nobody with standing to approve one. The window is as small as the
    rule allows (it closes on the first owner, not the first operator) and every enrolment inside
    it is audited at high severity and raised as a notification, so it is visible rather than
    merely permitted.
    """
    return any(identity_is_owner(i) for i in enrolled_identities(exclude=exclude))


def grant_enrolment_approval(identity: str, granted_by: str, reason: str,
                             seconds: int = 0) -> Dict[str, Any]:
    """Let one named identity enrol an authenticator. Single use, time limited, audited by the caller."""
    init_tables()
    now = time.time()
    expires = now + float(seconds or ENROLMENT_APPROVAL_SECONDS)
    with feature_conn() as conn:
        conn.execute("DELETE FROM platform_operator_mfa_approvals WHERE identity = ?", (identity,))
        conn.execute(
            "INSERT INTO platform_operator_mfa_approvals (identity, granted_by, reason, created_at, expires_at, used_at) "
            "VALUES (?, ?, ?, ?, ?, 0)", (identity, str(granted_by or ""), str(reason or "")[:500], now, expires))
        conn.commit()
    return {"identity": identity, "granted_by": granted_by, "expires_at": _iso(expires)}


def _claim_enrolment_approval(identity: str) -> Optional[Dict[str, Any]]:
    """Consume a live approval for `identity`, or return None."""
    init_tables()
    now = time.time()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT identity, granted_by, reason, expires_at FROM platform_operator_mfa_approvals "
            "WHERE identity = ? AND used_at = 0 AND expires_at > ?", (identity, now)).fetchone()
        if not row:
            return None
        claimed = conn.execute(
            "UPDATE platform_operator_mfa_approvals SET used_at = ? WHERE identity = ? AND used_at = 0 AND expires_at > ?",
            (now, identity, now))
        if int(claimed.rowcount or 0) != 1:
            conn.rollback()
            return None
        conn.commit()
    return dict(row)


def begin_enrolment(identity: str, account_label: str) -> Dict[str, Any]:
    """Start TOTP enrolment for `identity`. Raises OperatorAuthError.

    Enrolment used to be trust-on-first-use: /platform/mfa/enroll/start and /enroll/confirm are
    exempt from the elevation gate (they have to be -- an unenrolled operator cannot pass it), so
    anyone holding a stolen operator key or a hijacked session could enrol *their own*
    authenticator before the real holder ever did, and MFA then protected the attacker.

    The first authenticator on a platform has to be self-service, or there is nobody to approve it.
    After that, enrolling a *new* identity takes an owner's single-use, time-limited approval
    (POST /platform/mfa/enrolment-approvals), so the second factor is only ever added by someone who
    already holds one. Re-enrolling after an owner reset is covered by the same approval, because
    reset_mfa deletes the record and the identity is then "new" again.
    """
    if not identity:
        raise OperatorAuthError(400, "mfa_identity_required",
                                "MFA needs a named identity. Sign in with SSO or a named operator key; the shared key cannot enrol.")
    existing = mfa_record(identity)
    if existing and existing["status"] == "active":
        raise OperatorAuthError(409, "mfa_already_enrolled", "MFA is already enrolled. An owner can reset it.")
    approval = None
    if enrolment_gate_closed(exclude=identity):
        approval = _claim_enrolment_approval(identity)
        if not approval:
            raise OperatorAuthError(
                403, "mfa_enrolment_approval_required",
                "An owner already holds an authenticator, so a new one has to be approved. Ask an owner to "
                "approve this account (Operators -> MFA), then enrol within the hour.")
    secret = new_totp_secret()
    now = _now_iso()
    token = _encrypt(secret)
    with feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO platform_operator_mfa (identity, secret_enc, status, last_step, recovery_json, last_verified_at, created_at, confirmed_at, updated_at) "
                    "VALUES (?, ?, 'pending', 0, '[]', 0, ?, '', ?)", (identity, token, now, now))
        except INTEGRITY_ERRORS:
            conn.execute("UPDATE platform_operator_mfa SET secret_enc = ?, status = 'pending', last_step = 0, recovery_json = '[]', "
                         "updated_at = ? WHERE identity = ? AND status = 'pending'", (token, now, identity))
        conn.commit()
    uri = otpauth_uri(account_label or identity, secret)
    qr = ""
    try:
        from services import qr_svg

        qr = qr_svg.svg_data_uri(uri)
    except Exception:  # the QR is a convenience; the secret and URI are always returned
        qr = ""
    return {"otpauth_uri": uri, "secret": base32_secret(secret), "qr_svg_data_uri": qr,
            "algorithm": "SHA1", "digits": TOTP_DIGITS, "period": TOTP_STEP,
            "approved_by": str((approval or {}).get("granted_by") or ""),
            "first_enrolment": approval is None}


def _normalize_recovery(code: str) -> str:
    return "".join(ch for ch in str(code or "").lower() if ch.isalnum())


def _new_recovery_codes() -> Tuple[List[str], List[str]]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [_sha256("recovery:" + _normalize_recovery(c)) for c in codes]


def _record_attempt(identity: str, success: bool) -> None:
    with feature_conn() as conn:
        conn.execute("INSERT INTO platform_operator_mfa_attempts (id, identity, success, created_at) VALUES (?, ?, ?, ?)",
                     (uuid.uuid4().hex, identity, 1 if success else 0, time.time()))
        conn.execute("DELETE FROM platform_operator_mfa_attempts WHERE created_at < ?", (time.time() - 86400,))
        conn.commit()


def _check_rate_limit(identity: str) -> None:
    init_tables()
    with feature_conn() as conn:
        # Failed attempts count; a successful check does not use up the allowance.
        row = conn.execute("SELECT COUNT(*) FROM platform_operator_mfa_attempts WHERE identity = ? AND success = 0 AND created_at >= ?",
                           (identity, time.time() - MFA_ATTEMPT_WINDOW)).fetchone()
    if int(row[0] or 0) >= MFA_MAX_ATTEMPTS:
        raise OperatorAuthError(429, "mfa_rate_limited", "Too many MFA attempts. Wait five minutes and try again.")


def verify_mfa(identity: str, code: str = "", recovery_code: str = "", *, confirm_pending: bool = False,
               now: Optional[float] = None) -> Dict[str, Any]:
    """Check a TOTP or recovery code. Returns {"method", "recovery_codes"?}. Raises OperatorAuthError."""
    if not identity:
        raise OperatorAuthError(400, "mfa_identity_required", "MFA needs a named identity.")
    _check_rate_limit(identity)
    record = mfa_record(identity)
    wanted = "pending" if confirm_pending else "active"
    if not record or record["status"] != wanted:
        _record_attempt(identity, False)
        code_name = "mfa_not_pending" if confirm_pending else "mfa_not_enrolled"
        raise OperatorAuthError(409 if confirm_pending else 403, code_name,
                                "Start enrolment first." if confirm_pending else "MFA is not enrolled for this identity.")
    result: Dict[str, Any] = {}
    if recovery_code and not confirm_pending:
        try:
            hashes = list(json.loads(record["recovery_json"] or "[]"))
        except ValueError:
            hashes = []
        candidate = _sha256("recovery:" + _normalize_recovery(recovery_code))
        match = next((h for h in hashes if hmac.compare_digest(str(h), candidate)), None)
        if not match:
            _record_attempt(identity, False)
            raise OperatorAuthError(401, "mfa_invalid_code", "That recovery code is not valid or was already used.")
        hashes.remove(match)
        with feature_conn() as conn:
            cur = conn.execute("UPDATE platform_operator_mfa SET recovery_json = ?, last_verified_at = ?, updated_at = ? "
                               "WHERE identity = ? AND recovery_json = ?",
                               (json.dumps(hashes), time.time(), _now_iso(), identity, record["recovery_json"]))
            conn.commit()
        if int(cur.rowcount or 0) != 1:  # a concurrent use of the same code
            _record_attempt(identity, False)
            raise OperatorAuthError(401, "mfa_invalid_code", "That recovery code is not valid or was already used.")
        _record_attempt(identity, True)
        result.update(method="recovery_code", recovery_codes_remaining=len(hashes))
        return result
    secret = _decrypt_secret(record["secret_enc"])
    step = match_totp(secret, code, now=now, last_step=int(record["last_step"] or 0))
    if step is None:
        _record_attempt(identity, False)
        replay = match_totp(secret, code, now=now, last_step=0) is not None
        raise OperatorAuthError(401, "mfa_code_reused" if replay else "mfa_invalid_code",
                                "That code was already used. Wait for the next one." if replay else "The code is not valid.")
    fields = {"last_step": step, "last_verified_at": time.time(), "updated_at": _now_iso()}
    codes: List[str] = []
    if confirm_pending:
        codes, hashes = _new_recovery_codes()
        fields.update(status="active", confirmed_at=_now_iso(), recovery_json=json.dumps(hashes))
    assignments = ", ".join(f"{k} = ?" for k in fields)
    with feature_conn() as conn:
        # The last_step guard makes a concurrent replay of the same code lose the race.
        cur = conn.execute(f"UPDATE platform_operator_mfa SET {assignments} WHERE identity = ? AND last_step < ?",
                           (*fields.values(), identity, step))
        conn.commit()
    if int(cur.rowcount or 0) != 1:
        _record_attempt(identity, False)
        raise OperatorAuthError(401, "mfa_code_reused", "That code was already used. Wait for the next one.")
    _record_attempt(identity, True)
    result["method"] = "totp"
    if codes:
        result["recovery_codes"] = codes
    return result


def regenerate_recovery_codes(identity: str) -> List[str]:
    record = mfa_record(identity)
    if not record or record["status"] != "active":
        raise OperatorAuthError(403, "mfa_not_enrolled", "MFA is not enrolled for this identity.")
    codes, hashes = _new_recovery_codes()
    with feature_conn() as conn:
        conn.execute("UPDATE platform_operator_mfa SET recovery_json = ?, updated_at = ? WHERE identity = ?",
                     (json.dumps(hashes), _now_iso(), identity))
        conn.commit()
    return codes


def reset_mfa(identity: str) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM platform_operator_mfa WHERE identity = ?", (identity,))
        conn.execute("DELETE FROM platform_operator_mfa_attempts WHERE identity = ?", (identity,))
        conn.commit()
    return int(cur.rowcount or 0) > 0


def list_mfa_identities() -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT identity, status, confirmed_at, last_verified_at, recovery_json FROM platform_operator_mfa "
                            "ORDER BY identity").fetchall()
    out = []
    for row in rows:
        row = dict(row)
        try:
            remaining = len(json.loads(row["recovery_json"] or "[]"))
        except ValueError:
            remaining = 0
        out.append({"identity": row["identity"], "status": row["status"], "confirmed_at": row["confirmed_at"],
                    "last_verified_at": _iso(float(row["last_verified_at"] or 0)), "recovery_codes_remaining": remaining})
    return out


# ── Request-level policy (called from app._require_platform_admin) ───────────


def session_cookie(request: Any) -> str:
    try:
        return str(request.cookies.get(SESSION_COOKIE) or "")
    except Exception:
        return ""


def _mfa_elevation_needed(identity: str) -> bool:
    if mfa_required():
        return True
    record = mfa_record(identity)
    return bool(record and record["status"] == "active")


def _set_actor(request: Any, actor: Dict[str, Any]) -> None:
    request.state.actor_id = actor["actor_id"]
    request.state.actor_role = actor["actor_role"]
    request.state.platform_operator = actor
    _operators.CURRENT_OPERATOR.set(actor)


def require_session_actor(request: Any, allowed_roles: Iterable[str]) -> Dict[str, Any]:
    """Authenticate a cookie session. Raises fastapi.HTTPException."""
    from fastapi import HTTPException

    raw = session_cookie(request)
    row, state = load_session(raw)
    if not row:
        messages = {"expired": "Your operator session expired. Sign in again.",
                    "idle_expired": "Your operator session timed out after inactivity. Sign in again.",
                    "revoked": "Your operator session was revoked. Sign in again."}
        raise HTTPException(status_code=401, detail={"code": f"session_{state}",
                                                     "message": messages.get(state, "Sign in to the operator console.")})
    ceiling = row["role"]
    if row["auth_method"] == "sso":
        current = role_for_email(row["email"])  # roster changes take effect on the next request
        if not current:
            revoke_session_by_ref(row["ref"], "system", "operator removed from roster")
            raise HTTPException(status_code=401, detail={"code": "session_revoked",
                                                         "message": "This account is no longer an authorized operator."})
        ceiling = current
    method = str(getattr(request, "method", "GET") or "GET").upper()
    if method not in SAFE_METHODS:
        sent = str(request.headers.get(CSRF_HEADER) or "")
        if not sent or not hmac.compare_digest(sent.encode(), csrf_token_for(raw).encode()):
            raise HTTPException(status_code=403, detail={"code": "csrf_failed",
                                                         "message": "Missing or invalid CSRF token. Reload the console and try again."})
    try:
        role = _operators.effective_role({"ceiling_role": ceiling, "bound": True}, request.headers.get("x-platform-admin-role"))
    except _operators.RoleError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
    actor: Dict[str, Any] = {
        "actor_id": row["operator"], "actor_role": role, "ceiling_role": ceiling, "bound": True,
        "credential_source": "operator_session", "auth_method": row["auth_method"], "email": row["email"],
        "session_ref": row["ref"], "session_expires_at": _iso(min(float(row["expires_at"]), float(row["last_seen_at"]) + session_idle_seconds())),
        "session_absolute_expires_at": _iso(row["expires_at"]), "mfa_verified_at": float(row["mfa_verified_at"] or 0),
    }
    identity = identity_for(actor)
    elevated = float(row["mfa_verified_at"] or 0) > 0
    actor["mfa_elevated"] = elevated
    _set_actor(request, actor)
    if _mfa_elevation_needed(identity) and not elevated and str(request.url.path) not in MFA_EXEMPT_PATHS:
        enrolled = bool((mfa_record(identity) or {}).get("status") == "active")
        raise HTTPException(status_code=401, detail={
            "code": "mfa_required" if enrolled else "mfa_enrolment_required",
            "message": "Enter your authenticator code to continue." if enrolled else "Enrol an authenticator app to continue.",
        })
    if role not in set(allowed_roles):
        raise HTTPException(status_code=403, detail=f"Platform admin role '{role}' is not allowed for this operation.")
    return actor


def apply_key_policy(request: Any, credential: Dict[str, Any], actor: Dict[str, Any],
                     record_event: Optional[Callable[..., None]] = None) -> None:
    """Break-glass and MFA policy for key-authenticated requests. Raises fastapi.HTTPException."""
    from fastapi import HTTPException

    if credential.get("source") == "legacy_shared_key":
        if strict_environment():
            actor["auth_method"] = "break_glass"
            if not break_glass_allowed():
                raise HTTPException(status_code=403, detail={
                    "code": "break_glass_disabled",
                    "message": f"The shared platform key is disabled in {environment()}. Sign in with SSO; "
                               "break-glass access needs PQC_ALLOW_BREAK_GLASS_KEY=1.",
                })
            _audit_break_glass(request, actor, record_event)
        else:
            actor["auth_method"] = "shared_key"
        actor["mfa_elevated"] = False
        return
    actor["auth_method"] = "operator_key"
    identity = identity_for(actor)
    record = mfa_record(identity)
    last = float((record or {}).get("last_verified_at") or 0)
    actor["mfa_verified_at"] = last
    active = bool(record and record["status"] == "active")
    needed = mfa_required() or active
    elevated = active and (time.time() - last) <= session_absolute_seconds()
    actor["mfa_elevated"] = elevated
    if needed and not elevated and str(request.url.path) not in MFA_EXEMPT_PATHS:
        _operators.CURRENT_OPERATOR.set(actor)
        raise HTTPException(status_code=401, detail={
            "code": "mfa_required" if active else "mfa_enrolment_required",
            "message": "Verify your authenticator code (POST /platform/mfa/verify) to use this operator key."
            if active else "Enrol MFA for this operator key (POST /platform/mfa/enroll/start) before using it.",
        })


def _audit_break_glass(request: Any, actor: Dict[str, Any], record_event: Optional[Callable[..., None]]) -> None:
    if record_event is None:
        return
    method = str(getattr(request, "method", "GET") or "GET").upper()
    path = str(request.url.path)
    now = time.time()
    key = (method, path)
    with _LOCK:
        # Every write is recorded. Reads are recorded once a minute per route so a console page load
        # (a dozen parallel reads) produces a readable trail rather than a flood.
        if method in SAFE_METHODS and now - _BREAK_GLASS_SEEN.get(key, 0) < 60:
            return
        _BREAK_GLASS_SEEN[key] = now
    token = _operators.CURRENT_OPERATOR.set(actor)
    details = {
        "severity": "high", "method": method, "path": path, "environment": environment(),
        "ip": str(getattr(getattr(request, "client", None), "host", "") or ""),
        "user_agent": str(request.headers.get("user-agent") or "")[:200],
        "claimed_user": _operators.sanitize_claimed_user(request.headers.get("x-platform-admin-user")),
    }
    # A break-glass use that is not recorded is a break-glass use that did not happen, as far as
    # anyone reviewing the trail later can tell. This used to log "could not be audited" and let
    # the request through: during the load test a real break-glass access went unrecorded because
    # the database had momentarily dropped its connections. Retry across a blink, and if the
    # record still cannot be written, refuse the access rather than perform it unwitnessed.
    last: Optional[BaseException] = None
    for attempt in range(BREAK_GLASS_AUDIT_ATTEMPTS):
        try:
            record_event("", "platform.break_glass_used", "shared platform key used in " + environment(), details)
            last = None
            break
        except Exception as exc:
            last = exc
            logger.warning("[operator-auth] break-glass audit attempt %d/%d failed: %s",
                           attempt + 1, BREAK_GLASS_AUDIT_ATTEMPTS, exc.__class__.__name__)
            if attempt + 1 < BREAK_GLASS_AUDIT_ATTEMPTS:
                time.sleep(BREAK_GLASS_AUDIT_BACKOFF_SECONDS * (attempt + 1))
    try:
        _operators.CURRENT_OPERATOR.reset(token)
    except Exception:
        pass
    if last is not None:
        with _LOCK:
            _BREAK_GLASS_SEEN.pop(key, None)  # nothing was recorded, so do not suppress the next try
        logger.critical("[operator-auth] break-glass use REFUSED: it could not be audited (%s)",
                        last.__class__.__name__)
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail={
            "code": "break_glass_not_auditable",
            "message": "Break-glass access could not be recorded, so it was refused. "
                       "Retry once the audit store is reachable.",
        })
    logger.warning("[operator-auth] BREAK-GLASS shared platform key used: %s %s", method, path)


def require_step_up(actor: Optional[Dict[str, Any]] = None, action: str = "") -> None:
    """Destructive actions: a TOTP check within PQC_ADMIN_STEP_UP_SECONDS. Raises fastapi.HTTPException."""
    from fastapi import HTTPException

    actor = actor or _operators.CURRENT_OPERATOR.get() or {}
    method = str(actor.get("auth_method") or "")
    if method in {"shared_key", "break_glass", ""}:
        # The shared key has no identity to verify. Locally it keeps working; in production it is
        # break-glass only and each use is audited with severity high.
        return
    identity = identity_for(actor)
    record = mfa_record(identity)
    active = bool(record and record["status"] == "active")
    if not active:
        if mfa_required():
            raise HTTPException(status_code=403, detail={"code": "mfa_enrolment_required",
                                                         "message": "Enrol MFA before performing this action."})
        return
    verified = float(actor.get("mfa_verified_at") or 0)
    if method == "operator_key":
        verified = float(record.get("last_verified_at") or 0)
    elif method == "sso":
        verified = float(actor.get("mfa_verified_at") or 0)
    if time.time() - verified > step_up_seconds():
        raise HTTPException(status_code=403, detail={
            "code": "mfa_step_up_required",
            "message": f"Confirm your authenticator code to {action or 'perform this action'} (required within the last "
                       f"{step_up_seconds() // 60} minutes).",
        })


def whoami_extras(request: Any, actor: Dict[str, Any]) -> Dict[str, Any]:
    method = str(actor.get("auth_method") or "")
    identity = identity_for(actor)
    status = mfa_status(identity) if identity else {"enrolled": False, "pending": False, "recovery_codes_remaining": 0,
                                                     "required": mfa_required(), "identity": "", "confirmed_at": "",
                                                     "last_verified_at": ""}
    verified = float(actor.get("mfa_verified_at") or 0)
    extras: Dict[str, Any] = {
        "auth_method": method,
        "email": actor.get("email") or "",
        "mfa": {**status, "elevated": bool(actor.get("mfa_elevated")),
                "step_up_valid_until": _iso(verified + step_up_seconds()) if verified else "",
                "can_enrol": bool(identity)},
        "session": None,
        "csrf_token": "",
        "break_glass": method == "break_glass",
        "policy": {"mfa_required": mfa_required(), "break_glass_allowed": break_glass_allowed(),
                   "environment": environment(), "step_up_seconds": step_up_seconds()},
    }
    if actor.get("credential_source") == "operator_session":
        raw = session_cookie(request)
        extras["session"] = {"session_ref": actor.get("session_ref"), "expires_at": actor.get("session_expires_at"),
                             "absolute_expires_at": actor.get("session_absolute_expires_at"),
                             "idle_timeout_seconds": session_idle_seconds()}
        extras["csrf_token"] = csrf_token_for(raw) if raw else ""
    return extras


def go_live_checks() -> List[Dict[str, Any]]:
    """Checks for /platform/go-live-gate: SSO configured, MFA required, break-glass disabled."""
    sso = sso_enabled()
    required = mfa_required()
    glass = bool(_flag("PQC_ALLOW_BREAK_GLASS_KEY"))
    return [
        {"key": "admin_sso", "label": "Operator SSO", "status": "pass" if sso else "fail",
         "detail": "Operator SSO (OIDC) is configured with a roster or allowed domains." if sso else
         "Operator SSO is not configured; the portal relies on keys.",
         "fix": "Set PQC_ADMIN_OIDC_ISSUER, PQC_ADMIN_OIDC_CLIENT_ID and PQC_ADMIN_OPERATOR_ROLES (or PQC_ADMIN_OIDC_ALLOWED_DOMAINS)."},
        {"key": "admin_mfa_required", "label": "Operator MFA required", "status": "pass" if required else "fail",
         "detail": "Operators must pass TOTP before the console unlocks." if required else "Operator MFA is not required.",
         "fix": "Set PQC_ENVIRONMENT=production (MFA defaults on) and do not set PQC_ADMIN_REQUIRE_MFA=0."},
        {"key": "admin_break_glass_disabled", "label": "Shared key is break-glass only", "status": "fail" if glass else "pass",
         "detail": "PQC_ALLOW_BREAK_GLASS_KEY=1: the shared platform key is accepted (every use audited)." if glass else
         "The shared platform key is refused in production/staging unless break-glass is enabled.",
         "fix": "Unset PQC_ALLOW_BREAK_GLASS_KEY once the emergency is over."},
    ]
