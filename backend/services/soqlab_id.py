"""Sign in with SOQLAB: one passkey for Morrow and Q-Lab, held at id.soqlab.com.

Off unless all four are set (then also needs MORROW_PUBLIC_BASE_URL, which gives the callback URL):

  MORROW_SOQLAB_ID_ISSUER         https://id.soqlab.com
  MORROW_SOQLAB_ID_CLIENT_ID      Morrow's client ID at the service
  MORROW_SOQLAB_ID_CLIENT_SECRET  its client secret (client_secret_basic at /token)
  MORROW_SOQLAB_ID_LINK_KEY       Morrow's EC P-256 private key, PEM ("\\n" escapes allowed), that signs link tickets

The service registers https://<MORROW_PUBLIC_BASE_URL host>/auth/soqlab/callback as Morrow's redirect URI.

What it is. OpenID Connect authorization code with PKCE (S256). The service gives Morrow a pairwise
`sub` (different for every product) and nothing else: no name, no email. Morrow maps that sub to its
own account (morrow_soqlab_links) and then signs the person in exactly as a passkey sign-in does,
with its own tokens (services/auth_issuer.start_session). Morrow's own passkeys keep working.

Linking. A signed-in person (recent sign-in), a recovery ticket, or a new sign-up gets a link
ticket: a 5-minute ES256 JWT signed with MORROW_SOQLAB_ID_LINK_KEY (the service only holds the public
half), single-use jti. The browser goes to <issuer>/link?ticket=..., creates or picks a SOQLAB passkey,
and comes back with a code; the ID token then carries link_ticket = our jti, and only then is the
sub bound to the account the ticket was issued for. A sign-up allocates the new account's id in the
ticket and creates the account when it comes back.

No cookies. Every round trip is a row in morrow_soqlab_flows keyed by the SHA-256 of `state`, bound
to the browser tab by a random secret the page keeps in sessionStorage (`flow`), single use (claimed
atomically before anything is checked, so a replayed callback is refused), 10 minutes.

Network. The issuer comes from configuration only, never from a request. Discovery, keys, /token and
/unlink are fetched only from the issuer's own origin, https (http only for localhost), no
redirects followed, 5 s timeout, 64 KB cap. Discovery and keys are cached for an hour; an unknown
key id refetches the keys at most once a minute.

ID tokens. ES256 only (the header is checked before anything else), kid from the JWKS, iss, aud
(and azp when aud is a list), exp and iat, nonce, amr containing "passkey", and link_ticket as above.
The redirect back must carry iss equal to the issuer (RFC 9207).

Tables. Neither table has a tenant column: a link belongs to an account, not an organization, like
morrow_passkeys and morrow_recovery_codes, so they are not in services/postgres_rls.ORG_SCOPED_TABLES.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlencode, urlparse

FLOW_TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_soqlab_flows (
        state_sha256 TEXT PRIMARY KEY,
        binding_sha256 TEXT NOT NULL,
        purpose TEXT NOT NULL,
        user_id TEXT NOT NULL DEFAULT '',
        nonce TEXT NOT NULL,
        code_verifier TEXT NOT NULL,
        jti TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL DEFAULT '{}',
        return_to TEXT NOT NULL DEFAULT '/ui/',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    )
"""

LINK_TABLE = """
    CREATE TABLE IF NOT EXISTS morrow_soqlab_links (
        issuer TEXT NOT NULL,
        sub TEXT NOT NULL,
        user_id TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        PRIMARY KEY (issuer, sub)
    )
"""

PURPOSES = {"login", "link", "recover", "signup"}
#: Where a page that started a round trip wants to come back to (never a URL from the request).
RETURN_PATHS = {"console": "/ui/", "signup": "/signup", "reset": "/reset-password"}
FLOW_TTL = 600
TICKET_TTL = 300
MAX_FETCH_BYTES = 65536
FETCH_TIMEOUT = 5.0
CACHE_TTL = 3600
JWKS_REFRESH_MIN = 60
LEEWAY = 60


class SoqlabIdError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


# ── Configuration ──────────────────────────────────────────────────────────────

def _env(name: str) -> str:
    return str(os.getenv(name) or "").strip()


def issuer() -> str:
    """The configured issuer, normalized, or '' when it isn't a usable https origin."""
    raw = _env("MORROW_SOQLAB_ID_ISSUER").rstrip("/")
    if not raw:
        return ""
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    if p.path or p.query or p.fragment or p.params or p.username or p.password or not host:
        return ""
    if p.scheme == "https" or (p.scheme == "http" and host in {"localhost", "127.0.0.1"}):
        return raw
    return ""


def client_id() -> str:
    return _env("MORROW_SOQLAB_ID_CLIENT_ID")


def _client_secret() -> str:
    return _env("MORROW_SOQLAB_ID_CLIENT_SECRET")


_key_cache: Dict[str, Any] = {}


def _link_key():
    """The EC P-256 private key that signs link tickets, or None."""
    pem = _env("MORROW_SOQLAB_ID_LINK_KEY").replace("\\n", "\n")
    if not pem:
        return None
    if _key_cache.get("pem") == pem:
        return _key_cache["key"]
    key = None
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        loaded = load_pem_private_key(pem.encode("utf-8"), password=None)
        if isinstance(loaded, ec.EllipticCurvePrivateKey) and loaded.curve.name == "secp256r1":
            key = loaded
    except Exception:
        key = None
    _key_cache.update({"pem": pem, "key": key})
    return key


def redirect_uri() -> str:
    from services.public_config import public_base_url
    base = public_base_url()
    return f"{base}/auth/soqlab/callback" if base else ""


def enabled() -> bool:
    return bool(issuer() and client_id() and _client_secret() and redirect_uri() and _link_key() is not None)


def issuer_host() -> str:
    return (urlparse(issuer()).hostname or "") if enabled() else ""


# ── Storage ────────────────────────────────────────────────────────────────────

def init_tables(db) -> None:
    db.execute(FLOW_TABLE)
    db.execute(LINK_TABLE)
    db.execute("CREATE INDEX IF NOT EXISTS idx_morrow_soqlab_flows_expiry ON morrow_soqlab_flows (expires_at)")
    db.commit()


def _now() -> int:
    return int(time.time())


def _sha(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def link_of_user(db, user_id: str) -> Optional[Dict[str, Any]]:
    row = db.execute("SELECT sub, created_at, last_used_at FROM morrow_soqlab_links WHERE issuer=? AND user_id=?",
                     (issuer(), str(user_id or ""))).fetchone()
    return {"sub": row[0], "created_at": row[1], "last_used_at": row[2]} if row else None


def user_of_sub(db, sub: str) -> str:
    row = db.execute("SELECT user_id FROM morrow_soqlab_links WHERE issuer=? AND sub=?", (issuer(), sub)).fetchone()
    return str(row[0]) if row else ""


def touch(db, sub: str) -> None:
    db.execute("UPDATE morrow_soqlab_links SET last_used_at=? WHERE issuer=? AND sub=?", (_now(), issuer(), sub))
    db.commit()


def bind(db, user_id: str, sub: str, *, replace: bool = False) -> None:
    """Link sub to user_id. A sub linked to another account is refused; an account already linked to a
    different sub is refused unless `replace` (account recovery)."""
    owner = user_of_sub(db, sub)
    if owner and owner != user_id:
        raise SoqlabIdError(409, "This SOQLAB passkey is already linked to a different Morrow account.", "sub_taken")
    if owner == user_id:
        return
    current = link_of_user(db, user_id)
    if current and not replace:
        raise SoqlabIdError(409, "This account is already linked to a SOQLAB passkey. Unlink it first.", "already_linked")
    if current:
        db.execute("DELETE FROM morrow_soqlab_links WHERE user_id=?", (user_id,))
    db.execute("INSERT INTO morrow_soqlab_links (issuer, sub, user_id, created_at) VALUES (?, ?, ?, ?)",
               (issuer(), sub, user_id, _now()))
    db.commit()


def unbind(db, user_id: str) -> str:
    """Delete the account's link; the sub it had ('' when none)."""
    current = link_of_user(db, user_id)
    db.execute("DELETE FROM morrow_soqlab_links WHERE user_id=?", (str(user_id or ""),))
    db.commit()
    return current["sub"] if current else ""


# ── Network (issuer origin only) ───────────────────────────────────────────────

def _same_origin(url: str) -> bool:
    a, b = urlparse(url or ""), urlparse(issuer())
    return bool(a.scheme and a.netloc) and (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())


def _http(method: str, url: str, *, data: Optional[Dict[str, str]] = None,
          headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any]:
    """One request to the issuer's origin: no redirects, a timeout and a size cap. (status, JSON or None)."""
    import requests

    if not _same_origin(url):
        raise SoqlabIdError(502, "SOQLAB ID answered with an address outside its own site.", "foreign_url")
    try:
        with requests.request(method, url, data=data, headers={"Accept": "application/json", **(headers or {})},
                              timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True) as res:
            body = b""
            for chunk in res.iter_content(8192):
                body += chunk
                if len(body) > MAX_FETCH_BYTES:
                    raise SoqlabIdError(502, "SOQLAB ID sent too much data.", "too_large")
            status = res.status_code
    except SoqlabIdError:
        raise
    except Exception:
        raise SoqlabIdError(502, "SOQLAB ID can't be reached just now. Try again in a minute.", "unreachable") from None
    try:
        return status, json.loads(body.decode("utf-8")) if body else None
    except Exception:
        return status, None


#: Swappable in tests (a fake issuer); everything network goes through here.
fetch: Callable[..., Tuple[int, Any]] = _http

_cache_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()


def discovery() -> Dict[str, Any]:
    iss = issuer()
    with _cache_lock:
        hit = _cache.get("discovery")
        if hit and hit[0] == iss and hit[1] > time.time():
            return hit[2]
    status, doc = fetch("GET", iss + "/.well-known/openid-configuration")
    if status != 200 or not isinstance(doc, dict):
        raise SoqlabIdError(502, "SOQLAB ID can't be reached just now. Try again in a minute.", "discovery")
    if doc.get("issuer") != iss:
        raise SoqlabIdError(502, "SOQLAB ID's configuration names a different issuer.", "issuer_mismatch")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not _same_origin(str(doc.get(name) or "")):
            raise SoqlabIdError(502, "SOQLAB ID's configuration points outside its own site.", "foreign_endpoint")
    with _cache_lock:
        _cache["discovery"] = (iss, time.time() + CACHE_TTL, doc)
    return doc


def _jwks(force: bool = False) -> Dict[str, Any]:
    uri = discovery()["jwks_uri"]
    with _cache_lock:
        hit = _cache.get("jwks")
        if hit and hit[0] == uri and (hit[1] > time.time()) and not (force and hit[3] + JWKS_REFRESH_MIN < time.time()):
            return hit[2]
    status, doc = fetch("GET", uri)
    if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise SoqlabIdError(502, "SOQLAB ID's keys can't be read just now. Try again in a minute.", "jwks")
    with _cache_lock:
        _cache["jwks"] = (uri, time.time() + CACHE_TTL, doc, time.time())
    return doc


def _key_for(kid: str):
    import jwt

    for attempt in (False, True):
        for jwk in _jwks(force=attempt).get("keys") or []:
            if isinstance(jwk, dict) and jwk.get("kid") == kid and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
                return jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
    raise SoqlabIdError(401, "SOQLAB ID's answer was signed with a key it doesn't publish.", "unknown_kid")


# ── Round trips ────────────────────────────────────────────────────────────────

def _link_ticket(sub: str, jti: str, state: str, nonce: str, challenge: str) -> str:
    import jwt

    now = _now()
    claims = {"iss": client_id(), "aud": issuer(), "sub": sub, "jti": jti, "iat": now, "exp": now + TICKET_TTL,
              "code_challenge": challenge, "state": state, "nonce": nonce, "redirect_uri": redirect_uri()}
    return jwt.encode(claims, _link_key(), algorithm="ES256", headers={"typ": "JWT"})


def start(db, purpose: str, *, user_id: str = "", context: Optional[Dict[str, Any]] = None,
          return_to: str = "console") -> Dict[str, Any]:
    """Begin a round trip: {authorize_url, flow}. The page keeps `flow` and sends it back with the code.

    login: <issuer>/authorize. link, recover, signup: <issuer>/link with a ticket for `user_id`
    (signup: the id the new account will get)."""
    if not enabled():
        raise SoqlabIdError(404, "Sign in with SOQLAB isn't turned on here.", "disabled")
    if purpose not in PURPOSES:
        raise SoqlabIdError(400, "Unknown kind of SOQLAB sign-in.")
    if purpose != "login" and not user_id:
        raise SoqlabIdError(400, "A link needs an account.")
    doc = discovery()
    state, nonce, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    jti = secrets.token_urlsafe(24) if purpose != "login" else ""
    now = _now()
    db.execute("DELETE FROM morrow_soqlab_flows WHERE expires_at < ?", (now - 86400,))
    db.execute("INSERT INTO morrow_soqlab_flows (state_sha256, binding_sha256, purpose, user_id, nonce, code_verifier, jti,"
               " context, return_to, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (_sha(state), _sha(binding), purpose, user_id, nonce, verifier, jti, json.dumps(context or {}),
                RETURN_PATHS.get(return_to, "/ui/"), now, now + FLOW_TTL))
    db.commit()
    if purpose == "login":
        url = doc["authorization_endpoint"] + "?" + urlencode({
            "response_type": "code", "client_id": client_id(), "redirect_uri": redirect_uri(), "scope": "openid",
            "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
    else:
        url = issuer() + "/link?" + urlencode({"ticket": _link_ticket(user_id, jti, state, nonce, challenge)})
    return {"authorize_url": url, "flow": binding, "expires_in": FLOW_TTL}


def return_path(db, state: str) -> str:
    """Where the page that started this round trip lives (for GET /auth/soqlab/callback)."""
    row = db.execute("SELECT return_to FROM morrow_soqlab_flows WHERE state_sha256=?", (_sha(state),)).fetchone()
    return str(row[0]) if row and str(row[0]) in RETURN_PATHS.values() else "/ui/"


def claim(db, state: str, binding: str) -> Dict[str, Any]:
    """Use up the round trip `state` names, once. The tab's binding must match."""
    key = _sha(state)
    row = db.execute("SELECT binding_sha256, purpose, user_id, nonce, code_verifier, jti, context, expires_at, used_at"
                     " FROM morrow_soqlab_flows WHERE state_sha256=?", (key,)).fetchone()
    if not row:
        raise SoqlabIdError(400, "This sign-in wasn't started here, or it has expired. Start again.", "unknown_state")
    cur = db.execute("UPDATE morrow_soqlab_flows SET used_at=? WHERE state_sha256=? AND used_at IS NULL", (_now(), key))
    db.commit()
    if getattr(cur, "rowcount", 1) != 1 or row[8] is not None:
        raise SoqlabIdError(400, "This sign-in was already used. Start again.", "replayed")
    if not hmac.compare_digest(str(row[0]), _sha(binding)):
        raise SoqlabIdError(400, "This sign-in was started in a different browser tab. Start again.", "binding")
    if int(row[7]) < _now():
        raise SoqlabIdError(400, "This sign-in took too long. Start again.", "expired_flow")
    try:
        context = json.loads(row[6] or "{}")
    except ValueError:
        context = {}
    return {"purpose": row[1], "user_id": row[2], "nonce": row[3], "code_verifier": row[4], "jti": row[5],
            "context": context if isinstance(context, dict) else {}}


def _verify_id_token(token: str, flow: Dict[str, Any]) -> Dict[str, Any]:
    import jwt

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise SoqlabIdError(401, "SOQLAB ID's answer couldn't be read.", "bad_token") from None
    if header.get("alg") != "ES256":
        raise SoqlabIdError(401, "SOQLAB ID's answer wasn't signed the way it must be.", "bad_alg")
    key = _key_for(str(header.get("kid") or ""))
    try:
        claims = jwt.decode(token, key, algorithms=["ES256"], audience=client_id(), issuer=issuer(), leeway=LEEWAY,
                            options={"require": ["iss", "aud", "sub", "exp", "iat"]})
    except jwt.ExpiredSignatureError:
        raise SoqlabIdError(401, "SOQLAB ID's answer has expired. Start again.", "expired") from None
    except jwt.InvalidAudienceError:
        raise SoqlabIdError(401, "SOQLAB ID's answer was meant for a different site.", "wrong_aud") from None
    except Exception:
        raise SoqlabIdError(401, "SOQLAB ID's answer didn't check out.", "bad_token") from None
    if isinstance(claims.get("aud"), list) and claims.get("azp") != client_id():
        raise SoqlabIdError(401, "SOQLAB ID's answer was meant for a different site.", "wrong_aud")
    if int(claims.get("iat") or 0) > _now() + LEEWAY:
        raise SoqlabIdError(401, "SOQLAB ID's answer is dated in the future.", "bad_iat")
    if not hmac.compare_digest(str(claims.get("nonce") or ""), str(flow["nonce"])):
        raise SoqlabIdError(401, "SOQLAB ID's answer belongs to a different sign-in.", "nonce")
    amr = claims.get("amr")
    if not isinstance(amr, list) or "passkey" not in amr:
        raise SoqlabIdError(401, "SOQLAB ID didn't confirm a passkey.", "amr")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not 1 <= len(sub) <= 255:
        raise SoqlabIdError(401, "SOQLAB ID's answer didn't check out.", "bad_sub")
    ticket = claims.get("link_ticket")
    if flow["jti"]:
        if not isinstance(ticket, str) or not hmac.compare_digest(ticket, flow["jti"]):
            raise SoqlabIdError(401, "SOQLAB ID's answer belongs to a different link.", "link_ticket")
    elif ticket is not None:
        raise SoqlabIdError(401, "SOQLAB ID's answer belongs to a link, not a sign-in.", "link_ticket")
    return claims


def exchange(flow: Dict[str, Any], code: str, iss: str) -> Dict[str, Any]:
    """Check the redirect's iss, exchange the code, verify the ID token. The verified claims."""
    if not hmac.compare_digest(str(iss or ""), issuer()):
        raise SoqlabIdError(400, "This answer didn't come from SOQLAB ID.", "iss")
    if not code or len(code) > 512:
        raise SoqlabIdError(400, "SOQLAB ID's answer had no code. Start again.", "no_code")
    token_endpoint = discovery()["token_endpoint"]
    basic = base64.b64encode(f"{quote(client_id(), safe='')}:{quote(_client_secret(), safe='')}".encode()).decode()
    status, body = fetch("POST", token_endpoint, headers={"Authorization": "Basic " + basic},
                         data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(),
                               "code_verifier": flow["code_verifier"]})
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("id_token"), str):
        raise SoqlabIdError(401, "SOQLAB ID didn't accept this sign-in. Start again.", "token_refused")
    return _verify_id_token(body["id_token"], flow)


def remote_unlink(sub: str) -> bool:
    """Ask the service to forget the link (best effort; the local unlink already happened)."""
    if not sub or not enabled():
        return False
    try:
        basic = base64.b64encode(f"{quote(client_id(), safe='')}:{quote(_client_secret(), safe='')}".encode()).decode()
        status, _ = fetch("POST", issuer() + "/unlink", headers={"Authorization": "Basic " + basic}, data={"sub": sub})
        return status == 200
    except SoqlabIdError:
        return False


def new_user_id() -> str:
    return str(uuid.uuid4())
