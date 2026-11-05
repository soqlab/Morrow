"""Certificate-manager and cloud KMS inventory sync: read what an organization's certificate and key
managers already know, and put every certificate and key into Morrow's inventory, classified for
quantum risk.

  keyfactor        Keyfactor Command (on-prem or hosted)            certificates
  venafi_cloud     Venafi TLS Protect Cloud (CyberArk Certificate Manager - SaaS)   certificates
  venafi_tpp       Venafi Trust Protection Platform (on-prem)        certificates
  digicert         DigiCert CertCentral                              certificates
  aws_kms          AWS Key Management Service                        keys
  azure_key_vault  Azure Key Vault                                   keys
  gcp_kms          Google Cloud KMS                                  keys

READ-ONLY. Every call below lists, searches or describes. Nothing here issues, renews, revokes,
retires, imports, rotates, disables or deletes a certificate or a key, and no write endpoint of any
vendor is referenced. The only POSTs are a search (TLS Protect Cloud certificatesearch), token
requests (TPP, Azure AD, Google OAuth) and the AWS JSON protocol, where every action -- including
ListKeys and DescribeKey -- is a POST.

TESTED AGAINST DOCUMENTED RESPONSES ONLY. The fixtures in test_cert_inventory.py are shaped exactly
like each vendor's published examples (URLs below and next to each connector). None of these
connectors has been run against a live account; field names a vendor documents only loosely are
read defensively and called out in docs/CERTIFICATE_AND_KMS_INVENTORY.md.

How it fits the rest of Morrow (same pattern as services/code_hosts.py):
  * Credentials are sealed with the platform vault key (vault_crypto.encrypt_secret) the moment they
    arrive and are never returned by any route.
  * A customer-supplied server URL (Keyfactor, TPP) must be HTTPS on a public address, checked when
    the connection is added and again before every sync (services/gateway_network). A Morrow
    installed inside a company network may reach internal servers with
    MORROW_CERT_SOURCES_ALLOW_PRIVATE=1 (MORROW_CODE_HOSTS_ALLOW_PRIVATE=1 is honoured too: it is the
    same deployment decision). Redirects are never followed, and every follow-up URL a server hands
    back (TPP _links, Azure nextLink and key ids) must stay on the host that was checked.
  * Every row carries org_id and is only read through that organization.
  * Each certificate or key becomes an inventory asset (db.upsert_asset). A certificate also seen by
    a TLS scan is matched by fingerprint and attached to that host:port asset instead of being
    listed twice; the same certificate reported by two managers lands on one asset.
  * Quantum risk comes from services/fips_pq.classify_algorithm, the same table the rest of the
    platform uses.
  * Scheduled sync is off for every connection until someone picks an interval; Celery beat runs
    run_due_syncs() (tasks.py) and it only touches connections whose interval has come round.
"""

from __future__ import annotations

import base64
import email.utils
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from db_feature_store import atomic, feature_conn

TIMEOUT_S = 25
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ATTEMPTS = 5            # per request, for 429 / 503 / throttling answers
MAX_BACKOFF_S = 60.0
MAX_ITEMS_PER_SYNC = 50_000
MAX_REQUESTS_PER_SYNC = 20_000
MAX_DIGICERT_DETAILS = 2_000
MAX_SOURCES_PER_ORG = 25
MIN_MANUAL_SYNC_INTERVAL_S = 30
TLS_SCAN_LOOKBACK = 50
SCHEDULE_CHOICES = (0, 6, 12, 24, 168)   # hours; 0 = scheduled sync off (the default)

AZURE_KEYS_API_VERSION = "2025-07-01"

SCHEMA = """
    CREATE TABLE IF NOT EXISTS org_cert_sources (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        base_url TEXT NOT NULL DEFAULT '',
        settings_json TEXT NOT NULL DEFAULT '{}',
        secret_enc TEXT NOT NULL,
        account TEXT NOT NULL DEFAULT '',
        schedule_hours INTEGER NOT NULL DEFAULT 0,
        next_sync_at TEXT,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_sync_started_at TEXT,
        last_sync_at TEXT,
        last_sync_status TEXT NOT NULL DEFAULT '',
        last_sync_message TEXT NOT NULL DEFAULT '',
        last_sync_count INTEGER NOT NULL DEFAULT 0
    )
"""

ITEMS_SCHEMA = """
    CREATE TABLE IF NOT EXISTS org_cert_inventory (
        org_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        item_key TEXT NOT NULL,
        provider TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        fingerprint_sha1 TEXT NOT NULL DEFAULT '',
        fingerprint_sha256 TEXT NOT NULL DEFAULT '',
        serial TEXT NOT NULL DEFAULT '',
        subject TEXT NOT NULL DEFAULT '',
        issuer TEXT NOT NULL DEFAULT '',
        key_algorithm TEXT NOT NULL DEFAULT '',
        key_size INTEGER,
        curve TEXT NOT NULL DEFAULT '',
        signature_algorithm TEXT NOT NULL DEFAULT '',
        not_after TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT '',
        algorithm TEXT NOT NULL DEFAULT '',
        risk TEXT NOT NULL DEFAULT '',
        classification_json TEXT NOT NULL DEFAULT '{}',
        asset_key TEXT NOT NULL DEFAULT '',
        linked_tls INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (org_id, source_id, item_key)
    )
"""

# ── What the console shows ──────────────────────────────────────────────────────────────────────
# fields: name, label, type (text|password|url|textarea|select), required, secret, placeholder.

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "keyfactor": {
        "name": "Keyfactor Command", "kind": "certificates",
        "docs": ["https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificatesGET.htm",
                 "https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/Web%20API%20Common%20Features.htm"],
        "steps": ["Create (or pick) a service account with the Certificates: Read permission.",
                  "Enter the API address: your server and the API path, usually https://keyfactor.example.com/KeyfactorAPI.",
                  "Give the username as DOMAIN\\user and its password, or paste an OAuth access token instead."],
        "fields": [
            {"name": "base_url", "label": "API address", "type": "url", "required": True,
             "placeholder": "https://keyfactor.example.com/KeyfactorAPI"},
            {"name": "username", "label": "Username (DOMAIN\\user)", "type": "text"},
            {"name": "password", "label": "Password", "type": "password", "secret": True},
            {"name": "token", "label": "Or an OAuth access token", "type": "password", "secret": True},
        ],
    },
    "venafi_cloud": {
        "name": "Venafi TLS Protect Cloud", "kind": "certificates",
        "docs": ["https://mim.pan.dev/api-endpoints/saas/certificate-manager-saas-api",
                 "https://mim.pan.dev/api-endpoints/saas/certificates-search-get-by-expression",
                 "https://github.com/Venafi/vcert/blob/master/pkg/venafi/cloud/search.go"],
        "steps": ["Sign in to TLS Protect Cloud, open your avatar > Preferences > API Keys and copy the key.",
                  "Pick the region your tenant lives in.",
                  "A key belonging to a user who can see the certificates is enough; Morrow only searches."],
        "fields": [
            {"name": "region", "label": "Region", "type": "select", "required": True,
             "options": ["us", "eu", "uk", "au", "ca", "sg"]},
            {"name": "api_key", "label": "API key", "type": "password", "secret": True, "required": True},
        ],
    },
    "venafi_tpp": {
        "name": "Venafi Trust Protection Platform", "kind": "certificates",
        "docs": ["https://docs.venafi.com/Docs/current/TopNav/Content/SDK/AuthSDK/r-SDKa-POST-AuthorizeOAuth.php",
                 "https://docs.venafi.com/Docs/25.3/TopNav/Content/SDK/WebSDK/r-SDK-GET-Certificates.php"],
        "steps": ["In TPP, create an API integration (API > Integrations) that allows the certificate scope (read only is enough).",
                  "Copy its Client ID, and use a user who can read the certificate folders you want inventoried.",
                  "Enter the server address, e.g. https://tpp.example.com."],
        "fields": [
            {"name": "base_url", "label": "Server address", "type": "url", "required": True,
             "placeholder": "https://tpp.example.com"},
            {"name": "client_id", "label": "API integration Client ID", "type": "text", "required": True},
            {"name": "username", "label": "Username", "type": "text", "required": True,
             "placeholder": "local:morrow-reader or AD+corp:svc-morrow"},
            {"name": "password", "label": "Password", "type": "password", "secret": True, "required": True},
        ],
    },
    "digicert": {
        "name": "DigiCert CertCentral", "kind": "certificates",
        "docs": ["https://dev.digicert.com/certcentral-apis/services-api/orders/list-orders.html",
                 "https://dev.digicert.com/md/certcentral-apis/services-api/orders/order-info.md"],
        "steps": ["In CertCentral open Automation > API Keys (or Account > API Keys) and add a key.",
                  "A key restricted to View Only is enough; Morrow only lists orders.",
                  "Paste it here."],
        "fields": [
            {"name": "api_key", "label": "API key", "type": "password", "secret": True, "required": True},
        ],
    },
    "aws_kms": {
        "name": "AWS KMS", "kind": "keys",
        "docs": ["https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html",
                 "https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html"],
        "steps": ["Create an IAM user or role key with only kms:ListKeys and kms:DescribeKey (the same credential shape as Cloud discovery).",
                  "List the regions to read, separated by commas."],
        "fields": [
            {"name": "access_key_id", "label": "Access key ID", "type": "text", "required": True},
            {"name": "secret_access_key", "label": "Secret access key", "type": "password", "secret": True, "required": True},
            {"name": "session_token", "label": "Session token (temporary credentials only)", "type": "password", "secret": True},
            {"name": "regions", "label": "Regions", "type": "text", "required": True, "placeholder": "us-east-1, eu-west-1"},
        ],
    },
    "azure_key_vault": {
        "name": "Azure Key Vault", "kind": "keys",
        "docs": ["https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys",
                 "https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key"],
        "steps": ["Use an app registration (the same tenant/client/secret shape as Cloud discovery).",
                  "Give it the Key Vault Reader role on each vault (or an access policy with List and Get on keys).",
                  "List the vault URLs, one per line, like https://myvault.vault.azure.net."],
        "fields": [
            {"name": "tenant_id", "label": "Tenant ID", "type": "text", "required": True},
            {"name": "client_id", "label": "Client ID", "type": "text", "required": True},
            {"name": "client_secret", "label": "Client secret", "type": "password", "secret": True, "required": True},
            {"name": "vault_urls", "label": "Vault URLs (one per line)", "type": "textarea", "required": True,
             "placeholder": "https://myvault.vault.azure.net"},
        ],
    },
    "gcp_kms": {
        "name": "Google Cloud KMS", "kind": "keys",
        "docs": ["https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/list",
                 "https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list",
                 "https://docs.cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm"],
        "steps": ["Create a service account with roles/cloudkms.viewer on the project and download a JSON key.",
                  "Paste the key file's contents. Leave locations empty to read every location."],
        "fields": [
            {"name": "project_id", "label": "Project ID", "type": "text", "placeholder": "taken from the key file when empty"},
            {"name": "service_account_json", "label": "Service account key (JSON)", "type": "textarea", "secret": True, "required": True},
            {"name": "locations", "label": "Locations (optional)", "type": "text", "placeholder": "global, us-east1"},
        ],
    },
}

VENAFI_CLOUD_REGIONS = {
    # https://mim.pan.dev/api-endpoints/saas/certificate-manager-saas-api (region base URLs)
    "us": "api.venafi.cloud", "eu": "api.eu.venafi.cloud", "uk": "api.uk.venafi.cloud",
    "au": "api.au.venafi.cloud", "ca": "api.ca.venafi.cloud", "sg": "api.sg.venafi.cloud",
}

# What to tell the user when a vendor refuses the credentials.
AUTH_HELP = {
    "keyfactor": "Keyfactor Command refused the credentials. Check the username is written DOMAIN\\user and the "
                 "password is current (or that the OAuth token has not expired), and that the account has the "
                 "Certificates: Read permission (/certificates/collections/read/).",
    "venafi_cloud": "TLS Protect Cloud refused the API key. Copy a current key from your avatar > Preferences > "
                    "API Keys, and check the region matches your tenant.",
    "venafi_tpp": "Trust Protection Platform refused the sign-in. Check the Client ID matches the API integration, "
                  "that the integration allows the certificate scope, and the username (with its identity-provider "
                  "prefix, e.g. local:user or AD+corp:user) and password.",
    "digicert": "DigiCert refused the API key (X-DC-DEVKEY). Check the key is still active under API Keys and "
                "that its restrictions allow viewing orders.",
    "aws_kms": "AWS refused the access key. Check the key is active and its policy allows kms:ListKeys and "
               "kms:DescribeKey in the listed regions.",
    "azure_key_vault": "Azure refused access. Check the tenant ID, client ID and client secret (secrets expire), and "
                       "that the app has the Key Vault Reader role (or List and Get on keys) on every listed vault.",
    "gcp_kms": "Google Cloud refused the service account. Check the key has not been deleted and the account has "
               "roles/cloudkms.viewer on the project.",
}

_AWS_AUTH_TYPES = ("UnrecognizedClientException", "InvalidSignatureException", "AccessDeniedException",
                   "IncompleteSignature", "MissingAuthenticationToken", "ExpiredTokenException",
                   "InvalidClientTokenId", "SignatureDoesNotMatch")
_AWS_THROTTLE_TYPES = ("ThrottlingException", "Throttling", "TooManyRequestsException", "LimitExceededException",
                       "RequestLimitExceeded")

_ready = False
_ready_lock = threading.Lock()
_sync_locks: Dict[str, threading.Lock] = {}
_sync_locks_guard = threading.Lock()

_sleep: Callable[[float], None] = time.sleep   # tests replace it, so backoff never really waits


class CertSourceError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def _now() -> str:
    return _iso(_now_dt())


def _init() -> None:
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with feature_conn() as conn:
            conn.execute(SCHEMA)
            conn.execute(ITEMS_SCHEMA)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_org_cert_inventory_org ON org_cert_inventory (org_id, risk)")
            conn.commit()
        _ready = True


def init_tables() -> None:
    _init()


# ── URL checks (SSRF guard) ─────────────────────────────────────────────────────────────────────

def private_servers_allowed() -> bool:
    """MORROW_CERT_SOURCES_ALLOW_PRIVATE=1 (or MORROW_CODE_HOSTS_ALLOW_PRIVATE=1): a Morrow installed
    inside a company network may reach the company's own Keyfactor or TPP on internal addresses and
    non-standard ports. Off by default, and must stay off on a shared hosted instance."""
    for name in ("MORROW_CERT_SOURCES_ALLOW_PRIVATE", "MORROW_CODE_HOSTS_ALLOW_PRIVATE"):
        if os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on"):
            return True
    return False


def _require_public_host(host: str) -> None:
    if private_servers_allowed():
        return
    from services import gateway_network

    try:
        gateway_network.public_ips(gateway_network.hostname(host))
    except gateway_network.CheckError as exc:
        raise CertSourceError(400, f"{host}: {exc}. The server must be reachable on the public internet "
                                   "(an internal server needs MORROW_CERT_SOURCES_ALLOW_PRIVATE=1 on a "
                                   "self-hosted Morrow).") from None


def normalize_server_url(value: Any, keep_path: bool = True) -> str:
    """A customer-supplied server address: https, no credentials/query/fragment, public host."""
    text = str(value or "").strip().rstrip("/")
    if not text:
        raise CertSourceError(400, "Enter the server address, like https://server.example.com.")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        raise CertSourceError(400, "That is not a valid address.") from None
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or "\\" in text or any(c.isspace() for c in text)):
        raise CertSourceError(400, "Use the https:// address of the server, without a query or credentials.")
    if port not in (None, 443) and not private_servers_allowed():
        raise CertSourceError(400, "Only HTTPS on the standard port (443) is supported.")
    path = parts.path.rstrip("/") if keep_path else ""
    if not keep_path and parts.path not in ("", "/"):
        raise CertSourceError(400, "Enter the server address only, without a path.")
    if path and not re.fullmatch(r"(/[A-Za-z0-9._~-]+){1,4}", path):
        raise CertSourceError(400, "The address path may only contain letters, digits, '.', '_', '-' and '/'.")
    host = parts.hostname.lower()
    _require_public_host(host)
    suffix = f":{port}" if port not in (None, 443) else ""
    return f"https://{host}{suffix}{path}"


_AZURE_VAULT_RE = re.compile(r"^https://([a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9]))\.vault\.azure\.net$")


def normalize_vault_url(value: Any) -> str:
    text = str(value or "").strip().rstrip("/").lower()
    if text and "." not in text and "/" not in text:
        text = f"https://{text}.vault.azure.net"
    if not _AZURE_VAULT_RE.match(text):
        raise CertSourceError(400, f"{str(value)[:80]!r} is not a Key Vault URL. Use https://<vault-name>.vault.azure.net.")
    return text


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


# ── HTTP: no redirects, bounded, retries with backoff on rate limits ────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _transport(method: str, url: str, headers: Dict[str, str], data: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
    """One HTTP exchange. Replaced in tests by a fake that answers like each vendor documents."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=TIMEOUT_S) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        hdrs = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        try:
            body = exc.read(MAX_RESPONSE_BYTES + 1) or b""
        except Exception:
            body = b""
        return exc.code, hdrs, body
    except (urllib.error.URLError, OSError) as exc:
        raise CertSourceError(502, f"Could not reach {_host(url)} ({exc.__class__.__name__}). Check the address "
                                   "and that Morrow can reach it.") from None


def _retry_after(headers: Dict[str, str], attempt: int) -> float:
    value = str(headers.get("retry-after") or "").strip()
    if value:
        if value.isdigit():
            return min(float(value), MAX_BACKOFF_S)
        try:
            when = email.utils.parsedate_to_datetime(value)
            return max(0.0, min((when - _now_dt()).total_seconds(), MAX_BACKOFF_S))
        except Exception:
            pass
    return min(2.0 ** attempt, MAX_BACKOFF_S)


def _message(payload: Any) -> str:
    """The vendor's own error text, in whichever shape it uses."""
    if not isinstance(payload, dict):
        return ""
    for key in ("message", "Message", "error_description", "ErrorDetails", "detail"):
        if isinstance(payload.get(key), str):
            return payload[key]
    err = payload.get("error") or payload.get("errors")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("code") or "")
    if isinstance(err, list) and err:
        first = err[0]
        return str(first.get("message") or first.get("code") or "") if isinstance(first, dict) else str(first)
    if isinstance(err, str):
        return err
    return ""


class _Session:
    """Per-sync request context: provider, allowed hosts, request budget."""

    def __init__(self, provider: str, hosts: Iterable[str] = ()):
        self.provider = provider
        self.hosts = {h.lower() for h in hosts if h}
        self.requests = 0

    def allow(self, *hosts: str) -> None:
        self.hosts.update(h.lower() for h in hosts if h)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Any = None,
                form: Optional[Dict[str, str]] = None, raw_body: Optional[bytes] = None,
                stage: str = "") -> Tuple[int, Any, Dict[str, str]]:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or (parts.hostname or "").lower() not in self.hosts:
            raise CertSourceError(502, f"{PROVIDERS[self.provider]['name']} pointed Morrow at {parts.hostname or url[:60]}, "
                                       "a different server than the one configured. Morrow did not follow it.")
        hdrs = {"Accept": "application/json", "User-Agent": "Morrow-Inventory/1", **(headers or {})}
        data = raw_body
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        for attempt in range(MAX_ATTEMPTS):
            self.requests += 1
            if self.requests > MAX_REQUESTS_PER_SYNC:
                raise CertSourceError(400, f"Stopped after {MAX_REQUESTS_PER_SYNC} requests to "
                                           f"{PROVIDERS[self.provider]['name']}; narrow the connection's scope.")
            status, resp_headers, raw = _transport(method, url, hdrs, data)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise CertSourceError(502, f"{PROVIDERS[self.provider]['name']} sent a response larger than "
                                           f"{MAX_RESPONSE_BYTES // (1024 * 1024)} MB.")
            try:
                payload = json.loads(raw) if raw else {}
            except ValueError:
                payload = {"raw": raw[:300].decode("utf-8", "replace")}
            throttled = status in (429, 503) or (
                self.provider == "aws_kms" and status == 400 and isinstance(payload, dict)
                and str(payload.get("__type", "")).split("#")[-1] in _AWS_THROTTLE_TYPES)
            if throttled and attempt < MAX_ATTEMPTS - 1:
                _sleep(_retry_after(resp_headers, attempt))
                continue
            if throttled:
                raise CertSourceError(429, f"{PROVIDERS[self.provider]['name']} is rate-limiting Morrow (HTTP {status}) "
                                           f"after {MAX_ATTEMPTS} attempts with backoff. Try again later, or sync less often.")
            if status >= 400 or 300 <= status < 400:
                raise self._error(status, payload, stage)
            return status, payload, resp_headers
        raise CertSourceError(502, "No answer.")  # pragma: no cover - loop always returns or raises

    def _error(self, status: int, payload: Any, stage: str) -> CertSourceError:
        name = PROVIDERS[self.provider]["name"]
        message = re.sub(r"\s+", " ", _message(payload))[:240]
        tail = f" ({message})" if message else ""
        aws_type = str(payload.get("__type", "")).split("#")[-1] if isinstance(payload, dict) else ""
        if (status in (401, 403) or (stage == "token" and status in (400, 401))
                or (self.provider == "aws_kms" and aws_type in _AWS_AUTH_TYPES)):
            return CertSourceError(400, AUTH_HELP[self.provider] + tail)
        if 300 <= status < 400:
            return CertSourceError(400, f"{name} answered with a redirect (HTTP {status}). Enter the final address "
                                        "of the API; Morrow does not follow redirects.")
        if status == 404:
            return CertSourceError(400, f"{name} answered 404: check the address (and API path) is right.{tail}")
        return CertSourceError(502, f"{name} answered HTTP {status}.{tail}")


# ── Algorithm normalisation and quantum-risk classification ─────────────────────────────────────

_RISK_ORDER = {"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _family(text: Any) -> str:
    t = re.sub(r"[\s\-]+", "_", str(text or "").upper())
    if not t:
        return ""
    if "ML_DSA" in t or "DILITHIUM" in t:
        return "ML-DSA"
    if "ML_KEM" in t or "KYBER" in t:
        return "ML-KEM"
    if "SLH_DSA" in t or "SPHINCS" in t:
        return "SLH-DSA"
    if "XWING" in t:
        return "X-Wing"
    if "ED25519" in t:
        return "Ed25519"
    if "ED448" in t:
        return "Ed448"
    if "HMAC" in t:
        return "HMAC"
    if "RSA" in t:
        return "RSA"
    if "ECDH" in t:
        return "ECDH"
    if t.startswith(("EC", "P_", "P2", "P3", "P5", "SECP", "PRIME", "NIST")) or "ECDSA" in t or "ECC" in t:
        return "EC"
    if "AES" in t or "SYMMETRIC" in t or t.startswith("OCT"):
        return "AES"
    if "SM2" in t:
        return "SM2"
    if "DSA" in t:
        return "DSA"
    return str(text).strip()[:40]


def _curve(text: Any) -> str:
    t = re.sub(r"[\s_\-]+", "", str(text or "").upper())
    if not t:
        return ""
    if "SECP256K1" in t or t.endswith("256K"):
        return "secp256k1"
    for bits, name in (("256", "P-256"), ("384", "P-384"), ("521", "P-521")):
        if bits in t and ("P" in t or "SECP" in t or "NIST" in t or "PRIME" in t):
            return name
    if "25519" in t:
        return "Ed25519"
    if "448" in t:
        return "Ed448"
    return str(text).strip()[:40]


def _curve_from_size(size: Optional[int]) -> str:
    return {256: "P-256", 384: "P-384", 521: "P-521"}.get(size or 0, "")


def _int(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip())
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def _weak_signature(sig: str) -> str:
    t = re.sub(r"[\s_\-]+", "", str(sig or "").upper())
    if "MD5" in t or "MD2" in t:
        return "MD5"
    if "SHA1" in t:
        return "SHA-1"
    return ""


def classify(item: Dict[str, Any]) -> Dict[str, Any]:
    """Quantum-risk verdict for one certificate or key, via services/fips_pq.classify_algorithm."""
    from services.fips_pq import classify_algorithm

    family = item.get("key_algorithm") or ""
    size = item.get("key_size")
    curve = item.get("curve") or ""
    raw = str(item.get("algorithm_detail") or "")
    label, lookup = family or "unknown", family
    if family == "RSA":
        label = f"RSA-{size}" if size else "RSA"
        lookup = label if size in (2048, 3072, 4096) else "RSA"
    elif family in ("EC", "ECDH"):
        label = f"{family} {curve}".strip() if curve else family
        if family == "ECDH":
            lookup = {"P-256": "ECDH-256", "P-384": "ECDH-384"}.get(curve, "ECDH")
        else:
            lookup = curve if curve in ("P-256", "P-384", "P-521") else "ECDSA"
    elif family in ("Ed25519", "Ed448"):
        lookup = "ED25519"                        # EdDSA either way: broken by Shor
    elif family == "SM2":
        lookup = "ECDSA"                          # SM2 is an elliptic-curve scheme
    elif family == "DSA":
        lookup = "DH"                             # discrete log, same verdict as DH
    elif family in ("ML-DSA", "ML-KEM", "SLH-DSA"):
        m = re.search(r"(\d{2,4})", raw)
        level = m.group(1) if m else ""
        if family == "SLH-DSA":
            m2 = re.search(r"SLH[_-]DSA[_-](SHA2|SHAKE)[_-](\d{3})([SF])", raw.upper())
            label = f"SLH-DSA-{m2.group(1)}-{m2.group(2)}{m2.group(3).lower()}" if m2 else "SLH-DSA"
        else:
            label = f"{family}-{level}" if level else family
        lookup = label if label != family else {"ML-DSA": "ML-DSA-65", "ML-KEM": "ML-KEM-768",
                                                "SLH-DSA": "SLH-DSA-SHA2-128s"}[family]
    elif family == "X-Wing":
        label, lookup = "X-Wing (X25519 + ML-KEM-768)", "X25519MLKEM768"
    elif family == "AES":
        label = f"AES-{size}" if size else "AES"
        # An AES key of unknown size (an external or HSM key the API does not size) stays "unknown".
        lookup = {128: "AES-128", 256: "AES-256"}.get(size or 0, label)
    elif family == "HMAC":
        m = re.search(r"SHA[_-]?(1|224|256|384|512)\b", raw.upper())
        digest = m.group(1) if m else (str(size) if size in (224, 256, 384, 512) else "")
        label = f"HMAC-SHA{digest}" if digest else "HMAC"
        # HMAC is symmetric: Grover halves its security margin but Shor does not apply. Judge it by
        # its hash, which is what fips_pq knows about.
        lookup = {"1": "SHA-1", "256": "SHA-256", "384": "SHA-384", "512": "SHA-512"}.get(digest, label)
    verdict = classify_algorithm(lookup or label)
    verdict = {**verdict, "algorithm": label}
    sig = _weak_signature(item.get("signature_algorithm") or "")
    signature = None
    if sig:
        sv = classify_algorithm(sig)
        signature = {"algorithm": item.get("signature_algorithm"), "status": sv["status"], "risk": sv["risk"],
                     "details": sv["details"]}
        if _RISK_ORDER.get(sv["risk"], 0) > _RISK_ORDER.get(verdict["risk"], 0):
            verdict["risk"] = sv["risk"]
    verdict["signature"] = signature
    verdict["quantum_vulnerable"] = verdict["status"] == "quantum_vulnerable"
    return verdict


# ── Fingerprints and dates ──────────────────────────────────────────────────────────────────────

def _fp(value: Any) -> str:
    text = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return text if len(text) in (40, 64) else ""


def _date(value: Any) -> str:
    """ISO-8601 UTC from the shapes vendors use: ISO strings, yyyy-MM-dd, epoch seconds."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,11}(\.\d+)?", value.strip())):
        try:
            return _iso(datetime.fromtimestamp(float(value), tz=timezone.utc))
        except (OverflowError, OSError, ValueError):
            return ""
    text = str(value).strip()
    m = re.fullmatch(r"/Date\((\d+)\)/", text)
    if m:
        return _iso(datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc))
    # .NET-style 7-digit fractions (TPP, Keyfactor) are trimmed to the 6 Python 3.11 accepts.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:40]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _iso(dt)


def _first(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _item(**fields: Any) -> Dict[str, Any]:
    base = {"kind": "certificate", "item_key": "", "name": "", "fingerprint_sha1": "", "fingerprint_sha256": "",
            "serial": "", "subject": "", "issuer": "", "key_algorithm": "", "key_size": None, "curve": "",
            "signature_algorithm": "", "not_after": "", "owner": "", "state": "", "algorithm_detail": "",
            "metadata": {}}
    base.update(fields)
    fp = _fp(base.get("fingerprint"))
    base.pop("fingerprint", None)
    if fp:
        base["fingerprint_sha1" if len(fp) == 40 else "fingerprint_sha256"] = fp
    if not base["curve"] and base["key_algorithm"] in ("EC", "ECDH"):
        base["curve"] = _curve_from_size(base["key_size"])
    return base


# ── Keyfactor Command ───────────────────────────────────────────────────────────────────────────
# GET {base}/Certificates?PageReturned=&ReturnLimit= with Authorization Basic DOMAIN\user:pass or
# Bearer; X-Keyfactor-API-Version 1; X-Keyfactor-Requested-With APIClient (mandatory only on writes,
# sent anyway). Response: a JSON array of certificates (Id, Thumbprint, SerialNumber, IssuedDN,
# IssuedCN, IssuerDN, NotAfter, KeySizeInBits, KeyTypeString, KeyAlgorithm, SigningAlgorithm,
# Metadata, CertStateString, OwnerRoleName, RequesterName). Paging: PageReturned (1-based) x
# ReturnLimit; stop on a short page. X-Total-Count is a common response header.
#   https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificatesGET.htm
#   https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/Web%20API%20Common%20Features.htm

KEYFACTOR_PAGE = 200


def _kf_headers(ctx: Dict[str, Any]) -> Dict[str, str]:
    s = ctx["secret"]
    if s.get("token"):
        auth = f"Bearer {s['token']}"
    else:
        auth = "Basic " + base64.b64encode(f"{ctx['settings'].get('username', '')}:{s.get('password', '')}".encode()).decode()
    return {"Authorization": auth, "Accept": "application/json; charset=utf-8", "X-Keyfactor-API-Version": "1",
            "X-Keyfactor-Requested-With": "APIClient"}


def _kf_page(ctx, session, page: int, limit: int) -> List[Dict[str, Any]]:
    q = urllib.parse.urlencode({"PageReturned": page, "ReturnLimit": limit, "includeMetadata": "true",
                                "includeExpired": "false", "includeRevoked": "false"})
    _, data, _ = session.request("GET", f"{ctx['base_url']}/Certificates?{q}", _kf_headers(ctx))
    if not isinstance(data, list):
        raise CertSourceError(502, "Keyfactor Command did not return a certificate list; check the API path "
                                   "(usually /KeyfactorAPI).")
    return data


def _keyfactor_test(ctx, session) -> str:
    _kf_page(ctx, session, 1, 1)
    return ctx["settings"].get("username") or "OAuth token"


def _keyfactor_owner(c: Dict[str, Any]) -> str:
    meta = c.get("Metadata") if isinstance(c.get("Metadata"), dict) else {}
    for key in ("Owner", "OwnerEmail", "Email-Contact", "AppOwnerEmailAddress", "BusinessOwner"):
        if meta.get(key):
            return str(meta[key])
    return str(c.get("OwnerRoleName") or c.get("RequesterName") or "")


def _keyfactor_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    page = 1
    while True:
        rows = _kf_page(ctx, session, page, KEYFACTOR_PAGE)
        for c in rows:
            if not isinstance(c, dict):
                continue
            alg = str(c.get("KeyAlgorithm") or c.get("KeyTypeString") or "")
            family = _family(re.sub(r"\(.*\)", "", alg) or c.get("KeyTypeString"))
            size = _int(c.get("KeySizeInBits"))
            yield _item(kind="certificate", item_key=str(c.get("Id") or c.get("Thumbprint") or ""),
                        name=str(c.get("IssuedCN") or c.get("IssuedDN") or ""), fingerprint=c.get("Thumbprint"),
                        serial=str(c.get("SerialNumber") or ""), subject=str(c.get("IssuedDN") or ""),
                        issuer=str(c.get("IssuerDN") or ""), key_algorithm=family, key_size=size,
                        curve=_curve(alg) if family == "EC" and re.search(r"P-?\d{3}|secp", alg, re.I) else "",
                        signature_algorithm=str(c.get("SigningAlgorithm") or ""), not_after=_date(c.get("NotAfter")),
                        owner=_keyfactor_owner(c), state=str(c.get("CertStateString") or ""), algorithm_detail=alg,
                        metadata={"keyfactor_id": c.get("Id"), "template": c.get("TemplateName") or "",
                                  "owner_role": c.get("OwnerRoleName") or ""})
        if len(rows) < KEYFACTOR_PAGE:
            return
        page += 1


# ── Venafi TLS Protect Cloud ────────────────────────────────────────────────────────────────────
# POST https://api.venafi.cloud/outagedetection/v1/certificatesearch, header tppl-api-key.
# Body {"paging": {"pageNumber": n, "pageSize": m}} (vcert SearchRequest/Paging); response
# {"count": N, "certificates": [{id, certificateName, fingerprint, serialNumber, subjectCN[],
# subjectDN, issuerCN[], validityEnd, keyStrength, encryptionType, keyCurve, signatureAlgorithm,
# signatureHashAlgorithm, applicationIds, ...}]}. Region hosts per the SaaS API overview.
#   https://mim.pan.dev/api-endpoints/saas/certificate-manager-saas-api
#   https://mim.pan.dev/api-endpoints/saas/certificates-search-get-by-expression
#   https://github.com/Venafi/vcert/blob/master/pkg/venafi/cloud/search.go
# Field names beyond vcert's struct come from the documented SaaS export fields
# (https://docs.defectdojo.com/supported_tools/parsers/file/venafi/) and are read defensively.

VENAFI_CLOUD_PAGE = 200


def _vc_base(ctx) -> str:
    return "https://" + VENAFI_CLOUD_REGIONS[ctx["settings"]["region"]]


def _vc_search(ctx, session, page: int, size: int) -> Dict[str, Any]:
    _, data, _ = session.request("POST", _vc_base(ctx) + "/outagedetection/v1/certificatesearch",
                                 {"tppl-api-key": ctx["secret"]["api_key"]},
                                 body={"paging": {"pageNumber": page, "pageSize": size}})
    return data if isinstance(data, dict) else {}


def _venafi_cloud_test(ctx, session) -> str:
    data = _vc_search(ctx, session, 0, 1)
    return f"{int(data.get('count') or 0)} certificates visible"


def _venafi_cloud_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    seen: set = set()
    page = 0
    while True:
        data = _vc_search(ctx, session, page, VENAFI_CLOUD_PAGE)
        certs = [c for c in (data.get("certificates") or []) if isinstance(c, dict)]
        fresh = [c for c in certs if str(c.get("id") or c.get("fingerprint")) not in seen]
        for c in fresh:
            seen.add(str(c.get("id") or c.get("fingerprint")))
            enc = str(c.get("encryptionType") or c.get("keyType") or "")
            family = _family(enc)
            size = _int(c.get("keyStrength") or c.get("keySize"))
            ownership = c.get("ownership") if isinstance(c.get("ownership"), dict) else {}
            owner = ""
            for key in ("owningUsers", "owningTeams", "owningContainers"):
                vals = ownership.get(key)
                if isinstance(vals, list) and vals:
                    owner = str(vals[0].get("name") if isinstance(vals[0], dict) else vals[0])
                    break
            yield _item(kind="certificate", item_key=str(c.get("id") or c.get("fingerprint") or ""),
                        name=str(c.get("certificateName") or _first(c.get("subjectCN"))),
                        fingerprint=c.get("fingerprint"), serial=str(c.get("serialNumber") or ""),
                        subject=str(c.get("subjectDN") or _first(c.get("subjectCN"))),
                        issuer=str(c.get("issuerDN") or _first(c.get("issuerCN"))), key_algorithm=family,
                        key_size=size, curve=_curve(c.get("keyCurve")) if c.get("keyCurve") else "",
                        signature_algorithm=str(c.get("signatureAlgorithm") or c.get("signatureHashAlgorithm") or ""),
                        not_after=_date(c.get("validityEnd")), owner=owner,
                        state=str(c.get("certificateStatus") or ""), algorithm_detail=enc,
                        metadata={"venafi_id": c.get("id"), "application_ids": c.get("applicationIds") or []})
        total = int(data.get("count") or 0)
        if not fresh or len(certs) < VENAFI_CLOUD_PAGE or len(seen) >= total:
            return
        page += 1


# ── Venafi Trust Protection Platform ────────────────────────────────────────────────────────────
# Token: POST {base}/vedauth/authorize/oauth {client_id, username, password, scope} -> access_token.
# List:  GET {base}/vedsdk/certificates/?Limit=&Offset=&OptionalFields=KeyAlgorithm,KeySize,Subject,Issuer
#        (trailing slash required, else 307), Authorization: Bearer. Response {"Certificates":
#        [{CreatedOn, DN, Guid, Name, ParentDn, SchemaClass, X509: {CN, Issuer, KeyAlgorithm, KeySize,
#        SANS, Serial, Subject, Thumbprint (SHA-1), ValidFrom, ValidTo}}], "TotalCount", "_links"}.
#   https://docs.venafi.com/Docs/current/TopNav/Content/SDK/AuthSDK/r-SDKa-POST-AuthorizeOAuth.php
#   https://docs.venafi.com/Docs/25.3/TopNav/Content/SDK/WebSDK/r-SDK-GET-Certificates.php

TPP_PAGE = 500


def _tpp_token(ctx, session) -> str:
    _, data, _ = session.request("POST", ctx["base_url"] + "/vedauth/authorize/oauth", {}, body={
        "client_id": ctx["settings"]["client_id"], "username": ctx["settings"]["username"],
        "password": ctx["secret"]["password"], "scope": "certificate"}, stage="token")
    token = str((data or {}).get("access_token") or "")
    if not token:
        raise CertSourceError(400, AUTH_HELP["venafi_tpp"])
    return token


def _tpp_page(ctx, session, token: str, offset: int, limit: int) -> Dict[str, Any]:
    q = urllib.parse.urlencode({"Limit": limit, "Offset": offset, "OptionalFields": "KeyAlgorithm,KeySize,Subject,Issuer"})
    _, data, _ = session.request("GET", f"{ctx['base_url']}/vedsdk/certificates/?{q}",
                                 {"Authorization": f"Bearer {token}"})
    return data if isinstance(data, dict) else {}


def _venafi_tpp_test(ctx, session) -> str:
    _tpp_page(ctx, session, _tpp_token(ctx, session), 0, 1)
    return ctx["settings"]["username"]


def _venafi_tpp_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    token = _tpp_token(ctx, session)
    offset = 0
    while True:
        data = _tpp_page(ctx, session, token, offset, TPP_PAGE)
        certs = [c for c in (data.get("Certificates") or []) if isinstance(c, dict)]
        for c in certs:
            x = c.get("X509") if isinstance(c.get("X509"), dict) else {}
            alg = str(x.get("KeyAlgorithm") or "")
            yield _item(kind="certificate", item_key=str(c.get("Guid") or c.get("DN") or ""),
                        name=str(x.get("CN") or c.get("Name") or ""), fingerprint=x.get("Thumbprint"),
                        serial=str(x.get("Serial") or ""), subject=str(x.get("Subject") or x.get("CN") or ""),
                        issuer=str(x.get("Issuer") or ""), key_algorithm=_family(alg), key_size=_int(x.get("KeySize")),
                        signature_algorithm="", not_after=_date(x.get("ValidTo")), owner="",
                        algorithm_detail=alg, metadata={"tpp_dn": c.get("DN") or "", "folder": c.get("ParentDn") or ""})
        offset += len(certs)
        total = _int(data.get("TotalCount")) or 0
        if not certs or len(certs) < TPP_PAGE or offset >= total:
            return


# ── DigiCert CertCentral ────────────────────────────────────────────────────────────────────────
# List:  GET https://www.digicert.com/services/v2/order/certificate?offset=&limit= (default 1000,
#        max 5000), header X-DC-DEVKEY. Response {"orders": [{id, certificate: {id, common_name,
#        dns_names, valid_till, days_remaining, signature_hash}, status, organization, container,
#        product}], "page": {"total", "limit", "offset"}}.
# Info:  GET https://www.digicert.com/services/v2/order/certificate/{order_id} adds certificate
#        {thumbprint, serial_number, key_size, signature_hash, csr, ca_cert}, user {email}.
#        The key algorithm is not a documented field: it is read from the order's CSR when present,
#        otherwise inferred from key_size (256/384/521 = EC) and marked as inferred.
#   https://dev.digicert.com/certcentral-apis/services-api/orders/list-orders.html
#   https://dev.digicert.com/md/certcentral-apis/services-api/orders/order-info.md

DIGICERT_API = "https://www.digicert.com/services/v2"
DIGICERT_PAGE = 1000


def _dc_headers(ctx) -> Dict[str, str]:
    return {"X-DC-DEVKEY": ctx["secret"]["api_key"], "Content-Type": "application/json"}


def _dc_list(ctx, session, offset: int, limit: int) -> Dict[str, Any]:
    q = urllib.parse.urlencode({"offset": offset, "limit": limit, "filters[status]": "issued"})
    _, data, _ = session.request("GET", f"{DIGICERT_API}/order/certificate?{q}", _dc_headers(ctx))
    return data if isinstance(data, dict) else {}


def _digicert_test(ctx, session) -> str:
    data = _dc_list(ctx, session, 0, 1)
    return f"{int((data.get('page') or {}).get('total') or 0)} issued orders"


def _csr_key(pem: Any) -> Tuple[str, Optional[int], str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

        text = str(pem or "").strip()
        if not text:
            return "", None, ""
        if "BEGIN" not in text:
            text = "-----BEGIN CERTIFICATE REQUEST-----\n" + text + "\n-----END CERTIFICATE REQUEST-----"
        key = x509.load_pem_x509_csr(text.encode()).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return "RSA", key.key_size, ""
        if isinstance(key, ec.EllipticCurvePublicKey):
            return "EC", key.curve.key_size, _curve(key.curve.name)
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, "Ed25519"
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", 456, "Ed448"
    except Exception:
        pass
    return "", None, ""


def _digicert_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    offset, details = 0, 0
    while True:
        data = _dc_list(ctx, session, offset, DIGICERT_PAGE)
        orders = [o for o in (data.get("orders") or []) if isinstance(o, dict)]
        for o in orders:
            cert = o.get("certificate") if isinstance(o.get("certificate"), dict) else {}
            info: Dict[str, Any] = {}
            if details < MAX_DIGICERT_DETAILS and o.get("id"):
                details += 1
                _, info, _ = session.request("GET", f"{DIGICERT_API}/order/certificate/{_int(o['id']) or 0}",
                                             _dc_headers(ctx))
                info = info if isinstance(info, dict) else {}
            full = {**cert, **(info.get("certificate") if isinstance(info.get("certificate"), dict) else {})}
            size = _int(full.get("key_size"))
            family, csr_size, curve = _csr_key(full.get("csr"))
            inferred = False
            if not family and size:
                family, curve, inferred = ("EC", _curve_from_size(size), True) if size in (256, 384, 521) else ("RSA", "", True)
            user = info.get("user") if isinstance(info.get("user"), dict) else {}
            org = o.get("organization") if isinstance(o.get("organization"), dict) else {}
            container = o.get("container") if isinstance(o.get("container"), dict) else {}
            yield _item(kind="certificate", item_key=str(o.get("id") or full.get("id") or ""),
                        name=str(full.get("common_name") or ""), fingerprint=full.get("thumbprint"),
                        serial=str(full.get("serial_number") or ""), subject=str(full.get("common_name") or ""),
                        issuer=str((full.get("ca_cert") or {}).get("name") or "") if isinstance(full.get("ca_cert"), dict) else "",
                        key_algorithm=family, key_size=csr_size or size, curve=curve,
                        signature_algorithm=str(full.get("signature_hash") or ""), not_after=_date(full.get("valid_till")),
                        owner=str(user.get("email") or ""), state=str(o.get("status") or ""),
                        metadata={"digicert_order_id": o.get("id"), "organization": org.get("name") or "",
                                  "container": container.get("name") or "", "dns_names": full.get("dns_names") or [],
                                  "key_algorithm_inferred": inferred,
                                  "details_skipped": not info})
        offset += len(orders)
        total = int((data.get("page") or {}).get("total") or 0)
        if not orders or offset >= total:
            return


# ── AWS KMS ─────────────────────────────────────────────────────────────────────────────────────
# JSON protocol: POST https://kms.{region}.amazonaws.com/ with X-Amz-Target TrentService.ListKeys /
# TrentService.DescribeKey, Content-Type application/x-amz-json-1.1, SigV4 over content-type;host;
# x-amz-date;x-amz-target (signing reused from services/cloud_discovery). ListKeys {"Limit": 1-1000,
# "Marker"} -> {"Keys": [{KeyArn, KeyId}], "NextMarker", "Truncated"}; DescribeKey {"KeyId"} ->
# {"KeyMetadata": {KeySpec, KeyUsage, KeyState, KeyManager, Description, ValidTo, ...}}.
#   https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
#   https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html

_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")


def _aws_call(ctx, session, region: str, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    from services.cloud_discovery import _aws_sign_request

    host = f"kms.{region}.amazonaws.com"
    session.allow(host)
    body = json.dumps(payload).encode("utf-8")
    s = ctx["secret"]
    headers = _aws_sign_request("POST", "kms", region, host, "/", "", body, ctx["settings"]["access_key_id"],
                                s["secret_access_key"], s.get("session_token", ""),
                                extra_headers={"Content-Type": "application/x-amz-json-1.1",
                                               "X-Amz-Target": f"TrentService.{action}"})
    _, data, _ = session.request("POST", f"https://{host}/", headers, raw_body=body)
    return data if isinstance(data, dict) else {}


def _aws_kms_test(ctx, session) -> str:
    _aws_call(ctx, session, ctx["settings"]["regions"][0], "ListKeys", {"Limit": 1})
    key = ctx["settings"]["access_key_id"]
    return f"{key[:4]}…{key[-4:]}"


def _aws_keyspec(spec: str) -> Tuple[str, Optional[int], str]:
    s = str(spec or "").upper()
    m = re.match(r"RSA_(\d+)", s)
    if m:
        return "RSA", int(m.group(1)), ""
    if s.startswith("ECC_NIST_P"):
        bits = int(s.rsplit("P", 1)[1])
        return "EC", bits, _curve_from_size(bits)
    if s == "ECC_SECG_P256K1":
        return "EC", 256, "secp256k1"
    if s.startswith("ECC_NIST_EDWARDS25519") or "ED25519" in s:
        return "Ed25519", 256, "Ed25519"
    if s == "SYMMETRIC_DEFAULT":
        return "AES", 256, ""                    # AES-256-GCM
    m = re.match(r"HMAC_(\d+)", s)
    if m:
        return "HMAC", int(m.group(1)), ""
    if s.startswith("ML_DSA"):
        return "ML-DSA", None, ""
    if s.startswith("SM2"):
        return "SM2", 256, "SM2"
    return _family(s), None, ""


def _aws_kms_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    for region in ctx["settings"]["regions"]:
        marker = ""
        while True:
            req: Dict[str, Any] = {"Limit": 1000}
            if marker:
                req["Marker"] = marker
            page = _aws_call(ctx, session, region, "ListKeys", req)
            for k in page.get("Keys") or []:
                if not isinstance(k, dict) or not k.get("KeyId"):
                    continue
                meta = _aws_call(ctx, session, region, "DescribeKey", {"KeyId": k["KeyId"]}).get("KeyMetadata") or {}
                spec = str(meta.get("KeySpec") or meta.get("CustomerMasterKeySpec") or "")
                family, size, curve = _aws_keyspec(spec)
                yield _item(kind="key", item_key=str(meta.get("Arn") or k.get("KeyArn") or k["KeyId"]),
                            name=str(meta.get("Description") or k["KeyId"]), key_algorithm=family, key_size=size,
                            curve=curve, not_after=_date(meta.get("ValidTo")), state=str(meta.get("KeyState") or ""),
                            algorithm_detail=spec,
                            metadata={"region": region, "key_id": k["KeyId"], "key_spec": spec,
                                      "key_usage": meta.get("KeyUsage") or "", "key_manager": meta.get("KeyManager") or "",
                                      "origin": meta.get("Origin") or "", "account": meta.get("AWSAccountId") or ""})
            if not page.get("Truncated") or not page.get("NextMarker"):
                break
            marker = str(page["NextMarker"])


# ── Azure Key Vault ─────────────────────────────────────────────────────────────────────────────
# Token: client credentials, scope https://vault.azure.net/.default (token request reused from
# services/cloud_discovery). List: GET {vault}/keys?api-version=2025-07-01&maxresults=25 ->
# {"value": [{kid, attributes {enabled, exp, nbf, created, updated}, tags, managed}], "nextLink"}.
# The list carries no key type, so each key is read: GET {kid}?api-version -> {"key": {kid, kty
# (EC|EC-HSM|RSA|RSA-HSM|oct|oct-HSM), crv (P-256|P-384|P-521|P-256K), n, e}, attributes, tags}.
# No key_size is returned; an RSA size is the bit length of the modulus n.
#   https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys
#   https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key

_AZURE_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _azure_token(ctx, session) -> str:
    from services.cloud_discovery import _azure_get_token

    session.allow("login.microsoftonline.com")
    s, st = ctx["secret"], ctx["settings"]

    def post(url, form):
        return session.request("POST", url, {}, form=form, stage="token")[1]

    token = _azure_get_token(st["tenant_id"], st["client_id"], s["client_secret"],
                             scope="https://vault.azure.net/.default", http_post=post)
    if not token:
        raise CertSourceError(400, AUTH_HELP["azure_key_vault"])
    return token


def _b64len_bits(value: Any) -> Optional[int]:
    try:
        text = str(value or "")
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        raw = raw.lstrip(b"\x00")
        return len(raw) * 8 if raw else None
    except Exception:
        return None


def _azure_list(session, token: str, vault: str, maxresults: int = 25) -> Iterator[Dict[str, Any]]:
    url = f"{vault}/keys?api-version={AZURE_KEYS_API_VERSION}&maxresults={maxresults}"
    while url:
        _, data, _ = session.request("GET", url, {"Authorization": f"Bearer {token}"})
        data = data if isinstance(data, dict) else {}
        for item in data.get("value") or []:
            if isinstance(item, dict):
                yield item
        nxt = str(data.get("nextLink") or "")
        if nxt and _host(nxt) != _host(vault):
            raise CertSourceError(502, "Azure Key Vault returned a next page on a different host; stopped.")
        url = nxt


def _azure_key_vault_test(ctx, session) -> str:
    token = _azure_token(ctx, session)
    vault = ctx["settings"]["vault_urls"][0]
    session.request("GET", f"{vault}/keys?api-version={AZURE_KEYS_API_VERSION}&maxresults=1",
                    {"Authorization": f"Bearer {token}"})
    return ctx["settings"]["client_id"]


def _azure_key_vault_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    token = _azure_token(ctx, session)
    for vault in ctx["settings"]["vault_urls"]:
        for listed in _azure_list(session, token, vault):
            kid = str(listed.get("kid") or "")
            if not kid or _host(kid) != _host(vault):
                continue
            _, bundle, _ = session.request("GET", f"{kid}?api-version={AZURE_KEYS_API_VERSION}",
                                           {"Authorization": f"Bearer {token}"})
            bundle = bundle if isinstance(bundle, dict) else {}
            key = bundle.get("key") if isinstance(bundle.get("key"), dict) else {}
            kty = str(key.get("kty") or "")
            family = {"RSA": "RSA", "RSA-HSM": "RSA", "EC": "EC", "EC-HSM": "EC", "oct": "AES", "oct-HSM": "AES"}.get(kty, _family(kty))
            size = _b64len_bits(key.get("n")) if family == "RSA" else None
            crv = str(key.get("crv") or "")
            curve = "secp256k1" if crv == "P-256K" else crv
            if family == "EC":
                size = {"P-256": 256, "P-384": 384, "P-521": 521, "P-256K": 256}.get(crv)
            attrs = bundle.get("attributes") or listed.get("attributes") or {}
            tags = bundle.get("tags") or listed.get("tags") or {}
            owner = ""
            if isinstance(tags, dict):
                owner = str(next((v for k, v in tags.items() if str(k).strip().lower() in ("owner", "owner_email", "contact")), "") or "")
            yield _item(kind="key", item_key=kid, name=kid.rstrip("/").split("/keys/", 1)[-1], key_algorithm=family,
                        key_size=size, curve=curve, not_after=_date(attrs.get("exp")), owner=owner,
                        state="Enabled" if attrs.get("enabled", True) else "Disabled", algorithm_detail=kty,
                        metadata={"vault": vault, "kty": kty, "key_ops": key.get("key_ops") or [],
                                  "managed": bool(bundle.get("managed") or listed.get("managed"))})


# ── Google Cloud KMS ────────────────────────────────────────────────────────────────────────────
# Token: service-account JWT bearer grant (reused from services/cloud_discovery; never the metadata
# server). Walk: GET v1/projects/{p}/locations -> locations[]; GET v1/{location}/keyRings ->
# keyRings[]; GET v1/{keyRing}/cryptoKeys -> cryptoKeys[]; GET v1/{cryptoKey}/cryptoKeyVersions ->
# cryptoKeyVersions[{name, state, protectionLevel, algorithm}]; all paged by pageToken/nextPageToken.
# algorithm is a CryptoKeyVersionAlgorithm enum (RSA_SIGN_PSS_2048_SHA256, EC_SIGN_P256_SHA256,
# EC_SIGN_ED25519, GOOGLE_SYMMETRIC_ENCRYPTION, ML_KEM_768, KEM_XWING, PQ_SIGN_ML_DSA_65, ...).
#   https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/list
#   https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list
#   https://docs.cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm

GCP_KMS = "https://cloudkms.googleapis.com/v1"


def _gcp_token(ctx, session) -> str:
    from services.cloud_discovery import _gcp_service_account_token

    session.allow("oauth2.googleapis.com", "cloudkms.googleapis.com")

    def post(url, form):
        return session.request("POST", url, {}, form=form, stage="token")[1]

    try:
        token = _gcp_service_account_token(ctx["secret"]["service_account"], http_post=post)
    except CertSourceError:
        raise
    except Exception:
        raise CertSourceError(400, "The service account key could not be used to sign a token; paste the whole "
                                   "JSON key file again.") from None
    if not token:
        raise CertSourceError(400, AUTH_HELP["gcp_kms"])
    return token


def _gcp_pages(session, token: str, url: str, field: str) -> Iterator[Dict[str, Any]]:
    page = ""
    while True:
        sep = "&" if "?" in url else "?"
        full = f"{url}{sep}pageSize=1000" + (f"&pageToken={urllib.parse.quote(page, safe='')}" if page else "")
        _, data, _ = session.request("GET", full, {"Authorization": f"Bearer {token}"})
        data = data if isinstance(data, dict) else {}
        for item in data.get(field) or []:
            if isinstance(item, dict):
                yield item
        page = str(data.get("nextPageToken") or "")
        if not page:
            return


_GCP_NAME_RE = re.compile(r"^projects/[A-Za-z0-9._:-]+/locations/[A-Za-z0-9_-]+(/keyRings/[A-Za-z0-9_-]+(/cryptoKeys/[A-Za-z0-9_-]+)?)?$")


def _gcp_safe(name: str) -> str:
    if not _GCP_NAME_RE.match(name):
        raise CertSourceError(502, f"Google Cloud KMS returned an unexpected resource name: {name[:80]}")
    return name


def _gcp_algorithm(alg: str) -> Tuple[str, Optional[int], str]:
    a = str(alg or "").upper()
    m = re.search(r"RSA_[A-Z0-9_]*?_(\d{4})", a)
    if m:
        return "RSA", int(m.group(1)), ""
    if a == "EC_SIGN_ED25519":
        return "Ed25519", 256, "Ed25519"
    if "SECP256K1" in a:
        return "EC", 256, "secp256k1"
    m = re.search(r"(?:EC_SIGN|KEM_ECDH)_P(256|384|521)", a)
    if m:
        bits = int(m.group(1))
        return ("ECDH" if a.startswith("KEM_ECDH") else "EC"), bits, _curve_from_size(bits)
    if a == "GOOGLE_SYMMETRIC_ENCRYPTION":
        return "AES", 256, ""                    # AES-256-GCM
    m = re.match(r"AES_(128|256)", a)
    if m:
        return "AES", int(m.group(1)), ""
    if a == "EXTERNAL_SYMMETRIC_ENCRYPTION":
        return "AES", None, ""
    if a.startswith("HMAC_"):
        return "HMAC", None, ""
    return _family(a), None, ""


def _gcp_project(ctx) -> str:
    return ctx["settings"].get("project_id") or str(ctx["secret"]["service_account"].get("project_id") or "")


def _gcp_kms_test(ctx, session) -> str:
    token = _gcp_token(ctx, session)
    session.request("GET", f"{GCP_KMS}/projects/{_gcp_project(ctx)}/locations?pageSize=1",
                    {"Authorization": f"Bearer {token}"})
    return str(ctx["secret"]["service_account"].get("client_email") or "")


def _gcp_kms_fetch(ctx, session) -> Iterator[Dict[str, Any]]:
    token = _gcp_token(ctx, session)
    project = _gcp_project(ctx)
    locations = ctx["settings"].get("locations") or [
        str(loc.get("locationId") or str(loc.get("name", "")).rsplit("/", 1)[-1])
        for loc in _gcp_pages(session, token, f"{GCP_KMS}/projects/{project}/locations", "locations")]
    for location in locations:
        parent = _gcp_safe(f"projects/{project}/locations/{location}")
        for ring in _gcp_pages(session, token, f"{GCP_KMS}/{parent}/keyRings", "keyRings"):
            ring_name = _gcp_safe(str(ring.get("name") or ""))
            for ck in _gcp_pages(session, token, f"{GCP_KMS}/{ring_name}/cryptoKeys", "cryptoKeys"):
                key_name = _gcp_safe(str(ck.get("name") or ""))
                labels = ck.get("labels") if isinstance(ck.get("labels"), dict) else {}
                for ver in _gcp_pages(session, token, f"{GCP_KMS}/{key_name}/cryptoKeyVersions", "cryptoKeyVersions"):
                    state = str(ver.get("state") or "")
                    if state == "DESTROYED":
                        continue
                    alg = str(ver.get("algorithm") or "")
                    family, size, curve = _gcp_algorithm(alg)
                    yield _item(kind="key", item_key=str(ver.get("name") or ""), name=str(ver.get("name") or "").split("/cryptoKeys/", 1)[-1],
                                key_algorithm=family, key_size=size, curve=curve, state=state,
                                owner=str(labels.get("owner") or labels.get("team") or ""), algorithm_detail=alg,
                                metadata={"location": location, "algorithm": alg, "purpose": ck.get("purpose") or "",
                                          "protection_level": ver.get("protectionLevel") or "",
                                          "next_rotation": ck.get("nextRotationTime") or ""})


_IMPL: Dict[str, Tuple[Callable, Callable]] = {
    "keyfactor": (_keyfactor_test, _keyfactor_fetch),
    "venafi_cloud": (_venafi_cloud_test, _venafi_cloud_fetch),
    "venafi_tpp": (_venafi_tpp_test, _venafi_tpp_fetch),
    "digicert": (_digicert_test, _digicert_fetch),
    "aws_kms": (_aws_kms_test, _aws_kms_fetch),
    "azure_key_vault": (_azure_key_vault_test, _azure_key_vault_fetch),
    "gcp_kms": (_gcp_kms_test, _gcp_kms_fetch),
}


# ── Input checks ────────────────────────────────────────────────────────────────────────────────

def provider_info(provider: Any) -> Dict[str, Any]:
    info = PROVIDERS.get(str(provider or "").strip().lower())
    if not info:
        raise CertSourceError(400, f"Choose one of: {', '.join(p['name'] for p in PROVIDERS.values())}.")
    return info


def _clean(value: Any, limit: int = 300) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) > limit:
        raise CertSourceError(400, f"A value is longer than {limit} characters.")
    return text


def _list(value: Any) -> List[str]:
    if isinstance(value, list):
        parts = value
    else:
        parts = re.split(r"[\s,;]+", str(value or ""))
    return [p.strip() for p in parts if str(p).strip()]


def _validate(provider: str, fields: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """(base_url, settings, secret) from what the user typed. Secrets never go into settings."""
    info = provider_info(provider)
    f = {k: v for k, v in (fields or {}).items() if isinstance(k, str)}
    for spec in info["fields"]:
        if spec.get("required") and not str(f.get(spec["name"]) or "").strip():
            raise CertSourceError(400, f"Enter {spec['label']}.")
    settings: Dict[str, Any] = {}
    secret: Dict[str, Any] = {}
    base_url = ""
    if provider == "keyfactor":
        base_url = normalize_server_url(f.get("base_url"))
        if urllib.parse.urlsplit(base_url).path in ("", "/"):
            base_url += "/KeyfactorAPI"
        token, password, user = _clean(f.get("token"), 4000), _clean(f.get("password"), 300), _clean(f.get("username"), 200)
        if token:
            secret["token"] = token
        elif user and password:
            settings["username"], secret["password"] = user, password
        else:
            raise CertSourceError(400, "Enter a username and password, or an OAuth access token.")
    elif provider == "venafi_cloud":
        region = _clean(f.get("region") or "us").lower()
        if region not in VENAFI_CLOUD_REGIONS:
            raise CertSourceError(400, f"Pick a region: {', '.join(VENAFI_CLOUD_REGIONS)}.")
        settings["region"] = region
        secret["api_key"] = _clean(f.get("api_key"), 200)
        base_url = "https://" + VENAFI_CLOUD_REGIONS[region]
    elif provider == "venafi_tpp":
        base_url = normalize_server_url(f.get("base_url"), keep_path=False)
        settings.update(client_id=_clean(f.get("client_id"), 200), username=_clean(f.get("username"), 200))
        secret["password"] = _clean(f.get("password"), 300)
    elif provider == "digicert":
        secret["api_key"] = _clean(f.get("api_key"), 200)
        base_url = DIGICERT_API
    elif provider == "aws_kms":
        key_id = _clean(f.get("access_key_id"), 128)
        if not re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{12,124}", key_id):
            raise CertSourceError(400, "The access key ID looks wrong: it starts with AKIA (or ASIA for temporary keys).")
        regions = _list(f.get("regions"))[:30]
        bad = [r for r in regions if not _AWS_REGION_RE.match(r)]
        if not regions or bad:
            raise CertSourceError(400, f"List AWS regions like us-east-1{'; not a region: ' + bad[0][:30] if bad else ''}.")
        settings.update(access_key_id=key_id, regions=regions)
        secret.update(secret_access_key=_clean(f.get("secret_access_key"), 200),
                      session_token=_clean(f.get("session_token"), 4000))
        base_url = "https://kms.amazonaws.com"
    elif provider == "azure_key_vault":
        tenant, client = _clean(f.get("tenant_id"), 100), _clean(f.get("client_id"), 100)
        if not _AZURE_GUID_RE.match(tenant) and not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", tenant.lower()):
            raise CertSourceError(400, "The tenant ID is a GUID (or your tenant's domain, like contoso.onmicrosoft.com).")
        if not _AZURE_GUID_RE.match(client):
            raise CertSourceError(400, "The client ID is the app registration's Application (client) ID, a GUID.")
        vaults = [normalize_vault_url(v) for v in _list(f.get("vault_urls"))][:50]
        if not vaults:
            raise CertSourceError(400, "List at least one vault URL.")
        settings.update(tenant_id=tenant, client_id=client, vault_urls=list(dict.fromkeys(vaults)))
        secret["client_secret"] = _clean(f.get("client_secret"), 300)
        base_url = "https://vault.azure.net"
    elif provider == "gcp_kms":
        raw = f.get("service_account_json")
        try:
            sa = raw if isinstance(raw, dict) else json.loads(str(raw or ""))
        except ValueError:
            raise CertSourceError(400, "Paste the whole service account key file (JSON).") from None
        if not isinstance(sa, dict) or sa.get("type") != "service_account" or not sa.get("client_email") or not sa.get("private_key"):
            raise CertSourceError(400, "That is not a service account key: it needs type, client_email and private_key.")
        project = _clean(f.get("project_id"), 100) or str(sa.get("project_id") or "")
        if not re.fullmatch(r"[a-z][a-z0-9:.-]{4,98}[a-z0-9]", project or ""):
            raise CertSourceError(400, "Enter the project ID (lowercase letters, digits and hyphens).")
        locations = _list(f.get("locations"))[:40]
        if any(not re.fullmatch(r"[a-z0-9-]{2,40}", loc) for loc in locations):
            raise CertSourceError(400, "Locations look like global, us-east1 or europe-west2.")
        settings.update(project_id=project, locations=locations)
        secret["service_account"] = {k: sa[k] for k in ("type", "project_id", "private_key_id", "private_key", "client_email") if k in sa}
        base_url = GCP_KMS
    for value in secret.values():
        if isinstance(value, str) and any(c in value for c in "\r\n\t") and provider != "gcp_kms":
            raise CertSourceError(400, "Paste credentials exactly as shown, without line breaks.")
    return base_url, settings, secret


def _hosts_for(provider: str, base_url: str, settings: Dict[str, Any]) -> List[str]:
    if provider == "azure_key_vault":
        return [_host(v) for v in settings.get("vault_urls") or []]
    if provider in ("aws_kms", "gcp_kms"):
        return []                                # added per call by the connector, fixed vendor hosts
    return [_host(base_url)]


def _ctx(provider: str, base_url: str, settings: Dict[str, Any], secret: Dict[str, Any]) -> Tuple[Dict[str, Any], _Session]:
    return ({"provider": provider, "base_url": base_url, "settings": settings, "secret": secret},
            _Session(provider, _hosts_for(provider, base_url, settings)))


# ── Connections ─────────────────────────────────────────────────────────────────────────────────

def _public(row: Any) -> Dict[str, Any]:
    info = PROVIDERS.get(row["provider"], {})
    try:
        settings = json.loads(row["settings_json"] or "{}")
    except ValueError:
        settings = {}
    visible = {k: v for k, v in settings.items() if k in ("region", "regions", "vault_urls", "project_id", "locations",
                                                          "username", "client_id", "tenant_id")}
    return {"id": row["id"], "provider": row["provider"], "provider_name": info.get("name", row["provider"]),
            "kind": info.get("kind", ""), "label": row["label"], "base_url": row["base_url"], "account": row["account"],
            "settings": visible, "schedule_hours": int(row["schedule_hours"] or 0), "next_sync_at": row["next_sync_at"],
            "created_at": row["created_at"], "last_sync_at": row["last_sync_at"],
            "last_sync_status": row["last_sync_status"], "last_sync_message": row["last_sync_message"],
            "last_sync_count": int(row["last_sync_count"] or 0)}


_COLS = ("id, provider, label, base_url, settings_json, account, schedule_hours, next_sync_at, created_at, "
         "last_sync_at, last_sync_status, last_sync_message, last_sync_count")


def list_sources(org_id: str) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(f"SELECT {_COLS} FROM org_cert_sources WHERE org_id = ? ORDER BY created_at", (org_id,)).fetchall()
    return [_public(r) for r in rows]


def _schedule(hours: Any) -> int:
    try:
        value = int(hours or 0)
    except (TypeError, ValueError):
        value = -1
    if value not in SCHEDULE_CHOICES:
        raise CertSourceError(400, "Scheduled sync is off (0) or every 6, 12, 24 or 168 hours.")
    return value


def _next_run(hours: int) -> Optional[str]:
    return _iso(_now_dt() + timedelta(hours=hours)) if hours else None


def add_source(org_id: str, provider: Any, fields: Dict[str, Any], label: Any = "", schedule_hours: Any = 0,
               created_by: str = "") -> Dict[str, Any]:
    """Check the credentials against the vendor (a read-only call), then store them sealed."""
    from vault_crypto import encrypt_secret

    provider = str(provider or "").strip().lower()
    info = provider_info(provider)
    hours = _schedule(schedule_hours)
    base_url, settings, secret = _validate(provider, fields)
    ctx, session = _ctx(provider, base_url, settings, secret)
    account = _IMPL[provider][0](ctx, session)
    _init()
    new_id = "cs_" + secrets.token_hex(8)
    with feature_conn() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM org_cert_sources WHERE org_id = ?", (org_id,)).fetchone()
        if int(count["n"] or 0) >= MAX_SOURCES_PER_ORG:
            raise CertSourceError(400, f"An organization can hold up to {MAX_SOURCES_PER_ORG} inventory connections.")
        with atomic(conn):
            conn.execute(
                "INSERT INTO org_cert_sources (id, org_id, provider, label, base_url, settings_json, secret_enc, account, "
                "schedule_hours, next_sync_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (new_id, org_id, provider, str(label or "").strip()[:80] or info["name"], base_url, json.dumps(settings),
                 encrypt_secret(json.dumps(secret)), str(account or "")[:160], hours, _next_run(hours),
                 str(created_by or "")[:200], _now()))
        conn.commit()
    return next(s for s in list_sources(org_id) if s["id"] == new_id)


def _load(org_id: str, source_id: str) -> Dict[str, Any]:
    from vault_crypto import decrypt_secret

    _init()
    with feature_conn() as conn:
        row = conn.execute("SELECT id, provider, base_url, settings_json, secret_enc, last_sync_started_at "
                           "FROM org_cert_sources WHERE org_id = ? AND id = ?", (org_id, source_id)).fetchone()
    if not row:
        raise CertSourceError(404, "No such inventory connection on this organization.")
    try:
        secret = json.loads(decrypt_secret(row["secret_enc"]))
    except Exception:
        raise CertSourceError(500, "The stored credentials could not be decrypted. Remove the connection and add it again.") from None
    return {"id": row["id"], "provider": row["provider"], "base_url": row["base_url"],
            "settings": json.loads(row["settings_json"] or "{}"), "secret": secret,
            "last_sync_started_at": row["last_sync_started_at"]}


def _recheck(src: Dict[str, Any]) -> None:
    """DNS can change after a connection was added: check a customer-supplied host again before use."""
    if src["provider"] in ("keyfactor", "venafi_tpp"):
        _require_public_host(_host(src["base_url"]))


def test_source(org_id: str, source_id: str) -> Dict[str, Any]:
    src = _load(org_id, source_id)
    _recheck(src)
    ctx, session = _ctx(src["provider"], src["base_url"], src["settings"], src["secret"])
    return {"ok": True, "account": _IMPL[src["provider"]][0](ctx, session)}


def set_schedule(org_id: str, source_id: str, schedule_hours: Any) -> Dict[str, Any]:
    hours = _schedule(schedule_hours)
    _init()
    with feature_conn() as conn:
        cur = conn.execute("UPDATE org_cert_sources SET schedule_hours = ?, next_sync_at = ? WHERE org_id = ? AND id = ?",
                           (hours, _next_run(hours), org_id, source_id))
        conn.commit()
    if not int(cur.rowcount or 0):
        raise CertSourceError(404, "No such inventory connection on this organization.")
    return next(s for s in list_sources(org_id) if s["id"] == source_id)


def remove_source(org_id: str, source_id: str) -> bool:
    _init()
    with feature_conn() as conn:
        stale = conn.execute("SELECT item_key, asset_key, provider FROM org_cert_inventory WHERE org_id = ? AND source_id = ?",
                             (org_id, source_id)).fetchall()
        cur = conn.execute("DELETE FROM org_cert_sources WHERE org_id = ? AND id = ?", (org_id, source_id))
        conn.execute("DELETE FROM org_cert_inventory WHERE org_id = ? AND source_id = ?", (org_id, source_id))
        conn.commit()
    if int(cur.rowcount or 0):
        _unmirror(org_id, source_id, [dict(r) for r in stale])
    return int(cur.rowcount or 0) > 0


# ── Inventory: TLS dedup, asset mirroring, sync ─────────────────────────────────────────────────

def _tls_fingerprints(org_id: str) -> Dict[str, str]:
    """{fingerprint: host:port} from the organization's recent TLS scans (scanner.cert_sha1/256)."""
    import db

    token = db.set_current_organization_id(org_id)
    try:
        scans = db.list_scan_results_bulk(limit=TLS_SCAN_LOOKBACK)
    except Exception:
        return {}
    finally:
        db.reset_current_organization_id(token)
    out: Dict[str, str] = {}
    for scan in scans:                            # newest first: the newest sighting wins
        for r in scan.get("results") or []:
            if not isinstance(r, dict) or not r.get("host"):
                continue
            key = f"{r['host']}:{int(r.get('port') or 443)}"
            for fp in (r.get("cert_sha1"), r.get("cert_sha256")):
                if _fp(fp):
                    out.setdefault(_fp(fp), key)
    return out


def _asset_key(provider: str, item: Dict[str, Any], tls: Dict[str, str]) -> Tuple[str, bool]:
    for fp in (item["fingerprint_sha1"], item["fingerprint_sha256"]):
        if fp and fp in tls:
            return tls[fp], True
    if item["kind"] == "certificate":
        fp = item["fingerprint_sha1"] or item["fingerprint_sha256"]
        if fp:
            return f"cert:{fp}", False           # the same certificate from two managers: one asset
        return f"cert:{provider}:{item['item_key']}"[:400], False
    return f"kms:{provider}:{item['item_key']}"[:400], False


def _mirror(org_id: str, source_id: str, provider: str, items: List[Dict[str, Any]]) -> int:
    """Put each item on its inventory asset, keeping whatever people already wrote on that asset."""
    import db

    errors = 0
    token = db.set_current_organization_id(org_id)
    try:
        for it in items:
            try:
                existing = db.get_asset(it["asset_key"]) or {}
                meta = dict(existing.get("metadata") or {})
                inv = dict(meta.get("cert_inventory") or {})
                inv[source_id] = {
                    "provider": provider, "provider_name": PROVIDERS[provider]["name"], "kind": it["kind"],
                    "name": it["name"], "algorithm": it["classification"]["algorithm"], "key_size": it["key_size"],
                    "curve": it["curve"], "signature_algorithm": it["signature_algorithm"], "not_after": it["not_after"],
                    "fingerprint_sha1": it["fingerprint_sha1"], "fingerprint_sha256": it["fingerprint_sha256"],
                    "serial": it["serial"], "owner": it["owner"], "risk": it["classification"]["risk"],
                    "status": it["classification"]["status"], "synced_at": it["last_seen_at"]}
                meta["cert_inventory"] = inv
                tags = {t for t in (existing.get("tags") or []) if not str(t).startswith("quantum-risk:")}
                tags |= {f"source:{provider}", f"inventory:{it['kind']}"}
                worst = max((v.get("risk", "") for v in inv.values()), key=lambda r: _RISK_ORDER.get(r, 0))
                if worst:
                    tags.add(f"quantum-risk:{worst}")
                db.upsert_asset(it["asset_key"], owner=existing.get("owner") or it["owner"],
                                team=existing.get("team") or "", environment=existing.get("environment") or "",
                                criticality=existing.get("criticality") or "",
                                confidentiality_lifetime=existing.get("confidentiality_lifetime") or "",
                                notes=existing.get("notes") or "", tags=sorted(tags), metadata=meta)
            except Exception:
                errors += 1
    finally:
        db.reset_current_organization_id(token)
    return errors


def _unmirror(org_id: str, source_id: str, rows: List[Dict[str, Any]]) -> None:
    """Take a source's entry off assets whose item it no longer reports. The asset row stays."""
    import db

    token = db.set_current_organization_id(org_id)
    try:
        for r in rows:
            try:
                existing = db.get_asset(r["asset_key"])
                if not existing:
                    continue
                meta = dict(existing.get("metadata") or {})
                inv = dict(meta.get("cert_inventory") or {})
                if source_id not in inv:
                    continue
                inv.pop(source_id, None)
                meta["cert_inventory"] = inv
                tags = set(existing.get("tags") or [])
                if not inv:
                    tags = {t for t in tags if not str(t).startswith(("quantum-risk:", "inventory:"))}
                remaining = {v.get("provider") for v in inv.values()}
                tags = {t for t in tags if not (str(t) == f"source:{r['provider']}" and r["provider"] not in remaining)}
                db.upsert_asset(r["asset_key"], owner=existing.get("owner") or "", team=existing.get("team") or "",
                                environment=existing.get("environment") or "", criticality=existing.get("criticality") or "",
                                confidentiality_lifetime=existing.get("confidentiality_lifetime") or "",
                                notes=existing.get("notes") or "", tags=sorted(tags), metadata=meta or {"cert_inventory": {}})
            except Exception:
                continue
    finally:
        db.reset_current_organization_id(token)


def _lock_for(source_id: str) -> threading.Lock:
    with _sync_locks_guard:
        return _sync_locks.setdefault(source_id, threading.Lock())


def _record(org_id: str, source_id: str, status: str, message: str, count: Optional[int] = None,
            schedule_next: bool = True) -> None:
    with feature_conn() as conn:
        row = conn.execute("SELECT schedule_hours FROM org_cert_sources WHERE org_id = ? AND id = ?",
                           (org_id, source_id)).fetchone()
        hours = int(row["schedule_hours"] or 0) if row else 0
        if count is None:
            conn.execute("UPDATE org_cert_sources SET last_sync_at = ?, last_sync_status = ?, last_sync_message = ?, "
                         "next_sync_at = ? WHERE org_id = ? AND id = ?",
                         (_now(), status, message[:500], _next_run(hours), org_id, source_id))
        else:
            conn.execute("UPDATE org_cert_sources SET last_sync_at = ?, last_sync_status = ?, last_sync_message = ?, "
                         "last_sync_count = ?, next_sync_at = ? WHERE org_id = ? AND id = ?",
                         (_now(), status, message[:500], count, _next_run(hours), org_id, source_id))
        conn.commit()


def sync_source(org_id: str, source_id: str, trigger: str = "manual") -> Dict[str, Any]:
    """Read every certificate or key from the source into the inventory. Read-only at the vendor."""
    src = _load(org_id, source_id)
    if trigger == "manual" and src.get("last_sync_started_at"):
        try:
            started = datetime.fromisoformat(str(src["last_sync_started_at"]).replace("Z", "+00:00"))
            if (_now_dt() - started).total_seconds() < MIN_MANUAL_SYNC_INTERVAL_S:
                raise CertSourceError(429, "This connection synced moments ago; wait half a minute.")
        except ValueError:
            pass
    lock = _lock_for(source_id)
    if not lock.acquire(blocking=False):
        raise CertSourceError(409, "A sync of this connection is already running.")
    try:
        started_at = _now()
        with feature_conn() as conn:
            conn.execute("UPDATE org_cert_sources SET last_sync_started_at = ? WHERE org_id = ? AND id = ?",
                         (started_at, org_id, source_id))
            conn.commit()
        try:
            _recheck(src)
            ctx, session = _ctx(src["provider"], src["base_url"], src["settings"], src["secret"])
            fetched: List[Dict[str, Any]] = []
            for item in _IMPL[src["provider"]][1](ctx, session):
                if not item.get("item_key"):
                    continue
                fetched.append(item)
                if len(fetched) >= MAX_ITEMS_PER_SYNC:
                    break
        except CertSourceError as exc:
            _record(org_id, source_id, "error", exc.detail)
            raise
        except Exception as exc:  # a vendor answer shaped unlike its documentation
            _record(org_id, source_id, "error", f"Unexpected answer ({exc.__class__.__name__}).")
            raise CertSourceError(502, f"{PROVIDERS[src['provider']]['name']} answered in a shape Morrow did not expect "
                                       f"({exc.__class__.__name__}).") from None
        summary = _store(org_id, source_id, src["provider"], fetched, started_at)
        truncated = len(fetched) >= MAX_ITEMS_PER_SYNC
        message = (f"{summary['items']} {'keys' if PROVIDERS[src['provider']]['kind'] == 'keys' else 'certificates'}; "
                   f"{summary['quantum_vulnerable']} quantum-vulnerable; {summary['linked_to_tls']} matched to TLS scans"
                   + ("; stopped at the per-sync limit" if truncated else ""))
        _record(org_id, source_id, "ok", message, summary["items"])
        return {"ok": True, "trigger": trigger, "message": message, "truncated": truncated, **summary}
    finally:
        lock.release()


def _store(org_id: str, source_id: str, provider: str, fetched: List[Dict[str, Any]], started_at: str) -> Dict[str, Any]:
    tls = _tls_fingerprints(org_id)
    by_risk: Dict[str, int] = {}
    linked = vulnerable = 0
    seen: Dict[str, Dict[str, Any]] = {}
    for it in fetched:
        it["classification"] = classify(it)
        it["asset_key"], it["linked_tls"] = _asset_key(provider, it, tls)
        it["last_seen_at"] = started_at
        seen[it["item_key"]] = it
    with feature_conn() as conn:
        previous = {r["item_key"]: dict(r) for r in conn.execute(
            "SELECT item_key, asset_key, provider, first_seen_at FROM org_cert_inventory WHERE org_id = ? AND source_id = ?",
            (org_id, source_id)).fetchall()}
        conn.execute("DELETE FROM org_cert_inventory WHERE org_id = ? AND source_id = ?", (org_id, source_id))
        for it in seen.values():
            c = it["classification"]
            by_risk[c["risk"]] = by_risk.get(c["risk"], 0) + 1
            linked += 1 if it["linked_tls"] else 0
            vulnerable += 1 if c["quantum_vulnerable"] else 0
            first = (previous.get(it["item_key"]) or {}).get("first_seen_at") or started_at
            conn.execute(
                "INSERT INTO org_cert_inventory (org_id, source_id, item_key, provider, kind, name, fingerprint_sha1, "
                "fingerprint_sha256, serial, subject, issuer, key_algorithm, key_size, curve, signature_algorithm, "
                "not_after, owner, state, algorithm, risk, classification_json, asset_key, linked_tls, metadata_json, "
                "first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (org_id, source_id, it["item_key"][:500], provider, it["kind"], it["name"][:300], it["fingerprint_sha1"],
                 it["fingerprint_sha256"], it["serial"][:200], it["subject"][:500], it["issuer"][:500],
                 it["key_algorithm"][:40], it["key_size"], it["curve"][:40], it["signature_algorithm"][:80],
                 it["not_after"][:40], it["owner"][:200], it["state"][:40], c["algorithm"][:80], c["risk"],
                 json.dumps(c), it["asset_key"], 1 if it["linked_tls"] else 0, json.dumps(it["metadata"], default=str)[:8000],
                 first, started_at))
        conn.commit()
    gone = [row for key, row in previous.items() if key not in seen]
    mirror_errors = _mirror(org_id, source_id, provider, list(seen.values()))
    moved = [row for key, row in previous.items() if key in seen and row["asset_key"] != seen[key]["asset_key"]]
    _unmirror(org_id, source_id, gone + moved)
    return {"items": len(seen), "removed": len(gone), "linked_to_tls": linked, "quantum_vulnerable": vulnerable,
            "by_risk": by_risk, "asset_errors": mirror_errors}


def list_inventory(org_id: str, source_id: str = "", risk: str = "", limit: int = 500) -> List[Dict[str, Any]]:
    _init()
    sql = ("SELECT source_id, item_key, provider, kind, name, fingerprint_sha1, fingerprint_sha256, serial, subject, issuer, "
           "key_algorithm, key_size, curve, signature_algorithm, not_after, owner, state, algorithm, risk, "
           "classification_json, asset_key, linked_tls, first_seen_at, last_seen_at FROM org_cert_inventory WHERE org_id = ?")
    params: List[Any] = [org_id]
    if source_id:
        sql += " AND source_id = ?"
        params.append(source_id)
    if risk:
        sql += " AND risk = ?"
        params.append(risk)
    sql += " ORDER BY not_after LIMIT ?"
    params.append(max(1, min(int(limit or 500), 5000)))
    with feature_conn() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["classification"] = json.loads(d.pop("classification_json") or "{}")
        d["linked_tls"] = bool(d["linked_tls"])
        d["provider_name"] = PROVIDERS.get(d["provider"], {}).get("name", d["provider"])
        out.append(d)
    return out


def run_due_syncs(now: Optional[datetime] = None, limit: int = 50) -> Dict[str, Any]:
    """Celery beat entry point: sync every connection whose schedule is on and due. Off by default."""
    from services.tenant_scope import platform_scope

    _init()
    stamp = _iso(now or _now_dt())
    with platform_scope("cert inventory: scheduled sync picks due connections across tenants"), feature_conn() as conn:
        due = [dict(r) for r in conn.execute(
            "SELECT id, org_id FROM org_cert_sources WHERE schedule_hours > 0 AND next_sync_at IS NOT NULL "
            "AND next_sync_at <= ? ORDER BY next_sync_at LIMIT ?", (stamp, int(limit))).fetchall()]
    results = []
    for row in due:
        import db

        token = db.set_current_organization_id(row["org_id"])
        try:
            res = sync_source(row["org_id"], row["id"], trigger="schedule")
            results.append({"id": row["id"], "ok": True, "items": res["items"]})
        except CertSourceError as exc:
            results.append({"id": row["id"], "ok": False, "error": exc.detail[:200]})
        except Exception as exc:  # pragma: no cover - one tenant's failure must not stop the others
            results.append({"id": row["id"], "ok": False, "error": exc.__class__.__name__})
        finally:
            db.reset_current_organization_id(token)
    return {"due": len(due), "results": results}


def providers_public() -> List[Dict[str, Any]]:
    return [{"id": key, "name": info["name"], "kind": info["kind"], "steps": info["steps"], "docs": info["docs"],
             "fields": info["fields"]} for key, info in PROVIDERS.items()]
