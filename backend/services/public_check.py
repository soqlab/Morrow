"""The free, public, no-account post-quantum readiness check.

What this is
------------
Anyone types a domain into ``/check`` and gets a real answer about that domain's
public TLS endpoint in seconds. No account, no tenant, no stored customer data.
It is the shop window for the platform, so the answer has to be true, sourced,
and honest about being one endpoint at one moment.

What it does, exactly
---------------------
1. **Passive first.** Public Certificate Transparency data for the domain, read
   from a CT search service (crt.sh by default). That yields issued
   certificates, issuers, validity windows and history without touching the
   target at all. CT is advisory here: when it is slow, rate limited or down --
   and crt.sh frequently is -- the check continues and the result says
   ``status: "unavailable"`` with the reason. CT being unavailable is never
   reported as "this domain has no certificates".
2. **Then one light active check.** A TLS handshake to the domain on port 443 to
   see what it negotiates *now*: protocol version, cipher suite, certificate key
   type and size, signature algorithm, expiry, and the negotiated key-exchange
   group, including hybrid post-quantum where it can be observed. The handshake
   facts are read with ``scanner._leaf_cert_facts`` and the key-exchange group
   with ``scanner._probe_key_exchange_group`` -- the hand-rolled ClientHello that
   already exists in this codebase. Nothing here reimplements TLS parsing.

   Honest count of connections: **two at most**, to one host, on one port. The
   first is an ordinary verified handshake (what a browser does). The second
   sends one ClientHello that offers post-quantum groups, because a normal
   Python handshake cannot ask for them, and reads the ServerHello. That is the
   whole of it.

What it does not do
-------------------
No port scanning. No subdomain enumeration. No vulnerability probing. No
crawling. No repeated connections. No HTTP request to the target. No OCSP or CRL
fetch (``scanner.scan_host`` does those; this module deliberately does not call
it, because that function also enumerates TLS versions and cipher suites, which
is more contact than this tool is allowed to make).

Guardrails, enforced here rather than promised in documentation
---------------------------------------------------------------
* **Opt-out, checked before any contact at all** -- before DNS resolution, let
  alone a handshake. A domain owner writes to the published address and their
  domain (and everything under it) is refused. Sources: the
  ``public_check_optouts`` table and ``MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS``.
* **SSRF guard** -- reused from services/alert_routing.py, the same code that
  guards outbound webhooks: every address the name resolves to must be globally
  routable, and IPv4-mapped and 6to4 forms are unwrapped first so
  ``::ffff:127.0.0.1`` cannot pass. Private, loopback, link-local, CGNAT,
  reserved, multicast and unspecified ranges are refused; credentials in the
  input are refused; the address that was checked is the address that is
  connected to (TLS still verifies the hostname), so DNS rebinding cannot
  redirect the handshake inward.
* **Rate limits** -- per client IP (hashed), per target domain, and globally,
  through services/org_rate_limits.py, so Redis backs them when configured and
  all API replicas share one budget.
* **Cache** -- a result is cached per domain and served from cache. A popular
  domain is checked once per TTL, not once per visitor.
* **Bounded queue and a deadline** -- a fixed number of checks run at once, a
  bounded number may wait, and a check that exceeds its deadline is reported as
  failed. A slow target cannot occupy the server.
* **A log** -- one row per check attempt: domain, time, salted hash of the
  requester IP, outcome. Enough to investigate abuse, not enough to profile a
  visitor. Documented on /privacy.

No tenant data
--------------
Every table here is ``public_check_*`` and carries no organization id. This
module imports nothing that reads or writes an organization's workspace, and
``test_public_checker.py`` asserts that no tenant table is touched by a check.

Settings
--------
``MORROW_PUBLIC_CHECK_ENABLED``                 1       master switch
``MORROW_PUBLIC_CHECK_CACHE_SECONDS``           3600    cache TTL (minimum 600)
``MORROW_PUBLIC_CHECK_IP_LIMIT``                10      checks per IP per hour
``MORROW_PUBLIC_CHECK_IP_BURST``                3       checks per IP per minute
``MORROW_PUBLIC_CHECK_DOMAIN_LIMIT``            4       checks per domain per hour
``MORROW_PUBLIC_CHECK_GLOBAL_LIMIT``            240     checks per hour, whole service
``MORROW_PUBLIC_CHECK_CONCURRENCY``             4       checks running at once
``MORROW_PUBLIC_CHECK_MAX_QUEUE``               32      checks admitted but waiting
``MORROW_PUBLIC_CHECK_QUEUE_WAIT_SECONDS``      5       how long a check may wait for a slot
``MORROW_PUBLIC_CHECK_DEADLINE_SECONDS``        15      whole-check deadline
``MORROW_PUBLIC_CHECK_HANDSHAKE_TIMEOUT``       6       TLS socket timeout
``MORROW_PUBLIC_CHECK_CT_ENABLED``              1       read Certificate Transparency
``MORROW_PUBLIC_CHECK_CT_PROVIDER``             crtsh   crtsh | certspotter | none
``MORROW_PUBLIC_CHECK_CT_TIMEOUT``              6       CT HTTP timeout
``MORROW_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS`` 5       politeness throttle between CT calls
``MORROW_PUBLIC_CHECK_CT_MAX_CERTS``            25      CT entries summarised
``MORROW_PUBLIC_CHECK_CT_CERT_FETCH``           3       CT certificates fetched for key type/size
``MORROW_PUBLIC_CHECK_CT_TOKEN``                ""      bearer token for certspotter
``MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS``          ""      comma-separated, in addition to the table
``MORROW_PUBLIC_CHECK_ABUSE_CONTACT``           ""      shown on the page; falls back to the support address
``MORROW_PUBLIC_CHECK_LOG_RETENTION_DAYS``      30      log rows older than this are pruned
``MORROW_PUBLIC_CHECK_IP_SALT``                 ""      salt for the IP hash; generated and stored if unset
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

#: Port 443. Not a setting: "one hostname, port 443, one handshake" is the design, and a
#: configurable port would turn this into the port prober the guardrails exist to prevent.
PORT = 443

MAX_HOSTNAME_LEN = 253
MAX_LABEL_LEN = 63
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_TLD_RE = re.compile(r"^[a-z]{2,63}$")
_IDNA_TLD_RE = re.compile(r"^xn--[a-z0-9-]{2,59}$")

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()

#: Admission control. ``_slots`` bounds how many checks run at once; ``_waiting`` bounds how many
#: may queue for a slot. Together they are the "bounded queue" guardrail.
_slots = threading.Semaphore(1)
_slots_size = 0
_slots_lock = threading.Lock()
_waiting = [0]

#: Politeness throttle on outbound CT calls, shared by every check in this process.
_ct_lock = threading.Lock()
_ct_last_call = [0.0]


class PublicCheckError(Exception):
    """A refusal with an HTTP status and a reason the page can show verbatim."""

    def __init__(self, status_code: int, detail: str, outcome: str = "refused",
                 retry_after: Optional[float] = None):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.detail = str(detail)
        self.outcome = str(outcome)
        self.retry_after = retry_after


# ── Settings ─────────────────────────────────────────────────────────────────


def _flag(name: str, default: str = "1") -> bool:
    return str(os.getenv(name, default) or default).strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def enabled() -> bool:
    return _flag("MORROW_PUBLIC_CHECK_ENABLED", "1")


def cache_seconds() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_CACHE_SECONDS", 3600, 600, 30 * 24 * 3600))


def ip_limit() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_IP_LIMIT", 10, 1, 10_000))


def ip_burst() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_IP_BURST", 3, 1, 1_000))


def domain_limit() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_DOMAIN_LIMIT", 4, 1, 1_000))


def global_limit() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_GLOBAL_LIMIT", 240, 1, 1_000_000))


def concurrency() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_CONCURRENCY", 4, 1, 64))


def max_queue() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_MAX_QUEUE", 32, 1, 4096))


def queue_wait_seconds() -> float:
    return _num("MORROW_PUBLIC_CHECK_QUEUE_WAIT_SECONDS", 5.0, 0.1, 120.0)


def deadline_seconds() -> float:
    return _num("MORROW_PUBLIC_CHECK_DEADLINE_SECONDS", 15.0, 2.0, 120.0)


def handshake_timeout() -> float:
    return _num("MORROW_PUBLIC_CHECK_HANDSHAKE_TIMEOUT", 6.0, 1.0, 60.0)


def ct_enabled() -> bool:
    return _flag("MORROW_PUBLIC_CHECK_CT_ENABLED", "1") and ct_provider() != "none"


def ct_provider() -> str:
    raw = str(os.getenv("MORROW_PUBLIC_CHECK_CT_PROVIDER", "crtsh") or "crtsh").strip().lower()
    return raw if raw in CT_PROVIDERS or raw == "none" else "crtsh"


def ct_timeout() -> float:
    return _num("MORROW_PUBLIC_CHECK_CT_TIMEOUT", 6.0, 1.0, 60.0)


def ct_min_interval_seconds() -> float:
    """crt.sh publishes no rate limit and asks informally for roughly one request every 5 s."""
    return _num("MORROW_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS", 5.0, 0.0, 300.0)


def ct_max_certs() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_CT_MAX_CERTS", 25, 1, 500))


def ct_cert_fetch() -> int:
    """How many CT certificates are downloaded to read their key type and size.

    crt.sh's JSON index does not carry the public key, so key history costs one extra request per
    certificate. Bounded, newest-first, and 0 turns it off.
    """
    return int(_num("MORROW_PUBLIC_CHECK_CT_CERT_FETCH", 3, 0, 10))


def ct_token() -> str:
    return str(os.getenv("MORROW_PUBLIC_CHECK_CT_TOKEN", "") or "").strip()


def log_retention_days() -> int:
    return int(_num("MORROW_PUBLIC_CHECK_LOG_RETENTION_DAYS", 30, 1, 3650))


def abuse_contact() -> str:
    """Where to send an abuse report or an opt-out request. Empty when nothing is configured."""
    for name in ("MORROW_PUBLIC_CHECK_ABUSE_CONTACT", "MORROW_SUPPORT_EMAIL", "MORROW_SECURITY_CONTACT_EMAIL"):
        value = str(os.getenv(name, "") or "").strip()
        if value and "@" in value and " " not in value:
            return value[:200]
    return ""


def settings_public() -> Dict[str, Any]:
    """The guardrails, as the page shows them. Values, not promises."""
    return {
        "enabled": enabled(),
        "port": PORT,
        "cache_seconds": cache_seconds(),
        "checks_per_ip_per_hour": ip_limit(),
        "checks_per_ip_per_minute": ip_burst(),
        "checks_per_domain_per_hour": domain_limit(),
        "checks_per_hour_total": global_limit(),
        "concurrent_checks": concurrency(),
        "max_queued_checks": max_queue(),
        "queue_wait_seconds": queue_wait_seconds(),
        "deadline_seconds": deadline_seconds(),
        "certificate_transparency": {
            "enabled": ct_enabled(),
            "provider": ct_provider() if ct_enabled() else "none",
            "timeout_seconds": ct_timeout(),
            "min_interval_seconds": ct_min_interval_seconds(),
            "certificates_summarised": ct_max_certs(),
            "certificates_downloaded_for_key_type": ct_cert_fetch(),
        },
        "abuse_contact": abuse_contact(),
        "log_retention_days": log_retention_days(),
        "opt_out_domains": len(_optout_set()),
        "rate_limit_backend": "redis" if str(os.getenv("REDIS_URL") or os.getenv("CELERY_BROKER_URL") or "") else "memory",
    }


# ── Time ─────────────────────────────────────────────────────────────────────


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ── Storage ──────────────────────────────────────────────────────────────────


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def init_tables() -> None:
    """Create this module's own tables. Nothing here belongs to an organization."""
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS public_check_results (
                    domain      TEXT PRIMARY KEY,
                    checked_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    outcome     TEXT NOT NULL DEFAULT 'ok',
                    result_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_public_check_results_expires
                    ON public_check_results (expires_at);
                CREATE TABLE IF NOT EXISTS public_check_log (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain            TEXT NOT NULL,
                    created_at        TEXT NOT NULL,
                    requester_ip_hash TEXT NOT NULL DEFAULT '',
                    outcome           TEXT NOT NULL,
                    detail            TEXT NOT NULL DEFAULT '',
                    duration_ms       INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_public_check_log_created
                    ON public_check_log (created_at);
                CREATE INDEX IF NOT EXISTS idx_public_check_log_domain
                    ON public_check_log (domain, created_at);
                /* The permanent record behind /r/{domain}. public_check_results above is a
                   cache with a TTL, which is what keeps the per-domain check budget honest;
                   these two tables are the opposite requirement -- a result that stays put so
                   a shared link, a badge or a citation still resolves years later. Separate
                   tables rather than a longer TTL, because the two lifetimes are unrelated. */
                CREATE TABLE IF NOT EXISTS public_check_observations (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain       TEXT NOT NULL,
                    observed_at  TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    source       TEXT NOT NULL DEFAULT 'measured',
                    outcome      TEXT NOT NULL,
                    posture      TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    result_json  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_public_check_obs_domain
                    ON public_check_observations (domain, observed_at DESC);
                /* An unchanged endpoint extends last_seen_at on the existing row instead of
                   appending a duplicate, so the history reads as a list of changes rather than
                   one row per visit. */
                CREATE UNIQUE INDEX IF NOT EXISTS idx_public_check_obs_dedupe
                    ON public_check_observations (domain, content_hash, source);
                CREATE TABLE IF NOT EXISTS public_check_domains (
                    domain           TEXT PRIMARY KEY,
                    first_seen_at    TEXT NOT NULL,
                    last_observed_at TEXT NOT NULL,
                    latest_id        INTEGER NOT NULL,
                    posture          TEXT NOT NULL,
                    source           TEXT NOT NULL DEFAULT 'measured',
                    observations     INTEGER NOT NULL DEFAULT 1,
                    hidden           INTEGER NOT NULL DEFAULT 0,
                    claimed_org_id   TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_public_check_domains_posture
                    ON public_check_domains (hidden, posture, last_observed_at DESC);
                CREATE TABLE IF NOT EXISTS public_check_optouts (
                    domain     TEXT PRIMARY KEY,
                    reason     TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS public_check_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def _meta_get(key: str) -> str:
    init_tables()
    try:
        with feature_conn() as conn:
            row = conn.execute("SELECT value FROM public_check_meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else ""
    except Exception:
        return ""


def _meta_set(key: str, value: str) -> None:
    init_tables()
    try:
        with feature_conn() as conn:
            conn.execute("DELETE FROM public_check_meta WHERE key = ?", (key,))
            conn.execute("INSERT INTO public_check_meta (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
    except Exception:
        logger.warning("public check: could not store meta key %s", key)


def _ip_salt() -> str:
    """A stable salt for the requester-IP hash.

    An unsalted SHA-256 of an IPv4 address is reversible by brute force in seconds, so the log
    would hold the addresses it claims not to hold. A configured salt wins; otherwise one is
    generated once and stored, so hashes stay comparable across restarts (which is the whole point
    of logging them) without the operator having to set anything.
    """
    configured = str(os.getenv("MORROW_PUBLIC_CHECK_IP_SALT", "") or "").strip()
    if configured:
        return configured
    stored = _meta_get("ip_salt")
    if stored:
        return stored
    generated = secrets.token_hex(16)
    _meta_set("ip_salt", generated)
    return _meta_get("ip_salt") or generated


def hash_ip(value: Any) -> str:
    raw = str(value or "").strip() or "unknown"
    return hashlib.sha256((_ip_salt() + "|" + raw).encode("utf-8")).hexdigest()[:32]


# ── Target validation ────────────────────────────────────────────────────────


def normalize_domain(value: Any) -> str:
    """The one hostname this check will contact, or a refusal.

    Accepts what a person actually pastes (``https://Example.COM/path``, a trailing dot,
    ``example.com:443``) and refuses everything that is not a single public hostname: credentials,
    wildcards, IP literals, single-label names, non-443 ports, spaces, and anything that is not a
    registrable name.
    """
    raw = str(value or "").strip()
    if not raw:
        raise PublicCheckError(400, "Enter a domain, for example example.com.", "refused_invalid")
    if len(raw) > 400:
        raise PublicCheckError(400, "That is too long to be a domain name.", "refused_invalid")
    if any(ch.isspace() for ch in raw):
        raise PublicCheckError(400, "A domain name contains no spaces.", "refused_invalid")

    # Strip a pasted scheme and path, but refuse anything that is not http(s).
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        if scheme.lower() not in {"http", "https"}:
            raise PublicCheckError(400, "Enter a domain name, not a URL with another scheme.", "refused_invalid")
        raw = rest
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in raw:
        raise PublicCheckError(
            400, "Remove the credentials before the host. This check only takes a bare domain name.",
            "refused_credentials")
    if raw.startswith("["):
        raise PublicCheckError(400, "This check takes a domain name, not an IP address.", "refused_ip_literal")
    if raw.count(":") == 1:
        raw, _, port = raw.partition(":")
        if port not in {"", "443"}:
            raise PublicCheckError(
                400, f"This check only ever connects on port {PORT}. Remove the port from the address.",
                "refused_port")
    elif ":" in raw:
        raise PublicCheckError(400, "This check takes a domain name, not an IP address.", "refused_ip_literal")

    host = raw.rstrip(".").strip()
    if not host:
        raise PublicCheckError(400, "Enter a domain, for example example.com.", "refused_invalid")
    if "*" in host or "%" in host or "_" in host:
        raise PublicCheckError(
            400, "Enter one exact hostname. Wildcards are not a host this check can connect to.",
            "refused_wildcard")

    # An IP literal is not a domain and is never an acceptable target for this tool.
    try:
        ipaddress.ip_address(host)
        raise PublicCheckError(400, "This check takes a domain name, not an IP address.", "refused_ip_literal")
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        try:
            host = host.lower().encode("ascii").decode("ascii")
        except UnicodeEncodeError:
            raise PublicCheckError(400, "That is not a hostname this check can resolve.", "refused_invalid") from None

    if len(host) > MAX_HOSTNAME_LEN:
        raise PublicCheckError(400, f"A hostname is at most {MAX_HOSTNAME_LEN} characters.", "refused_invalid")
    labels = host.split(".")
    if len(labels) < 2:
        raise PublicCheckError(
            400, "Enter a full domain name with a top-level domain, for example example.com.",
            "refused_invalid")
    for label in labels:
        if not label or len(label) > MAX_LABEL_LEN or not _LABEL_RE.match(label):
            raise PublicCheckError(400, "That is not a valid hostname.", "refused_invalid")
    tld = labels[-1]
    if not (_TLD_RE.match(tld) or _IDNA_TLD_RE.match(tld)):
        raise PublicCheckError(400, "That does not end in a top-level domain.", "refused_invalid")
    return host


# ── Opt-out ──────────────────────────────────────────────────────────────────


def _optout_set() -> set:
    """Domains that must never be contacted: the table plus the environment list."""
    out = set()
    for item in re.split(r"[,;\s]+", str(os.getenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "") or "")):
        cleaned = item.strip().lower().rstrip(".")
        if cleaned:
            out.add(cleaned)
    try:
        init_tables()
        with feature_conn() as conn:
            for row in conn.execute("SELECT domain FROM public_check_optouts").fetchall():
                cleaned = str(row["domain"] or "").strip().lower()
                if cleaned:
                    out.add(cleaned)
    except Exception:
        # A storage failure must not silently un-opt-out a domain that opted out in configuration,
        # so the environment list still applies. It is logged loudly.
        logger.warning("public check: could not read the opt-out table; using the configured list only")
    return out


def opted_out(domain: str) -> str:
    """The opt-out entry that covers this domain (itself or any parent), or ""."""
    host = str(domain or "").strip().lower().rstrip(".")
    if not host:
        return ""
    entries = _optout_set()
    if not entries:
        return ""
    labels = host.split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        if candidate in entries:
            return candidate
    return ""


def add_optout(domain: str, reason: str = "", created_by: str = "") -> Dict[str, Any]:
    host = normalize_domain(domain)
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM public_check_optouts WHERE domain = ?", (host,))
        conn.execute(
            "INSERT INTO public_check_optouts (domain, reason, created_by, created_at) VALUES (?, ?, ?, ?)",
            (host, str(reason or "")[:500], str(created_by or "")[:200], iso(now_utc())),
        )
        conn.execute("DELETE FROM public_check_results WHERE domain = ? OR domain LIKE ?", (host, "%." + host))
        conn.commit()
    # The cached result is deleted; the permanent record is hidden rather than deleted. What we
    # observed is the evidence that makes an abuse complaint answerable, and it becomes
    # unreachable through every public route the moment this runs.
    hidden = set_registry_hidden(host, True)
    return {"domain": host, "opted_out": True, "registry_rows_hidden": hidden}


def remove_optout(domain: str) -> Dict[str, Any]:
    host = normalize_domain(domain)
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM public_check_optouts WHERE domain = ?", (host,))
        conn.commit()
    # Hiding is instant and automatic; restoring is an operator action, which is the right way
    # round for a promise made to someone who asked to be left alone.
    restored = set_registry_hidden(host, False)
    return {"domain": host, "opted_out": False, "registry_rows_restored": restored}


def list_optouts() -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT domain, reason, created_by, created_at FROM public_check_optouts ORDER BY domain"
        ).fetchall()
    return [{"domain": r["domain"], "reason": r["reason"], "created_by": r["created_by"],
             "created_at": r["created_at"]} for r in rows]


# ── Rate limits (services/org_rate_limits.py: Redis when configured) ─────────


def _limit(kind: str, key: str, limit: int, window: float, message: str) -> None:
    from services import org_rate_limits

    result = org_rate_limits.hit(kind, key, limit, window)
    if not result.get("allowed"):
        raise PublicCheckError(429, message, "rate_limited", retry_after=result.get("retry_after"))


def enforce_rate_limits(domain: str, ip_hash: str) -> None:
    """Per IP, per domain, and for the whole service. Raises 429 with a retry hint."""
    _limit("public_check_global", "all", global_limit(), 3600.0,
           "The free checker is at its hourly limit for everyone. Try again shortly.")
    _limit("public_check_ip_burst", ip_hash, ip_burst(), 60.0,
           f"That is more than {ip_burst()} checks in a minute from your address. Wait a moment.")
    _limit("public_check_ip", ip_hash, ip_limit(), 3600.0,
           f"The free checker allows {ip_limit()} checks an hour per address.")
    _limit("public_check_domain", domain, domain_limit(), 3600.0,
           f"{domain} has already been checked {domain_limit()} times this hour. "
           "The cached result is the same answer, and this limit exists so the checker cannot be "
           "pointed at one host repeatedly.")


# ── Admission control: a bounded queue with a short wait ─────────────────────


def _resize_slots() -> None:
    global _slots, _slots_size
    want = concurrency()
    with _slots_lock:
        if want != _slots_size:
            _slots = threading.Semaphore(want)
            _slots_size = want


class _Admission:
    """A slot in the bounded queue, or a 503 that says the checker is busy."""

    def __enter__(self) -> "_Admission":
        _resize_slots()
        with _slots_lock:
            if _waiting[0] >= max_queue():
                raise PublicCheckError(
                    503,
                    "The free checker is busy right now. The result is cached, so trying again in a "
                    "moment costs the target nothing.",
                    "queue_full", retry_after=5.0)
            _waiting[0] += 1
        try:
            if not _slots.acquire(timeout=queue_wait_seconds()):
                raise PublicCheckError(
                    503,
                    "The free checker is busy right now. Try again in a moment.",
                    "queue_timeout", retry_after=5.0)
        finally:
            with _slots_lock:
                _waiting[0] = max(0, _waiting[0] - 1)
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            _slots.release()
        except ValueError:  # pragma: no cover - only if the semaphore was resized mid-flight
            pass


def queue_depth() -> Dict[str, int]:
    return {"waiting": int(_waiting[0]), "concurrency": concurrency(), "max_queue": max_queue()}


# ── SSRF guard (services/alert_routing.py) ───────────────────────────────────


def resolve_public_address(host: str) -> str:
    """Resolve, refuse every non-public answer, and return the address that will be connected to.

    The guard is ``alert_routing.ip_is_public`` -- the same function that stops an outbound webhook
    reaching inside the network -- so there is one definition of "public address" in the process.
    Every resolved address must pass: a name that resolves to one public and one private address is
    refused outright, because which one a later connect would pick is not something this code can
    promise. The returned address is then what the handshake connects to, so a second DNS answer
    cannot redirect it.
    """
    from services import alert_routing

    try:
        addresses = alert_routing.resolve_host(host, PORT)
    except (OSError, UnicodeError) as exc:
        raise PublicCheckError(400, f"{host} does not resolve in public DNS.", "refused_dns") from exc
    if not addresses:
        raise PublicCheckError(400, f"{host} does not resolve in public DNS.", "refused_dns")
    blocked = [a for a in addresses if not alert_routing.ip_is_public(a)]
    if blocked:
        raise PublicCheckError(
            403,
            f"{host} resolves to an address that is not on the public internet "
            f"({blocked[0]}). This checker only contacts public hosts: private, loopback, "
            "link-local, carrier-grade NAT, reserved and IPv4-mapped addresses are refused.",
            "refused_private")
    return addresses[0]


# ── The one active check: a TLS handshake, and the key-exchange probe ────────


def observe_endpoint(host: str, address: str = "", timeout: Optional[float] = None,
                     deadline: Optional[float] = None) -> Dict[str, Any]:
    """One verified TLS handshake on 443, plus the existing post-quantum ClientHello probe.

    Returns the subset of ``scanner.scan_host``'s fact dict that this tool is allowed to collect,
    with ``scan_status`` set by the scanner's own ``_finalise_scan_status`` so a failed check can
    never be mistaken for a clean one.
    """
    import scanner
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    budget = float(timeout if timeout is not None else handshake_timeout())
    target = address or host

    facts: Dict[str, Any] = {
        "host": host, "port": PORT, "address_checked": address,
        "error": "", "error_code": "", "scan_status": "ok",
        "tls_version": "", "cipher_name": "", "cipher_bits": None, "alpn": None,
        "certificate_verified": False, "verify_error": "",
        "key_exchange": "", "key_exchange_group_id": None, "key_exchange_family": "",
        "key_exchange_observed": False, "key_exchange_observation_method": "",
        "key_exchange_unobservable_reason": "", "key_exchange_hello_retry": False,
        "subject": "", "issuer": "", "not_before": "", "not_after": "", "days_until_expiry": None,
        "key_type": "", "key_detail": "", "key_bits": 0, "key_curve": "", "sig_algorithm": "",
        "san_dns": [],
        # These are the fields policy.evaluate_tls_findings reads. This tool does not probe TLS
        # versions or enumerate ciphers (that is scanning), so the only version it can attest to is
        # the one it negotiated, and the cipher list stays empty rather than claiming "none found".
        "tls_supported_versions": [], "tls12_accepted_ciphers": [], "tls12_weak_accepted_ciphers": [],
        "ocsp_urls": [], "crl_urls": [], "cert_chain": [], "chain_length": 0, "chain_issues": [],
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        with socket.create_connection((target, PORT), timeout=budget) as sock:
            sock.settimeout(budget)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                facts["certificate_verified"] = True
                facts["tls_version"] = ssock.version() or ""
                if facts["tls_version"]:
                    facts["tls_supported_versions"] = [facts["tls_version"]]
                cipher = ssock.cipher()
                if cipher:
                    facts["cipher_name"] = cipher[0] or ""
                    facts["cipher_bits"] = cipher[2] if len(cipher) > 2 else None
                try:
                    facts["alpn"] = ssock.selected_alpn_protocol()
                except Exception:
                    facts["alpn"] = None
                der = ssock.getpeercert(binary_form=True)
                if der:
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    leaf = scanner._leaf_cert_facts(cert)
                    for key in ("subject", "issuer", "not_before", "not_after", "days_until_expiry",
                                "key_type", "key_detail", "key_bits", "key_curve", "sig_algorithm",
                                "san_dns", "ocsp_urls", "crl_urls"):
                        if key in leaf:
                            facts[key] = leaf[key]
    except ssl.SSLCertVerificationError as exc:
        # A certificate that does not verify is a finding, not a reason to handshake again without
        # verification. scanner.scan_host retries unverified because an internal estate is full of
        # private CAs; a public checker pointed at a stranger's host makes one connection and
        # reports what it saw.
        facts["verify_error"] = str(exc)[:300]
        facts["error"] = str(exc)[:300]
        facts["error_code"] = scanner._error_code_from_exception(exc)
    except Exception as exc:
        facts["error"] = str(exc)[:300]
        facts["error_code"] = scanner._error_code_from_exception(exc)

    # The key-exchange probe: one ClientHello that offers post-quantum groups, pinned to the same
    # address. Only worth a round trip if something answered on 443 at all.
    remaining = budget if deadline is None else max(0.0, deadline - time.monotonic())
    if facts["tls_version"] or facts["error_code"] in ("TLS_VERIFY_FAILED", "CERT_EXPIRED",
                                                       "HOSTNAME_MISMATCH", "SELF_SIGNED"):
        if remaining < 1.0:
            facts["key_exchange_unobservable_reason"] = "the check ran out of its time budget"
        else:
            try:
                facts.update(scanner._probe_key_exchange_group(
                    host, PORT, timeout=min(budget, remaining), address=address))
            except Exception as exc:
                facts["key_exchange_unobservable_reason"] = f"probe failed: {type(exc).__name__}"
    else:
        facts["key_exchange_unobservable_reason"] = "no TLS handshake completed on this endpoint"

    scanner._finalise_scan_status(facts)
    return facts


# ── Certificate Transparency (passive, advisory, and allowed to be down) ─────


def _ct_throttle(budget: float) -> bool:
    """Wait out the politeness interval. False when waiting would blow the budget."""
    interval = ct_min_interval_seconds()
    if interval <= 0:
        return True
    with _ct_lock:
        wait = interval - (time.monotonic() - _ct_last_call[0])
        if wait > 0:
            if wait > budget:
                return False
            time.sleep(wait)
        _ct_last_call[0] = time.monotonic()
    return True


def _http_get_json(url: str, timeout: float, headers: Optional[Dict[str, str]] = None) -> Any:
    import requests

    response = requests.get(url, timeout=timeout, headers=dict(headers or {}),
                            allow_redirects=False)
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}")
    return response.json()


def _http_get_text(url: str, timeout: float) -> str:
    import requests

    response = requests.get(url, timeout=timeout, allow_redirects=False)
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}")
    return response.text


def _key_facts_from_pem(pem_text: str) -> Dict[str, Any]:
    """Key type, size and signature algorithm from a certificate, via the scanner's own parser."""
    import scanner
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"), default_backend())
    out = dict(scanner._pk_details(cert))
    try:
        out["sig_algorithm"] = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    except Exception:
        out["sig_algorithm"] = ""
    return out


def _ct_crtsh(domain: str, timeout: float) -> Dict[str, Any]:
    """crt.sh's JSON interface.

    ``https://crt.sh/?q=<domain>&output=json&deduplicate=Y`` returns one object per logged
    certificate with issuer_name, common_name, name_value, not_before, not_after, entry_timestamp
    and the crt.sh id. The index carries no public key, so key type and size cost one extra
    ``?d=<id>`` request per certificate; ``MORROW_PUBLIC_CHECK_CT_CERT_FETCH`` bounds how many.

    crt.sh publishes no rate limit and its availability is unreliable; every failure here is
    reported as "unavailable", never as "no certificates".
    """
    from urllib.parse import quote

    rows = _http_get_json(
        f"https://crt.sh/?q={quote(domain)}&output=json&deduplicate=Y&exclude=expired",
        timeout, {"User-Agent": "airlock-public-check/1.0", "Accept": "application/json"})
    if not isinstance(rows, list):
        raise RuntimeError("crt.sh did not return a JSON array")

    entries: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        entries.append({
            "id": row.get("id"),
            "issuer": str(row.get("issuer_name") or "")[:300],
            "common_name": str(row.get("common_name") or "")[:300],
            "names": [n for n in str(row.get("name_value") or "").split("\n") if n][:25],
            "not_before": str(row.get("not_before") or "")[:40],
            "not_after": str(row.get("not_after") or "")[:40],
            "logged_at": str(row.get("entry_timestamp") or "")[:40],
        })
    entries.sort(key=lambda e: str(e.get("not_before") or ""), reverse=True)
    trimmed = entries[:ct_max_certs()]

    keys: List[Dict[str, Any]] = []
    budget = ct_cert_fetch()
    for entry in trimmed:
        if budget <= 0 or not entry.get("id"):
            break
        try:
            pem = _http_get_text(f"https://crt.sh/?d={int(entry['id'])}", timeout)
            if "BEGIN CERTIFICATE" not in pem:
                continue
            facts = _key_facts_from_pem(pem)
            keys.append({
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "issuer": entry.get("issuer", ""),
                "key_type": facts.get("key_type", ""),
                "key_bits": facts.get("key_bits", 0),
                "key_curve": facts.get("key_curve", ""),
                "sig_algorithm": facts.get("sig_algorithm", ""),
            })
            budget -= 1
        except Exception:
            # One certificate that will not download or parse is not a reason to lose the index.
            budget -= 1
            continue
    return {"entries": trimmed, "total": len(entries), "keys": keys,
            "provider": "crt.sh", "provider_url": "https://crt.sh/"}


def _ct_certspotter(domain: str, timeout: float) -> Dict[str, Any]:
    """SSLMate's CertSpotter issuances API.

    Chosen as the built-in alternative because it returns the DER of each certificate in the same
    response, so key type and size come back without a second request per certificate. Without a
    token it is rate limited to a handful of queries an hour, which is why it is not the default.
    """
    from urllib.parse import quote
    import base64

    headers = {"User-Agent": "airlock-public-check/1.0", "Accept": "application/json"}
    token = ct_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    rows = _http_get_json(
        "https://api.certspotter.com/v1/issuances"
        f"?domain={quote(domain)}&include_subdomains=false"
        "&expand=dns_names&expand=issuer&expand=cert_der",
        timeout, headers)
    if not isinstance(rows, list):
        raise RuntimeError("certspotter did not return a JSON array")

    entries: List[Dict[str, Any]] = []
    keys: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        issuer = row.get("issuer") or {}
        entry = {
            "id": row.get("id"),
            "issuer": str((issuer or {}).get("name") or "")[:300],
            "common_name": "",
            "names": [str(n) for n in (row.get("dns_names") or [])][:25],
            "not_before": str(row.get("not_before") or "")[:40],
            "not_after": str(row.get("not_after") or "")[:40],
            "logged_at": "",
        }
        entries.append(entry)
        der = row.get("cert_der")
        if der and len(keys) < ct_cert_fetch():
            try:
                import scanner
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_der_x509_certificate(base64.b64decode(der), default_backend())
                facts = scanner._pk_details(cert)
                keys.append({
                    "not_before": entry["not_before"], "not_after": entry["not_after"],
                    "issuer": entry["issuer"], "key_type": facts.get("key_type", ""),
                    "key_bits": facts.get("key_bits", 0), "key_curve": facts.get("key_curve", ""),
                    "sig_algorithm": (cert.signature_algorithm_oid._name or ""),
                })
            except Exception:
                pass
    entries.sort(key=lambda e: str(e.get("not_before") or ""), reverse=True)
    return {"entries": entries[:ct_max_certs()], "total": len(entries), "keys": keys,
            "provider": "certspotter", "provider_url": "https://sslmate.com/ct_search_api/"}


#: Add a provider by adding one callable here. It takes (domain, timeout) and returns
#: {"entries": [...], "total": int, "keys": [...], "provider": str, "provider_url": str}, or raises.
#: Anything it raises becomes "unavailable" with the reason; it must never fabricate an empty list.
CT_PROVIDERS: Dict[str, Callable[[str, float], Dict[str, Any]]] = {
    "crtsh": _ct_crtsh,
    "certspotter": _ct_certspotter,
}


def certificate_transparency(domain: str, deadline: Optional[float] = None) -> Dict[str, Any]:
    """Public CT data for the domain. Never raises; "unavailable" is a first-class answer."""
    base = {"status": "skipped", "provider": ct_provider(), "provider_url": "",
            "certificate_count": None, "entries": [], "issuers": [], "key_history": [],
            "earliest_not_before": "", "latest_not_after": "", "reason": ""}
    if not ct_enabled():
        base["reason"] = "Certificate Transparency lookup is switched off on this deployment."
        return base

    budget = ct_timeout()
    if deadline is not None:
        budget = min(budget, max(0.0, deadline - time.monotonic()))
    if budget < 1.0:
        base["status"] = "unavailable"
        base["reason"] = "The check ran out of its time budget before Certificate Transparency answered."
        return base
    if not _ct_throttle(budget):
        base["status"] = "unavailable"
        base["reason"] = (f"Skipped to stay within one request every {ct_min_interval_seconds():.0f}s "
                          "to the Certificate Transparency service.")
        return base

    fetch = CT_PROVIDERS.get(ct_provider())
    if fetch is None:
        base["status"] = "unavailable"
        base["reason"] = f"No Certificate Transparency provider named {ct_provider()!r}."
        return base

    try:
        data = fetch(domain, budget)
    except Exception as exc:
        base["status"] = "unavailable"
        base["reason"] = (f"The Certificate Transparency service did not answer "
                          f"({type(exc).__name__}: {str(exc)[:120]}). This is not evidence that the "
                          "domain has no certificates.")
        return base

    entries = data.get("entries") or []
    issuers: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for entry in entries:
        name = str(entry.get("issuer") or "").strip()
        if name:
            counts[name] = counts.get(name, 0) + 1
    for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]:
        issuers.append({"issuer": name, "certificates": count})

    befores = sorted([str(e.get("not_before") or "") for e in entries if e.get("not_before")])
    afters = sorted([str(e.get("not_after") or "") for e in entries if e.get("not_after")])
    base.update({
        "status": "ok",
        "provider": str(data.get("provider") or ct_provider()),
        "provider_url": str(data.get("provider_url") or ""),
        "certificate_count": int(data.get("total") or len(entries)),
        "entries": entries,
        "issuers": issuers,
        "key_history": data.get("keys") or [],
        "earliest_not_before": befores[0] if befores else "",
        "latest_not_after": afters[-1] if afters else "",
        "reason": "",
    })
    if not base["key_history"]:
        base["reason"] = ("Key types and sizes are not in the Certificate Transparency index; "
                          "downloading logged certificates to read them is bounded by "
                          "MORROW_PUBLIC_CHECK_CT_CERT_FETCH and produced none here.")
    return base


# ── The verdict ──────────────────────────────────────────────────────────────

#: The published deadlines this answer refers to. Pulled from services/regulatory.py so the free
#: answer and the paid product cannot drift apart about what a date is.
_DEADLINE_FRAMEWORKS = ("NIST_SP_800_208", "CNSA_2_0")


def published_deadlines() -> List[Dict[str, Any]]:
    from services import regulatory

    out: List[Dict[str, Any]] = []
    for framework_id in _DEADLINE_FRAMEWORKS:
        try:
            framework = regulatory.get_framework(framework_id)
        except Exception:
            framework = None
        if not framework:
            continue
        out.append({
            "framework": framework_id,
            "name": framework.get("name", ""),
            "authority": framework.get("authority", ""),
            "jurisdiction": framework.get("jurisdiction", ""),
            "soft_deadline": framework.get("soft_deadline", ""),
            "hard_deadline": framework.get("hard_deadline", ""),
            "applies_to": framework.get("mandatory_for", []),
            "reference": framework.get("filing_url", ""),
        })
    return out


def _headline(observed: Dict[str, Any], readiness: Dict[str, Any]) -> Tuple[str, str, str]:
    """(status, headline, one plain sentence). Never calls a failed check clean."""
    status_code = str(observed.get("scan_status") or "")
    if status_code != "ok":
        reason = {
            "dns_error": "the name did not resolve",
            "timeout": "the host did not answer in time",
            "tls_error": "the TLS handshake failed",
            "unreachable": "the host could not be reached",
            "no_certificate": "no certificate could be read",
        }.get(status_code, "the check did not complete")
        return ("not_assessed",
                "Not checked — the endpoint did not answer",
                f"Nothing was measured here because {reason}. This is not a clean result: "
                "it means there is no evidence either way.")

    family = str(observed.get("key_exchange_family") or "")
    key_type = str(observed.get("key_type") or "")
    key_bits = int(observed.get("key_bits") or 0)
    key_label = f"{key_type}{'-' + str(key_bits) if key_bits else ''}"
    classical_cert = bool(readiness.get("classical_crypto_dependency"))

    if family in ("pq_hybrid", "pq_pure"):
        if classical_cert:
            return ("hybrid_key_exchange",
                    "Partly protected — hybrid key exchange, classical certificate",
                    f"This endpoint already negotiates {observed.get('key_exchange')}, so traffic "
                    "recorded today cannot be decrypted later by a quantum computer. The "
                    f"certificate still uses {key_label}, which a quantum computer could forge "
                    "once one exists, so the identity half of the handshake is not yet protected.")
        return ("post_quantum",
                "Post-quantum key exchange in use",
                f"This endpoint negotiates {observed.get('key_exchange')} and presents no classical "
                "public key this check could identify.")

    if classical_cert:
        kx = (str(observed.get("key_exchange") or "") if observed.get("key_exchange_observed")
              else "a classical key exchange")
        return ("quantum_vulnerable",
                "Quantum-vulnerable today",
                f"Everything this endpoint negotiated is breakable by a sufficiently large quantum "
                f"computer: the certificate's {key_label} key, and {kx}. Traffic recorded today can "
                "be decrypted once such a machine exists - which is why the deadlines below are "
                "dated before anyone expects one.")

    return ("inconclusive",
            "Reached, but not classified",
            "The handshake succeeded, but this check could not classify the endpoint's public-key "
            "algorithm. That is an unknown, not a pass.")


def _classify(name: str) -> Dict[str, Any]:
    from services import fips_pq

    try:
        return fips_pq.classify_algorithm(name)
    except Exception:
        return {"algorithm": name, "status": "unknown"}


#: Roles whose algorithm proves identity, so the replacement is a signature scheme.
_SIGNATURE_ROLES = frozenset({"certificate key", "certificate signature"})
#: Roles whose algorithm establishes a shared secret, so the replacement is a KEM.
_KEM_ROLES = frozenset({"key exchange"})
#: Matched against the suggestion with separators removed, so "X25519MLKEM768" (the hybrid group's
#: own name, and a perfectly good answer for a key exchange) counts as naming a KEM.
_KEM_TOKENS = ("MLKEM", "KYBER")
_SIG_TOKENS = ("MLDSA", "SLHDSA", "DILITHIUM", "SPHINCS", "FALCON")
_SIG_SUGGESTION = "Migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
_KEM_SUGGESTION = "Migrate to ML-KEM-768 (FIPS 203), hybrid with X25519 while clients catch up"


def _narrow_action_to_role(verdict: Dict[str, Any]) -> None:
    """Keep the catalogue's suggestion only where it fits what the algorithm is actually doing.

    services/fips_pq.py keys its migration advice by algorithm, not by role, so RSA-2048 is always
    answered with "Migrate to ML-KEM-768". That is right for a key exchange and wrong for a
    certificate: ML-KEM is key encapsulation and cannot sign anything. Printed under a card headed
    CERTIFICATE KEY it is advice that does not work.

    Only the *suggestion* is narrowed, and only when the catalogue's one names the wrong kind of
    primitive for the role. The classification itself -- status, risk and the reason -- is passed
    through untouched, so the free answer and the paid product still agree about what is broken;
    they differ only in that this one says which replacement applies here. The catalogue's original
    wording is kept in ``action_from_catalogue`` so nothing is silently rewritten.
    """
    if str(verdict.get("status") or "") != "quantum_vulnerable":
        return
    role = str(verdict.get("role") or "")
    action = str(verdict.get("action") or "")
    if not action or action == "none":
        return
    upper = re.sub(r"[-_\s]+", "", action.upper())
    if role in _SIGNATURE_ROLES and not any(t in upper for t in _SIG_TOKENS):
        verdict["action_from_catalogue"] = action
        verdict["action"] = _SIG_SUGGESTION
    elif role in _KEM_ROLES and not any(t in upper for t in _KEM_TOKENS):
        verdict["action_from_catalogue"] = action
        verdict["action"] = _KEM_SUGGESTION


def _algorithm_verdicts(observed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every algorithm this endpoint depends on, named the way the rest of the platform names it.

    The raw strings off the wire are not algorithm names the classifier knows: a certificate's
    signature algorithm arrives as ``sha256WithRSAEncryption``, a curve as ``secp256r1``, a hybrid
    group as ``X25519MLKEM768``. Handed over as-is, all three came back "unknown -- manual review
    required", which on a public page sits next to two "quantum-vulnerable" cards and reads as
    *probably fine*. That is the exact failure this project's rules exist to prevent: an unknown
    quietly becoming a pass.

    So the same resolvers the CBOM uses do the decomposition first --
    ``cbom.canonical_algorithm`` for the public key, ``cbom.signature_algorithm_parts`` to split a
    signature into its signing algorithm and digest, ``cbom.key_exchange_algorithms`` to split a
    hybrid group into its classical and post-quantum halves -- and ``fips_pq`` classifies the
    resolved names. A hybrid group therefore produces two honest cards (X25519 vulnerable, ML-KEM-768
    compliant) instead of one, which is also the truthful picture of what hybrid means.
    """
    from services import cbom

    out: List[Dict[str, Any]] = []
    seen: set = set()

    def add(resolved: str, observed_as: str, role: str) -> None:
        name = str(resolved or "").strip()
        if not name:
            return
        key = (name.lower(), role)
        if key in seen:
            return
        seen.add(key)
        verdict = _classify(name)
        verdict["observed_as"] = str(observed_as or name)
        verdict["resolved_as"] = name
        verdict["role"] = role
        _narrow_action_to_role(verdict)
        out.append(verdict)

    key_type = str(observed.get("key_type") or "")
    key_bits = int(observed.get("key_bits") or 0)
    if key_type:
        add(cbom.canonical_algorithm(key_type, key_bits) or key_type,
            f"{key_type} {key_bits}".strip(), "certificate key")

    sig = str(observed.get("sig_algorithm") or "")
    if sig:
        signer, digest = cbom.signature_algorithm_parts(sig, key_bits)
        add(signer or sig, sig, "certificate signature")
        add(digest or "", sig, "signature digest")

    group = str(observed.get("key_exchange") or "")
    if group and observed.get("key_exchange_observed"):
        parts = cbom.key_exchange_algorithms(group) or [group]
        for part in parts:
            add(part, group, "key exchange")

    return out


def _evidence(observed: Dict[str, Any], ct: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every figure on the page, with where it came from. Nothing unmeasured is listed as fact."""
    rows: List[Dict[str, Any]] = []

    def add(label: str, value: Any, source: str, note: str = "") -> None:
        rows.append({"label": label, "value": "" if value is None else str(value),
                     "source": source, "note": note})

    add("Address connected to", observed.get("address_checked") or "-", "handshake",
        "Resolved before the connection and pinned, so DNS cannot change the target mid-check.")
    add("TLS protocol", observed.get("tls_version") or "not observed", "handshake",
        "The version this endpoint negotiated with this client. Other versions were not probed.")
    add("Cipher suite", observed.get("cipher_name") or "not observed", "handshake")
    if observed.get("key_exchange_observed"):
        add("Key-exchange group", observed.get("key_exchange"), "handshake",
            f"Family: {observed.get('key_exchange_family') or 'unclassified'}.")
    else:
        add("Key-exchange group", "not observed", "handshake",
            str(observed.get("key_exchange_unobservable_reason") or "")
            or "The server named no key-exchange group.")
    key_type = observed.get("key_type") or ""
    key_bits = observed.get("key_bits") or 0
    add("Certificate key", f"{key_type} {key_bits or ''}".strip() or "not observed", "handshake")
    add("Signature algorithm", observed.get("sig_algorithm") or "not observed", "handshake")
    add("Certificate issuer", observed.get("issuer") or "not observed", "handshake")
    add("Certificate expires", observed.get("not_after") or "not observed", "handshake",
        (f"{observed.get('days_until_expiry')} days from now."
         if observed.get("days_until_expiry") is not None else ""))
    add("Certificate verified against public roots", "yes" if observed.get("certificate_verified") else "no",
        "handshake", str(observed.get("verify_error") or "")[:200])

    if ct.get("status") == "ok":
        add("Certificates in Certificate Transparency", ct.get("certificate_count"),
            "certificate_transparency",
            f"Unexpired certificates logged for this name, read from {ct.get('provider')}.")
        if ct.get("issuers"):
            add("Issuers seen in CT", ", ".join(i["issuer"] for i in ct["issuers"][:3]),
                "certificate_transparency")
        if ct.get("latest_not_after"):
            add("Latest CT certificate expiry", ct.get("latest_not_after"), "certificate_transparency")
        for item in (ct.get("key_history") or [])[:5]:
            add("CT certificate key", f"{item.get('key_type','')} {item.get('key_bits') or ''}".strip(),
                "certificate_transparency",
                f"Issued {item.get('not_before','')} by {str(item.get('issuer',''))[:80]}.")
    else:
        add("Certificate Transparency", ct.get("status"), "certificate_transparency",
            str(ct.get("reason") or ""))
    return rows


_LIMITS = [
    "One endpoint: the hostname you typed, on port 443. Other names, other ports and anything "
    "behind a different load balancer were not checked.",
    "One moment: what this server negotiated with this client, just now. A different client, a "
    "different data centre or tomorrow's configuration can differ.",
    "Public data only: the TLS handshake and public Certificate Transparency logs. Nothing inside "
    "your systems was read.",
    "One client's view: a key-exchange group the server would offer a browser but not this probe "
    "would be reported as not observed, not as absent.",
    "No judgement about your certificate authority, your key management, or anything the handshake "
    "does not carry.",
]

_FULL_ASSESSMENT_ADDS = [
    "Every endpoint, not one: discovery across your estate, including internal hosts this tool is "
    "forbidden to touch.",
    "Your code and dependencies: where classical cryptography is called from, and which repository "
    "owns it.",
    "Certificates and keys you issue yourself, from your own CA and key stores.",
    "Harvest-now-decrypt-later exposure weighted by what the data is actually worth and how long it "
    "stays sensitive.",
    "Signed evidence and a CBOM you can hand an auditor, and drift detection so a fix does not "
    "quietly come undone.",
    "A migration path per endpoint, validated as a change to your infrastructure rather than a "
    "recommendation.",
]


def build_result(domain: str, observed: Dict[str, Any], ct: Dict[str, Any],
                 checked_at: Optional[datetime] = None) -> Dict[str, Any]:
    """Turn the observation and the CT data into the answer the page shows.

    Classification comes from services/fips_pq.py, the findings and the readiness assessment from
    policy.py, and the harvest-now-decrypt-later framing from services/hndl.py -- the same code the
    paid product uses, so the free answer and the paid one agree.
    """
    from policy import evaluate_tls_findings, derive_risk_and_score, derive_quantum_readiness
    from services import hndl
    from services.model_basis import model_basis

    when = checked_at or now_utc()
    findings = evaluate_tls_findings(observed)
    scoring = derive_risk_and_score(findings)
    readiness = derive_quantum_readiness(observed, findings)
    status, headline, explanation = _headline(observed, readiness)
    reachable = str(observed.get("scan_status") or "") == "ok"

    algorithms = _algorithm_verdicts(observed)

    q_day = hndl.default_q_day_year()
    hndl_view = hndl.score_tls_endpoint_hndl(
        host=domain, port=PORT,
        tls_version=observed.get("tls_version") or "",
        cipher_name=observed.get("cipher_name") or "",
        key_type=observed.get("key_type") or "",
        key_bits=int(observed.get("key_bits") or 0),
        key_exchange=observed.get("key_exchange") or "",
    ) if reachable else {"risk_tier": hndl.UNMEASURED, "algo_class": hndl.UNMEASURED,
                         "p_broken": None, "rationale": (
                             "No cryptography was observed on this endpoint, so there is no "
                             "algorithm to model and no honest number to show.")}

    return {
        "domain": domain,
        "checked_at": iso(when),
        "outcome": "ok" if reachable else "failed",
        # The permanent record, not /check/{domain}: that page served a cache which expires
        # in an hour and is pruned after a week, so the link it handed out went dead.
        "permalink": f"/r/{domain}",
        "verdict": {
            "status": status,
            "headline": headline,
            "explanation": explanation,
            "quantum_vulnerable": bool(readiness.get("classical_crypto_dependency")) if reachable else None,
            "risk_level": scoring.get("risk_level") if reachable else None,
            "crypto_agility_score": readiness.get("crypto_agility_score"),
            "quantum_readiness_level": readiness.get("quantum_readiness_level"),
            "harvest_now_decrypt_later_risk": readiness.get("harvest_now_decrypt_later_risk"),
            "next_steps": (readiness.get("immediate_hardening_actions") or [])[:3]
                          + (readiness.get("pq_migration_actions") or [])[:2],
        },
        "observed": {
            "reachable": reachable,
            "scan_status": observed.get("scan_status"),
            "error": observed.get("error") or observed.get("verify_error") or "",
            "error_code": observed.get("error_code") or "",
            "address_checked": observed.get("address_checked") or "",
            "port": PORT,
            "tls_version": observed.get("tls_version") or "",
            "cipher_name": observed.get("cipher_name") or "",
            "alpn": observed.get("alpn"),
            "certificate_verified": bool(observed.get("certificate_verified")),
            "key_exchange": observed.get("key_exchange") or "",
            "key_exchange_family": observed.get("key_exchange_family") or "",
            "key_exchange_observed": bool(observed.get("key_exchange_observed")),
            "key_exchange_unobservable_reason": observed.get("key_exchange_unobservable_reason") or "",
            "certificate": {
                "subject": observed.get("subject") or "",
                "issuer": observed.get("issuer") or "",
                "not_before": observed.get("not_before") or "",
                "not_after": observed.get("not_after") or "",
                "days_until_expiry": observed.get("days_until_expiry"),
                "key_type": observed.get("key_type") or "",
                "key_bits": observed.get("key_bits") or 0,
                "key_curve": observed.get("key_curve") or "",
                "sig_algorithm": observed.get("sig_algorithm") or "",
            },
            "connections_made": 2 if observed.get("key_exchange_observation_method") else 1,
        },
        "certificate_transparency": {
            "status": ct.get("status"),
            "provider": ct.get("provider"),
            "provider_url": ct.get("provider_url"),
            "reason": ct.get("reason"),
            "certificate_count": ct.get("certificate_count"),
            "issuers": ct.get("issuers") or [],
            "key_history": ct.get("key_history") or [],
            "earliest_not_before": ct.get("earliest_not_before"),
            "latest_not_after": ct.get("latest_not_after"),
            "recent": [{k: e.get(k) for k in ("issuer", "common_name", "not_before", "not_after")}
                       for e in (ct.get("entries") or [])[:10]],
        },
        "algorithms": algorithms,
        "findings": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"),
                      "title": f.get("title"), "detail": f.get("description") or f.get("detail") or ""}
                     for f in findings][:25],
        # The dollar figure services/hndl.py can also produce is deliberately left out: it prices
        # a stranger's data from per-port assumptions this check knows nothing about. The algorithm
        # class and the break probability are the parts that follow from what was observed.
        "harvest_now_decrypt_later": {
            "algorithm_class": hndl_view.get("algo_class"),
            "risk_tier": hndl_view.get("risk_tier"),
            "break_probability_by_q_day": hndl_view.get("p_broken"),
            "q_day_year_used": q_day.get("year"),
            "q_day_year_source": q_day.get("source"),
            "rationale": hndl_view.get("rationale") or "",
        },
        "deadlines": published_deadlines(),
        "evidence": _evidence(observed, ct),
        "limits": list(_LIMITS),
        "what_a_full_assessment_adds": list(_FULL_ASSESSMENT_ADDS),
        "sources": {
            "handshake": "Measured just now: one TLS handshake to this hostname on port 443, plus "
                         "one ClientHello offering post-quantum groups.",
            "certificate_transparency": f"Public Certificate Transparency logs, read from "
                                        f"{ct.get('provider') or 'no provider'}. Passive: the target "
                                        "was not contacted for this.",
            "model": "Q-Day year, break probabilities and harvest-now-decrypt-later tiers are a "
                     "planning model, not a forecast. See model_basis.",
            "reference": "Published deadlines are quoted from the issuing authority; see the "
                         "reference link on each.",
        },
        "guardrails": settings_public(),
        "model_basis": model_basis(
            kind="model",
            summary=("The TLS facts on this page were measured; the Q-Day year, the break "
                     "probabilities and the harvest-now-decrypt-later tier are a planning model "
                     "built from stated assumptions, not a prediction of when a quantum computer "
                     "will exist."),
            assumptions=[
                f"Q-Day year used: {q_day.get('year')} (source: {q_day.get('source')}).",
                "Quantum vulnerability of RSA, ECDSA, ECDH, EdDSA, DSA and finite-field DH is taken "
                "as given: Shor's algorithm breaks all of them on a cryptographically relevant "
                "quantum computer.",
                "A key-exchange group that was not observed is reported as not observed. It is "
                "never counted as absent.",
                "Deadlines are the dates published by NIST and the NSA; whether they bind this "
                "domain depends on who operates it, which this check cannot know.",
                "One endpoint, one moment, public data only.",
            ],
            sources=[
                "TLS handshake with this endpoint on port 443 (measured).",
                f"Certificate Transparency via {ct.get('provider') or 'no provider'} (public log data).",
                "FIPS 203/204/205 algorithm classification (services/fips_pq.py).",
                "Q-Day model (services/q_intel.py) via services/hndl.py.",
                "Deadlines from NIST and NSA CNSA 2.0 (services/regulatory.py).",
            ],
            as_of="2026-10",
        ),
    }


# ── Cache ────────────────────────────────────────────────────────────────────


def cached_result(domain: str) -> Optional[Dict[str, Any]]:
    """The cached answer for this domain, or None when there is none or it has expired."""
    init_tables()
    try:
        with feature_conn() as conn:
            row = conn.execute(
                "SELECT domain, checked_at, expires_at, outcome, result_json "
                "FROM public_check_results WHERE domain = ?", (domain,)).fetchone()
    except Exception:
        logger.warning("public check: cache read failed for %s", domain)
        return None
    if not row:
        return None
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= now_utc():
        return None
    try:
        payload = json.loads(row["result_json"])
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    payload["cache"] = {"hit": True, "checked_at": row["checked_at"], "expires_at": row["expires_at"],
                        "ttl_seconds": max(0, int((expires - now_utc()).total_seconds()))}
    return payload


def store_result(domain: str, result: Dict[str, Any]) -> None:
    init_tables()
    checked_at = str(result.get("checked_at") or iso(now_utc()))
    expires_at = iso(now_utc() + timedelta(seconds=cache_seconds()))
    try:
        with feature_conn() as conn:
            conn.execute("DELETE FROM public_check_results WHERE domain = ?", (domain,))
            conn.execute(
                "INSERT INTO public_check_results (domain, checked_at, expires_at, outcome, result_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (domain, checked_at, expires_at, str(result.get("outcome") or "ok"),
                 json.dumps(result, separators=(",", ":"))))
            conn.execute("DELETE FROM public_check_results WHERE expires_at < ?",
                         (iso(now_utc() - timedelta(days=7)),))
            conn.commit()
    except Exception:
        logger.warning("public check: cache write failed for %s", domain)
    # The cache above expires; this does not. Every completed check lands in the permanent
    # record, including a failed one -- an endpoint that stopped answering is a fact worth
    # keeping, and leaving it out would make the history look like nothing happened.
    record_observation(domain, result)


# ── Registry: the permanent record ───────────────────────────────────────────

#: The posture ladder. One vocabulary for the page, the badge, the API and the catalogue, so a
#: colour, a word and a database row can never disagree about what was found.
POSTURE_MORROW_READY = "pq_ready"
POSTURE_HYBRID = "hybrid"
POSTURE_CLASSICAL = "classical_only"
POSTURE_UNREACHABLE = "unreachable"
POSTURE_UNKNOWN = "unknown"

#: verdict.status (from _headline) -> posture. Mapping rather than re-deriving, so the record and
#: the page the visitor saw cannot drift apart.
_POSTURE_BY_STATUS = {
    "post_quantum": POSTURE_MORROW_READY,
    "hybrid_key_exchange": POSTURE_HYBRID,
    "quantum_vulnerable": POSTURE_CLASSICAL,
    "not_assessed": POSTURE_UNREACHABLE,
    "inconclusive": POSTURE_UNKNOWN,
}

#: What each posture means, in one sentence, for the page and the API. "unreachable" and
#: "unknown" are deliberately separate and neither is ever phrased as reassurance: the scanner
#: accuracy audit found that reading a failed check as a clean one is the worst bug this product
#: can have, and a registry would publish that mistake at scale.
POSTURE_MEANING = {
    POSTURE_MORROW_READY: "A post-quantum algorithm was negotiated. Traffic recorded today cannot be "
                       "decrypted later by a quantum computer.",
    POSTURE_HYBRID: "A hybrid key exchange was negotiated, so recorded traffic is protected, while "
                    "the certificate's identity key is still classical.",
    POSTURE_CLASSICAL: "Only classical cryptography was observed. Traffic recorded today can be "
                       "decrypted once a sufficiently large quantum computer exists.",
    POSTURE_UNREACHABLE: "Nothing was measured: the endpoint did not complete a handshake. This is "
                         "not a clean result, it is an absence of evidence.",
    POSTURE_UNKNOWN: "Catalogued, but no algorithm could be established from what was observed.",
}

POSTURE_LABEL = {
    POSTURE_MORROW_READY: "ready",
    POSTURE_HYBRID: "hybrid",
    POSTURE_CLASSICAL: "classical",
    POSTURE_UNREACHABLE: "unreachable",
    POSTURE_UNKNOWN: "unknown",
}


def posture_of(result: Dict[str, Any]) -> str:
    """The posture for a stored result. Anything unrecognised is 'unknown', never 'ready'."""
    status = str(((result or {}).get("verdict") or {}).get("status") or "")
    return _POSTURE_BY_STATUS.get(status, POSTURE_UNKNOWN)


def content_hash(result: Dict[str, Any]) -> str:
    """A digest of the endpoint's cryptography, and of nothing else.

    Only the fields that describe what was negotiated and what key is presented. Deliberately
    excluded: the time of the check, timings, queue state, and the certificate's validity dates --
    a renewal that keeps the same algorithm is not a change in posture, and including not_after
    would append a row every ninety days for every domain on the internet.
    """
    observed = (result or {}).get("observed") or {}
    cert = observed.get("certificate") or {}
    basis = "\n".join(str(part) for part in (
        observed.get("scan_status") or "",
        observed.get("tls_version") or "",
        observed.get("cipher_name") or "",
        observed.get("key_exchange") or "",
        observed.get("key_exchange_family") or "",
        bool(observed.get("key_exchange_observed")),
        cert.get("key_type") or "",
        int(cert.get("key_bits") or 0),
        cert.get("key_curve") or "",
        cert.get("sig_algorithm") or "",
        cert.get("subject") or "",
        cert.get("issuer") or "",
        ((result or {}).get("verdict") or {}).get("status") or "",
    ))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def observation_summary(result: Dict[str, Any]) -> str:
    """One line describing the cryptography, for a history row."""
    observed = (result or {}).get("observed") or {}
    cert = observed.get("certificate") or {}
    if not observed.get("reachable"):
        return str(observed.get("error_code") or observed.get("scan_status") or "no handshake")
    parts: List[str] = []
    if observed.get("tls_version"):
        parts.append(str(observed["tls_version"]))
    if observed.get("key_exchange_observed") and observed.get("key_exchange"):
        parts.append(str(observed["key_exchange"]))
    key_type = str(cert.get("key_type") or "")
    if key_type:
        bits = int(cert.get("key_bits") or 0)
        curve = str(cert.get("key_curve") or "")
        parts.append(f"{key_type} {curve}".strip() if curve else
                     (f"{key_type}-{bits}" if bits else key_type))
    return " / ".join(parts) or "no algorithm identified"


def record_observation(domain: str, result: Dict[str, Any], source: str = "measured") -> int:
    """Append this observation to the permanent record, or extend an identical one.

    Returns the observation id, or 0 when the write failed. A failure here must never fail the
    check the visitor asked for: the registry is a side effect of answering, not the answer.
    """
    init_tables()
    now = iso(now_utc())
    digest = content_hash(result)
    posture = posture_of(result)
    outcome = str((result or {}).get("outcome") or "ok")
    observed_at = str((result or {}).get("checked_at") or now)
    payload = json.dumps(result, separators=(",", ":"))
    try:
        with feature_conn() as conn:
            existing_obs = conn.execute(
                "SELECT id, observed_at FROM public_check_observations "
                "WHERE domain = ? AND content_hash = ? AND source = ?",
                (domain, digest, source)).fetchone()
            if existing_obs is not None:
                obs_id = int(existing_obs["id"])
                # Same cryptography as before: extend the sighting and refresh the stored payload
                # so the page shows current deadlines and model values, but do not add a row.
                conn.execute(
                    "UPDATE public_check_observations SET last_seen_at = ?, result_json = ? "
                    "WHERE id = ?", (now, payload, obs_id))
                is_new = False
            else:
                cursor = conn.execute(
                    "INSERT INTO public_check_observations "
                    "(domain, observed_at, last_seen_at, source, outcome, posture, content_hash, "
                    " result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (domain, observed_at, now, source, outcome, posture, digest, payload))
                obs_id = int(cursor.lastrowid or 0)
                is_new = True

            catalog = conn.execute(
                "SELECT first_seen_at, observations, hidden FROM public_check_domains "
                "WHERE domain = ?", (domain,)).fetchone()
            # An opted-out domain is still recorded -- the evidence of what we saw is what makes
            # an abuse complaint answerable -- but it is hidden from every public route.
            hidden = 1 if opted_out(domain) else (int(catalog["hidden"]) if catalog else 0)
            if catalog is None:
                conn.execute(
                    "INSERT INTO public_check_domains "
                    "(domain, first_seen_at, last_observed_at, latest_id, posture, source, "
                    " observations, hidden) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (domain, observed_at, now, obs_id, posture, source, 1, hidden))
            else:
                conn.execute(
                    "UPDATE public_check_domains SET last_observed_at = ?, latest_id = ?, "
                    "posture = ?, source = ?, observations = ?, hidden = ? WHERE domain = ?",
                    (now, obs_id, posture, source,
                     int(catalog["observations"] or 0) + (1 if is_new else 0), hidden, domain))
            conn.commit()
        return obs_id
    except Exception:
        logger.warning("public check: registry write failed for %s", domain)
        return 0


def _registry_payload(row: Any) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(row["result_json"])
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def registry_entry(domain: str) -> Optional[Dict[str, Any]]:
    """The catalogue row and the latest stored result, or None when there is no record.

    Hidden domains return None: every public route then answers exactly as it does for a domain
    that was never checked, which is what the opt-out promise requires.
    """
    init_tables()
    try:
        with feature_conn() as conn:
            row = conn.execute(
                "SELECT d.domain, d.first_seen_at, d.last_observed_at, d.posture, d.source, "
                "       d.observations, d.hidden, o.id AS observation_id, o.observed_at, "
                "       o.last_seen_at, o.outcome, o.content_hash, o.result_json "
                "FROM public_check_domains d "
                "JOIN public_check_observations o ON o.id = d.latest_id "
                "WHERE d.domain = ?", (domain,)).fetchone()
    except Exception:
        logger.warning("public check: registry read failed for %s", domain)
        return None
    if row is None or int(row["hidden"] or 0):
        return None
    payload = _registry_payload(row)
    if payload is None:
        return None
    return {
        "domain": row["domain"],
        "first_seen_at": row["first_seen_at"],
        "last_observed_at": row["last_observed_at"],
        "posture": row["posture"],
        "source": row["source"],
        "observations": int(row["observations"] or 0),
        "observation_id": int(row["observation_id"]),
        "observed_at": row["observed_at"],
        "last_seen_at": row["last_seen_at"],
        "outcome": row["outcome"],
        "content_hash": row["content_hash"],
        "result": payload,
    }


def registry_observation(domain: str, observation_id: int) -> Optional[Dict[str, Any]]:
    """One immutable observation by id, for a citable URL."""
    init_tables()
    try:
        with feature_conn() as conn:
            hidden = conn.execute(
                "SELECT hidden FROM public_check_domains WHERE domain = ?", (domain,)).fetchone()
            if hidden is not None and int(hidden["hidden"] or 0):
                return None
            row = conn.execute(
                "SELECT id, domain, observed_at, last_seen_at, source, outcome, posture, "
                "       content_hash, result_json FROM public_check_observations "
                "WHERE domain = ? AND id = ?", (domain, int(observation_id))).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    payload = _registry_payload(row)
    if payload is None:
        return None
    return {
        "domain": row["domain"],
        "observation_id": int(row["id"]),
        "observed_at": row["observed_at"],
        "last_seen_at": row["last_seen_at"],
        "source": row["source"],
        "outcome": row["outcome"],
        "posture": row["posture"],
        "content_hash": row["content_hash"],
        "result": payload,
    }


def registry_history(domain: str, limit: int = 20) -> List[Dict[str, Any]]:
    """The observations for a domain, newest first. Empty for a hidden or unknown domain."""
    init_tables()
    try:
        with feature_conn() as conn:
            hidden = conn.execute(
                "SELECT hidden FROM public_check_domains WHERE domain = ?", (domain,)).fetchone()
            if hidden is not None and int(hidden["hidden"] or 0):
                return []
            rows = conn.execute(
                "SELECT id, observed_at, last_seen_at, source, outcome, posture, result_json "
                "FROM public_check_observations WHERE domain = ? "
                "ORDER BY observed_at DESC, id DESC LIMIT ?",
                (domain, max(1, min(200, int(limit))))).fetchall()
    except Exception:
        return []
    history: List[Dict[str, Any]] = []
    for row in rows:
        payload = _registry_payload(row) or {}
        history.append({
            "observation_id": int(row["id"]),
            "observed_at": row["observed_at"],
            "last_seen_at": row["last_seen_at"],
            "source": row["source"],
            "outcome": row["outcome"],
            "posture": row["posture"],
            "summary": observation_summary(payload),
        })
    return history


def set_registry_hidden(domain: str, hidden: bool) -> int:
    """Hide or restore a domain and every subdomain of it. Returns the number of rows changed.

    add_optout() already deletes cached results for the domain and its subdomains, and
    opted_out() resolves a subdomain to its covering opt-out, so the registry has to hide the
    same set -- otherwise the guarantee is narrower in the registry than in the checker that
    made it.
    """
    init_tables()
    try:
        with feature_conn() as conn:
            cursor = conn.execute(
                "UPDATE public_check_domains SET hidden = ? WHERE domain = ? OR domain LIKE ?",
                (1 if hidden else 0, domain, "%." + domain))
            conn.commit()
            return int(cursor.rowcount or 0)
    except Exception:
        logger.warning("public check: registry hide failed for %s", domain)
        return 0


# ── Log ──────────────────────────────────────────────────────────────────────


def log_check(domain: str, ip_hash: str, outcome: str, detail: str = "",
              duration_ms: Optional[int] = None) -> None:
    """One row per attempt, so abuse can be investigated. The IP is salted-hashed, never stored."""
    init_tables()
    try:
        with feature_conn() as conn:
            conn.execute(
                "INSERT INTO public_check_log (domain, created_at, requester_ip_hash, outcome, detail, duration_ms) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(domain or "")[:300], iso(now_utc()), str(ip_hash or "")[:64],
                 str(outcome or "")[:64], str(detail or "")[:500],
                 int(duration_ms) if duration_ms is not None else None))
            conn.execute("DELETE FROM public_check_log WHERE created_at < ?",
                         (iso(now_utc() - timedelta(days=log_retention_days())),))
            conn.commit()
    except Exception:
        logger.warning("public check: could not write the check log for %s", domain)


def recent_log(limit: int = 100, domain: str = "") -> List[Dict[str, Any]]:
    """For an abuse investigation. Operator-only; never served on a public route."""
    init_tables()
    bound = max(1, min(int(limit or 100), 1000))
    with feature_conn() as conn:
        if domain:
            rows = conn.execute(
                "SELECT domain, created_at, requester_ip_hash, outcome, detail, duration_ms "
                "FROM public_check_log WHERE domain = ? ORDER BY created_at DESC LIMIT ?",
                (str(domain).lower(), bound)).fetchall()
        else:
            rows = conn.execute(
                "SELECT domain, created_at, requester_ip_hash, outcome, detail, duration_ms "
                "FROM public_check_log ORDER BY created_at DESC LIMIT ?", (bound,)).fetchall()
    return [{"domain": r["domain"], "created_at": r["created_at"],
             "requester_ip_hash": r["requester_ip_hash"], "outcome": r["outcome"],
             "detail": r["detail"], "duration_ms": r["duration_ms"]} for r in rows]


# ── The check ────────────────────────────────────────────────────────────────


def run_check(domain: Any, client_ip: str = "", force: bool = False,
              allow_cache: bool = True) -> Dict[str, Any]:
    """Validate, refuse, serve the cache, or make the one check. Order matters.

    1. Validate the hostname. Nothing is contacted for a target this tool will not accept.
    2. Opt-out, before DNS: an opted-out domain is not resolved, let alone connected to.
    3. The cache, which does not consume the check budget. A popular domain is checked once.
    4. Rate limits: per IP, per domain, and for the whole service.
    5. Admission to the bounded queue.
    6. Resolve and refuse any non-public address; pin the one that is checked.
    7. One handshake, one key-exchange probe, one passive CT lookup.
    """
    started = time.monotonic()
    ip_hash = hash_ip(client_ip)
    host = normalize_domain(domain)  # raises PublicCheckError(400) for a target we will not touch

    try:
        covered = opted_out(host)
        if covered:
            raise PublicCheckError(
                403,
                f"{covered} has asked not to be checked by this service, so {host} was not "
                "contacted. Nothing was resolved and no connection was made.",
                "refused_optout")

        if allow_cache and not force:
            hit = cached_result(host)
            if hit is not None:
                log_check(host, ip_hash, "cache_hit", "", int((time.monotonic() - started) * 1000))
                return hit

        if not enabled():
            raise PublicCheckError(
                503, "The free checker is switched off on this deployment.", "disabled")

        enforce_rate_limits(host, ip_hash)

        with _Admission():
            deadline = time.monotonic() + deadline_seconds()
            address = resolve_public_address(host)
            observed = observe_endpoint(host, address=address,
                                        timeout=min(handshake_timeout(), deadline_seconds()),
                                        deadline=deadline)
            ct = certificate_transparency(host, deadline=deadline)

        result = build_result(host, observed, ct)
        result["cache"] = {"hit": False, "checked_at": result["checked_at"],
                           "expires_at": iso(now_utc() + timedelta(seconds=cache_seconds())),
                           "ttl_seconds": cache_seconds()}
        store_result(host, result)
        log_check(host, ip_hash, result["outcome"],
                  str(result["observed"].get("error_code") or ""),
                  int((time.monotonic() - started) * 1000))
        return result
    except PublicCheckError as exc:
        log_check(host, ip_hash, exc.outcome, exc.detail[:200],
                  int((time.monotonic() - started) * 1000))
        raise
    except Exception as exc:
        logger.exception("public check failed for %s", host)
        log_check(host, ip_hash, "error", f"{type(exc).__name__}", int((time.monotonic() - started) * 1000))
        raise PublicCheckError(
            500, "The check failed for a reason on our side, so there is no result to show. "
                 "This is not a clean verdict for this domain.", "error") from exc


def export_json(result: Dict[str, Any]) -> Dict[str, Any]:
    """A small, stable export of a cached result: measurement, sources, limits."""
    return {
        "schema": "airlock.public-check/1",
        "domain": result.get("domain"),
        "checked_at": result.get("checked_at"),
        "outcome": result.get("outcome"),
        "verdict": result.get("verdict"),
        "observed": result.get("observed"),
        "certificate_transparency": {k: v for k, v in (result.get("certificate_transparency") or {}).items()
                                     if k != "recent"},
        "algorithms": result.get("algorithms"),
        "harvest_now_decrypt_later": result.get("harvest_now_decrypt_later"),
        "deadlines": result.get("deadlines"),
        "evidence": result.get("evidence"),
        "limits": result.get("limits"),
        "sources": result.get("sources"),
        "model_basis": result.get("model_basis"),
    }


def export_cbom(result: Dict[str, Any]) -> Dict[str, Any]:
    """A CycloneDX 1.6 CBOM for the one endpoint, from the existing generator."""
    from services import cbom

    observed = result.get("observed") or {}
    certificate = observed.get("certificate") or {}
    facts = {
        "host": result.get("domain"), "port": PORT,
        "scan_status": "ok" if observed.get("reachable") else "unreachable",
        "tls_version": observed.get("tls_version") or "",
        "cipher_name": observed.get("cipher_name") or "",
        "key_exchange": observed.get("key_exchange") or "",
        "key_exchange_observed": bool(observed.get("key_exchange_observed")),
        "key_type": certificate.get("key_type") or "",
        "key_bits": certificate.get("key_bits") or 0,
        "key_curve": certificate.get("key_curve") or "",
        "sig_algorithm": certificate.get("sig_algorithm") or "",
        "subject": certificate.get("subject") or "",
        "issuer": certificate.get("issuer") or "",
        "not_before": certificate.get("not_before") or "",
        "not_after": certificate.get("not_after") or "",
        "findings": [],
    }
    document = cbom.generate_cbom([facts], org_name="", scan_id=f"public-check:{result.get('domain')}")
    return document
