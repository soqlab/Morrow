"""Verified domains: on a hosted deployment, an organization scans only what it has proved it controls.

An account on a hosted deployment can make the platform connect to any host it names, from the
operator's addresses and under the operator's name. With self sign-up that would be a free
reconnaissance service pointed at other people's infrastructure. So when
MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1:

  * an organization adds a domain and gets a DNS TXT record to publish:
        _morrow-verify.<domain>  TXT  "morrow-verify=<token>"
  * once the record resolves, the domain is verified, and the organization may scan that domain
    and every name under it (example.com covers www.example.com and vpn.eu.example.com);
  * anything else is refused before a socket is opened: other domains, and IP addresses, whose
    ownership a DNS record cannot show.

The check runs inside scanner.scan_host and ssh_scanner.scan_ssh, which every scan path calls,
using the organization of the current context. A context that lost its organization arrives as
the default organization, which is refused unless listed: the failure is a refused scan, never
an unrestricted one. Organizations the operator trusts (a signed pilot, the operator's own) are
listed in MORROW_SCAN_UNRESTRICTED_ORGS.

What this does not stop: a verified domain's owner can point a name under it at any address.
The scan then reaches that address, but presents the owner's name, from a rate-limited account
tied to a verified domain and an email address, which is the trade-off scanning services make.
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import atomic, feature_conn

RECORD_PREFIX = "_morrow-verify"
VALUE_PREFIX = "morrow-verify="
MAX_DOMAINS_PER_ORG = 50

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,62}}$")

SCHEMA = """
    CREATE TABLE IF NOT EXISTS org_verified_domains (
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        token TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        verified_at TEXT,
        last_checked_at TEXT,
        last_error TEXT,
        PRIMARY KEY (org_id, domain)
    )
"""

_ready = False
_ready_lock = threading.Lock()
_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()
_CACHE_SECONDS = 15.0


class DomainError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _flag(name: str) -> bool:
    return str(os.getenv(name, "0") or "0").strip().lower() in {"1", "true", "yes", "on"}


def enforcement_enabled() -> bool:
    return _flag("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS")


def unrestricted_orgs() -> set:
    raw = str(os.getenv("MORROW_SCAN_UNRESTRICTED_ORGS") or "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _init() -> None:
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with feature_conn() as conn:
            conn.execute(SCHEMA)
            conn.commit()
        _ready = True


def _invalidate(org_id: str) -> None:
    with _cache_lock:
        _cache.pop(org_id, None)


def normalize_domain(value: Any) -> str:
    """A bare registrable-looking domain from what someone typed, or DomainError."""
    text = str(value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)       # scheme
    text = text.split("/", 1)[0].split("?", 1)[0]            # path, query
    text = text.rsplit("@", 1)[-1]                           # userinfo
    if text.startswith("[") or _is_ip(text.split(":", 1)[0]):
        raise DomainError(400, "Enter a domain name, not an IP address: a DNS record can't show who owns an address.")
    text = text.split(":", 1)[0].rstrip(".")                 # port, trailing dot
    if text.startswith("*."):
        text = text[2:]
    try:
        text = text.encode("idna").decode("ascii")
    except Exception:
        raise DomainError(400, "That doesn't look like a domain name.") from None
    if len(text) > 253 or not _DOMAIN_RE.match(text):
        raise DomainError(400, "That doesn't look like a domain name. Enter something like example.com.")
    return text


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text or "").strip("[]"))
        return True
    except ValueError:
        return False


def _row(r: Any) -> Dict[str, Any]:
    domain, token = r["domain"], r["token"]
    return {
        "domain": domain,
        "status": r["status"],
        "created_at": r["created_at"],
        "verified_at": r["verified_at"],
        "last_checked_at": r["last_checked_at"],
        "last_error": r["last_error"] or "",
        "record_name": f"{RECORD_PREFIX}.{domain}",
        "record_type": "TXT",
        "record_value": f"{VALUE_PREFIX}{token}",
    }


def list_domains(org_id: str) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT domain, token, status, created_at, verified_at, last_checked_at, last_error "
            "FROM org_verified_domains WHERE org_id = ? ORDER BY domain", (org_id,)
        ).fetchall()
    return [_row(r) for r in rows]


def add_domain(org_id: str, domain: Any) -> Dict[str, Any]:
    name = normalize_domain(domain)
    _init()
    with feature_conn() as conn:
        existing = conn.execute(
            "SELECT domain, token, status, created_at, verified_at, last_checked_at, last_error "
            "FROM org_verified_domains WHERE org_id = ? AND domain = ?", (org_id, name)
        ).fetchone()
        if existing:
            return _row(existing)
        count = conn.execute("SELECT COUNT(*) AS n FROM org_verified_domains WHERE org_id = ?", (org_id,)).fetchone()
        if int(count["n"] or 0) >= MAX_DOMAINS_PER_ORG:
            raise DomainError(400, f"An organization can hold up to {MAX_DOMAINS_PER_ORG} domains. Remove one first.")
        with atomic(conn):
            conn.execute(
                "INSERT INTO org_verified_domains (org_id, domain, token, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                (org_id, name, secrets.token_urlsafe(24), _now()),
            )
        conn.commit()
    _invalidate(org_id)
    return next(d for d in list_domains(org_id) if d["domain"] == name)


def remove_domain(org_id: str, domain: Any) -> bool:
    name = normalize_domain(domain)
    _init()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM org_verified_domains WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.commit()
    _invalidate(org_id)
    return int(cur.rowcount or 0) > 0


def _txt_values(name: str) -> List[str]:
    """The TXT strings published at name, read fresh from DNS. Raises DomainError on lookup failure."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8.0
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        raise DomainError(504, "The DNS lookup timed out. Try again in a minute.") from None
    except Exception as exc:
        raise DomainError(502, f"The DNS lookup failed ({exc.__class__.__name__}). Try again in a minute.") from None
    values: List[str] = []
    for record in answer:
        values.append(b"".join(record.strings).decode("utf-8", "replace").strip())
    return values


def verify_domain(org_id: str, domain: Any) -> Dict[str, Any]:
    name = normalize_domain(domain)
    _init()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT domain, token, status FROM org_verified_domains WHERE org_id = ? AND domain = ?", (org_id, name)
        ).fetchone()
    if not row:
        raise DomainError(404, "Add the domain first.")
    expected = f"{VALUE_PREFIX}{row['token']}"
    record = f"{RECORD_PREFIX}.{name}"
    found = _txt_values(record)
    ok = expected in found
    error = "" if ok else (
        f"No TXT record {record} with the value {expected} was found yet. DNS changes can take a few "
        "minutes to appear; check the record and try again."
    )
    now = _now()
    with feature_conn() as conn:
        if ok:
            conn.execute(
                "UPDATE org_verified_domains SET status = 'verified', verified_at = COALESCE(verified_at, ?), "
                "last_checked_at = ?, last_error = '' WHERE org_id = ? AND domain = ?", (now, now, org_id, name))
        else:
            conn.execute(
                "UPDATE org_verified_domains SET last_checked_at = ?, last_error = ? WHERE org_id = ? AND domain = ?",
                (now, error, org_id, name))
        conn.commit()
    _invalidate(org_id)
    result = next(d for d in list_domains(org_id) if d["domain"] == name)
    result["verified_now"] = ok
    return result


def verified_domains(org_id: str) -> List[str]:
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(org_id)
        if hit and hit[0] > now:
            return hit[1]
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT domain FROM org_verified_domains WHERE org_id = ? AND status = 'verified'", (org_id,)
        ).fetchall()
    domains = [r["domain"] for r in rows]
    with _cache_lock:
        _cache[org_id] = (now + _CACHE_SECONDS, domains)
    return domains


def _host_name(host: Any) -> str:
    text = str(host or "").strip().lower().rstrip(".")
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    return text


def refusal(org_id: str, host: Any) -> str:
    """Why this organization may not scan this host, or "" when it may."""
    if not enforcement_enabled():
        return ""
    org = str(org_id or "").strip()
    if org and org in unrestricted_orgs():
        return ""
    name = _host_name(host)
    if not name:
        return "No host to scan."
    if _is_ip(name):
        return ("Scan by host name under one of your verified domains: an IP address can't be "
                "verified as yours.")
    try:
        name = name.encode("idna").decode("ascii")
    except Exception:
        return "That host name isn't valid."
    for domain in verified_domains(org) if org else []:
        if name == domain or name.endswith("." + domain):
            return ""
    return (f"{name} is not under a verified domain of your organization. Verify the domain first "
            "under Domains; you can only scan what you've shown you control.")


def refusal_for_current_org(host: Any) -> str:
    if not enforcement_enabled():
        return ""
    from db import current_organization_id

    return refusal(current_organization_id(), host)
