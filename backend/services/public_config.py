"""
Deployment-specific values that appear inside generated artifacts.

Generated certificates, credentials, CI workflows, SARIF reports and incident
templates must not carry placeholder domains or made-up identifiers. Each value
here comes from configuration and is empty when not configured, in which case
callers omit the field rather than invent one.

  MORROW_PUBLIC_BASE_URL          https://app.your-domain.com — links in generated files
  MORROW_DID_WEB_DOMAIN           did:web domain for issued credentials (defaults to the base URL host)
  MORROW_STATUS_PAGE_URL          public status page linked from incident templates
  MORROW_PRIVATE_ENTERPRISE_OID   OID for the hybrid-certificate post-quantum public-key extension,
                               under your IANA Private Enterprise Number (1.3.6.1.4.1.<PEN>.<n>)
"""

from __future__ import annotations

import os
import re
from urllib.parse import quote, urlparse

_OID_RE = re.compile(r"^[0-2](\.(0|[1-9][0-9]*))+$")
_IANA_PEN_ARC = "1.3.6.1.4.1."
_EXAMPLE_PEN_ARCS = ("1.3.6.1.4.1.99999", "1.3.6.1.4.1.32473")  # 32473 is IANA's documentation PEN


def public_base_url() -> str:
    raw = str(os.getenv("MORROW_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return raw


def public_host() -> str:
    base = public_base_url()
    return (urlparse(base).hostname or "") if base else ""


def did_web_domain() -> str:
    """did:web method-specific id for this deployment (port encoded as %3A), or ''."""
    configured = str(os.getenv("MORROW_DID_WEB_DOMAIN", "") or "").strip().strip("/")
    if configured:
        return configured.replace(":", "%3A") if "%3A" not in configured else configured
    base = public_base_url()
    if not base:
        return ""
    parsed = urlparse(base)
    host = parsed.hostname or ""
    if not host:
        return ""
    return f"{host}%3A{parsed.port}" if parsed.port else host


def did_web_identifier(*path_segments: str) -> str:
    domain = did_web_domain()
    if not domain:
        return ""
    parts = [domain] + [quote(str(p), safe="") for p in path_segments if str(p)]
    return "did:web:" + ":".join(parts)


def status_page_url() -> str:
    raw = str(os.getenv("MORROW_STATUS_PAGE_URL", "") or "").strip()
    parsed = urlparse(raw) if raw else None
    if not parsed or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return raw


def private_enterprise_oid() -> str:
    """Configured OID for the private post-quantum extension, or '' (extension omitted)."""
    raw = str(os.getenv("MORROW_PRIVATE_ENTERPRISE_OID", "") or "").strip()
    if not raw or not _OID_RE.match(raw):
        return ""
    if not raw.startswith(_IANA_PEN_ARC):
        return ""
    if any(raw == arc or raw.startswith(arc + ".") for arc in _EXAMPLE_PEN_ARCS):
        return ""
    return raw
