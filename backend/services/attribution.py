"""
Trigger Enrichment — neutral network facts for a canary trigger

Reports what can be observed about where a canary trigger came from:
  - the IP address and whether it is public, private, or reserved
  - its ASN, network owner and country, from a public IP lookup
  - whether the user agent names a common HTTP client or scanning tool

It does NOT attribute activity to any actor, agency, group, or government.
IP, ASN, timing and user-agent data cannot support attribution, and the
platform does not label carriers or hosting providers as fronts for anyone.
Treat the output as leads for your own investigation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from services.model_basis import model_basis as _model_basis


# ── User-agent patterns for common clients and scanning tools ────────────────
# Tool identification only; none of these implies who is operating the tool.
_TOOL_UA_PATTERNS: List[Tuple[str, str]] = [
    (r"python-requests/\d", "Python requests library"),
    (r"curl/\d",            "curl"),
    (r"Go-http-client/",    "Go net/http client"),
    (r"masscan",            "masscan port scanner"),
    (r"zgrab",              "zgrab scanner"),
    (r"nmap",               "Nmap scripting engine"),
    (r"Shodan",             "Shodan crawler"),
    (r"censys",             "Censys scanner"),
    (r"^-?$",               "Empty user agent"),
]


def _ip_facts(ip: str) -> Dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"valid": False}
    return {
        "valid": True,
        "version": addr.version,
        "is_global": bool(addr.is_global),
        "is_private": bool(addr.is_private),
        "is_loopback": bool(addr.is_loopback),
        "is_reserved": bool(addr.is_reserved),
    }


def _geoip_with_asn(ip: str) -> Dict[str, Any]:
    """Public IP lookup (country, network owner, ASN). Returns {} for non-public IPs or on failure."""
    facts = _ip_facts(ip)
    if not facts.get("valid") or not facts.get("is_global"):
        return {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,isp,as,query,city,timezone"
        req = urllib.request.Request(url, headers={"User-Agent": "Morrow/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "fail":
            return {}
        return {
            "country":      data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "city":         data.get("city", ""),
            "org":          data.get("org", ""),
            "isp":          data.get("isp", ""),
            "asn":          (data.get("as") or "").split(" ")[0],  # "AS64500 Example Net" → "AS64500"
            "timezone":     data.get("timezone", ""),
        }
    except Exception:
        return {}


def _ua_tool(ua: str) -> str:
    for pattern, tool in _TOOL_UA_PATTERNS:
        if re.search(pattern, ua or "", re.IGNORECASE):
            return tool
    return ""


def attribution_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="reference",
        summary=(
            "Neutral network facts about the trigger source (IP, ASN, network owner, user-agent tool). "
            "No actor, agency, or country attribution is made."
        ),
        assumptions=[
            "ASN, network owner and country come from a public IP geolocation lookup (ip-api.com) and can be wrong or stale.",
            "User-agent strings are client-supplied and trivially spoofed; a tool match does not identify who used the tool.",
            "Non-public IP addresses are not looked up.",
        ],
        sources=["https://ip-api.com/docs"],
        as_of="2026-09",
    )


def attribute_trigger(
    trigger_ip: str,
    trigger_ua: str = "",
    trigger_time_iso: str = "",
    canary_tier: str = "",
) -> Dict[str, Any]:
    """
    Enrich a canary trigger with neutral network facts.

    Returns:
      network, geo, ip_facts, indicators, attribution_provided (always False), summary
    """
    facts = _ip_facts(trigger_ip)
    geo = _geoip_with_asn(trigger_ip)

    indicators: List[Dict[str, Any]] = []
    if facts.get("valid") and not facts.get("is_global"):
        indicators.append({
            "type": "ip_scope",
            "value": trigger_ip,
            "description": "Non-public address (private, loopback, or reserved); the trigger came from inside a network you control or via a proxy.",
        })
    if geo.get("asn"):
        owner = geo.get("org") or geo.get("isp") or "unknown owner"
        indicators.append({
            "type": "asn",
            "value": geo["asn"],
            "description": f"Announced by {geo['asn']} ({owner}).",
        })
    if trigger_ua is not None:
        tool = _ua_tool(trigger_ua)
        if tool:
            indicators.append({
                "type": "user_agent",
                "value": (trigger_ua or "")[:120],
                "description": f"User agent matches {tool}.",
            })
    if canary_tier:
        indicators.append({
            "type": "canary_tier",
            "value": canary_tier,
            "description": f"Canary tier '{canary_tier}' was triggered.",
        })

    network = {
        "asn": geo.get("asn", ""),
        "org": geo.get("org", ""),
        "isp": geo.get("isp", ""),
        "country_code": geo.get("country_code", ""),
    }
    return {
        "trigger_ip":           trigger_ip,
        "trigger_ua":           trigger_ua,
        "trigger_time":         trigger_time_iso,
        "canary_tier":          canary_tier,
        "network":              network,
        "geo":                  geo,
        "ip_facts":             facts,
        "indicators":           indicators,
        "attribution_provided": False,
        "summary": (
            f"Trigger from {trigger_ip}"
            + (f" ({network['asn']}, {network['org'] or network['isp']})" if network["asn"] else "")
            + f". {len(indicators)} network fact{'s' if len(indicators) != 1 else ''} recorded; no attribution is made."
        ),
        "disclaimer": (
            "Network facts only. IP, ASN and user-agent data cannot establish who is responsible; "
            "do not present these results as attribution."
        ),
        "model_basis": attribution_model_basis(),
    }
