"""The read-only tools behind `morrow-mcp` (morrow_mcp/server.py), without the MCP SDK.

Each tool is one or two GET requests to your Morrow server's API with your organization's read-only
API key, so the server applies the same organization scoping and role checks as the console, and
journals the call in its hash-chained audit log (the ``X-Client: mcp/<tool>`` header names the tool;
backend/services/mcp_access.py). Nothing here can change anything: the client only issues GET
requests, and the server refuses anything else from an assistant.

Whatever comes back is passed on as data: bounded in size, control characters removed, and wrapped
with the request it came from.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

import httpx

DEFAULT_TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 2_000_000   # read from the server
MAX_OUTPUT_CHARS = 12_000        # handed to the assistant
MAX_STRING = 1_000
MAX_ITEMS = 25
MAX_KEYS = 60
MAX_DEPTH = 6

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$")
CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,59}$")
JURISDICTION_RE = re.compile(r"^[A-Za-z]{2,8}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")


class ToolInputError(ValueError):
    """An argument that can't be sent (the message says which and why)."""


class MorrowMCPError(RuntimeError):
    """Morrow refused or could not answer; the message is safe to show."""


@dataclass
class Config:
    url: str
    api_key: str
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def from_env(cls, url: Optional[str] = None) -> "Config":
        base = (url or os.getenv("MORROW_URL") or "http://localhost:8000").strip().rstrip("/")
        return cls(url=base, api_key=(os.getenv("MORROW_API_KEY") or "").strip())

    def problems(self) -> List[str]:
        """What is wrong with this configuration, in words a person can act on."""
        out = []
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            out.append(f"MORROW_URL must be an http(s) address, not {self.url!r}.")
        elif parts.scheme == "http" and not _local(parts.hostname) and os.getenv("MORROW_MCP_ALLOW_HTTP") != "1":
            out.append("MORROW_URL uses plain http to another machine, which would send your key unencrypted. "
                       "Use https, or set MORROW_MCP_ALLOW_HTTP=1 if this is a trusted private network.")
        if not self.api_key:
            out.append("MORROW_API_KEY is not set. Create an organization API key with only the read scope "
                       "and put it in your assistant's MCP settings.")
        elif not self.api_key.startswith("pq_"):
            out.append("MORROW_API_KEY should be a Morrow organization API key (it starts with pq_).")
        return out


def _local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def clean(value: Any, depth: int = 0) -> Tuple[Any, bool]:
    """A bounded copy of decoded JSON: (value, whether anything was cut)."""
    if isinstance(value, str):
        text = _CONTROL.sub("", value)
        if len(text) > MAX_STRING:
            return text[:MAX_STRING] + " [...]", True
        return text, False
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if depth >= MAX_DEPTH:
        return "[nested data left out]", True
    cut = False
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_KEYS:
                out["[more fields left out]"] = len(value) - MAX_KEYS
                cut = True
                break
            key, _ = clean(str(k)[:100], depth + 1)
            out[key], c = clean(v, depth + 1)
            cut = cut or c
        return out, cut
    if isinstance(value, (list, tuple)):
        items = []
        for v in list(value)[:MAX_ITEMS]:
            item, c = clean(v, depth + 1)
            items.append(item)
            cut = cut or c
        if len(value) > MAX_ITEMS:
            items.append(f"[{len(value) - MAX_ITEMS} more items left out]")
            cut = True
        return items, cut
    return clean(str(value), depth)


def render(request: str, data: Any) -> str:
    """The text an assistant receives: the request it answers, then the bounded data, as JSON."""
    body, cut = clean(data)
    text = json.dumps({"source": "Morrow", "request": request, "truncated": cut, "data": body},
                      ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) > MAX_OUTPUT_CHARS:
        text = json.dumps({"source": "Morrow", "request": request, "truncated": True,
                           "data_excerpt": text[:MAX_OUTPUT_CHARS - 300]}, ensure_ascii=False)
    return text


class ReadOnlyClient:
    """GET-only HTTP client for one Morrow server. There is no method that sends anything else.

    ``http`` lets tests pass an httpx.Client of their own (FastAPI's TestClient is one).
    """

    def __init__(self, config: Config, transport: Optional[httpx.BaseTransport] = None,
                 http: Optional[httpx.Client] = None):
        self.config = config
        self._http = http or httpx.Client(base_url=config.url, timeout=config.timeout_s,
                                          follow_redirects=False, transport=transport)

    def close(self) -> None:
        self._http.close()

    def get(self, tool: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        problems = self.config.problems()
        if problems:
            raise MorrowMCPError(" ".join(problems))
        headers = {"Authorization": f"Bearer {self.config.api_key}", "X-Client": f"mcp/{tool}",
                   "Accept": "application/json", "User-Agent": "morrow-mcp"}
        query = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            with self._http.stream("GET", path, params=query, headers=headers, follow_redirects=False) as resp:
                raw = bytearray()
                for chunk in resp.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise MorrowMCPError("Morrow's answer was too large to pass on.")
                status = resp.status_code
        except httpx.TimeoutException:
            raise MorrowMCPError("Morrow did not answer in time.") from None
        except httpx.HTTPError as exc:
            raise MorrowMCPError(f"Could not reach Morrow at {self.config.url} ({type(exc).__name__}).") from None
        try:
            payload = json.loads(bytes(raw).decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            payload = None
        if status >= 400:
            detail = payload.get("detail") if isinstance(payload, dict) else None
            if not isinstance(detail, str):
                detail = f"HTTP {status}"
            raise MorrowMCPError(f"Morrow refused: {clean(detail)[0][:500]} (HTTP {status})")
        if 300 <= status < 400:
            raise MorrowMCPError(f"Morrow answered with a redirect (HTTP {status}); check MORROW_URL.")
        if payload is None:
            raise MorrowMCPError("Morrow's answer was not JSON; check MORROW_URL points at the API.")
        return payload


def _domain(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(text):
        raise ToolInputError(f"{str(value)[:80]!r} is not a domain name (for example example.com).")
    return text


def _q(value: str) -> str:
    return quote(value, safe="")


# ----------------------------------------------------------------------------------------------
# The tools. Each returns (request description, data); server.py renders it.
# ----------------------------------------------------------------------------------------------

def risk_sentence(client: ReadOnlyClient, domain: str) -> Tuple[str, Any]:
    host = _domain(domain)
    path = f"/api/public/grade/{_q(host)}"
    result = client.get("risk_sentence", path, {"stored": "1"})
    risk = result.get("risk") if isinstance(result, dict) else None
    data = {"domain": host, "grade": result.get("grade") if isinstance(result, dict) else None,
            "checked_at": (result or {}).get("scanned_at"),
            "risk": risk}
    return f"GET {path}?stored=1", data


def inventory_summary(client: ReadOnlyClient) -> Tuple[str, Any]:
    page = client.get("inventory_summary", "/assets", {"limit": 500})
    scans = client.get("inventory_summary", "/scans", {"limit": 5})
    items = page.get("items") if isinstance(page, dict) else []
    items = items if isinstance(items, list) else []

    def count(key: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for a in items:
            name = str((a or {}).get(key) or "unset")[:60]
            out[name] = out.get(name, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1])[:15])

    recent = []
    for s in scans if isinstance(scans, list) else []:
        if isinstance(s, dict):
            recent.append({k: s.get(k) for k in ("scan_id", "status", "created_at", "summary") if k in s})
    data = {"assets": len(items), "more_than_shown": bool(isinstance(page, dict) and page.get("next_cursor")),
            "by_criticality": count("criticality"), "by_environment": count("environment"),
            "without_owner": sum(1 for a in items if not (a or {}).get("owner")),
            "recent_scans": recent}
    return "GET /assets, GET /scans", data


def findings_needing_action(client: ReadOnlyClient, limit: int = 20) -> Tuple[str, Any]:
    limit = max(1, min(int(limit), 50))
    feed = client.get("findings_needing_action", "/work/remediation-feed", {"limit": limit})
    keep = ("id", "kind", "title", "asset_key", "repository", "status", "priority", "risk_label",
            "next_action", "blocked", "blockers", "safe_to_apply", "pr_url", "updated_at")
    cards = [{k: c.get(k) for k in keep if k in c} for c in (feed or {}).get("cards") or [] if isinstance(c, dict)]
    return "GET /work/remediation-feed", {"summary": (feed or {}).get("summary"), "cards": cards}


def make_safe_status(client: ReadOnlyClient, domain: str) -> Tuple[str, Any]:
    host = _domain(domain)
    out: Dict[str, Any] = {"domain": host}
    for key, path in (("plan", f"/api/public/make-safe/{_q(host)}"),
                      ("recheck", f"/api/public/make-safe/{_q(host)}/watch"),
                      ("proof", f"/r/{_q(host)}/proof.json")):
        try:
            out[key] = client.get("make_safe_status", path)
        except MorrowMCPError as exc:  # no grade yet, or no proof yet: say so beside the rest
            out[key] = {"unavailable": str(exc)}
    return (f"GET /api/public/make-safe/{host}, GET /api/public/make-safe/{host}/watch, "
            f"GET /r/{host}/proof.json"), out


def watch_changes(client: ReadOnlyClient, domain: Optional[str] = None) -> Tuple[str, Any]:
    if domain:
        host = _domain(domain)
        path = f"/api/public/history/{_q(host)}"
        return f"GET {path}", client.get("watch_changes", path, {"limit": 20})
    return "GET /api/public/changes", client.get("watch_changes", "/api/public/changes", {"limit": 25})


def harvest_clock(client: ReadOnlyClient, domain: str, data: Optional[str] = None,
                  jurisdiction: Optional[str] = None) -> Tuple[str, Any]:
    host = _domain(domain)
    if data and not CATEGORY_RE.match(data):
        raise ToolInputError(f"{data[:60]!r} is not a data category id (for example personal-data-general).")
    if jurisdiction and not JURISDICTION_RE.match(jurisdiction):
        raise ToolInputError(f"{jurisdiction[:20]!r} is not a jurisdiction code (for example EU or US).")
    grade = client.get("harvest_clock", f"/api/public/grade/{_q(host)}", {"stored": "1"})
    risk = (grade or {}).get("risk") or {}
    state = risk.get("state") if risk.get("state") in ("safe", "at_risk", "no_tls", "unknown") else "unknown"
    clock = client.get("harvest_clock", "/api/public/risk-sentence",
                       {"host": host, "state": state, "fixable": int(risk.get("fixable") or 0),
                        "data": data, "jur": jurisdiction})
    return (f"GET /api/public/grade/{host}?stored=1, GET /api/public/risk-sentence",
            {"domain": host, "grade": (grade or {}).get("grade"), "clock": clock})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    fn: Callable[..., Tuple[str, Any]] = field(compare=False)


# Descriptions say what each tool returns; they never tell the assistant what to do.
TOOLS: Tuple[ToolSpec, ...] = (
    ToolSpec("risk_sentence", "Quantum risk in one sentence",
             "A domain's stored Morrow grade and its quantum risk in one sentence (when recorded traffic "
             "could be read, how many settings fix it). Stored results only; no new check is run.",
             risk_sentence),
    ToolSpec("inventory_summary", "Inventory summary",
             "Your organization's asset inventory in numbers (by criticality and environment, assets "
             "without an owner) and its five most recent scans.", inventory_summary),
    ToolSpec("findings_needing_action", "Findings needing action",
             "Open remediation and migration work for your organization, highest priority first: what it "
             "is, where, its status and the next action. Limit 1-50.", findings_needing_action),
    ToolSpec("make_safe_status", "Make it safe",
             "Make it safe for a graded domain: the fix for its stack, the re-check session's status and "
             "the signed quantum-safe proof, where there is one.", make_safe_status),
    ToolSpec("watch_changes", "What changed",
             "With a domain: its stored grade history, newest first. Without: Morrow's public feed of "
             "sites that became post-quantum ready or dropped below B.", watch_changes),
    ToolSpec("harvest_clock", "Harvest clock",
             "For a domain's stored grade: from which year traffic recorded today could be read, how long "
             "the chosen kind of data must stay private (data: a Shelf-Life category id; jurisdiction: "
             "for example EU) and whether that is long enough.", harvest_clock),
)
