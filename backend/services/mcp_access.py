"""AI assistants over MCP (tools/morrow_mcp): who may ask, and the journal entry each question leaves.

morrow-mcp runs on the customer's own machine and calls this API with the organization's API key,
marking every request ``X-Client: mcp/<tool>``. Such a request is answered only when:

* ``MORROW_MCP_ENABLED=1`` is set on this server. It is off unless set, and off on the hosted
  service: assistant access is for self-hosted installs at first;
* it carries an organization API key (``Authorization: Bearer pq_...``) whose scopes are exactly
  ``read`` -- a write, admin or sign key, a session token, a support token or no credential is
  refused with a message saying to create a read-only key;
* it is a GET or HEAD. The read scope already refuses anything else; this says so in the
  assistant's terms.

Every request that reaches the key check is appended to the organization's hash-chained audit
journal (services/audit_chain.py) as ``mcp.tool_call``: the tool name, the key id, method, route
path and status, allowed or denied. Never the key, the query string or the response.
"""

from __future__ import annotations

import os
import re
from typing import Any, Awaitable, Callable, Dict, Optional

from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

MCP_PREFIX = "mcp/"
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_METHODS = frozenset({"GET", "HEAD"})

OFF = ("Assistant (MCP) access is turned off on this server. It is available on self-hosted Morrow: "
       "the server's operator turns it on with MORROW_MCP_ENABLED=1.")
NEEDS_READ_KEY = ("Morrow only answers an AI assistant that uses a read-only organization API key. Create one "
                  "with only the read scope and put it in your assistant's MCP settings as MORROW_API_KEY.")
BROAD_KEY = ("This API key can change things, so Morrow won't let an AI assistant use it. Create an API key "
             "with only the read scope and use that one instead.")
WRITE_REFUSED = "Your assistant can only read from Morrow. This request would change something, so it was refused."


def enabled() -> bool:
    return os.getenv("MORROW_MCP_ENABLED", "").strip() == "1"


def tool_name(x_client: str) -> Optional[str]:
    """The tool named by ``X-Client: mcp/<tool>``; "unknown" if it is not a plain name; None if not MCP."""
    text = str(x_client or "")
    if not text.lower().startswith(MCP_PREFIX):
        return None
    name = text[len(MCP_PREFIX):].strip()
    return name if _TOOL_RE.match(name) else "unknown"


def _record(claims: Dict[str, Any], tool: str, method: str, path: str, status: int, decision: str, reason: str) -> None:
    from db import append_audit_log, reset_current_organization_id, set_current_organization_id

    token = set_current_organization_id(str(claims.get("org_id") or ""))
    try:
        append_audit_log(
            actor_id=str(claims.get("sub") or ""),
            actor_role=str(claims.get("role") or ""),
            action="mcp.tool_call",
            resource_type="mcp_tool",
            resource_id=tool,
            decision=decision,
            reason=reason[:200],
            details={"tool": tool, "api_key_id": str(claims.get("api_key_id") or ""), "method": method,
                     "path": str(path or "")[:300], "status": int(status), "client": "mcp"},
        )
    finally:
        reset_current_organization_id(token)


async def _journal(claims: Dict[str, Any], tool: str, method: str, path: str, status: int,
                   decision: str, reason: str = "") -> None:
    try:
        await run_in_threadpool(_record, claims, tool, method, path, status, decision, reason)
    except Exception:  # a journal write never changes the answer that was already decided
        pass


async def handle(request: Any, call_next: Callable[[Any], Awaitable[Any]], bearer: str, tool: str) -> Any:
    """Answer or refuse one MCP-marked request (called from app.set_request_auth_context)."""
    from services import api_keys

    if not enabled():
        return JSONResponse(status_code=403, content={"detail": OFF})
    if not str(bearer or "").startswith(api_keys.TOKEN_PREFIX):
        return JSONResponse(status_code=403, content={"detail": NEEDS_READ_KEY})
    method = str(request.method or "").upper()
    path = request.url.path
    # The scope is checked before the route rules, so a write, admin or sign key always gets the
    # same answer: make a read-only key.
    record, error, status = await run_in_threadpool(api_keys.verify_token, bearer)
    if not record:
        return JSONResponse(status_code=status, content={"detail": error})
    key_actor = {"sub": f"apikey:{record.get('id')}", "role": record.get("role"),
                 "org_id": record.get("organization_id"), "api_key_id": record.get("id")}
    if set(record.get("scopes") or []) != {"read"}:
        await _journal(key_actor, tool, method, path, 403, "deny", "key is not read-only")
        return JSONResponse(status_code=403, content={"detail": BROAD_KEY})
    if method not in _METHODS:
        await _journal(key_actor, tool, method, path, 403, "deny", "assistants can only read")
        return JSONResponse(status_code=403, content={"detail": WRITE_REFUSED})
    claims, error, status = await run_in_threadpool(api_keys.claims_for_request, bearer, method, path)
    if not claims:
        await _journal(key_actor, tool, method, path, status, "deny", str(error or ""))
        return JSONResponse(status_code=status, content={"detail": error})
    request.state.auth_claims = claims
    request.state.authenticated = True
    request.state.mcp_tool = tool
    response = await call_next(request)
    await _journal(claims, tool, method, path, response.status_code, "allow")
    return response
