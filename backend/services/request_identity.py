"""Who a request belongs to, for usage attribution and per-organization rate limits.

Used by the traffic journal (app._record_traffic_event) and the per-organization limiter. Metadata only:
the result is an organization id, an actor id, a role and whether the identity was established. It never
reads bodies, query strings or token material beyond the claims the auth middleware already verified.

Rules, in order:
  1. A verified credential (request.state.authenticated with auth_claims: a JWT in MORROW_AUTH_MODE=jwt, or an
     organization API key in any mode) -> its organization and subject.
  2. MORROW_AUTH_MODE=headers, where the x-user-id / x-org-id headers *are* the identity contract (development
     and trusted-proxy deployments; production requires jwt) -> the resolved organization and x-user-id.
     Vendor-operator routes (/platform, /vendor-admin) are not customer usage and stay unattributed.
  3. Anything else is anonymous: no organization, no actor.

Before this module the journal only honoured rule 1 and, outside jwt mode, took the actor from headers even
for API keys. The dev and header-mode deployments therefore journaled every request as anonymous, so
Customer 360 showed zero API requests for every customer.
"""

from __future__ import annotations

from typing import Any, Dict

_OPERATOR_PREFIXES = ("/platform/", "/v1/platform/", "/vendor-admin")


def _clean(value: Any, limit: int) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable()).strip()[:limit]


def resolve(request: Any, auth_mode: str) -> Dict[str, Any]:
    state = request.state
    org = _clean(getattr(state, "org_id", ""), 128)
    claims = getattr(state, "auth_claims", {}) or {}
    if bool(getattr(state, "authenticated", False)) and isinstance(claims, dict) and claims:
        actor = _clean(getattr(state, "actor_id", "") or claims.get("sub") or claims.get("email") or claims.get("user_id"), 120)
        role = claims.get("role") or claims.get("roles") or ""
        if isinstance(role, (list, tuple)):
            role = ",".join(str(x) for x in role)
        claim_org = _clean(claims.get("org_id") or claims.get("organization_id") or claims.get("org"), 128)
        return {"authenticated": True, "organization_id": org or claim_org, "actor_id": actor,
                "actor_role": _clean(getattr(state, "actor_role", "") or role, 80), "method": str(claims.get("auth_method") or "jwt")}
    path = str(getattr(request.url, "path", "") or "")
    if str(auth_mode or "").lower() == "headers" and not path.startswith(_OPERATOR_PREFIXES):
        user = _clean(request.headers.get("x-user-id"), 120)
        header_org = _clean(request.headers.get("x-org-id"), 128)
        if user or header_org:
            return {"authenticated": True, "organization_id": org or header_org, "actor_id": user,
                    "actor_role": _clean(request.headers.get("x-user-role"), 80), "method": "headers"}
    return {"authenticated": False, "organization_id": "", "actor_id": "", "actor_role": "", "method": ""}
