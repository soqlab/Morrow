"""Passive TLS discovery routes.

  POST   /v1/runtime/passive/ingest          log-shipper endpoint; ingest token is the credential
  GET    /v1/runtime/passive/endpoints       deduplicated observations for the caller's org
  GET    /v1/runtime/passive/tokens          list ingest tokens (no secrets)
  POST   /v1/runtime/passive/tokens          create one; the secret is returned exactly once
  DELETE /v1/runtime/passive/tokens/{id}     revoke

The ingest route is exempt from the customer auth middleware (app._auth_public_path) because a
log shipper has no user session; it authenticates by the ingest token alone and takes its
organization from the token, never from x-org-id.
"""

from __future__ import annotations

import sys
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from db import current_organization_id, reset_current_organization_id, set_current_organization_id
from services import org_rate_limits, passive_discovery, passive_ingest

RequireRole = Callable[..., Dict[str, Any]]
INGEST_PATH = "/v1/runtime/passive/ingest"


class CreateIngestToken(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    default_format: str = Field("", max_length=16)


def _default_org_id() -> str:
    app_module = sys.modules.get("app")
    return str(getattr(app_module, "DEFAULT_ORG_ID", "default-org") if app_module else "default-org")


def _active_org_id(request: Request) -> str:
    return str(getattr(request.state, "org_id", "") or current_organization_id() or _default_org_id()).strip()


def _actor(request: Request) -> str:
    claims = getattr(request.state, "auth_claims", {}) or {}
    return str(claims.get("sub") or claims.get("email") or request.headers.get("x-user-id") or "unknown")[:160]


def _presented_token(request: Request) -> str:
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return str(request.headers.get("x-morrow-ingest-token") or "").strip()


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise passive_ingest.PayloadError(413, f"Body exceeds {limit} bytes.")
    chunks = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise passive_ingest.PayloadError(413, f"Body exceeds {limit} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def _ingest_sync(token: Dict[str, Any], fmt: str, records: list) -> Dict[str, Any]:
    org = token["organization_id"]
    ctx = set_current_organization_id(org)
    try:
        result = passive_discovery.parse_batch(fmt, records)
        stored = passive_ingest.store_observations(org, token["id"], result["observations"])
        assets = passive_ingest.merge_into_inventory(stored["new_asset_keys"], org)
    finally:
        reset_current_organization_id(ctx)
    summary: Dict[str, int] = {}
    for obs in result["observations"]:
        summary[obs["pq_status"]] = summary.get(obs["pq_status"], 0) + 1
    return {
        "ok": True,
        "format": fmt,
        "received": result["received"],
        "parsed": result["parsed"],
        "skipped": result["skipped"],
        "unparseable": result["unparseable"],
        "unparseable_by_reason": result["unparseable_by_reason"],
        "unparseable_samples": result["unparseable_samples"],
        "pq_status_counts": summary,
        "endpoints_touched": stored["endpoints_touched"],
        "endpoints_new": stored["endpoints_new"],
        "assets_upserted": assets,
        "group_logged": fmt != "alb",
        **({"note": "AWS ALB access logs do not record the key-exchange group; TLS 1.3 endpoints "
                    "seen only through ALB stay 'unknown' until another source or a scan observes it."}
           if fmt == "alb" else {}),
    }


def create_passive_discovery_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter()
    try:
        from db_postgres import register_deferred_schema

        register_deferred_schema("passive_discovery", passive_ingest.init_tables)
    except Exception:  # pragma: no cover - SQLite-only builds
        pass

    @router.post(INGEST_PATH)
    async def api_passive_ingest(request: Request, format: Optional[str] = Query(None, max_length=16)):
        token, error = await run_in_threadpool(passive_ingest.verify_token, _presented_token(request))
        if not token:
            return JSONResponse(status_code=401, content={"detail": error},
                                headers={"WWW-Authenticate": "Bearer"})
        limit = passive_ingest.rate_limit_per_minute()
        if limit:
            hit = await run_in_threadpool(org_rate_limits.hit, "passive_ingest", token["id"], limit, 60.0)
            if not hit["allowed"]:
                retry = max(1, int(hit.get("retry_after") or 1))
                return JSONResponse(status_code=429, content={"detail": f"Ingest rate limit of {limit}/minute exceeded."},
                                    headers={"Retry-After": str(retry)})
        fmt = str(format or token.get("default_format") or "").strip().lower()
        if fmt not in passive_discovery.FORMATS:
            return JSONResponse(status_code=400, content={
                "detail": f"Pass ?format= one of {', '.join(passive_discovery.FORMATS)} (or set a default on the token)."})
        try:
            body = await _read_body(request, passive_ingest.max_body_bytes())
            records = await run_in_threadpool(
                passive_ingest.decode_records, body,
                request.headers.get("content-type", ""), request.headers.get("content-encoding", ""))
        except passive_ingest.PayloadError as exc:
            return JSONResponse(status_code=exc.status, content={"detail": exc.detail})
        response = await run_in_threadpool(_ingest_sync, token, fmt, records)
        return response

    @router.get("/v1/runtime/passive/endpoints")
    def api_passive_endpoints(request: Request, host: str = Query("", max_length=253),
                              limit: int = Query(500, ge=1, le=5000)):
        org = _active_org_id(request)
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="passive.endpoints.list",
                     resource_type="passive_discovery", resource_id=org)
        items = passive_ingest.list_endpoints(org, host=host, limit=limit)
        counts: Dict[str, int] = {}
        for item in items:
            counts[item["pq_status"]] = counts.get(item["pq_status"], 0) + 1
        return {"organization_id": org, "count": len(items), "pq_status_counts": counts, "items": items}

    @router.get("/v1/runtime/passive/tokens")
    def api_passive_tokens(request: Request):
        org = _active_org_id(request)
        require_role(request, allowed_roles=["admin"], action="passive.tokens.list",
                     resource_type="passive_ingest_token", resource_id=org)
        return {"items": passive_ingest.list_tokens(org)}

    @router.post("/v1/runtime/passive/tokens")
    def api_passive_token_create(body: CreateIngestToken, request: Request):
        org = _active_org_id(request)
        require_role(request, allowed_roles=["admin"], action="passive.tokens.create",
                     resource_type="passive_ingest_token", resource_id=org)
        try:
            record, secret = passive_ingest.create_token(org, body.name, body.default_format, _actor(request))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"token": record, "secret": secret,
                "note": "Store this secret now; Morrow keeps only a salted hash and cannot show it again.",
                "ingest_url": INGEST_PATH}

    @router.delete("/v1/runtime/passive/tokens/{token_id}")
    def api_passive_token_revoke(token_id: str, request: Request):
        org = _active_org_id(request)
        require_role(request, allowed_roles=["admin"], action="passive.tokens.revoke",
                     resource_type="passive_ingest_token", resource_id=token_id)
        record = passive_ingest.revoke_token(token_id, org, _actor(request))
        if not record:
            raise HTTPException(status_code=404, detail="Ingest token not found.")
        return {"token": record}

    return router
