"""CBOM ingest from CI (services/cbom_webhook.py).

  POST   /v1/cbom/ingest                 signed-in operator or admin; organization = the caller's
  POST   /v1/runtime/cbom/ingest         CI; per-organization ingest token is the credential
  GET    /v1/cbom/webhook/setup          admin: endpoints, signing status, GitHub Actions step
  POST   /v1/cbom/webhook/signing-key    admin: create or rotate the signing key (returned once)
  DELETE /v1/cbom/webhook/signing-key    admin: remove it
  GET    /v1/cbom/webhook/ingests        viewer and up: recent ingests
  GET    /v1/cbom/ingest-tokens          admin: list tokens (no secrets)
  POST   /v1/cbom/ingest-tokens          admin: create one; the secret is returned exactly once
  DELETE /v1/cbom/ingest-tokens/{id}     admin: revoke

The organization is never read from X-Org-Id. The signed-in route takes it from the authenticated
identity and refuses a request whose X-Org-Id names a different one; the CI route is exempt from
the customer auth middleware (app._auth_public_path), as the passive-discovery ingest is, and takes
the organization from the token alone. On both, an organization that has a signing key gets only
correctly signed documents.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from db import reset_current_organization_id, set_current_organization_id
from services import cbom_webhook

RUNTIME_INGEST_PATH = "/v1/runtime/cbom/ingest"


class CreateCbomIngestToken(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


def _presented_token(request: Request) -> str:
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return str(request.headers.get("x-morrow-ingest-token") or "").strip()


def _actor_name(request: Request) -> str:
    claims = getattr(request.state, "auth_claims", {}) or {}
    return str(claims.get("sub") or claims.get("email") or request.headers.get("x-user-id") or "unknown")[:160]


async def _read_body(request: Request) -> bytes:
    limit = cbom_webhook.max_body_bytes()
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"Body exceeds {limit} bytes.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=f"Body exceeds {limit} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def _ingest(db: Callable[[], Any], org_id: str, body: bytes, signature: str) -> Dict[str, Any]:
    with db() as conn:
        cbom_webhook.init_tables(conn)
        refusal = cbom_webhook.signature_refusal(conn, org_id, body, signature)
        if refusal:
            raise HTTPException(status_code=401, detail=refusal)
        try:
            payload = cbom_webhook.parse_payload(body)
        except OverflowError as exc:
            raise HTTPException(status_code=413, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return cbom_webhook.ingest_cbom(conn, org_id, payload)


def create_cbom_ingest_router(
    require_role: Callable[..., Any],
    org_of: Callable[[Request], str],
    db: Callable[[], Any],
    limiter: Optional[Any] = None,
) -> APIRouter:
    router = APIRouter()

    def _limit(rule: str):
        return limiter.limit(rule) if limiter is not None else (lambda fn: fn)

    @router.post("/v1/cbom/ingest")
    @router.post("/cbom/ingest")
    @_limit("30/minute")
    async def api_cbomwh_ingest(request: Request):
        """Ingest a CBOM as the signed-in operator or admin, into the caller's organization."""
        require_role(request, allowed_roles=["operator", "admin"], action="cbom.ingest",
                     resource_type="cbom", resource_id="")
        org_id = org_of(request)
        claimed = str(request.headers.get("x-org-id") or "").strip()
        if claimed and claimed != org_id:
            raise HTTPException(status_code=403, detail="X-Org-Id does not match the authenticated organization.")
        body = await _read_body(request)
        return _ingest(db, org_id, body, request.headers.get("x-morrow-signature", ""))

    @router.post(RUNTIME_INGEST_PATH)
    @_limit("30/minute")
    async def api_cbomwh_runtime_ingest(request: Request):
        """Ingest a CBOM from CI. The ingest token is the credential and names the organization."""
        with db() as conn:
            cbom_webhook.init_tables(conn)
            token, error = cbom_webhook.verify_token(conn, _presented_token(request))
        if not token:
            raise HTTPException(status_code=401, detail=error)
        org_id = token["organization_id"]
        ctx = set_current_organization_id(org_id)
        request.state.org_id = org_id
        try:
            body = await _read_body(request)
            result = _ingest(db, org_id, body, request.headers.get("x-morrow-signature", ""))
        finally:
            reset_current_organization_id(ctx)
        return {**result, "token_id": token["id"]}

    @router.get("/v1/cbom/webhook/setup")
    @router.get("/cbom/webhook/setup")
    def api_cbomwh_setup(request: Request):
        """Endpoints, signing status and a ready-to-paste CI step. Read-only: it never creates a key
        (that would silently start refusing unsigned uploads) and never returns one."""
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.webhook.setup",
                     resource_type="cbom", resource_id=org_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            created = cbom_webhook.signing_key_created_at(conn, org_id)
            tokens = cbom_webhook.list_tokens(conn, org_id)
        base = str(request.base_url).rstrip("/")
        return {
            "signing_required": created is not None,
            "signing_key_created_at": created,
            "endpoint": f"{base}{RUNTIME_INGEST_PATH}",
            "interactive_endpoint": f"{base}/v1/cbom/ingest",
            "ingest_tokens": [t for t in tokens if t["status"] == "active"],
            "github_actions_step": cbom_webhook.github_actions_step(base),
            "next_steps": [
                "Create an ingest token (POST /v1/cbom/ingest-tokens) and store it as the "
                "MORROW_CBOM_INGEST_TOKEN repository secret.",
                "Optionally create a signing key (POST /v1/cbom/webhook/signing-key) and store it as "
                "MORROW_CBOM_SIGNING_KEY. Once it exists, unsigned uploads are refused.",
            ],
        }

    @router.post("/v1/cbom/webhook/signing-key")
    @router.post("/cbom/webhook/signing-key")
    def api_cbomwh_signing_key_create(request: Request):
        """Create or rotate the signing key. Returned once; from now on uploads must be signed."""
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.webhook.signing_key.set",
                     resource_type="cbom", resource_id=org_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            secret = cbom_webhook.set_new_secret(conn, org_id)
        return {"secret": secret, "signing_required": True,
                "note": "Store this key now as MORROW_CBOM_SIGNING_KEY. Unsigned or wrongly signed uploads are refused."}

    @router.delete("/v1/cbom/webhook/signing-key")
    @router.delete("/cbom/webhook/signing-key")
    def api_cbomwh_signing_key_delete(request: Request):
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.webhook.signing_key.delete",
                     resource_type="cbom", resource_id=org_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            removed = cbom_webhook.delete_secret(conn, org_id)
        return {"removed": removed, "signing_required": False}

    @router.get("/v1/cbom/webhook/ingests")
    @router.get("/cbom/webhook/ingests")
    def api_cbomwh_list(request: Request, limit: int = Query(20, ge=1, le=200)):
        require_role(request, allowed_roles=["viewer", "analyst", "operator", "admin", "owner"],
                     action="cbom.webhook.ingests", resource_type="cbom", resource_id="")
        with db() as conn:
            cbom_webhook.init_tables(conn)
            return {"ingests": cbom_webhook.list_ingests(conn, org_of(request), limit)}

    @router.get("/v1/cbom/ingest-tokens")
    @router.get("/cbom/ingest-tokens")
    def api_cbom_tokens(request: Request):
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.tokens.list",
                     resource_type="cbom_ingest_token", resource_id=org_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            return {"items": cbom_webhook.list_tokens(conn, org_id)}

    @router.post("/v1/cbom/ingest-tokens")
    @router.post("/cbom/ingest-tokens")
    def api_cbom_token_create(body: CreateCbomIngestToken, request: Request):
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.tokens.create",
                     resource_type="cbom_ingest_token", resource_id=org_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            try:
                record, secret = cbom_webhook.create_token(conn, org_id, body.name, _actor_name(request))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        return {"token": record, "secret": secret,
                "note": "Store this secret now; Morrow keeps only a salted hash and cannot show it again."}

    @router.delete("/v1/cbom/ingest-tokens/{token_id}")
    @router.delete("/cbom/ingest-tokens/{token_id}")
    def api_cbom_token_revoke(token_id: str, request: Request):
        org_id = org_of(request)
        require_role(request, allowed_roles=["admin"], action="cbom.tokens.revoke",
                     resource_type="cbom_ingest_token", resource_id=token_id)
        with db() as conn:
            cbom_webhook.init_tables(conn)
            record = cbom_webhook.revoke_token(conn, token_id, org_id, _actor_name(request))
        if not record:
            raise HTTPException(status_code=404, detail="Ingest token not found.")
        return {"token": record}

    return router
