"""Inventory connections to certificate managers and cloud KMS (services/cert_inventory).

Read-only at every vendor. Credentials go in once, are sealed with the vault key and never come
back out of any route here.
"""
from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from db import current_organization_id
from services import cert_inventory as inv


class CertSourceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(..., min_length=2, max_length=40)
    label: str = Field("", max_length=80)
    fields: Dict[str, Any] = Field(default_factory=dict)
    schedule_hours: int = Field(0, ge=0, le=168)


class ScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule_hours: int = Field(..., ge=0, le=168)


def create_cert_inventory_router(require_role: Callable) -> APIRouter:
    router = APIRouter(tags=["Certificate and KMS inventory"])
    readers = ["viewer", "operator", "admin", "owner"]
    operators = ["operator", "admin", "owner"]
    admins = ["admin", "owner"]

    def org(request: Request) -> str:
        return str(getattr(request.state, "org_id", None) or current_organization_id())

    def call(request: Request, response: Response, roles, action: str, resource_id: str, fn, *args):
        response.headers["Cache-Control"] = "no-store"
        require_role(request, allowed_roles=roles, action="cert_sources." + action, resource_type="cert_source",
                     resource_id=str(resource_id)[:40])
        try:
            return fn(org(request), *args)
        except inv.CertSourceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None

    @router.get("/cert-sources/providers")
    def providers(request: Request, response: Response):
        """Certificate managers and KMS services that can be connected, with what each needs."""
        return {"api_version": "v1", "read_only": True, "providers": inv.providers_public()}

    @router.get("/cert-sources")
    def list_sources(request: Request, response: Response):
        return {"api_version": "v1", "connections": call(request, response, readers, "list", "", inv.list_sources)}

    @router.post("/cert-sources")
    def add_source(body: CertSourceBody, request: Request, response: Response):
        """Connect a source. The credentials are checked with a read-only call, then stored sealed."""
        actor = ""
        claims = getattr(request.state, "auth_claims", {}) or {}
        if isinstance(claims, dict):
            actor = str(claims.get("sub") or claims.get("email") or "")
        connection = call(request, response, admins, "add", body.provider, lambda o: inv.add_source(
            o, body.provider, body.fields, body.label, body.schedule_hours, created_by=actor))
        return {"api_version": "v1", "connection": connection}

    @router.post("/cert-sources/{source_id}/test")
    def test_source(source_id: str, request: Request, response: Response):
        return {"api_version": "v1", **call(request, response, operators, "test", source_id, inv.test_source, source_id)}

    @router.post("/cert-sources/{source_id}/sync")
    def sync_source(source_id: str, request: Request, response: Response):
        """Read every certificate or key from the source into the inventory now."""
        return {"api_version": "v1", **call(request, response, operators, "sync", source_id, inv.sync_source, source_id)}

    @router.put("/cert-sources/{source_id}/schedule")
    def schedule(source_id: str, body: ScheduleBody, request: Request, response: Response):
        connection = call(request, response, admins, "schedule", source_id, inv.set_schedule, source_id, body.schedule_hours)
        return {"api_version": "v1", "connection": connection}

    @router.delete("/cert-sources/{source_id}")
    def remove(source_id: str, request: Request, response: Response):
        if not call(request, response, admins, "remove", source_id, inv.remove_source, source_id):
            raise HTTPException(status_code=404, detail="No such inventory connection on this organization.")
        return {"api_version": "v1", "removed": True}

    @router.get("/cert-inventory")
    def inventory(request: Request, response: Response, source_id: str = Query("", max_length=40),
                  risk: str = Query("", max_length=20), limit: int = Query(500, ge=1, le=5000)):
        items = call(request, response, readers, "inventory", source_id, inv.list_inventory, source_id, risk, limit)
        return {"api_version": "v1", "items": items, "count": len(items)}

    return router
