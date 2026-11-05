"""Read and change the organization's migration deadlines (services/migration_milestones).

GET is open to every seat that can read the velocity report. PUT and DELETE are for organization
administrators: the deadlines decide whether the report calls the programme on track, so changing
them is a settings change and is audited with the list before and after. The audit entry is
written before the change, so a deployment whose audit storage is down refuses the change
instead of making it unrecorded.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services import migration_milestones as store

RequireRole = Callable[..., Dict[str, Any]]

READ_ROLES = ["viewer", "analyst", "operator", "admin", "owner"]
ADMIN_ROLES = ["admin", "owner"]


class MilestoneIn(BaseModel):
    name: str = Field(..., max_length=store.MAX_NAME * 2)
    date: str = Field(..., max_length=32)
    scope: Optional[str] = Field(default="", max_length=store.MAX_SCOPE * 2)
    source: Optional[str] = Field(default="", max_length=store.MAX_SOURCE * 2)
    source_url: Optional[str] = Field(default="", max_length=store.MAX_URL * 2)
    id: Optional[str] = Field(default="", max_length=120)


class MilestonesBody(BaseModel):
    milestones: List[MilestoneIn] = Field(..., max_length=store.MAX_MILESTONES * 2)
    reason: Optional[str] = Field(default="", max_length=500)


def _http(exc: store.MilestoneError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def create_migration_milestones_router(
    require_role: RequireRole,
    audit_event: Callable[..., None],
    org_of: Callable[[Request], str],
) -> APIRouter:
    router = APIRouter()

    def _answer(org: str, actor_role: str) -> Dict[str, Any]:
        current = store.get(org)
        return {"api_version": "v1", "org_id": org, **current, "defaults": store.defaults(),
                "bounds": store.describe_bounds(),
                "can_edit": str(actor_role or "").lower() in ADMIN_ROLES}

    @router.get("/migration-velocity/milestones")
    @router.get("/v1/migration-velocity/milestones")
    def api_get_milestones(request: Request):
        org = org_of(request)
        actor = require_role(request, READ_ROLES, action="velocity.milestones.read",
                             resource_type="organization", resource_id=org)
        try:
            return _answer(org, actor.get("actor_role", ""))
        except store.MilestoneError as exc:
            raise _http(exc) from None

    @router.put("/migration-velocity/milestones")
    @router.put("/v1/migration-velocity/milestones")
    def api_put_milestones(body: MilestonesBody, request: Request):
        org = org_of(request)
        actor = require_role(request, ADMIN_ROLES, action="velocity.milestones.update",
                             resource_type="organization", resource_id=org)
        try:
            raw = [m.model_dump() if hasattr(m, "model_dump") else m.dict() for m in body.milestones]
            clean = store.validate(raw)
            before = store.get(org)
            audit_event(request, action="velocity.milestones.updated", resource_type="organization",
                        resource_id=org, reason=str(body.reason or "")[:500], required=True,
                        details={"before": before["milestones"], "before_source": before["source"],
                                 "after": clean})
            saved = store.save(org, clean, actor=actor.get("actor_id", ""))
        except store.MilestoneError as exc:
            raise _http(exc) from None
        return {**_answer(org, actor.get("actor_role", "")), "milestones": saved["milestones"]}

    @router.delete("/migration-velocity/milestones")
    @router.delete("/v1/migration-velocity/milestones")
    def api_reset_milestones(request: Request):
        org = org_of(request)
        actor = require_role(request, ADMIN_ROLES, action="velocity.milestones.reset",
                             resource_type="organization", resource_id=org)
        try:
            before = store.get(org)
            audit_event(request, action="velocity.milestones.reset", resource_type="organization",
                        resource_id=org, required=True,
                        details={"before": before["milestones"], "before_source": before["source"],
                                 "after": store.defaults()})
            store.reset(org)
        except store.MilestoneError as exc:
            raise _http(exc) from None
        return _answer(org, actor.get("actor_role", ""))

    return router
