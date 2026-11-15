"""Quantum fire drill (/fire-drills/...). Logic in services/fire_drill.py.

Members (viewer, analyst, operator) see the drills and the schedule. Only an organization admin or
owner runs a drill or changes the schedule. A drill is always a dry run.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from db import current_organization_id
from services import fire_drill

RequireRole = Callable[..., Dict[str, Any]]

VIEW = ["viewer", "analyst", "operator", "admin", "owner"]
ADMIN = ["admin", "owner"]


class DrillRequest(BaseModel):
    broken: str = Field(fire_drill.DEFAULT_ALGORITHM, min_length=1, max_length=80)
    fallback: str = Field("", max_length=80)


class ScheduleRequest(BaseModel):
    cadence: str = Field(..., min_length=2, max_length=20)
    broken: str = Field(fire_drill.DEFAULT_ALGORITHM, min_length=1, max_length=80)
    fallback: str = Field("", max_length=80)


def _org(request: Request) -> str:
    return str(getattr(request.state, "org_id", "") or current_organization_id())


def create_fire_drill_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter(tags=["Quantum fire drill"])

    def guard(request: Request, roles: List[str], action: str, rid: str = "") -> Dict[str, Any]:
        return require_role(request, allowed_roles=roles, action=action, resource_type="fire_drill", resource_id=rid or _org(request))

    def run(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except fire_drill.DrillError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None

    @router.get("/fire-drills")
    def api_fire_drills(request: Request):
        actor = guard(request, VIEW, "fire_drill.list")
        out = fire_drill.overview(_org(request))
        out["can_run"] = str(actor.get("actor_role") or "").lower() in ADMIN
        return {"api_version": "v1", **out}

    @router.post("/fire-drills")
    def api_fire_drill_run(body: DrillRequest, request: Request):
        actor = guard(request, ADMIN, "fire_drill.run")
        return run(fire_drill.run_drill, _org(request), actor, body.broken, body.fallback, trigger="manual")

    @router.get("/fire-drills/schedule")
    def api_fire_drill_schedule(request: Request):
        guard(request, VIEW, "fire_drill.schedule.read")
        return fire_drill.get_schedule(_org(request))

    @router.put("/fire-drills/schedule")
    def api_fire_drill_schedule_set(body: ScheduleRequest, request: Request):
        actor = guard(request, ADMIN, "fire_drill.schedule.write")
        return run(fire_drill.set_schedule, _org(request), actor, body.cadence, body.broken, body.fallback)

    @router.get("/fire-drills/{drill_id}")
    def api_fire_drill_get(drill_id: str, request: Request):
        guard(request, VIEW, "fire_drill.get", drill_id)
        return run(fire_drill.get_drill, _org(request), drill_id)

    return router
