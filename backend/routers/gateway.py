from __future__ import annotations

import time
from typing import Callable, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from db import current_organization_id
from services import gateway
from services.gateway_network import CheckError


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SiteRequest(StrictModel):
    website: str = Field(min_length=3, max_length=300)
    origin: str = Field(min_length=3, max_length=300)


class ExceptionRule(StrictModel):
    rule_id: int = Field(ge=900000, le=999999)
    path: str = Field(min_length=1, max_length=180, pattern=r"^/[A-Za-z0-9/_.-]*$")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
    expires_at: int
    reason: str = Field(min_length=8, max_length=160, pattern=r"^[\x20-\x7e]+$")

    @model_validator(mode="after")
    def narrow(self):
        if ".." in self.path or "//" in self.path or self.path.startswith("/__airlock"):
            raise ValueError("Use an exact application path")
        if self.rule_id in (949110, 959100, 980130):
            raise ValueError("Exclude the specific detection rule, not the aggregate blocking rule")
        if not time.time() < self.expires_at <= time.time() + 7 * 86400:
            raise ValueError("Exceptions must expire within seven days")
        return self


class PolicyRequest(StrictModel):
    expected_version: int = Field(ge=1)
    mode: Literal["observe", "enforce"]
    retention_hours: int = Field(default=24, ge=0, le=24)
    max_body_bytes: int = Field(default=1048576, ge=32768, le=8388608)
    exceptions: list[ExceptionRule] = Field(default_factory=list, max_length=20)
    reason: str = Field(min_length=8, max_length=200)


class RollbackRequest(StrictModel):
    expected_version: int = Field(ge=1)
    version: int = Field(ge=1)
    reason: str = Field(min_length=8, max_length=200)


class CheckCase(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    path: str = Field(default="/", max_length=180, pattern=r"^/[A-Za-z0-9/_.-]*$")
    expected_status: int = Field(default=200, ge=200, le=499)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value):
        if ".." in value or "//" in value or value.startswith("/__airlock"):
            raise ValueError("Use an application path without traversal or reserved routes")
        return value


class CompatibilityRequest(StrictModel):
    approved: bool = False
    cases: list[CheckCase] = Field(min_length=1, max_length=4)


class JourneyCheck(StrictModel):
    kind: Literal["login", "forms", "uploads", "websocket"]
    result: Literal["passed", "failed", "not_applicable"]
    evidence: str = Field(min_length=8, max_length=300)


class JourneyRequest(StrictModel):
    checks: list[JourneyCheck] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def unique(self):
        if len({c.kind for c in self.checks}) != 4:
            raise ValueError("Review each of the four application journeys once")
        return self


def create_gateway_router(require_role: Callable) -> APIRouter:
    router = APIRouter(prefix="/gateway", tags=["Website Gateway"])

    def invoke(request, response, action, fn, *args, write=False, admin=False):
        response.headers["Cache-Control"] = "no-store"
        roles = ["admin", "owner"] if admin else ["operator", "admin", "owner"] if write else ["viewer", "operator", "admin", "owner"]
        # The create argument is an unvalidated URL and may contain accidentally pasted credentials.
        resource_id = str(args[0]) if args and action != "create" else ""
        actor = require_role(request, allowed_roles=roles, action="gateway." + action, resource_type="gateway", resource_id=resource_id)
        org = str(getattr(request.state, "org_id", None) or current_organization_id())
        try:
            return fn(org, *args, **({"actor": actor.get("actor_id", "unknown")} if action in {"create", "policy", "rollback", "compatibility", "journeys"} else {}))
        except gateway.GatewayError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        except CheckError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/sites")
    def sites(request: Request, response: Response):
        return {"items": invoke(request, response, "list", gateway.list_sites)}

    @router.post("/sites", status_code=201)
    def create(body: SiteRequest, request: Request, response: Response):
        return invoke(request, response, "create", gateway.create_site, body.website, body.origin, write=True)

    @router.get("/sites/{site_id}")
    def detail(site_id: str, request: Request, response: Response):
        return invoke(request, response, "read", gateway.get_site, site_id)

    @router.post("/sites/{site_id}/ownership")
    def ownership(site_id: str, request: Request, response: Response):
        return invoke(request, response, "ownership", gateway.verify_ownership, site_id, write=True)

    @router.post("/sites/{site_id}/compatibility")
    def compatibility(site_id: str, body: CompatibilityRequest, request: Request, response: Response):
        return invoke(request, response, "compatibility", gateway.compatibility, site_id, [c.model_dump() for c in body.cases], body.approved, write=True)

    @router.post("/sites/{site_id}/journeys")
    def journeys(site_id: str, body: JourneyRequest, request: Request, response: Response):
        return invoke(request, response, "journeys", gateway.review_journeys, site_id, [c.model_dump() for c in body.checks], write=True)

    @router.get("/sites/{site_id}/history")
    def history(site_id: str, request: Request, response: Response):
        return {"items": invoke(request, response, "history", gateway.history, site_id)}

    @router.put("/sites/{site_id}/policy")
    def policy(site_id: str, body: PolicyRequest, request: Request, response: Response):
        def change(org, sid, actor):
            values = body.model_dump(exclude={"reason", "expected_version"})
            return gateway.change_policy(org, sid, values, actor, body.reason, body.expected_version)
        return invoke(request, response, "policy", change, site_id, admin=True)

    @router.post("/sites/{site_id}/rollback")
    def rollback(site_id: str, body: RollbackRequest, request: Request, response: Response):
        def change(org, sid, actor):
            return gateway.change_policy(org, sid, {}, actor, body.reason, body.expected_version, body.version)
        return invoke(request, response, "rollback", change, site_id, admin=True)

    @router.post("/sites/{site_id}/bootstrap")
    def bootstrap(site_id: str, request: Request, response: Response):
        return invoke(request, response, "bootstrap", gateway.bootstrap, site_id, admin=True)

    @router.post("/sites/{site_id}/probe")
    def probe(site_id: str, request: Request, response: Response):
        return invoke(request, response, "probe", gateway.probe, site_id, write=True)

    @router.post("/sites/{site_id}/apply")
    def apply(site_id: str, request: Request, response: Response):
        return invoke(request, response, "apply", lambda org, sid: gateway.probe(org, sid, apply=True), site_id, admin=True)

    @router.delete("/sites/{site_id}/statistics")
    def purge(site_id: str, request: Request, response: Response):
        return invoke(request, response, "purge", gateway.purge, site_id, admin=True)

    return router
