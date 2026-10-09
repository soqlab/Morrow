from __future__ import annotations

import os
from typing import Any, Callable, Dict

from fastapi import APIRouter, Query, Request, Response

from db import (
    list_assets,
    list_audit_logs,
    list_github_installations,
    list_github_pr_events,
    list_repositories,
    list_remediations,
    list_scan_rows,
    list_validation_jobs,
    list_webhook_events,
)
from services.e2e_readiness import build_e2e_readiness, compact_readiness_handoff, readiness_handoff_markdown


RequireRole = Callable[..., Dict[str, Any]]


def _auth_configured() -> bool:
    keys = (
        "AUTH0_DOMAIN",
        "AUTH0_CLIENT_ID",
        "AUTH0_AUDIENCE",
        "PQC_AUTH_DOMAIN",
        "PQC_AUTH_CLIENT_ID",
        "PQC_JWT_ISSUER",
        "PQC_JWT_AUDIENCE",
    )
    return any(str(os.getenv(k) or "").strip() for k in keys)


def create_readiness_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter()

    def _readiness(limit: int) -> Dict[str, Any]:
        return build_e2e_readiness(
            auth_configured=_auth_configured(),
            repositories=list_repositories(limit=int(limit)),
            github_installations=list_github_installations(limit=int(limit)),
            scans=list_scan_rows(limit=min(int(limit), 100)),
            assets=list_assets(limit=int(limit)),
            remediations=list_remediations(limit=int(limit)),
            validations=list_validation_jobs(limit=int(limit)),
            pr_events=list_github_pr_events(limit=100),
            audit_events=list_audit_logs(limit=100),
            webhook_events=list_webhook_events(limit=100),
        )

    @router.get("/readiness/e2e")
    @router.get("/v1/readiness/e2e")
    def api_e2e_readiness(
        request: Request,
        limit: int = Query(500, ge=1, le=2000),
    ):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="readiness.e2e",
            resource_type="organization",
            resource_id=str(getattr(request.state, "org_id", "*")),
        )
        return _readiness(int(limit))

    @router.get("/readiness/e2e/export")
    @router.get("/v1/readiness/e2e/export")
    def api_e2e_readiness_export(
        request: Request,
        format: str = Query("markdown", pattern="^(markdown|json)$"),
        limit: int = Query(500, ge=1, le=2000),
    ):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="readiness.e2e.export",
            resource_type="organization",
            resource_id=str(getattr(request.state, "org_id", "*")),
        )
        readiness = _readiness(int(limit))
        if str(format or "").lower() == "json":
            return compact_readiness_handoff(readiness)
        return Response(
            content=readiness_handoff_markdown(readiness),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'inline; filename="pqc-e2e-readiness-handoff.md"'},
        )

    return router
