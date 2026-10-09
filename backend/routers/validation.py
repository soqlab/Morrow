"""API routes for remediation validation and validation sandbox evidence."""

from __future__ import annotations

from typing import Callable, Dict

from fastapi import APIRouter, HTTPException, Query, Request

from db import get_remediation, get_validation_job, list_validation_jobs
from remediation_validation import validation_evidence_package, validation_sandbox_profile


RequireRole = Callable[..., Dict[str, str]]


def create_validation_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter()

    @router.get("/remediations/{remediation_id}/validations")
    def api_list_remediation_validations(
        remediation_id: int,
        request: Request,
        status: str = Query("", max_length=32),
        limit: int = Query(100, ge=1, le=1000),
    ):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="validation.list",
            resource_type="validation_job",
            resource_id=str(remediation_id),
        )
        row = get_remediation(int(remediation_id))
        if not row:
            raise HTTPException(status_code=404, detail="remediation not found")
        return {"items": list_validation_jobs(remediation_id=int(remediation_id), status=status, limit=limit)}

    @router.get("/validation-jobs/{validation_job_id}")
    def api_get_validation_job(validation_job_id: int, request: Request):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="validation.get",
            resource_type="validation_job",
            resource_id=str(validation_job_id),
        )
        row = get_validation_job(int(validation_job_id))
        if not row:
            raise HTTPException(status_code=404, detail="validation job not found")
        return row

    @router.get("/validation/sandbox-profile")
    def api_validation_sandbox_profile(request: Request):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="validation.sandbox_profile",
            resource_type="validation",
            resource_id="sandbox",
        )
        return validation_sandbox_profile()

    @router.get("/validation-jobs/{validation_job_id}/evidence")
    def api_get_validation_job_evidence(validation_job_id: int, request: Request):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="validation.evidence",
            resource_type="validation_job",
            resource_id=str(validation_job_id),
        )
        row = get_validation_job(int(validation_job_id))
        if not row:
            raise HTTPException(status_code=404, detail="validation job not found")
        return validation_evidence_package(row)

    return router
