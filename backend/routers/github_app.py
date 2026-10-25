"""API routes for GitHub App enterprise onboarding and diagnostics."""

from __future__ import annotations

import sys
from typing import Any, Callable, Dict

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from db import list_github_installations
from integrations.github_app import (
    diagnose_github_repo_access,
    github_app_credential_status,
    sync_github_app_installations,
    sync_github_app_repositories,
)
from services.github_pr import github_get_repo_metadata


RequireRole = Callable[..., Dict[str, str]]


class GithubAppInstallationsSyncRequest(BaseModel):
    credential_id: int
    async_mode: bool = True


class GithubAppRepoSyncRequest(BaseModel):
    credential_id: int
    installation_id: int
    async_mode: bool = True


class GithubAppRepoDiagnosticRequest(BaseModel):
    credential_id: int
    repository: str
    check_live_repo: bool = False


def create_github_app_router(require_role: RequireRole, celery_app: Any, default_org_id: str) -> APIRouter:
    router = APIRouter()

    def app_override(name: str, fallback):
        # Legacy tests monkeypatch symbols on app.py; keep that seam while routes live here.
        app_mod = sys.modules.get("app")
        return getattr(app_mod, name, fallback) if app_mod is not None else fallback

    @router.get("/integrations/github-app/installations")
    def api_list_github_app_installations(request: Request, limit: int = Query(200, ge=1, le=2000)):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="github_app.installations.list",
            resource_type="github_installation",
            resource_id="*",
        )
        return {"items": list_github_installations(limit=limit)}

    @router.get("/integrations/github-app/status")
    def api_github_app_status(request: Request, credential_id: int = Query(0, ge=0)):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="github_app.status",
            resource_type="github_app",
            resource_id=str(credential_id or "all"),
        )
        installations = list_github_installations(limit=2000)
        response: Dict[str, Any] = {
            "ok": True,
            "installations_count": len(installations),
            "installations": installations,
            "credential": None,
            "next_steps": [],
        }
        if int(credential_id or 0) > 0:
            status = app_override("github_app_credential_status", github_app_credential_status)(int(credential_id))
            response["credential"] = status
            if not status.get("ready"):
                response["ok"] = False
                response["next_steps"].append(status.get("next_step") or "Fix GitHub App credential configuration.")
        if not installations:
            response["next_steps"].append("Sync GitHub App installations or install the GitHub App on the target organization.")
        if not response["next_steps"]:
            response["next_steps"].append("Sync repositories for the relevant installation, then run repository diagnostics.")
        return response

    @router.post("/integrations/github-app/sync-installations")
    def api_sync_github_app_installations(req: GithubAppInstallationsSyncRequest, request: Request):
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="github_app.installations.sync",
            resource_type="github_app",
            resource_id=str(req.credential_id),
        )
        org_id = getattr(request.state, "org_id", default_org_id)
        if req.async_mode:
            task = celery_app.send_task(
                "morrow.sync_github_app_installations",
                args=[req.credential_id, org_id],
            )
            return {"async": True, "job_id": task.id}
        sync_func = app_override("sync_github_app_installations", sync_github_app_installations)
        return sync_func(credential_id=req.credential_id)

    @router.post("/integrations/github-app/sync-repositories")
    def api_sync_github_app_repositories(req: GithubAppRepoSyncRequest, request: Request):
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="github_app.repositories.sync",
            resource_type="github_installation",
            resource_id=str(req.installation_id),
        )
        org_id = getattr(request.state, "org_id", default_org_id)
        if req.async_mode:
            task = celery_app.send_task(
                "morrow.sync_github_app_repositories",
                args=[req.credential_id, req.installation_id, org_id],
            )
            return {"async": True, "job_id": task.id}
        sync_func = app_override("sync_github_app_repositories", sync_github_app_repositories)
        return sync_func(
            credential_id=req.credential_id,
            installation_id=req.installation_id,
        )

    @router.post("/integrations/github-app/repo-diagnostics")
    def api_github_app_repo_diagnostics(req: GithubAppRepoDiagnosticRequest, request: Request):
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="github_app.repo_diagnostics",
            resource_type="repository",
            resource_id=str(req.repository or ""),
        )
        checker = github_get_repo_metadata if bool(req.check_live_repo) else None
        diagnose_func = app_override("diagnose_github_repo_access", diagnose_github_repo_access)
        result = diagnose_func(
            int(req.credential_id or 0),
            str(req.repository or "").strip(),
            check_repo_metadata=checker,
        )
        result["check_live_repo"] = bool(req.check_live_repo)
        return result

    return router
