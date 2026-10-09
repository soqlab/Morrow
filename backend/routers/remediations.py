from typing import Any, Callable, Dict, Optional
import hashlib
import sys

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from db import (
    acknowledge_remediation_drift,
    append_audit_log,
    create_remediation,
    create_validation_job,
    current_organization_id,
    get_latest_validation_job_for_remediation,
    get_remediation,
    get_repository_by_id,
    get_repository_by_name,
    list_remediations,
    mark_remediation_merged,
    set_remediation_pr,
    update_remediation_status,
    update_validation_job,
)
from events import emit_platform_event
from idempotency import complete_idempotency_key
from remediation_drift import check_all_remediation_drift, check_remediation_drift
from remediation_validation import execute_validation_job
from integrations.github_app import diagnose_github_repo_access
from services.github_pr import (
    github_create_branch,
    github_create_pr,
    github_get_file,
    github_get_repo_metadata,
    github_put_file,
)
from services.pr_readiness import build_pr_readiness
from services.remediation_workflow import (
    build_remediation_branch_name,
    build_remediation_commit_message,
    build_remediation_pr_body,
    build_remediation_pr_title,
    guardrail_reason,
    pr_readiness,
    resolve_remediation_updated_content,
    split_owner_repo,
)


RequireRole = Callable[..., Dict[str, Any]]


class RemediationSuggestRequest(BaseModel):
    asset_key: str
    repository_id: int = 0
    repository: str = ""
    file_path: str
    vulnerability: str
    github_credential_id: int
    ref: str = ""


class RemediationDecisionRequest(BaseModel):
    note: str = ""


class RemediationCreatePRRequest(BaseModel):
    github_credential_id: int
    branch_prefix: str = "fix/pqc-remediation"
    base_branch: str = ""
    title: str = ""
    body: str = ""
    allow_unvalidated: bool = False


class RemediationValidateRequest(BaseModel):
    github_credential_id: int
    ref: str = ""
    validator_type: str = "auto"
    async_mode: bool = True
    timeout_seconds: int = 180


class RemediationMergedRequest(BaseModel):
    merged_at: str = ""


def _try_enqueue(task, *args) -> Optional[str]:
    """Publish a Celery task, returning its id, or None when the broker is unavailable.

    Callers must have a synchronous fallback. Without this, a .delay() from inside a request
    blocks on broker reconnection: /remediations/drift/check and /remediations/branches/cleanup
    never returned at all when Redis was down, each hung request holding a worker thread.
    tasks.py now bounds the retry window, and this turns the remaining failure into a decision
    the endpoint can act on rather than a 500.
    """
    try:
        res = task.delay(*args)
        return str(getattr(res, "id", "") or "")
    except Exception as exc:  # broker unreachable, publish rejected, serialization failure
        import logging
        logging.warning("[REMEDIATION] Celery dispatch unavailable (%s); running synchronously", exc)
        return None


class RemediationDriftCheckRequest(BaseModel):
    remediation_id: int = 0
    github_credential_id: int = 0
    async_mode: bool = True
    limit: int = 200


class RemediationBranchCleanupRequest(BaseModel):
    github_credential_id: int = 0
    async_mode: bool = True
    limit: int = 100


class RemediationSingleBranchCleanupRequest(BaseModel):
    github_credential_id: int = 0


class RemediationDriftAcknowledgeRequest(BaseModel):
    note: str = ""


class RemediationDriftRevalidateRequest(BaseModel):
    github_credential_id: int = 0
    async_mode: bool = True


def _app_attr(name: str) -> Any:
    app_module = sys.modules.get("app")
    if app_module is None or not hasattr(app_module, name):
        raise HTTPException(status_code=503, detail=f"{name} unavailable")
    return getattr(app_module, name)


def _app_callable(name: str, fallback: Any) -> Any:
    app_module = sys.modules.get("app")
    if app_module is not None and hasattr(app_module, name):
        return getattr(app_module, name)
    return fallback


def _default_org_id() -> str:
    app_module = sys.modules.get("app")
    return str(getattr(app_module, "DEFAULT_ORG_ID", "default-org") if app_module else "default-org")


def _model_payload(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model.dict()


def create_remediations_router(
    require_role: RequireRole,
    validate_remediation_task: Any,
    check_remediation_drift_task: Any,
    cleanup_remediation_branches_task: Any,
) -> APIRouter:
    router = APIRouter()

    @router.get("/remediations")
    def api_list_remediations(
        request: Request,
        status: str = Query("", max_length=32),
        repo_id: Optional[int] = Query(None, ge=1),
        asset_key_str: str = Query("", max_length=512),
        drift_status: str = Query("", max_length=32),
        parent_remediation_id: Optional[int] = Query(None, ge=1),
        origin_kind: str = Query("", max_length=64),
        limit: int = Query(200, ge=1, le=2000),
    ):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="remediation.list", resource_type="remediation", resource_id="*")
        return {
            "items": list_remediations(
                status=status,
                repo_id=repo_id,
                asset_key_str=asset_key_str,
                drift_status=drift_status,
                parent_remediation_id=parent_remediation_id,
                origin_kind=origin_kind,
                limit=limit,
            )
        }

    @router.get("/remediations/{remediation_id}")
    def api_get_remediation(remediation_id: int, request: Request):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="remediation.get", resource_type="remediation", resource_id=str(remediation_id))
        row = get_remediation(int(remediation_id))
        if not row:
            raise HTTPException(status_code=404, detail="remediation not found")
        return row

    @router.get("/remediations/{remediation_id}/pr-readiness")
    @router.get("/v1/remediations/{remediation_id}/pr-readiness")
    def api_remediation_pr_readiness(
        remediation_id: int,
        request: Request,
        github_credential_id: int = Query(0, ge=0),
        check_live_repo: bool = Query(False),
    ):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="remediation.pr_readiness", resource_type="remediation", resource_id=str(remediation_id))
        row = get_remediation(int(remediation_id))
        if not row:
            raise HTTPException(status_code=404, detail="remediation not found")
        repo_row = get_repository_by_id(int(row.get("repo_id") or 0)) if int(row.get("repo_id") or 0) else None
        latest_validation = get_latest_validation_job_for_remediation(int(remediation_id), passed_only=False)
        github_diag: Dict[str, Any] = {}
        repo_name = str((repo_row or {}).get("name") or row.get("repository_name") or "").strip()
        if bool(check_live_repo) and int(github_credential_id or 0) > 0 and repo_name:
            github_diag = _app_callable("diagnose_github_repo_access", diagnose_github_repo_access)(
                int(github_credential_id or 0),
                repo_name,
                check_repo_metadata=True,
            )
        return build_pr_readiness(
            row,
            repo_row,
            latest_validation,
            github_credential_id=int(github_credential_id or 0),
            github_diagnostics=github_diag,
        )

    @router.post("/remediations/suggest")
    def api_suggest_remediation(req: RemediationSuggestRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.suggest", resource_type="remediation", resource_id=req.asset_key)
        repo_row = None
        rid = int(req.repository_id or 0)
        if rid:
            repo_row = get_repository_by_id(rid)
        if not repo_row:
            name = (req.repository or "").strip()
            if name:
                repo_row = get_repository_by_name(name)
        if not repo_row:
            raise HTTPException(status_code=404, detail="repository not found; sync GitHub first")

        repo_name = str(repo_row.get("name") or "").strip()
        if "/" not in repo_name:
            raise HTTPException(status_code=400, detail="repository name must be owner/repo")
        owner, repo = split_owner_repo(repo_name)

        file_path = str(req.file_path or "").strip()
        vulnerability = str(req.vulnerability or "").strip()
        asset_key_in = str(req.asset_key or "").strip()
        if not file_path:
            raise HTTPException(status_code=400, detail="file_path is required")
        if not asset_key_in:
            raise HTTPException(status_code=400, detail="asset_key is required")
        if not vulnerability:
            raise HTTPException(status_code=400, detail="vulnerability is required")

        idem = _app_attr("_reserve_idempotency_or_raise")(request, action="remediation.suggest", payload=_model_payload(req))
        if idem.get("replay"):
            return idem.get("response") or {}

        precheck_reason = guardrail_reason("\n".join([vulnerability, file_path]))
        if precheck_reason:
            _app_attr("_audit_event")(request, action="remediation.suggest", resource_type="remediation", resource_id=asset_key_in, decision="deny", reason=precheck_reason, details={"file_path": file_path, "phase": "pre_llm"})
            raise HTTPException(status_code=400, detail=precheck_reason)

        token = _app_attr("_github_repo_token_or_502")(int(req.github_credential_id), repo_name)
        gh_file = _app_callable("_github_get_file", github_get_file)(owner, repo, file_path, str(req.ref or "").strip(), token)
        if not gh_file.get("ok"):
            raise HTTPException(status_code=502, detail={"error": "failed to fetch file from github", "github": gh_file})
        original = str(gh_file.get("content") or "")

        prompt = (
            "You are fixing infrastructure-as-code.\n"
            f"Asset: {asset_key_in}\n"
            f"Vulnerability: {vulnerability}\n\n"
            "Task:\n- Update the following file to remediate the vulnerability.\n- Prefer minimal changes.\n- Do not change unrelated formatting.\n\n"
            "Output rules (IMPORTANT):\n- Return ONLY one of the following:\n  1) A unified diff that applies to this file, OR\n  2) The full updated file contents.\n- No explanations.\n\n"
            f"File path: {file_path}\nFile contents:\n<file_contents>\n{original}\n</file_contents>\n"
        )
        llm = _app_attr("_openai_chat")(prompt)
        if not llm.get("ok"):
            raise HTTPException(status_code=502, detail={"error": "openai call failed", **llm})
        try:
            content = ((((llm.get("json") or {}).get("choices") or [])[0] or {}).get("message") or {}).get("content") or ""
        except Exception:
            content = ""
        patch = _app_attr("_extract_patch_from_llm")(content)
        try:
            mode = patch.get("mode")
            if mode == "diff":
                updated = _app_attr("_apply_unified_diff")(original, patch.get("diff") or "")
            elif mode == "content":
                updated = str(patch.get("content") or "")
            else:
                raise ValueError("model returned empty suggestion")
            updated = _app_attr("_strip_outer_file_wrapper")(updated)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"failed to apply suggestion: {e}")

        suggested_fix = _app_attr("_unified_diff")(original, updated, file_path)
        postcheck_reason = guardrail_reason("\n".join([suggested_fix, updated]))
        if postcheck_reason:
            _app_attr("_audit_event")(request, action="remediation.suggest", resource_type="remediation", resource_id=asset_key_in, decision="deny", reason=postcheck_reason, details={"file_path": file_path, "phase": "post_llm"})
            raise HTTPException(status_code=400, detail=postcheck_reason)

        remediation = create_remediation(
            asset_key_str=asset_key_in,
            repo_id=int(repo_row.get("id") or 0),
            file_path=file_path,
            vulnerability=vulnerability,
            suggested_fix=suggested_fix,
            original_content=original,
            suggested_content=updated,
            status="pending",
        )
        response = {"ok": True, "remediation": remediation}
        if idem.get("enabled"):
            complete_idempotency_key(key=str(idem.get("key") or ""), action="remediation.suggest", response=response)
        return response

    @router.post("/remediations/{remediation_id}/approve")
    def api_approve_remediation(remediation_id: int, req: RemediationDecisionRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.approve", resource_type="remediation", resource_id=str(remediation_id))
        if not get_remediation(int(remediation_id)):
            raise HTTPException(status_code=404, detail="remediation not found")
        return {"ok": True, "remediation": update_remediation_status(int(remediation_id), "approved", review_note=req.note)}

    @router.post("/remediations/{remediation_id}/reject")
    def api_reject_remediation(remediation_id: int, req: RemediationDecisionRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.reject", resource_type="remediation", resource_id=str(remediation_id))
        if not get_remediation(int(remediation_id)):
            raise HTTPException(status_code=404, detail="remediation not found")
        return {"ok": True, "remediation": update_remediation_status(int(remediation_id), "rejected", review_note=req.note)}

    @router.post("/remediations/{remediation_id}/validate")
    def api_validate_remediation(remediation_id: int, req: RemediationValidateRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.validate", resource_type="remediation", resource_id=str(remediation_id))
        if not get_remediation(int(remediation_id)):
            raise HTTPException(status_code=404, detail="remediation not found")
        idem = _app_attr("_reserve_idempotency_or_raise")(request, action="remediation.validate", payload={"remediation_id": int(remediation_id), **_model_payload(req)})
        if idem.get("replay"):
            return idem.get("response") or {}
        validation = create_validation_job(remediation_id=int(remediation_id), validator_type=str(req.validator_type or "auto").strip().lower() or "auto", git_ref=str(req.ref or "").strip(), status="queued", details={"timeout_seconds": int(req.timeout_seconds or 180)})
        org_id = getattr(request.state, "org_id", _default_org_id())
        task_id = _try_enqueue(validate_remediation_task, int(validation["id"]), int(remediation_id), int(req.github_credential_id), org_id, str(req.ref or "").strip(), str(req.validator_type or "auto").strip().lower() or "auto", int(req.timeout_seconds or 180)) if req.async_mode else None
        if task_id is not None:
            validation = update_validation_job(int(validation["id"]), job_id=task_id) or validation
        else:
            validation = _app_callable("execute_validation_job", execute_validation_job)(int(validation["id"]), int(remediation_id), int(req.github_credential_id), git_ref=str(req.ref or "").strip(), validator_type=str(req.validator_type or "auto").strip().lower() or "auto", timeout_seconds=int(req.timeout_seconds or 180))
        response = {"ok": True, "validation": validation}
        if idem.get("enabled"):
            complete_idempotency_key(key=str(idem.get("key") or ""), action="remediation.validate", response=response)
        return response

    @router.post("/remediations/{remediation_id}/create-pr")
    def api_create_remediation_pr(remediation_id: int, req: RemediationCreatePRRequest, request: Request):
        actor = require_role(request, allowed_roles=["operator", "admin"], action="remediation.create_pr", resource_type="remediation", resource_id=str(remediation_id))
        row = get_remediation(int(remediation_id))
        if not row:
            raise HTTPException(status_code=404, detail="remediation not found")
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        feature_guard = _app_attr("_require_org_feature")
        if callable(feature_guard):
            feature_guard(org_id, "github_pr_creation", "GitHub PR creation")
        latest_validation = get_latest_validation_job_for_remediation(int(remediation_id), passed_only=False)
        readiness = pr_readiness(row, latest_validation, allow_unvalidated=bool(req.allow_unvalidated), actor_role=str(actor.get("actor_role") or ""))
        if not readiness.get("ok"):
            raise HTTPException(status_code=int(readiness.get("status_code") or 400), detail=str(readiness.get("reason") or "remediation is not ready for PR creation"))
        repo_row = get_repository_by_id(int(row.get("repo_id") or 0)) if int(row.get("repo_id") or 0) else None
        if not repo_row:
            raise HTTPException(status_code=400, detail="repository not found for this remediation")
        repo_name = str(repo_row.get("name") or "").strip()
        if "/" not in repo_name:
            raise HTTPException(status_code=400, detail="repository name must be owner/repo")
        owner, repo = split_owner_repo(repo_name)
        idem = _app_attr("_reserve_idempotency_or_raise")(request, action="remediation.create_pr", payload={"remediation_id": int(remediation_id), "github_credential_id": int(req.github_credential_id or 0), "branch_prefix": req.branch_prefix, "base_branch": req.base_branch, "title": req.title, "body": req.body, "allow_unvalidated": req.allow_unvalidated})
        if idem.get("replay"):
            return idem.get("response") or {}
        token = _app_attr("_github_repo_token_or_502")(int(req.github_credential_id), repo_name)
        base = str(req.base_branch or "").strip()
        if not base:
            repo_meta = _app_callable("_github_get_repo_metadata", github_get_repo_metadata)(owner, repo, token)
            if not repo_meta.get("ok"):
                raise HTTPException(status_code=502, detail={"error": "failed to fetch repo metadata", "github": repo_meta})
            base = str((repo_meta.get("json") or {}).get("default_branch") or "main").strip() or "main"
        branch_prefix = (req.branch_prefix or "fix/pqc-remediation").strip().rstrip("/")
        branch = ""
        br: Dict[str, Any] = {}
        for _attempt in range(5):
            candidate = build_remediation_branch_name(branch_prefix, int(remediation_id))
            br = _app_callable("_github_create_branch", github_create_branch)(owner, repo, candidate, base, token, allow_existing=False)
            if br.get("ok"):
                branch = candidate
                break
            if int(br.get("http_status") or 0) != 422:
                raise HTTPException(status_code=502, detail={"error": "failed to create branch", "github": br})
        if not branch:
            raise HTTPException(status_code=502, detail={"error": "failed to create unique branch", "github": br})
        file_path = str(row.get("file_path") or "").strip()
        if not file_path:
            raise HTTPException(status_code=400, detail="remediation missing file_path")
        gh_file = _app_callable("_github_get_file", github_get_file)(owner, repo, file_path, base, token)
        if not gh_file.get("ok"):
            raise HTTPException(status_code=502, detail={"error": "failed to fetch file from github", "github": gh_file})
        original = str(gh_file.get("content") or "")
        sha = str(gh_file.get("sha") or "")
        try:
            updated_content = resolve_remediation_updated_content(row, latest_validation, original, lambda original_text, diff_text: _app_attr("_apply_unified_diff")(original_text, diff_text))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"failed to resolve remediation content: {e}")
        put = _app_callable("_github_put_file", github_put_file)(owner, repo, file_path, branch, build_remediation_commit_message(row), updated_content, sha, token)
        if not put.get("ok"):
            raise HTTPException(status_code=502, detail={"error": "failed to commit file update", "github": put})
        pr = _app_callable("_github_create_pr", github_create_pr)(owner, repo, build_remediation_pr_title(row, requested_title=str(req.title or "")), build_remediation_pr_body(row, file_path, int(remediation_id), requested_body=str(req.body or "")), head=f"{owner}:{branch}", base=base, token=token)
        if not pr.get("ok"):
            raise HTTPException(status_code=502, detail={"error": "failed to create PR", "github": pr})
        updated = set_remediation_pr(int(remediation_id), str((pr.get("json") or {}).get("html_url") or "").strip(), status="pr_created", branch=branch, base_branch=base, github_credential_id=int(req.github_credential_id or 0))
        response = {"ok": True, "remediation": updated, "pr": pr.get("json") or {}}
        if idem.get("enabled"):
            complete_idempotency_key(key=str(idem.get("key") or ""), action="remediation.create_pr", response=response)
        return response

    @router.post("/remediations/drift/check")
    def api_check_remediation_drift(req: RemediationDriftCheckRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.drift_check", resource_type="remediation", resource_id=str(int(req.remediation_id or 0) or "*"))
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        if req.async_mode:
            task_id = _try_enqueue(check_remediation_drift_task, int(req.limit or 200), int(req.github_credential_id or 0), org_id, int(req.remediation_id or 0))
            if task_id is not None:
                return {"ok": True, "queued": True, "task_id": task_id}
            # Broker unavailable — fall through to the synchronous path below.
        if int(req.remediation_id or 0) > 0:
            return {"ok": True, "result": check_remediation_drift(int(req.remediation_id), github_credential_id=int(req.github_credential_id or 0))}
        return {"ok": True, "result": check_all_remediation_drift(limit=int(req.limit or 200), github_credential_id=int(req.github_credential_id or 0))}

    @router.post("/remediations/branches/cleanup")
    def api_cleanup_remediation_branches(req: RemediationBranchCleanupRequest, request: Request):
        require_role(request, allowed_roles=["admin"], action="remediation.branch_cleanup", resource_type="remediation", resource_id="*")
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        if req.async_mode:
            task_id = _try_enqueue(cleanup_remediation_branches_task, int(req.limit or 100), int(req.github_credential_id or 0), org_id)
            if task_id is not None:
                return {"ok": True, "queued": True, "task_id": task_id}
            # Broker unavailable — fall through to the synchronous path below.
        from remediation_branch_cleanup import cleanup_verified_closed_branches
        return {"ok": True, "result": cleanup_verified_closed_branches(limit=int(req.limit or 100), github_credential_id=int(req.github_credential_id or 0))}

    @router.get("/remediations/branches/cleanup/status")
    def api_remediation_branch_cleanup_status(request: Request, status: str = Query("verified_closed", max_length=64), limit: int = Query(200, ge=1, le=1000)):
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="remediation.branch_cleanup_status", resource_type="remediation", resource_id="*")
        rows = list_remediations(status=str(status or "").strip(), limit=int(limit))
        items = []
        summary = {"total": 0, "pending": 0, "deleted": 0, "skipped": 0, "failed": 0}
        for row in rows:
            cleanup_status = str(row.get("branch_cleanup_status") or "").strip().lower()
            normalized = cleanup_status or "pending"
            if normalized not in summary:
                summary[normalized] = 0
            summary["total"] += 1
            summary[normalized] += 1
            items.append({"id": int(row.get("id") or 0), "status": row.get("status") or "", "asset_key": row.get("asset_key") or "", "repo_id": int(row.get("repo_id") or 0), "pr_url": row.get("pr_url") or "", "pr_branch": row.get("pr_branch") or "", "pr_base_branch": row.get("pr_base_branch") or "", "github_credential_id": int(row.get("github_credential_id") or 0), "branch_cleanup_status": cleanup_status, "branch_cleanup_at": row.get("branch_cleanup_at") or "", "branch_cleanup_error": row.get("branch_cleanup_error") or "", "branch_cleanup_attempts": int(row.get("branch_cleanup_attempts") or 0)})
        return {"ok": True, "summary": summary, "items": items}

    @router.post("/remediations/{remediation_id}/branch/cleanup")
    def api_cleanup_one_remediation_branch(remediation_id: int, req: RemediationSingleBranchCleanupRequest, request: Request):
        require_role(request, allowed_roles=["admin"], action="remediation.branch_cleanup_one", resource_type="remediation", resource_id=str(remediation_id))
        from remediation_branch_cleanup import cleanup_remediation_branch
        return {"ok": True, "result": cleanup_remediation_branch(int(remediation_id), github_credential_id=int(req.github_credential_id or 0))}

    @router.post("/remediations/{remediation_id}/drift/acknowledge")
    def api_acknowledge_remediation_drift(remediation_id: int, req: RemediationDriftAcknowledgeRequest, request: Request):
        actor = require_role(request, allowed_roles=["operator", "admin"], action="remediation.drift_acknowledge", resource_type="remediation", resource_id=str(remediation_id))
        row = get_remediation(int(remediation_id))
        if not row:
            raise HTTPException(status_code=404, detail="remediation not found")
        drift_status = str(row.get("drift_status") or "").strip().lower()
        if drift_status not in ("drifted", "check_failed"):
            raise HTTPException(status_code=400, detail="remediation has no active drift to acknowledge")
        updated = acknowledge_remediation_drift(int(remediation_id), actor_id=str(actor.get("actor_id") or ""), note=str(req.note or ""))
        append_audit_log(actor_id=str(actor.get("actor_id") or ""), actor_role=str(actor.get("actor_role") or ""), action="remediation.drift_acknowledged", resource_type="remediation", resource_id=str(remediation_id), decision="allow", reason=str(req.note or "").strip(), details={"drift_status": drift_status})
        try:
            emit_platform_event("remediation.drift_acknowledged", {"remediation_id": int(remediation_id), "asset_key": str((updated or row).get("asset_key") or "").strip(), "repository": str((updated or row).get("repository_name") or "").strip(), "file_path": str((updated or row).get("file_path") or "").strip(), "drift_status": drift_status, "actor_id": str(actor.get("actor_id") or "").strip(), "note": str(req.note or "").strip()}, dedupe_key=hashlib.sha256(f"remediation.drift_acknowledged:{int(remediation_id)}:{str(actor.get('actor_id') or '').strip()}:{str((updated or {}).get('updated_at') or '')}".encode("utf-8")).hexdigest())
        except Exception:
            pass
        return {"ok": True, "remediation": updated}

    @router.post("/remediations/{remediation_id}/drift/revalidate")
    def api_revalidate_remediation_drift(remediation_id: int, req: RemediationDriftRevalidateRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.drift_revalidate", resource_type="remediation", resource_id=str(remediation_id))
        if not get_remediation(int(remediation_id)):
            raise HTTPException(status_code=404, detail="remediation not found")
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        if req.async_mode:
            task_id = _try_enqueue(check_remediation_drift_task, 1, int(req.github_credential_id or 0), org_id, int(remediation_id))
            if task_id is not None:
                return {"ok": True, "queued": True, "task_id": task_id}
            # Broker unavailable — run it inline rather than hanging or failing.
        return {"ok": True, "result": check_remediation_drift(int(remediation_id), github_credential_id=int(req.github_credential_id or 0))}

    @router.post("/remediations/{remediation_id}/mark-merged")
    def api_mark_remediation_merged(remediation_id: int, req: RemediationMergedRequest, request: Request):
        require_role(request, allowed_roles=["operator", "admin"], action="remediation.mark_merged", resource_type="remediation", resource_id=str(remediation_id))
        if not get_remediation(int(remediation_id)):
            raise HTTPException(status_code=404, detail="remediation not found")
        updated = mark_remediation_merged(int(remediation_id), merged_at_iso=str(req.merged_at or "").strip())
        if updated:
            try:
                emit_platform_event("remediation.merged", {"remediation_id": int(updated.get("id") or remediation_id), "asset_key": str(updated.get("asset_key") or "").strip(), "repository": str(updated.get("repository_name") or "").strip(), "file_path": str(updated.get("file_path") or "").strip(), "pr_url": str(updated.get("pr_url") or "").strip(), "merged_at": str(updated.get("merged_at") or "").strip(), "status": str(updated.get("status") or "").strip().lower()}, dedupe_key=hashlib.sha256(f"remediation.merged:{int(updated.get('id') or remediation_id)}:{str(updated.get('merged_at') or '').strip()}".encode("utf-8")).hexdigest())
            except Exception:
                pass
        return {"ok": True, "remediation": updated}

    return router
