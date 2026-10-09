from __future__ import annotations

from typing import Any, Dict, Optional


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _validation_summary(validation: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not validation:
        return {"present": False, "status": "", "id": 0, "finished_at": ""}
    return {
        "present": True,
        "id": int(validation.get("id") or 0),
        "status": _clean(validation.get("status")).lower(),
        "validator_type": _clean(validation.get("validator_type")),
        "exit_code": int(validation.get("exit_code") or 0),
        "finished_at": _clean(validation.get("finished_at")),
    }


def build_pr_readiness(
    remediation: Dict[str, Any],
    repository: Optional[Dict[str, Any]],
    latest_validation: Optional[Dict[str, Any]],
    *,
    github_credential_id: int = 0,
    github_diagnostics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a machine-readable readiness checklist before a real GitHub PR."""
    row = remediation or {}
    repo = repository or {}
    status = _clean(row.get("status")).lower()
    repo_name = _clean(repo.get("name") or row.get("repository_name"))
    file_path = _clean(row.get("file_path"))
    validation = _validation_summary(latest_validation)
    validation_status = validation.get("status") or ""

    blockers = []
    warnings = []
    next_action = "inspect"
    phase = "blocked"

    if not row:
        blockers.append("remediation not found")
    if status not in {"approved", "validation_passed", "validated"}:
        if status in {"pending", "suggested", "pending_review", "candidate"}:
            next_action = "approve"
        elif status == "rejected":
            next_action = "reopen_or_resuggest"
        elif status == "pr_created":
            next_action = "track_pr"
            phase = "already_in_pr"
        elif status == "merged":
            next_action = "verify_close"
            phase = "already_merged"
        elif status == "verified_closed":
            next_action = "monitor_drift"
            phase = "closed"
        else:
            next_action = "inspect"
        if status not in {"pr_created", "merged", "verified_closed"}:
            blockers.append("remediation must be approved before PR creation")

    if not repo_name:
        blockers.append("linked repository is missing")
    elif "/" not in repo_name:
        blockers.append("linked repository must be in owner/repo format")
    if not file_path:
        blockers.append("target file_path is missing")
    if not _clean(row.get("suggested_content")) and not _clean(row.get("suggested_fix")):
        blockers.append("remediation has no suggested content or diff")
    if int(github_credential_id or 0) <= 0:
        blockers.append("github_credential_id is required")
    if validation_status != "passed":
        if status in {"approved", "validation_passed", "validated"}:
            next_action = "validate"
            phase = "needs_validation"
        blockers.append("latest validation must pass before PR creation")

    diag = github_diagnostics or {}
    if diag:
        if not bool(diag.get("ok")):
            blockers.append("GitHub repository access diagnostic failed")
        if diag.get("warnings"):
            warnings.extend([_clean(w) for w in diag.get("warnings") or [] if _clean(w)])

    if not blockers:
        phase = "ready"
        next_action = "create_pr"

    return {
        "ok": not blockers,
        "ready": not blockers,
        "phase": phase,
        "next_action": next_action,
        "blockers": blockers,
        "warnings": warnings,
        "remediation": {
            "id": int(row.get("id") or 0),
            "status": status,
            "asset_key": _clean(row.get("asset_key")),
            "file_path": file_path,
            "repository": repo_name,
            "pr_url": _clean(row.get("pr_url")),
        },
        "validation": validation,
        "github": {
            "credential_id": int(github_credential_id or 0),
            "repository": repo_name,
            "diagnostics": diag,
        },
        "calls": {
            "validate": f"/remediations/{int(row.get('id') or 0)}/validate",
            "create_pr": f"/remediations/{int(row.get('id') or 0)}/create-pr",
        },
    }
