from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List

from db import (
    get_remediation,
    get_repository_by_id,
    list_remediations,
    update_remediation_branch_cleanup,
)
from integrations.github_app import _github_api, resolve_github_repo_token


_PROTECTED_BRANCHES = {"main", "master", "trunk", "develop"}


def cleanup_remediation_branch(remediation_id: int, github_credential_id: int = 0) -> Dict[str, Any]:
    """Delete a remediation branch after the remediation is verified closed."""
    remediation = get_remediation(int(remediation_id))
    if not remediation:
        return {"ok": False, "status": "skipped", "error": "remediation not found"}

    status = str(remediation.get("status") or "").strip().lower()
    if status != "verified_closed":
        return {"ok": True, "status": "skipped", "reason": f"status is {status or 'empty'}"}

    branch = str(remediation.get("pr_branch") or "").strip()
    base_branch = str(remediation.get("pr_base_branch") or "").strip()
    if not branch:
        update_remediation_branch_cleanup(int(remediation_id), "skipped", error="no branch recorded")
        return {"ok": True, "status": "skipped", "reason": "no branch recorded"}
    if branch == base_branch or branch in _PROTECTED_BRANCHES:
        update_remediation_branch_cleanup(int(remediation_id), "skipped", error="protected branch")
        return {"ok": True, "status": "skipped", "reason": "protected branch"}

    repo_id = int(remediation.get("repo_id") or 0)
    repo = get_repository_by_id(repo_id) if repo_id else None
    repo_name = str((repo or {}).get("name") or "").strip()
    if "/" not in repo_name:
        update_remediation_branch_cleanup(int(remediation_id), "failed", error="repository name is invalid")
        return {"ok": False, "status": "failed", "error": "repository name is invalid"}

    cred_id = int(github_credential_id or remediation.get("github_credential_id") or 0)
    if cred_id <= 0:
        update_remediation_branch_cleanup(int(remediation_id), "failed", error="github credential id missing")
        return {"ok": False, "status": "failed", "error": "github credential id missing"}

    token_result = resolve_github_repo_token(cred_id, repo_name)
    if not token_result.get("ok"):
        err = str(token_result.get("error") or "failed to resolve github token")
        update_remediation_branch_cleanup(int(remediation_id), "failed", error=err)
        return {"ok": False, "status": "failed", "error": err}

    owner, name = repo_name.split("/", 1)
    quoted_branch = urllib.parse.quote(branch, safe="/")
    url = f"https://api.github.com/repos/{owner}/{name}/git/refs/heads/{quoted_branch}"
    result = _github_api("DELETE", url, str(token_result.get("token") or ""))
    http_status = int(result.get("http_status") or 0)
    if result.get("ok") or http_status == 204:
        update_remediation_branch_cleanup(int(remediation_id), "deleted")
        return {"ok": True, "status": "deleted", "branch": branch}
    if http_status == 404:
        update_remediation_branch_cleanup(int(remediation_id), "skipped", error="branch already absent")
        return {"ok": True, "status": "skipped", "reason": "branch already absent", "branch": branch}

    err = str(result.get("raw") or result.get("error") or "github delete branch failed")[:2000]
    update_remediation_branch_cleanup(int(remediation_id), "failed", error=err)
    return {"ok": False, "status": "failed", "error": err, "github": result}


def cleanup_verified_closed_branches(limit: int = 100, github_credential_id: int = 0) -> Dict[str, Any]:
    items = list_remediations(status="verified_closed", limit=max(1, min(int(limit or 100), 1000)))
    results: List[Dict[str, Any]] = []
    for item in items:
        cleanup_status = str(item.get("branch_cleanup_status") or "").strip().lower()
        if cleanup_status in {"deleted", "skipped"}:
            continue
        results.append(cleanup_remediation_branch(int(item.get("id") or 0), github_credential_id=github_credential_id))
    return {
        "ok": True,
        "checked": len(items),
        "processed": len(results),
        "deleted": sum(1 for r in results if r.get("status") == "deleted"),
        "failed": sum(1 for r in results if r.get("status") == "failed"),
        "results": results,
    }
