from __future__ import annotations

from typing import Any, Dict, Optional

from db import upsert_repository
from vault_db import get_credential


def sync_github_repos(credential_id: int, org: Optional[str] = None, visibility: str = "all") -> Dict[str, Any]:
    try:
        from github import Github
    except Exception as e:
        return {"ok": False, "error": f"PyGithub missing: {e}"}

    cred = get_credential(int(credential_id), reveal=True)
    if not cred:
        return {"ok": False, "error": "credential not found"}

    token = cred.get("secret") or ""
    meta = cred.get("meta_json") or {}
    org_name = org or meta.get("org") or meta.get("organization") or meta.get("org_name")

    gh = Github(token)
    try:
        if org_name:
            repo_iter = gh.get_organization(org_name).get_repos(visibility=visibility)
        else:
            repo_iter = gh.get_user().get_repos(visibility=visibility)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    synced = 0
    for repo in repo_iter:
        try:
            upsert_repository(name=repo.full_name, html_url=repo.html_url)
            synced += 1
        except Exception as e:  # pragma: no cover - defensive
            return {"ok": False, "error": f"failed at {repo.full_name}: {e}", "synced": synced}

    return {"ok": True, "synced": synced, "organization": org_name or "(user)", "visibility": visibility}
