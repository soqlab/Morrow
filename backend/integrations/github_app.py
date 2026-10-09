from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from db import (
    get_github_installation,
    list_github_installations,
    upsert_github_installation,
    upsert_repository,
)
from vault_db import get_credential


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _github_api(
    method: str,
    url: str,
    token: str,
    body: Optional[Dict[str, Any]] = None,
    timeout_s: int = 30,
) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pqc-scanner-github-app",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, data=data, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {}
            return {"ok": True, "http_status": int(resp.status), "json": payload, "raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        return {"ok": False, "http_status": int(e.code), "json": payload, "raw": raw}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _build_app_jwt(app_id: str, private_key_pem: str, ttl_s: int = 540) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"iat": max(0, now - 60), "exp": now + int(ttl_s), "iss": str(app_id)}

    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"

    key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def _resolve_app_credential(credential_id: int) -> Dict[str, Any]:
    cred = get_credential(int(credential_id), reveal=True)
    if not cred:
        return {"ok": False, "error": "credential not found"}

    secret = str(cred.get("secret") or "").strip()
    if not secret:
        return {"ok": False, "error": "credential secret is empty"}

    meta = cred.get("meta_json") or {}
    app_id = str(meta.get("app_id") or meta.get("github_app_id") or "").strip()
    if not app_id:
        return {"ok": False, "error": "credential meta_json.app_id is required for GitHub App"}

    try:
        app_jwt = _build_app_jwt(app_id=app_id, private_key_pem=secret)
    except Exception as e:
        return {"ok": False, "error": f"failed to build GitHub App JWT: {e}"}

    return {"ok": True, "app_id": app_id, "app_jwt": app_jwt}


def _installation_access_token(app_jwt: str, installation_id: int) -> Dict[str, Any]:
    url = f"https://api.github.com/app/installations/{int(installation_id)}/access_tokens"
    r = _github_api("POST", url, app_jwt, body={})
    if not r.get("ok"):
        return r
    payload = r.get("json") or {}
    token = str(payload.get("token") or "").strip()
    if not token:
        return {"ok": False, "error": "GitHub App access token missing in response", "github": r}
    return {"ok": True, "token": token, "expires_at": payload.get("expires_at"), "github": r}


def _installation_for_repo(app_jwt: str, owner: str, repo: str) -> Dict[str, Any]:
    repo_path = f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
    repo_install = _github_api("GET", f"https://api.github.com/repos/{repo_path}/installation", app_jwt)
    if repo_install.get("ok"):
        payload = repo_install.get("json") or {}
        installation_id = int(payload.get("id") or 0)
        if installation_id > 0:
            account = payload.get("account") or {}
            upsert_github_installation(
                installation_id=installation_id,
                account_login=str(account.get("login") or owner),
                account_type=str(account.get("type") or ""),
                target_type=str(payload.get("target_type") or ""),
                permissions=(payload.get("permissions") or {}),
                repositories_count=int(payload.get("repository_selection") == "selected"),
                suspended_at=str(payload.get("suspended_at") or ""),
            )
            return {
                "ok": True,
                "installation_id": installation_id,
                "account_login": str(account.get("login") or owner),
                "github": repo_install,
            }

    owner_lc = str(owner or "").strip().lower()
    for row in list_github_installations(limit=2000):
        if str(row.get("account_login") or "").strip().lower() == owner_lc:
            try:
                return {
                    "ok": True,
                    "installation_id": int(row.get("installation_id") or 0),
                    "account_login": str(row.get("account_login") or owner),
                    "github": repo_install,
                    "source": "cached_installation",
                }
            except Exception:
                continue
    return {
        "ok": False,
        "error": f"no GitHub App installation found for repo owner '{owner}'",
        "github": repo_install,
    }


def resolve_github_repo_token(credential_id: int, repo_full_name: str) -> Dict[str, Any]:
    cred = get_credential(int(credential_id), reveal=True)
    if not cred:
        return {"ok": False, "error": "credential not found"}

    provider = str(cred.get("provider") or "").strip().lower() or "github"
    secret = str(cred.get("secret") or "").strip()
    if not secret:
        return {"ok": False, "error": "credential secret is empty"}

    if provider != "github_app":
        return {
            "ok": True,
            "token": secret,
            "credential_provider": provider,
            "credential_id": int(credential_id),
        }

    repo_name = str(repo_full_name or "").strip()
    if "/" not in repo_name:
        return {"ok": False, "error": "repository name must be owner/repo"}
    owner, repo = repo_name.split("/", 1)

    resolved = _resolve_app_credential(int(credential_id))
    if not resolved.get("ok"):
        return resolved

    installation = _installation_for_repo(str(resolved["app_jwt"]), owner, repo)
    if not installation.get("ok"):
        return installation

    installation_id = int(installation.get("installation_id") or 0)
    if installation_id < 1:
        return {"ok": False, "error": "resolved GitHub App installation_id is invalid"}

    tok = _installation_access_token(app_jwt=str(resolved["app_jwt"]), installation_id=installation_id)
    if not tok.get("ok"):
        return {
            "ok": False,
            "error": "failed to mint installation token",
            "installation_id": installation_id,
            "github": tok,
        }
    return {
        "ok": True,
        "token": str(tok.get("token") or ""),
        "expires_at": tok.get("expires_at"),
        "installation_id": installation_id,
        "credential_provider": "github_app",
        "credential_id": int(credential_id),
    }


def github_app_credential_status(credential_id: int) -> Dict[str, Any]:
    """Return safe setup status for a GitHub credential without exposing secrets."""
    cred = get_credential(int(credential_id), reveal=False)
    if not cred:
        return {
            "ok": False,
            "credential_id": int(credential_id),
            "ready": False,
            "provider": "",
            "missing": ["credential"],
            "next_step": "Create a GitHub App credential or GitHub token credential.",
        }
    provider = str(cred.get("provider") or "").strip().lower() or "github"
    meta = cred.get("meta_json") or {}
    missing = []
    if provider == "github_app":
        if not str(meta.get("app_id") or meta.get("github_app_id") or "").strip():
            missing.append("meta_json.app_id")
        if not str(meta.get("app_slug") or meta.get("slug") or "").strip():
            # Optional, but useful in UI diagnostics. Do not block readiness on it.
            pass
    ready = provider != "github_app" or not missing
    installations = list_github_installations(limit=2000) if provider == "github_app" else []
    return {
        "ok": ready,
        "credential_id": int(credential_id),
        "ready": ready,
        "provider": provider,
        "name": str(cred.get("name") or ""),
        "is_github_app": provider == "github_app",
        "app_id_configured": bool(str(meta.get("app_id") or meta.get("github_app_id") or "").strip()),
        "installations_count": len(installations),
        "installations": installations,
        "missing": missing,
        "next_step": "" if ready else "Add the missing GitHub App metadata and private key credential.",
    }


def diagnose_github_repo_access(
    credential_id: int,
    repo_full_name: str,
    *,
    check_repo_metadata=None,
) -> Dict[str, Any]:
    """Diagnose whether a credential can resolve repo-scoped GitHub access.

    The returned payload intentionally excludes the token.
    """
    repo_name = str(repo_full_name or "").strip()
    result: Dict[str, Any] = {
        "ok": False,
        "ready": False,
        "credential_id": int(credential_id),
        "repo": repo_name,
        "steps": [],
        "missing": [],
        "safe_to_attempt_pr": False,
    }
    if "/" not in repo_name:
        result["missing"].append("repository must be owner/repo")
        result["steps"].append({"name": "repo_format", "ok": False, "message": "repository must be owner/repo"})
        return result
    owner, repo = repo_name.split("/", 1)
    result["owner"] = owner
    result["repo_name"] = repo
    result["steps"].append({"name": "repo_format", "ok": True, "message": "repository name is valid"})

    credential = github_app_credential_status(int(credential_id))
    result["credential"] = {k: v for k, v in credential.items() if k != "installations"}
    result["steps"].append(
        {
            "name": "credential",
            "ok": bool(credential.get("ready")),
            "message": "credential is configured" if credential.get("ready") else str(credential.get("next_step") or "credential is not ready"),
        }
    )
    if not credential.get("ready"):
        result["missing"].extend(credential.get("missing") or ["credential"])
        return result

    resolved = resolve_github_repo_token(int(credential_id), repo_name)
    if not resolved.get("ok"):
        result["steps"].append(
            {
                "name": "repo_token",
                "ok": False,
                "message": str(resolved.get("error") or "failed to resolve repository token"),
                "http_status": int(((resolved.get("github") or {}).get("http_status") or 0) if isinstance(resolved.get("github"), dict) else 0),
            }
        )
        result["missing"].append("repo_scoped_token")
        return result

    provider = str(resolved.get("credential_provider") or credential.get("provider") or "").strip().lower()
    result["credential_provider"] = provider
    result["installation_id"] = int(resolved.get("installation_id") or 0)
    result["expires_at"] = resolved.get("expires_at") or ""
    result["steps"].append(
        {
            "name": "repo_token",
            "ok": True,
            "message": "repo-scoped token resolved" if provider == "github_app" else "GitHub token credential resolved",
            "installation_id": int(resolved.get("installation_id") or 0),
        }
    )

    if check_repo_metadata is not None:
        meta = check_repo_metadata(owner, repo, str(resolved.get("token") or ""))
        result["repository_metadata_check"] = {
            "ok": bool(meta.get("ok")),
            "http_status": int(meta.get("http_status") or 0),
        }
        result["steps"].append(
            {
                "name": "repo_metadata",
                "ok": bool(meta.get("ok")),
                "message": "repository metadata is reachable" if meta.get("ok") else "repository metadata is not reachable",
                "http_status": int(meta.get("http_status") or 0),
            }
        )
        if not meta.get("ok"):
            result["missing"].append("repository_api_access")
            return result

    result["ok"] = True
    result["ready"] = True
    result["safe_to_attempt_pr"] = True
    return result


def sync_github_app_installations(credential_id: int) -> Dict[str, Any]:
    resolved = _resolve_app_credential(credential_id)
    if not resolved.get("ok"):
        return resolved

    app_jwt = str(resolved["app_jwt"])
    page = _github_api("GET", "https://api.github.com/app/installations?per_page=100", app_jwt)
    if not page.get("ok"):
        return {"ok": False, "error": "failed to list GitHub App installations", "github": page}

    items = page.get("json") or []
    if not isinstance(items, list):
        items = []

    synced = 0
    for it in items:
        try:
            account = it.get("account") or {}
            iid = int(it.get("id") or 0)
            if iid < 1:
                continue
            upsert_github_installation(
                installation_id=iid,
                account_login=str(account.get("login") or ""),
                account_type=str(account.get("type") or ""),
                target_type=str(it.get("target_type") or ""),
                permissions=(it.get("permissions") or {}),
                repositories_count=int(it.get("repositories_count") or 0),
                suspended_at=str(it.get("suspended_at") or ""),
            )
            synced += 1
        except Exception:
            continue

    return {"ok": True, "synced": synced, "credential_id": int(credential_id), "app_id": resolved.get("app_id")}


def sync_github_app_repositories(credential_id: int, installation_id: int) -> Dict[str, Any]:
    resolved = _resolve_app_credential(credential_id)
    if not resolved.get("ok"):
        return resolved

    tok = _installation_access_token(app_jwt=str(resolved["app_jwt"]), installation_id=int(installation_id))
    if not tok.get("ok"):
        return {"ok": False, "error": "failed to mint installation token", "github": tok}

    inst_token = str(tok["token"])
    page = _github_api("GET", "https://api.github.com/installation/repositories?per_page=100", inst_token)
    if not page.get("ok"):
        return {"ok": False, "error": "failed to list installation repositories", "github": page}

    payload = page.get("json") or {}
    repos = payload.get("repositories") if isinstance(payload, dict) else []
    if not isinstance(repos, list):
        repos = []

    synced = 0
    for repo in repos:
        try:
            upsert_repository(name=str(repo.get("full_name") or ""), html_url=str(repo.get("html_url") or ""))
            synced += 1
        except Exception:
            continue

    existing = get_github_installation(int(installation_id)) or {}
    owner_login = ""
    owner_type = ""
    if repos:
        owner = repos[0].get("owner") or {}
        owner_login = str(owner.get("login") or "")
        owner_type = str(owner.get("type") or "")
    upsert_github_installation(
        installation_id=int(installation_id),
        account_login=str(existing.get("account_login") or owner_login),
        account_type=str(existing.get("account_type") or owner_type),
        target_type=str(existing.get("target_type") or ""),
        permissions=(existing.get("permissions") or {}),
        repositories_count=len(repos),
        suspended_at=str(existing.get("suspended_at") or ""),
    )

    return {
        "ok": True,
        "installation_id": int(installation_id),
        "synced": synced,
        "expires_at": tok.get("expires_at"),
        "credential_id": int(credential_id),
    }
