from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


def github_api(method: str, url: str, token: str, body: Optional[Dict[str, Any]] = None, timeout_s: int = 30) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            return {"ok": 200 <= int(resp.status) < 300, "http_status": int(resp.status), "json": parsed, "raw": raw[:2000]}
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        parsed = None
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = None
        return {"ok": False, "http_status": int(getattr(exc, "code", 0) or 0), "json": parsed, "raw": raw[:2000]}
    except Exception as exc:
        return {"ok": False, "http_status": 0, "json": None, "raw": str(exc)[:2000]}


def github_get_file(owner: str, repo: str, path: str, ref: str, token: str) -> Dict[str, Any]:
    q = f"ref={urllib.parse.quote(ref)}" if ref else ""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}"
    if q:
        url += "?" + q
    response = github_api("GET", url, token)
    if not response.get("ok"):
        return response
    payload = response.get("json") or {}
    content_b64 = payload.get("content") or ""
    sha = payload.get("sha") or ""
    try:
        raw = base64.b64decode(content_b64.encode("utf-8")).decode("utf-8", errors="replace") if content_b64 else ""
    except Exception:
        raw = ""
    return {"ok": True, "http_status": response.get("http_status"), "sha": sha, "content": raw, "json": payload}


def github_create_branch(
    owner: str,
    repo: str,
    new_branch: str,
    base_branch: str,
    token: str,
    *,
    allow_existing: bool = True,
) -> Dict[str, Any]:
    ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(base_branch)}"
    ref = github_api("GET", ref_url, token)
    if not ref.get("ok"):
        return {"ok": False, "step": "get_base_ref", **ref}
    sha = (((ref.get("json") or {}).get("object") or {}).get("sha") or "").strip()
    if not sha:
        return {"ok": False, "step": "get_base_ref", "error": "missing sha"}

    create_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
    body = {"ref": f"refs/heads/{new_branch}", "sha": sha}
    created = github_api("POST", create_url, token, body=body)
    if created.get("ok"):
        return {"ok": True, "sha": sha}
    if allow_existing and int(created.get("http_status") or 0) == 422:
        return {"ok": True, "sha": sha, "note": "branch already exists"}
    return {"ok": False, "step": "create_branch", **created}


def github_put_file(owner: str, repo: str, path: str, branch: str, message: str, content: str, sha: str, token: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}"
    body = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
        "branch": branch,
    }
    if sha:
        body["sha"] = sha
    return github_api("PUT", url, token, body=body)


def github_create_pr(owner: str, repo: str, title: str, body: str, head: str, base: str, token: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    payload = {"title": title, "body": body, "head": head, "base": base}
    return github_api("POST", url, token, body=payload)


def github_get_repo_metadata(owner: str, repo: str, token: str) -> Dict[str, Any]:
    return github_api("GET", f"https://api.github.com/repos/{owner}/{repo}", token)


def github_create_commit_status(
    owner: str,
    repo: str,
    sha: str,
    token: str,
    *,
    state: str,
    context: str,
    description: str,
    target_url: str = "",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "state": state,
        "context": context,
        "description": description[:140],
    }
    if target_url:
        payload["target_url"] = target_url
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{urllib.parse.quote(sha)}"
    return github_api("POST", url, token, body=payload)


def github_create_check_run(
    owner: str,
    repo: str,
    head_sha: str,
    token: str,
    *,
    name: str,
    conclusion: str,
    summary: str,
    text: str = "",
    details_url: str = "",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": name,
            "summary": summary[:65535],
        },
    }
    if text:
        payload["output"]["text"] = text[:65535]
    if details_url:
        payload["details_url"] = details_url
    url = f"https://api.github.com/repos/{owner}/{repo}/check-runs"
    return github_api("POST", url, token, body=payload)
