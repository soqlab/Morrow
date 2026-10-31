"""Code-host connections: open a pull request (or merge request) wherever an organization keeps its code.

An organization connects the hosts it uses with an access token it creates itself, so nothing has
to be registered by the operator first and every host works the same way:

  github        GitHub.com or GitHub Enterprise Server       pull request
  gitlab        GitLab.com or self-managed GitLab            merge request
  bitbucket     Bitbucket Cloud                              pull request
  azure_devops  Azure DevOps (Azure Repos)                   pull request
  gitea         Gitea, Forgejo, Codeberg                     pull request

open_change_request() is the one call the rest of the platform makes: given a connection, a
repository, the files to write and a title, it creates a branch from the base, commits the files to
it and opens the request, returning its URL. Every provider does the same three steps through its
own API.

Tokens are encrypted with the platform vault key (vault_crypto) and never returned by any route. A
self-hosted base URL must be HTTPS on a public address, so a connection cannot be used to reach
the platform's own network. Each connection belongs to one organization (org_id) and is only
read through that organization.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from db_feature_store import atomic, feature_conn

TIMEOUT_S = 20
MAX_FILES = 50
MAX_FILE_BYTES = 512 * 1024

SCHEMA = """
    CREATE TABLE IF NOT EXISTS org_code_connections (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        base_url TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        account TEXT NOT NULL DEFAULT '',
        token_enc TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_used_at TEXT
    )
"""

# What the console shows when someone picks a host: where to make the token and what it needs.
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "github": {
        "name": "GitHub",
        "request_name": "pull request",
        "default_base_url": "https://github.com",
        "self_hosted": True,
        "repo_format": "owner/repository",
        "token_url": "https://github.com/settings/personal-access-tokens/new",
        "token_steps": [
            "Open the link and create a fine-grained personal access token.",
            "Under Repository access, choose the repositories Morrow may open pull requests on.",
            "Under Permissions, set Contents and Pull requests to Read and write.",
            "Create the token and paste it here.",
        ],
    },
    "gitlab": {
        "name": "GitLab",
        "request_name": "merge request",
        "default_base_url": "https://gitlab.com",
        "self_hosted": True,
        "repo_format": "group/project",
        "token_url": "{base}/-/user_settings/personal_access_tokens?name=Morrow&scopes=api",
        "token_steps": [
            "Open the link (it pre-fills the name and the api scope).",
            "Set an expiry date and create the token.",
            "Paste it here. A project or group access token with the api scope and Developer role works too.",
        ],
    },
    "bitbucket": {
        "name": "Bitbucket",
        "request_name": "pull request",
        "default_base_url": "https://bitbucket.org",
        "self_hosted": False,
        "repo_format": "workspace/repository",
        "token_url": "https://support.atlassian.com/bitbucket-cloud/docs/create-a-repository-access-token/",
        "token_steps": [
            "In the repository, open Repository settings > Access tokens > Create access token.",
            "Give it the Repositories: Write and Pull requests: Write scopes.",
            "Paste the token here. (An Atlassian API token works too: paste it as email:token.)",
        ],
    },
    "azure_devops": {
        "name": "Azure DevOps",
        "request_name": "pull request",
        "default_base_url": "",
        "self_hosted": False,
        "base_url_hint": "https://dev.azure.com/your-organization",
        "repo_format": "project/repository",
        "token_url": "{base}/_usersSettings/tokens",
        "token_steps": [
            "Enter your organization URL above, then open the link.",
            "Create a new token with the Code: Read & write scope.",
            "Paste it here.",
        ],
    },
    "gitea": {
        "name": "Gitea / Forgejo",
        "request_name": "pull request",
        "default_base_url": "https://codeberg.org",
        "self_hosted": True,
        "repo_format": "owner/repository",
        "token_url": "{base}/user/settings/applications",
        "token_steps": [
            "Open the link and generate a new token.",
            "Give it read and write access to repository, and read access to user.",
            "Paste it here.",
        ],
    },
}

_ready = False
_ready_lock = threading.Lock()


class CodeHostError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _init() -> None:
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with feature_conn() as conn:
            conn.execute(SCHEMA)
            conn.commit()
        _ready = True


# ── Input checks ────────────────────────────────────────────────────────────────────────────────

def provider_info(provider: str) -> Dict[str, Any]:
    info = PROVIDERS.get(str(provider or "").strip().lower())
    if not info:
        raise CodeHostError(400, f"Choose one of: {', '.join(p['name'] for p in PROVIDERS.values())}.")
    return info


def normalize_base_url(provider: str, value: Any) -> str:
    info = provider_info(provider)
    text = str(value or "").strip().rstrip("/") or info["default_base_url"]
    if not text:
        raise CodeHostError(400, f"Enter your {info['name']} URL, like {info.get('base_url_hint', 'https://...')}.")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise CodeHostError(400, "Use the https:// address of your server, without a query or credentials.")
    if parts.port not in (None, 443):
        raise CodeHostError(400, "Only HTTPS on the standard port is supported.")
    path = parts.path.rstrip("/")
    if provider == "azure_devops":
        if parts.hostname not in ("dev.azure.com",) and not parts.hostname.endswith(".visualstudio.com"):
            raise CodeHostError(400, "Use your Azure DevOps organization URL, like https://dev.azure.com/your-organization.")
        if parts.hostname == "dev.azure.com" and not re.fullmatch(r"/[A-Za-z0-9][A-Za-z0-9._-]{0,99}", path or ""):
            raise CodeHostError(400, "Include your organization: https://dev.azure.com/your-organization.")
    elif path and provider != "gitlab" and provider != "gitea":
        raise CodeHostError(400, "Enter the server address only, without a path.")
    host = parts.hostname.lower()
    if host != urllib.parse.urlsplit(info["default_base_url"] or "https://x").hostname:
        _require_public_host(host)
    return f"https://{host}{path}"


_KNOWN_SAAS = {"github.com", "api.github.com", "gitlab.com", "bitbucket.org", "api.bitbucket.org",
               "dev.azure.com", "codeberg.org"}


def _require_public_host(host: str) -> None:
    """A self-hosted server must resolve only to public addresses (no reaching internal networks)."""
    if host in _KNOWN_SAAS or host.endswith(".visualstudio.com"):
        return
    from services import gateway_network

    try:
        gateway_network.public_ips(gateway_network.hostname(host))
    except gateway_network.CheckError as exc:
        raise CodeHostError(400, f"{host}: {exc}. The server must be reachable on the public internet.") from None


def normalize_repo(provider: str, value: Any) -> str:
    text = str(value or "").strip().strip("/")
    text = re.sub(r"\.git$", "", text)
    text = re.sub(r"^https?://[^/]+/", "", text)                 # a pasted repository URL
    if provider == "azure_devops":
        text = text.replace("/_git/", "/")
    text = re.sub(r"/-/.*$", "", text)                           # GitLab UI suffixes
    parts = [p for p in text.split("/") if p]
    pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$")
    if len(parts) < 2 or (provider != "gitlab" and len(parts) != 2) or not all(pattern.match(p) for p in parts):
        raise CodeHostError(400, f"Enter the repository as {provider_info(provider)['repo_format']}.")
    return "/".join(parts)


def _safe_path(path: Any) -> str:
    text = str(path or "").strip().lstrip("/")
    if not text or ".." in text.split("/") or "\\" in text or len(text) > 400 or text.startswith(".git/"):
        raise CodeHostError(400, f"Invalid file path: {str(path)[:80]}")
    return text


def _branch_name(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(title or "update").lower()).strip("-")[:40] or "update"
    return f"morrow/{slug}-{secrets.token_hex(3)}"


# ── HTTP ────────────────────────────────────────────────────────────────────────────────────────

def _http(method: str, url: str, headers: Dict[str, str], body: Any = None, form: Optional[Dict[str, str]] = None,
          allow: Tuple[int, ...] = (), raw: bool = False) -> Tuple[int, Any]:
    data = None
    headers = {"Accept": "application/json", "User-Agent": "Morrow", **headers}
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    want_text = raw
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body_bytes = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read() or b""
        status = exc.code
    except (urllib.error.URLError, OSError) as exc:
        raise CodeHostError(502, f"Could not reach the code host ({exc.__class__.__name__}).") from None
    if want_text and status < 400:
        return status, body_bytes.decode("utf-8", "replace")
    try:
        payload = json.loads(body_bytes) if body_bytes else {}
    except ValueError:
        payload = {"raw": body_bytes[:300].decode("utf-8", "replace")}
    if status >= 400 and status not in allow:
        raise _http_error(status, payload)
    return status, payload


def _http_error(status: int, payload: Any) -> CodeHostError:
    message = ""
    if isinstance(payload, dict):
        message = str(payload.get("message") or payload.get("error_description") or payload.get("error") or "")
        if isinstance(payload.get("error"), dict):
            message = str(payload["error"].get("message") or "")
    message = re.sub(r"\s+", " ", message)[:240]
    if status in (401, 403):
        return CodeHostError(400, "The code host refused the token. Check it hasn't expired and has the "
                                  "permissions listed for this host." + (f" ({message})" if message else ""))
    if status == 404:
        return CodeHostError(400, "Repository or branch not found, or the token can't see it." + (f" ({message})" if message else ""))
    return CodeHostError(502, f"The code host answered {status}." + (f" {message}" if message else ""))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


# ── Providers ───────────────────────────────────────────────────────────────────────────────────
# Each provider: identity(conn) -> account name, and open(conn, repo, base, branch, files, title, body)
# -> {"url", "number", "branch", "base"}. conn carries base_url and token.

def _gh_api(conn: Dict[str, str]) -> str:
    return "https://api.github.com" if conn["base_url"] == "https://github.com" else conn["base_url"] + "/api/v3"


def _gh_headers(conn):
    return {"Authorization": f"Bearer {conn['token']}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def _github_identity(conn):
    return str(_http("GET", _gh_api(conn) + "/user", _gh_headers(conn))[1].get("login") or "")


def _github_open(conn, repo, base, branch, files, title, body):
    api, h = _gh_api(conn), _gh_headers(conn)
    r = f"{api}/repos/{repo}"
    base = base or _http("GET", r, h)[1].get("default_branch") or "main"
    sha = _http("GET", f"{r}/git/ref/heads/{_q(base)}", h)[1]["object"]["sha"]
    _http("POST", f"{r}/git/refs", h, {"ref": f"refs/heads/{branch}", "sha": sha})
    for path, content in files.items():
        status, existing = _http("GET", f"{r}/contents/{urllib.parse.quote(path)}?ref={_q(branch)}", h, allow=(404,))
        payload = {"message": title, "content": _b64(content), "branch": branch}
        if status == 200 and isinstance(existing, dict) and existing.get("sha"):
            payload["sha"] = existing["sha"]
        _http("PUT", f"{r}/contents/{urllib.parse.quote(path)}", h, payload)
    pr = _http("POST", f"{r}/pulls", h, {"title": title, "head": branch, "base": base, "body": body})[1]
    return {"url": pr.get("html_url", ""), "number": pr.get("number"), "branch": branch, "base": base}


def _gl_headers(conn):
    return {"PRIVATE-TOKEN": conn["token"]}


def _gitlab_identity(conn):
    return str(_http("GET", conn["base_url"] + "/api/v4/user", _gl_headers(conn))[1].get("username") or "")


def _gitlab_open(conn, repo, base, branch, files, title, body):
    h = _gl_headers(conn)
    p = f"{conn['base_url']}/api/v4/projects/{_q(repo)}"
    base = base or _http("GET", p, h)[1].get("default_branch") or "main"
    actions = []
    for path, content in files.items():
        status, _ = _http("GET", f"{p}/repository/files/{_q(path)}?ref={_q(base)}", h, allow=(404,))
        actions.append({"action": "update" if status == 200 else "create", "file_path": path, "content": content})
    _http("POST", f"{p}/repository/commits", h,
          {"branch": branch, "start_branch": base, "commit_message": title, "actions": actions})
    mr = _http("POST", f"{p}/merge_requests", h, {"source_branch": branch, "target_branch": base, "title": title,
                                                    "description": body, "remove_source_branch": True})[1]
    return {"url": mr.get("web_url", ""), "number": mr.get("iid"), "branch": branch, "base": base}


def _bb_headers(conn):
    token = conn["token"]
    if ":" in token:  # an Atlassian API token, pasted as email:token
        return {"Authorization": "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")}
    return {"Authorization": f"Bearer {token}"}


def _bitbucket_identity(conn):
    status, me = _http("GET", "https://api.bitbucket.org/2.0/user", _bb_headers(conn), allow=(401, 403))
    if status == 200:
        return str(me.get("username") or me.get("display_name") or "")
    # A repository access token cannot read /user; it is checked against the repository on first use.
    if ":" in conn["token"]:
        raise _http_error(status, me)
    return "repository access token"


def _bitbucket_open(conn, repo, base, branch, files, title, body):
    h = _bb_headers(conn)
    r = f"https://api.bitbucket.org/2.0/repositories/{repo}"
    base = base or ((_http("GET", r, h)[1].get("mainbranch") or {}).get("name")) or "main"
    parent = _http("GET", f"{r}/refs/branches/{_q(base)}", h)[1]["target"]["hash"]
    form = {"message": title, "branch": branch, "parents": parent}
    form.update({"/" + path: content for path, content in files.items()})
    _http("POST", f"{r}/src", h, form=form)
    pr = _http("POST", f"{r}/pullrequests", h, {
        "title": title, "description": body, "close_source_branch": True,
        "source": {"branch": {"name": branch}}, "destination": {"branch": {"name": base}}})[1]
    return {"url": ((pr.get("links") or {}).get("html") or {}).get("href", ""), "number": pr.get("id"),
            "branch": branch, "base": base}


def _ado_headers(conn):
    return {"Authorization": "Basic " + base64.b64encode((":" + conn["token"]).encode("utf-8")).decode("ascii")}


def _azure_devops_identity(conn):
    data = _http("GET", conn["base_url"] + "/_apis/connectionData?api-version=7.1-preview", _ado_headers(conn))[1]
    user = data.get("authenticatedUser") or {}
    return str(user.get("providerDisplayName") or user.get("customDisplayName") or "")


def _azure_devops_open(conn, repo, base, branch, files, title, body):
    h = _ado_headers(conn)
    project, name = repo.split("/", 1)
    r = f"{conn['base_url']}/{_q(project)}/_apis/git/repositories/{_q(name)}"
    v = "api-version=7.1"
    info = _http("GET", f"{r}?{v}", h)[1]
    base = base or str(info.get("defaultBranch") or "refs/heads/main").replace("refs/heads/", "")
    refs = _http("GET", f"{r}/refs?filter={_q('heads/' + base)}&{v}", h)[1].get("value") or []
    head = next((x["objectId"] for x in refs if x.get("name") == f"refs/heads/{base}"), None)
    if not head:
        raise CodeHostError(400, f"Branch {base} not found in {repo}.")
    changes = []
    for path, content in files.items():
        status, _ = _http("GET", f"{r}/items?path={_q('/' + path)}&versionDescriptor.version={_q(base)}&{v}", h, allow=(404,))
        changes.append({"changeType": "edit" if status == 200 else "add", "item": {"path": "/" + path},
                        "newContent": {"content": content, "contentType": "rawtext"}})
    _http("POST", f"{r}/pushes?{v}", h, {"refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": "0" * 40}],
                                        "commits": [{"comment": title, "parents": [head], "changes": changes}]})
    pr = _http("POST", f"{r}/pullrequests?{v}", h, {"sourceRefName": f"refs/heads/{branch}",
                                                   "targetRefName": f"refs/heads/{base}", "title": title,
                                                   "description": body[:4000]})[1]
    number = pr.get("pullRequestId")
    return {"url": f"{conn['base_url']}/{_q(project)}/_git/{_q(name)}/pullrequest/{number}", "number": number,
            "branch": branch, "base": base}


def _gt_headers(conn):
    return {"Authorization": f"token {conn['token']}"}


def _gitea_identity(conn):
    return str(_http("GET", conn["base_url"] + "/api/v1/user", _gt_headers(conn))[1].get("login") or "")


def _gitea_open(conn, repo, base, branch, files, title, body):
    h = _gt_headers(conn)
    r = f"{conn['base_url']}/api/v1/repos/{repo}"
    base = base or _http("GET", r, h)[1].get("default_branch") or "main"
    changes = []
    for path, content in files.items():
        status, existing = _http("GET", f"{r}/contents/{urllib.parse.quote(path)}?ref={_q(base)}", h, allow=(404,))
        change = {"operation": "update" if status == 200 else "create", "path": path, "content": _b64(content)}
        if status == 200 and isinstance(existing, dict) and existing.get("sha"):
            change["sha"] = existing["sha"]
        changes.append(change)
    _http("POST", f"{r}/contents", h, {"branch": base, "new_branch": branch, "message": title, "files": changes})
    pr = _http("POST", f"{r}/pulls", h, {"head": branch, "base": base, "title": title, "body": body})[1]
    return {"url": pr.get("html_url", ""), "number": pr.get("number"), "branch": branch, "base": base}


# Reading one file: (provider) -> fn(conn, repo, path, ref) -> (default_or_given_ref, text or None when absent).

def _github_read(conn, repo, path, ref):
    api, h = _gh_api(conn), _gh_headers(conn)
    ref = ref or _http("GET", f"{api}/repos/{repo}", h)[1].get("default_branch") or "main"
    status, data = _http("GET", f"{api}/repos/{repo}/contents/{urllib.parse.quote(path)}?ref={_q(ref)}", h, allow=(404,))
    return ref, (_unb64(data.get("content")) if status == 200 else None)


def _gitlab_read(conn, repo, path, ref):
    h = _gl_headers(conn)
    p = f"{conn['base_url']}/api/v4/projects/{_q(repo)}"
    ref = ref or _http("GET", p, h)[1].get("default_branch") or "main"
    status, data = _http("GET", f"{p}/repository/files/{_q(path)}?ref={_q(ref)}", h, allow=(404,))
    return ref, (_unb64(data.get("content")) if status == 200 else None)


def _bitbucket_read(conn, repo, path, ref):
    h = _bb_headers(conn)
    r = f"https://api.bitbucket.org/2.0/repositories/{repo}"
    ref = ref or ((_http("GET", r, h)[1].get("mainbranch") or {}).get("name")) or "main"
    status, data = _http("GET", f"{r}/src/{_q(ref)}/{urllib.parse.quote(path)}", h, allow=(404,), raw=True)
    return ref, (data if status == 200 else None)


def _azure_devops_read(conn, repo, path, ref):
    h = _ado_headers(conn)
    project, name = repo.split("/", 1)
    r = f"{conn['base_url']}/{_q(project)}/_apis/git/repositories/{_q(name)}"
    ref = ref or str(_http("GET", f"{r}?api-version=7.1", h)[1].get("defaultBranch") or "refs/heads/main").replace("refs/heads/", "")
    status, data = _http("GET", f"{r}/items?path={_q('/' + path)}&versionDescriptor.version={_q(ref)}"
                                f"&includeContent=true&$format=json&api-version=7.1", h, allow=(404,))
    return ref, (str(data.get("content") or "") if status == 200 else None)


def _gitea_read(conn, repo, path, ref):
    h = _gt_headers(conn)
    r = f"{conn['base_url']}/api/v1/repos/{repo}"
    ref = ref or _http("GET", r, h)[1].get("default_branch") or "main"
    status, data = _http("GET", f"{r}/contents/{urllib.parse.quote(path)}?ref={_q(ref)}", h, allow=(404,))
    return ref, (_unb64(data.get("content")) if status == 200 else None)


def _unb64(value: Any) -> str:
    return base64.b64decode(str(value or "").encode("ascii")).decode("utf-8", "replace")


_READ: Dict[str, Callable] = {
    "github": _github_read, "gitlab": _gitlab_read, "bitbucket": _bitbucket_read,
    "azure_devops": _azure_devops_read, "gitea": _gitea_read,
}


_IMPL: Dict[str, Tuple[Callable, Callable]] = {
    "github": (_github_identity, _github_open),
    "gitlab": (_gitlab_identity, _gitlab_open),
    "bitbucket": (_bitbucket_identity, _bitbucket_open),
    "azure_devops": (_azure_devops_identity, _azure_devops_open),
    "gitea": (_gitea_identity, _gitea_open),
}


# ── Connections ─────────────────────────────────────────────────────────────────────────────────

def _public(row: Any) -> Dict[str, Any]:
    info = PROVIDERS.get(row["provider"], {})
    return {"id": row["id"], "provider": row["provider"], "provider_name": info.get("name", row["provider"]),
            "request_name": info.get("request_name", "pull request"), "base_url": row["base_url"],
            "label": row["label"], "account": row["account"], "is_default": bool(row["is_default"]),
            "created_at": row["created_at"], "last_used_at": row["last_used_at"]}


def list_connections(org_id: str) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT id, provider, base_url, label, account, is_default, created_at, last_used_at "
            "FROM org_code_connections WHERE org_id = ? ORDER BY is_default DESC, created_at", (org_id,)).fetchall()
    return [_public(r) for r in rows]


def add_connection(org_id: str, provider: str, token: Any, base_url: Any = "", label: Any = "",
                   created_by: str = "", identity: Optional[Callable] = None) -> Dict[str, Any]:
    """Check the token against the host, then store it encrypted. The first connection is the default."""
    from vault_crypto import encrypt_secret

    provider = str(provider or "").strip().lower()
    info = provider_info(provider)
    secret = str(token or "").strip()
    if len(secret) < 8 or len(secret) > 1000 or any(c.isspace() for c in secret):
        raise CodeHostError(400, f"Paste the {info['name']} token exactly as shown, without spaces.")
    url = normalize_base_url(provider, base_url)
    account = (identity or _IMPL[provider][0])({"base_url": url, "token": secret})
    _init()
    new_id = "ch_" + secrets.token_hex(8)
    with feature_conn() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM org_code_connections WHERE org_id = ?", (org_id,)).fetchone()
        if int(count["n"] or 0) >= 20:
            raise CodeHostError(400, "An organization can hold up to 20 code-host connections. Remove one first.")
        with atomic(conn):
            conn.execute(
                "INSERT INTO org_code_connections (id, org_id, provider, base_url, label, account, token_enc, "
                "is_default, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (new_id, org_id, provider, url, str(label or "").strip()[:80] or info["name"], account[:120],
                 encrypt_secret(secret), 1 if int(count["n"] or 0) == 0 else 0, str(created_by or "")[:200], _now()))
        conn.commit()
    return next(c for c in list_connections(org_id) if c["id"] == new_id)


def remove_connection(org_id: str, connection_id: str) -> bool:
    _init()
    with feature_conn() as conn:
        was_default = conn.execute("SELECT is_default FROM org_code_connections WHERE org_id = ? AND id = ?",
                                   (org_id, connection_id)).fetchone()
        cur = conn.execute("DELETE FROM org_code_connections WHERE org_id = ? AND id = ?", (org_id, connection_id))
        if was_default and int(was_default["is_default"] or 0):
            nxt = conn.execute("SELECT id FROM org_code_connections WHERE org_id = ? ORDER BY created_at LIMIT 1",
                               (org_id,)).fetchone()
            if nxt:
                conn.execute("UPDATE org_code_connections SET is_default = 1 WHERE id = ?", (nxt["id"],))
        conn.commit()
    return int(cur.rowcount or 0) > 0


def set_default(org_id: str, connection_id: str) -> bool:
    _init()
    with feature_conn() as conn:
        found = conn.execute("SELECT id FROM org_code_connections WHERE org_id = ? AND id = ?",
                             (org_id, connection_id)).fetchone()
        if not found:
            return False
        conn.execute("UPDATE org_code_connections SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE org_id = ?",
                     (connection_id, org_id))
        conn.commit()
    return True


def _load(org_id: str, connection_id: str = "") -> Dict[str, str]:
    from vault_crypto import decrypt_secret

    _init()
    with feature_conn() as conn:
        if connection_id:
            row = conn.execute("SELECT id, provider, base_url, token_enc FROM org_code_connections "
                               "WHERE org_id = ? AND id = ?", (org_id, connection_id)).fetchone()
        else:
            row = conn.execute("SELECT id, provider, base_url, token_enc FROM org_code_connections "
                               "WHERE org_id = ? ORDER BY is_default DESC, created_at LIMIT 1", (org_id,)).fetchone()
    if not row:
        raise CodeHostError(400, "Connect a code host first (GitHub, GitLab, Bitbucket, Azure DevOps or Gitea) under "
                                 "Code hosts.")
    try:
        token = decrypt_secret(row["token_enc"])
    except Exception:
        raise CodeHostError(500, "The stored token could not be decrypted. Remove the connection and add it again.") from None
    return {"id": row["id"], "provider": row["provider"], "base_url": row["base_url"], "token": token}


def has_connection(org_id: str) -> bool:
    try:
        return bool(list_connections(org_id))
    except Exception:
        return False


def test_connection(org_id: str, connection_id: str) -> Dict[str, Any]:
    conn = _load(org_id, connection_id)
    return {"ok": True, "account": _IMPL[conn["provider"]][0](conn)}


def open_change_request(org_id: str, repo: Any, files: Dict[str, str], title: str, body: str = "",
                        base_branch: str = "", connection_id: str = "", branch: str = "") -> Dict[str, Any]:
    """Create a branch, commit files to it and open a pull/merge request. Returns its URL and number."""
    conn = _load(org_id, connection_id)
    provider = conn["provider"]
    repo_name = normalize_repo(provider, repo)
    if not files:
        raise CodeHostError(400, "There are no file changes to propose.")
    if len(files) > MAX_FILES:
        raise CodeHostError(400, f"At most {MAX_FILES} files per request.")
    clean: Dict[str, str] = {}
    for path, content in files.items():
        text = str(content if content is not None else "")
        if len(text.encode("utf-8")) > MAX_FILE_BYTES:
            raise CodeHostError(400, f"{path} is larger than {MAX_FILE_BYTES // 1024} KB.")
        clean[_safe_path(path)] = text
    title = re.sub(r"\s+", " ", str(title or "Morrow: post-quantum update")).strip()[:200]
    base = str(base_branch or "").strip()
    if base and not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", base):
        raise CodeHostError(400, "Invalid base branch name.")
    new_branch = str(branch or "").strip() or _branch_name(title)
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", new_branch):
        raise CodeHostError(400, "Invalid branch name.")
    result = _IMPL[provider][1](conn, repo_name, base, new_branch, clean, title, str(body or "")[:60000])
    with feature_conn() as db:
        db.execute("UPDATE org_code_connections SET last_used_at = ? WHERE id = ?", (_now(), conn["id"]))
        db.commit()
    result.update({"provider": provider, "provider_name": PROVIDERS[provider]["name"],
                   "request_name": PROVIDERS[provider]["request_name"], "repository": repo_name,
                   "connection_id": conn["id"]})
    return result


def read_file(org_id: str, repo: Any, path: Any, ref: str = "", connection_id: str = "") -> Dict[str, Any]:
    """The current text of one file. ref "" means the repository's default branch, returned as "ref"."""
    conn = _load(org_id, connection_id)
    repo_name = normalize_repo(conn["provider"], repo)
    ref = str(ref or "").strip()
    if ref and not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", ref):
        raise CodeHostError(400, "Invalid branch name.")
    used, text = _READ[conn["provider"]](conn, repo_name, _safe_path(path), ref)
    return {"ref": used, "exists": text is not None, "content": text or "", "repository": repo_name,
            "connection_id": conn["id"], "provider": conn["provider"]}


def providers_public() -> List[Dict[str, Any]]:
    return [{"id": key, **{k: v for k, v in info.items()}} for key, info in PROVIDERS.items()]
