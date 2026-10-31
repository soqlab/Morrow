"""Code-host connections (services/code_hosts): connect with a token, open a PR/MR on five hosts.

The hosts' APIs are replaced by a recorder that answers like each host does, so these tests check
the calls each provider makes and in what order, and that tokens are stored encrypted and never
returned. Reuses the real-stack fixture from test_invite_landing.
"""

import base64
import json
import re

import pytest

from test_invite_landing import PASSWORD, api, make_org  # noqa: F401  (api is a fixture)

from services import code_hosts as ch


class FakeHost:
    """Answers code-host API calls from a table of (method, url regex) -> (status, payload)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, body=None, form=None, allow=(), raw=False):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body, "form": form})
        for (m, pattern), answer in self.routes.items():
            if m == method and re.search(pattern, url):
                status, payload = answer(body, form) if callable(answer) else answer
                if status >= 400 and status not in allow:
                    raise ch._http_error(status, payload)
                return status, payload
        raise AssertionError(f"unexpected call {method} {url}")


@pytest.fixture
def hosts(api, monkeypatch):
    monkeypatch.setattr(ch, "_ready", False)
    monkeypatch.setattr(ch, "_require_public_host", lambda host: None)
    return api


def bearer(client, app, role="admin"):
    with app._db() as db:
        app._issuer_create_user(db, f"{role}@acme.example", PASSWORD, "", role, "org-acme")
    token = client.post("/auth/login", json={"email": f"{role}@acme.example", "password": PASSWORD}).json()["access_token"]
    return {"Authorization": "Bearer " + token}


FILES = {"nginx/conf.d/tls.conf": "ssl_ecdh_curve X25519MLKEM768:X25519;\n"}


def test_github_creates_branch_commits_and_opens_pr(hosts, monkeypatch):
    fake = FakeHost({
        ("GET", r"api\.github\.com/user$"): (200, {"login": "octo"}),
        ("GET", r"/repos/acme/web$"): (200, {"default_branch": "main"}),
        ("GET", r"/git/ref/heads/main$"): (200, {"object": {"sha": "abc123"}}),
        ("POST", r"/git/refs$"): (201, {}),
        ("GET", r"/contents/nginx/conf\.d/tls\.conf\?ref="): (404, {"message": "Not Found"}),
        ("PUT", r"/contents/nginx/conf\.d/tls\.conf$"): (201, {}),
        ("POST", r"/pulls$"): (201, {"html_url": "https://github.com/acme/web/pull/7", "number": 7}),
    })
    monkeypatch.setattr(ch, "_http", fake)
    conn = ch.add_connection("org-acme", "github", "github_pat_0123456789")
    assert conn["account"] == "octo" and conn["is_default"] is True and "token" not in json.dumps(conn)
    pr = ch.open_change_request("org-acme", "https://github.com/acme/web.git", FILES, "Enable hybrid key exchange")
    assert pr["url"].endswith("/pull/7") and pr["base"] == "main" and pr["branch"].startswith("morrow/")
    put = next(c for c in fake.calls if c["method"] == "PUT")
    assert base64.b64decode(put["body"]["content"]).decode() == FILES["nginx/conf.d/tls.conf"]
    assert put["body"]["branch"] == pr["branch"] and "sha" not in put["body"]
    ref = next(c for c in fake.calls if c["url"].endswith("/git/refs"))
    assert ref["body"] == {"ref": f"refs/heads/{pr['branch']}", "sha": "abc123"}
    assert all(c["headers"]["Authorization"] == "Bearer github_pat_0123456789" for c in fake.calls)


def test_gitlab_self_managed_opens_merge_request(hosts, monkeypatch):
    fake = FakeHost({
        ("GET", r"git\.acme\.example/api/v4/user$"): (200, {"username": "ci-bot"}),
        ("GET", r"/projects/platform%2Fedge$"): (200, {"default_branch": "trunk"}),
        ("GET", r"/repository/files/"): (200, {}),
        ("POST", r"/repository/commits$"): (201, {}),
        ("POST", r"/merge_requests$"): (201, {"web_url": "https://git.acme.example/platform/edge/-/merge_requests/3", "iid": 3}),
    })
    monkeypatch.setattr(ch, "_http", fake)
    ch.add_connection("org-acme", "gitlab", "glpat-0123456789", base_url="git.acme.example")
    mr = ch.open_change_request("org-acme", "platform/edge", FILES, "PQ update")
    assert mr["request_name"] == "merge request" and mr["number"] == 3 and mr["base"] == "trunk"
    commit = next(c for c in fake.calls if c["url"].endswith("/repository/commits"))
    assert commit["body"]["start_branch"] == "trunk" and commit["body"]["actions"][0]["action"] == "update"
    assert fake.calls[0]["headers"]["PRIVATE-TOKEN"] == "glpat-0123456789"


def test_bitbucket_repository_token_and_pr(hosts, monkeypatch):
    fake = FakeHost({
        ("GET", r"/2\.0/user$"): (403, {"error": {"message": "forbidden"}}),
        ("GET", r"/repositories/acme/web$"): (200, {"mainbranch": {"name": "master"}}),
        ("GET", r"/refs/branches/master$"): (200, {"target": {"hash": "f00d"}}),
        ("POST", r"/repositories/acme/web/src$"): (201, {}),
        ("POST", r"/pullrequests$"): (201, {"id": 12, "links": {"html": {"href": "https://bitbucket.org/acme/web/pull-requests/12"}}}),
    })
    monkeypatch.setattr(ch, "_http", fake)
    conn = ch.add_connection("org-acme", "bitbucket", "ATCTT3xFfGN0repoToken")
    assert conn["account"] == "repository access token"
    pr = ch.open_change_request("org-acme", "acme/web", FILES, "PQ update")
    src = next(c for c in fake.calls if c["url"].endswith("/src"))
    assert src["form"]["parents"] == "f00d" and src["form"]["/nginx/conf.d/tls.conf"].startswith("ssl_ecdh_curve")
    assert pr["url"].endswith("/pull-requests/12")


def test_azure_devops_push_and_pr(hosts, monkeypatch):
    fake = FakeHost({
        ("GET", r"/_apis/connectionData"): (200, {"authenticatedUser": {"providerDisplayName": "Dana"}}),
        ("GET", r"/_apis/git/repositories/web\?"): (200, {"defaultBranch": "refs/heads/main"}),
        ("GET", r"/refs\?filter="): (200, {"value": [{"name": "refs/heads/main", "objectId": "1" * 40}]}),
        ("GET", r"/items\?path="): (404, {}),
        ("POST", r"/pushes\?"): (201, {}),
        ("POST", r"/pullrequests\?"): (201, {"pullRequestId": 41}),
    })
    monkeypatch.setattr(ch, "_http", fake)
    ch.add_connection("org-acme", "azure_devops", "adoPAT0123456789", base_url="https://dev.azure.com/acme")
    pr = ch.open_change_request("org-acme", "Platform/web", FILES, "PQ update")
    push = next(c for c in fake.calls if "/pushes" in c["url"])["body"]
    assert push["commits"][0]["parents"] == ["1" * 40] and push["commits"][0]["changes"][0]["changeType"] == "add"
    assert pr["url"] == "https://dev.azure.com/acme/Platform/_git/web/pullrequest/41"
    assert fake.calls[0]["headers"]["Authorization"].startswith("Basic ")


def test_gitea_change_files_and_pr(hosts, monkeypatch):
    fake = FakeHost({
        ("GET", r"/api/v1/user$"): (200, {"login": "dev"}),
        ("GET", r"/api/v1/repos/acme/web$"): (200, {"default_branch": "main"}),
        ("GET", r"/contents/nginx/conf\.d/tls\.conf\?ref="): (200, {"sha": "oldsha"}),
        ("POST", r"/api/v1/repos/acme/web/contents$"): (201, {}),
        ("POST", r"/pulls$"): (201, {"html_url": "https://codeberg.org/acme/web/pulls/5", "number": 5}),
    })
    monkeypatch.setattr(ch, "_http", fake)
    ch.add_connection("org-acme", "gitea", "0123456789abcdef")
    pr = ch.open_change_request("org-acme", "acme/web", FILES, "PQ update")
    change = next(c for c in fake.calls if c["url"].endswith("/contents"))["body"]
    assert change["new_branch"] == pr["branch"] and change["files"][0] == {
        "operation": "update", "path": "nginx/conf.d/tls.conf", "content": change["files"][0]["content"], "sha": "oldsha"}


def test_bad_token_is_not_stored(hosts, monkeypatch):
    monkeypatch.setattr(ch, "_http", FakeHost({("GET", r"/user$"): (401, {"message": "Bad credentials"})}))
    with pytest.raises(ch.CodeHostError) as err:
        ch.add_connection("org-acme", "github", "github_pat_wrong000")
    assert "refused the token" in err.value.detail
    assert ch.list_connections("org-acme") == []


@pytest.mark.parametrize("provider,url", [
    ("gitlab", "http://git.acme.example"), ("gitlab", "https://user:pw@git.acme.example"),
    ("azure_devops", "https://evil.example/acme"), ("github", "https://ghe.acme.example:8443"),
])
def test_unsafe_base_urls_are_refused(hosts, provider, url):
    with pytest.raises(ch.CodeHostError):
        ch.normalize_base_url(provider, url)


def test_private_self_hosted_server_is_refused(api, monkeypatch):
    monkeypatch.setattr(ch, "_ready", False)
    from services import gateway_network

    def private(host):
        raise gateway_network.CheckError("Private, special-use, or mixed DNS answers are blocked")
    monkeypatch.setattr(gateway_network, "public_ips", private)
    with pytest.raises(ch.CodeHostError) as err:
        ch.normalize_base_url("gitlab", "https://gitlab.internal-corp.net")
    assert "public internet" in err.value.detail


@pytest.mark.parametrize("path", ["../etc/passwd", ".git/config", "a\\b", ""])
def test_unsafe_file_paths_are_refused(hosts, monkeypatch, path):
    monkeypatch.setattr(ch, "_http", FakeHost({("GET", r"/user$"): (200, {"login": "octo"})}))
    ch.add_connection("org-acme", "github", "github_pat_0123456789")
    with pytest.raises(ch.CodeHostError):
        ch.open_change_request("org-acme", "acme/web", {path: "x"}, "t")


def test_connections_are_per_organization_and_api_never_returns_tokens(hosts, monkeypatch):
    client, app = hosts
    make_org(client, "org-acme", "Acme")
    monkeypatch.setattr(ch, "_http", FakeHost({("GET", r"/user$"): (200, {"login": "octo"})}))
    auth = bearer(client, app)
    added = client.post("/code-hosts", json={"provider": "github", "token": "github_pat_secret0001"}, headers=auth)
    assert added.status_code == 200, added.text
    listed = client.get("/code-hosts", headers=auth)
    assert "github_pat_secret0001" not in listed.text and listed.json()["connections"][0]["account"] == "octo"
    assert ch.list_connections("org-other") == []
    with app._db() as _:
        pass
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        stored = conn.execute("SELECT token_enc FROM org_code_connections").fetchone()["token_enc"]
    assert "github_pat_secret0001" not in stored
    providers = client.get("/code-hosts/providers", headers=auth).json()["providers"]
    assert {p["id"] for p in providers} == {"github", "gitlab", "bitbucket", "azure_devops", "gitea"}


def test_only_admins_connect_and_viewers_cannot_open_requests(hosts, monkeypatch):
    client, app = hosts
    make_org(client, "org-acme", "Acme")
    viewer = bearer(client, app, role="viewer")
    assert client.post("/code-hosts", json={"provider": "github", "token": "github_pat_x0000000"}, headers=viewer).status_code == 403
    assert client.post("/code-hosts/change-requests", json={"repository": "acme/web", "files": FILES}, headers=viewer).status_code == 403


def test_read_file_on_each_host(hosts, monkeypatch):
    text = "ssl_protocols TLSv1.2;\n"
    b64 = base64.b64encode(text.encode()).decode()
    cases = {
        "github": ({"base_url": ""}, {("GET", r"/user$"): (200, {"login": "o"}), ("GET", r"/repos/acme/web$"): (200, {"default_branch": "main"}),
                    ("GET", r"/contents/"): (200, {"content": b64})}),
        "gitlab": ({"base_url": ""}, {("GET", r"/api/v4/user$"): (200, {"username": "o"}), ("GET", r"/projects/acme%2Fweb$"): (200, {"default_branch": "main"}),
                    ("GET", r"/repository/files/"): (200, {"content": b64})}),
        "bitbucket": ({"base_url": ""}, {("GET", r"/2\.0/user$"): (200, {"username": "o"}), ("GET", r"/repositories/acme/web$"): (200, {"mainbranch": {"name": "main"}}),
                       ("GET", r"/src/main/"): (200, text)}),
        "azure_devops": ({"base_url": "https://dev.azure.com/acme"}, {("GET", r"connectionData"): (200, {"authenticatedUser": {}}),
                         ("GET", r"/repositories/web\?"): (200, {"defaultBranch": "refs/heads/main"}), ("GET", r"/items\?"): (200, {"content": text})}),
        "gitea": ({"base_url": ""}, {("GET", r"/api/v1/user$"): (200, {"login": "o"}), ("GET", r"/api/v1/repos/acme/web$"): (200, {"default_branch": "main"}),
                   ("GET", r"/contents/"): (200, {"content": b64})}),
    }
    for provider, (opts, routes) in cases.items():
        monkeypatch.setattr(ch, "_http", FakeHost(routes))
        org = f"org-{provider}"
        ch.add_connection(org, provider, "token0123456789", base_url=opts["base_url"])
        repo = "acme/web" if provider != "azure_devops" else "Platform/web"
        got = ch.read_file(org, repo, "nginx/tls.conf")
        assert got == {**got, "ref": "main", "exists": True, "content": text}, provider


def test_autopilot_opens_snippet_as_new_file_on_connected_host(hosts, monkeypatch):
    client, app = hosts
    make_org(client, "org-acme", "Acme")
    auth = bearer(client, app)
    captured = {}
    monkeypatch.setattr(ch, "_http", FakeHost({("GET", r"/user$"): (200, {"login": "octo"})}))
    assert client.post("/code-hosts", json={"provider": "github", "token": "github_pat_0123456789"}, headers=auth).status_code == 200

    def fake_open(org, repo, files, title, body="", base_branch="", connection_id="", branch=""):
        captured.update(org=org, repo=repo, files=files, title=title, body=body)
        return {"url": "https://github.com/acme/edge/pull/3", "number": 3, "branch": "morrow/x", "base": "main",
                "provider": "github", "provider_name": "GitHub", "request_name": "pull request", "repository": repo,
                "connection_id": "ch"}
    monkeypatch.setattr(ch, "open_change_request", fake_open)
    task = client.post("/autopilot/analyze", json={"scan_result": {"host": "edge.acme.example", "port": 443, "server": "nginx"}}, headers=auth)
    assert task.status_code == 200, task.text
    task_id = task.json()["task_id"]
    res = client.post("/autopilot/deploy", json={"task_id": task_id, "repository": "acme/edge"}, headers=auth)
    assert res.status_code == 200, res.text
    assert res.json()["pr_url"].endswith("/pull/3") and res.json()["status"] == "deployed"
    (path, content), = captured["files"].items()
    assert path.startswith("morrow/pq-tls/") and "ssl_protocols" in content    # a new file, not nginx.conf
    assert "include " in captured["body"] and captured["org"] == "org-acme"


def test_autopilot_legacy_github_token_path_no_longer_crashes(hosts, monkeypatch):
    client, app = hosts
    make_org(client, "org-acme", "Acme")
    auth = bearer(client, app)
    from services import migration_autopilot

    seen = {}
    monkeypatch.setattr(migration_autopilot, "create_github_pr", lambda **kw: seen.update(kw) or {"pr_url": "https://github.com/a/b/pull/1"})
    task_id = client.post("/autopilot/analyze", json={"scan_result": {"host": "a.acme.example", "port": 443}}, headers=auth).json()["task_id"]
    res = client.post("/autopilot/deploy", json={"task_id": task_id, "github_token": "ghp_x", "repo_full_name": "a/b"}, headers=auth)
    assert res.status_code == 200, res.text
    assert seen["repo_full_name"] == "a/b" and seen["base_branch"] == "main"


def test_github_oauth_state_is_signed_and_expires(hosts, monkeypatch):
    client, app = hosts
    state = app._github_oauth_state_sign("org-acme", "user-1")
    assert app._github_oauth_state_verify(state)["org"] == "org-acme"
    payload, mac = state.rsplit(".", 1)
    forged = base64.urlsafe_b64encode(json.dumps({"org": "org-victim", "uid": "x", "exp": 9999999999}).encode()).decode().rstrip("=")
    assert app._github_oauth_state_verify(f"{forged}.{mac}") is None
    assert app._github_oauth_state_verify(base64.urlsafe_b64encode(b'{"org":"org-victim","uid":"x"}').decode()) is None
    import time as _time
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 3600)
    assert app._github_oauth_state_verify(state) is None
