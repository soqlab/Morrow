"""Public demo mode (PQC_DEMO_MODE=1).

Each visitor gets a private, throwaway workspace filled with the fictional Example Financial
Group estate. No signup, no email; the workspace and its account are deleted after
PQC_DEMO_TTL_SECONDS. The process cannot open network connections to anything but itself, so the
demo can never be used to scan or contact third parties, and only an allowlist of write
actions is accepted.

Never enable this on an instance holding real customer data.
"""
from __future__ import annotations

import glob
import ipaddress
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timedelta, timezone

log = logging.getLogger("pqc.demo")

ENABLED = os.getenv("PQC_DEMO_MODE", "").strip() == "1"
TTL_SECONDS = int(os.getenv("PQC_DEMO_TTL_SECONDS", "3600"))
MAX_WORKSPACES = int(os.getenv("PQC_DEMO_MAX_WORKSPACES", "40"))
STARTS_PER_IP_PER_HOUR = int(os.getenv("PQC_DEMO_STARTS_PER_IP_HOUR", "5"))
ORG_RE = re.compile(r"^demo-(\d{10})-[0-9a-f]{12}$")
ORG_COLUMNS = ("organization_id", "org_id", "org", "tenant_id")

# Writes a visitor may make. Everything else that is not a read is refused.
ALLOWED_WRITES = [(m, re.compile(p)) for m, p in [
    ("POST", r"/auth/(logout|refresh)"),
    ("PUT", r"/assets/[^/]+"),
    ("POST", r"/collections"),
    ("DELETE", r"/collections/[^/]+"),
    ("POST", r"/migration-tasks"),
    ("PATCH", r"/migration-tasks/[^/]+"),
    ("POST", r"/policies(/[^/]+/evaluate)?"),
    ("PUT", r"/policies/[^/]+"),
    ("DELETE", r"/policies/[^/]+"),
    ("POST", r"/policy/review"),
    ("PUT", r"/policy"),
    ("POST", r"/remediations/[^/]+/(approve|reject|mark-merged|drift/acknowledge)"),
    ("POST", r"/baselines(/from-scan/[^/]+)?"),
    ("POST", r"/canaries/deploy"),
    ("POST", r"/hndl-canary-tokens"),
]]
# Only the server's own seeding may post synthetic scans: scan ids are global, so a visitor
# choosing another workspace's id could overwrite it.
SEED_ONLY_WRITES = [("POST", re.compile(r"/scans/synthetic"))]
# Reads that stay closed: operator consoles and platform administration.
BLOCKED_READ_PREFIXES = ("/vendor-admin", "/platform", "/admin", "/dev", "/support-session")
OWN_PATHS = {"/demo/start", "/demo/status"}

NOT_IN_DEMO = ("Not available in the demo. Scanning, integrations and administration are switched "
               "off here; self-host Morrow to use them: https://github.com/soqlab/morrow")


# ---------------------------------------------------------------- network lock
def _is_local(host) -> bool:
    if host is None:
        return True
    h = host.decode() if isinstance(host, bytes) else str(host)
    h = h.strip("[]").split("%")[0]
    if h in ("", "localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def install_network_guard() -> None:
    """Refuse every IP connection and DNS lookup except to this machine."""
    if not ENABLED or getattr(socket, "_pqc_demo_guard", False):
        return
    orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex
    orig_sendto, orig_getaddrinfo = socket.socket.sendto, socket.getaddrinfo

    def check(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, tuple) else address
            if not _is_local(host):
                raise PermissionError(f"outbound network is disabled in the demo ({host})")

    def connect(self, address):
        check(self, address)
        return orig_connect(self, address)

    def connect_ex(self, address):
        check(self, address)
        return orig_connect_ex(self, address)

    def sendto(self, data, *args):
        check(self, args[-1])
        return orig_sendto(self, data, *args)

    def getaddrinfo(host, *args, **kwargs):
        if not _is_local(host):
            raise socket.gaierror(socket.EAI_NONAME, "DNS is disabled in the demo")
        return orig_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.getaddrinfo = getaddrinfo
    socket._pqc_demo_guard = True
    log.warning("[PQC DEMO] demo mode: outbound network restricted to this machine")


# ---------------------------------------------------------------- request policy
def request_allowed(method: str, path: str, from_seed: bool = False) -> bool:
    if path in OWN_PATHS:
        return True
    if method in ("GET", "HEAD", "OPTIONS"):
        return not any(path == p or path.startswith(p + "/") for p in BLOCKED_READ_PREFIXES)
    if from_seed and any(method == m and rx.fullmatch(path) for m, rx in SEED_ONLY_WRITES):
        return True
    return any(method == m and rx.fullmatch(path) for m, rx in ALLOWED_WRITES)


def _from_seed(request) -> bool:
    # Seeding calls this process over loopback with no proxy in between; visitors always
    # arrive through the hosting proxy, which adds X-Forwarded-For.
    host = request.client.host if request.client else ""
    return _is_local(host) and "x-forwarded-for" not in request.headers


_starts: dict[str, deque] = defaultdict(deque)
_starts_lock = threading.Lock()


def _rate_limited(ip: str) -> bool:
    now = time.time()
    with _starts_lock:
        q = _starts[ip]
        while q and q[0] < now - 3600:
            q.popleft()
        if len(q) >= STARTS_PER_IP_PER_HOUR:
            return True
        q.append(now)
        return False


def _client_ip(request) -> str:
    # Headers set by the hosting edge first. In X-Forwarded-For the leftmost entries are whatever
    # the client sent; the proxy appends the real address, so take the last one.
    for header in ("cf-connecting-ip", "true-client-ip"):
        if request.headers.get(header):
            return request.headers[header].strip()
    fwd = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return fwd[-1] if fwd else (request.client.host if request.client else "?")


# ---------------------------------------------------------------- workspaces
def _db_path() -> str:
    import db as dbmod
    return os.environ.get("PQC_SCANNER_DB", dbmod.DB_PATH)


def _db_files() -> list[str]:
    main = _db_path()
    dirs = {os.path.dirname(os.path.abspath(main))}
    if os.getenv("PQC_DATA_DIR"):
        dirs.add(os.path.abspath(os.environ["PQC_DATA_DIR"]))
    files = {os.path.abspath(main)}
    for d in dirs:
        for pattern in ("*.db", "*.sqlite", "*.sqlite3"):
            files.update(os.path.abspath(p) for p in glob.glob(os.path.join(d, pattern)))
    return sorted(f for f in files if os.path.exists(f))


def active_workspaces() -> list[str]:
    with closing(sqlite3.connect(_db_path(), timeout=30)) as conn:
        rows = conn.execute("SELECT id FROM organizations WHERE id LIKE 'demo-%'").fetchall()
    return [r[0] for r in rows if ORG_RE.match(r[0])]


def workspace_exists(org_id: str) -> bool:
    with closing(sqlite3.connect(_db_path(), timeout=30)) as conn:
        return conn.execute("SELECT 1 FROM organizations WHERE id=?", (org_id,)).fetchone() is not None


def _token_org(token: str) -> str:
    """The org claim, read without verifying: the app's own auth verifies the token afterwards."""
    try:
        import jwt
        return str(jwt.decode(token, options={"verify_signature": False}).get("org_id") or "")
    except Exception:
        return ""


def expires_at(org_id: str) -> int | None:
    m = ORG_RE.match(org_id or "")
    return int(m.group(1)) + TTL_SECONDS if m else None


def purge_workspace(org_id: str) -> int:
    """Delete every row that belongs to the workspace, in every table of every database file."""
    if not ORG_RE.match(org_id):
        raise ValueError("not a demo workspace")
    deleted = 0
    for path in _db_files():
        with closing(sqlite3.connect(path, timeout=30, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Append-only tables (the audit log) refuse deletes through triggers. A demo
                # workspace must leave nothing behind, so lift them inside this transaction and
                # restore them before it commits; on any error the rollback restores them too.
                guards = conn.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='trigger' "
                    "AND sql LIKE '%BEFORE DELETE%' AND sql LIKE '%RAISE%'").fetchall()
                for name, _sql in guards:
                    conn.execute(f'DROP TRIGGER "{name}"')

                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                user_ids = []
                if "pqc_users" in tables:
                    user_ids = [r[0] for r in conn.execute("SELECT id FROM pqc_users WHERE org_id=?", (org_id,))]
                for t in tables:
                    cols = {r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')}
                    for c in ORG_COLUMNS:
                        if c in cols:
                            deleted += conn.execute(f'DELETE FROM "{t}" WHERE "{c}"=?', (org_id,)).rowcount
                    for c in ("user_id", "actor_id", "subject_id"):
                        if c in cols and user_ids:
                            marks = ",".join("?" * len(user_ids))
                            deleted += conn.execute(f'DELETE FROM "{t}" WHERE "{c}" IN ({marks})', user_ids).rowcount
                    if t in ("organizations", "admin_orgs") and "id" in cols:
                        deleted += conn.execute(f'DELETE FROM "{t}" WHERE id=?', (org_id,)).rowcount
                # Anything still naming the workspace (cross-tenant rollups keep org ids inside
                # JSON payloads) goes too. Demo ids contain no LIKE wildcards.
                for t in tables:
                    for c in [r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')]:
                        deleted += conn.execute(
                            f'DELETE FROM "{t}" WHERE CAST("{c}" AS TEXT) LIKE ?', (f"%{org_id}%",)).rowcount

                for _name, sql in guards:
                    conn.execute(sql)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
    return deleted


def purge_expired() -> None:
    now = time.time()
    for org_id in active_workspaces():
        exp = expires_at(org_id)
        if exp is not None and exp <= now:
            try:
                n = purge_workspace(org_id)
                log.info("[PQC DEMO] deleted expired workspace %s (%d rows)", org_id, n)
            except Exception:
                log.exception("[PQC DEMO] could not delete workspace %s", org_id)


PROCESS_STARTED = int(time.time())


def _cleanup_loop() -> None:
    # The schema is created during startup, after this module is imported.
    time.sleep(20)
    first = True
    while True:
        try:
            if first:
                # Leftovers from a previous run only: a visitor whose request woke the server
                # may already have a workspace by now.
                for org_id in active_workspaces():
                    m = ORG_RE.match(org_id)
                    if m and int(m.group(1)) < PROCESS_STARTED:
                        purge_workspace(org_id)
                first = False
            purge_expired()
        except Exception:
            log.exception("[PQC DEMO] cleanup pass failed")
        time.sleep(120)


def create_workspace() -> dict:
    import db as dbmod
    from services import auth_issuer
    from services import demo_estate as E

    org_id = f"demo-{int(time.time())}-{secrets.token_hex(6)}"
    dbmod.upsert_organization(org_id, E.COMPANY)
    with closing(dbmod.get_connection()) as conn:
        user = auth_issuer.create_user(
            conn, f"{org_id}@demo.invalid", secrets.token_urlsafe(24) + "Aa1!",
            full_name="Demo visitor", role="admin", org_id=org_id)
        conn.commit()
    token = auth_issuer.issue_access_token(user)
    try:
        _seed(org_id, token)
    except Exception:
        purge_workspace(org_id)
        raise
    return {"access_token": token, "token_type": "bearer", "org_id": org_id, "expires_at": expires_at(org_id)}


def _seed(org_id: str, token: str) -> None:
    import requests
    import db as dbmod
    from services import demo_estate as E

    base = f"http://127.0.0.1:{os.getenv('PORT', '8000')}"
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.trust_env = False

    def call(method, path, body=None):
        r = s.request(method, base + path, json=body, timeout=120)
        if r.status_code >= 300:
            log.warning("[PQC DEMO] seed %s %s -> %s %s", method, path, r.status_code, r.text[:200])
        return r

    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    ctx = dbmod.set_current_organization_id(org_id)
    try:
        repo_ids = {slug: int(dbmod.upsert_repository(name, f"https://github.com/{name}").get("id") or 0)
                    for slug, name in E.REPOS.items()}

        scan_ids = []
        for i in range(E.SCAN_COUNT):
            scanned_at = now - timedelta(days=E.SCAN_SPACING_DAYS * (E.SCAN_COUNT - 1 - i), hours=i % 6)
            results = [E.build_facts(e, i, scanned_at) for e in E.ESTATE if e[11] <= min(i, 4)]
            # Scan ids are global, not per organization: suffix them so workspaces never collide.
            scan_id = f"scan-{scanned_at.strftime('%Y%m%d')}-estate-{org_id[-12:]}"
            r = call("POST", "/scans/synthetic", {
                "scan_id": scan_id, "created_at": scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "results": results, "auto_close_merged": False})
            if r.status_code == 200:
                scan_ids.append(scan_id)

        for host, port, env, team, owner, crit, lifetime, repo, tags, *_ in E.ESTATE:
            call("PUT", f"/assets/{host}:{port}", {
                "owner": owner, "team": team, "environment": env, "criticality": crit,
                "confidentiality_lifetime": lifetime, "tags": tags,
                "notes": f"{E.COMPANY} demo estate record (fictional).",
                "metadata": {"business_service": team, "data_classification":
                             "restricted" if "restricted" in tags or "customer-data" in tags else "internal"},
                "repository_id": repo_ids.get(repo, 0)})

        for name, tag in E.COLLECTIONS:
            call("POST", "/collections", {
                "name": name, "description": f"{E.COMPANY} demo estate",
                "targets_text": "\n".join(f"{e[0]}:{e[1]}" for e in E.ESTATE if tag in e[8])})

        made = []
        for asset_key, repo, path, title, fix, status in E.REMEDIATION_PLAN:
            original = f"# {path}\nmin_tls_version = \"1.2\"\nkey_algorithm   = \"rsa-2048\"\ncrypto_owner    = \"\"\n"
            suggested = (f"# {path}\nmin_tls_version = \"1.3\"\nkey_algorithm   = \"rsa-3072\"\n"
                         f"crypto_owner    = \"platform-security\"\npqc_stage       = \"hybrid-group-pending\"\n")
            row = dbmod.create_remediation(
                asset_key, repo_ids.get(repo, 0), path, title, fix,
                original_content=original, suggested_content=suggested, status=status,
                review_note="Reviewed in the weekly crypto migration forum.", origin_kind="scan_finding")
            rid = int(row.get("id") or 0)
            made.append((rid, status))
            if status in {"pr_created", "verified_closed"}:
                v = dbmod.create_validation_job(
                    rid, validator_type="terraform", git_ref="main", status="passed", job_id=f"val-{org_id}-{rid}",
                    details={"commands": [{"cmd": "terraform fmt -check", "exit_code": 0},
                                          {"cmd": "terraform validate", "exit_code": 0}],
                             "iac_policy": {"status": "passed", "findings": []}})
                dbmod.update_validation_job(int(v.get("id") or 0), status="passed",
                                            stdout="Validation passed.\n", stderr="", exit_code=0, finished=True)

        with closing(sqlite3.connect(_db_path(), timeout=30)) as conn:
            conn.execute("UPDATE pqc_users SET full_name=? WHERE org_id=?", ("Demo visitor", org_id))
            for host, port, *rest in E.ESTATE:
                seen = now - timedelta(days=E.SCAN_SPACING_DAYS * (E.SCAN_COUNT - 1 - min(rest[-1], 4)))
                conn.execute("UPDATE assets SET updated_at=? WHERE asset_key=? AND organization_id=?",
                             (seen.strftime("%Y-%m-%dT%H:%M:%SZ"), f"{host}:{port}", org_id))
            ages = {"suggested": 6, "approved": 19, "pr_created": 33, "verified_closed": 61}
            for rid, status in made:
                created = now - timedelta(days=ages.get(status, 10), hours=rid % 24)
                fields = {"created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "updated_at": (created + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
                if status in {"pr_created", "verified_closed"}:
                    fields["pr_url"] = f"https://github.com/example-financial/repo/pull/{100 + rid}"
                    fields["pr_branch"] = f"pqc/remediation-{rid}"
                    fields["pr_base_branch"] = "main"
                if status == "verified_closed":
                    merged = created + timedelta(days=9)
                    fields["merged_at"] = merged.strftime("%Y-%m-%dT%H:%M:%SZ")
                    fields["closed_at"] = (merged + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    fields["verification_scan_id"] = scan_ids[-1] if scan_ids else ""
                    fields["drift_status"] = "clear"
                    fields["last_drift_checked_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                sets = ", ".join(f"{k}=?" for k in fields)
                conn.execute(f"UPDATE remediations SET {sets} WHERE id=?", (*fields.values(), rid))
            conn.commit()
    finally:
        dbmod.reset_current_organization_id(ctx)

    for title, asset, status, owner in E.MIGRATION_TASKS:
        call("POST", "/migration-tasks", {"title": title, "asset_key": asset, "status": status,
                                          "owner": owner, "priority": "high"})
    for tier, asset in E.CANARIES:
        call("POST", "/canaries/deploy", {"tier": tier, "asset_key": asset,
                                          "notes": f"{E.COMPANY} demo estate tripwire"})
    for asset in E.HNDL_TOKEN_ASSETS:
        call("POST", "/hndl-canary-tokens", {"asset_key": asset, "label": f"HNDL canary for {asset}"})
    call("POST", "/policies", E.POLICY)


# ---------------------------------------------------------------- wiring
def attach(app) -> None:
    """Add the demo endpoints and the request policy. Call after every other middleware."""
    if not ENABLED:
        return
    from fastapi.responses import JSONResponse, RedirectResponse
    from starlette.concurrency import run_in_threadpool

    @app.middleware("http")
    async def _demo_gate(request, call_next):
        path, method = request.url.path.rstrip("/") or "/", request.method.upper()

        # The marketing site, trial form and public checker don't apply here; open the console.
        if path == "/" and method in ("GET", "HEAD"):
            return RedirectResponse("/ui/", status_code=307)

        if path == "/demo/status":
            return JSONResponse({"demo": True, "ttl_seconds": TTL_SECONDS,
                                 "max_workspaces": MAX_WORKSPACES,
                                 "source": "https://github.com/soqlab/morrow"},
                                headers={"Cache-Control": "no-store"})

        if path == "/demo/start":
            if method != "POST":
                return JSONResponse({"detail": "Use POST"}, status_code=405)
            if _rate_limited(_client_ip(request)):
                return JSONResponse({"detail": "Too many demo workspaces from your network. Try again in an hour."},
                                    status_code=429)
            await run_in_threadpool(purge_expired)
            if len(await run_in_threadpool(active_workspaces)) >= MAX_WORKSPACES:
                return JSONResponse({"detail": "The demo is busy right now. Try again in a few minutes."},
                                    status_code=503)
            try:
                out = await run_in_threadpool(create_workspace)
            except Exception:
                log.exception("[PQC DEMO] could not create a workspace")
                return JSONResponse({"detail": "Could not create a demo workspace. Try again shortly."},
                                    status_code=500)
            return JSONResponse(out, headers={"Cache-Control": "no-store"})

        # Only tokens for a live demo workspace are accepted: after a restart or expiry the
        # visitor is sent back to "Start demo workspace" instead of an empty console.
        if "x-api-key" in request.headers:
            return JSONResponse({"detail": "API keys are not accepted in the demo."}, status_code=401)
        auth = request.headers.get("authorization", "")
        if auth[:7].lower() == "bearer ":
            org = _token_org(auth[7:].strip())
            if not ORG_RE.match(org) or not await run_in_threadpool(workspace_exists, org):
                return JSONResponse({"detail": "This demo workspace has ended. Start a new one."}, status_code=401)

        if not request_allowed(method, path, _from_seed(request)):
            return JSONResponse({"detail": NOT_IN_DEMO}, status_code=403)
        return await call_next(request)

    threading.Thread(target=_cleanup_loop, name="pqc-demo-cleanup", daemon=True).start()
    log.warning("[PQC DEMO] demo mode on: workspaces live %ds, at most %d at once", TTL_SECONDS, MAX_WORKSPACES)
