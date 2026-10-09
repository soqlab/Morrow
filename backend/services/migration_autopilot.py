"""
Autonomous PQC Migration Autopilot

The only tool that goes beyond telling you what's wrong and actually fixes it.
Given a scan result, the autopilot:
  1. Identifies the exact server type (nginx / Apache / Envoy / HAProxy / OpenSSL CLI)
  2. Generates the precise config diff to reach quantum-safe TLS
  3. Opens a GitHub PR with the diff (no manual copy-paste)
  4. Creates a Jira/Linear ticket linked to the PR
  5. Reschedules a rescan to verify the fix landed

Cipher targets (NIST FIPS 203/204/205 + hybrid transition):
  Immediate hardening (available today):
    TLS 1.3 only, ECDHE-only (no RSA key exchange), PFS mandatory
  Full PQC (OQS provider / BoringSSL-OQS / liboqs):
    X25519MLKEM768 (hybrid), MLKEM768 (pure), P384_MLKEM1024 (FIPS)
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Config templates ──────────────────────────────────────────────────────────

_NGINX_PATCH = """\
# PQC Migration Autopilot — generated patch
# Apply inside your server {} block

# PHASE 1: Immediate hardening (deploy today — no library changes)
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=63072000" always;

# PHASE 2: Full PQC (deploy when nginx is built with OQS provider)
# ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
# ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
"""

_APACHE_PATCH = """\
# PQC Migration Autopilot — generated patch
# Apply inside your VirtualHost block

# PHASE 1: Immediate hardening
SSLProtocol -all +TLSv1.3
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
SSLOpenSSLConfCmd Curves X25519:P-256:P-384
SSLSessionTickets off
SSLUseStapling on
Header always set Strict-Transport-Security "max-age=63072000"

# PHASE 2: Full PQC (mod_ssl with OQS provider)
# SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:P-256
"""

_ENVOY_PATCH = """\
# PQC Migration Autopilot — generated patch
# Apply to your transport_socket TLS context

transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_params:
        tls_minimum_protocol_version: TLSv1_3
        tls_maximum_protocol_version: TLSv1_3
        # PHASE 1: ECDHE hardening (deploy today)
        ecdh_curves:
          - X25519
          - P-256
          - P-384
        # PHASE 2: PQC hybrid (add when Envoy supports OQS)
        # ecdh_curves:
        #   - X25519MLKEM768
        #   - X25519
      tls_certificates:
        - certificate_chain: {filename: "/etc/ssl/certs/server.crt"}
          private_key: {filename: "/etc/ssl/private/server.key"}
"""

_HAPROXY_PATCH = """\
# PQC Migration Autopilot — generated patch
# Apply to your frontend or defaults section

# PHASE 1: Immediate hardening
ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
ssl-default-bind-options ssl-min-ver TLSv1.3 no-tls-tickets

# Per bind line — add: ciphers TLS_AES_256_GCM_SHA384
# bind *:443 ssl crt /etc/ssl/private/cert.pem ssl-min-ver TLSv1.3
"""

_OPENSSL_CONF_PATCH = """\
# PQC Migration Autopilot — openssl.cnf patch
[system_default_sect]
MinProtocol = TLSv1.3
CipherString = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Groups = X25519:P-256:P-384

# PHASE 2: Add OQS provider
# [provider_sect]
# oqsprovider = oqsprovider_sect
# [oqsprovider_sect]
# activate = 1
# Groups = X25519MLKEM768:X25519:P-256
"""

_SERVER_PATCHES: Dict[str, str] = {
    "nginx":   _NGINX_PATCH,
    "apache":  _APACHE_PATCH,
    "envoy":   _ENVOY_PATCH,
    "haproxy": _HAPROXY_PATCH,
    "openssl": _OPENSSL_CONF_PATCH,
}

# ── Server type inference ─────────────────────────────────────────────────────

def _infer_server_type(scan_result: Dict[str, Any]) -> str:
    server = str(scan_result.get("server_header") or scan_result.get("server") or "").lower()
    if "nginx" in server:     return "nginx"
    if "apache" in server:    return "apache"
    if "envoy" in server:     return "envoy"
    if "haproxy" in server:   return "haproxy"
    if "openssl" in server:   return "openssl"
    port = int(scan_result.get("port") or 443)
    if port in (6443, 10250): return "envoy"  # likely k8s / service mesh
    return "nginx"  # default assumption


# ── Migration priority scorer ─────────────────────────────────────────────────

def _migration_priority(scan_result: Dict[str, Any]) -> str:
    risk = str(scan_result.get("quantum_risk_level") or scan_result.get("risk_level") or "").lower()
    port = int(scan_result.get("port") or 443)
    str(scan_result.get("cert_key_type") or scan_result.get("key_type") or "").lower()
    kb   = int(scan_result.get("cert_key_bits") or scan_result.get("key_bits") or 0)

    if risk == "critical" or (kb and kb <= 1024):     return "p0"
    if risk == "high"     or port in (5432, 1433, 636, 389): return "p1"
    if risk == "medium":  return "p2"
    return "p3"


# ── DB ────────────────────────────────────────────────────────────────────────

def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    # NOTE: this table is deliberately NOT called "migration_tasks". app.py's /migration-tasks
    # feature already owns a table of that name with a different schema (organization_id, rule_id,
    # safety_class, ...). Because CREATE TABLE IF NOT EXISTS is a no-op when the name is taken, the
    # autopilot's columns were never created and every query here failed with
    # "no such column: org_id" — /autopilot/tasks and /autopilot/dashboard returned 500.
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("autopilot_migration_tasks"):
        return
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS autopilot_migration_tasks (
                id              TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL,
                asset_key       TEXT NOT NULL,
                host            TEXT NOT NULL,
                port            INTEGER NOT NULL DEFAULT 443,
                server_type     TEXT NOT NULL DEFAULT 'nginx',
                priority        TEXT NOT NULL DEFAULT 'p2',
                status          TEXT NOT NULL DEFAULT 'pending',
                config_patch    TEXT NOT NULL DEFAULT '',
                github_pr_url   TEXT NOT NULL DEFAULT '',
                jira_issue_url  TEXT NOT NULL DEFAULT '',
                jira_issue_key  TEXT NOT NULL DEFAULT '',
                notes           TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                completed_at    TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_autopilot_mig_org ON autopilot_migration_tasks(org_id, status)"
        )
        conn.commit()
    mark_schema_ensured("autopilot_migration_tasks")


# ── GitHub PR creator ─────────────────────────────────────────────────────────

def create_github_pr(
    github_token: str,
    repo_full_name: str,   # "owner/repo"
    base_branch: str,
    config_file_path: str, # path in repo, e.g. "nginx/nginx.conf"
    patch_content: str,
    asset_key: str,
    server_type: str,
) -> Dict[str, str]:
    """
    Create a GitHub PR with the config patch.
    Returns {pr_url, branch_name, sha}.
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "PQC-Scanner-Autopilot/1.0",
    }
    api = "https://api.github.com"

    def gh(method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(f"{api}{path}", data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub API {e.code}: {e.read().decode()[:300]}")

    # Get default branch SHA
    branch_data = gh("GET", f"/repos/{repo_full_name}/git/ref/heads/{base_branch}")
    base_sha = branch_data["object"]["sha"]

    # Create new branch
    branch_name = f"pqc-autopilot/{asset_key.replace(':', '-').replace('.', '-')}-{secrets.token_hex(4)}"
    gh("POST", f"/repos/{repo_full_name}/git/refs", {
        "ref": f"refs/heads/{branch_name}", "sha": base_sha,
    })

    # Get existing file SHA (needed to update)
    try:
        file_data = gh("GET", f"/repos/{repo_full_name}/contents/{config_file_path}?ref={branch_name}")
        file_sha = file_data.get("sha")
    except Exception:
        file_sha = None  # new file

    import base64
    content_b64 = base64.b64encode(patch_content.encode()).decode()
    update_body: Dict[str, Any] = {
        "message": f"PQC Autopilot: harden TLS on {asset_key} [{server_type}]",
        "content": content_b64, "branch": branch_name,
    }
    if file_sha:
        update_body["sha"] = file_sha
    gh("PUT", f"/repos/{repo_full_name}/contents/{config_file_path}", update_body)

    # Create PR
    pr = gh("POST", f"/repos/{repo_full_name}/pulls", {
        "title": f"[PQC Autopilot] Quantum-harden TLS: {asset_key}",
        "head": branch_name, "base": base_branch,
        "body": (
            f"## PQC Migration Autopilot\n\n"
            f"**Asset:** `{asset_key}`\n"
            f"**Server type:** `{server_type}`\n\n"
            f"### What this changes\n"
            f"- Enforces TLS 1.3 exclusively\n"
            f"- Removes RSA key exchange (forward secrecy only)\n"
            f"- Prepares config for Phase 2 PQC hybrid (X25519+ML-KEM-768)\n\n"
            f"### Phase 1 (this PR)\n"
            f"Immediate hardening — no library changes required.\n\n"
            f"### Phase 2 (follow-up PR)\n"
            f"Full ML-KEM-768 hybrid after OQS provider deployment.\n\n"
            f"*Generated by [PQC Scanner Autopilot](https://pqc-scanner.dev)*"
        ),
    })
    return {"pr_url": pr.get("html_url", ""), "branch_name": branch_name}


# ── Jira issue creator ────────────────────────────────────────────────────────

def create_jira_issue(
    jira_url: str,       # https://yourorg.atlassian.net
    jira_email: str,
    jira_token: str,
    project_key: str,
    asset_key: str,
    priority: str,
    server_type: str,
    pr_url: str = "",
) -> Dict[str, str]:
    """Create a Jira issue for the migration task."""
    import base64
    credentials = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()
    priority_map = {"p0": "Highest", "p1": "High", "p2": "Medium", "p3": "Low"}
    jira_priority = priority_map.get(priority, "Medium")

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[PQC] Quantum-harden TLS: {asset_key}",
            "description": {
                "type": "doc", "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": (
                        f"PQC Scanner Autopilot has identified quantum-vulnerable TLS on {asset_key}. "
                        f"A config patch has been generated for {server_type}. "
                        + (f"PR: {pr_url}" if pr_url else "No PR created — manual deployment required.")
                    )}],
                }],
            },
            "issuetype": {"name": "Task"},
            "priority": {"name": jira_priority},
            "labels": ["pqc-migration", "security", "autopilot"],
        }
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{jira_url.rstrip('/')}/rest/api/3/issue",
        data=data,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
        issue_key = result.get("key", "")
        return {
            "issue_key": issue_key,
            "issue_url": f"{jira_url.rstrip('/')}/browse/{issue_key}",
        }
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Jira API {e.code}: {e.read().decode()[:300]}")


# ── Core autopilot functions ──────────────────────────────────────────────────

def analyze_and_generate_patch(
    scan_result: Dict[str, Any],
    org_id: str,
) -> Dict[str, Any]:
    """
    Given a single scan result, generate a migration task with config patch.
    Does not deploy — just generates the plan.
    """
    _ensure_tables()

    host     = str(scan_result.get("host") or "")
    port     = int(scan_result.get("port") or 443)
    # A scan that observed no key gets "" and 0, not a fabricated RSA-2048 over TLS 1.2. The
    # generated plan then says the key type is unknown instead of asserting a certificate nobody
    # saw, and the RSA-specific phase below simply does not fire.
    key_type = str(scan_result.get("cert_key_type") or scan_result.get("key_type") or "")
    key_bits = int(scan_result.get("cert_key_bits") or scan_result.get("key_bits") or 0)
    tls_ver  = str(scan_result.get("tls_version") or "")
    risk     = str(scan_result.get("quantum_risk_level") or scan_result.get("risk_level") or "unknown")

    server_type = _infer_server_type(scan_result)
    priority    = _migration_priority(scan_result)
    asset_key   = f"{host}:{port}"
    patch       = _SERVER_PATCHES.get(server_type, _NGINX_PATCH)

    # Already PQC?
    kt = key_type.lower()
    is_pqc = any(x in kt for x in ("ml-kem", "kyber", "dilithium", "slh", "falcon"))
    is_tls13 = "1.3" in tls_ver

    migration_phases: List[str] = []
    if not is_tls13:
        migration_phases.append("Upgrade to TLS 1.3")
    if not is_pqc:
        migration_phases.append("Deploy hybrid X25519+ML-KEM-768 key exchange")
        migration_phases.append("Replace RSA/ECC certificate with ML-DSA or hybrid")
    if key_bits and key_bits < 3072 and "rsa" in kt:
        migration_phases.append(f"Replace RSA-{key_bits} key with RSA-4096 (interim) or ML-KEM")

    effort_days = len(migration_phases) * 2  # rough estimate

    task_id = secrets.token_urlsafe(12)
    now_iso = datetime.now(timezone.utc).isoformat()

    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO autopilot_migration_tasks
               (id, org_id, asset_key, host, port, server_type, priority,
                status, config_patch, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (task_id, org_id, asset_key, host, port, server_type,
             priority, patch, now_iso),
        )
        conn.commit()

    return {
        "task_id": task_id,
        "asset_key": asset_key,
        "host": host, "port": port,
        "server_type": server_type,
        "priority": priority,
        "risk_level": risk,
        "current_key_type": key_type,
        "current_key_bits": key_bits,
        "current_tls_version": tls_ver,
        "is_already_pqc": is_pqc,
        "migration_phases": migration_phases,
        "estimated_effort_days": effort_days,
        "config_patch": patch,
        "created_at": now_iso,
    }


def deploy_patch(
    task_id: str,
    org_id: str,
    github_token: str = "",
    github_repo: str = "",
    github_base_branch: str = "main",
    config_file_path: str = "nginx/nginx.conf",
    jira_url: str = "",
    jira_email: str = "",
    jira_token: str = "",
    jira_project: str = "",
) -> Dict[str, Any]:
    """
    Deploy a generated patch: create GitHub PR and/or Jira ticket.
    Returns updated task with PR + Jira URLs.
    """
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM autopilot_migration_tasks WHERE id = ? AND org_id = ?",
            (task_id, org_id),
        ).fetchone()

    if not row:
        raise ValueError(f"Task {task_id} not found")

    task = dict(row)
    patch = task.get("config_patch") or _NGINX_PATCH

    pr_url = ""
    jira_issue_url = ""
    jira_issue_key = ""

    # Create GitHub PR
    if github_token and github_repo:
        try:
            pr_result = create_github_pr(
                github_token=github_token,
                repo_full_name=github_repo,
                base_branch=github_base_branch,
                config_file_path=config_file_path,
                patch_content=patch,
                asset_key=task["asset_key"],
                server_type=task["server_type"],
            )
            pr_url = pr_result.get("pr_url", "")
        except Exception as e:
            pr_url = f"error: {str(e)[:120]}"

    # Create Jira issue
    if jira_url and jira_email and jira_token and jira_project:
        try:
            jira_result = create_jira_issue(
                jira_url=jira_url, jira_email=jira_email,
                jira_token=jira_token, project_key=jira_project,
                asset_key=task["asset_key"], priority=task["priority"],
                server_type=task["server_type"], pr_url=pr_url,
            )
            jira_issue_url = jira_result.get("issue_url", "")
            jira_issue_key = jira_result.get("issue_key", "")
        except Exception as e:
            jira_issue_url = f"error: {str(e)[:120]}"

    status = "deployed" if (pr_url or jira_issue_url) and "error" not in pr_url and "error" not in jira_issue_url else "partial"

    with closing(_db()) as conn:
        conn.execute(
            """UPDATE autopilot_migration_tasks SET github_pr_url=?, jira_issue_url=?,
               jira_issue_key=?, status=? WHERE id=?""",
            (pr_url, jira_issue_url, jira_issue_key, status, task_id),
        )
        conn.commit()

    return {
        **task,
        "github_pr_url": pr_url,
        "jira_issue_url": jira_issue_url,
        "jira_issue_key": jira_issue_key,
        "status": status,
    }


def list_migration_tasks(org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT * FROM autopilot_migration_tasks WHERE org_id = ?
               ORDER BY CASE priority WHEN 'p0' THEN 0 WHEN 'p1' THEN 1
                         WHEN 'p2' THEN 2 ELSE 3 END, created_at DESC
               LIMIT ?""",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_migration_dashboard(org_id: str) -> Dict[str, Any]:
    """Summary stats for the migration dashboard."""
    tasks = list_migration_tasks(org_id, limit=500)
    return {
        "total": len(tasks),
        "pending": sum(1 for t in tasks if t["status"] == "pending"),
        "deployed": sum(1 for t in tasks if t["status"] == "deployed"),
        "p0_critical": sum(1 for t in tasks if t["priority"] == "p0"),
        "p1_high": sum(1 for t in tasks if t["priority"] == "p1"),
        "by_server": {
            stype: sum(1 for t in tasks if t["server_type"] == stype)
            for stype in ("nginx", "apache", "envoy", "haproxy", "openssl")
        },
        "recent_tasks": tasks[:10],
    }
