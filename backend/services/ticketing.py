"""
Ticketing integration: create issues in Jira or ServiceNow from post-quantum findings.

Jira config (store as credentials via vault or env):
  JIRA_URL          e.g. https://yourco.atlassian.net
  JIRA_USER         e.g. user@yourco.com
  JIRA_API_TOKEN    API token (not password)
  JIRA_PROJECT_KEY  e.g. SEC
  JIRA_ISSUE_TYPE   e.g. Bug (default)

ServiceNow config:
  SNOW_INSTANCE     e.g. yourco.service-now.com
  SNOW_USER         e.g. admin
  SNOW_PASSWORD     ServiceNow password or OAuth token
  SNOW_TABLE        incident or sc_task (default: incident)
"""

from __future__ import annotations

import base64
import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple


# ── Shared helpers ────────────────────────────────────────────────────────────

def _http_post(url: str, payload: Dict[str, Any],
               headers: Dict[str, str], timeout: int = 20) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": body[:500]}


def _severity_to_priority_jira(severity: str) -> str:
    return {"critical": "Highest", "high": "High",
            "medium": "Medium", "low": "Low", "info": "Low"}.get(
        (severity or "").lower(), "Medium")


def _severity_to_priority_snow(severity: str) -> str:
    # ServiceNow: 1=Critical, 2=High, 3=Moderate, 4=Low
    return {"critical": "1", "high": "2", "medium": "3",
            "low": "4", "info": "4"}.get((severity or "").lower(), "3")


# ── Jira ─────────────────────────────────────────────────────────────────────

def _jira_headers(url: str = "", user: str = "", token: str = "") -> Dict[str, str]:
    jira_url  = url   or os.getenv("JIRA_URL", "").strip()
    jira_user = user  or os.getenv("JIRA_USER", "").strip()
    jira_tok  = token or os.getenv("JIRA_API_TOKEN", "").strip()
    if not (jira_url and jira_user and jira_tok):
        raise ValueError("JIRA_URL, JIRA_USER, and JIRA_API_TOKEN are all required.")
    cred = base64.b64encode(f"{jira_user}:{jira_tok}".encode()).decode()
    return {
        "Authorization": f"Basic {cred}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def create_jira_issue(
    finding: Dict[str, Any],
    asset_key: str,
    *,
    jira_url: str = "",
    jira_user: str = "",
    jira_api_token: str = "",
    project_key: str = "",
    issue_type: str = "",
    extra_labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a single Jira issue from a post-quantum finding. Returns the created issue key/URL."""
    url      = jira_url      or os.getenv("JIRA_URL", "").strip().rstrip("/")
    user     = jira_user     or os.getenv("JIRA_USER", "").strip()
    token    = jira_api_token or os.getenv("JIRA_API_TOKEN", "").strip()
    proj     = project_key   or os.getenv("JIRA_PROJECT_KEY", "SEC").strip()
    itype    = issue_type    or os.getenv("JIRA_ISSUE_TYPE", "Bug").strip()

    severity = (finding.get("severity") or "medium").lower()
    title    = finding.get("title") or finding.get("rule_id") or "Post-Quantum Finding"
    fix      = finding.get("fix") or ""
    evidence = finding.get("evidence") or {}
    rule_id  = finding.get("rule_id") or ""
    pq_note = finding.get("pq_note") or ""

    labels = ["morrow", "post-quantum", severity] + (extra_labels or [])

    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "heading", "attrs": {"level": 3},
             "content": [{"type": "text", "text": f"Asset: {asset_key}"}]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": f"Severity: {severity.upper()}  |  Rule: {rule_id}"}]},
            {"type": "heading", "attrs": {"level": 4},
             "content": [{"type": "text", "text": "Remediation"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": fix or "See Morrow for details."}]},
            *([{"type": "heading", "attrs": {"level": 4},
                "content": [{"type": "text", "text": "Post-Quantum Note"}]},
               {"type": "paragraph", "content": [{"type": "text", "text": pq_note}]}]
              if pq_note else []),
            {"type": "heading", "attrs": {"level": 4},
             "content": [{"type": "text", "text": "Evidence"}]},
            {"type": "codeBlock", "attrs": {"language": "json"},
             "content": [{"type": "text",
                          "text": json.dumps(evidence, indent=2, default=str)}]},
        ],
    }

    payload = {
        "fields": {
            "project":     {"key": proj},
            "summary":     f"[post-quantum] {title} — {asset_key}",
            "description": description,
            "issuetype":   {"name": itype},
            "priority":    {"name": _severity_to_priority_jira(severity)},
            "labels":      labels,
        }
    }

    status, resp = _http_post(
        f"{url}/rest/api/3/issue",
        payload,
        _jira_headers(url, user, token),
    )

    if status in (200, 201):
        key = resp.get("key", "")
        return {"success": True, "issue_key": key,
                "url": f"{url}/browse/{key}" if key else ""}
    return {"success": False, "status": status, "error": resp}


def create_jira_issues_bulk(
    findings_with_assets: List[Dict[str, Any]],
    **kwargs,
) -> List[Dict[str, Any]]:
    """
    Create one Jira issue per finding.

    findings_with_assets: list of dicts, each with keys:
      finding (dict), asset_key (str)
    """
    results = []
    for item in findings_with_assets:
        try:
            r = create_jira_issue(item["finding"], item["asset_key"], **kwargs)
        except Exception as exc:
            r = {"success": False, "error": str(exc)}
        results.append(r)
    return results


# ── ServiceNow ───────────────────────────────────────────────────────────────

def _snow_headers(user: str = "", password: str = "") -> Dict[str, str]:
    u = user     or os.getenv("SNOW_USER", "").strip()
    p = password or os.getenv("SNOW_PASSWORD", "").strip()
    if not (u and p):
        raise ValueError("SNOW_USER and SNOW_PASSWORD are required.")
    cred = base64.b64encode(f"{u}:{p}".encode()).decode()
    return {
        "Authorization": f"Basic {cred}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def create_servicenow_incident(
    finding: Dict[str, Any],
    asset_key: str,
    *,
    snow_instance: str = "",
    snow_user: str = "",
    snow_password: str = "",
    table: str = "",
    caller_id: str = "",
    assignment_group: str = "",
) -> Dict[str, Any]:
    """Create a ServiceNow incident or task from a post-quantum finding."""
    instance = (snow_instance or os.getenv("SNOW_INSTANCE", "")).strip().rstrip("/")
    tab      = table or os.getenv("SNOW_TABLE", "incident").strip()

    if not instance:
        raise ValueError("SNOW_INSTANCE is required (e.g. yourco.service-now.com).")

    severity  = (finding.get("severity") or "medium").lower()
    title     = finding.get("title") or finding.get("rule_id") or "Post-Quantum Finding"
    fix       = finding.get("fix") or ""
    evidence  = finding.get("evidence") or {}
    pq_note  = finding.get("pq_note") or ""

    description = (
        f"Asset: {asset_key}\n"
        f"Severity: {severity.upper()}\n"
        f"Rule: {finding.get('rule_id', '')}\n\n"
        f"Remediation:\n{fix}\n\n"
        + (f"Post-Quantum Note:\n{pq_note}\n\n" if pq_note else "")
        + f"Evidence:\n{json.dumps(evidence, indent=2, default=str)}"
    )

    payload: Dict[str, Any] = {
        "short_description": f"[Morrow] {title} — {asset_key}",
        "description": description,
        "urgency": _severity_to_priority_snow(severity),
        "impact":  _severity_to_priority_snow(severity),
        "category": "Security",
        "subcategory": "Post-Quantum Cryptography",
    }
    if caller_id:
        payload["caller_id"] = caller_id
    if assignment_group:
        payload["assignment_group"] = {"name": assignment_group}

    instance_url = instance if instance.startswith("http") else f"https://{instance}"
    status, resp = _http_post(
        f"{instance_url}/api/now/table/{tab}",
        payload,
        _snow_headers(snow_user, snow_password),
    )

    if status in (200, 201):
        result_body = resp.get("result") or resp
        sys_id  = result_body.get("sys_id", "")
        num     = result_body.get("number", "")
        return {
            "success": True,
            "sys_id":  sys_id,
            "number":  num,
            "url": f"{instance_url}/nav_to.do?uri={tab}.do?sys_id={sys_id}" if sys_id else "",
        }
    return {"success": False, "status": status, "error": resp}


def create_servicenow_bulk(
    findings_with_assets: List[Dict[str, Any]],
    **kwargs,
) -> List[Dict[str, Any]]:
    results = []
    for item in findings_with_assets:
        try:
            r = create_servicenow_incident(item["finding"], item["asset_key"], **kwargs)
        except Exception as exc:
            r = {"success": False, "error": str(exc)}
        results.append(r)
    return results


# ── Wave 15: DB-backed ticketing config + history ─────────────────────────────
import sqlite3
from datetime import datetime, timezone

_DDL = [
    """CREATE TABLE IF NOT EXISTS ticket_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        config TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL,
        UNIQUE(organization_id, provider)
    )""",
    """CREATE TABLE IF NOT EXISTS auto_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        finding_ref TEXT NOT NULL,
        finding_type TEXT NOT NULL DEFAULT 'remediation',
        ticket_url TEXT NOT NULL,
        ticket_id TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'medium',
        title TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
]


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    conn.commit()


def save_config(conn: sqlite3.Connection, org_id: str, provider: str, config: Dict) -> None:
    conn.execute(
        """INSERT INTO ticket_configs (organization_id, provider, config, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(organization_id, provider) DO UPDATE
           SET config=excluded.config, updated_at=excluded.updated_at""",
        (org_id, provider, json.dumps(config), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def get_config(conn: sqlite3.Connection, org_id: str, provider: str) -> Optional[Dict]:
    row = conn.execute(
        "SELECT config FROM ticket_configs WHERE organization_id=? AND provider=?",
        (org_id, provider),
    ).fetchone()
    return json.loads(row[0]) if row else None


def list_configs(conn: sqlite3.Connection, org_id: str) -> List[Dict]:
    rows = conn.execute(
        "SELECT provider, config, updated_at FROM ticket_configs WHERE organization_id=?",
        (org_id,),
    ).fetchall()
    return [{"provider": r[0], "config": json.loads(r[1]), "updated_at": r[2]} for r in rows]


def create_ticket(
    conn: sqlite3.Connection,
    org_id: str,
    provider: str,
    finding_ref: str,
    finding_type: str,
    title: str,
    body: str,
    severity: str = "medium",
) -> Dict:
    cfg = get_config(conn, org_id, provider)
    if not cfg:
        raise ValueError(f"No {provider} config found for org {org_id}")

    if provider == "jira":
        result = create_jira_issue(
            title, finding_ref,
            jira_url=cfg.get("base_url", ""),
            jira_user=cfg.get("email", ""),
            jira_api_token=cfg.get("api_token", ""),
            jira_project_key=cfg.get("project_key", ""),
            jira_issue_type=cfg.get("issue_type", "Bug"),
        )
        ticket_url = result.get("issue_url", "")
        ticket_id = result.get("issue_key", "")
    elif provider == "github":
        # Use stdlib approach for GitHub Issues
        import urllib.request
        import urllib.error
        gh_headers = {
            "Authorization": f"Bearer {cfg.get('token','')}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        labels = cfg.get("labels", ["pq-finding"])
        if isinstance(labels, str):
            labels = [label.strip() for label in labels.split(",") if label.strip()]
        payload_bytes = json.dumps({"title": title, "body": body, "labels": labels}).encode()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{cfg['owner']}/{cfg['repo']}/issues",
            data=payload_bytes, headers=gh_headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        ticket_url = data.get("html_url", "")
        ticket_id = str(data.get("number", ""))
        result = {"ticket_url": ticket_url, "ticket_id": ticket_id, "provider": "github"}
    else:
        raise ValueError(f"Unknown provider: {provider}")

    if not ticket_url:
        raise ValueError(f"Failed to create ticket via {provider}")

    conn.execute(
        """INSERT INTO auto_tickets
           (organization_id, provider, finding_ref, finding_type, ticket_url, ticket_id, severity, title, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (org_id, provider, finding_ref, finding_type,
         ticket_url, ticket_id, severity, title,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return {"ticket_id": ticket_id, "ticket_url": ticket_url, "provider": provider}


def list_tickets(conn: sqlite3.Connection, org_id: str, limit: int = 100) -> List[Dict]:
    rows = conn.execute(
        """SELECT id, provider, finding_ref, finding_type, ticket_url, ticket_id,
                  severity, title, created_at
           FROM auto_tickets WHERE organization_id=? ORDER BY created_at DESC LIMIT ?""",
        (org_id, limit),
    ).fetchall()
    cols = ["id", "provider", "finding_ref", "finding_type", "ticket_url",
            "ticket_id", "severity", "title", "created_at"]
    return [dict(zip(cols, r)) for r in rows]
