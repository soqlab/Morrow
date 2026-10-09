"""
Developer Self-Service Portal.
Lets individual developers view findings scoped to their team/repo and
submit remediation requests that admins can approve or reject.
"""
from __future__ import annotations
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_DDL = [
    """CREATE TABLE IF NOT EXISTS dev_teams (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        name TEXT NOT NULL,
        repo TEXT,
        tags TEXT NOT NULL DEFAULT '[]',
        members TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        UNIQUE(organization_id, name)
    )""",
    """CREATE TABLE IF NOT EXISTS dev_remediation_requests (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        requester_id TEXT NOT NULL,
        team TEXT NOT NULL DEFAULT '',
        repo TEXT NOT NULL DEFAULT '',
        finding_ref TEXT NOT NULL,
        finding_type TEXT NOT NULL DEFAULT 'asset',
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        priority TEXT NOT NULL DEFAULT 'medium',
        status TEXT NOT NULL DEFAULT 'pending',
        reviewer_id TEXT,
        reviewer_note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
]

_VALID_PRIORITIES = {"low", "medium", "high", "critical"}
_VALID_STATUSES = {"pending", "approved", "rejected", "in_progress", "completed"}


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    conn.commit()


# ── Teams ──────────────────────────────────────────────────────────────────────

def create_team(conn: sqlite3.Connection, org_id: str, name: str, repo: str = "",
                tags: List[str] = None, members: List[str] = None) -> Dict:
    team_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO dev_teams (id, organization_id, name, repo, tags, members, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (team_id, org_id, name, repo or "", json.dumps(tags or []), json.dumps(members or []), now),
    )
    conn.commit()
    return get_team(conn, team_id)


def get_team(conn: sqlite3.Connection, team_id: str) -> Optional[Dict]:
    row = conn.execute(
        "SELECT id, organization_id, name, repo, tags, members, created_at FROM dev_teams WHERE id=?",
        (team_id,),
    ).fetchone()
    if not row:
        return None
    cols = ["id", "organization_id", "name", "repo", "tags", "members", "created_at"]
    d = dict(zip(cols, row))
    d["tags"] = json.loads(d["tags"])
    d["members"] = json.loads(d["members"])
    return d


def list_teams(conn: sqlite3.Connection, org_id: str) -> List[Dict]:
    rows = conn.execute(
        "SELECT id, organization_id, name, repo, tags, members, created_at FROM dev_teams WHERE organization_id=? ORDER BY name",
        (org_id,),
    ).fetchall()
    cols = ["id", "organization_id", "name", "repo", "tags", "members", "created_at"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d["tags"])
        d["members"] = json.loads(d["members"])
        result.append(d)
    return result


def delete_team(conn: sqlite3.Connection, team_id: str, org_id: str) -> bool:
    cur = conn.execute("DELETE FROM dev_teams WHERE id=? AND organization_id=?", (team_id, org_id))
    conn.commit()
    return cur.rowcount > 0


# ── Findings scoped to team/repo ───────────────────────────────────────────────

def list_findings_for_scope(conn: sqlite3.Connection, org_id: str,
                             team: str = "", repo: str = "") -> List[Dict]:
    """Return scan findings filtered by team tag or repo name."""
    findings: List[Dict] = []

    # Try scan_results table first (primary findings store)
    try:
        filters = ["organization_id=?"]
        params: List[Any] = [org_id]
        if repo:
            filters.append("(host=? OR host LIKE ?)")
            params.extend([repo, f"%{repo}%"])
        elif team:
            filters.append("(tags LIKE ? OR endpoint LIKE ?)")
            params.extend([f"%{team}%", f"%{team}%"])

        rows = conn.execute(
            f"SELECT host, endpoint, finding_type, severity, algorithm, vulnerability, remediation_hint, scan_ts "
            f"FROM scan_results WHERE {' AND '.join(filters)} ORDER BY scan_ts DESC LIMIT 200",
            params,
        ).fetchall()
        cols = ["host", "endpoint", "finding_type", "severity", "algorithm",
                "vulnerability", "remediation_hint", "scan_ts"]
        for row in rows:
            findings.append(dict(zip(cols, row)))
    except Exception:
        pass

    # Also pull from remediations table (tracks pending/assigned work)
    try:
        filters2 = ["organization_id=?", "status != 'closed'"]
        params2: List[Any] = [org_id]
        if repo:
            filters2.append("(asset_key LIKE ?)")
            params2.append(f"%{repo}%")
        elif team:
            filters2.append("(title LIKE ? OR description LIKE ?)")
            params2.extend([f"%{team}%", f"%{team}%"])

        rows2 = conn.execute(
            f"SELECT id, asset_key, title, status, severity, assigned_to, created_at "
            f"FROM remediations WHERE {' AND '.join(filters2)} ORDER BY created_at DESC LIMIT 200",
            params2,
        ).fetchall()
        cols2 = ["id", "asset_key", "title", "status", "severity", "assigned_to", "created_at"]
        for row in rows2:
            d = dict(zip(cols2, row))
            d["finding_type"] = "remediation"
            findings.append(d)
    except Exception:
        pass

    return findings


# ── Remediation Requests ───────────────────────────────────────────────────────

def create_request(conn: sqlite3.Connection, org_id: str, requester_id: str,
                   team: str, repo: str, finding_ref: str, finding_type: str,
                   title: str, description: str, priority: str) -> Dict:
    req_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    priority = priority if priority in _VALID_PRIORITIES else "medium"
    conn.execute(
        """INSERT INTO dev_remediation_requests
           (id, organization_id, requester_id, team, repo, finding_ref, finding_type,
            title, description, priority, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
        (req_id, org_id, requester_id, team, repo, finding_ref, finding_type,
         title, description, priority, now, now),
    )
    conn.commit()
    return get_request(conn, req_id)


def get_request(conn: sqlite3.Connection, req_id: str) -> Optional[Dict]:
    row = conn.execute(
        """SELECT id, organization_id, requester_id, team, repo, finding_ref, finding_type,
                  title, description, priority, status, reviewer_id, reviewer_note,
                  created_at, updated_at
           FROM dev_remediation_requests WHERE id=?""",
        (req_id,),
    ).fetchone()
    if not row:
        return None
    cols = ["id", "organization_id", "requester_id", "team", "repo", "finding_ref",
            "finding_type", "title", "description", "priority", "status",
            "reviewer_id", "reviewer_note", "created_at", "updated_at"]
    return dict(zip(cols, row))


def list_requests(conn: sqlite3.Connection, org_id: str,
                  requester_id: str = "", status: str = "") -> List[Dict]:
    filters = ["organization_id=?"]
    params: List[Any] = [org_id]
    if requester_id:
        filters.append("requester_id=?")
        params.append(requester_id)
    if status:
        filters.append("status=?")
        params.append(status)
    rows = conn.execute(
        f"""SELECT id, organization_id, requester_id, team, repo, finding_ref, finding_type,
                   title, description, priority, status, reviewer_id, reviewer_note,
                   created_at, updated_at
            FROM dev_remediation_requests WHERE {' AND '.join(filters)}
            ORDER BY created_at DESC LIMIT 500""",
        params,
    ).fetchall()
    cols = ["id", "organization_id", "requester_id", "team", "repo", "finding_ref",
            "finding_type", "title", "description", "priority", "status",
            "reviewer_id", "reviewer_note", "created_at", "updated_at"]
    return [dict(zip(cols, r)) for r in rows]


def update_request_status(conn: sqlite3.Connection, req_id: str, org_id: str,
                          status: str, reviewer_id: str, reviewer_note: str = "") -> Optional[Dict]:
    status = status if status in _VALID_STATUSES else "pending"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE dev_remediation_requests
           SET status=?, reviewer_id=?, reviewer_note=?, updated_at=?
           WHERE id=? AND organization_id=?""",
        (status, reviewer_id, reviewer_note, now, req_id, org_id),
    )
    conn.commit()
    return get_request(conn, req_id)


def get_portal_stats(conn: sqlite3.Connection, org_id: str) -> Dict:
    """Summary counts for the dev portal dashboard."""
    try:
        row = conn.execute(
            """SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
                 SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
                 SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected,
                 SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed
               FROM dev_remediation_requests WHERE organization_id=?""",
            (org_id,),
        ).fetchone()
        team_count = conn.execute(
            "SELECT COUNT(*) FROM dev_teams WHERE organization_id=?", (org_id,)
        ).fetchone()[0]
        return {
            "total_requests": row[0] or 0,
            "pending": row[1] or 0,
            "approved": row[2] or 0,
            "rejected": row[3] or 0,
            "completed": row[4] or 0,
            "team_count": team_count or 0,
        }
    except Exception:
        return {"total_requests": 0, "pending": 0, "approved": 0,
                "rejected": 0, "completed": 0, "team_count": 0}
