"""
Multi-Tenant Admin Console

Platform-level organization management:
  - Create / update / delete organizations
  - Invite users by email and assign roles
  - Role management: platform_admin / org_admin / analyst / viewer
  - Per-org usage statistics (scan counts, asset counts, API calls)
  - Rate-limit overrides per org
  - Audit log of all admin actions

Tables: admin_orgs, admin_users, admin_invitations, admin_audit_log, admin_rate_limits
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn
from typing import Any, Dict, List, Optional


VALID_ROLES = {"platform_admin", "org_admin", "analyst", "viewer"}
VALID_STATUSES = {"active", "suspended", "pending"}


# ── DB ─────────────────────────────────────────────────────────────────────────

def _init_tables() -> None:
    with feature_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS admin_orgs (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                domain      TEXT,
                plan        TEXT NOT NULL DEFAULT 'free',
                status      TEXT NOT NULL DEFAULT 'active',
                max_assets  INTEGER NOT NULL DEFAULT 100,
                max_scans   INTEGER NOT NULL DEFAULT 500,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_users (
                id          TEXT PRIMARY KEY,
                org_id      TEXT NOT NULL,
                email       TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'viewer',
                status      TEXT NOT NULL DEFAULT 'active',
                last_login  TEXT,
                created_at  TEXT NOT NULL,
                UNIQUE(org_id, email)
            );

            CREATE TABLE IF NOT EXISTS admin_invitations (
                token       TEXT PRIMARY KEY,
                org_id      TEXT NOT NULL,
                email       TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'viewer',
                invited_by  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                accepted    INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id      TEXT,
                actor_email TEXT NOT NULL,
                action      TEXT NOT NULL,
                target_type TEXT,
                target_id   TEXT,
                detail      TEXT,
                ip_address  TEXT,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_rate_limits (
                org_id          TEXT PRIMARY KEY,
                scans_per_hour  INTEGER NOT NULL DEFAULT 60,
                api_calls_per_min INTEGER NOT NULL DEFAULT 100,
                updated_at      TEXT NOT NULL
            );
        """)
        conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def invite_reference(token: str) -> str:
    """The non-secret id for an invitation: a SHA-256 prefix of its token.

    Same derivation as services/platform_access.invite_id, kept here so this module never has to
    write a token into a row that is read back by an API. Defined locally rather than imported
    because platform_access imports this module.
    """
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:20]


def _audit(conn: Any, org_id: Optional[str], actor: str,
           action: str, target_type: str = "", target_id: str = "",
           detail: str = "", ip: str = "") -> None:
    conn.execute(
        "INSERT INTO admin_audit_log (org_id,actor_email,action,target_type,target_id,detail,ip_address,created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (org_id, actor, action, target_type, target_id, detail, ip, _now()),
    )


# ── Organization management ────────────────────────────────────────────────────

def create_org(
    name: str,
    domain: str = "",
    plan: str = "free",
    max_assets: int = 100,
    max_scans: int = 500,
    actor: str = "system",
) -> Dict[str, Any]:
    _init_tables()
    org_id = secrets.token_hex(8)
    now = _now()
    with feature_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO admin_orgs (id,name,domain,plan,status,max_assets,max_scans,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (org_id, name, domain, plan, "active", max_assets, max_scans, now, now),
            )
            _audit(conn, org_id, actor, "create_org", "org", org_id, f"name={name} plan={plan}")
            conn.commit()
        except INTEGRITY_ERRORS as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True, "org_id": org_id, "name": name, "plan": plan, "status": "active", "created_at": now}


def update_org(
    org_id: str,
    name: Optional[str] = None,
    domain: Optional[str] = None,
    plan: Optional[str] = None,
    status: Optional[str] = None,
    max_assets: Optional[int] = None,
    max_scans: Optional[int] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM admin_orgs WHERE id=?", (org_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "Org not found"}
        updates: Dict[str, Any] = {}
        if name is not None:      updates["name"]       = name
        if domain is not None:    updates["domain"]     = domain
        if plan is not None:      updates["plan"]       = plan
        if status is not None:
            if status not in VALID_STATUSES:
                return {"ok": False, "error": f"Invalid status: {status}"}
            updates["status"] = status
        if max_assets is not None: updates["max_assets"] = max_assets
        if max_scans is not None:  updates["max_scans"]  = max_scans
        if not updates:
            return {"ok": True, "org_id": org_id, "changed": 0}
        updates["updated_at"] = _now()
        set_clause = ", ".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE admin_orgs SET {set_clause} WHERE id=?", (*updates.values(), org_id))
        _audit(conn, org_id, actor, "update_org", "org", org_id, json.dumps(updates))
        conn.commit()
    return {"ok": True, "org_id": org_id, "changed": len(updates)}


def delete_org(org_id: str, actor: str = "system") -> Dict[str, Any]:
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT id FROM admin_orgs WHERE id=?", (org_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "Org not found"}
        conn.execute("UPDATE admin_orgs SET status='suspended', updated_at=? WHERE id=?", (_now(), org_id))
        _audit(conn, org_id, actor, "delete_org", "org", org_id)
        conn.commit()
    return {"ok": True, "org_id": org_id, "status": "suspended"}


def list_orgs(status_filter: str = "", org_id: str = "") -> List[Dict[str, Any]]:
    """The organization registry. `org_id` restricts it to one tenant, which is what a customer
    administrator gets: the unfiltered listing is the vendor's view of every customer."""
    _init_tables()
    clauses, params = [], []
    if status_filter:
        clauses.append("status=?")
        params.append(status_filter)
    if org_id:
        clauses.append("id=?")
        params.append(str(org_id))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with feature_conn() as conn:
        rows = conn.execute(f"SELECT * FROM admin_orgs{where} ORDER BY created_at DESC", tuple(params)).fetchall()
    return [dict(r) for r in rows]


def get_org(org_id: str) -> Optional[Dict[str, Any]]:
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM admin_orgs WHERE id=?", (org_id,)).fetchone()
    return dict(row) if row else None


# ── User management ────────────────────────────────────────────────────────────

def invite_user(
    org_id: str,
    email: str,
    role: str,
    invited_by: str,
    expires_hours: int = 72,
) -> Dict[str, Any]:
    if role not in VALID_ROLES:
        return {"ok": False, "error": f"Invalid role: {role}. Valid: {sorted(VALID_ROLES)}"}
    _init_tables()
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=expires_hours)).isoformat()
    now = _now()
    # The audit row names the invitation by its non-secret id, never by its bearer token. The token
    # used to be written here as target_id, which made admin_audit_log a durable cleartext store of
    # live invitation credentials that outlived revocation and was served to any admin.
    reference = invite_reference(token)
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO admin_invitations (token,org_id,email,role,invited_by,expires_at,created_at) VALUES (?,?,?,?,?,?,?)",
            (token, org_id, email, role, invited_by, expires, now),
        )
        _audit(conn, org_id, invited_by, "invite_user", "invitation", reference, f"email={email} role={role}")
        conn.commit()
    return {
        "ok":         True,
        "token":      token,          # for the caller to build the one-time link with; never stored or logged
        "invite_id":  reference,
        "email":      email,
        "role":       role,
        "expires_at": expires,
        "invite_url": "/admin/accept-invite",   # POST the token in the body; never in a URL
    }


def accept_invitation(token: str) -> Dict[str, Any]:
    _init_tables()
    with feature_conn() as conn:
        inv = conn.execute("SELECT * FROM admin_invitations WHERE token=?", (token,)).fetchone()
        if not inv:
            return {"ok": False, "error": "Invalid invitation token"}
        if inv["accepted"]:
            return {"ok": False, "error": "Invitation already accepted"}
        expires = datetime.fromisoformat(inv["expires_at"])
        if datetime.now(timezone.utc) > expires:
            return {"ok": False, "error": "Invitation expired"}

        user_id = secrets.token_hex(8)
        now = _now()
        try:
            # Savepoint-scoped: on Postgres a constraint failure aborts the whole
            # transaction, so without this the UPDATE below -- and the two
            # statements after it -- would fail rather than recover.
            with atomic(conn):
                conn.execute(
                    "INSERT INTO admin_users (id,org_id,email,role,status,created_at) VALUES (?,?,?,?,?,?)",
                    (user_id, inv["org_id"], inv["email"], inv["role"], "active", now),
                )
        except INTEGRITY_ERRORS:
            conn.execute(
                "UPDATE admin_users SET role=?, status='active' WHERE org_id=? AND email=?",
                (inv["role"], inv["org_id"], inv["email"]),
            )
        conn.execute("UPDATE admin_invitations SET accepted=1 WHERE token=?", (token,))
        _audit(conn, inv["org_id"], inv["email"], "accept_invitation", "user", user_id)
        conn.commit()
    return {"ok": True, "user_id": user_id, "org_id": inv["org_id"], "email": inv["email"], "role": inv["role"]}


def list_users(org_id: str) -> List[Dict[str, Any]]:
    _init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT id,email,role,status,last_login,created_at FROM admin_users WHERE org_id=? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def update_user_role(
    org_id: str,
    email: str,
    new_role: str,
    actor: str = "system",
) -> Dict[str, Any]:
    if new_role not in VALID_ROLES:
        return {"ok": False, "error": f"Invalid role: {new_role}"}
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT id FROM admin_users WHERE org_id=? AND email=?", (org_id, email)).fetchone()
        if not row:
            return {"ok": False, "error": "User not found"}
        conn.execute("UPDATE admin_users SET role=? WHERE org_id=? AND email=?", (new_role, org_id, email))
        _audit(conn, org_id, actor, "update_role", "user", row[0], f"email={email} new_role={new_role}")
        conn.commit()
    return {"ok": True, "email": email, "role": new_role}


def remove_user(org_id: str, email: str, actor: str = "system") -> Dict[str, Any]:
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT id FROM admin_users WHERE org_id=? AND email=?", (org_id, email)).fetchone()
        if not row:
            return {"ok": False, "error": "User not found"}
        conn.execute("UPDATE admin_users SET status='suspended' WHERE org_id=? AND email=?", (org_id, email))
        _audit(conn, org_id, actor, "remove_user", "user", row[0], f"email={email}")
        conn.commit()
    return {"ok": True, "email": email, "status": "suspended"}


def list_pending_invitations(org_id: str) -> List[Dict[str, Any]]:
    """Pending invitations, identified by their non-secret invite id.

    This used to select `token` and return the row verbatim, so listing invitations handed the
    caller live bearer credentials for every outstanding invitation. The token is shown exactly
    once, in the link returned when the invitation is created.
    """
    _init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT token,email,role,invited_by,expires_at,created_at FROM admin_invitations "
            "WHERE org_id=? AND accepted=0 ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        d = dict(r)
        d["invite_id"] = invite_reference(d.pop("token", ""))
        d["expired"] = datetime.fromisoformat(r["expires_at"]) < now
        out.append(d)
    return out


# ── Rate limit overrides ───────────────────────────────────────────────────────

def set_rate_limits(
    org_id: str,
    scans_per_hour: int,
    api_calls_per_min: int,
    actor: str = "system",
) -> Dict[str, Any]:
    _init_tables()
    now = _now()
    with feature_conn() as conn:
        conn.execute(
            """
            INSERT INTO admin_rate_limits (org_id, scans_per_hour, api_calls_per_min, updated_at)
            VALUES (?,?,?,?)
            ON CONFLICT(org_id) DO UPDATE SET
                scans_per_hour=excluded.scans_per_hour,
                api_calls_per_min=excluded.api_calls_per_min,
                updated_at=excluded.updated_at
            """,
            (org_id, scans_per_hour, api_calls_per_min, now),
        )
        _audit(conn, org_id, actor, "set_rate_limits", "org", org_id,
               f"scans/hr={scans_per_hour} api/min={api_calls_per_min}")
        conn.commit()
    return {"ok": True, "org_id": org_id, "scans_per_hour": scans_per_hour, "api_calls_per_min": api_calls_per_min}


def get_rate_limits(org_id: str) -> Dict[str, Any]:
    _init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM admin_rate_limits WHERE org_id=?", (org_id,)).fetchone()
    if row:
        return dict(row)
    return {"org_id": org_id, "scans_per_hour": 60, "api_calls_per_min": 100, "updated_at": None}


# ── Usage statistics ───────────────────────────────────────────────────────────

def get_org_usage(org_id: str) -> Dict[str, Any]:
    """Return scan counts, asset counts, and user counts for an org."""
    _init_tables()
    # The cut-off is computed here rather than in SQL: datetime('now', …) is SQLite-only and made this
    # endpoint fail with a 500 on a Postgres feature store. created_at columns hold ISO-8601 text.
    cutoff_30d = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    with feature_conn() as conn:
        # Scan counts (if scans table exists)
        try:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE organization_id=?", (org_id,)).fetchone()[0]
            scans_30d   = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE organization_id=? AND created_at >= ?",
                (org_id, cutoff_30d),
            ).fetchone()[0]
        except Exception:
            total_scans = scans_30d = 0

        # Asset counts
        try:
            total_assets = conn.execute("SELECT COUNT(DISTINCT asset_key) FROM scan_results WHERE organization_id=?", (org_id,)).fetchone()[0]
        except Exception:
            total_assets = 0

        # User counts
        user_count = conn.execute(
            "SELECT COUNT(*) FROM admin_users WHERE org_id=? AND status='active'", (org_id,)
        ).fetchone()[0]

        pending_invites = conn.execute(
            "SELECT COUNT(*) FROM admin_invitations WHERE org_id=? AND accepted=0", (org_id,)
        ).fetchone()[0]

        # Audit actions last 30d
        audit_30d = conn.execute(
            "SELECT COUNT(*) FROM admin_audit_log WHERE org_id=? AND created_at >= ?",
            (org_id, cutoff_30d),
        ).fetchone()[0]

    org = get_org(org_id) or {}
    rate = get_rate_limits(org_id)

    return {
        "org_id":          org_id,
        "org_name":        org.get("name", ""),
        "plan":            org.get("plan", ""),
        "status":          org.get("status", ""),
        "max_assets":      org.get("max_assets", 100),
        "max_scans":       org.get("max_scans", 500),
        "total_scans":     total_scans,
        "scans_30d":       scans_30d,
        "total_assets":    total_assets,
        "active_users":    user_count,
        "pending_invites": pending_invites,
        "audit_actions_30d": audit_30d,
        "scans_per_hour":  rate["scans_per_hour"],
        "api_calls_per_min": rate["api_calls_per_min"],
    }


def platform_overview(org_id: str = "") -> Dict[str, Any]:
    """Aggregate stats for the admin view.

    `org_id` scopes every number and the recent-activity list to one tenant, which is what a
    customer administrator gets. Without it this is the vendor's cross-tenant view, and the
    recent-activity list alone names other customers' administrators and the actions taken on them.
    """
    _init_tables()
    scope = str(org_id or "")
    org_where, org_args = (" WHERE id=?", (scope,)) if scope else ("", ())
    tenant_where, tenant_args = (" WHERE org_id=?", (scope,)) if scope else ("", ())
    with feature_conn() as conn:
        total_orgs   = conn.execute(f"SELECT COUNT(*) FROM admin_orgs{org_where}", org_args).fetchone()[0]
        active_orgs  = conn.execute(
            "SELECT COUNT(*) FROM admin_orgs WHERE status='active'" + (" AND id=?" if scope else ""), org_args
        ).fetchone()[0]
        total_users  = conn.execute(
            "SELECT COUNT(*) FROM admin_users WHERE status='active'" + (" AND org_id=?" if scope else ""), org_args
        ).fetchone()[0]
        total_invites= conn.execute(
            "SELECT COUNT(*) FROM admin_invitations WHERE accepted=0" + (" AND org_id=?" if scope else ""), org_args
        ).fetchone()[0]
        by_plan = {}
        for row in conn.execute(f"SELECT plan, COUNT(*) FROM admin_orgs{org_where} GROUP BY plan", org_args).fetchall():
            by_plan[row[0]] = row[1]
        try:
            if scope:
                total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE organization_id=?", (scope,)).fetchone()[0]
            else:
                total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        except Exception:
            total_scans = 0
        recent_audit = conn.execute(
            f"SELECT actor_email,action,target_type,target_id,created_at FROM admin_audit_log{tenant_where} "
            "ORDER BY id DESC LIMIT 20", tenant_args
        ).fetchall()

    return {
        "scope": scope or "platform",
        "total_orgs":   total_orgs,
        "active_orgs":  active_orgs,
        "total_users":  total_users,
        "pending_invites": total_invites,
        "orgs_by_plan": by_plan,
        "total_scans":  total_scans,
        "recent_audit": [
            {"actor": r[0], "action": r[1], "target_type": r[2], "target_id": r[3], "at": r[4]}
            for r in recent_audit
        ],
    }


# ── Audit log ──────────────────────────────────────────────────────────────────

def get_audit_log(
    org_id: Optional[str] = None,
    limit: int = 100,
    action_filter: str = "",
) -> List[Dict[str, Any]]:
    """Admin audit rows. `org_id=None` reads every tenant's rows and is a platform-operator view;
    callers that are not platform operators must always pass the tenant they are scoped to (the
    route at GET /admin/audit-log does)."""
    _init_tables()
    with feature_conn() as conn:
        if org_id and action_filter:
            rows = conn.execute(
                "SELECT * FROM admin_audit_log WHERE org_id=? AND action LIKE ? ORDER BY id DESC LIMIT ?",
                (org_id, f"%{action_filter}%", limit),
            ).fetchall()
        elif org_id:
            rows = conn.execute(
                "SELECT * FROM admin_audit_log WHERE org_id=? ORDER BY id DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        elif action_filter:
            rows = conn.execute(
                "SELECT * FROM admin_audit_log WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{action_filter}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM admin_audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]
