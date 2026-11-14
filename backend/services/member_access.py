"""One place that changes what a person may do in an organization, and takes it away at once.

A person's access to an organization was written in up to three places, and each route wrote some:

  * organization_memberships (db.py): their role and status in each organization they belong to.
  * morrow_users (services/auth_issuer.py): the built-in account. Its role and is_active describe the
    organization the account is currently bound to (org_id), and are what its tokens are minted from.
  * admin_users (services/admin_console.py): the invitation workflow's record, by email.

`PUT /auth/users/{id}/role` wrote only the account, `/organizations/{id}/members` only the membership,
`/admin/users/*` only admin_users, and none of them touched tokens already issued. So the records
disagreed, and a demoted or deactivated admin kept admin rights until their access token expired.

Now every role change, deactivation, reactivation and removal goes through `apply()`:

  1. The account row and the membership row are written together: one SQLite transaction, or, with
     the membership in Postgres, the account write is held open until the membership is committed
     and the membership is put back if the account can't be committed. admin_users follows.
  2. When access goes down (a lower role, a deactivation, a removal), every access token the person
     holds is cut off (services/session_revocation.py, a per-user "valid after" time checked on every
     request and cached for MORROW_TOKEN_REVOCATION_CACHE_SECONDS, applied at once on this replica).
     A deactivation or removal also deletes their refresh sessions, and the organization API keys
     they created whose scope is now above their role are revoked (all of them when they lose access).
  3. A promotion revokes nothing: authorization reads the membership on every request, so it takes
     effect on the next request. The token still carries the old role claim until it is refreshed.

Authoritative record: the membership. `effective_access()` is what the authorization checks read: the
membership's role and status when there is one, else the account's own role when it is bound to the
organization; an inactive account has no access anywhere. `reconcile()` runs once at startup and
brings old mismatches into line, always toward the lesser access, logging each fix by id only.

Removing or deactivating someone in the organization their account is bound to moves the account to
another organization where they are an active member (as accepting an invitation would), or, when
there is none, deactivates the account: an account can't keep minting tokens for an organization it
no longer belongs to.
"""

from __future__ import annotations

import logging
from contextlib import closing, contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Optional

logger = logging.getLogger(__name__)

ROLE = "role"
DEACTIVATE = "deactivate"
REACTIVATE = "reactivate"
REMOVE = "remove"
KINDS = (ROLE, DEACTIVATE, REACTIVATE, REMOVE)

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
#: admin_users (invitation workflow) roles and the membership role each one means.
CONSOLE_ROLE_TO_MEMBER = {"platform_admin": "admin", "org_admin": "admin", "analyst": "operator", "viewer": "viewer"}
MEMBER_ROLE_TO_CONSOLE = {"admin": "org_admin", "operator": "analyst", "viewer": "viewer"}


class NotFound(LookupError):
    """No account, membership or invitation record for this person in the organization."""


def member_role(value: object) -> str:
    """The membership role a role name means (viewer, operator, admin), "" when it means none."""
    text = str(value or "").strip().lower()
    if text in ROLE_RANK:
        return text
    return CONSOLE_ROLE_TO_MEMBER.get(text, "")


def _rank(role: object) -> int:
    return ROLE_RANK.get(member_role(role), 0)


def _ids(values: Iterable[object]) -> List[str]:
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out


@contextmanager
def _issuer_conn() -> Iterator[Any]:
    import sqlite3

    from db import get_connection

    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        yield conn


@contextmanager
def _org_context(org_id: str) -> Iterator[None]:
    from db import reset_current_organization_id, set_current_organization_id

    token = set_current_organization_id(org_id)
    try:
        yield
    finally:
        reset_current_organization_id(token)


def _pg_memberships() -> bool:
    from db_postgres import postgres_main_db_requested

    return postgres_main_db_requested()


def _account(conn, identifier: str) -> Optional[Dict[str, Any]]:
    from services import auth_issuer

    try:
        user = auth_issuer.get_user_by_id(conn, identifier)
        if not user and "@" in identifier:
            user = auth_issuer.get_user_by_email(conn, identifier.lower())
    except Exception as exc:
        if "no such table" in str(exc).lower():
            return None
        raise
    if not user:
        return None
    return {k: v for k, v in user.items() if k != "password_hash"}


def _console_row(org_id: str, email: str) -> Optional[Dict[str, Any]]:
    address = str(email or "").strip().lower()
    if not address:
        return None
    from db_feature_store import feature_conn
    from services import admin_console

    admin_console._init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT id, email, role, status FROM admin_users WHERE org_id=? AND lower(email)=?",
                           (org_id, address)).fetchone()
    return dict(row) if row else None


def find(org_id: str, identifiers: Iterable[object]) -> Dict[str, Any]:
    """Every record of this person in the organization: {account, membership, console, ids}.

    `account` is the built-in account, when it is bound to this organization or has a membership in
    it. People are named by account id, by email, or (header and external IdP identities) by whatever
    id their membership was recorded under.
    """
    from db import get_organization_member, list_organization_members

    org_id = str(org_id or "").strip()
    given = _ids(identifiers)
    account = None
    with _issuer_conn() as conn:
        for value in given:
            account = _account(conn, value)
            if account:
                break
    candidates = _ids(([account["id"], account.get("email")] if account else []) + given)
    membership = None
    with _org_context(org_id):
        for value in candidates:
            membership = get_organization_member(org_id, value)
            if membership:
                break
        if membership is None:
            emails = {v.lower() for v in candidates if "@" in v}
            if emails:
                membership = next((m for m in list_organization_members(org_id, limit=2000)
                                   if str(m.get("email") or "").strip().lower() in emails), None)
    if account and str(account.get("org_id") or "") != org_id and membership is None:
        account = None  # an account of another organization, and no membership here: not this person here
    email = ""
    for value in ([account.get("email")] if account else []) + [(membership or {}).get("email")] + candidates:
        if value and "@" in str(value):
            email = str(value).strip().lower()
            break
    console = _console_row(org_id, email) if email else None
    ids = _ids(candidates + ([membership["user_id"]] if membership else []) + ([email] if email else []))
    return {"org_id": org_id, "account": account, "membership": membership, "console": console, "ids": ids,
            "email": email}


def _bound_here(person: Dict[str, Any]) -> bool:
    account = person.get("account")
    return bool(account) and str(account.get("org_id") or "") == person["org_id"]


def _current(person: Dict[str, Any]) -> Dict[str, Any]:
    """The person's effective role and whether they have access, from the records found."""
    account, membership = person.get("account"), person.get("membership")
    if account and not account.get("is_active") and _bound_here(person):
        active = False
    else:
        active = None
    if membership:
        role = member_role(membership.get("role")) or "viewer"
        on = str(membership.get("status") or "active").lower() == "active"
        return {"role": role, "active": on if active is None else False}
    if _bound_here(person):
        return {"role": member_role(account.get("role")) or "viewer", "active": bool(account.get("is_active"))}
    console = person.get("console")
    if console:
        return {"role": member_role(console.get("role")) or "viewer",
                "active": str(console.get("status") or "active").lower() == "active"}
    return {"role": "", "active": False}


def effective_access(org_id: str, user_id: str) -> Dict[str, Any]:
    """What this person may do in the organization right now: {"role", "active"}.

    The membership is authoritative; without one, the built-in account's own role when it is bound to
    the organization. An inactive account has no access. Unknown people get {"role": "", "active": False}.
    """
    from db import get_organization_member

    uid = str(user_id or "").strip()
    org = str(org_id or "").strip()
    if not uid or not org:
        return {"role": "", "active": False}
    with _issuer_conn() as conn:
        account = _account(conn, uid)
    if account and not account.get("is_active"):
        return {"role": member_role(account.get("role")), "active": False}
    with _org_context(org):
        membership = get_organization_member(org, uid)
    if membership:
        return {"role": member_role(membership.get("role")) or "viewer",
                "active": str(membership.get("status") or "active").lower() == "active"}
    if account and str(account.get("org_id") or "") == org:
        return {"role": member_role(account.get("role")) or "viewer", "active": True}
    return {"role": "", "active": False}


def other_active_admins(org_id: str, exclude_ids: Iterable[object]) -> int:
    """How many people other than these have active admin access to the organization."""
    from db import list_organization_members

    org = str(org_id or "").strip()
    excluded = {str(v).strip().lower() for v in exclude_ids if str(v or "").strip()}
    seen: set = set()
    count = 0
    with _issuer_conn() as conn:
        accounts: Dict[str, Dict[str, Any]] = {}
        try:
            rows = conn.execute("SELECT id, email, role, org_id, is_active FROM morrow_users").fetchall()
            accounts = {str(r[0]): {"id": str(r[0]), "email": str(r[1] or "").lower(), "role": r[2],
                                    "org_id": str(r[3] or ""), "is_active": bool(r[4])} for r in rows}
        except Exception as exc:
            if "no such table" not in str(exc).lower():
                raise
    with _org_context(org):
        members = list_organization_members(org, limit=2000)
    for m in members:
        uid = str(m.get("user_id") or "")
        seen.add(uid)
        account = accounts.get(uid)
        keys = {uid.lower(), str(m.get("email") or "").lower()} - {""}
        if keys & excluded or (account and account["email"] and account["email"] in excluded):
            continue
        if member_role(m.get("role")) != "admin" or str(m.get("status") or "").lower() != "active":
            continue
        if account and not account["is_active"]:
            continue
        count += 1
    for account in accounts.values():
        if account["id"] in seen or account["org_id"] != org:
            continue
        if {account["id"].lower(), account["email"]} & excluded:
            continue
        if account["is_active"] and member_role(account["role"]) == "admin":
            count += 1
    return count


# ── Writing the records ─────────────────────────────────────────────────────────────────────────

def _other_membership(account_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    """Another organization where this account is an active member, most recently changed first."""
    from db import list_user_memberships

    for m in list_user_memberships(account_id, limit=500):
        if str(m.get("organization_id") or "") == org_id:
            continue
        if str(m.get("status") or "").lower() == "active" and member_role(m.get("role")):
            return m
    return None


def _membership_sql(conn, op: Dict[str, Any]) -> None:
    from db import _ensure_org_memberships_sqlite, _utc_now_iso

    _ensure_org_memberships_sqlite(conn)
    if op["action"] == "delete":
        conn.execute("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?",
                     (op["org_id"], op["user_id"]))
        return
    now = _utc_now_iso()
    conn.execute(
        "INSERT INTO organization_memberships(organization_id, user_id, role, display_name, email, status, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(organization_id, user_id) DO UPDATE SET "
        "role=excluded.role, display_name=excluded.display_name, email=excluded.email, status=excluded.status, "
        "updated_at=excluded.updated_at",
        (op["org_id"], op["user_id"], op["role"], op.get("display_name") or "", op.get("email") or "",
         op["status"], now, now),
    )


def _membership_pg(op: Dict[str, Any]) -> None:
    from db import remove_organization_member, upsert_organization_member

    if op["action"] == "delete":
        remove_organization_member(op["org_id"], op["user_id"])
    else:
        upsert_organization_member(op["org_id"], op["user_id"], role=op["role"], display_name=op.get("display_name") or "",
                                   email=op.get("email") or "", status=op["status"])


def _restore_pg(previous: Optional[Dict[str, Any]], op: Dict[str, Any]) -> None:
    if previous:
        _membership_pg({"action": "upsert", "org_id": op["org_id"], "user_id": previous["user_id"],
                        "role": member_role(previous.get("role")) or "viewer",
                        "display_name": previous.get("display_name") or "", "email": previous.get("email") or "",
                        "status": previous.get("status") or "active"})
    else:
        _membership_pg({"action": "delete", "org_id": op["org_id"], "user_id": op["user_id"]})


def _account_sql(conn, account_id: str, update: Dict[str, Any]) -> None:
    sets, args = [], []
    for column in ("org_id", "role", "is_active"):
        if column in update:
            sets.append(f"{column}=?")
            args.append(update[column])
    if sets:
        conn.execute(f"UPDATE morrow_users SET {', '.join(sets)} WHERE id=?", (*args, account_id))  # nosec B608  # column names are literals above; values are bound


def write(org_id: str, *, account_id: str = "", account_update: Optional[Dict[str, Any]] = None,
          membership_op: Optional[Dict[str, Any]] = None, previous_membership: Optional[Dict[str, Any]] = None) -> None:
    """Write the account change and the membership change together, or neither."""
    account_update = account_update or {}
    if membership_op:
        membership_op = {**membership_op, "org_id": org_id}
    if not _pg_memberships():
        with _issuer_conn() as conn:
            try:
                if account_id and account_update:
                    _account_sql(conn, account_id, account_update)
                if membership_op:
                    _membership_sql(conn, membership_op)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return
    with _issuer_conn() as conn:
        try:
            if account_id and account_update:
                _account_sql(conn, account_id, account_update)
            if membership_op:
                with _org_context(org_id):
                    _membership_pg(membership_op)
        except Exception:
            conn.rollback()
            raise
        try:
            conn.commit()
        except Exception:
            if membership_op:
                with _org_context(org_id):
                    _restore_pg(previous_membership, membership_op)
            raise


def _console_write(org_id: str, row: Dict[str, Any], *, role: str = "", status: str = "", actor: str = "",
                   action: str = "") -> bool:
    from db_feature_store import feature_conn
    from services import admin_console

    sets, args = [], []
    if role and role != row.get("role"):
        sets.append("role=?")
        args.append(role)
    if status and status != row.get("status"):
        sets.append("status=?")
        args.append(status)
    if not sets:
        return False
    with _org_context(org_id), feature_conn() as conn:
        conn.execute(f"UPDATE admin_users SET {', '.join(sets)} WHERE id=?", (*args, row["id"]))  # nosec B608  # literal column names; values are bound
        admin_console._audit(conn, org_id, actor or "system", action or "update_access", "user", row["id"],
                             f"role={role}" if role else f"status={status}")
        conn.commit()
    return True


# ── Revoking what a person holds ─────────────────────────────────────────────────────────────────

def revoke_access(org_id: str, ids: Iterable[object], *, account_id: str = "", sign_out: bool, role_limit: str,
                  actor: str = "", reason: str = "") -> Dict[str, Any]:
    """Cut off every access token of this person; with `sign_out`, their refresh sessions too; and
    revoke the organization API keys they created whose scope is above `role_limit` ("" = all)."""
    from services import api_keys, session_revocation

    people = _ids(ids)
    for identifier in people:
        session_revocation.revoke("user", identifier, revoked_by=actor, reason=reason)
    sessions = 0
    if sign_out and account_id:
        from services import auth_issuer

        with _issuer_conn() as conn:
            sessions = int(auth_issuer.revoke_refresh_sessions(conn, user_id=account_id) or 0)
    limit = _rank(role_limit)
    lowered = {p.lower() for p in people}
    revoked_keys: List[str] = []
    with _org_context(org_id):
        for key in api_keys.list_keys(org_id, status="active", limit=2000):
            if str(key.get("created_by") or "").strip().lower() not in lowered:
                continue
            if _rank(key.get("role")) > limit:
                api_keys.revoke_key(key["id"], revoked_by=actor or "system", reason=reason or "creator lost access")
                revoked_keys.append(key["id"])
    return {"access_tokens_revoked": bool(people), "refresh_sessions_revoked": sessions, "api_keys_revoked": revoked_keys}


# ── The one function every path goes through ─────────────────────────────────────────────────────

def apply(org_id: str, identifiers: Iterable[object], kind: str, *, role: str = "", console_role: str = "",
          profile: Optional[Dict[str, str]] = None, create: bool = False, actor: str = "",
          reason: str = "") -> Dict[str, Any]:
    """Change a person's role, deactivate, reactivate or remove them in one organization.

    `role` is a membership role (viewer, operator, admin) or an invitation-workflow role (org_admin,
    analyst, ...), which `console_role` keeps for admin_users. `create` lets a role change record a
    membership for someone with no record yet (adding a member). Raises NotFound when nothing records
    the person here, ValueError for an unknown kind or role. Returns what changed and what was revoked.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown change {kind!r}")
    org_id = str(org_id or "").strip()
    profile = profile or {}
    new_role = ""
    if kind == ROLE:
        new_role = member_role(role)
        if not new_role:
            raise ValueError("role must be viewer, operator or admin")
    person = find(org_id, identifiers)
    account, membership, console = person["account"], person["membership"], person["console"]
    if not (account or membership or console):
        if not (create and kind == ROLE):
            raise NotFound(org_id)
    before = _current(person)
    bound = _bound_here(person)

    account_update: Dict[str, Any] = {}
    membership_op: Optional[Dict[str, Any]] = None
    member_user = (membership or {}).get("user_id") or (account or {}).get("id") or (_ids(identifiers) or [""])[0]
    base = {"user_id": member_user,
            "display_name": profile.get("display_name") or (membership or {}).get("display_name")
            or (account or {}).get("full_name") or "",
            "email": profile.get("email") or (membership or {}).get("email") or person["email"] or ""}
    rebound_to = ""
    after_role, after_active = before["role"], before["active"]

    if kind == ROLE:
        after_role = new_role
        if membership:
            status = str(membership.get("status") or "active").lower()
        elif create or not bound or account.get("is_active"):
            status = "active"  # adding someone as a member gives them access, their account included
        else:
            status = "disabled"
        if account or membership or create:
            membership_op = {"action": "upsert", **base, "role": new_role, "status": status}
        if bound:
            account_update["role"] = new_role
            if status == "active" and not membership and not account.get("is_active"):
                account_update["is_active"] = 1
        after_active = status == "active" and (not bound or bool(account_update.get("is_active", account.get("is_active"))))
        if not (account or membership or console):
            after_active = True
    elif kind in (DEACTIVATE, REMOVE):
        after_active = False
        keep_role = before["role"] or member_role((account or {}).get("role")) or "viewer"
        if kind == REMOVE:
            membership_op = {"action": "delete", "user_id": member_user} if membership else None
        elif membership or bound:
            membership_op = {"action": "upsert", **base, "role": keep_role, "status": "disabled"}
        if bound:
            elsewhere = _other_membership(account["id"], org_id)
            if elsewhere:
                rebound_to = str(elsewhere["organization_id"])
                account_update.update(org_id=rebound_to, role=member_role(elsewhere.get("role")))
            else:
                account_update["is_active"] = 0
    elif kind == REACTIVATE:
        after_active = True
        keep_role = before["role"] or "viewer"
        if membership or bound:
            membership_op = {"action": "upsert", **base, "role": keep_role, "status": "active"}
        if bound and not account.get("is_active"):
            account_update["is_active"] = 1

    write(org_id, account_id=(account or {}).get("id") or "", account_update=account_update if account else {},
          membership_op=membership_op, previous_membership=membership)

    console_updated = False
    if console:
        if kind == ROLE:
            wanted = console_role if member_role(console_role) == new_role else (
                console.get("role") if member_role(console.get("role")) == new_role else MEMBER_ROLE_TO_CONSOLE[new_role])
            console_updated = _console_write(org_id, console, role=str(wanted), actor=actor, action="update_role")
        elif kind in (DEACTIVATE, REMOVE):
            console_updated = _console_write(org_id, console, status="suspended", actor=actor, action="remove_user")
        else:
            console_updated = _console_write(org_id, console, status="active", actor=actor, action="reactivate_user")

    lowered = (kind in (DEACTIVATE, REMOVE)) or (kind == ROLE and before["active"] and _rank(new_role) < _rank(before["role"]))
    revoked = {"access_tokens_revoked": False, "refresh_sessions_revoked": 0, "api_keys_revoked": []}
    if lowered:
        revoked = revoke_access(org_id, person["ids"], account_id=(account or {}).get("id") or "",
                                sign_out=kind in (DEACTIVATE, REMOVE),
                                role_limit="" if kind in (DEACTIVATE, REMOVE) else new_role,
                                actor=actor, reason=reason or f"access {kind}")
    return {
        "user_id": (account or {}).get("id") or member_user,
        "previous_role": before["role"], "previous_active": before["active"],
        "role": after_role, "active": after_active,
        "account_updated": bool(account and account_update),
        "membership_updated": membership_op is not None,
        "console_updated": console_updated,
        "rebound_to": rebound_to,
        "access_lowered": lowered,
        **revoked,
    }


# ── Startup reconciliation ──────────────────────────────────────────────────────────────────────

def reconcile(log: Optional[logging.Logger] = None) -> List[Dict[str, Any]]:
    """Bring every built-in account and its membership in the account's organization into agreement.

    Idempotent. Each mismatch is resolved toward the lesser access: the lower of the two roles, and
    disabled if either record says so. A missing membership is recorded from the account. Every fix
    is logged by organization and account id only, and access tokens of anyone whose access went down
    are revoked. Returns the fixes.
    """
    from db import get_organization_member
    from services import tenant_scope

    log = log or logger
    fixes: List[Dict[str, Any]] = []
    with _issuer_conn() as conn:
        try:
            rows = conn.execute("SELECT id, email, full_name, role, org_id, is_active FROM morrow_users").fetchall()
        except Exception as exc:
            if "no such table" in str(exc).lower():
                return fixes
            raise
    accounts = [{"id": str(r[0]), "email": str(r[1] or ""), "full_name": str(r[2] or ""), "role": str(r[3] or ""),
                 "org_id": str(r[4] or ""), "is_active": bool(r[5])} for r in rows]
    with tenant_scope.platform_scope("startup access reconciliation", actor="system"):
        for account in accounts:
            org_id = account["org_id"]
            if not org_id:
                continue
            with _org_context(org_id):
                membership = get_organization_member(org_id, account["id"])
            account_role = member_role(account["role"]) or "viewer"
            account_on = account["is_active"]
            if membership is None:
                write(org_id, membership_op={"action": "upsert", "user_id": account["id"], "role": account_role,
                                             "status": "active" if account_on else "disabled",
                                             "display_name": account["full_name"], "email": account["email"]})
                fix = {"org_id": org_id, "user_id": account["id"], "fix": "membership_recorded",
                       "role": account_role, "active": account_on}
                log.warning("[access-reconcile] org=%s user=%s membership recorded from the account (role %s, %s)",
                            org_id, account["id"], account_role, "active" if account_on else "disabled")
                fixes.append(fix)
                continue
            m_role = member_role(membership.get("role")) or "viewer"
            m_on = str(membership.get("status") or "active").lower() == "active"
            role = account_role if _rank(account_role) <= _rank(m_role) else m_role
            on = account_on and m_on
            account_update: Dict[str, Any] = {}
            if account["role"] != role:
                account_update["role"] = role
            rebound = ""
            if account_on and not on:
                elsewhere = _other_membership(account["id"], org_id)
                if elsewhere:
                    rebound = str(elsewhere["organization_id"])
                    account_update.update(org_id=rebound, role=member_role(elsewhere.get("role")))
                else:
                    account_update["is_active"] = 0
            membership_op = None
            if m_role != role or m_on != on:
                membership_op = {"action": "upsert", "user_id": membership["user_id"], "role": role,
                                 "status": "active" if on else "disabled",
                                 "display_name": membership.get("display_name") or "",
                                 "email": membership.get("email") or ""}
            if not account_update and membership_op is None:
                continue
            write(org_id, account_id=account["id"], account_update=account_update, membership_op=membership_op,
                  previous_membership=membership)
            lowered = (_rank(role) < max(_rank(account_role), _rank(m_role))) or (not on and (account_on or m_on))
            fix = {"org_id": org_id, "user_id": account["id"], "fix": "records_aligned",
                   "account": {"role": account_role, "active": account_on}, "membership": {"role": m_role, "active": m_on},
                   "now": {"role": role, "active": on}, "rebound_to": rebound}
            log.warning("[access-reconcile] org=%s user=%s account %s/%s and membership %s/%s disagreed; now %s/%s%s",
                        org_id, account["id"], account_role, "active" if account_on else "inactive", m_role,
                        "active" if m_on else "disabled", role, "active" if on else "disabled",
                        f"; account moved to org={rebound}" if rebound else "")
            if lowered:
                try:
                    revoke_access(org_id, [account["id"]], account_id=account["id"], sign_out=not on,
                                  role_limit=role if on else "", actor="system", reason="access reconciled")
                except Exception:
                    log.exception("[access-reconcile] org=%s user=%s token revocation failed", org_id, account["id"])
            fixes.append(fix)
    return fixes
