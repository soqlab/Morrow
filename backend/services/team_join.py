"""Domain team sign-in: anyone with a verified mailbox at an organization's verified domain may join it.

  GET  /domain-join                     admin: the organization's join policies and who joined
  PUT  /domain-join/{domain}            admin: {"enabled": true|false}
  POST /auth/team-join/request {email}  public: emails a single-use join link (same answer either way)
  POST /auth/team-join/preview {token}  public: organization name and masked address for a join link
  GET  /join                            public page (static/join.html)
  then POST /auth/passkey/register/begin|finish with kind "join": the new account's passkey

How an organization proves it owns a domain is the existing DNS check (services/domain_verification:
_morrow-verify.<domain> TXT morrow-verify=<token>). On top of it:

  * Enabling needs an organization admin, a domain this organization has verified, and the TXT
    record still being there right now (looked up live when the admin switches it on).
  * Free email providers are refused (FREE_MAIL_DOMAINS, plus MORROW_FREE_MAIL_DOMAINS): an
    address at gmail.com says nothing about which organization someone belongs to. Nobody can
    publish a TXT record there anyway, but the refusal does not depend on that.
  * One domain, one organization. Two organizations can each hold a verified row for the same
    domain (the table is keyed by organization and domain, and whoever controls the DNS can publish
    both records). For team sign-in the FIRST to verify wins: an organization may enable it only
    if no other organization verified the domain earlier and none has it enabled. A join resolves
    to exactly one enabled policy or none.
  * Only the exact domain: alice@eu.acme.example does not join through acme.example. An
    organization that wants a subdomain verifies and enables that subdomain too.
  * The DNS record is looked up again, live, when the link is requested and when the account is
    created. A domain whose record has gone stops admitting people at once, without waiting for a
    periodic re-check, and the refusal is journaled.
  * The mailbox is proved by the emailed link (MORROW_TEAM_JOIN_TTL_SECONDS, default 30 minutes,
    single use; a newer request replaces older links). The account is created with a passkey,
    never a password, and the least-privileged role, viewer. An admin raises it if needed.
  * Every join is recorded three times: the tenant audit log (domains.team_join.joined), the
    organization's admin audit log (domain_join) and org_domain_joins, which the admin page lists.
"""

from __future__ import annotations

import os
import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

DEFAULT_ROLE = "viewer"

#: Consumer mailbox providers. Not exhaustive: MORROW_FREE_MAIL_DOMAINS adds more.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
    "hotmail.it", "hotmail.es", "live.com", "live.co.uk", "live.fr", "live.de", "msn.com", "passport.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.it", "yahoo.es", "yahoo.co.jp", "yahoo.com.br",
    "ymail.com", "rocketmail.com", "aol.com", "aim.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "protonmail.ch", "pm.me", "tutanota.com", "tutanota.de", "tuta.io", "tuta.com",
    "gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch", "web.de", "t-online.de", "freenet.de", "mail.com",
    "email.com", "usa.com", "zoho.com", "zohomail.com", "yandex.com", "yandex.ru", "ya.ru", "mail.ru", "inbox.ru",
    "list.ru", "bk.ru", "rambler.ru", "qq.com", "163.com", "126.com", "yeah.net", "sina.com", "sohu.com",
    "naver.com", "daum.net", "hanmail.net", "fastmail.com", "fastmail.fm", "hey.com", "hushmail.com",
    "mailbox.org", "posteo.de", "posteo.net", "disroot.org", "riseup.net", "laposte.net", "orange.fr", "free.fr",
    "sfr.fr", "wanadoo.fr", "libero.it", "virgilio.it", "seznam.cz", "wp.pl", "o2.pl", "interia.pl", "onet.pl",
    "rediffmail.com", "btinternet.com", "sky.com", "virginmedia.com", "comcast.net", "verizon.net", "att.net",
    "sbcglobal.net", "bellsouth.net", "cox.net", "charter.net", "earthlink.net", "optonline.net", "bigpond.com",
    "duck.com", "skiff.com", "mailfence.com", "runbox.com", "cock.li", "guerrillamail.com", "mailinator.com",
    "10minutemail.com", "temp-mail.org", "yopmail.com",
})

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS org_domain_join_policies (
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (org_id, domain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_domain_joins (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        email TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        joined_at TEXT NOT NULL
    )
    """,
)

_ready = False
_ready_lock = threading.Lock()


class JoinError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


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
            for ddl in SCHEMA:
                conn.execute(ddl)
            conn.commit()
        _ready = True


def init_tables() -> None:
    """Create this module's tables now (registered with register_deferred_schema in app.py)."""
    global _ready
    _ready = False
    _init()


def free_mail_domains() -> frozenset:
    extra = {d.strip().lower() for d in str(os.getenv("MORROW_FREE_MAIL_DOMAINS") or "").split(",") if d.strip()}
    return FREE_MAIL_DOMAINS | extra


def is_free_mail(domain: str) -> bool:
    return str(domain or "").strip().lower().rstrip(".") in free_mail_domains()


def email_domain(email: Any) -> str:
    """The domain of a plausible address, lower-case and IDNA-encoded, or JoinError(400)."""
    from services import domain_verification as _domains

    text = str(email or "").strip().lower()
    if len(text) > 320 or text.count("@") != 1:
        raise JoinError(400, "Enter your work email address.", "invalid_email")
    local, _, host = text.partition("@")
    if not local or len(local) > 64 or any(c.isspace() for c in local):
        raise JoinError(400, "Enter your work email address.", "invalid_email")
    try:
        return _domains.normalize_domain(host)
    except _domains.DomainError:
        raise JoinError(400, "Enter your work email address.", "invalid_email") from None


def _verified_row(conn: Any, org_id: str, domain: str) -> Optional[Any]:
    return conn.execute(
        "SELECT token, verified_at FROM org_verified_domains WHERE org_id = ? AND domain = ? AND status = 'verified'",
        (org_id, domain),
    ).fetchone()


def dns_record_present(org_id: str, domain: str) -> bool:
    """Look the organization's TXT record up now. Raises JoinError(503) when DNS can't answer."""
    from services import domain_verification as _domains

    _domains._init()
    with feature_conn() as conn:
        row = conn.execute("SELECT token FROM org_verified_domains WHERE org_id = ? AND domain = ?",
                           (org_id, domain)).fetchone()
    if not row:
        return False
    try:
        values = _domains._txt_values(f"{_domains.RECORD_PREFIX}.{domain}")
    except _domains.DomainError:
        raise JoinError(503, "We couldn't check the domain's DNS record just now. Try again in a minute.", "dns_unavailable") from None
    return f"{_domains.VALUE_PREFIX}{row['token']}" in values


def _first_verifier(conn: Any, domain: str) -> str:
    rows = conn.execute(
        "SELECT org_id, verified_at FROM org_verified_domains WHERE domain = ? AND status = 'verified' "
        "ORDER BY verified_at, org_id", (domain,)
    ).fetchall()
    return str(rows[0]["org_id"]) if rows else ""


def set_policy(org_id: str, domain: Any, enabled: bool, actor: str = "") -> Dict[str, Any]:
    from services import domain_verification as _domains

    try:
        name = _domains.normalize_domain(domain)
    except _domains.DomainError as exc:
        raise JoinError(exc.status_code, exc.detail) from None
    _init()
    _domains._init()
    if enabled:
        if is_free_mail(name):
            raise JoinError(400, f"{name} is a free email provider, so an address there doesn't show which organization "
                                 "someone belongs to. Team sign-in works only with your own domain.", "free_mail")
        with feature_conn() as conn:
            if not _verified_row(conn, org_id, name):
                raise JoinError(409, f"Verify {name} first: team sign-in needs a domain your organization has proved it controls.",
                                "domain_not_verified")
            first = _first_verifier(conn, name)
            other = conn.execute(
                "SELECT org_id FROM org_domain_join_policies WHERE domain = ? AND enabled = 1 AND org_id <> ?",
                (name, org_id)).fetchone()
        if other or (first and first != org_id):
            raise JoinError(409, f"Another organization verified {name} first, so team sign-in for it belongs to that "
                                 "organization. Contact support if this is your domain.", "domain_claimed")
        if not dns_record_present(org_id, name):
            raise JoinError(409, f"The DNS record that verified {name} is gone. Publish it again and check the domain, "
                                 "then turn team sign-in on.", "dns_record_missing")
    now = _now()
    with feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO org_domain_join_policies (org_id, domain, enabled, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                    (org_id, name, 1 if enabled else 0, now, str(actor or "")[:200]))
        except INTEGRITY_ERRORS:
            conn.execute("UPDATE org_domain_join_policies SET enabled = ?, updated_at = ?, updated_by = ? "
                         "WHERE org_id = ? AND domain = ?", (1 if enabled else 0, now, str(actor or "")[:200], org_id, name))
        conn.commit()
    return next(p for p in list_policies(org_id) if p["domain"] == name)


def list_policies(org_id: str) -> List[Dict[str, Any]]:
    """Every verified domain of the organization with its team sign-in state."""
    from services import domain_verification as _domains

    _init()
    _domains._init()
    with feature_conn() as conn:
        domains = conn.execute(
            "SELECT domain, status, verified_at FROM org_verified_domains WHERE org_id = ? ORDER BY domain", (org_id,)
        ).fetchall()
        policies = {r["domain"]: r for r in conn.execute(
            "SELECT domain, enabled, updated_at, updated_by FROM org_domain_join_policies WHERE org_id = ?", (org_id,)
        ).fetchall()}
        out = []
        for d in domains:
            p = policies.get(d["domain"])
            first = _first_verifier(conn, d["domain"]) if d["status"] == "verified" else ""
            out.append({
                "domain": d["domain"],
                "verified": d["status"] == "verified",
                "enabled": bool(p and int(p["enabled"] or 0)) and d["status"] == "verified",
                "updated_at": p["updated_at"] if p else None,
                "free_mail": is_free_mail(d["domain"]),
                "claimed_by_other_organization": bool(first and first != org_id),
            })
    return out


def list_joins(org_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT email, domain, user_id, role, joined_at FROM org_domain_joins WHERE org_id = ? "
            "ORDER BY joined_at DESC LIMIT ?", (org_id, max(1, min(int(limit), 1000)))
        ).fetchall()
    return [{"email": r["email"], "domain": r["domain"], "user_id": r["user_id"], "role": r["role"],
             "joined_at": r["joined_at"]} for r in rows]


def resolve(domain: str) -> Optional[str]:
    """The one organization people at this domain may join, or None.

    Re-applies every rule an admin had to pass to enable it: still verified in the table, the
    organization is the first verifier, and it is the only enabled policy for the domain.
    """
    from services import domain_verification as _domains

    name = str(domain or "").strip().lower()
    if not name or is_free_mail(name):
        return None
    _init()
    _domains._init()
    with feature_conn() as conn:
        rows = conn.execute("SELECT org_id FROM org_domain_join_policies WHERE domain = ? AND enabled = 1",
                            (name,)).fetchall()
        if len(rows) != 1:
            return None
        org_id = str(rows[0]["org_id"])
        if not _verified_row(conn, org_id, name) or _first_verifier(conn, name) != org_id:
            return None
    return org_id


def check_join_allowed(org_id: str, domain: str) -> None:
    """Raise JoinError unless people at `domain` may join `org_id` right now (DNS looked up live)."""
    if is_free_mail(domain):
        raise JoinError(400, "Free email addresses can't be used to join an organization.", "free_mail")
    if resolve(domain) != org_id:
        raise JoinError(403, "Team sign-in for this domain is switched off. Ask your administrator for an invitation.",
                        "join_disabled")
    if not dns_record_present(org_id, domain):
        raise JoinError(403, "This organization's domain is no longer verified, so team sign-in is paused. "
                             "Ask your administrator.", "domain_not_verified")


def add_member(org_id: str, domain: str, *, user_id: str, email: str) -> Dict[str, Any]:
    """Make the new account a viewer of the organization and record the join (audit + join list)."""
    from services import tenant_scope as _tenant_scope
    from services.platform_access import _init as _admin_tables
    from services.platform_access import bind_account_to_organization

    _init()
    _admin_tables()   # admin_users and admin_audit_log, the organization's own member list and trail
    address = str(email or "").strip().lower()
    now = _now()
    # Same reason as invitation acceptance (services/platform_access.py): the joiner is not yet a
    # member, so these tenant rows are written from a named, journaled cross-tenant scope.
    with _tenant_scope.platform_scope("domain team sign-in: the tenant is the one that owns the domain",
                                      actor=str(user_id)), feature_conn() as conn:
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO admin_users (id, org_id, email, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (secrets.token_hex(8), org_id, address, DEFAULT_ROLE, "active", now))
        except INTEGRITY_ERRORS:
            pass  # already listed (an earlier invitation); the membership below is what authorizes.
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO admin_audit_log (org_id, actor_email, action, target_type, target_id, detail, ip_address, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (org_id, address, "domain_join", "user", str(user_id), f"joined through verified domain {domain}", "", now))
        except INTEGRITY_ERRORS:
            pass
        conn.execute(
            "INSERT INTO org_domain_joins (id, org_id, domain, email, user_id, role, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secrets.token_hex(12), org_id, domain, address, str(user_id), DEFAULT_ROLE, now))
        conn.commit()
    membership = None
    try:
        from db import upsert_organization_member

        with _tenant_scope.platform_scope("domain team sign-in: membership in the domain's organization", actor=str(user_id)):
            membership = upsert_organization_member(org_id, str(user_id), role=DEFAULT_ROLE, email=address, status="active")
    except Exception:
        membership = None
    bound = bind_account_to_organization(str(user_id), org_id, DEFAULT_ROLE, email=address)
    return {"org_id": org_id, "domain": domain, "role": DEFAULT_ROLE, "membership_recorded": membership is not None,
            "organization_binding_updated": bound, "joined_at": now}


def email_body(link: str, org_name: str, email: str, minutes: int) -> Dict[str, str]:
    return {
        "subject": f"Join {org_name} on Morrow",
        "body": (
            f"Someone asked to join {org_name} on Morrow as {email}.\n\n"
            f"To join, open this link within {minutes} minutes and create a passkey:\n\n{link}\n\n"
            "The link works once. If you didn't ask for this, ignore this email: nothing happens without it.\n"
        ),
    }
