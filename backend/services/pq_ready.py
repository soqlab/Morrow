"""The opt-in public list of post-quantum ready domains.

No domain is ever listed without its owner choosing it. An organisation can list a domain only
when all of these hold, and the list re-checks them on every league tick (weekly per domain):

  * the organisation has verified the domain by DNS TXT (services/domain_verification.py);
  * the domain's newest public grade under the current rubric is A or B (services/public_grade.py);
  * an admin of that organisation opted it in, and has not opted it out.

When the grade drops below B, or the domain is no longer verified, the entry leaves the list at
once and the reason is kept on the row, so the organisation's own view says why. Opting out takes
effect immediately. Entries are shown alphabetically or by the date they joined; they are never
ranked against each other.

Storage: ``pq_ready_listings``, one row per (organisation, domain), org-scoped (``org_id``) and
covered by the Postgres RLS plan (services/postgres_rls.py). The public read and the weekly
re-check cross tenants, so they run in a named, journaled ``tenant_scope.platform_scope``.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn

LISTABLE_GRADES = ("A", "B")

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS pq_ready_listings (
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        listed INTEGER NOT NULL DEFAULT 0,
        joined_at TEXT NOT NULL DEFAULT '',
        removed_at TEXT NOT NULL DEFAULT '',
        removed_reason TEXT NOT NULL DEFAULT '',
        grade TEXT NOT NULL DEFAULT '',
        checked_at TEXT NOT NULL DEFAULT '',
        updated_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (org_id, domain)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pq_ready_listed ON pq_ready_listings (listed, domain)",
)

_ready = ""
_ready_lock = threading.Lock()


class ListingError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def _init() -> None:
    """Create the table once per database (a per-process flag alone would skip a second database)."""
    global _ready
    identity = _db_identity()
    if _ready == identity:
        return
    with _ready_lock:
        if _ready == identity:
            return
        with feature_conn() as conn:
            for ddl in SCHEMA:
                conn.execute(ddl)
            conn.commit()
        _ready = identity


def init_tables() -> None:
    """Create the table now (registered with register_deferred_schema in app.py)."""
    global _ready
    _ready = ""
    _init()


def _grade_of(domain: str) -> Optional[Dict[str, Any]]:
    from services import public_grade

    return public_grade.latest(domain)


def _row(r: Any) -> Dict[str, Any]:
    return {"domain": r["domain"], "listed": bool(r["listed"]), "joined_at": r["joined_at"] or None,
            "removed_at": r["removed_at"] or None, "removed_reason": r["removed_reason"] or None,
            "grade": r["grade"] or None, "checked_at": r["checked_at"] or None}


def for_org(org_id: str) -> List[Dict[str, Any]]:
    """Every verified domain of the organisation with its listing state and whether it can join."""
    from services import domain_verification

    _init()
    with feature_conn() as conn:
        rows = {r["domain"]: _row(r) for r in conn.execute(
            "SELECT domain, listed, joined_at, removed_at, removed_reason, grade, checked_at "
            "FROM pq_ready_listings WHERE org_id = ? ORDER BY domain", (org_id,)).fetchall()}
    out = []
    for domain in sorted(domain_verification.verified_domains(org_id)):
        entry = rows.get(domain) or {"domain": domain, "listed": False, "joined_at": None, "removed_at": None,
                                     "removed_reason": None, "grade": None, "checked_at": None}
        latest = _grade_of(domain)
        entry["current_grade"] = (latest or {}).get("grade")
        entry["current_checked_at"] = (latest or {}).get("scanned_at")
        entry["eligible"] = entry["current_grade"] in LISTABLE_GRADES
        out.append(entry)
    return out


def opt_in(org_id: str, domain: str, actor: str = "") -> Dict[str, Any]:
    from services import domain_verification

    name = domain_verification.normalize_domain(domain)
    if name not in domain_verification.verified_domains(org_id):
        raise ListingError(403, f"{name} is not verified for your organisation. Verify it by DNS first.",
                           "not_verified")
    latest = _grade_of(name)
    if not latest:
        raise ListingError(409, f"{name} has no public grade yet. Grade it at /{name}, then opt in.", "not_graded")
    grade = str(latest.get("grade") or "")
    if grade not in LISTABLE_GRADES:
        raise ListingError(409, f"{name} is graded {grade}. Only A or B can be listed as post-quantum ready.",
                           "grade_too_low")
    _init()
    now = _now()
    with feature_conn() as conn:
        conn.execute("DELETE FROM pq_ready_listings WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.execute(
            "INSERT INTO pq_ready_listings (org_id, domain, listed, joined_at, removed_at, removed_reason, grade, "
            "checked_at, updated_by) VALUES (?, ?, 1, ?, '', '', ?, ?, ?)",
            (org_id, name, now, grade, str(latest.get("scanned_at") or ""), str(actor or "")))
        conn.commit()
    return {"domain": name, "listed": True, "joined_at": now, "grade": grade,
            "checked_at": latest.get("scanned_at")}


def opt_out(org_id: str, domain: str, actor: str = "") -> Dict[str, Any]:
    from services import domain_verification

    name = domain_verification.normalize_domain(domain)
    _init()
    now = _now()
    with feature_conn() as conn:
        conn.execute(
            "UPDATE pq_ready_listings SET listed = 0, removed_at = ?, removed_reason = ?, updated_by = ? "
            "WHERE org_id = ? AND domain = ? AND listed = 1",
            (now, "Opted out by your organisation.", str(actor or ""), org_id, name))
        conn.commit()
    return {"domain": name, "listed": False, "removed_at": now}


def refresh() -> Dict[str, int]:
    """Re-check every listed entry: still verified, still A or B. Runs after each league tick."""
    from services import domain_verification
    from services import tenant_scope

    _init()
    kept = removed = 0
    with tenant_scope.platform_scope("post-quantum ready list: weekly re-check of every listed domain"):
        with feature_conn() as conn:
            rows = conn.execute("SELECT org_id, domain FROM pq_ready_listings WHERE listed = 1").fetchall()
        for r in rows:
            org_id, domain = str(r["org_id"]), str(r["domain"])
            latest = _grade_of(domain)
            grade = str((latest or {}).get("grade") or "")
            reason = ""
            domain_verification._invalidate(org_id)
            if domain not in domain_verification.verified_domains(org_id):
                reason = "Removed automatically: the domain is no longer verified for your organisation."
            elif grade not in LISTABLE_GRADES:
                when = str((latest or {}).get("scanned_at") or "")[:10]
                reason = (f"Removed automatically: the check of {when} graded it {grade or 'unknown'}; "
                          "the list takes A or B only. Fix it, re-check, and opt in again.")
            with feature_conn() as conn:
                if reason:
                    conn.execute(
                        "UPDATE pq_ready_listings SET listed = 0, removed_at = ?, removed_reason = ?, grade = ?, "
                        "checked_at = ?, updated_by = 'weekly re-check' WHERE org_id = ? AND domain = ?",
                        (_now(), reason, grade, str((latest or {}).get("scanned_at") or ""), org_id, domain))
                    removed += 1
                else:
                    conn.execute("UPDATE pq_ready_listings SET grade = ?, checked_at = ? WHERE org_id = ? AND domain = ?",
                                 (grade, str((latest or {}).get("scanned_at") or ""), org_id, domain))
                    kept += 1
                conn.commit()
    return {"kept": kept, "removed": removed}


def listed_domains() -> List[str]:
    """Every listed domain, so the weekly tick re-grades them along with the sector lists."""
    from services import tenant_scope

    _init()
    with tenant_scope.platform_scope("post-quantum ready list: which domains the weekly tick re-grades"):
        with feature_conn() as conn:
            rows = conn.execute("SELECT DISTINCT domain FROM pq_ready_listings WHERE listed = 1").fetchall()
    return sorted(str(r["domain"]) for r in rows)


def public_list(order: str = "name") -> Dict[str, Any]:
    """The public list: domain, sector, grade, date checked, date joined. Never ranked."""
    from services import league, tenant_scope

    _init()
    with tenant_scope.platform_scope("post-quantum ready list: the public, opt-in list"):
        with feature_conn() as conn:
            rows = conn.execute("SELECT domain, joined_at, grade, checked_at FROM pq_ready_listings "
                                "WHERE listed = 1").fetchall()
    classifier = league.Classifier(league.load_spec())
    names = {s["id"]: s["name"] for s in league.load_spec()["sectors"]}
    seen: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        domain = str(r["domain"])
        joined = str(r["joined_at"] or "")
        if domain in seen and seen[domain]["joined_at"] <= joined:
            continue  # two organisations verified the same domain: list it once, first joiner's date
        sector = classifier.classify(domain)
        seen[domain] = {"domain": domain, "sector": sector, "sector_name": names.get(sector, "Other"),
                        "grade": str(r["grade"] or ""), "checked_at": str(r["checked_at"] or ""), "joined_at": joined}
    entries = list(seen.values())
    if order == "joined":
        entries.sort(key=lambda e: (e["joined_at"], e["domain"]), reverse=True)
        order = "joined"
    else:
        entries.sort(key=lambda e: e["domain"])
        order = "name"
    return {"entries": entries, "count": len(entries), "order": order,
            "about": "Organisations that verified their domain and chose to be listed while it grades A or B. "
                     "Not a ranking; re-checked weekly; an entry leaves the list when its grade drops below B."}


def atom(base_url: str) -> str:
    """The list as an Atom feed: one entry per listed domain, newest joiners first."""
    from xml.sax.saxutils import escape

    data = public_list("joined")
    updated = max([e["joined_at"] for e in data["entries"]] + ["1970-01-01T00:00:00Z"])
    base = base_url.rstrip("/")
    items = []
    for e in data["entries"]:
        items.append(
            "<entry><id>urn:morrow:pq-ready:" + escape(e["domain"]) + ":" + escape(e["joined_at"]) + "</id>"
            "<title>" + escape(e["domain"]) + " is post-quantum ready (grade " + escape(e["grade"]) + ")</title>"
            "<updated>" + escape(e["joined_at"]) + "</updated>"
            '<link href="' + escape(base + "/" + e["domain"]) + '"/>'
            "<summary>" + escape(f"{e['sector_name']}. Grade {e['grade']}, checked {e['checked_at'][:10]}. "
                                 "Listed by the domain's owner.") + "</summary></entry>")
    return ('<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'
            "<id>urn:morrow:pq-ready</id><title>Post-quantum ready, by choice</title>"
            "<updated>" + escape(updated) + "</updated>"
            '<link rel="alternate" href="' + escape(base + "/league") + '"/>'
            + "".join(items) + "</feed>\n")
