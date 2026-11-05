"""Read, verify and export a tenant's hash-chained audit journal.

`audit_logs` is append-only (database triggers refuse UPDATE and DELETE) and each entry's
``entry_hash`` is SHA-256 over the previous entry's hash and this entry's fields (see
``db._compute_audit_entry_hash``). Nothing ever checked that chain, so a row edited by someone with
database access, or a row deleted after the triggers were dropped, went unnoticed. This module
re-derives every hash in order and reports the first entry where the stored chain disagrees.

The export carries exactly the fields the hash covers, so ``scripts/verify_migration_proof.py``
can repeat the check offline without trusting this server.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import closing
from typing import Any, Dict, Iterator, List, Optional

from db import current_organization_id

EXPORT_FORMAT = "morrow.audit-journal/v1"
HASH_FIELDS = ("prev_hash", "actor_id", "actor_role", "action", "resource_type", "resource_id",
               "decision", "reason", "details_json", "created_at")
_COLUMNS = ("id, organization_id, actor_id, actor_role, action, resource_type, resource_id, decision, "
            "reason, details_json, prev_hash, entry_hash, created_at")


def compute_entry_hash(entry: Dict[str, Any]) -> str:
    """The journal's hash, identical to db._compute_audit_entry_hash / db_postgres's copy."""
    values = [str(entry.get(name) or "") for name in HASH_FIELDS]
    values[HASH_FIELDS.index("details_json")] = str(entry.get("details_json") or "{}")
    return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


def _flush_queue() -> None:
    try:
        from services.audit_queue import flush

        flush()
    except Exception:
        pass


def iter_entries(org_id: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """Every journal entry of one tenant, oldest first, with the hash inputs as stored."""
    _flush_queue()
    org = str(org_id or current_organization_id() or "").strip()
    from db_postgres import postgres_main_db_requested

    if postgres_main_db_requested():
        from psycopg2.extras import RealDictCursor

        from db_postgres import DEFAULT_ORG_ID, _iso_utc, _json_obj, pg_product_conn

        with pg_product_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(f"SELECT {_COLUMNS} FROM audit_logs WHERE organization_id = %s ORDER BY id ASC",
                            (org or DEFAULT_ORG_ID,))
                for row in cur:
                    item = dict(row)
                    # Same normalisation pg_list_audit_logs applies, which is the form that was hashed.
                    item["details_json"] = json.dumps(_json_obj(item.get("details_json")),
                                                      separators=(",", ":"), sort_keys=True)
                    item["created_at"] = _iso_utc(item.get("created_at"))
                    item["id"] = int(item.get("id") or 0)
                    yield item
        return

    import sqlite3

    import db

    with closing(db.get_connection()) as conn:
        db._ensure_sprint13_tables(conn)
        conn.row_factory = sqlite3.Row
        for row in conn.execute(f"SELECT {_COLUMNS} FROM audit_logs WHERE organization_id = ? ORDER BY id ASC",
                                (org,)):
            item = dict(row)
            item["id"] = int(item.get("id") or 0)
            yield item


def verify_entries(entries: List[Dict[str, Any]], max_breaks: int = 20) -> Dict[str, Any]:
    """Check each entry's hash and its link to the entry before it."""
    breaks: List[Dict[str, Any]] = []
    total = 0
    prev_hash = ""
    head: Optional[Dict[str, Any]] = None
    for index, entry in enumerate(entries):
        total += 1
        problems = []
        if index == 0:
            prev_hash = str(entry.get("prev_hash") or "")
            if prev_hash:
                problems.append("first entry links to a predecessor that is not present (truncated journal)")
        elif str(entry.get("prev_hash") or "") != prev_hash:
            problems.append("prev_hash does not match the previous entry's entry_hash")
        expected = compute_entry_hash(entry)
        if expected != str(entry.get("entry_hash") or ""):
            problems.append("entry_hash does not match the entry's contents")
        if problems and len(breaks) < max_breaks:
            breaks.append({"id": entry.get("id"), "created_at": entry.get("created_at"), "problems": problems})
        prev_hash = str(entry.get("entry_hash") or "")
        head = entry
    return {
        "ok": not breaks,
        "entries_checked": total,
        "breaks": breaks,
        "head": {"id": head.get("id"), "entry_hash": head.get("entry_hash"),
                 "created_at": head.get("created_at")} if head else None,
    }


def verify_chain(org_id: Optional[str] = None) -> Dict[str, Any]:
    org = str(org_id or current_organization_id() or "").strip()
    result = verify_entries(list(iter_entries(org)))
    result["organization_id"] = org
    result["algorithm"] = "sha256 over '|'.join(" + ", ".join(HASH_FIELDS) + ")"
    return result


def export_chain(org_id: Optional[str] = None) -> Dict[str, Any]:
    org = str(org_id or current_organization_id() or "").strip()
    keep = ("id",) + HASH_FIELDS + ("entry_hash",)
    entries = [{k: e.get(k) for k in keep} for e in iter_entries(org)]
    return {"format": EXPORT_FORMAT, "organization_id": org, "hash_fields": list(HASH_FIELDS), "entries": entries}
