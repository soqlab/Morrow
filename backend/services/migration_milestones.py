"""Migration deadlines per organization: the named milestones the velocity report measures against.

The velocity report used to know one deadline, 1 January 2030. Real programmes have several:
an agency deprecating quantum-vulnerable algorithms on one date and disallowing them on another,
a sector regulator with its own date, an internal target set a year early. Each organization
keeps its own list here; one that has never saved a list gets DEFAULT_MILESTONES.

Storage: one row per organization in ``org_migration_milestones`` (feature store, so the same
code serves SQLite and Postgres). The tenant column is ``org_id`` and the table is in
services/postgres_rls.ORG_SCOPED_TABLES / TENANT_COLUMNS, so on Postgres it is under the same
row-level-security policy as the other org-scoped settings tables. Every statement is also
scoped by org_id, and the wildcard organization is refused.

Sources for the defaults (checked against the primary documents, November 2026):

  NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", final, October 2026,
  https://doi.org/10.6028/NIST.IR.8547 (initial public draft November 2024, same dates).
  Section 4 and Tables 3 and 4: NIST will deprecate all quantum-vulnerable public-key
  digital signature (RSA, ECDSA, EdDSA) and key-establishment (finite-field and elliptic-curve
  DH/MQV, RSA) schemes "after 2030" and disallow them "after 2035". "After 2030" means they
  remain merely deprecated through 31 December 2030, so that is the milestone date; likewise
  31 December 2035. The same report restates NSM-10's 2035 target for completing the federal
  migration.

Not a default, on purpose: NSA CNSA 2.0 (National Security Systems only). Its per-category
dates (software/firmware signing exclusively CNSA 2.0 by 2030, web/cloud and operating systems
by 2033, all NSS quantum-resistant by 2035) are widely quoted, but the NSA advisory itself
(media.defense.gov CSA_CNSA_2.0_ALGORITHMS.PDF) could not be retrieved to check when this was
written. An organization under CNSA 2.0 adds those milestones itself, with its own scope.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

import db_feature_store as store

TABLE = "org_migration_milestones"

#: Bounds on what an organization may save. Past dates are allowed (a missed deadline is still a
#: deadline the report should show as missed); dates outside these years are a typo.
EARLIEST_DATE = date(2000, 1, 1)
LATEST_DATE = date(2100, 12, 31)
MAX_MILESTONES = 12
MAX_NAME = 120
MAX_SCOPE = 300
MAX_SOURCE = 300
MAX_URL = 500

NIST_IR_8547_URL = "https://doi.org/10.6028/NIST.IR.8547"

DEFAULT_MILESTONES: List[Dict[str, str]] = [
    {
        "id": "nist-ir-8547-deprecated",
        "name": "Quantum-vulnerable public-key deprecated (NIST IR 8547)",
        "date": "2030-12-31",
        "scope": "RSA, ECDSA and EdDSA signatures; DH, ECDH and RSA key establishment. "
                 "Deprecated under NIST standards after 2030.",
        "source": "NIST IR 8547 (final, October 2026), section 4, Tables 3 and 4",
        "source_url": NIST_IR_8547_URL,
    },
    {
        "id": "nist-ir-8547-disallowed",
        "name": "Quantum-vulnerable public-key disallowed (NIST IR 8547)",
        "date": "2035-12-31",
        "scope": "All quantum-vulnerable public-key cryptography disallowed under NIST standards "
                 "after 2035; also the NSM-10 target for completing the federal migration.",
        "source": "NIST IR 8547 (final, October 2026), section 4, Tables 3 and 4",
        "source_url": NIST_IR_8547_URL,
    },
]

SCHEMA = f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        org_id TEXT PRIMARY KEY,
        milestones TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
    )
"""

_ready: set = set()
_ready_lock = threading.Lock()
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class MilestoneError(ValueError):
    def __init__(self, detail: str, status_code: int = 422) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def defaults() -> List[Dict[str, str]]:
    return [dict(m) for m in DEFAULT_MILESTONES]


def _identity() -> tuple:
    try:
        return (store.dialect(), store._feature_dsn() if store.postgres_enabled() else store._sqlite_path())
    except Exception:
        return (store.dialect(), "")


def _init() -> None:
    identity = _identity()
    if identity in _ready:
        return
    with _ready_lock:
        if identity in _ready:
            return
        with store.feature_conn() as conn:
            conn.execute(SCHEMA)
            conn.commit()
        _ready.add(identity)


def init_tables() -> None:
    """Create this module's tables now (db_postgres.apply_deferred_schemas, registered in app.py),
    so a fresh Postgres deployment has them before the RLS plan is applied, not on first use."""
    _init()


def _org(org_id: Any) -> str:
    org = str(org_id or "").strip()
    if not org or org == "*":
        raise MilestoneError("A verified organization is required.", 403)
    return org


def _scope(conn: Any, org: str) -> None:
    # Publish the tenant for the row-level-security policy, as services/llm/org_config does. The
    # request context normally already set it; a background caller may not have.
    if store.postgres_enabled():
        conn.execute("SELECT set_config('app.current_organization_id',?,true)", (org,))


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str:
    text = _CONTROL.sub(" ", str(value if value is not None else "")).strip()
    text = re.sub(r"\s+", " ", text)
    if required and not text:
        raise MilestoneError(f"Each milestone needs a {field}.")
    if len(text) > limit:
        raise MilestoneError(f"A milestone {field} can be at most {limit} characters.")
    return text


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "milestone"


def _date(value: Any, name: str) -> str:
    raw = str(value or "").strip()
    parsed: Optional[date] = None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        try:
            parsed = date.fromisoformat(raw)
        except ValueError:  # 2030-02-30
            parsed = None
    if parsed is None:
        raise MilestoneError(f"'{name}': the date must be a calendar date written YYYY-MM-DD.")
    if not (EARLIEST_DATE <= parsed <= LATEST_DATE):
        raise MilestoneError(
            f"'{name}': the date must fall between {EARLIEST_DATE.isoformat()} and {LATEST_DATE.isoformat()}.")
    return parsed.isoformat()


def validate(raw: Any) -> List[Dict[str, str]]:
    """A clean, date-ordered milestone list from what a caller sent, or MilestoneError."""
    if not isinstance(raw, list):
        raise MilestoneError("milestones must be a list.")
    if not raw:
        raise MilestoneError("Keep at least one milestone, or reset to the defaults.")
    if len(raw) > MAX_MILESTONES:
        raise MilestoneError(f"An organization can track up to {MAX_MILESTONES} milestones.")
    out: List[Dict[str, str]] = []
    names: set = set()
    ids: set = set()
    for item in raw:
        if not isinstance(item, dict):
            raise MilestoneError("Each milestone must be an object with a name and a date.")
        name = _text(item.get("name"), "name", MAX_NAME, required=True)
        if name.lower() in names:
            raise MilestoneError(f"Two milestones are both called '{name}'. Give each its own name.")
        names.add(name.lower())
        when = _date(item.get("date"), name)
        url = _text(item.get("source_url"), "source link", MAX_URL)
        if url and not re.match(r"^https?://[^\s/]+", url, re.I):
            raise MilestoneError(f"'{name}': the source link must be an http(s) URL.")
        ident = _slug(str(item.get("id") or "") or name)
        base, n = ident, 2
        while ident in ids:
            ident, n = f"{base}-{n}", n + 1
        ids.add(ident)
        out.append({
            "id": ident,
            "name": name,
            "date": when,
            "scope": _text(item.get("scope"), "scope", MAX_SCOPE),
            "source": _text(item.get("source"), "source", MAX_SOURCE),
            "source_url": url,
        })
    out.sort(key=lambda m: (m["date"], m["name"].lower()))
    return out


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get(org_id: Any) -> Dict[str, Any]:
    """{"milestones": [...], "source": "organization" | "default", "updated_at", "updated_by"}."""
    org = _org(org_id)
    _init()
    with store.feature_conn() as conn:
        _scope(conn, org)
        row = conn.execute(f"SELECT milestones, updated_at, updated_by FROM {TABLE} WHERE org_id = ?",  # nosec B608  # TABLE is a module constant; org is bound
                           (org,)).fetchone()
    if row:
        try:
            saved = validate(json.loads(row["milestones"]))
            return {"milestones": saved, "source": "organization",
                    "updated_at": row["updated_at"], "updated_by": row["updated_by"] or ""}
        except (ValueError, TypeError):
            pass  # an unreadable row falls back to the defaults rather than breaking the report
    return {"milestones": defaults(), "source": "default", "updated_at": None, "updated_by": ""}


def milestones_for(org_id: Any) -> List[Dict[str, str]]:
    """The list the velocity report should use. Never raises: storage trouble means defaults."""
    try:
        return get(org_id)["milestones"]
    except Exception:
        return defaults()


def save(org_id: Any, raw: Any, actor: str = "") -> Dict[str, Any]:
    org = _org(org_id)
    clean = validate(raw)
    _init()
    with store.feature_conn() as conn:
        _scope(conn, org)
        conn.execute(
            f"INSERT INTO {TABLE} (org_id, milestones, updated_at, updated_by) VALUES (?, ?, ?, ?) "  # nosec B608  # TABLE is a module constant; values are bound
            "ON CONFLICT (org_id) DO UPDATE SET milestones = excluded.milestones, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (org, json.dumps(clean, separators=(",", ":")), _now(), str(actor or "")[:200]),
        )
        conn.commit()
    return get(org)


def reset(org_id: Any) -> Dict[str, Any]:
    """Forget the organization's list; the defaults apply again."""
    org = _org(org_id)
    _init()
    with store.feature_conn() as conn:
        _scope(conn, org)
        conn.execute(f"DELETE FROM {TABLE} WHERE org_id = ?", (org,))  # nosec B608  # TABLE is a module constant; org is bound
        conn.commit()
    return get(org)


def describe_bounds() -> Dict[str, Any]:
    """What validate() accepts, for the API answer and the console form."""
    return {"earliest_date": EARLIEST_DATE.isoformat(), "latest_date": LATEST_DATE.isoformat(),
            "max_milestones": MAX_MILESTONES, "max_name": MAX_NAME, "max_scope": MAX_SCOPE,
            "max_source": MAX_SOURCE}


__all__ = ["DEFAULT_MILESTONES", "MilestoneError", "defaults", "describe_bounds", "get", "milestones_for",
           "reset", "save", "validate"]
