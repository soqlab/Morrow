"""Wall mode: one sentence and one number on an office screen, through a display link.

A display link lets a TV or monitor show the organization's quantum risk without anyone signing in on
it. An admin creates the link in Administration -> Display links; the screen opens
``/wall#t=<token>`` and the page sends the token as the ``X-Display-Token`` header to
``GET /api/public/wall``. The fragment never reaches the server, a log line or a Referer.

What a display link can do, and nothing more:

* read one payload -- the risk sentence (services/risk_sentence.py), one number the admin picked
  (NUMBERS below) and how old the data behind them is. No other route accepts the token: it is not
  a bearer token, an API key or a session, and the auth middleware never looks at it;
* be revoked at once, and expire on its own if the admin set an expiry.

Storage: ``display_links``, one row per link, org-scoped (``org_id``) and in the Postgres RLS plan
(services/postgres_rls.py). Only the SHA-256 of the token is kept; the token itself is shown to the
admin once, inside the link. The token carries 256 random bits, so a fast unsalted hash is enough:
there is nothing to guess. Looking a token up crosses tenants (the token names its organization),
so that one statement runs in a named ``tenant_scope.platform_scope``; everything the wall then
reads runs as the link's organization only.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn

TOKEN_PREFIX = "mwd_"
_TOKEN_RE = re.compile(r"^mwd_[A-Za-z0-9_-]{40,60}$")
MAX_LINKS_PER_ORG = 50
NAME_MAX = 80
#: How often a link's "last used" time is rewritten. The screen asks every minute.
LAST_USED_GRANULARITY_SECONDS = 300
EXPIRY_CHOICES_DAYS = (0, 1, 7, 30, 90, 365)

#: The numbers an admin can put on the screen. The first one is the default.
NUMBERS: List[Dict[str, str]] = [
    {"id": "not_safe", "label": "Hosts not yet quantum-safe",
     "help": "How many of your scanned hosts still use a key exchange a quantum computer could break."},
    {"id": "safe_share", "label": "Share of hosts that are quantum-safe",
     "help": "The percentage of your scanned hosts whose key exchange already includes ML-KEM."},
    {"id": "time_to_safe", "label": "Fire drill: days to safe",
     "help": "Time-to-safe from your latest quantum fire drill."},
]
NUMBER_IDS = tuple(n["id"] for n in NUMBERS)
DEFAULT_NUMBER = NUMBER_IDS[0]

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS display_links (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
        metric TEXT NOT NULL DEFAULT 'not_safe', token_hash TEXT NOT NULL UNIQUE,
        created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT NOT NULL DEFAULT '',
        revoked_at TEXT NOT NULL DEFAULT '', revoked_by TEXT NOT NULL DEFAULT '',
        last_used_at TEXT NOT NULL DEFAULT '')""",
    "CREATE INDEX IF NOT EXISTS idx_display_links_org ON display_links(org_id, created_at)",
)

_ready_lock = threading.Lock()
_ready_for = ""


class DisplayLinkError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _init() -> None:
    global _ready_for
    from db_feature_store import dialect, _sqlite_path  # noqa: F401  (path changes between test databases)

    marker = f"{dialect()}:{_sqlite_path() if dialect() == 'sqlite' else ''}"
    if _ready_for == marker:
        return
    with _ready_lock:
        with feature_conn() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.commit()
        _ready_for = marker


def init_tables() -> None:
    """Create the table now (db_postgres.apply_deferred_schemas, registered in app.py)."""
    global _ready_for
    _ready_for = ""
    _init()


def _scope(reason: str):
    from services import tenant_scope

    return tenant_scope.platform_scope(reason)


def _status(row: Dict[str, Any], now: datetime) -> str:
    if row.get("revoked_at"):
        return "revoked"
    exp = _ts(row.get("expires_at"))
    if exp and exp <= now:
        return "expired"
    return "active"


def _public(row: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
    """A link as the settings screen sees it. Never the hash."""
    d = dict(row)
    d.pop("token_hash", None)
    d.pop("org_id", None)
    d["status"] = _status(d, now or _now())
    d["metric_label"] = next((n["label"] for n in NUMBERS if n["id"] == d.get("metric")), d.get("metric"))
    for k in ("expires_at", "revoked_at", "revoked_by", "last_used_at"):
        d[k] = d.get(k) or None
    return d


def options() -> Dict[str, Any]:
    return {"numbers": NUMBERS, "default_number": DEFAULT_NUMBER, "expiry_days": list(EXPIRY_CHOICES_DAYS)}


def _base_url() -> str:
    try:
        from services.public_config import public_base_url

        return (public_base_url() or "").rstrip("/")
    except Exception:
        return ""


# ── Managing links (admin, inside the organization's own tenant context) ─────────────────────────


def list_links(org_id: str) -> List[Dict[str, Any]]:
    _init()
    now = _now()
    with feature_conn() as conn:
        rows = conn.execute("SELECT * FROM display_links WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT 200",
                            (org_id,)).fetchall()
    return [_public(r, now) for r in rows]


def create_link(org_id: str, created_by: str, name: str = "", metric: str = DEFAULT_NUMBER,
                expires_in_days: int = 0, now: Optional[datetime] = None) -> Dict[str, Any]:
    """A new link. The returned ``token`` and ``url`` are shown once; only the hash is stored."""
    _init()
    now = now or _now()
    metric = str(metric or DEFAULT_NUMBER)
    if metric not in NUMBER_IDS:
        raise DisplayLinkError(400, f"Pick one of: {', '.join(NUMBER_IDS)}.")
    try:
        days = int(expires_in_days or 0)
    except (TypeError, ValueError):
        days = -1
    if days not in EXPIRY_CHOICES_DAYS:
        raise DisplayLinkError(400, "Expiry must be never, or 1, 7, 30, 90 or 365 days.")
    label = re.sub(r"\s+", " ", str(name or "")).strip()[:NAME_MAX] or "Office screen"
    with feature_conn() as conn:
        live = [r for r in conn.execute("SELECT revoked_at, expires_at FROM display_links WHERE org_id = ?",
                                        (org_id,)).fetchall() if _status(dict(r), now) == "active"]
        if len(live) >= MAX_LINKS_PER_ORG:
            raise DisplayLinkError(409, f"Your organization already has {MAX_LINKS_PER_ORG} working display links. "
                                        "Revoke one first.")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        link_id = "dsp_" + secrets.token_hex(8)
        expires = _iso(now + timedelta(days=days)) if days else ""
        conn.execute(
            "INSERT INTO display_links (id, org_id, name, metric, token_hash, created_by, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (link_id, org_id, label, metric, hash_token(token), str(created_by or "")[:160], _iso(now), expires))
        conn.commit()
        row = conn.execute("SELECT * FROM display_links WHERE org_id = ? AND id = ?", (org_id, link_id)).fetchone()
    out = _public(row, now)
    out["token"] = token
    out["url"] = f"{_base_url()}/wall#t={token}"
    return out


def _get(conn: Any, org_id: str, link_id: str) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM display_links WHERE org_id = ? AND id = ?", (org_id, str(link_id or ""))).fetchone()
    if not row:
        raise DisplayLinkError(404, "No display link with that id in your organization.")
    return dict(row)


def set_metric(org_id: str, link_id: str, metric: str) -> Dict[str, Any]:
    _init()
    if metric not in NUMBER_IDS:
        raise DisplayLinkError(400, f"Pick one of: {', '.join(NUMBER_IDS)}.")
    with feature_conn() as conn:
        _get(conn, org_id, link_id)
        conn.execute("UPDATE display_links SET metric = ? WHERE org_id = ? AND id = ?", (metric, org_id, link_id))
        conn.commit()
        return _public(_get(conn, org_id, link_id))


def revoke_link(org_id: str, link_id: str, revoked_by: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    _init()
    now = now or _now()
    with feature_conn() as conn:
        row = _get(conn, org_id, link_id)
        if not row.get("revoked_at"):
            conn.execute("UPDATE display_links SET revoked_at = ?, revoked_by = ? WHERE org_id = ? AND id = ?",
                         (_iso(now), str(revoked_by or "")[:160], org_id, link_id))
            conn.commit()
        return _public(_get(conn, org_id, link_id), now)


# ── The screen ──────────────────────────────────────────────────────────────────────────────────


def resolve(token: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The link a presented token belongs to, or DisplayLinkError(401). Records "last used"."""
    text = str(token or "").strip()
    if not _TOKEN_RE.match(text):
        raise DisplayLinkError(401, "This screen has no display link. Open the link an admin made in Morrow.")
    _init()
    now = now or _now()
    with _scope("wall mode: the organization a display link belongs to"), feature_conn() as conn:
        row = conn.execute("SELECT id, org_id, metric, revoked_at, expires_at, last_used_at FROM display_links "
                           "WHERE token_hash = ?", (hash_token(text),)).fetchone()
        if not row:
            raise DisplayLinkError(401, "This display link does not exist. Ask an admin for a new one.")
        link = dict(row)
        state = _status(link, now)
        if state == "revoked":
            raise DisplayLinkError(401, "This display link was revoked. Ask an admin for a new one.")
        if state == "expired":
            raise DisplayLinkError(401, "This display link has expired. Ask an admin for a new one.")
        last = _ts(link.get("last_used_at"))
        if not last or (now - last).total_seconds() >= LAST_USED_GRANULARITY_SECONDS:
            conn.execute("UPDATE display_links SET last_used_at = ? WHERE id = ?", (_iso(now), link["id"]))
            conn.commit()
    return {"id": link["id"], "org_id": link["org_id"], "metric": link["metric"]}


def host_state(fact: Dict[str, Any]) -> str:
    """``safe`` (key exchange includes ML-KEM), ``at_risk`` (classical or not seen) or ``unknown`` (not reached)."""
    from services import crypto_switch

    if str(fact.get("scan_status") or "ok").lower() not in ("ok", "completed", "success", ""):
        return "unknown"
    family, _ = crypto_switch.observed(fact, "kex")
    return "safe" if family == "mlkem" else "at_risk"


def _target(fact: Dict[str, Any]) -> str:
    key = str(fact.get("asset_key") or "")
    return key[:-4] if key.endswith(":443") else key


def build(facts: List[Dict[str, Any]], drill: Optional[Dict[str, Any]], metric: str,
          now: Optional[datetime] = None) -> Dict[str, Any]:
    """The wall's one sentence and one number from the organization's own data. Pure.

    ``number.value`` is None whenever Morrow has nothing to count: the screen then says so and never
    shows a zero it did not measure.
    """
    from services import risk_sentence

    now = now or _now()
    metric = metric if metric in NUMBER_IDS else DEFAULT_NUMBER
    states = [(f, host_state(f)) for f in facts or []]
    at = [f for f, s in states if s == "at_risk"]
    safe = [f for f, s in states if s == "safe"]
    unknown = [f for f, s in states if s == "unknown"]
    scanned_at = [t for t in (_ts(f.get("scanned_at")) for f in facts or []) if t]
    scan_as_of = _iso(max(scanned_at)) if scanned_at else None

    if not states:
        sentence = "Morrow has no scan of your systems yet. Run a scan and this screen fills in."
        risk_state = None
    else:
        pick = at[0] if at else (safe[0] if len(safe) == len(states) else states[0][0])
        state = "at_risk" if at else ("safe" if len(safe) == len(states) else "unknown")
        others = max(0, (len(at) if at else len(states)) - 1)
        risk = risk_sentence.build(_target(pick), state, pick.get("findings_count") or 0, others=others, now=now)
        sentence, risk_state = risk["sentence"], risk["state"]

    measured = len(at) + len(safe)
    if metric == "not_safe":
        number = {"value": len(at) if states else None, "unit": "",
                  "label": ("host not yet quantum-safe" if len(at) == 1 else "hosts not yet quantum-safe"),
                  "detail": (f"of {len(states)} scanned" + (f" · {len(unknown)} could not be read" if unknown else ""))
                  if states else "No scan yet"}
        as_of = scan_as_of
    elif metric == "safe_share":
        value = int(round(100.0 * len(safe) / measured)) if measured else None
        number = {"value": value, "unit": "%", "label": "of your hosts are quantum-safe",
                  "detail": (f"{len(safe)} of {measured} hosts" + (f" · {len(unknown)} could not be read" if unknown else ""))
                  if measured else ("No scan yet" if not states else "No host could be read")}
        as_of = scan_as_of
    else:
        ok = bool(drill) and drill.get("status") == "ok" and drill.get("time_to_safe_days") is not None
        days = drill.get("days") if ok else None
        value = int(drill["time_to_safe_days"]) if ok else None
        lo = int(-(-float(days["low"]) // 1)) if days else None
        hi = int(-(-float(days["high"]) // 1)) if days else None
        number = {"value": value, "unit": "", "label": ("day to safe" if value == 1 else "days to safe"),
                  "detail": (f"if {drill.get('broken')} broke this morning" + (f" · range {lo}–{hi} days" if lo != hi else ""))
                  if ok else ("No fire drill has run yet" if not drill else "The latest fire drill has no time-to-safe")}
        as_of = drill.get("created_at") if drill else None

    return {
        "sentence": sentence,
        "risk_state": risk_state,
        "metric": metric,
        "number": number,
        "data_as_of": as_of,
        "hosts": {"scanned": len(states), "safe": len(safe), "at_risk": len(at), "unknown": len(unknown)},
    }


def latest_drill(org_id: str) -> Optional[Dict[str, Any]]:
    try:
        from services import fire_drill

        rows = fire_drill.list_drills(org_id, limit=1)
    except Exception:
        return None
    return rows[0] if rows else None


def payload_for(link: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Everything the screen shows, read as the link's organization and nothing else."""
    import db

    org_id = link["org_id"]
    ctx = db.set_current_organization_id(org_id)
    try:
        facts = db.latest_scan_facts_for_org(limit=5000)  # the sentence needs them for every number
        drill = latest_drill(org_id) if link["metric"] == "time_to_safe" else None
    finally:
        db.reset_current_organization_id(ctx)
    return build(facts, drill, link["metric"], now)


def etag(body: Dict[str, Any]) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return '"' + hashlib.sha256(raw).hexdigest()[:32] + '"'
