"""The public list "Not yet post-quantum": large public sites whose newest check is below B.

Who can be on it: only domains from the stored Tranco top list (services/tranco.py), graded by
the weekly league tick. Never a domain someone typed into the checker, never a private
individual's site, never a domain that opted out (services/public_check.opted_out). A domain
leaves the list on its first check that grades it A or B, and can then opt into the ready list.

How it is worded: measured facts with their date and source, never a label. Each entry reads
like "acme.com: traffic recorded today could be decrypted around 2035-2040 (checked 2026-11-13).
Key exchange: x25519 only." Entries are sorted by sector then name and are not ranked against
each other; the grade is shown as measured.

Right of reply: an organisation that has verified the domain (DNS TXT) can attach one plain-text
statement of at most 280 characters, shown with the entry and dated. Moderation is by length and
characters only. Table ``not_ready_replies`` is org-scoped and in the Postgres RLS plan; reading
replies for the public list crosses tenants and runs in a named ``tenant_scope.platform_scope``.

Corrections: anyone can ask for a correction (domain, reason, contact). Requests are stored in
``public_correction_requests``, rate limited per address, and written to the checker's abuse log.
"""

from __future__ import annotations

import os
import re
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn

READY = ("A", "B")
REPLY_MAX = 280
REASON_MAX = 1000
CONTACT_MAX = 200
#: Words the list never uses about anyone. Tests hold every generated sentence to this.
BANNED_WORDS = ("unsafe", "insecure", "fail", "shame", "vulnerable", "dangerous", "bad")

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS not_ready_replies (
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (org_id, domain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS public_correction_requests (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        reason TEXT NOT NULL,
        contact TEXT NOT NULL,
        created_at TEXT NOT NULL,
        requester_hash TEXT NOT NULL DEFAULT ''
    )
    """,
)
_ready = ""
_lock = threading.Lock()


class ReplyError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def _identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def init_tables() -> None:
    global _ready
    identity = _identity()
    if _ready == identity:
        return
    with _lock:
        with feature_conn() as conn:
            for ddl in SCHEMA:
                conn.execute(ddl)
            conn.commit()
        _ready = identity


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(value: Any, limit: int) -> str:
    """Plain text: control and formatting characters removed, whitespace collapsed, at most ``limit``."""
    text = "".join(ch for ch in str(value or "") if unicodedata.category(ch)[0] != "C")
    return re.sub(r"\s+", " ", text).strip()[:limit]


def statement(result: Dict[str, Any]) -> str:
    """One measured sentence for an entry: what was seen, with the date. No labels."""
    domain = str(result.get("domain") or "")
    day = str(result.get("scanned_at") or "")[:10]
    kx = result.get("key_exchange") or {}
    ex = result.get("exposure") or {}
    group = kx.get("group") or ""
    parts = []
    if ex.get("decrypt_year_low"):
        parts.append(f"{domain}: traffic recorded today could be decrypted around {ex['decrypt_year_low']}-"
                     f"{ex['decrypt_year_high']} (checked {day}).")
    else:
        parts.append(f"{domain}: checked {day}.")
    if group and not kx.get("post_quantum"):
        parts.append(f"Key exchange: {group} only.")
    elif not group:
        parts.append("Key exchange: not observed.")
    cert = result.get("certificate") or {}
    if cert.get("verified") is False:
        parts.append("The certificate did not verify in this check.")
    versions = (result.get("tls") or {}).get("versions") or {}
    if versions.get("1.0") or versions.get("1.1"):
        parts.append("TLS 1.0 or 1.1 was accepted.")
    return " ".join(parts)


def _replies() -> Dict[str, Dict[str, str]]:
    from services import tenant_scope

    init_tables()
    with tenant_scope.platform_scope("not-yet-post-quantum list: owners' replies shown with their entries"):
        with feature_conn() as conn:
            rows = conn.execute("SELECT domain, text, created_at FROM not_ready_replies ORDER BY created_at").fetchall()
    out: Dict[str, Dict[str, str]] = {}
    for r in rows:
        out[str(r["domain"])] = {"text": str(r["text"]), "at": str(r["created_at"])}
    return out


def entries(sector: str = "") -> Dict[str, Any]:
    from services import decrypt_window, league, public_check, public_grade, tranco

    spec = league.load_spec()
    classifier = league.Classifier(spec)
    names = {s["id"]: s["name"] for s in spec["sectors"]}
    names[league.UNCLASSIFIED] = "Other popular sites"
    optouts = league._optout_entries()
    domains = [d for d in tranco.domains() if not league._covered(d, optouts) and not public_check.opted_out(d)]
    replies = _replies()
    out = []
    for d in domains:
        latest = public_grade.latest(d)
        if not latest or latest.get("grade") in READY or latest.get("grade") not in public_grade.GRADES:
            continue
        sid = classifier.classify(d)
        if sector and sid != sector:
            continue
        ex = latest.get("exposure") or {}
        out.append({
            "domain": d, "sector": sid, "sector_name": names.get(sid, sid), "grade": latest.get("grade"),
            "checked_at": latest.get("scanned_at"), "statement": statement(latest),
            "key_exchange": (latest.get("key_exchange") or {}).get("group") or None,
            "decrypt_year_low": ex.get("decrypt_year_low"), "decrypt_year_high": ex.get("decrypt_year_high"),
            "source_url": ex.get("source_url") or decrypt_window.EXPOSURE_SOURCE_URL,
            "reply": replies.get(d),
        })
    out.sort(key=lambda e: (e["sector_name"], e["domain"]))
    meta = tranco.meta()
    return {
        "title": "Not yet post-quantum",
        "entries": out, "count": len(out), "sector": sector or None,
        "sectors": sorted({(e["sector"], e["sector_name"]) for e in out}, key=lambda x: x[1]),
        "methodology": methodology(meta),
    }


def methodology(meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from services import decrypt_window, public_grade, tranco

    return {
        "rubric_version": public_grade.RUBRIC_VERSION,
        "measured": "One set of TLS handshakes to port 443 per site, at most once a week: the key exchange "
                    "the server chooses when post-quantum groups are offered, the TLS versions it accepts, "
                    "and whether its certificate verifies. Nothing else is fetched.",
        "who": "Only sites from the Tranco list of popular sites (" + tranco.CITATION + "), top "
               + str(tranco.size()) + ". Never a domain typed into the checker, never a domain that opted out.",
        "leaves": "A site leaves the list on its first check graded A or B.",
        "decrypt_window": {"low": decrypt_window.DECRYPT_YEAR_LOW, "high": decrypt_window.DECRYPT_YEAR_HIGH,
                           "source": decrypt_window.EXPOSURE_SOURCE_LABEL, "source_url": decrypt_window.EXPOSURE_SOURCE_URL},
        "list": meta,
        "not_a_ranking": "Sorted by sector, then name. Entries are not ranked against each other.",
    }


def set_reply(org_id: str, domain: str, text: str, actor: str = "") -> Dict[str, Any]:
    from services import domain_verification

    name = domain_verification.normalize_domain(domain)
    if name not in domain_verification.verified_domains(org_id):
        raise ReplyError(403, f"{name} is not verified for your organisation. Verify it by DNS to reply.", "not_verified")
    body = clean_text(text, REPLY_MAX + 1)
    if not body:
        raise ReplyError(400, "The reply is empty.", "empty")
    if len(body) > REPLY_MAX:
        raise ReplyError(400, f"A reply is at most {REPLY_MAX} characters.", "too_long")
    init_tables()
    now = _now()
    with feature_conn() as conn:
        conn.execute("DELETE FROM not_ready_replies WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.execute("INSERT INTO not_ready_replies (org_id, domain, text, created_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                     (org_id, name, body, now, str(actor or "")))
        conn.commit()
    return {"domain": name, "text": body, "at": now}


def delete_reply(org_id: str, domain: str) -> bool:
    from services import domain_verification

    name = domain_verification.normalize_domain(domain)
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM not_ready_replies WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def my_replies(org_id: str) -> Dict[str, Dict[str, str]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT domain, text, created_at FROM not_ready_replies WHERE org_id = ?", (org_id,)).fetchall()
    return {str(r["domain"]): {"text": str(r["text"]), "at": str(r["created_at"])} for r in rows}


def request_correction(domain: Any, reason: Any, contact: Any, client_ip: str = "") -> Dict[str, Any]:
    from services import org_rate_limits, public_check

    name = str(domain or "").strip().lower().rstrip(".")[:253]
    why = clean_text(reason, REASON_MAX)
    who = clean_text(contact, CONTACT_MAX)
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,63}$", name):
        raise ReplyError(400, "Name the domain the correction is about, for example example.com.", "bad_domain")
    if len(why) < 10:
        raise ReplyError(400, "Say what is wrong in a sentence or two.", "no_reason")
    if not who:
        raise ReplyError(400, "Leave an email address or another way to reach you.", "no_contact")
    ip_hash = public_check.hash_ip(client_ip)
    hit = org_rate_limits.hit("correction_request_ip", ip_hash, 5, 3600.0)
    if not hit.get("allowed"):
        raise ReplyError(429, "Five correction requests an hour from one address; try again later.", "rate_limited")
    init_tables()
    rid = str(uuid.uuid4())
    with feature_conn() as conn:
        conn.execute("INSERT INTO public_correction_requests (id, domain, reason, contact, created_at, requester_hash) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (rid, name, why, who, _now(), ip_hash))
        conn.commit()
    public_check.log_check(name, ip_hash, "correction_request", why[:200])
    return {"id": rid, "domain": name, "received": True}


def changes(sector: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    """Joins and leaves, newest first: a Tranco domain joins when a check grades it below B after it
    was A, B or ungraded, and leaves when a check grades it A or B after it was below."""
    from services import league, public_check, public_grade, tranco

    classifier = league.Classifier(league.load_spec())
    events = []
    for d in tranco.domains():
        if public_check.opted_out(d):
            continue
        if sector and classifier.classify(d) != sector:
            continue
        previous_ready: Optional[bool] = None
        for change in reversed(public_grade.grade_changes(d)):
            ready = change["grade"] in READY
            if previous_ready is None:
                if not ready:
                    events.append({"domain": d, "event": "joined", "grade": change["grade"], "at": change["scanned_at"]})
            elif ready != previous_ready:
                events.append({"domain": d, "event": "left" if ready else "joined", "grade": change["grade"],
                               "at": change["scanned_at"]})
            previous_ready = ready
    events.sort(key=lambda e: e["at"], reverse=True)
    return events[:limit]


def atom(base_url: str, sector: str = "") -> str:
    from xml.sax.saxutils import escape

    base = base_url.rstrip("/")
    items = []
    events = changes(sector)
    for e in events:
        title = (f"{e['domain']} joined the list (grade {e['grade']})" if e["event"] == "joined"
                 else f"{e['domain']} left the list (grade {e['grade']})")
        items.append("<entry><id>urn:morrow:not-ready:" + escape(e["domain"]) + ":" + escape(e["at"]) + "</id>"
                     "<title>" + escape(title) + "</title><updated>" + escape(e["at"]) + "</updated>"
                     '<link href="' + escape(base + "/" + e["domain"]) + '"/></entry>')
    updated = events[0]["at"] if events else "1970-01-01T00:00:00Z"
    return ('<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'
            "<id>urn:morrow:not-ready" + (":" + escape(sector) if sector else "") + "</id>"
            "<title>Not yet post-quantum" + (" (" + escape(sector) + ")" if sector else "") + ": joining and leaving</title>"
            "<updated>" + escape(updated) + "</updated>"
            '<link rel="alternate" href="' + escape(base + "/league") + '"/>' + "".join(items) + "</feed>\n")
