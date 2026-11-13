"""Vendor check: a buyer's list of vendor domains, each given the public grade, as one report.

A buyer pastes or uploads a list of the domains their vendors run. Morrow grades each one with the
public grade (services/public_grade.py: the same guarded handshake probe as ``/<domain>``,
including the key-exchange check) and answers first: "12 of your 40 vendors would let today's
traffic be read later. Worst: payroll.example (RSA key exchange)." The vendors are listed worst
first, each linking to its public ``/<domain>`` page, with a polite "ask your vendor" note the
buyer can send themselves. Morrow sends nothing to anyone.

The list
--------
``parse`` accepts pasted text or an uploaded CSV / text file: any cell or word that is a bare
hostname or a URL is taken (scheme, path, port and a leading ``*.`` dropped); e-mail addresses,
IP addresses and anything else are reported as skipped, never guessed. Duplicates are removed.
At most ``max_domains(signed_in)`` domains: 50 without an account, 500 signed in
(``MORROW_VENDOR_MAX_ANON``, ``MORROW_VENDOR_MAX_SIGNED_IN``). A longer list is refused with the
count, not cut silently.

The check
---------
A report is a row in ``vendor_check_reports``. Its vendors are graded by a background job in
this process: at most ``jobs()`` reports at once (the rest wait, "queued"), ``workers()`` domains
at a time within one report. A stored public grade younger than ``reuse_seconds()`` (24 h) is
reused without contacting anything; otherwise ``public_grade.check`` runs the probe behind its
SSRF guard (``resolve_pinned``: one pinned public address, private/loopback/link-local/CGNAT/
reserved/this server refused), the opt-out list, its per-domain and global budgets, its
concurrency cap and its per-check deadline. When those budgets say "later", the job waits and
retries until the report's deadline (``MORROW_VENDOR_JOB_DEADLINE``, 30 min); what is left is
marked "not checked yet" and is picked up by the next re-check. Progress is written after every
domain, so the report page shows it live and a restarted server resumes the job (a report whose
runner stopped heartbeating is claimed again on the next read).

Rate limits, through services/org_rate_limits.py: lists per client IP per hour and domains per
client IP per day (anonymous), lists per organisation per hour (signed in), and a global budget
of uncached vendor probes per hour.

The link
--------
Each report has a read-only link ``/vendors/r/<token>``: 24 random URL-safe characters
(``secrets.token_urlsafe``), stored only as a SHA-256 hash for anonymous reports. It expires
(30 days anonymous, ``MORROW_VENDOR_REPORT_DAYS``; a year for a saved list) and can be revoked:
anonymously with the manage key returned once at creation, signed in by the organisation. A new
link can be issued for a saved list, which ends the old one. The same token serves the report as
JSON and as CSV.

Saved lists
-----------
Signed in, a list can be saved: it is re-checked every ``interval_days`` (default 7) by the
Celery beat entry ``morrow.vendor_recheck`` (hourly, a few lists per tick; without a worker
``python -m services.vendor_check --recheck``), under the same link, so the shared report stays
current. Each finished run adds one line to the report's history (how many vendors were exposed).

Storage and tenants: ``vendor_check_reports`` has ``org_id`` (empty for an anonymous report) and
is in the Postgres RLS plan (services/postgres_rls.py). A read by link and the background runner
cross tenants by design and run in named ``tenant_scope.platform_scope`` blocks.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

READY = ("A", "B")
ORDER = {"F": 0, "E": 1, "D": 2, "C": 3, "B": 4, "A": 5}
NAME_MAX = 80
STALE_RUNNER_SECONDS = 90.0
#: Words the generated sentences and notes never use about a vendor (as on the public lists).
BANNED_WORDS = ("unsafe", "insecure", "fail", "shame", "vulnerable", "dangerous", "bad")

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS vendor_check_reports (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        token_hash TEXT NOT NULL,
        token TEXT NOT NULL DEFAULT '',
        manage_hash TEXT NOT NULL DEFAULT '',
        domains_json TEXT NOT NULL,
        results_json TEXT NOT NULL DEFAULT '{}',
        history_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'queued',
        total INTEGER NOT NULL DEFAULT 0,
        done INTEGER NOT NULL DEFAULT 0,
        saved INTEGER NOT NULL DEFAULT 0,
        interval_days INTEGER NOT NULL DEFAULT 7,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        started_at TEXT NOT NULL DEFAULT '',
        finished_at TEXT NOT NULL DEFAULT '',
        deadline_at TEXT NOT NULL DEFAULT '',
        next_check_at TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL,
        revoked_at TEXT NOT NULL DEFAULT '',
        heartbeat_at TEXT NOT NULL DEFAULT '',
        runner TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        requester_hash TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_check_token ON vendor_check_reports (token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_vendor_check_org ON vendor_check_reports (org_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_vendor_check_due ON vendor_check_reports (saved, next_check_at)",
)

_ready = ""
_ready_lock = threading.Lock()
_jobs_lock = threading.Lock()
_jobs_sem: Dict[str, Any] = {"size": 0, "sem": threading.Semaphore(1)}
_active: set = set()
_RUNNER = uuid.uuid4().hex[:12]


class VendorError(Exception):
    def __init__(self, status_code: int, error: str, detail: str, retry_after: Optional[float] = None):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.error = str(error)
        self.detail = str(detail)
        self.retry_after = retry_after

    def as_dict(self) -> Dict[str, Any]:
        return {"error": self.error, "detail": self.detail}


# ── settings ─────────────────────────────────────────────────────────────────


def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def max_domains(signed_in: bool) -> int:
    if signed_in:
        return int(_num("MORROW_VENDOR_MAX_SIGNED_IN", 500, 1, 5000))
    return int(_num("MORROW_VENDOR_MAX_ANON", 50, 1, 1000))


def jobs() -> int:
    return int(_num("MORROW_VENDOR_JOBS", 2, 1, 16))


def workers() -> int:
    return int(_num("MORROW_VENDOR_WORKERS", 3, 1, 16))


def reuse_seconds() -> int:
    return int(_num("MORROW_VENDOR_REUSE_SECONDS", 24 * 3600, 60, 14 * 24 * 3600))


def job_deadline_seconds() -> float:
    return _num("MORROW_VENDOR_JOB_DEADLINE", 1800, 30, 6 * 3600)


def report_days(saved: bool) -> int:
    if saved:
        return int(_num("MORROW_VENDOR_SAVED_REPORT_DAYS", 365, 1, 3650))
    return int(_num("MORROW_VENDOR_REPORT_DAYS", 30, 1, 365))


def ip_lists_per_hour() -> int:
    return int(_num("MORROW_VENDOR_IP_PER_HOUR", 4, 1, 10_000))


def ip_domains_per_day() -> int:
    return int(_num("MORROW_VENDOR_IP_DOMAINS_PER_DAY", 300, 1, 1_000_000))


def org_lists_per_hour() -> int:
    return int(_num("MORROW_VENDOR_ORG_PER_HOUR", 30, 1, 10_000))


def global_probes_per_hour() -> int:
    return int(_num("MORROW_VENDOR_GLOBAL_PROBES_PER_HOUR", 300, 1, 1_000_000))


# ── time and storage ─────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def init_tables() -> None:
    global _ready
    identity = _identity()
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


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _platform(reason: str):
    from services import tenant_scope

    return tenant_scope.platform_scope("vendor check: " + reason)


# ── parsing the list ─────────────────────────────────────────────────────────

_SPLIT = re.compile(r"[\s,;|\t]+")
_HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_FILE_LIKE = frozenset("php html htm txt xml json js css png jpg jpeg gif svg pdf csv xlsx docx exe zip".split())


def _cells(text: str) -> Iterable[str]:
    """Every cell of a CSV, or every word of plain text. A CSV header row is just more cells."""
    sample = text[:4096]
    if "," in sample or ";" in sample or "\t" in sample:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            for row in csv.reader(io.StringIO(text), dialect):
                for cell in row:
                    yield from (w for w in _SPLIT.split(cell) if w)
            return
        except csv.Error:
            pass
    yield from (w for w in _SPLIT.split(text) if w)


def clean_domain(value: str) -> Tuple[Optional[str], str]:
    """(hostname, "") or (None, why it was skipped). A URL gives its host; nothing is guessed."""
    raw = str(value or "").strip().strip("\"'<>()[]").strip()
    if not raw:
        return None, "empty"
    s = raw.lower()
    if "@" in s and "://" not in s:
        return None, "an e-mail address, not a domain"
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = re.sub(r":\d+$", "", s).rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    try:
        ipaddress.ip_address(s.strip("[]"))
        return None, "an IP address; give the vendor's domain"
    except ValueError:
        pass
    try:
        s = s.encode("idna").decode("ascii") if any(ord(c) > 127 for c in s) else s
    except UnicodeError:
        return None, "not a domain name"
    if not _HOST_RE.match(s) or s.rsplit(".", 1)[-1] in _FILE_LIKE:
        return None, "not a domain name"
    return s, ""


def parse(text: Any, cap: int) -> Dict[str, Any]:
    """The distinct vendor domains in pasted text or an uploaded file, in the order given."""
    body = str(text or "")
    if len(body) > 2_000_000:
        raise VendorError(413, "too_large", "That file is over 2 MB. Paste or upload just the list of domains.")
    domains: List[str] = []
    seen = set()
    skipped: List[Dict[str, str]] = []
    duplicates = 0
    for cell in _cells(body):
        host, why = clean_domain(cell)
        if host is None:
            # Header words ("domain", "vendor", "name") are not worth reporting one by one.
            if why != "empty" and "." in cell and len(skipped) < 50:
                skipped.append({"value": cell[:120], "reason": why})
            continue
        if host in seen:
            duplicates += 1
            continue
        seen.add(host)
        domains.append(host)
    if not domains:
        raise VendorError(400, "no_domains", "No domain names were found. Put one per line, for example payroll.example.com.")
    if len(domains) > cap:
        raise VendorError(400, "too_many", f"That list has {len(domains)} domains; up to {cap} can be checked at once"
                          + (" without an account." if cap == max_domains(False) and cap < max_domains(True) else "."))
    return {"domains": domains, "skipped": skipped, "duplicates": duplicates}


# ── wording ──────────────────────────────────────────────────────────────────


def why_label(result: Dict[str, Any]) -> str:
    """A few words for what decides the vendor's grade, e.g. "RSA key exchange"."""
    grade = str(result.get("grade") or "")
    kx = result.get("key_exchange") or {}
    versions = (result.get("tls") or {}).get("versions") or {}
    group = str(kx.get("group") or "")
    if grade == "F":
        # The rubric's order: no TLS, then a certificate that does not verify, then no forward secrecy.
        if not any(versions.values()):
            return "no TLS"
        if (result.get("certificate") or {}).get("verified") is False:
            return "certificate does not verify"
        return "RSA key exchange"
    if kx.get("post_quantum"):
        weak = [w for w in ("1.0", "1.1") if versions.get(w)]
        if grade == "B":
            return "post-quantum key exchange" + (", TLS " + "/".join(weak) + " still on" if weak else ", one weakness left")
        return "post-quantum key exchange (" + (group or "hybrid") + ")"
    if grade == "E":
        return "TLS 1.0/1.1 or weak ciphers"
    if grade == "D":
        return "TLS 1.2 only, classical key exchange"
    return "classical key exchange" + (" (" + group + ")" if group else "")


def _fact(entry: Dict[str, Any]) -> str:
    """What the check found, as the middle of a sentence about the vendor's domain."""
    why = entry.get("why") or ""
    group = entry.get("key_exchange") or ""
    if why == "RSA key exchange":
        return "accepts RSA key exchange, which has no forward secrecy, so recorded traffic can be read later"
    if why == "certificate does not verify":
        return "presents a certificate that does not verify"
    if why == "no TLS":
        return "did not complete a TLS handshake on port 443"
    if entry.get("grade") == "E":
        return "still accepts TLS 1.0/1.1 or weak ciphers and uses a classical key exchange"
    return ("negotiates " + group + ", a classical key exchange only" if group else "uses a classical key exchange only")


def note(entry: Dict[str, Any], base_url: str) -> str:
    """A short, polite message the buyer can send their vendor. Morrow never sends it."""
    domain = entry["domain"]
    day = str(entry.get("checked_at") or "")[:10]
    link = (base_url.rstrip("/") + "/" + domain) if base_url else "/" + domain
    return (
        f"Subject: Post-quantum key exchange on {domain}\n\n"
        "Hello,\n\n"
        "We are reviewing how the services we rely on protect data in transit against \"harvest now, "
        "decrypt later\": traffic recorded today and decrypted once a large quantum computer exists.\n\n"
        f"A public check on {day} found that {domain} {_fact(entry)}. The details, and the configuration "
        f"change that adds a hybrid post-quantum key exchange (X25519MLKEM768), are here:\n{link}\n\n"
        "Could you tell us whether this is planned, and roughly when? A short reply is enough.\n\n"
        f"If you run {domain}, you can claim it on that page with a DNS record, to be told when the result "
        f"changes and to add a public reply:\n{link}#w-claim\n\n"
        "Thank you."
    )


def _rank_key(e: Dict[str, Any]) -> Tuple[int, int, str]:
    if e.get("grade") in ORDER:
        return (0, ORDER[e["grade"]], e["domain"])
    return (1 if e.get("status") in ("unreachable", "refused", "invalid") else 2, 0, e["domain"])


def summaries(entries: List[Dict[str, Any]], total: int, pending: int) -> Dict[str, str]:
    graded = [e for e in entries if e.get("grade") in ORDER]
    exposed = [e for e in graded if e["grade"] not in READY]
    unchecked = [e for e in entries if e.get("grade") not in ORDER and e.get("status") not in ("pending", "queued")]
    worst = sorted(exposed, key=_rank_key)[0] if exposed else None
    word = "vendor" if total == 1 else "vendors"
    tail = ""
    if pending:
        tail = f" {pending} still being checked."
    elif unchecked:
        tail = f" {len(unchecked)} could not be checked."
    if not graded:
        text = f"Checking your {total} {word}." if pending else f"None of your {total} {word} could be checked."
        return {"plain": text, "standard": text, "expert": text}
    if not exposed:
        lead = (f"All {len(graded)} of your {word} checked so far protect today's traffic against future quantum computers."
                if pending else f"None of your {len(graded)} checked {word} would let today's traffic be read later.")
        return {"plain": lead + tail, "standard": lead + tail,
                "expert": f"{len(graded)}/{total} graded, all A or B (post-quantum key exchange)." + tail}
    n = len(exposed)
    of = f"{n} of your {len(graded) if pending or unchecked else total} {'checked ' if pending or unchecked else ''}{word}"
    plain = f"{of} would let today's traffic be read later. Worst: {worst['domain']} ({worst['why']})."
    counts = {g: sum(1 for e in graded if e["grade"] == g) for g in ORDER}
    dist = " ".join(f"{g}×{counts[g]}" for g in ("A", "B", "C", "D", "E", "F") if counts[g])
    expert = (f"{n}/{len(graded)} graded below B (classical key exchange or worse); {dist}. "
              f"Worst: {worst['domain']}, grade {worst['grade']} ({worst['why']}).")
    return {"plain": plain + tail, "standard": plain + tail, "expert": expert + tail}


# ── the report ───────────────────────────────────────────────────────────────


def _entry_from_result(domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
    kx = result.get("key_exchange") or {}
    ex = result.get("exposure") or {}
    entry = {
        "domain": domain, "status": "graded", "grade": result.get("grade"),
        "key_exchange": kx.get("group") or None, "post_quantum": bool(kx.get("post_quantum")),
        "checked_at": result.get("scanned_at"), "why": why_label(result),
        "readable_from": ex.get("decrypt_year_low") if ex.get("recorded_traffic_at_risk") else None,
        "detail": "",
    }
    entry["exposed"] = entry["grade"] not in READY
    return entry


def _entry_error(domain: str, status: str, detail: str) -> Dict[str, Any]:
    return {"domain": domain, "status": status, "grade": None, "key_exchange": None, "post_quantum": None,
            "checked_at": _iso(_now()), "why": "", "readable_from": None, "detail": detail[:300], "exposed": None}


def _row(r: Any) -> Dict[str, Any]:
    return {k: r[k] for k in r.keys()} if hasattr(r, "keys") else dict(r)


def _load(conn: Any, report_id: str) -> Optional[Dict[str, Any]]:
    r = conn.execute("SELECT * FROM vendor_check_reports WHERE id = ?", (report_id,)).fetchone()
    return _row(r) if r else None


def render(row: Dict[str, Any], base_url: str = "") -> Dict[str, Any]:
    """The public shape of a report: the answer, the vendors worst first, notes, progress."""
    domains = json.loads(row.get("domains_json") or "[]")
    results = json.loads(row.get("results_json") or "{}")
    entries = []
    for d in domains:
        e = results.get(d) or {"domain": d, "status": "pending", "grade": None, "key_exchange": None,
                               "post_quantum": None, "checked_at": None, "why": "", "readable_from": None,
                               "detail": "", "exposed": None}
        e = dict(e)
        e["page"] = "/" + d
        if e.get("grade") in ORDER and e["grade"] not in READY:
            e["note"] = note(e, base_url)
        entries.append(e)
    entries.sort(key=_rank_key)
    pending = sum(1 for e in entries if e["status"] in ("pending", "queued"))
    graded = [e for e in entries if e.get("grade") in ORDER]
    counts = {g: sum(1 for e in graded if e["grade"] == g) for g in ("A", "B", "C", "D", "E", "F")}
    status = row.get("status") or "queued"
    return {
        "id": row.get("id"), "name": row.get("name") or "", "status": status,
        "total": len(domains), "done": len(domains) - pending, "pending": pending,
        "graded": len(graded), "exposed": sum(1 for e in graded if e["grade"] not in READY), "grades": counts,
        "summaries": summaries(entries, len(domains), pending if status in ("queued", "running") else 0),
        "vendors": entries,
        "created_at": row.get("created_at"), "updated_at": row.get("updated_at"),
        "started_at": row.get("started_at") or None, "finished_at": row.get("finished_at") or None,
        "expires_at": row.get("expires_at"), "saved": bool(row.get("saved")),
        "interval_days": int(row.get("interval_days") or 7) if row.get("saved") else None,
        "next_check_at": (row.get("next_check_at") or None) if row.get("saved") else None,
        "history": json.loads(row.get("history_json") or "[]"),
        "basis": "Each vendor gets the public grade (rubric " + _rubric() + "): one set of TLS handshakes to port 443 "
                 "of the domain given, read-only. A stored grade under a day old is reused. \"Read later\" means "
                 "the key exchange is classical, so recorded traffic is exposed once a large quantum computer exists.",
        "sends_nothing": "Morrow sends nothing to your vendors. The notes are for you to send, if you choose.",
    }


def _rubric() -> str:
    from services import public_grade

    return public_grade.RUBRIC_VERSION


def to_csv(report: Dict[str, Any]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(["domain", "grade", "post_quantum", "key_exchange", "why", "readable_from", "checked_at", "status",
                "detail", "page"])
    for e in report["vendors"]:
        row = [e["domain"], e.get("grade") or "", "" if e.get("post_quantum") is None else ("yes" if e["post_quantum"] else "no"),
               e.get("key_exchange") or "", e.get("why") or "", e.get("readable_from") or "", e.get("checked_at") or "",
               e.get("status") or "", e.get("detail") or "", e["page"]]
        # A cell that starts with =, +, - or @ is a formula to a spreadsheet: quote it out.
        w.writerow([("'" + str(c)) if str(c)[:1] in ("=", "+", "-", "@") else c for c in row])
    return out.getvalue()


# ── creating, reading, revoking ──────────────────────────────────────────────


def _charge_anonymous(ip_hash: str, count: int) -> None:
    from services import org_rate_limits

    hit = org_rate_limits.hit("vendor_check_ip", ip_hash, ip_lists_per_hour(), 3600.0)
    if not hit.get("allowed"):
        raise VendorError(429, "rate_limited", f"More than {ip_lists_per_hour()} vendor lists an hour from your address. "
                          "Sign in to check more.", retry_after=float(hit.get("retry_after") or 3600))
    for _ in range(max(0, count)):
        hit = org_rate_limits.hit("vendor_check_ip_domains", ip_hash, ip_domains_per_day(), 86400.0)
        if not hit.get("allowed"):
            raise VendorError(429, "rate_limited", f"More than {ip_domains_per_day()} vendor domains a day from your "
                              "address. Sign in to check more.", retry_after=float(hit.get("retry_after") or 86400))


def create(text: Any, *, client_ip: str = "", org_id: str = "", name: str = "", saved: bool = False,
           interval_days: int = 7, actor: str = "", start: bool = True) -> Dict[str, Any]:
    """Parse the list, store a queued report and start grading it. Returns the link (once)."""
    from services import org_rate_limits, public_check, public_grade

    if not public_grade.enabled():
        raise VendorError(503, "disabled", "The public grade is switched off on this server.")
    signed_in = bool(org_id)
    parsed = parse(text, max_domains(signed_in))
    ip_hash = public_check.hash_ip(client_ip)
    if signed_in:
        hit = org_rate_limits.hit("vendor_check_org", org_id, org_lists_per_hour(), 3600.0)
        if not hit.get("allowed"):
            raise VendorError(429, "rate_limited", f"More than {org_lists_per_hour()} vendor lists an hour for your "
                              "organisation.", retry_after=float(hit.get("retry_after") or 3600))
    else:
        _charge_anonymous(ip_hash, len(parsed["domains"]))
        saved = False
    init_tables()
    token = secrets.token_urlsafe(18)
    manage = "" if signed_in else secrets.token_urlsafe(18)
    now = _now()
    rid = uuid.uuid4().hex
    interval = max(1, min(90, int(interval_days or 7)))
    row = {
        "id": rid, "org_id": org_id or "", "name": re.sub(r"\s+", " ", str(name or "")).strip()[:NAME_MAX],
        "token_hash": hash_token(token), "token": token if signed_in else "",
        "manage_hash": hash_token(manage) if manage else "", "domains_json": json.dumps(parsed["domains"]),
        "results_json": "{}", "history_json": "[]", "status": "queued", "total": len(parsed["domains"]), "done": 0,
        "saved": 1 if saved else 0, "interval_days": interval, "created_at": _iso(now), "updated_at": _iso(now),
        "deadline_at": _iso(now + timedelta(seconds=job_deadline_seconds())),
        "next_check_at": _iso(now + timedelta(days=interval)) if saved else "",
        "expires_at": _iso(now + timedelta(days=report_days(saved))), "created_by": str(actor or "")[:200],
        "requester_hash": ip_hash,
    }
    cols = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    with feature_conn() as conn:
        conn.execute(f"INSERT INTO vendor_check_reports ({cols}) VALUES ({marks})", tuple(row.values()))  # nosec B608  # fixed column names
        conn.commit()
    public_check.log_check(f"{len(parsed['domains'])} domains", ip_hash, "vendor_check_created", rid[:12])
    if start:
        kick(rid)
    return {"id": rid, "token": token, "manage_key": manage or None, "report_url": "/vendors/r/" + token,
            "expires_at": row["expires_at"], "total": row["total"], "skipped": parsed["skipped"],
            "duplicates": parsed["duplicates"], "saved": bool(saved)}


def _by_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or len(token) > 64 or not re.match(r"^[A-Za-z0-9_-]+$", token):
        return None
    init_tables()
    with _platform("a shared report read by its link"):
        with feature_conn() as conn:
            r = conn.execute("SELECT * FROM vendor_check_reports WHERE token_hash = ?", (hash_token(token),)).fetchone()
    return _row(r) if r else None


def _usable(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not row:
        raise VendorError(404, "not_found", "There is no report at this link.")
    if row.get("revoked_at"):
        raise VendorError(410, "revoked", "This report's link was revoked by the person who made it.")
    if str(row.get("expires_at") or "") <= _iso(_now()):
        raise VendorError(410, "expired", "This report's link has expired. Run the check again for a new one.")
    return row


def read(token: str, base_url: str = "") -> Dict[str, Any]:
    row = _usable(_by_token(token))
    if row.get("status") in ("queued", "running"):
        kick(row["id"])
    return render(row, base_url)


def revoke_anonymous(token: str, manage_key: str) -> Dict[str, Any]:
    row = _by_token(token)
    if not row or not manage_key or not row.get("manage_hash") or not secrets.compare_digest(
            row["manage_hash"], hash_token(manage_key)):
        raise VendorError(404, "not_found", "There is no report at this link that this key can revoke.")
    with _platform("revoking an anonymous report by its manage key"):
        with feature_conn() as conn:
            conn.execute("UPDATE vendor_check_reports SET revoked_at = ?, updated_at = ? WHERE id = ?",
                         (_iso(_now()), _iso(_now()), row["id"]))
            conn.commit()
    return {"revoked": True}


# signed in: the organisation's own reports


def for_org(org_id: str) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT * FROM vendor_check_reports WHERE org_id = ? ORDER BY saved DESC, created_at DESC",
                            (org_id,)).fetchall()
    out = []
    for r in rows[:200]:
        row = _row(r)
        rep = render(row)
        out.append({"id": row["id"], "name": row["name"], "saved": bool(row["saved"]), "status": row["status"],
                    "total": rep["total"], "done": rep["done"], "graded": rep["graded"], "exposed": rep["exposed"],
                    "summary": rep["summaries"]["standard"], "created_at": row["created_at"],
                    "finished_at": row["finished_at"] or None, "next_check_at": rep["next_check_at"],
                    "interval_days": rep["interval_days"], "expires_at": row["expires_at"],
                    "revoked": bool(row["revoked_at"]),
                    "report_url": None if row["revoked_at"] else "/vendors/r/" + row["token"]})
    return out


def _org_row(org_id: str, report_id: str) -> Dict[str, Any]:
    init_tables()
    with feature_conn() as conn:
        r = conn.execute("SELECT * FROM vendor_check_reports WHERE id = ? AND org_id = ?", (report_id, org_id)).fetchone()
    if not r:
        raise VendorError(404, "not_found", "No such vendor list in your organisation.")
    return _row(r)


def org_update(org_id: str, report_id: str, *, revoke: Optional[bool] = None, new_link: bool = False,
               saved: Optional[bool] = None, interval_days: Optional[int] = None,
               recheck: bool = False) -> Dict[str, Any]:
    row = _org_row(org_id, report_id)
    sets: Dict[str, Any] = {"updated_at": _iso(_now())}
    token = row["token"]
    if new_link:
        token = secrets.token_urlsafe(18)
        sets.update(token=token, token_hash=hash_token(token), revoked_at="",
                    expires_at=_iso(_now() + timedelta(days=report_days(bool(row["saved"] if saved is None else saved)))))
    elif revoke is not None:
        sets["revoked_at"] = _iso(_now()) if revoke else ""
    if interval_days is not None:
        sets["interval_days"] = max(1, min(90, int(interval_days)))
    if saved is not None:
        sets["saved"] = 1 if saved else 0
        if saved:
            days = int(sets.get("interval_days") or row["interval_days"] or 7)
            sets["next_check_at"] = _iso(_now() + timedelta(days=days))
            sets["expires_at"] = max(str(row["expires_at"]), _iso(_now() + timedelta(days=report_days(True))))
        else:
            sets["next_check_at"] = ""
    if recheck and row["status"] not in ("queued", "running"):
        sets.update(_restart_fields())
    cols = ", ".join(f"{k} = ?" for k in sets)
    with feature_conn() as conn:
        conn.execute(f"UPDATE vendor_check_reports SET {cols} WHERE id = ? AND org_id = ?",  # nosec B608  # fixed column names
                     (*sets.values(), report_id, org_id))
        conn.commit()
    if recheck:
        kick(report_id)
    out = _org_row(org_id, report_id)
    return {"id": report_id, "report_url": None if out["revoked_at"] else "/vendors/r/" + token,
            "revoked": bool(out["revoked_at"]), "saved": bool(out["saved"]), "interval_days": out["interval_days"],
            "status": out["status"], "expires_at": out["expires_at"]}


def org_delete(org_id: str, report_id: str) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM vendor_check_reports WHERE id = ? AND org_id = ?", (report_id, org_id))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def org_report(org_id: str, report_id: str, base_url: str = "") -> Dict[str, Any]:
    row = _org_row(org_id, report_id)
    if row.get("status") in ("queued", "running"):
        kick(report_id)
    out = render(row, base_url)
    out["report_url"] = None if row["revoked_at"] else "/vendors/r/" + row["token"]
    return out


# ── the job ──────────────────────────────────────────────────────────────────


def _restart_fields() -> Dict[str, Any]:
    now = _now()
    return {"status": "queued", "done": 0, "started_at": "", "finished_at": "", "runner": "", "heartbeat_at": "",
            "deadline_at": _iso(now + timedelta(seconds=job_deadline_seconds()))}


def _jobs_semaphore() -> threading.Semaphore:
    want = jobs()
    with _jobs_lock:
        if _jobs_sem["size"] != want:
            _jobs_sem["sem"] = threading.Semaphore(want)
            _jobs_sem["size"] = want
        return _jobs_sem["sem"]


def _claim(report_id: str) -> bool:
    """Take the report for this process, unless a live runner already has it."""
    stale = _iso(_now() - timedelta(seconds=STALE_RUNNER_SECONDS))
    with _platform("the background runner claims a report"):
        with feature_conn() as conn:
            cur = conn.execute(
                "UPDATE vendor_check_reports SET runner = ?, heartbeat_at = ? WHERE id = ? "
                "AND status IN ('queued', 'running') AND (runner = '' OR runner = ? OR heartbeat_at < ?)",
                (_RUNNER, _iso(_now()), report_id, _RUNNER, stale))
            conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def kick(report_id: str) -> bool:
    """Start (or resume) grading a report in a background thread. False when it is already running."""
    with _jobs_lock:
        if report_id in _active:
            return False
        _active.add(report_id)
    if not _claim(report_id):
        with _jobs_lock:
            _active.discard(report_id)
        return False
    thread = threading.Thread(target=_run_guarded, args=(report_id,), name="vendor-check-" + report_id[:8], daemon=True)
    thread.start()
    return True


def _run_guarded(report_id: str) -> None:
    try:
        run(report_id)
    except Exception:
        logger.exception("vendor check: the run of %s stopped", report_id[:12])
    finally:
        with _jobs_lock:
            _active.discard(report_id)


def grade_vendor(domain: str, client_ip: str = "", stop_at: float = 0.0, sleep=time.sleep) -> Dict[str, Any]:
    """One vendor: a recent stored grade, else the guarded public check. Waits out rate limits."""
    from services import org_rate_limits, public_grade

    try:
        host = public_grade.normalize(domain)
    except public_grade.GradeError as exc:
        return _entry_error(domain, "invalid", exc.detail)
    recent = public_grade.latest(host, reuse_seconds())
    if recent is not None:
        return _entry_from_result(host, recent)
    while True:
        try:
            cached = public_grade.latest(host, public_grade.cache_seconds())
            if cached is None:
                hit = org_rate_limits.hit("vendor_check_global", "all", global_probes_per_hour(), 3600.0)
                if not hit.get("allowed"):
                    raise public_grade.GradeError(429, "rate_limited", "The vendor check is at its hourly limit.",
                                                  retry_after=float(hit.get("retry_after") or 60))
            result = cached or public_grade.check(host, client_ip, charge=False)
            return _entry_from_result(host, result)
        except public_grade.GradeError as exc:
            if exc.status_code == 429:
                wait = max(1.0, min(30.0, float(exc.retry_after or 10)))
                if stop_at and time.monotonic() + wait > stop_at:
                    return _entry_error(host, "not_checked", "Not checked yet: the check's hourly budget was spent. "
                                        "It is picked up by the next re-check.")
                sleep(wait)
                continue
            status = {"refused_optout": "refused", "refused_target": "refused", "invalid_domain": "invalid",
                      "unresolvable": "unreachable", "unreachable": "unreachable", "disabled": "not_checked"}
            return _entry_error(host, status.get(exc.error, "unreachable"), exc.detail)
        except Exception as exc:  # one vendor must never stop the list
            return _entry_error(host, "unreachable", type(exc).__name__)


def run(report_id: str, sleep=time.sleep) -> Optional[Dict[str, Any]]:
    """Grade every vendor of a claimed report, writing progress after each one."""
    init_tables()
    sem = _jobs_semaphore()
    while not sem.acquire(timeout=20.0):
        _heartbeat(report_id)
    try:
        with _platform("the background runner reads a report"):
            with feature_conn() as conn:
                row = _load(conn, report_id)
        if not row or row["status"] not in ("queued", "running"):
            return row
        domains = json.loads(row["domains_json"] or "[]")
        results = json.loads(row["results_json"] or "{}")
        started = row["started_at"] or _iso(_now())
        # A fresh run re-grades everything; a resumed one keeps what it already has.
        todo = [d for d in domains if row["status"] == "queued" or results.get(d, {}).get("status") in (None, "pending", "not_checked")]
        if row["status"] == "queued":
            results = {d: v for d, v in results.items() if d in domains}
        _write(report_id, status="running", started_at=started, results_json=json.dumps(results))
        try:
            deadline = datetime.strptime(row["deadline_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            stop_at = time.monotonic() + max(5.0, (deadline - _now()).total_seconds())
        except ValueError:
            stop_at = time.monotonic() + job_deadline_seconds()
        lock = threading.Lock()
        fresh: Dict[str, Dict[str, Any]] = {}

        def one(domain: str) -> None:
            entry = grade_vendor(domain, "", stop_at, sleep)
            with lock:
                fresh[domain] = entry
                merged = dict(results)
                merged.update(fresh)
                _write(report_id, results_json=json.dumps(merged), done=len([d for d in domains if d in merged]))

        with ThreadPoolExecutor(max_workers=workers()) as pool:
            for _ in pool.map(one, todo):
                pass
        results.update(fresh)
        graded = [v for v in results.values() if v.get("grade") in ORDER]
        history = json.loads(row["history_json"] or "[]")
        history.append({"at": _iso(_now()), "total": len(domains), "graded": len(graded),
                        "exposed": sum(1 for v in graded if v["grade"] not in READY)})
        fields: Dict[str, Any] = {"status": "done", "finished_at": _iso(_now()), "runner": "",
                                  "history_json": json.dumps(history[-60:]), "results_json": json.dumps(results),
                                  "done": len(domains)}
        if row["saved"]:
            fields["next_check_at"] = _iso(_now() + timedelta(days=int(row["interval_days"] or 7)))
        _write(report_id, **fields)
        return fields
    finally:
        sem.release()


def _write(report_id: str, **fields: Any) -> None:
    fields["updated_at"] = _iso(_now())
    fields["heartbeat_at"] = fields["updated_at"]
    cols = ", ".join(f"{k} = ?" for k in fields)
    with _platform("the background runner records progress"):
        with feature_conn() as conn:
            conn.execute(f"UPDATE vendor_check_reports SET {cols} WHERE id = ?", (*fields.values(), report_id))  # nosec B608  # fixed column names
            conn.commit()


def _heartbeat(report_id: str) -> None:
    try:
        _write(report_id)
    except Exception:
        logger.warning("vendor check: could not record a heartbeat for %s", report_id[:12])


# ── saved lists: the re-check ────────────────────────────────────────────────


def recheck_due(max_lists: int = 5) -> Dict[str, Any]:
    """Queue and start the saved lists whose re-check is due. Called hourly by Celery beat."""
    init_tables()
    now = _iso(_now())
    with _platform("saved vendor lists: which are due for their re-check"):
        with feature_conn() as conn:
            rows = conn.execute(
                "SELECT id FROM vendor_check_reports WHERE saved = 1 AND revoked_at = '' AND next_check_at != '' "
                "AND next_check_at <= ? AND status NOT IN ('queued', 'running') ORDER BY next_check_at LIMIT ?",
                (now, max(1, min(50, int(max_lists))))).fetchall()
            ids = [str(r["id"]) for r in rows]
            for rid in ids:
                fields = _restart_fields()
                cols = ", ".join(f"{k} = ?" for k in fields)
                conn.execute(f"UPDATE vendor_check_reports SET {cols} WHERE id = ?", (*fields.values(), rid))  # nosec B608  # fixed column names
            conn.commit()
    started = [rid for rid in ids if kick(rid)]
    return {"due": len(ids), "started": len(started)}


def recheck_due_and_wait(max_lists: int = 5, timeout: Optional[float] = None) -> Dict[str, Any]:
    """recheck_due, then wait (at most the job deadline) for the runs this process started."""
    out = recheck_due(max_lists)
    end = time.monotonic() + (timeout if timeout is not None else job_deadline_seconds() + 60)
    while time.monotonic() < end:
        with _jobs_lock:
            if not _active:
                break
        time.sleep(2)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m services.vendor_check",
                                     description="Re-check saved vendor lists that are due.")
    parser.add_argument("--recheck", action="store_true", help="start the due saved lists and wait for them")
    parser.add_argument("--max", type=int, default=5)
    args = parser.parse_args(argv)
    if not args.recheck:
        parser.error("give --recheck")
    print(json.dumps(recheck_due_and_wait(args.max), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
