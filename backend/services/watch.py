"""Watch mode and domain claims: Morrow keeps checking a domain and says when its answer changes.

Watching
--------
A signed-in person watches a public domain from its page (/<domain>). The watch tick
(``tick``; Celery beat every 15 minutes, ``MORROW_WATCH_SCAN``, default on) re-checks every watched
domain whose last check is older than ``MORROW_WATCH_INTERVAL_HOURS`` (default 24, 1 to 168), at most
``MORROW_WATCH_TICK_MAX`` domains a tick (default 10, 1 to 50), with the same guarded probes as the
public grade: services/public_grade.grade_one (SSRF guard with a pinned address, opt-outs, timeouts)
and services/third_party.run for the outside services. A domain watched by many people is checked
once. Opted-out domains are never contacted. A person watches at most ``MORROW_WATCH_MAX_PER_USER``
domains (default 25).

What counts as a change (``diff``): the handshake becoming post-quantum or stopping being it, the
grade moving, a certificate change that moved the grade or stopped verifying, and an outside service
the domain depends on switching its key exchange, or a new outside service with a classical one. A
check that fails changes nothing: the previous answer stands until a check succeeds.

Every change is one sentence that leads with the answer ("statements.example.com became post-quantum
ready on Tue 14 Nov — the handshake now uses X25519MLKEM768.") and goes to every watcher of that
domain through channels that are not email:
  * the in-app list (``watch_events``; /watching and the domain page);
  * browser push (services/web_push.py; off, with a plain sentence, when VAPID keys are not set);
  * the person's Slack or generic webhooks, through the platform's SSRF-guarded sender
    (services/alert_routing.validate_webhook_url / post_json; targets sealed with the vault key);
  * a private Atom feed at /api/public/watch-feed/<token>.atom. The token is 32 random bytes; only
    its SHA-256 is stored, so the address is shown once, and making a new one ends the old one.

Claims
------
The owner of a domain claims it with the platform's existing DNS proof (services/domain_verification:
``_morrow-verify.<domain> TXT morrow-verify=<token>``; no email anywhere). A claim needs that record
for the exact domain, live. One organization holds a claim at a time: when another organization
claimed it first and its record is still published, the claim is refused; when that record is gone
(the domain changed hands), the claim moves. A claim turns watching on for the person who made it,
lets the organization reply publicly (services/not_ready.set_reply), opt the domain out, and shows the
page's "Talk to SOQLAB about migrating" action. Public pages show only whether a domain is claimed
and since when, never by whom.

Tables: ``watch_domains``, ``watch_events``, ``watch_push_subscriptions``, ``watch_channels``,
``watch_feed_tokens`` and ``domain_claims`` are org-scoped (``org_id``) and in the Postgres RLS plan.
``watch_domain_state`` (the last answer per domain) belongs to no tenant. The tick, the feed and the
public claim line cross tenants and run in named ``tenant_scope.platform_scope`` blocks.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

logger = logging.getLogger(__name__)

CHANNEL_KINDS = ("slack_webhook", "generic_webhook")
MAX_CHANNELS_PER_USER = 5
MAX_PUSH_PER_USER = 10
EVENT_KEEP = 500
WORKERS = 2
#: The TLS statuses of an outside service that are an answer (not "could not tell").
_ANSWERED = ("pq", "classical", "no_tls")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS watch_domains (
        org_id TEXT NOT NULL, user_id TEXT NOT NULL, domain TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'manual', created_at TEXT NOT NULL,
        PRIMARY KEY (org_id, user_id, domain))""",
    """CREATE TABLE IF NOT EXISTS watch_events (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, domain TEXT NOT NULL,
        kind TEXT NOT NULL, sentence TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}',
        at TEXT NOT NULL, created_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_watch_events_owner ON watch_events (org_id, user_id, created_at)",
    """CREATE TABLE IF NOT EXISTS watch_push_subscriptions (
        org_id TEXT NOT NULL, user_id TEXT NOT NULL, endpoint TEXT NOT NULL,
        p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at TEXT NOT NULL,
        last_status TEXT NOT NULL DEFAULT '', PRIMARY KEY (org_id, endpoint))""",
    """CREATE TABLE IF NOT EXISTS watch_channels (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL,
        target_sealed TEXT NOT NULL, target_hint TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
        last_status TEXT NOT NULL DEFAULT '', last_sent_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS watch_feed_tokens (
        org_id TEXT NOT NULL, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL, PRIMARY KEY (org_id, user_id))""",
    """CREATE TABLE IF NOT EXISTS domain_claims (
        org_id TEXT NOT NULL, domain TEXT NOT NULL, claimed_at TEXT NOT NULL,
        claimed_by TEXT NOT NULL DEFAULT '', PRIMARY KEY (org_id, domain))""",
    """CREATE TABLE IF NOT EXISTS watch_domain_state (
        domain TEXT PRIMARY KEY, checked_at TEXT NOT NULL, state_json TEXT NOT NULL DEFAULT '{}',
        last_error TEXT NOT NULL DEFAULT '', last_success_at TEXT)""",
)
ORG_TABLES = ("watch_domains", "watch_events", "watch_push_subscriptions", "watch_channels",
              "watch_feed_tokens", "domain_claims")

_ready = ""
_ready_lock = threading.Lock()
_TICK_LOCK = threading.Lock()


class WatchError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


# ── settings ────────────────────────────────────────────────────────────────

def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or "").strip() or default)
    except ValueError:
        value = default
    return max(low, min(high, value))


def enabled() -> bool:
    return str(os.getenv("MORROW_WATCH_SCAN", "1") or "1").strip().lower() not in ("0", "false", "no", "off")


def interval_hours() -> float:
    return _num("MORROW_WATCH_INTERVAL_HOURS", 24, 1, 168)


def tick_max() -> int:
    return int(_num("MORROW_WATCH_TICK_MAX", 10, 1, 50))


def max_per_user() -> int:
    return int(_num("MORROW_WATCH_MAX_PER_USER", 25, 1, 200))


def third_party_enabled() -> bool:
    return str(os.getenv("MORROW_WATCH_THIRD_PARTY", "1") or "1").strip().lower() not in ("0", "false", "no", "off")


def contact_address() -> str:
    value = str(os.getenv("MORROW_SALES_CONTACT", "") or "").strip()
    return value if value and "@" in value and " " not in value else "contact@soqlab.com"


def settings() -> Dict[str, Any]:
    return {"interval_hours": interval_hours(), "tick_max": tick_max(), "max_per_user": max_per_user(),
            "scheduled": enabled(), "third_party": third_party_enabled()}


# ── storage ─────────────────────────────────────────────────────────────────

def _identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


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


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text: Any) -> Optional[datetime]:
    try:
        return datetime.strptime(str(text)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def say_day(text: Any) -> str:
    """'Tue 14 Nov' from an ISO timestamp (no %-d: it is not portable)."""
    dt = _parse(text) or now_utc()
    return f"{dt:%a} {dt.day} {dt:%b}"


def _scope(reason: str):
    from services import tenant_scope

    return tenant_scope.platform_scope(reason)


def normalize(domain: Any) -> str:
    from services import public_grade

    try:
        return public_grade.normalize(domain)
    except public_grade.GradeError as exc:
        raise WatchError(400, exc.detail, "bad_domain") from None


# ── snapshots and change detection ──────────────────────────────────────────

def snapshot(result: Dict[str, Any], exposure: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The parts of a check that a change is measured on."""
    kx = result.get("key_exchange") or {}
    cert = result.get("certificate") or {}
    snap: Dict[str, Any] = {
        "grade": result.get("grade"), "pq": bool(kx.get("post_quantum")), "group": kx.get("group") or "",
        "scanned_at": result.get("scanned_at"),
        "cert": {k: cert.get(k) for k in ("key_type", "key_bits", "signature_algorithm", "not_after", "issuer", "verified")},
        "reason": (result.get("reasons") or [""])[0],
        "services": None,
    }
    if exposure and isinstance(exposure.get("services"), list):
        snap["services"] = {
            str(s.get("host")): {"status": s.get("status"), "group": s.get("key_exchange") or "",
                                 "vendor": s.get("vendor") or "", "role": s.get("role") or "other"}
            for s in exposure["services"] if s.get("host")}
    return snap


def _cn(issuer: Any) -> str:
    text = str(issuer or "")
    for part in text.replace("/", ",").split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return text[:60]


def _role(role: str) -> str:
    from services import third_party

    return third_party.ROLE_LABEL.get(role or "other", "an outside service")


def diff(domain: str, before: Optional[Dict[str, Any]], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Changes from one snapshot to the next, each with its answer-first sentence. Pure."""
    if not before or not after or not after.get("grade"):
        return []
    at = after.get("scanned_at") or iso(now_utc())
    day = say_day(at)
    out: List[Dict[str, Any]] = []
    g0, g1 = before.get("grade"), after.get("grade")
    group = after.get("group") or ""
    grade_note = f" Grade {g0} to {g1}." if g0 and g0 != g1 else ""
    if after.get("pq") and not before.get("pq"):
        out.append({"kind": "pq_ready", "sentence": f"{domain} became post-quantum ready on {day} — the handshake now "
                                                    f"uses {group or 'a post-quantum key exchange'}.{grade_note}"})
    elif before.get("pq") and not after.get("pq"):
        out.append({"kind": "pq_lost", "sentence": f"{domain} stopped using a post-quantum key exchange on {day} — the "
                                                   f"handshake now uses {group or 'a key exchange Morrow could not read'}."
                                                   f"{grade_note}"})
    elif g0 and g1 and g0 != g1:
        better = "ABCDEF".find(str(g1)) < "ABCDEF".find(str(g0))
        why = f" {after['reason']}" if after.get("reason") else ""
        out.append({"kind": "grade_up" if better else "grade_down",
                    "sentence": f"{domain} went from grade {g0} to {g1} on {day}.{why}"})
    c0, c1 = before.get("cert") or {}, after.get("cert") or {}
    ident = ("key_type", "key_bits", "signature_algorithm", "not_after", "issuer")
    cert_moved = any(c0.get(k) != c1.get(k) for k in ident)
    if c0.get("verified") is not False and c1.get("verified") is False:
        out.append({"kind": "cert_unverified", "sentence": f"{domain}'s certificate stopped verifying on {day}."})
    elif cert_moved and g0 != g1 and c1:
        out.append({"kind": "cert_changed",
                    "sentence": f"{domain}'s certificate changed on {day} ({c1.get('key_type') or '?'} "
                                f"{c1.get('key_bits') or ''}, from {_cn(c1.get('issuer')) or 'an unnamed issuer'}, expires "
                                f"{str(c1.get('not_after') or '?')[:10]}), and the grade moved from {g0} to {g1}."
                                .replace(" , ", ", ")})
    s0, s1 = before.get("services"), after.get("services")
    if isinstance(s0, dict) and isinstance(s1, dict):
        for host in sorted(s1):
            new = s1[host]
            old = s0.get(host)
            name = new.get("vendor") or host
            via = f" ({host})" if new.get("vendor") else ""
            if old and old.get("status") in _ANSWERED and new.get("status") in _ANSWERED:
                if new["status"] == "pq" and old["status"] != "pq":
                    out.append({"kind": "service_pq_ready", "host": host,
                                "sentence": f"{name}{via}, {_role(new.get('role'))} on {domain}, became post-quantum ready "
                                            f"on {day} — it now uses {new.get('group') or 'a post-quantum key exchange'}."})
                elif old["status"] == "pq" and new["status"] != "pq":
                    out.append({"kind": "service_pq_lost", "host": host,
                                "sentence": f"{name}{via}, {_role(new.get('role'))} on {domain}, stopped using a "
                                            f"post-quantum key exchange on {day}."})
            elif not old and new.get("status") in ("classical", "no_tls"):
                how = f"a classical key exchange ({new['group']})" if new.get("group") else "no post-quantum key exchange"
                out.append({"kind": "service_added", "host": host,
                            "sentence": f"{domain} started depending on {name}{via}, {_role(new.get('role'))}, on {day}; "
                                        f"it uses {how}."})
    for e in out:
        e["at"] = at
        e["domain"] = domain
    return out


def _state(conn: Any, domain: str) -> Optional[Dict[str, Any]]:
    row = conn.execute("SELECT checked_at, state_json, last_error, last_success_at FROM watch_domain_state WHERE domain = ?",
                       (domain,)).fetchone()
    if not row:
        return None
    try:
        snap = json.loads(row["state_json"] or "{}")
    except ValueError:
        snap = {}
    return {"checked_at": row["checked_at"], "snapshot": snap, "last_error": row["last_error"] or "",
            "last_success_at": row["last_success_at"]}


def _save_state(conn: Any, domain: str, checked_at: str, snap: Optional[Dict[str, Any]], error: str = "") -> None:
    existing = conn.execute("SELECT state_json FROM watch_domain_state WHERE domain = ?", (domain,)).fetchone()
    if existing is None:
        try:
            with atomic(conn):
                conn.execute("INSERT INTO watch_domain_state (domain, checked_at, state_json, last_error, last_success_at) "
                             "VALUES (?, ?, ?, ?, ?)", (domain, checked_at, json.dumps(snap or {}, sort_keys=True),
                                                        error[:300], None if snap is None else checked_at))
            return
        except INTEGRITY_ERRORS:
            pass
    if snap is None:
        conn.execute("UPDATE watch_domain_state SET checked_at = ?, last_error = ? WHERE domain = ?",
                     (checked_at, error[:300], domain))
    else:
        conn.execute("UPDATE watch_domain_state SET checked_at = ?, state_json = ?, last_error = '', last_success_at = ? "
                     "WHERE domain = ?", (checked_at, json.dumps(snap, sort_keys=True), checked_at, domain))


def domain_state(domain: str) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        return _state(conn, domain)


# ── watches ─────────────────────────────────────────────────────────────────

def _baseline(conn: Any, domain: str) -> None:
    """Start the domain's state from its newest stored public grade, so the first scheduled check
    already has something to compare with. Never contacts the domain."""
    if _state(conn, domain) is not None:
        return
    from services import public_grade

    latest = public_grade.latest(domain)
    if latest and latest.get("grade") in public_grade.GRADES:
        # checked_at is the grade's own date: a week-old answer is due for a fresh check.
        _save_state(conn, domain, str(latest.get("scanned_at") or iso(now_utc())), snapshot(latest))


def watch(org_id: str, user_id: str, domain: Any, source: str = "manual") -> Dict[str, Any]:
    name = normalize(domain)
    if not user_id:
        raise WatchError(401, "Sign in to watch a domain.", "signed_out")
    init_tables()
    with feature_conn() as conn:
        mine = conn.execute("SELECT domain, source FROM watch_domains WHERE org_id = ? AND user_id = ?",
                            (org_id, user_id)).fetchall()
        current = {r["domain"]: r["source"] for r in mine}
        if name not in current:
            if len(current) >= max_per_user():
                raise WatchError(400, f"You can watch up to {max_per_user()} domains. Stop watching one first.", "too_many")
            try:
                with atomic(conn):
                    conn.execute("INSERT INTO watch_domains (org_id, user_id, domain, source, created_at) VALUES (?, ?, ?, ?, ?)",
                                 (org_id, user_id, name, source, iso(now_utc())))
            except INTEGRITY_ERRORS:
                pass
        elif source == "claim" and current[name] != "claim":
            conn.execute("UPDATE watch_domains SET source = 'claim' WHERE org_id = ? AND user_id = ? AND domain = ?",
                         (org_id, user_id, name))
        conn.commit()
    with _scope("watch: start a watched domain's shared state from its stored public grade"), feature_conn() as conn:
        _baseline(conn, name)
        conn.commit()
    return watching(org_id, user_id, name)


def unwatch(org_id: str, user_id: str, domain: Any) -> bool:
    name = normalize(domain)
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM watch_domains WHERE org_id = ? AND user_id = ? AND domain = ?", (org_id, user_id, name))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def _public_state(st: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not st:
        return None
    snap = st.get("snapshot") or {}
    return {"checked_at": st.get("checked_at"), "last_success_at": st.get("last_success_at"),
            "last_error": st.get("last_error") or "", "grade": snap.get("grade"), "post_quantum": bool(snap.get("pq")),
            "key_exchange": snap.get("group") or None, "services_tracked": snap.get("services") is not None}


def next_check(st: Optional[Dict[str, Any]]) -> Optional[str]:
    checked = _parse((st or {}).get("checked_at"))
    return iso(checked + timedelta(hours=interval_hours())) if checked else None


def watching(org_id: str, user_id: str, domain: Any) -> Dict[str, Any]:
    name = normalize(domain)
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT source, created_at FROM watch_domains WHERE org_id = ? AND user_id = ? AND domain = ?",
                           (org_id, user_id, name)).fetchone()
        events = conn.execute("SELECT id, domain, kind, sentence, at FROM watch_events WHERE org_id = ? AND user_id = ? "
                              "AND domain = ? ORDER BY created_at DESC, at DESC LIMIT 20", (org_id, user_id, name)).fetchall()
    st = domain_state(name)
    return {"domain": name, "watching": bool(row), "source": row["source"] if row else None,
            "since": row["created_at"] if row else None, "state": _public_state(st),
            "next_check": next_check(st) if row else None, "interval_hours": interval_hours(),
            "events": [dict(e) for e in events]}


def overview(org_id: str, user_id: str) -> Dict[str, Any]:
    from services import web_push

    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT domain, source, created_at FROM watch_domains WHERE org_id = ? AND user_id = ? "
                            "ORDER BY domain", (org_id, user_id)).fetchall()
        events = conn.execute("SELECT id, domain, kind, sentence, at FROM watch_events WHERE org_id = ? AND user_id = ? "
                              "ORDER BY created_at DESC, at DESC LIMIT 100", (org_id, user_id)).fetchall()
        push = conn.execute("SELECT COUNT(*) AS n FROM watch_push_subscriptions WHERE org_id = ? AND user_id = ?",
                            (org_id, user_id)).fetchone()
        feed = conn.execute("SELECT created_at FROM watch_feed_tokens WHERE org_id = ? AND user_id = ?",
                            (org_id, user_id)).fetchone()
    watches = []
    for r in rows:
        st = domain_state(r["domain"])
        watches.append({"domain": r["domain"], "source": r["source"], "since": r["created_at"],
                        "state": _public_state(st), "next_check": next_check(st)})
    return {"watches": watches, "events": [dict(e) for e in events], "push": {**web_push.status(), "subscriptions": int(push["n"] or 0)},
            "channels": list_channels(org_id, user_id), "feed": {"exists": bool(feed), "created_at": feed["created_at"] if feed else None},
            "settings": settings()}


# ── the tick ────────────────────────────────────────────────────────────────

def due_domains(limit: int, now: Optional[datetime] = None) -> List[str]:
    """Watched domains whose last check is older than the interval; never-checked first."""
    from services import public_check

    init_tables()
    cutoff = iso((now or now_utc()) - timedelta(hours=interval_hours()))
    with _scope("watch tick: which watched domains are due, across every organization"), feature_conn() as conn:
        names = sorted({r["domain"] for r in conn.execute("SELECT DISTINCT domain FROM watch_domains").fetchall()})
        states = {r["domain"]: r["checked_at"] for r in conn.execute("SELECT domain, checked_at FROM watch_domain_state").fetchall()}
    due = sorted((states.get(d) or "", d) for d in names if (states.get(d) or "") < cutoff)
    out = []
    for _, d in due:
        if len(out) >= max(0, int(limit)):
            break
        if public_check.opted_out(d):
            continue
        out.append(d)
    return out


def check_domain(domain: str, grade: Optional[Callable[[str], Dict[str, Any]]] = None,
                 exposure: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
                 deliver: bool = True) -> Dict[str, Any]:
    """Check one watched domain now, record its state, and fan out what changed."""
    from services import public_grade

    grade = grade or public_grade.grade_one
    result = grade(domain)
    checked_at = str(result.get("scanned_at") or iso(now_utc()))
    with _scope("watch tick: record a watched domain's state"), feature_conn() as conn:
        before = _state(conn, domain)
        if "error" in result or result.get("grade") not in public_grade.GRADES:
            _save_state(conn, domain, iso(now_utc()), None, str(result.get("detail") or result.get("error") or "error"))
            conn.commit()
            return {"domain": domain, "ok": False, "error": result.get("error"), "events": []}
        conn.commit()
    try:
        public_grade.store(result)
    except Exception:
        logger.warning("watch: could not store the grade for %s", domain)
    tp = None
    if third_party_enabled():
        try:
            if exposure is not None:
                tp = exposure(domain, result)
            else:
                from services import third_party

                tp = third_party.run(domain, result)
        except Exception:
            logger.warning("watch: the outside-service check of %s failed", domain)
            tp = None
    snap = snapshot(result, tp)
    prev = (before or {}).get("snapshot") or None
    if prev and snap.get("services") is None:
        snap["services"] = prev.get("services")  # an outside-service check that failed changes nothing
    events = diff(domain, prev, snap)
    with _scope("watch tick: record a watched domain's state"), feature_conn() as conn:
        _save_state(conn, domain, checked_at, snap)
        conn.commit()
    sent = fan_out(domain, events) if events and deliver else {"watchers": 0}
    return {"domain": domain, "ok": True, "grade": snap.get("grade"), "events": events, "delivery": sent}


def tick(max_domains: Optional[int] = None, grade: Optional[Callable] = None, exposure: Optional[Callable] = None,
         now: Optional[datetime] = None) -> Dict[str, Any]:
    started = iso(now_utc())
    if not _TICK_LOCK.acquire(blocking=False):
        return {"started_at": started, "busy": True, "checked": 0, "failed": 0, "changes": 0}
    try:
        limit = max(1, min(tick_max(), int(max_domains or tick_max())))
        todo = due_domains(limit, now)
        counts = {"checked": 0, "failed": 0, "changes": 0}
        lock = threading.Lock()

        def work(d: str) -> None:
            try:
                out = check_domain(d, grade=grade, exposure=exposure)
            except Exception:
                logger.exception("watch: checking %s failed", d)
                out = {"ok": False, "events": []}
            with lock:
                counts["checked" if out.get("ok") else "failed"] += 1
                counts["changes"] += len(out.get("events") or [])

        if todo:
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                list(pool.map(work, todo))
        return {"started_at": started, "finished_at": iso(now_utc()), "due": len(todo), **counts}
    finally:
        _TICK_LOCK.release()


# ── notification fan-out ────────────────────────────────────────────────────

def _base_url() -> str:
    from services.public_config import public_base_url

    return (public_base_url() or "https://morrow.soqlab.com").rstrip("/")


def message(domain: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    first = events[0]["sentence"]
    more = len(events) - 1
    return {"title": f"Morrow: {domain}", "body": first + (f" (+{more} more)" if more else ""),
            "url": f"{_base_url()}/{domain}", "tag": f"morrow-watch-{domain}"}


def webhook_payload(kind: str, domain: str, events: List[Dict[str, Any]], test: bool = False) -> Dict[str, Any]:
    msg = message(domain, events)
    if kind == "slack_webhook":
        lines = "\n".join(f"- {e['sentence']}" for e in events)
        return {"text": f"{events[0]['sentence']}", "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{domain}*\n{lines}\n<{msg['url']}|Open in Morrow>"}}]}
    return {"source": "morrow", "type": "watch.test" if test else "watch.change", "test": bool(test), "domain": domain,
            "link": msg["url"], "sent_at": iso(now_utc()),
            "changes": [{k: e.get(k) for k in ("kind", "sentence", "at", "host")} for e in events]}


def _watchers(conn: Any, domain: str) -> List[Any]:
    return conn.execute("SELECT org_id, user_id FROM watch_domains WHERE domain = ?", (domain,)).fetchall()


def fan_out(domain: str, events: List[Dict[str, Any]], push_sender: Optional[Callable] = None,
            webhook_sender: Optional[Callable] = None) -> Dict[str, Any]:
    """Record the changes for every watcher of domain and deliver them. Never raises."""
    from services import alert_routing, web_push

    push_sender = push_sender or web_push.send
    webhook_sender = webhook_sender or alert_routing.post_json
    init_tables()
    summary = {"watchers": 0, "events": 0, "push": {"sent": 0, "failed": 0, "disabled": 0, "gone": 0},
               "webhooks": {"sent": 0, "failed": 0}}
    now = iso(now_utc())
    msg = message(domain, events)
    # Record first and read the targets, then send with no database transaction open (a send can
    # take seconds and must not hold SQLite's write lock), then write what each target answered.
    targets = []
    with _scope("watch: record a change for everyone watching the domain"), feature_conn() as conn:
        watchers = _watchers(conn, domain)
        summary["watchers"] = len(watchers)
        for w in watchers:
            org, user = w["org_id"], w["user_id"]
            for e in events:
                conn.execute("INSERT INTO watch_events (id, org_id, user_id, domain, kind, sentence, detail_json, at, created_at) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             (uuid.uuid4().hex, org, user, domain, e["kind"], e["sentence"],
                              json.dumps({k: e.get(k) for k in ("host",) if e.get(k)}), e.get("at") or now, now))
                summary["events"] += 1
            _trim(conn, org, user)
            subs = conn.execute("SELECT endpoint, p256dh, auth FROM watch_push_subscriptions WHERE org_id = ? AND user_id = ?",
                                (org, user)).fetchall()
            chans = conn.execute("SELECT id, kind, target_sealed FROM watch_channels WHERE org_id = ? AND user_id = ?",
                                 (org, user)).fetchall()
            targets.append((org, [dict(x) for x in subs], [dict(x) for x in chans]))
        conn.commit()
    results = []
    for org, subs, chans in targets:
        for s in subs:
            out = push_sender({"endpoint": s["endpoint"], "p256dh": s["p256dh"], "auth": s["auth"]}, msg)
            results.append(("push", org, s["endpoint"], out))
        for c in chans:
            try:
                out = webhook_sender(alert_routing.unseal(c["target_sealed"]), webhook_payload(c["kind"], domain, events))
            except Exception as exc:
                out = {"ok": False, "error": f"Send failed: {exc.__class__.__name__}"}
            results.append(("hook", org, c["id"], out))
    with _scope("watch: record how each watcher's channels answered"), feature_conn() as conn:
        for kind, org, key, out in results:
            status = "ok" if out.get("ok") else str(out.get("error") or "failed")[:200]
            if kind == "hook":
                summary["webhooks"]["sent" if out.get("ok") else "failed"] += 1
                conn.execute("UPDATE watch_channels SET last_status = ?, last_sent_at = ? WHERE id = ? AND org_id = ?",
                             (status, now, key, org))
            elif out.get("disabled"):
                summary["push"]["disabled"] += 1
            elif out.get("gone"):
                summary["push"]["gone"] += 1
                conn.execute("DELETE FROM watch_push_subscriptions WHERE org_id = ? AND endpoint = ?", (org, key))
            else:
                summary["push"]["sent" if out.get("ok") else "failed"] += 1
                conn.execute("UPDATE watch_push_subscriptions SET last_status = ? WHERE org_id = ? AND endpoint = ?",
                             (status, org, key))
        conn.commit()
    return summary


def _trim(conn: Any, org: str, user: str) -> None:
    rows = conn.execute("SELECT id FROM watch_events WHERE org_id = ? AND user_id = ? ORDER BY created_at DESC, at DESC",
                        (org, user)).fetchall()
    for r in rows[EVENT_KEEP:]:
        conn.execute("DELETE FROM watch_events WHERE id = ? AND org_id = ?", (r["id"], org))


# ── push subscriptions ──────────────────────────────────────────────────────

def add_push(org_id: str, user_id: str, sub: Dict[str, Any], resolve: bool = True) -> Dict[str, Any]:
    from services import web_push

    st = web_push.status()
    if not st["enabled"]:
        raise WatchError(503, st["reason"], "push_disabled")
    try:
        endpoint = web_push.validate_endpoint(sub.get("endpoint"), resolve=resolve)
    except web_push.PushError as exc:
        raise WatchError(exc.status_code, exc.detail, exc.code) from None
    keys = sub.get("keys") or {}
    p256dh, auth = str(keys.get("p256dh") or ""), str(keys.get("auth") or "")
    try:
        if len(web_push.unb64u(p256dh)) != 65 or len(web_push.unb64u(auth)) != 16:
            raise ValueError
    except Exception:
        raise WatchError(400, "The browser subscription keys are malformed.", "bad_keys") from None
    init_tables()
    with feature_conn() as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM watch_push_subscriptions WHERE org_id = ? AND user_id = ?",
                         (org_id, user_id)).fetchone()
        conn.execute("DELETE FROM watch_push_subscriptions WHERE org_id = ? AND endpoint = ?", (org_id, endpoint))
        if int(n["n"] or 0) >= MAX_PUSH_PER_USER:
            raise WatchError(400, f"Up to {MAX_PUSH_PER_USER} browsers per person. Turn one off first.", "too_many")
        conn.execute("INSERT INTO watch_push_subscriptions (org_id, user_id, endpoint, p256dh, auth, created_at) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (org_id, user_id, endpoint, p256dh, auth, iso(now_utc())))
        conn.commit()
    return {"subscribed": True}


def remove_push(org_id: str, user_id: str, endpoint: Any) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM watch_push_subscriptions WHERE org_id = ? AND user_id = ? AND endpoint = ?",
                           (org_id, user_id, str(endpoint or "")))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


# ── webhook channels ────────────────────────────────────────────────────────

def list_channels(org_id: str, user_id: str) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT id, kind, target_hint, created_at, last_status, last_sent_at FROM watch_channels "
                            "WHERE org_id = ? AND user_id = ? ORDER BY created_at", (org_id, user_id)).fetchall()
    return [dict(r) for r in rows]


def add_channel(org_id: str, user_id: str, kind: Any, target: Any, resolve: bool = True) -> Dict[str, Any]:
    from services import alert_routing

    kind = str(kind or "").strip()
    if kind not in CHANNEL_KINDS:
        raise WatchError(400, "Choose a Slack webhook or a generic webhook.", "bad_kind")
    try:
        url = alert_routing.validate_webhook_url(target, resolve=resolve)
        sealed = alert_routing.seal(url)
    except alert_routing.AlertRoutingError as exc:
        raise WatchError(exc.status_code, exc.detail, "bad_target") from None
    init_tables()
    with feature_conn() as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM watch_channels WHERE org_id = ? AND user_id = ?", (org_id, user_id)).fetchone()
        if int(n["n"] or 0) >= MAX_CHANNELS_PER_USER:
            raise WatchError(400, f"Up to {MAX_CHANNELS_PER_USER} webhooks per person. Remove one first.", "too_many")
        cid = uuid.uuid4().hex[:16]
        conn.execute("INSERT INTO watch_channels (id, org_id, user_id, kind, target_sealed, target_hint, created_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)", (cid, org_id, user_id, kind, sealed,
                                                      alert_routing.target_hint(kind, url), iso(now_utc())))
        conn.commit()
    return next(c for c in list_channels(org_id, user_id) if c["id"] == cid)


def remove_channel(org_id: str, user_id: str, channel_id: str) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM watch_channels WHERE id = ? AND org_id = ? AND user_id = ?",
                           (str(channel_id), org_id, user_id))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def test_channels(org_id: str, user_id: str, push_sender: Optional[Callable] = None,
                  webhook_sender: Optional[Callable] = None) -> Dict[str, Any]:
    """One test message to every channel of this person, with what each answered."""
    from services import alert_routing, web_push

    push_sender = push_sender or web_push.send
    webhook_sender = webhook_sender or alert_routing.post_json
    events = [{"kind": "test", "sentence": "This is a test from Morrow: changes to the domains you watch arrive here.",
               "at": iso(now_utc())}]
    out: Dict[str, Any] = {"push": [], "webhooks": []}
    init_tables()
    with feature_conn() as conn:
        subs = conn.execute("SELECT endpoint, p256dh, auth FROM watch_push_subscriptions WHERE org_id = ? AND user_id = ?",
                            (org_id, user_id)).fetchall()
        chans = conn.execute("SELECT id, kind, target_sealed, target_hint FROM watch_channels WHERE org_id = ? AND user_id = ?",
                             (org_id, user_id)).fetchall()
    msg = {"title": "Morrow", "body": events[0]["sentence"], "url": _base_url() + "/watching", "tag": "morrow-watch-test"}
    for s in subs:
        r = push_sender({"endpoint": s["endpoint"], "p256dh": s["p256dh"], "auth": s["auth"]}, msg)
        out["push"].append({"ok": bool(r.get("ok")), "error": r.get("error") or ""})
    for c in chans:
        try:
            r = webhook_sender(alert_routing.unseal(c["target_sealed"]), webhook_payload(c["kind"], "example", events, test=True))
        except Exception as exc:
            r = {"ok": False, "error": f"Send failed: {exc.__class__.__name__}"}
        out["webhooks"].append({"id": c["id"], "hint": c["target_hint"], "ok": bool(r.get("ok")), "error": r.get("error") or ""})
    return out


# ── the private feed ────────────────────────────────────────────────────────

def _hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def new_feed(org_id: str, user_id: str) -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM watch_feed_tokens WHERE org_id = ? AND user_id = ?", (org_id, user_id))
        conn.execute("INSERT INTO watch_feed_tokens (org_id, user_id, token_hash, created_at) VALUES (?, ?, ?, ?)",
                     (org_id, user_id, _hash(token), iso(now_utc())))
        conn.commit()
    return {"url": f"{_base_url()}/api/public/watch-feed/{token}.atom", "token": token}


def drop_feed(org_id: str, user_id: str) -> bool:
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM watch_feed_tokens WHERE org_id = ? AND user_id = ?", (org_id, user_id))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def feed_events(token: str, limit: int = 100) -> Optional[List[Dict[str, Any]]]:
    """The events of the person a feed token belongs to, newest first, or None for an unknown token."""
    text = str(token or "")
    if not (20 <= len(text) <= 100):
        return None
    init_tables()
    with _scope("watch feed: the events of the person a private feed token belongs to"), feature_conn() as conn:
        owner = conn.execute("SELECT org_id, user_id FROM watch_feed_tokens WHERE token_hash = ?", (_hash(text),)).fetchone()
        if not owner:
            return None
        rows = conn.execute("SELECT id, domain, kind, sentence, at, created_at FROM watch_events WHERE org_id = ? AND user_id = ? "
                            "ORDER BY created_at DESC, at DESC LIMIT ?", (owner["org_id"], owner["user_id"], int(limit))).fetchall()
    return [dict(r) for r in rows]


def feed_atom(token: str) -> Optional[str]:
    from xml.sax.saxutils import escape

    events = feed_events(token)
    if events is None:
        return None
    base = _base_url()
    items = []
    for e in events:
        items.append("<entry><id>urn:morrow:watch:" + escape(e["id"]) + "</id><title>" + escape(e["sentence"]) + "</title>"
                     "<updated>" + escape(e["created_at"]) + "</updated><published>" + escape(e["at"]) + "</published>"
                     '<link href="' + escape(base + "/" + e["domain"]) + '"/><category term="' + escape(e["kind"]) + '"/>'
                     "<content type=\"text\">" + escape(e["sentence"]) + "</content></entry>")
    updated = events[0]["created_at"] if events else "1970-01-01T00:00:00Z"
    return ('<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'
            "<id>urn:morrow:watch-feed:" + _hash(token)[:16] + "</id><title>Morrow: what changed on the domains you watch</title>"
            "<updated>" + escape(updated) + "</updated>"
            '<link rel="alternate" href="' + escape(base + "/watching") + '"/>' + "".join(items) + "</feed>\n")


# ── claims ──────────────────────────────────────────────────────────────────

def _domain_error(exc: Exception) -> WatchError:
    return WatchError(getattr(exc, "status_code", 400), getattr(exc, "detail", str(exc)), "domain")


def _claim_row(conn: Any, org_id: str, name: str) -> Optional[Any]:
    return conn.execute("SELECT claimed_at, claimed_by FROM domain_claims WHERE org_id = ? AND domain = ?",
                        (org_id, name)).fetchone()


def claim_status(org_id: str, domain: Any) -> Dict[str, Any]:
    """This organization's view of a claim: the record to publish, whether it is ours, whether it is taken."""
    from services import domain_verification

    name = normalize(domain)
    init_tables()
    rows = [d for d in domain_verification.list_domains(org_id) if d["domain"] == name]
    with feature_conn() as conn:
        mine = _claim_row(conn, org_id, name)
    with _scope("domain claim: is this domain claimed by another organization"), feature_conn() as conn:
        other = conn.execute("SELECT org_id FROM domain_claims WHERE domain = ? AND org_id <> ?", (name, org_id)).fetchone()
    rec = rows[0] if rows else None
    return {"domain": name, "claimed": bool(mine), "claimed_at": mine["claimed_at"] if mine else None,
            "claimed_by_other": bool(other) and not mine, "verified": bool(rec and rec["status"] == "verified"),
            "record": {"name": rec["record_name"], "type": "TXT", "value": rec["record_value"]} if rec else None,
            "last_error": rec["last_error"] if rec else "", "contact": contact_address()}


def start_claim(org_id: str, domain: Any) -> Dict[str, Any]:
    from services import domain_verification

    name = normalize(domain)
    try:
        domain_verification.add_domain(org_id, name)
    except domain_verification.DomainError as exc:
        raise _domain_error(exc) from None
    return claim_status(org_id, name)


def _record_present(org_id: str, name: str) -> Optional[bool]:
    """Is this organization's TXT record for name published right now? None when DNS cannot answer."""
    from services import domain_verification

    with _scope("domain claim: read the earlier claimant's DNS token"), feature_conn() as conn:
        row = conn.execute("SELECT token FROM org_verified_domains WHERE org_id = ? AND domain = ?", (org_id, name)).fetchone()
    if not row:
        return False
    try:
        values = domain_verification._txt_values(f"{domain_verification.RECORD_PREFIX}.{name}")
    except domain_verification.DomainError:
        return None
    return f"{domain_verification.VALUE_PREFIX}{row['token']}" in values


def claim(org_id: str, user_id: str, domain: Any) -> Dict[str, Any]:
    """Check this organization's DNS record now and, if it is there, claim the domain."""
    from services import domain_verification

    name = normalize(domain)
    init_tables()
    try:
        result = domain_verification.verify_domain(org_id, name)
    except domain_verification.DomainError as exc:
        if exc.status_code == 404:
            raise WatchError(404, f"Start the claim first: Morrow gives you a DNS record to publish for {name}.",
                             "not_started") from None
        raise _domain_error(exc) from None
    if not result.get("verified_now"):
        raise WatchError(409, result.get("last_error") or "The DNS record was not found yet.", "record_missing")
    with _scope("domain claim: who holds the claim on this domain"), feature_conn() as conn:
        others = [r["org_id"] for r in conn.execute("SELECT org_id FROM domain_claims WHERE domain = ? AND org_id <> ?",
                                                     (name, org_id)).fetchall()]
    moved_from = []
    for other in others:
        present = _record_present(other, name)
        if present is None:
            raise WatchError(503, "Morrow could not read DNS just now to check the earlier claim. Try again in a minute.",
                             "dns_unavailable")
        if present:
            raise WatchError(409, f"Another organization claimed {name} first and its DNS record is still published. "
                                  "If you control this domain's DNS, remove the other _morrow-verify value and claim again.",
                             "claimed_by_other")
        moved_from.append(other)
    if moved_from:
        with _scope("domain claim: the earlier claimant's DNS record is gone, so the claim moves"), feature_conn() as conn:
            for other in moved_from:
                conn.execute("DELETE FROM domain_claims WHERE org_id = ? AND domain = ?", (other, name))
            conn.commit()
    with feature_conn() as conn:
        if not _claim_row(conn, org_id, name):
            try:
                with atomic(conn):
                    conn.execute("INSERT INTO domain_claims (org_id, domain, claimed_at, claimed_by) VALUES (?, ?, ?, ?)",
                                 (org_id, name, iso(now_utc()), str(user_id or "")[:200]))
            except INTEGRITY_ERRORS:
                pass
        conn.commit()
    if user_id:
        try:
            watch(org_id, user_id, name, source="claim")
        except WatchError as exc:
            if exc.code != "too_many":
                raise
    out = claim_status(org_id, name)
    out["moved"] = bool(moved_from)
    return out


def release(org_id: str, domain: Any) -> bool:
    name = normalize(domain)
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM domain_claims WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.commit()
    return bool(getattr(cur, "rowcount", 0))


def require_claim(org_id: str, domain: Any) -> str:
    name = normalize(domain)
    init_tables()
    with feature_conn() as conn:
        if not _claim_row(conn, org_id, name):
            raise WatchError(403, f"Claim {name} first: only its owner can do this.", "not_claimed")
    return name


def public_claim(domain: Any) -> Dict[str, Any]:
    """What a public page says about a claim: whether there is one and since when. Never who."""
    name = normalize(domain)
    init_tables()
    from services import not_ready

    not_ready.init_tables()
    with _scope("public domain page: is this domain claimed, and its owner's public reply"), feature_conn() as conn:
        row = conn.execute("SELECT org_id, claimed_at FROM domain_claims WHERE domain = ? ORDER BY claimed_at LIMIT 1",
                           (name,)).fetchone()
        reply = None
        if row:
            r = conn.execute("SELECT text, created_at FROM not_ready_replies WHERE org_id = ? AND domain = ?",
                             (row["org_id"], name)).fetchone()
            if r:
                reply = {"text": r["text"], "at": r["created_at"]}
    return {"domain": name, "claimed": bool(row), "since": row["claimed_at"] if row else None, "reply": reply,
            "how": "Claim it with a DNS TXT record: no email, no call."}


# ── /about-scanner ──────────────────────────────────────────────────────────

def about_scanner(example_host: str = "example.com") -> Dict[str, Any]:
    """What Morrow's checker sends, when, and how to stop it, with this server's live settings."""
    from services import league, public_check, public_grade, third_party

    base = _base_url()
    abuse = public_check.abuse_contact()
    return {
        "user_agent": public_grade.USER_AGENT,
        "header": {"name": public_grade.SCANNER_INFO_HEADER, "example": public_grade.scanner_info(example_host)},
        "from_header": False,
        "what": [
            {"part": "The grade", "sends": "A handful of TLS handshakes to port 443 (which key exchange the server picks when "
                                           "post-quantum groups are offered, which TLS versions it accepts, whether its "
                                           "certificate verifies) and one HEAD / request, to read the Server header."},
            {"part": "Outside services", "sends": "One GET / of the homepage (at most 512 KB, at most "
                                                  f"{third_party.MAX_REDIRECTS} redirects), DNS lookups (CNAME, MX and a "
                                                  "fixed list of common sign-in and payment names), then one TLS "
                                                  f"ClientHello to each of at most {third_party.max_hosts()} outside hosts "
                                                  "the page or DNS names."},
        ],
        "when": [
            {"why": "Somebody opens your page", "how_often": f"the stored answer is reused for "
                                                             f"{public_grade.cache_seconds() // 60} minutes; at most "
                                                             f"{public_grade.domain_per_hour()} fresh checks an hour per domain, "
                                                             "whoever asks"},
            {"why": "The sector league and the popular-sites list", "how_often": f"once every {league.REFRESH_DAYS} days"},
            {"why": "Somebody watches your domain", "how_often": f"once every {interval_hours():g} hours, however many people "
                                                                  "watch it"},
        ],
        "never": ["any port but 443", "a private, loopback, link-local or this server's own address (checked once, then "
                  "the connection is pinned to that address)", "anything past your homepage: no crawl, no login, no form "
                  "posts, no vulnerability probes", "email: Morrow never writes to anyone about a check"],
        "your_result": f"{base}/{example_host}",
        "opt_out": {"page": f"{base}/abuse", "contact": abuse,
                    "how": "Ask once and the domain and every name under it are refused before DNS is even looked up. "
                           "If you have claimed the domain in Morrow, you can do it yourself from its page."},
        "stored": "The handshake facts and the grade, with the date. No page content, no cookies, no personal data.",
    }
