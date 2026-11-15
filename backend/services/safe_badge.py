"""The live safe badge: one line of HTML a domain's owner pastes on their own site.

    <a href="https://morrow.soqlab.com/example.com"><img src="https://morrow.soqlab.com/api/public/safe-badge/example.com.svg"
       alt="Morrow quantum-safety check for example.com" height="20" referrerpolicy="no-referrer"></a>

It reads "Quantum-safe · verified 2026-11-15" while, and only while, all of this holds:
  * the domain is claimed in Morrow by DNS (services/watch.claim: ``_morrow-verify`` TXT record) and
    the organization holding that claim turned the badge on. A claim that moves to another
    organization takes the badge with it: the old organization's switch no longer counts;
  * Morrow's newest stored check of the domain (services/public_grade, current rubric) is grade A or
    B, which needs a key exchange that includes ML-KEM;
  * that check is at most :data:`FRESH_HOURS` old.
Otherwise the badge is neutral: "Morrow · quantum check", no claim either way. It never says
"not safe" on the owner's own site, and it never says "safe" from an old or failed check.

Re-checks reuse the watch tick (services/watch.due_domains / check_domain): a domain with a badge
on is due every :data:`RECHECK_HOURS` even if nobody watches it, with the same guarded probe as
every public check (public_grade.grade_one: SSRF guard, opt-outs, timeouts, the honest scanner
User-Agent) and the tick's own per-run limit. Serving the badge never contacts the domain: it
reads stored data only, cached in memory for :data:`CACHE_SECONDS`.

No cookies, no script, no fonts or images from anywhere else; the SVG is self-contained. The
badge request is not written to the traffic monitor (app.py, ``_is_embed_path``).

``safe_badges`` is org-scoped (``org_id``) and in the Postgres RLS plan.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn

FRESH_HOURS = 48
RECHECK_HOURS = 24
CACHE_SECONDS = 300
SAFE_GRADES = ("A", "B")
SVG_CACHE = "public, max-age=3600"
NEUTRAL_LABEL = ("Morrow", "quantum check")

SCHEMA = """CREATE TABLE IF NOT EXISTS safe_badges (
    org_id TEXT NOT NULL, domain TEXT NOT NULL, enabled_at TEXT NOT NULL,
    enabled_by TEXT NOT NULL DEFAULT '', PRIMARY KEY (org_id, domain))"""
ORG_TABLES = ("safe_badges",)

_ready = ""
_ready_lock = threading.Lock()
_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _identity() -> str:
    import os

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
            conn.execute(SCHEMA)
            conn.commit()
        _ready = identity


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(text: Any) -> Optional[datetime]:
    try:
        return datetime.strptime(str(text)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _scope(reason: str):
    from services import tenant_scope

    return tenant_scope.platform_scope(reason)


def base_url() -> str:
    from services.public_config import public_base_url

    return (public_base_url() or "https://morrow.soqlab.com").rstrip("/")


# ── the owner's switch ───────────────────────────────────────────────────────


def snippet(domain: str) -> str:
    base = base_url()
    return (f'<a href="{base}/{domain}"><img src="{base}/api/public/safe-badge/{domain}.svg" '
            f'alt="Morrow quantum-safety check for {domain}" height="20" referrerpolicy="no-referrer"></a>')


def owner_view(org_id: str, domain: Any) -> Dict[str, Any]:
    """What the owner sees: on or off, the snippet, and what the badge shows right now."""
    from services import watch

    name = watch.require_claim(org_id, domain)
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT enabled_at FROM safe_badges WHERE org_id = ? AND domain = ?", (org_id, name)).fetchone()
    return {"domain": name, "enabled": bool(row), "enabled_at": row["enabled_at"] if row else None,
            "snippet": snippet(name), "status": status(name, use_cache=False), "fresh_hours": FRESH_HOURS,
            "recheck_hours": RECHECK_HOURS}


def enable(org_id: str, user_id: str, domain: Any) -> Dict[str, Any]:
    from services import watch

    name = watch.require_claim(org_id, domain)
    init_tables()
    with feature_conn() as conn:
        if not conn.execute("SELECT 1 FROM safe_badges WHERE org_id = ? AND domain = ?", (org_id, name)).fetchone():
            try:
                with atomic(conn):
                    conn.execute("INSERT INTO safe_badges (org_id, domain, enabled_at, enabled_by) VALUES (?, ?, ?, ?)",
                                 (org_id, name, watch.iso(_now()), str(user_id or "")[:200]))
            except INTEGRITY_ERRORS:
                pass
        conn.commit()
    # The domain's shared state starts from its newest stored grade, so the tick knows what it had.
    with _scope("safe badge: start the domain's shared watch state from its stored public grade"), feature_conn() as conn:
        watch._baseline(conn, name)
        conn.commit()
    forget(name)
    return owner_view(org_id, name)


def disable(org_id: str, domain: Any) -> bool:
    from services import watch

    name = watch.normalize(domain)
    init_tables()
    with feature_conn() as conn:
        cur = conn.execute("DELETE FROM safe_badges WHERE org_id = ? AND domain = ?", (org_id, name))
        conn.commit()
    forget(name)
    return bool(getattr(cur, "rowcount", 0))


def forget(name: str) -> None:
    with _cache_lock:
        _cache.pop(name, None)


# ── which domains the tick must re-check ─────────────────────────────────────


def active_domains() -> List[str]:
    """Domains with the badge on by the organization that holds the claim now."""
    from services import watch

    init_tables()
    watch.init_tables()
    with _scope("safe badge: which badges are on, across every organization"), feature_conn() as conn:
        rows = conn.execute("SELECT DISTINCT b.domain FROM safe_badges b JOIN domain_claims c "
                            "ON c.org_id = b.org_id AND c.domain = b.domain").fetchall()
    return sorted(r["domain"] for r in rows)


# ── the public answer ────────────────────────────────────────────────────────


def _enabled_by_claimant(name: str) -> bool:
    from services import watch

    init_tables()
    watch.init_tables()
    with _scope("safe badge: is the badge on, by the organization holding the claim"), feature_conn() as conn:
        row = conn.execute("SELECT 1 FROM safe_badges b JOIN domain_claims c ON c.org_id = b.org_id AND c.domain = b.domain "
                           "WHERE b.domain = ? LIMIT 1", (name,)).fetchone()
    return bool(row)


def _safe_since(name: str) -> Optional[str]:
    """The first check of the current unbroken run of safe checks, newest first back to the last unsafe one."""
    from services import public_grade

    since = None
    for r in public_grade.history_all(name, 2000):
        if r["grade"] in SAFE_GRADES and r["post_quantum"]:
            since = r["scanned_at"]
        else:
            break
    return since


def evaluate(enabled: bool, latest: Optional[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Pure: the badge's state from the switch and the newest stored check."""
    now = now or _now()
    if not enabled:
        return {"state": "neutral", "reason": "off", "verified_at": None}
    if not latest:
        return {"state": "neutral", "reason": "no_check", "verified_at": None}
    at = _parse(latest.get("scanned_at"))
    kx = latest.get("key_exchange") or {}
    if at is None or now - at > timedelta(hours=FRESH_HOURS):
        return {"state": "neutral", "reason": "stale", "verified_at": None, "last_check": latest.get("scanned_at")}
    if latest.get("grade") not in SAFE_GRADES or not kx.get("post_quantum"):
        return {"state": "neutral", "reason": "not_safe", "verified_at": None, "last_check": latest.get("scanned_at")}
    return {"state": "safe", "reason": "", "verified_at": latest.get("scanned_at"), "last_check": latest.get("scanned_at"),
            "key_exchange": kx.get("group") or None}


REASONS = {
    "off": "The owner has not turned the badge on, so it makes no claim.",
    "no_check": "Morrow has no check of this domain yet, so the badge makes no claim.",
    "stale": f"Morrow's newest check is more than {FRESH_HOURS} hours old, so the badge makes no claim until a new one succeeds.",
    "not_safe": "Morrow's newest check did not find a post-quantum key exchange, so the badge makes no claim.",
    "": "Morrow's newest check found a key exchange that includes ML-KEM: traffic recorded now can't be read later with a quantum computer.",
}


def status(domain: Any, use_cache: bool = True) -> Dict[str, Any]:
    """The public answer for a domain: safe or neutral, verified when, safe since when. Never who owns it."""
    from services import public_check, public_grade, watch

    name = watch.normalize(domain)
    if use_cache:
        with _cache_lock:
            hit = _cache.get(name)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
    enabled = _enabled_by_claimant(name) and not public_check.opted_out(name)
    latest = public_grade.latest(name) if enabled else None
    out = {"domain": name, "enabled": enabled, **evaluate(enabled, latest)}
    out["safe_since"] = _safe_since(name) if out["state"] == "safe" else None
    out["explanation"] = REASONS.get(out["reason"], "")
    out["page"] = f"{base_url()}/{name}"
    with _cache_lock:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[name] = (time.monotonic(), out)
    return out


# ── the image ────────────────────────────────────────────────────────────────


def _w(text: str) -> int:
    """Approximate width of 11px Verdana text: no font is fetched, so this only needs to be close."""
    return int(sum(7.2 if c.isupper() or c in "mwMW" else 4 if c in " ·.-il1:" else 6.4 for c in text)) + 12


def _xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def svg(st: Dict[str, Any]) -> str:
    if st.get("state") == "safe":
        left, right = "Quantum-safe", "verified " + str(st.get("verified_at") or "")[:10]
        color, title = "#2e7d32", f"Quantum-safe, verified by Morrow on {str(st.get('verified_at') or '')[:10]}"
    else:
        left, right = NEUTRAL_LABEL
        color, title = "#6b6b6b", "Morrow quantum check: see the result on Morrow"
    lw, rw = _w(left), _w(right)
    width = lw + rw
    left, right, title = _xml(left), _xml(right), _xml(title)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{title}">'
        f"<title>{title}</title>"
        f'<clipPath id="r"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#444"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/></g>'
        '<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" fill="#fff">'
        f'<text x="{lw / 2:.0f}" y="14">{left}</text>'
        f'<text x="{lw + rw / 2:.0f}" y="14">{right}</text>'
        "</g></svg>"
    )
