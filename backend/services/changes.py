"""What changed: the public feed of post-quantum readiness changes Morrow has measured.

Built only from grades Morrow already stores (``public_grade_checks``, current rubric) for the
domains it already watches. Nothing is checked for the feed, and the feed follows the same naming
rules as the public lists:

Named entries (a domain appears by name)
  * A popular site from the stored Tranco list (services/tranco.py), the only source the
    "Not yet post-quantum" list (services/not_ready.py) names, under the same opt-out rules
    (services/public_check.opted_out and the league's opt-out entries). Two kinds of change are
    named, both crossing the line that list draws at grade B:
      - ``ready``: a check graded it A or B after it was below B ("became post-quantum ready");
      - ``not_ready``: a check graded it below B after it was A or B. The not-ready list would
        name it from that check on, so the feed may too. A move within A/B, or within C-F, is not
        a change here. A first grade is not a change.
    The owner's right-of-reply statement (not_ready_replies) is shown with the entry.
  * A domain on the opt-in post-quantum ready list (services/pq_ready.py), which its verified
    owner chose to put there: ``listed``, dated when it joined. A domain that only appears
    because its owner listed it is never named for a drop; it simply leaves that list.

Unnamed entries (sector counts)
  * The league's named-organisation sector lists (services/league.py) are never named in public.
    Their changes appear only as weekly counts per sector: "2 sites in Banks & payments became
    post-quantum ready in the week of 2026-11-09; 1 dropped below B." No domain is given.

Wording is the measured change with its date: grades, the key exchange seen, and the check's
day. Never a label (the BANNED_WORDS of services/not_ready.py are held to in tests).

Served as JSON, Atom and RSS under /api/public/changes, filterable by sector, cached in this
process for ``CACHE_SECONDS`` and rate limited per client IP (routers/public_grade.py).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

READY = ("A", "B")
CACHE_SECONDS = 300.0
WINDOW_DAYS = 400
MAX_EVENTS = 300

_cache: Dict[str, Any] = {}


def _identity() -> str:
    import os

    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def clear_cache() -> None:
    _cache.clear()


def _week_start(iso_text: str) -> str:
    day = datetime.strptime(str(iso_text)[:10], "%Y-%m-%d")
    return (day - timedelta(days=day.weekday())).strftime("%Y-%m-%d")


def crossings(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Checks (oldest first in, newest first out) where the grade crossed the A/B line."""
    out: List[Dict[str, Any]] = []
    previous: Optional[Dict[str, Any]] = None
    for h in history:
        if previous is not None:
            was, now = previous["grade"] in READY, h["grade"] in READY
            if was != now:
                out.append({"kind": "ready" if now else "not_ready", "at": h["scanned_at"], "grade": h["grade"],
                            "previous_grade": previous["grade"], "group": h.get("group") or "",
                            "post_quantum": bool(h.get("post_quantum"))})
        previous = h
    return list(reversed(out))


def _named_title(domain: str, e: Dict[str, Any]) -> str:
    day = str(e["at"])[:10]
    if e["kind"] == "ready":
        return (f"{domain} became post-quantum ready: grade {e['previous_grade']} to {e['grade']}"
                + (f", key exchange {e['group']}" if e.get("group") else "") + f" (checked {day}).")
    if e["kind"] == "listed":
        return f"{domain} listed itself as post-quantum ready (grade {e['grade']}, {day})."
    kx = (f"; key exchange {e['group']} only" if e.get("group") and not e.get("post_quantum")
          else "; key exchange not observed" if not e.get("group") else "")
    return f"{domain} dropped below B: grade {e['previous_grade']} to {e['grade']}{kx} (checked {day})."


def _sector_title(name: str, week: str, ready: int, dropped: int) -> str:
    parts = []
    if ready:
        parts.append(f"{ready} site{'s' if ready != 1 else ''} in {name} became post-quantum ready")
    if dropped:
        parts.append(f"{dropped} dropped below B" if parts else
                     f"{dropped} site{'s' if dropped != 1 else ''} in {name} dropped below B")
    return "; ".join(parts) + f" in the week of {week}. Sites in the sector lists are not named."


def _build() -> Dict[str, Any]:
    from services import league, not_ready, pq_ready, public_check, public_grade, tranco

    spec = league.load_spec()
    classifier = league.Classifier(spec)
    names = {s["id"]: s["name"] for s in spec["sectors"]}
    names[league.UNCLASSIFIED] = "Other popular sites"
    optouts = league._optout_entries()
    since = public_grade.iso(public_grade.now_utc() - timedelta(days=WINDOW_DAYS))

    def allowed(d: str) -> bool:
        return not league._covered(d, optouts) and not public_check.opted_out(d)

    events: List[Dict[str, Any]] = []
    named_domains = [d for d in tranco.domains() if allowed(d)]
    named_set = set(named_domains)
    replies = not_ready._replies() if named_domains else {}
    history = league._grade_rows(named_domains) if named_domains else {}
    for d in named_domains:
        sid = classifier.classify(d)
        for e in crossings(history.get(d) or []):
            if e["at"] < since:
                continue
            item = dict(e, domain=d, sector=sid, sector_name=names.get(sid, sid), named=True, page="/" + d)
            item["title"] = _named_title(d, item)
            if d in replies:
                item["reply"] = replies[d]
            events.append(item)
    for entry in pq_ready.public_list("joined")["entries"]:
        d = entry["domain"]
        if not allowed(d) or not entry.get("joined_at") or entry["joined_at"] < since:
            continue
        sid = classifier.classify(d)
        item = {"kind": "listed", "at": entry["joined_at"], "grade": entry.get("grade") or "", "previous_grade": None,
                "group": "", "post_quantum": True, "domain": d, "sector": sid, "sector_name": names.get(sid, sid),
                "named": True, "page": "/" + d}
        item["title"] = _named_title(d, item)
        events.append(item)

    # The sector lists: counts per sector and week, never a name. Domains already named above
    # (Tranco) are counted here too when they are in a sector list; the count names nobody.
    league_domains = [d for d in league.league_list(spec) if allowed(d)]
    weekly: Dict[tuple, Dict[str, Any]] = {}
    for d, rows in league._grade_rows(league_domains).items():
        sid = classifier.classify(d)
        for e in crossings(rows):
            if e["at"] < since:
                continue
            key = (sid, _week_start(e["at"]))
            slot = weekly.setdefault(key, {"ready": 0, "not_ready": 0, "at": e["at"]})
            slot[e["kind"]] += 1
            slot["at"] = max(slot["at"], e["at"])
    for (sid, week), slot in weekly.items():
        name = names.get(sid, sid)
        events.append({"kind": "sector", "at": slot["at"], "week": week, "sector": sid, "sector_name": name,
                       "named": False, "became_ready": slot["ready"], "dropped": slot["not_ready"],
                       "page": "/report/" + sid if sid in {s["id"] for s in spec["sectors"]} else "/report",
                       "title": _sector_title(name, week, slot["ready"], slot["not_ready"])})
    events.sort(key=lambda e: (e["at"], e.get("domain") or e.get("sector") or ""), reverse=True)
    sectors = sorted({(e["sector"], e["sector_name"]) for e in events}, key=lambda x: x[1])
    return {"events": events[:MAX_EVENTS], "sectors": sectors, "named_pool": len(named_set),
            "generated_at": public_grade.iso(public_grade.now_utc())}


def feed(sector: str = "", kind: str = "", limit: int = 100) -> Dict[str, Any]:
    from services import public_grade

    key = _identity()
    hit = _cache.get(key)
    if not hit or time.monotonic() - hit[0] > CACHE_SECONDS:
        hit = (time.monotonic(), _build())
        _cache[key] = hit
    built = hit[1]
    sector = str(sector or "").strip().lower()[:40]
    kind = str(kind or "").strip().lower()
    events = [e for e in built["events"] if (not sector or e["sector"] == sector) and (not kind or e["kind"] == kind)]
    limit = max(1, min(MAX_EVENTS, int(limit)))
    counts = {k: sum(1 for e in events if e["kind"] == k) for k in ("ready", "not_ready", "listed", "sector")}
    return {
        "title": "What changed",
        "events": events[:limit], "count": len(events), "counts": counts, "sector": sector or None,
        "sectors": built["sectors"], "generated_at": built["generated_at"],
        "rubric_version": public_grade.RUBRIC_VERSION,
        "rules": {
            "named": "A domain is named only when it is a popular site from the Tranco list (the same rule as the "
                     "Not yet post-quantum list) or its verified owner listed it as post-quantum ready. Opted-out "
                     "domains are never named.",
            "changes": "A change is a check whose grade crossed the line at B: below B to A or B (became ready) or "
                       "A or B to below B (dropped below B). A first grade is not a change.",
            "sectors": "Sites in the sector lists are counted per week, never named.",
            "measured": "From stored public grades only; nothing is checked to make this feed.",
        },
    }


def _entry_text(e: Dict[str, Any]) -> str:
    text = e["title"]
    if e.get("reply"):
        text += f" Reply from the owner ({str(e['reply'].get('at'))[:10]}): {e['reply'].get('text')}"
    return text


def atom(base_url: str, sector: str = "") -> str:
    base = base_url.rstrip("/")
    data = feed(sector, limit=100)
    updated = data["events"][0]["at"] if data["events"] else data["generated_at"]
    suffix = ("?sector=" + sector) if sector else ""
    parts = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">',
             "<id>urn:morrow:changes" + (":" + escape(sector) if sector else "") + "</id>",
             "<title>Morrow: what changed" + (" (" + escape(sector) + ")" if sector else "") + "</title>",
             "<updated>" + escape(updated) + "</updated>", "<author><name>SOQLAB Morrow</name></author>",
             '<link rel="self" type="application/atom+xml" href="' + escape(base + "/api/public/changes.atom" + suffix) + '"/>',
             '<link rel="alternate" type="text/html" href="' + escape(base + "/changes" + suffix) + '"/>']
    for e in data["events"]:
        ident = "urn:morrow:change:" + e["kind"] + ":" + (e.get("domain") or e["sector"]) + ":" + e["at"]
        parts.append("<entry><id>" + escape(ident) + "</id><title>" + escape(e["title"]) + "</title>"
                     "<updated>" + escape(e["at"]) + "</updated><summary>" + escape(_entry_text(e)) + "</summary>"
                     '<link href="' + escape(base + e["page"]) + '"/></entry>')
    parts.append("</feed>")
    return "\n".join(parts) + "\n"


def _rfc822(iso_text: str) -> str:
    from email.utils import format_datetime
    from datetime import timezone

    try:
        when = datetime.strptime(str(iso_text)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        when = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return format_datetime(when, usegmt=True)


def rss(base_url: str, sector: str = "") -> str:
    base = base_url.rstrip("/")
    data = feed(sector, limit=100)
    suffix = ("?sector=" + sector) if sector else ""
    items = []
    for e in data["events"]:
        ident = "urn:morrow:change:" + e["kind"] + ":" + (e.get("domain") or e["sector"]) + ":" + e["at"]
        items.append("<item><title>" + escape(e["title"]) + "</title><link>" + escape(base + e["page"]) + "</link>"
                     "<description>" + escape(_entry_text(e)) + "</description>"
                     '<guid isPermaLink="false">' + escape(ident) + "</guid><pubDate>" + _rfc822(e["at"]) + "</pubDate></item>")
    return ('<?xml version="1.0" encoding="utf-8"?>\n<rss version="2.0"><channel>'
            "<title>Morrow: what changed" + (" (" + escape(sector) + ")" if sector else "") + "</title>"
            "<link>" + escape(base + "/changes" + suffix) + "</link>"
            "<description>Post-quantum readiness changes measured by Morrow's public grade.</description>"
            + "".join(items) + "</channel></rss>\n")
