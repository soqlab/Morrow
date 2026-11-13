"""Sector reports: an always-current, citable page per sector, at /report/<sector>.

"34% of the Banks & payments sites Morrow watches are post-quantum ready, up from 21% in August
2026." Built only from what the league (services/league.py) already stores: the explicit,
named-organisation domains of ``backend/league/sectors.json``, each graded at most once a week by
the public grade (services/public_grade.py) under the current rubric. Nothing is checked to make
a report. No site is named: like the league, a report gives counts and shares only.

What a report says, and how
  * Ready means the newest grade is A or B: a post-quantum (hybrid ML-KEM) key exchange was
    negotiated. The share is ready / graded, where graded counts the sector's sites with at least
    one stored grade under the current rubric.
  * The trend is weekly: for each week, every site's newest grade as of the end of that week.
    The comparison point is the week closest to ``COMPARE_DAYS`` (91) before the newest week,
    or the oldest week when the history is shorter; with under four weeks there is none.
  * The sample is stated: sites in the list, graded, not reachable at their latest attempt, not
    graded yet, and how many were left out because they opted out of being checked.
  * "As of" is the newest stored check among the sector's graded sites. The URL is stable:
    /report/<sector id>; the CSV is /api/public/report/<sector>.csv.

Cached in this process for ``CACHE_SECONDS``; the public routes are rate limited per client IP.
"""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

READY = ("A", "B")
GRADES = ("A", "B", "C", "D", "E", "F")
COMPARE_DAYS = 91
MIN_HISTORY_DAYS = 28
MAX_WEEKS = 104
CACHE_SECONDS = 300.0

NOT_MEASURED = (
    "Only the main public website of each organisation is checked, on port 443. Its other hosts, APIs, "
    "mail, VPNs and internal systems are not.",
    "The certificate's signature algorithm is not graded: browsers cannot use post-quantum certificates yet, "
    "and a signature only has to hold while the connection is live.",
    "A grade says what the server negotiated with Morrow's client on the day of the check, not what every "
    "client gets, and not how the organisation handles data after it arrives.",
    "The lists are hand-made from public sources and are not a random sample of the sector.",
)

_cache: Dict[str, Any] = {}


class ReportError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _identity() -> str:
    import os

    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|{os.getenv('DATABASE_URL', '')[:12]}"


def clear_cache() -> None:
    _cache.clear()


def _week_start(iso_text: str) -> str:
    day = datetime.strptime(str(iso_text)[:10], "%Y-%m-%d")
    return (day - timedelta(days=day.weekday())).strftime("%Y-%m-%d")


def _month(week: str) -> str:
    return datetime.strptime(week, "%Y-%m-%d").strftime("%B %Y")


def pct(x: Optional[float]) -> str:
    if x is None:
        return "-"
    value = round(x * 100, 1)
    return (str(int(value)) if value == int(value) else str(value)) + "%"


def trend(rows: Dict[str, List[Dict[str, Any]]], weeks: int = MAX_WEEKS) -> List[Dict[str, Any]]:
    """Weekly points: each site's newest grade as of that week's end (rows are oldest first)."""
    starts = sorted({_week_start(h["scanned_at"]) for hs in rows.values() for h in hs})[-weeks:]
    out = []
    for start in starts:
        end = (datetime.strptime(start, "%Y-%m-%d") + timedelta(days=7)).strftime("%Y-%m-%d")
        counts = {g: 0 for g in GRADES}
        graded = 0
        for hs in rows.values():
            seen = [h for h in hs if h["scanned_at"][:10] < end]
            if not seen:
                continue
            counts[seen[-1]["grade"]] = counts.get(seen[-1]["grade"], 0) + 1
            graded += 1
        if graded:
            ready = counts["A"] + counts["B"]
            out.append({"week": start, "graded": graded, "ready": ready, "share": round(ready / graded, 4),
                        "grades": counts})
    return out


def comparison(points: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if len(points) < 2:
        return None
    last = datetime.strptime(points[-1]["week"], "%Y-%m-%d")
    first = datetime.strptime(points[0]["week"], "%Y-%m-%d")
    if (last - first).days < MIN_HISTORY_DAYS:
        return None
    target = last - timedelta(days=COMPARE_DAYS)
    pick = min(points[:-1], key=lambda p: abs((datetime.strptime(p["week"], "%Y-%m-%d") - target).days))
    return {"week": pick["week"], "month": _month(pick["week"]), "share": pick["share"], "graded": pick["graded"],
            "ready": pick["ready"], "change": round(points[-1]["share"] - pick["share"], 4)}


def headline(name: str, share: Optional[float], ready: int, graded: int, cmp: Optional[Dict[str, Any]],
             as_of: Optional[str], rubric: str) -> Dict[str, str]:
    if not graded:
        text = f"No {name} site in Morrow's list has been graded yet."
        return {"plain": text, "standard": text, "expert": text}
    trend_words = ""
    if cmp:
        if abs(cmp["change"]) < 0.0005:
            trend_words = f", the same as in {cmp['month']}"
        else:
            trend_words = f", {'up' if cmp['change'] > 0 else 'down'} from {pct(cmp['share'])} in {cmp['month']}"
    plain = f"{pct(share)} of the {name} sites Morrow watches are post-quantum ready{trend_words}."
    standard = (f"{pct(share)} ({ready} of {graded}) of the {name} sites Morrow watches are post-quantum ready "
                f"(grade A or B){trend_words}.")
    expert = (f"{name}: {ready}/{graded} graded A or B ({pct(share)}) under rubric {rubric}, as of {str(as_of)[:10]}"
              + (f"; {pct(cmp['share'])} in the week of {cmp['week']} (n={cmp['graded']})." if cmp else "; no earlier week to compare."))
    return {"plain": plain, "standard": standard, "expert": expert}


def _build() -> Dict[str, Any]:
    from services import league, not_ready, public_grade

    spec = league.load_spec()
    classifier = league.Classifier(spec)
    optouts = league._optout_entries()
    from services import public_check

    every = league.league_list(spec)
    kept = [d for d in every if not league._covered(d, optouts) and not public_check.opted_out(d)]
    rows = league._grade_rows(kept)
    misses = league._latest_misses(kept)
    measured = not_ready.methodology(None)["measured"]
    reports: Dict[str, Dict[str, Any]] = {}
    for s in spec["sectors"]:
        sid = s["id"]
        mine = [d for d in kept if classifier.classify(d) == sid]
        left_out = sum(1 for d in every if classifier.classify(d) == sid and d not in set(kept))
        sector_rows = {d: rows.get(d) or [] for d in mine}
        latest = {d: hs[-1] for d, hs in sector_rows.items() if hs}
        counts = {g: 0 for g in GRADES}
        for h in latest.values():
            counts[h["grade"]] = counts.get(h["grade"], 0) + 1
        graded = len(latest)
        ready = counts["A"] + counts["B"]
        pq = sum(1 for h in latest.values() if h.get("post_quantum"))
        unreachable = sum(1 for d in mine if d in misses and (d not in latest or misses[d]["scanned_at"] > latest[d]["scanned_at"]))
        never = sum(1 for d in mine if d not in latest and d not in misses)
        as_of = max((h["scanned_at"] for h in latest.values()), default=None)
        points = trend(sector_rows)
        cmp = comparison(points)
        share = round(ready / graded, 4) if graded else None
        reports[sid] = {
            "id": sid, "name": s["name"], "url": "/report/" + sid, "csv": "/api/public/report/" + sid + ".csv",
            "as_of": as_of, "rubric_version": public_grade.RUBRIC_VERSION,
            "sample": {"listed": len(mine), "graded": graded, "unreachable": unreachable, "not_graded_yet": never,
                       "opted_out_left_out": left_out},
            "ready": ready, "ready_share": share, "pq_key_exchange": pq,
            "grades": counts, "trend": points, "comparison": cmp,
            "headline": headline(s["name"], share, ready, graded, cmp, as_of, public_grade.RUBRIC_VERSION),
            "methodology": {
                "who": s.get("method") or "", "sources": list(s.get("sources") or []),
                "list": "The named organisations of this sector in backend/league/sectors.json: each entry is the main "
                        "public domain of an organisation named from a public source. Nothing is added from a crawl "
                        "or a guess.",
                "measured": measured,
                "ready": "Post-quantum ready means the newest grade is A or B: the server chose a hybrid post-quantum "
                         "key exchange (such as X25519MLKEM768) when one was offered.",
                "cadence": "Each site is re-graded at most once a week. The trend shows, for every week, each site's "
                           "newest grade as of that week's end.",
                "not_measured": list(NOT_MEASURED),
                "names": "No site is named in a report. Any single domain can be checked at /<domain>.",
            },
        }
    return {"sectors": reports, "order": [s["id"] for s in spec["sectors"]],
            "generated_at": public_grade.iso(public_grade.now_utc())}


def _built() -> Dict[str, Any]:
    key = _identity()
    hit = _cache.get(key)
    if not hit or time.monotonic() - hit[0] > CACHE_SECONDS:
        hit = (time.monotonic(), _build())
        _cache[key] = hit
    return hit[1]


def report(sector: str) -> Dict[str, Any]:
    built = _built()
    sid = str(sector or "").strip().lower()
    if sid not in built["sectors"]:
        raise ReportError(404, "There is no report for that sector. The sectors are: " + ", ".join(built["order"]) + ".")
    return dict(built["sectors"][sid], generated_at=built["generated_at"])


def index() -> Dict[str, Any]:
    built = _built()
    rows = []
    graded = ready = 0
    for sid in built["order"]:
        r = built["sectors"][sid]
        rows.append({k: r[k] for k in ("id", "name", "url", "csv", "as_of", "ready", "ready_share", "comparison")}
                    | {"graded": r["sample"]["graded"], "listed": r["sample"]["listed"],
                       "headline": r["headline"], "trend": [{"week": p["week"], "share": p["share"]} for p in r["trend"]]})
        graded += r["sample"]["graded"]
        ready += r["ready"]
    as_of = max((r["as_of"] for r in rows if r["as_of"]), default=None)
    share = round(ready / graded, 4) if graded else None
    lead = (f"{pct(share)} of the {graded} sites Morrow watches in {sum(1 for r in rows if r['graded'])} sectors are "
            "post-quantum ready." if graded else "No site in the sector lists has been graded on this server yet.")
    return {"title": "Sector reports", "sectors": rows, "graded": graded, "ready": ready, "ready_share": share,
            "as_of": as_of, "generated_at": built["generated_at"], "summary": lead}


def to_csv(r: Dict[str, Any]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(["sector", "week_start", "graded", "ready", "ready_share_percent"] + list(GRADES) + ["as_of", "rubric_version"])
    for p in r["trend"]:
        w.writerow([r["id"], p["week"], p["graded"], p["ready"], round(p["share"] * 100, 1)]
                   + [p["grades"].get(g, 0) for g in GRADES] + [r["as_of"] or "", r["rubric_version"]])
    return out.getvalue()
