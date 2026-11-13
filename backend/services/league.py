"""The quantum-readiness league: well-known sites by sector, each graded at most once a week.

The list
--------
Exactly the explicit ``domains`` of ``backend/league/sectors.json``, deduplicated (829 domains in
eight sectors when this was written; ``list_size`` in the API reports the live number). Each is the
main public domain of a named organisation of that sector. Nothing is added from a ranking, a
crawl or a guess, and the classifier never guesses either: an exact domain wins, then a
registry-reserved suffix rule (.gov, .edu, .ac.<cc>, .nhs.uk ...), and anything else is
"unclassified".

Grading
-------
``tick(max_domains)`` grades up to N due domains with services.public_grade.grade_one (the same
guarded probe as the public grade: SSRF guard with a pinned address, opt-outs, per-connection
timeouts) and stores successes with public_grade.store, so they also appear in
/api/public/history. A domain is due when its newest attempt -- a stored grade under the current
rubric or a recorded miss -- is older than seven days, or it has never been attempted. Failures go
to ``public_league_misses`` so the table can say "not reachable" rather than show nothing, and a
failure also waits a week. Opted-out domains (services.public_check.opted_out) are skipped and
never contacted. Every tick is recorded in ``public_league_runs``.

Polite by construction: at most four threads, each grading one domain at a time; each domain at
most once a week; one tick bounded to N domains (default 20). With the Celery beat entry
(every 15 minutes, ``MORROW_LEAGUE_SCAN``, default on; "0" turns it off) that is at most 80
domains an hour, so the whole list is refreshed in roughly half a day each week.

Self-hosters without a worker: ``python -m services.league --tick [--max N]`` (from backend/).

The table (``table()``) is built only from stored rows. There are no fixtures in this path.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

SECTORS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "league", "sectors.json")
UNCLASSIFIED = "unclassified"
REFRESH_DAYS = 7
MAX_THREADS = 4
DEFAULT_TICK = 20
SORTS = ("grade", "domain", "scanned")

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()
_TICK_LOCK = threading.Lock()
_spec_cache: Dict[str, Any] = {}


# ── sectors and the classifier ───────────────────────────────────────────────


def load_spec(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or SECTORS_PATH
    cached = _spec_cache.get(path)
    if cached is None:
        with open(path, encoding="utf-8") as handle:
            cached = json.load(handle)
        _spec_cache[path] = cached
    return cached


def _bare(domain: str) -> str:
    d = str(domain or "").strip().lower().rstrip(".")
    return d[4:] if d.startswith("www.") else d


class Classifier:
    """Exact domain first, then registry suffix rules; anything else is "unclassified"."""

    def __init__(self, spec: Dict[str, Any]):
        self.exact: Dict[str, str] = {}
        self.rules: List[Tuple[str, Any]] = []
        self.exclude = {_bare(d) for d in spec.get("exclude", [])}
        for sector in spec["sectors"]:
            for d in sector.get("domains", []):
                self.exact.setdefault(_bare(d), sector["id"])
            for suffix in sector.get("suffixes", []):
                self.rules.append((sector["id"], re.compile(r"(^|\.)" + re.escape(suffix.lower()) + "$")))
            for pattern in sector.get("suffix_patterns", []):
                self.rules.append((sector["id"], re.compile(pattern)))

    def classify(self, domain: str) -> str:
        d = _bare(domain)
        if not d or d in self.exclude:
            return UNCLASSIFIED
        if d in self.exact:
            return self.exact[d]
        for sector_id, rule in self.rules:
            if rule.search(d):
                return sector_id
        return UNCLASSIFIED


def league_list(spec: Optional[Dict[str, Any]] = None) -> List[str]:
    """Every explicit domain in sectors.json, in file order, deduplicated."""
    spec = spec or load_spec()
    seen, out = set(), []
    for sector in spec["sectors"]:
        for d in sector.get("domains", []):
            key = _bare(d)
            if key and key not in seen:
                seen.add(key)
                out.append(key)
    return out


# ── storage: public_league_misses, public_league_runs ────────────────────────


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def init_tables() -> None:
    """Create the league's two tables. No organization column: nothing here belongs to a tenant."""
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        from db_feature_store import feature_conn

        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS public_league_misses (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT NOT NULL,
                    scanned_at  TEXT NOT NULL,
                    error       TEXT NOT NULL,
                    detail      TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_public_league_misses_domain
                    ON public_league_misses (domain, scanned_at);
                CREATE TABLE IF NOT EXISTS public_league_runs (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at   TEXT NOT NULL,
                    finished_at  TEXT NOT NULL DEFAULT '',
                    graded       INTEGER NOT NULL DEFAULT 0,
                    failed       INTEGER NOT NULL DEFAULT 0,
                    skipped      INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


def _chunks(items: List[str], size: int = 400) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _grade_rows(domains: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Stored grades under the current rubric for these domains, oldest first per domain."""
    from db_feature_store import feature_conn
    from services import public_grade

    public_grade.init_tables()
    out: Dict[str, List[Dict[str, Any]]] = {d: [] for d in domains}
    with feature_conn() as conn:
        for chunk in _chunks(domains):
            marks = ",".join("?" for _ in chunk)
            rows = conn.execute(
                "SELECT domain, scanned_at, grade, key_exchange_group, post_quantum FROM public_grade_checks "  # nosec B608  # placeholders only
                f"WHERE rubric_version = ? AND domain IN ({marks}) ORDER BY scanned_at ASC, id ASC",
                (public_grade.RUBRIC_VERSION, *chunk)).fetchall()
            for r in rows:
                out.setdefault(str(r["domain"]), []).append({
                    "scanned_at": str(r["scanned_at"]), "grade": str(r["grade"]),
                    "group": str(r["key_exchange_group"] or ""), "post_quantum": bool(r["post_quantum"])})
    return out


def _latest_misses(domains: List[str]) -> Dict[str, Dict[str, str]]:
    from db_feature_store import feature_conn

    init_tables()
    out: Dict[str, Dict[str, str]] = {}
    with feature_conn() as conn:
        for chunk in _chunks(domains):
            marks = ",".join("?" for _ in chunk)
            rows = conn.execute(
                "SELECT domain, scanned_at, error FROM public_league_misses "  # nosec B608  # placeholders only
                f"WHERE domain IN ({marks}) ORDER BY scanned_at ASC, id ASC", tuple(chunk)).fetchall()
            for r in rows:
                out[str(r["domain"])] = {"scanned_at": str(r["scanned_at"]), "error": str(r["error"])}
    return out


def record_miss(domain: str, scanned_at: str, error: str, detail: str = "") -> None:
    from db_feature_store import feature_conn

    init_tables()
    with feature_conn() as conn:
        conn.execute("INSERT INTO public_league_misses (domain, scanned_at, error, detail) VALUES (?, ?, ?, ?)",
                     (str(domain)[:300], str(scanned_at), str(error or "error")[:64], str(detail or "")[:300]))
        conn.execute("DELETE FROM public_league_misses WHERE domain = ? AND scanned_at < ?",
                     (str(domain)[:300], str(scanned_at)))
        conn.commit()


def last_run() -> Optional[Dict[str, Any]]:
    from db_feature_store import feature_conn

    init_tables()
    with feature_conn() as conn:
        r = conn.execute("SELECT started_at, finished_at, graded, failed, skipped FROM public_league_runs "
                         "ORDER BY id DESC LIMIT 1").fetchone()
    if not r:
        return None
    return {"started_at": str(r["started_at"]), "finished_at": str(r["finished_at"] or "") or None,
            "graded": int(r["graded"]), "failed": int(r["failed"]), "skipped": int(r["skipped"])}


def _optout_entries() -> set:
    from services import public_check

    return public_check._optout_set()


def _covered(domain: str, entries: set) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[i:]) in entries for i in range(len(labels) - 1))


# ── the tick ─────────────────────────────────────────────────────────────────


def enabled() -> bool:
    return str(os.getenv("MORROW_LEAGUE_SCAN", "1") or "1").strip().lower() not in ("0", "false", "no", "off")


def due_domains(limit: int, now: Optional[Any] = None) -> List[str]:
    """Up to ``limit`` domains whose newest attempt is older than REFRESH_DAYS; never-tried first."""
    from services import public_grade

    domains = league_list()
    cutoff = public_grade.iso((now or public_grade.now_utc()) - timedelta(days=REFRESH_DAYS))
    grades = _grade_rows(domains)
    misses = _latest_misses(domains)
    candidates = []
    for order, d in enumerate(domains):
        attempts = [g["scanned_at"] for g in grades.get(d) or []]
        if d in misses:
            attempts.append(misses[d]["scanned_at"])
        newest = max(attempts) if attempts else ""
        if newest < cutoff:
            candidates.append((newest, order, d))
    candidates.sort()
    return [d for _, _, d in candidates[:max(0, int(limit))]]


def tick(max_domains: int = DEFAULT_TICK, threads: int = MAX_THREADS, timeout: float = 8.0) -> Dict[str, Any]:
    """Grade up to max_domains due domains. Returns the run record."""
    from db_feature_store import feature_conn
    from services import public_check, public_grade

    init_tables()
    if not _TICK_LOCK.acquire(blocking=False):
        return {"started_at": public_grade.iso(public_grade.now_utc()), "finished_at": None, "graded": 0,
                "failed": 0, "skipped": 0, "busy": True}
    try:
        started = public_grade.iso(public_grade.now_utc())
        limit = max(0, min(500, int(max_domains)))
        todo, skipped = [], 0
        for d in due_domains(limit * 2 + 10):
            if len(todo) >= limit:
                break
            if public_check.opted_out(d):
                skipped += 1
                continue
            todo.append(d)
        counts = {"graded": 0, "failed": 0}
        lock = threading.Lock()

        def work(domain: str) -> None:
            result = public_grade.grade_one(domain, timeout=timeout)
            if "error" in result or result.get("grade") not in public_grade.GRADES:
                try:
                    record_miss(domain, str(result.get("scanned_at") or started), str(result.get("error") or "error"),
                                str(result.get("detail") or ""))
                except Exception:
                    logger.warning("league: could not record the miss for %s", domain)
                with lock:
                    counts["failed"] += 1
                return
            try:
                public_grade.store(result)
                with lock:
                    counts["graded"] += 1
            except Exception:
                logger.warning("league: could not store the grade for %s", domain)
                with lock:
                    counts["failed"] += 1

        if todo:
            with ThreadPoolExecutor(max_workers=max(1, min(MAX_THREADS, int(threads)))) as pool:
                for _ in pool.map(work, todo):
                    pass
        finished = public_grade.iso(public_grade.now_utc())
        run = {"started_at": started, "finished_at": finished, "graded": counts["graded"],
               "failed": counts["failed"], "skipped": skipped}
        with feature_conn() as conn:
            conn.execute("INSERT INTO public_league_runs (started_at, finished_at, graded, failed, skipped) "
                         "VALUES (?, ?, ?, ?, ?)", (started, finished, run["graded"], run["failed"], skipped))
            conn.commit()
        _table_cache.clear()
        return run
    finally:
        _TICK_LOCK.release()


# ── the table ────────────────────────────────────────────────────────────────

_table_cache: Dict[str, Any] = {}
_TABLE_TTL = 60.0


def _row_for(domain: str, sector: str, history: List[Dict[str, Any]], miss: Optional[Dict[str, str]]) -> Dict[str, Any]:
    latest = history[-1] if history else None
    previous_grade, changed_at = None, None
    if latest:
        # Walk back over the run of identical grades that ends at the latest check.
        i = len(history) - 1
        while i > 0 and history[i - 1]["grade"] == latest["grade"]:
            i -= 1
        if i > 0:
            previous_grade = history[i - 1]["grade"]
            changed_at = history[i]["scanned_at"]
    miss_error = None
    if miss and (not latest or miss["scanned_at"] > latest["scanned_at"]):
        miss_error = miss["error"]
    return {
        "domain": domain,
        "sector": sector,
        "grade": latest["grade"] if latest else None,
        "previous_grade": previous_grade,
        "changed_at": changed_at,
        "group": (latest["group"] or None) if latest else None,
        "post_quantum": latest["post_quantum"] if latest else None,
        "scanned_at": latest["scanned_at"] if latest else None,
        "miss": miss_error,
    }


def _build() -> Dict[str, Any]:
    from services import public_grade

    spec = load_spec()
    classifier = Classifier(spec)
    entries = _optout_entries()
    domains = [d for d in league_list(spec) if not _covered(d, entries)]
    grades = _grade_rows(domains)
    misses = _latest_misses(domains)
    rows = [_row_for(d, classifier.classify(d), grades.get(d) or [], misses.get(d)) for d in domains]
    sectors = []
    for s in spec["sectors"]:
        mine = [r for r in rows if r["sector"] == s["id"]]
        graded = [r for r in mine if r["grade"]]
        counts = {g: 0 for g in public_grade.GRADES}
        for r in graded:
            counts[r["grade"]] = counts.get(r["grade"], 0) + 1
        sectors.append({
            "id": s["id"], "name": s["name"], "method": s.get("method", ""), "sources": list(s.get("sources", [])),
            "count": len(mine), "graded": len(graded), "grades": counts,
            "pq_share": round(sum(1 for r in graded if r["post_quantum"]) / len(graded), 4) if graded else None,
        })
    return {"rows": rows, "sectors": sectors, "list_size": len(domains),
            "graded": sum(1 for r in rows if r["grade"]), "generated_at": public_grade.iso(public_grade.now_utc())}


def _cached_build() -> Dict[str, Any]:
    key = _db_identity()
    hit = _table_cache.get(key)
    if hit and time.monotonic() - hit[0] < _TABLE_TTL:
        return hit[1]
    built = _build()
    _table_cache[key] = (time.monotonic(), built)
    return built


def table(sector: str = "", q: str = "", sort: str = "grade", direction: str = "asc",
          limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    from services import public_grade

    built = _cached_build()
    rows = built["rows"]
    sector = str(sector or "").strip().lower()
    if sector:
        rows = [r for r in rows if r["sector"] == sector]
    needle = str(q or "").strip().lower()
    if needle:
        rows = [r for r in rows if needle in r["domain"]]
    sort = sort if sort in SORTS else "grade"
    reverse = str(direction or "").lower() == "desc"
    if sort == "domain":
        rows = sorted(rows, key=lambda r: r["domain"], reverse=reverse)
    elif sort == "scanned":
        # Never-graded rows sort last in either direction.
        dated = sorted((r for r in rows if r["scanned_at"]), key=lambda r: (r["scanned_at"], r["domain"]),
                       reverse=reverse)
        rows = dated + sorted((r for r in rows if not r["scanned_at"]), key=lambda r: r["domain"])
    else:
        order = {g: i for i, g in enumerate(public_grade.GRADES)}
        graded = sorted((r for r in rows if r["grade"]),
                        key=lambda r: (order.get(r["grade"], 99) * (-1 if reverse else 1), r["domain"]))
        rows = graded + sorted((r for r in rows if not r["grade"]), key=lambda r: r["domain"])
    total = len(rows)
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    return {
        "generated_at": built["generated_at"],
        "rubric_version": public_grade.RUBRIC_VERSION,
        "list_size": built["list_size"],
        "graded": built["graded"],
        "sectors": built["sectors"],
        "rows": [dict(r) for r in rows[offset:offset + limit]],
        "total": total,
        "last_run": last_run(),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m services.league",
                                     description="Grade the league's due domains (each at most once a week).")
    parser.add_argument("--tick", action="store_true", help="grade up to --max due domains and record the run")
    parser.add_argument("--max", type=int, default=DEFAULT_TICK, help=f"domains per tick (default {DEFAULT_TICK})")
    parser.add_argument("--list", action="store_true", help="print the league list (one domain per line)")
    args = parser.parse_args(argv)
    if args.list:
        sys.stdout.write("\n".join(league_list()) + "\n")
        return 0
    if not args.tick:
        parser.error("give --tick (or --list)")
    print(json.dumps(tick(args.max), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
