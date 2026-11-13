"""The Tranco top-sites list, the only source of domains for the public "Not yet post-quantum" list.

Tranco (https://tranco-list.eu) is a research-oriented ranking of popular sites that averages
several providers over 30 days and is hardened against manipulation. Cite it as: Le Pochat et al.,
"Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019.

Why only Tranco: the named list must hold large public sites, never a private individual's domain
and never a domain someone typed into the checker. The top N entries of the latest list (N =
``MORROW_LEAGUE_TRANCO_SIZE``, default 10000; 0 switches the source off) are stored in
``public_tranco_domains`` and refreshed when they are older than a week, from the league tick.

Grading them is the league tick's job (services/league.py): each listed domain at most once a
week, at most ``MORROW_LEAGUE_TICK_MAX`` per tick. 10,000 domains in a week need roughly 60 per
15-minute tick; at the default of 20 a full pass takes about three weeks.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn

API = "https://tranco-list.eu/api/lists/date/latest"
DOWNLOAD = "https://tranco-list.eu/download/{list_id}/{size}"
USER_AGENT = "SOQLAB-Morrow-League/1 (+https://morrow.soqlab.com/league)"
CITATION = ('Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", '
            "NDSS 2019. https://tranco-list.eu")
REFRESH_DAYS = 7
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS public_tranco_domains (
        domain TEXT PRIMARY KEY,
        rank INTEGER NOT NULL,
        list_id TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    )
    """,
)
_ready = ""
_lock = threading.Lock()


def size() -> int:
    try:
        return max(0, min(100000, int(os.getenv("MORROW_LEAGUE_TRANCO_SIZE", "10000") or 10000)))
    except ValueError:
        return 10000


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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse(text: str, limit: int) -> List[str]:
    out, seen = [], set()
    for rec in csv.reader(io.StringIO(text)):
        if len(rec) < 2:
            continue
        d = rec[1].strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(d) or d in seen:
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= limit:
            break
    return out


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response:  # nosec B310  # fixed https URL
        return response.read()


def store(domains: List[str], list_id: str) -> int:
    init_tables()
    stamp = _now().strftime("%Y-%m-%dT%H:%M:%SZ")
    with feature_conn() as conn:
        conn.execute("DELETE FROM public_tranco_domains")
        for rank, domain in enumerate(domains, start=1):
            conn.execute("INSERT INTO public_tranco_domains (domain, rank, list_id, fetched_at) VALUES (?, ?, ?, ?)",
                         (domain, rank, str(list_id), stamp))
        conn.commit()
    return len(domains)


def meta() -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT list_id, fetched_at, COUNT(*) AS n FROM public_tranco_domains "
                           "GROUP BY list_id, fetched_at ORDER BY fetched_at DESC LIMIT 1").fetchone()
    return {"list_id": row["list_id"], "fetched_at": row["fetched_at"], "count": int(row["n"])} if row else None


def refresh_if_stale(fetch=_fetch) -> Optional[Dict[str, Any]]:
    """Download the latest list when the stored one is missing or older than a week."""
    n = size()
    if not n:
        return None
    current = meta()
    if current:
        fetched = datetime.strptime(current["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if _now() - fetched < timedelta(days=REFRESH_DAYS):
            return current
    info = json.loads(fetch(API))
    if not info.get("available") or info.get("failed") or not info.get("list_id"):
        return current
    domains = parse(fetch(DOWNLOAD.format(list_id=info["list_id"], size=n)).decode("utf-8"), n)
    if domains:
        store(domains, info["list_id"])
    return meta()


def domains() -> List[str]:
    if not size():
        return []
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT domain FROM public_tranco_domains ORDER BY rank").fetchall()
    return [str(r["domain"]) for r in rows]


def contains(domain: str) -> bool:
    init_tables()
    with feature_conn() as conn:
        return conn.execute("SELECT 1 FROM public_tranco_domains WHERE domain = ?", (domain,)).fetchone() is not None
