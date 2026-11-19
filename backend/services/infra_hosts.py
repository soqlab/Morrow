"""Which popular host names are plumbing rather than sites, for the front page's rows of names.

The Tranco list ranks names by how often they are looked up, so CDN, cloud API, ad and tracking
hosts sit beside the sites people know (fbcdn.net next to facebook.com). The front page's two rows
of names ("Who's ready. Who isn't.") leave those out. The list is data, not code:
``data/infrastructure_hosts.json``, grouped by kind, each entry matching itself and every name
under it.

This only shapes the rows on "/". The full lists (/league, /api/public/not-ready and
/api/public/checked-safe without ``hide_infra``) are unchanged, their counts are unchanged, and any
host here can still be checked by typing it.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Dict, FrozenSet, List

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "infrastructure_hosts.json")


@lru_cache(maxsize=1)
def _load() -> Dict[str, List[str]]:
    # A missing or unreadable list must never break the lists it filters: the rows then show every
    # name, as they did before the list existed, and the problem is logged.
    try:
        with open(PATH, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        logging.getLogger(__name__).warning("infrastructure host list not readable at %s; rows are not filtered", PATH)
        return {}
    return {str(k): [str(h).strip().lower().rstrip(".") for h in v if str(h).strip()]
            for k, v in (payload.get("categories") or {}).items()}


def categories() -> Dict[str, List[str]]:
    return {k: list(v) for k, v in _load().items()}


@lru_cache(maxsize=1)
def hosts() -> FrozenSet[str]:
    return frozenset(h for group in _load().values() for h in group)


def is_infrastructure(domain: str) -> bool:
    """True when ``domain`` is a listed host or a name under one (a.b.fastly.net under fastly.net)."""
    name = str(domain or "").strip().lower().rstrip(".")
    if not name:
        return False
    listed = hosts()
    labels = name.split(".")
    return any(".".join(labels[i:]) in listed for i in range(len(labels)))
