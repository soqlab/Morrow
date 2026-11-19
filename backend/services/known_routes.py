"""Does any route answer this path? Asked by the auth gate before it answers 401.

A signed-out visitor who mistypes an address used to get ``401 missing bearer token`` for a page
that does not exist, because the gate ran before the router could say "not found". The gate now
asks :func:`exists` first: a path that no route could ever answer gets the 404 (the page for a
browser, JSON for an API client), and every path a route could answer gets the 401 exactly as
before.

Nothing is executed to find out. The route table is read once (paths only, through FastAPI's own
``iter_route_contexts``, which also walks included routers) and compared as text.

The comparison leans towards "it exists" wherever it could be wrong, because that is the safe
direction: a false "exists" is the old 401, a false "missing" is a 404 that still serves nothing.
So a path counts as known when any of its spellings matches a route, ignoring the method: the raw
path, the canonical form (decoded, ``..`` resolved, ``//`` collapsed, every ``/v1`` stripped, see
services/route_paths.py), the canonical form lowercased, and each with and without a trailing
slash. If the table holds a route whose shape cannot be read, every path counts as known.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from services import route_paths

try:  # FastAPI 0.14x keeps included routers behind one wrapper; this walks into them.
    from fastapi.routing import iter_route_contexts as _iter_route_contexts
except ImportError:  # pragma: no cover - older FastAPI copies routes into app.routes directly
    _iter_route_contexts = None

from starlette.routing import Mount, compile_path

#: (literal paths, compiled templates, mount prefixes), or None when a route could not be read.
_Table = Optional[Tuple[frozenset, List[Any], Tuple[str, ...]]]
_CACHE: Dict[Tuple[int, Any], Tuple[int, _Table]] = {}


def _contexts(app: Any):
    routes = list(getattr(app, "routes", []) or [])
    if _iter_route_contexts is None:  # pragma: no cover
        return routes
    return list(_iter_route_contexts(routes))


def _build(app: Any, ignore: Optional[Callable[[str, Any], bool]]) -> _Table:
    literals, templates, mounts = set(), [], []
    for ctx in _contexts(app):
        original = getattr(ctx, "original_route", ctx)
        path = getattr(ctx, "path", None)
        if not isinstance(path, str):
            return None  # a route this module cannot read: never call anything unknown
        if ignore is not None and ignore(path, getattr(ctx, "endpoint", None)):
            continue
        if isinstance(original, Mount):
            mounts.append(path.rstrip("/") or "/")
        elif "{" in path:
            templates.append(compile_path(path)[0])
        else:
            literals.add(path)
    return frozenset(literals), templates, tuple(mounts)


def _table(app: Any, ignore: Optional[Callable[[str, Any], bool]]) -> _Table:
    size = len(getattr(app, "routes", []) or [])
    key = (id(app), ignore)
    cached = _CACHE.get(key)
    if cached is not None and cached[0] == size:
        return cached[1]
    try:
        table = _build(app, ignore)
    except Exception:
        table = None
    _CACHE[key] = (size, table)
    return table


def spellings(path: str) -> set:
    """Every form of ``path`` that some part of the stack could route to the same handler."""
    raw = str(path or "/") or "/"
    canonical = route_paths.canonical_path(raw)
    forms = {raw, route_paths.strip_version_prefixes(raw), canonical, canonical.lower()}
    out = set()
    for form in forms:
        bare = form.rstrip("/") or "/"
        out.update({form, bare, bare if bare == "/" else bare + "/"})
    return out


def exists(app: Any, path: str, ignore: Optional[Callable[[str, Any], bool]] = None) -> bool:
    """True when a route could answer ``path`` (any method); False only when none could."""
    table = _table(app, ignore)
    if table is None:
        return True
    literals, templates, mounts = table
    for candidate in spellings(path):
        if candidate in literals:
            return True
        if any(candidate == m or candidate.startswith(m.rstrip("/") + "/") for m in mounts):
            return True
        if any(regex.match(candidate) for regex in templates):
            return True
    return False
