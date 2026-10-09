"""One canonical form for a request path, for every route guard in the process.

Why this module exists
----------------------
The API-key denylist, the support-session allow-list and the ``/v1`` alias middleware each used to
normalise the path themselves, and each of them stripped exactly one ``/v1`` prefix. The app
registers ``/v1/admin/...`` aliases next to ``/admin/...``, so ``/v1/v1/admin/audit-log`` passed the
denylist as the unblocked-looking ``/v1/admin/audit-log`` and was then routed by the middleware to
the real handler. An organization API key -- the one credential the design says can never reach
``/admin/*`` -- reached all of it.

A guard is only as good as the string it compares, so the string is produced here, once:

  * percent-encoded separators are decoded (``/%2e%2e/``, ``%2f``), repeatedly and boundedly, so an
    encoded separator cannot hide a segment from a prefix test;
  * backslashes become slashes and NUL/control bytes are dropped;
  * empty segments (``//``) and ``.`` segments are removed and ``..`` segments are resolved, so
    ``/ui/../admin`` and ``/./admin`` and ``//admin`` are all ``/admin``;
  * a trailing slash is removed (``/admin/`` is ``/admin``);
  * **every** leading ``/v1`` version prefix is stripped, not just the first, so any number of them
    collapses to the same route.

:func:`canonical_path` keeps the original case, because the route table is case-sensitive and the
support allow-list matches route templates against it. :func:`guard_path` lowercases on top of that
and is what a prefix, deny-list or allow-list comparison should use, so ``/ADMIN/orgs`` cannot slip
past a check written in lower case.

Normalising here never *widens* what the router accepts: the router still matches the path Starlette
was given. It only makes the guards see every spelling that could reach a protected handler.
"""

from __future__ import annotations

from urllib.parse import unquote

#: Version prefixes collapsed by the guards (and by app.api_version_prefix).
VERSION_PREFIX = "/v1"

#: Bound on percent-decoding so a deeply nested encoding cannot spin here.
_MAX_DECODE_ROUNDS = 4
#: Bound on version-prefix stripping; far above anything a route table could use.
_MAX_VERSION_PREFIXES = 16


def _decode(path: str) -> str:
    """Percent-decode until the value stops changing (bounded)."""
    seen = path
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(seen)
        if decoded == seen:
            return seen
        seen = decoded
    return seen


def strip_version_prefixes(path: str) -> str:
    """Remove every leading ``/v1`` from an already-shaped path. Case-insensitive."""
    route = str(path or "/")
    for _ in range(_MAX_VERSION_PREFIXES):
        lowered = route.lower()
        if lowered == VERSION_PREFIX:
            route = "/"
        elif lowered.startswith(VERSION_PREFIX + "/"):
            route = route[len(VERSION_PREFIX):]
        else:
            break
    return route or "/"


def canonical_path(path: str) -> str:
    """The canonical spelling of a request path, with case preserved."""
    route = str(path or "/")
    route = route.split("#", 1)[0].split("?", 1)[0]
    route = _decode(route)
    route = route.replace("\\", "/")
    route = "".join(ch for ch in route if ch >= " " and ch != "\x7f")
    segments: list[str] = []
    for part in route.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if segments:
                segments.pop()
            continue
        segments.append(part)
    route = "/" + "/".join(segments)
    return strip_version_prefixes(route)


def guard_path(path: str) -> str:
    """:func:`canonical_path` lowercased: what a prefix or allow/deny test compares against."""
    return canonical_path(path).lower()


def has_prefix(path: str, prefixes) -> bool:
    """True when the canonical, lowercased path is, or sits under, one of ``prefixes``."""
    route = guard_path(path)
    for raw in prefixes:
        prefix = str(raw or "").lower().rstrip("/")
        if not prefix:
            continue
        if route == prefix or route.startswith(prefix + "/"):
            return True
    return False
