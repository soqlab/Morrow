"""Which code is this server running? Served at GET /api/public/build.

The commit comes from the environment only, never from a guess: the first of
``MORROW_GIT_COMMIT`` (set it yourself when you build an image), ``RENDER_GIT_COMMIT`` (Render sets
it for every deploy), ``SOURCE_COMMIT`` and ``GIT_COMMIT`` (common CI conventions) that is set. It
must be a 7-40 character lowercase hex SHA; if the first set variable holds anything else the
commit is reported as null (the later variables are not consulted, so a mistyped override never
silently yields some other value), and a page or a verifier says "unknown" instead.

With a commit, anyone can check the running pages against the public repository:
scripts/verify-deploy.py compares the signed page manifest (/api/public/manifest) with
``git show <commit>:backend/static/<file>``.
"""

from __future__ import annotations

import os
import platform
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

REPOSITORY = "https://github.com/soqlab/Morrow"
COMMIT_ENV_VARS = ("MORROW_GIT_COMMIT", "RENDER_GIT_COMMIT", "SOURCE_COMMIT", "GIT_COMMIT")
_SHA = re.compile(r"^[0-9a-f]{7,40}$")
STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def commit_and_source() -> Tuple[Optional[str], Optional[str]]:
    """(sha, env var name) from the first set variable when it holds a valid SHA, else (None, None)."""
    for name in COMMIT_ENV_VARS:
        value = str(os.getenv(name, "") or "").strip()
        if value:
            return (value, name) if _SHA.match(value) else (None, None)
    return None, None


def commit() -> Optional[str]:
    return commit_and_source()[0]


def info() -> Dict[str, Any]:
    from services.public_grade import RUBRIC_VERSION

    sha, source = commit_and_source()
    return {
        "commit": sha,
        "commit_short": sha[:12] if sha else None,
        "source": source,
        "repository": REPOSITORY,
        "commit_url": f"{REPOSITORY}/commit/{sha}" if sha else None,
        "started_at": STARTED_AT,
        "rubric_version": RUBRIC_VERSION,
        "python": platform.python_version(),
    }
