"""Nothing in the published tree may point at a file that is not in it.

This exists because of a real break. Preparing the open-source release moved the commercial
collateral -- pricing, the pilot offer, the DPA template, the launch pack -- into a private
repository, and `scripts/launch-collateral-check.ps1` went with them because it read those
documents. Four files left behind still called it, so `market-ready-check.ps1` and
`prod-handoff.ps1` were broken in the published repository: they failed at the exact moment you
would run them, which is just before a launch.

A clone is the only thing a stranger gets. A reference that resolves on the author's laptop and
nowhere else is not a small untidiness -- it is the first thing that makes someone close the tab.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Where a reference may point. Anything outside this is a path into somebody's machine.
SEARCH_DIRS = ("scripts", "docs", ".github")
SEARCH_SUFFIXES = {".ps1", ".sh", ".py", ".md", ".yml", ".yaml"}

#: Referenced paths that are produced at runtime rather than committed, or are examples.
IGNORED = {
    # Output directories a script creates on its first run.
    "reports",
    # The private sibling repository, named on purpose so an operator knows where the rest went.
    "../morrow-private",
}

#: (document, reference) pairs that look like paths into this repository and are not. Each one is
#: listed individually rather than excluding a whole file, so a genuinely dead link in the same
#: document still fails. Deliberately not "anything that was ever in git history": the break this
#: test was written for -- scripts/launch-collateral-check.ps1 -- was in history too, and such a
#: rule would have let it through.
IGNORED_PAIRS = {
    # QUANTUM_PLATFORM_QA.md describes the contents of a separate demo target repository, not of
    # this one: the same list names config/crypto-config.java and config/nginx-*.conf.
    ("docs/QUANTUM_PLATFORM_QA.md", "scripts/DEMO_FLOW.md"),
    # A git command for recovering a document that was moved to the private repository. The path
    # is correct for the history it searches, which is the point of the sentence.
    ("docs/OPEN_SOURCE_READINESS.md", "docs/PRICING_AND_PACKAGING.md"),
}

#: scripts/foo.ps1, scripts\foo.ps1, docs/BAR.md -- in a command line, a link, or prose.
_REFERENCE = re.compile(
    r"(?<![\w./\\-])((?:scripts|docs|deploy|infra|examples|backend/services|backend/routers)"
    r"[/\\][\w./\\-]+\.(?:ps1|sh|py|md|yml|yaml|json|html|css|js|sql))"
)


def _candidate_files():
    for name in SEARCH_DIRS:
        base = REPO / name
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SEARCH_SUFFIXES:
                yield path


def _references(path: pathlib.Path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - unreadable file is its own problem
        return
    for match in _REFERENCE.finditer(text):
        raw = match.group(1).replace("\\", "/")
        # A trailing punctuation mark from prose is not part of the path.
        raw = raw.rstrip(".,;:)")
        if raw in IGNORED or any(raw.startswith(prefix + "/") for prefix in IGNORED):
            continue
        yield raw


@pytest.mark.parametrize("source", sorted(_candidate_files()), ids=lambda p: str(p.relative_to(REPO)))
def test_every_referenced_repository_file_exists(source):
    relative = source.relative_to(REPO).as_posix()
    missing = sorted({
        reference for reference in _references(source)
        if not (REPO / reference).exists()
        and (relative, reference) not in IGNORED_PAIRS
    })
    assert not missing, (
        f"{source.relative_to(REPO)} points at files that are not in this repository: "
        f"{', '.join(missing)}. Either restore them, or stop referencing them -- a clone is all "
        "anyone else gets."
    )
