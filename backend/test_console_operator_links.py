"""The customer console never links the vendor admin portal to customers.

A link to /vendor-admin/ may appear only (a) inside a NAV entry marked operator: true (the operator-only
Administrator Guide), or (b) inside a template branch guarded by S.operator, the flag verifyOperator() sets once
the server has accepted this tab's platform key.
"""

import pathlib
import re

import pytest

STATIC = pathlib.Path(__file__).resolve().parent / "static" / "index.html"
FRONTEND = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "index.html"


def _operator_entry_spans(html):
    """(start, end) of every NAV entry marked operator: true, up to the next entry or the end of its group."""
    spans = []
    for match in re.finditer(r'\{ id: "[^"]+",[^\n]*operator: true', html):
        nxt = re.compile(r"\n\s*\{ id: \"|\n\s*\]\},").search(html, match.end())
        spans.append((match.start(), nxt.start() if nxt else len(html)))
    return spans


def _guarded_by_operator(html, index):
    """True when index sits inside `${S.operator ? `...` : ""}` (template-literal nesting counted)."""
    guard = html.rfind("${S.operator ?", 0, index)
    if guard < 0 or index - guard > 600:
        return False
    close = html.find(': ""}', guard)
    return close > index


def test_vendor_admin_links_are_operator_only():
    html = STATIC.read_text(encoding="utf-8")
    spans = _operator_entry_spans(html)
    assert spans, "the operator-only Administrator Guide entry is missing"
    offenders = []
    for match in re.finditer(r"/vendor-admin", html):
        i = match.start()
        if any(a <= i < b for a, b in spans) or _guarded_by_operator(html, i):
            continue
        offenders.append(html[max(0, i - 160):i + 40].replace("\n", " "))
    assert not offenders, "customer-visible /vendor-admin reference(s):\n" + "\n".join(offenders)


def test_administration_banner_checks_the_operator_before_rendering():
    html = STATIC.read_text(encoding="utf-8")
    view = html[html.index("VIEWS.admin = async"):]
    view = view[:view.index("host.innerHTML")]
    assert "await verifyOperator()" in view


@pytest.mark.parametrize("path", [STATIC, FRONTEND])
def test_console_copies_are_identical(path):
    assert path.read_bytes() == STATIC.read_bytes()
