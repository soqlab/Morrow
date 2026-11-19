"""Every public page speaks the front page's language (static/feel.css, the "One language" layer).

The front page's story set the shapes: the system font stack, rounded generous surfaces, pill
buttons, the type scale and the AA safe/warn colours (instrument.css tokens). feel.css is loaded on
every instrument view, the record and proof pages, the documents and the 404 page, and carries those
shapes to each of them. What is checked here, without a browser:
  - each kind of page has its surfaces rounded and its buttons as pills, from the shared tokens;
  - the language layer animates nothing and fixes no colour (tokens only), so both themes and
    reduced motion keep working exactly as before;
  - every page that carries the frame loads the same, current asset version.
"""

from __future__ import annotations

import pathlib
import re

from services import site_chrome

STATIC = pathlib.Path(__file__).parent / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _layer() -> str:
    feel = _read("feel.css")
    return feel[feel.index("One language for every public page"):]


def test_every_kind_of_page_gets_rounded_surfaces_and_pill_buttons():
    layer = _layer()
    for selector, radius in ((".ins .ch {", "var(--r-lg)"), (".ins .i-btn {", "var(--r-pill)"),
                             (".ins .i-field {", "var(--r-md)"), (".ins .rec .panel {", "var(--r-lg)"),
                             (".ins .rec .btn {", "var(--r-pill)"), (".ins.doc .btn {", "var(--r-pill)"),
                             (".oopsPage .oops {", "var(--r-xl)"), (".oopsPage .oopsBtn {", "var(--r-pill)"),
                             (".ins .i-pal {", "var(--r-lg)"), (".ins .grade {", "var(--r-xl)"),
                             (".i-theme, .ins .i-theme {", "var(--r-pill)")):
        start = layer.index(selector)
        rule = layer[start:layer.index("}", start)]
        assert radius in rule, (selector, rule)
    # The one action of a page is the safe colour, with its AA ink, everywhere.
    for selector in (".ins .i-btn.solid {", ".ins .rec .actions .btn:first-child {", ".ins.doc .btn.primary {", ".oopsPage .oopsBtn.pri {"):
        start = layer.index(selector)
        rule = layer[start:layer.index("}", start)]
        assert "var(--safe)" in rule and "var(--safe-ink)" in rule, selector
    # Labels and headings in the system sans, not the old mono.
    assert ".ins .ch-head { padding: 14px 20px; border-bottom: 1px solid var(--line); font: 600 12px var(--sans);" in layer
    assert ".ins .i-say::before, .ins .i-say::after { content: none; }" in layer


def test_the_language_layer_moves_nothing_and_reads_tokens_only():
    layer = re.sub(r"/\*.*?\*/", "", _layer(), flags=re.S)
    assert "animation" not in layer and "transition" not in layer and "@keyframes" not in layer
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", layer), "a fixed colour in the language layer"
    feel = _read("feel.css")
    assert feel.index("@media (prefers-reduced-motion: reduce)") < feel.index("One language for every public page")


def test_every_framed_page_loads_the_current_assets():
    assert site_chrome.ASSET_VERSION == "20261119-one"
    for name in ("instrument.html", "404.html", "legal.html", "terms.html", "privacy.html", "check-abuse.html"):
        body = _read(name)
        assert "/ui/feel.css?v=20261119-one" in body and "20261118-feel" not in body, name
