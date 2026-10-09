"""The platform admin panel's wiring.

This panel has no other automated coverage: it is plain HTML, CSS, and a script
served as static files, so nothing in the suite would notice if a redesign
orphaned half of it. The failure is silent in the worst way — the page still
renders, the panel is simply empty forever, and it looks like the platform has
no data rather than like a bug.

Two things are checked, both of which a restyle can break without any error:

  * every element id the script reaches for exists in the markup, and
  * every class the script emits has a rule in the stylesheet.

Neither is a style opinion. A dropped id means a dead panel; a dropped class
means status colour, or the pill that carries it, silently disappears.
"""

import pathlib
import re

import pytest

ADMIN = pathlib.Path(__file__).parent / "static_admin"


def _read(name):
    return (ADMIN / name).read_text(encoding="utf-8")


# The portal is split into plain deferred scripts (no build step): the original panels in
# index.js, plus the shared shell, charts and the analytics pages. Traffic Lens carries the same
# shell. Each page is checked against every script and stylesheet it actually loads.
PAGES = [
    ("index.html", ("index.js", "admin-charts.js", "admin-shell.js", "admin-views.js", "admin-alerts.js", "admin-support.js", "admin-auth.js"), ("index.css", "admin-shell.css", "admin-auth.css")),
    ("traffic.html", ("traffic.js", "admin-shell.js"), ("traffic.css", "admin-shell.css")),
]


def _read_all(names):
    return "\n".join(_read(name) for name in names)


@pytest.mark.parametrize(("html_name", "js_names", "css_names"), PAGES)
def test_every_id_the_script_reaches_for_exists_in_the_markup(html_name, js_names, css_names):
    html, js = _read(html_name), _read_all(js_names)
    declared = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', html))

    wanted = set(re.findall(r'getElementById\(\s*["\']([A-Za-z0-9_-]+)["\']', js))
    wanted |= set(re.findall(r'querySelector(?:All)?\(\s*["\']#([A-Za-z0-9_-]+)["\']', js))

    missing = sorted(wanted - declared)
    assert not missing, f"{js_names} reach for ids {missing}, which {html_name} does not define"


@pytest.mark.parametrize(("html_name", "js_names", "css_names"), PAGES)
def test_every_class_the_script_emits_has_a_style(html_name, js_names, css_names):
    js, css = _read_all(js_names), _read_all(css_names)

    emitted = set()
    for group in re.findall(r'class="([^"$]*)"', js):
        emitted.update(c for c in group.split() if c and not c.startswith("$"))

    # Strip comments first: this file's header lists the classes it is meant to
    # cover, and a class named only there would satisfy the check while every
    # rule for it had been deleted.
    rules = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    styled = set(re.findall(r"\.([A-Za-z][A-Za-z0-9_-]*)", rules))
    unstyled = sorted(emitted - styled)
    assert not unstyled, (
        f"{js_names} render classes {unstyled} that {css_names} do not define — "
        "those elements will paint as unstyled text"
    )


def test_the_panels_added_for_feedback_and_readiness_are_wired_end_to_end():
    """These three panels are the reason an operator opens this page at all."""
    html, js = _read("index.html"), _read("index.js")
    for element_id, loader in [
        ("feedbackBody", "loadFeedback"),
        ("gateBody", "loadGate"),
        ("trafficBody", "loadTraffic"),
    ]:
        assert f'id="{element_id}"' in html, f"{element_id} panel is gone from the markup"
        assert f"function {loader}" in js, f"{loader} is gone from the script"
        assert f'"{element_id}"' in js, f"{loader} no longer writes into {element_id}"
    assert "loadExtras()" in js, "the new panels are defined but never loaded"


def test_the_feedback_panel_calls_routes_the_server_serves():
    """A renamed route would leave the panel permanently showing its error state."""
    js = _read("index.js")
    app = (pathlib.Path(__file__).parent / "app.py").read_text(encoding="utf-8")
    for route in ["/platform/feedback", "/platform/go-live-gate", "/platform/traffic/summary"]:
        assert route in js, f"the panel no longer calls {route}"
        assert f'"{route}"' in app or f"'{route}'" in app, f"the server no longer serves {route}"
