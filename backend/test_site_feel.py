"""Every public page shares the front page's frame and feel (services/site_chrome.py, static/feel.*).

What is checked here, without a browser:
  - one header and one footer: every page carries services/site_chrome.py's, byte for byte;
  - both themes: every page loads instrument.css (dark and light tokens) and none loads the old
    dark-only public.css; the record sheet reads tokens only, never a fixed colour;
  - nothing loops: no stylesheet of these pages has an infinite animation, feel.js has no timer
    that repeats; and the reduced-motion block is there to stop the rest;
  - without JavaScript the server-rendered pages are complete, and every control that needs
    script (the theme switch, the copy buttons) is hidden until feel.js shows it; /plain stays plain;
  - the record's ETag carries the page version, so a redesign is not answered with 304.
scripts/motion-smoke.js and scripts/instrument-smoke.js check the same promises in a real browser.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from fastapi.testclient import TestClient

from services import make_safe_page, registry_page, site_chrome
from services import public_check as _check

STATIC = pathlib.Path(__file__).parent / "static"
DOCUMENTS = ("terms.html", "privacy.html", "dpa.html", "security.html", "support.html", "data-boundary.html",
             "check-terms.html", "check-acceptable-use.html", "check-privacy.html", "check-abuse.html",
             "airlock-deployment.html", "enterprise-admin.html", "ai-trust.html", "legal.html", "404.html")
#: The sheets the public pages load. make-safe-done.css is left out on purpose: its one repeating
#: pulse marks a step while it is running and stops when the step ends (motion-smoke checks idle pages).
SHEETS = ("instrument.css", "feel.css", "registry.css", "doc.css", "oops.css", "make-safe.css",
          "instrument-board.css", "instrument-guided.css", "instrument-threat.css", "paste.css",
          "preflight.css")


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _record() -> dict:
    return {"domain": "example.com", "posture": _check.POSTURE_HYBRID, "observation_id": 7, "observations": 3,
            "observed_at": "2026-11-18T10:00:00Z", "last_seen_at": "2026-11-18T10:00:00Z",
            "first_seen_at": "2026-11-01T10:00:00Z",
            "result": {"verdict": {"headline": "Partly protected", "explanation": "A hybrid key exchange."},
                       "observed": {"reachable": True, "tls_version": "TLSv1.3"}}}


def _proof(safe: bool = True) -> str:
    doc = {"domain": "example.com", "status": "quantum_safe" if safe else "lapsed", "safe_since": "2026-11-15T12:00:00Z",
           "key_exchange": "X25519MLKEM768", "lapsed_at": None if safe else "2026-11-17T12:00:00Z",
           "statement": "example.com has negotiated post-quantum key exchange.", "method": "m", "owner": {},
           "signing_context": "morrow.quantum-safe-proof.v1"}
    return make_safe_page.render_proof({"document": doc, "signatures": [{"alg": "Ed25519"}, {"alg": "ML-DSA-65"}]},
                                       "https://morrow.test")


def _server_pages() -> dict:
    return {
        "record": registry_page.render_record(_record(), [], "https://morrow.test"),
        "missing": registry_page.render_missing("example.com", "https://morrow.test"),
        "graded": registry_page.render_missing("example.com", "https://morrow.test",
                                               {"grade": "B", "post_quantum": True, "scanned_at": "2026-11-18T10:00:00Z"}),
        "refused": registry_page.render_refused("example.com", "example.com", "https://morrow.test"),
        "proof": _proof(True),
        "lapsed": _proof(False),
        "no-proof": make_safe_page.render_missing("example.com", "https://morrow.test", "not_safe_yet"),
    }


def test_every_public_page_wears_the_shared_header_footer_and_both_themes():
    pages = {name: _read(name) for name in DOCUMENTS}
    pages.update({f"/r {k}": v for k, v in _server_pages().items()})
    for name, body in pages.items():
        assert site_chrome.HEADER in body, f"{name}: not the shared header"
        assert site_chrome.FOOTER in body, f"{name}: not the shared footer"
        for href in site_chrome.STYLES:
            assert href in body, f"{name}: does not load {href}"
        assert f'<script src="{site_chrome.SCRIPT}"></script>' in body.split("</head>")[0], name
        assert "/ui/public.css" not in body, f"{name}: still loads the dark-only sheet"
        assert '<body class="ins' in body, name
    # The instrument views: the same switch in the same header, the same footer links in the same order.
    ins = _read("instrument.html")
    assert site_chrome.THEME_TOGGLE in ins.split("</header>")[0]
    assert site_chrome.FOOTER_LINKS_HTML in ins.split('<footer class="i-foot">')[1]
    assert "/ui/feel.css" in ins and "/ui/feel.js" in ins
    # Both themes come from the shared tokens: the device's setting, and the switch's choice either way.
    tokens = _read("instrument.css")
    assert '@media (prefers-color-scheme: light)' in tokens
    assert ':root[data-theme="light"]' in tokens and ':root:not([data-theme="dark"])' in tokens
    # The record's own sheet reads tokens only, so it cannot be stuck in one theme.
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", _read("registry.css")), "registry.css has a fixed colour"


def test_nothing_animates_forever_and_reduced_motion_stops_the_rest():
    for name in SHEETS:
        rules = re.sub(r"/\*.*?\*/", "", _read(name), flags=re.S)
        assert not re.search(r"\binfinite\b", rules), f"{name} has an animation that never ends"
    for name in ("feel.css", "registry.css", "instrument.css", "instrument-board.css"):
        assert "@media (prefers-reduced-motion: reduce)" in _read(name), name
    feel = _read("feel.css")
    reduced = feel[feel.index("@media (prefers-reduced-motion: reduce)"):]
    for part in (".i-table tbody tr", ".rec .seal", ".is-copied", ".bar .seg", "transform: none"):
        assert part in reduced, f"reduced motion does not stop {part}"
    script = _read("feel.js")
    assert "setInterval" not in script, "feel.js must not run a repeating timer"
    assert "prefers-reduced-motion: reduce" in script, "count-ups must show the value straight away"
    # Each animation in the feel layer runs a counted number of times.
    for decl in re.findall(r"animation:\s*([^;]+);", feel + _read("registry.css")):
        if decl.strip() != "none" and "none !important" not in decl:
            assert re.search(r"\s1(\s|$)", decl), f"animation without a count: {decl}"


def test_server_rendered_pages_are_complete_without_javascript():
    for name, body in _server_pages().items():
        head, _, rest = body.partition("</head>")
        assert "<script" not in rest, f"{name}: script in the body"
        assert "style=" not in body and "onclick" not in body, name
        # A control that needs script is hidden until feel.js shows it.
        for tag in re.findall(r"<button[^>]*>", rest):
            assert " hidden" in tag or 'id="proof-verify"' in tag, f"{name}: a visible button that needs script: {tag}"
    record = _server_pages()["record"]
    assert "Partly protected" in record and "A hybrid key exchange." in record, "the verdict is in the HTML"
    assert '<a class="btn" href="/example.com#watch">Watch this domain</a>' in record
    assert 'data-seen-key="example.com"' in record and 'data-seen-label="hybrid' in record.lower()
    assert '<p class="feel-since" id="feel-since" role="status" hidden></p>' in record
    past = registry_page.render_record(_record(), [], "https://morrow.test", observation=_record())
    assert "data-seen-key" not in past and "#watch" not in past, "a past observation is not compared or watched"
    assert 'data-seen-key' not in _server_pages()["missing"], "nothing to compare before any measurement"
    proof = _server_pages()["proof"]
    assert '<div class="seal" data-state="safe">' in proof and "X25519MLKEM768" in proof
    assert "Quantum-safe since 2026-11-15" in proof
    assert '<div class="seal" data-state="lapsed">' in _server_pages()["lapsed"]


def test_plain_stays_plain_and_documents_render_without_script():
    import app as module

    client = TestClient(module.app)
    plain = client.get("/plain")
    assert plain.status_code == 200
    assert "<script" not in plain.text and "<link" not in plain.text and "feel" not in plain.text
    for path in ("/legal", "/abuse"):
        page = client.get(path)
        assert page.status_code == 200
        assert site_chrome.HEADER.replace("\n", "") in page.text.replace("\r\n", "\n").replace("\n", ""), path
        assert "<script" not in page.text.split("</head>", 1)[1], path


@pytest.fixture()
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "feel.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    _check._TABLES_READY.clear()
    _check.init_tables()
    yield _check
    _check._TABLES_READY.clear()


def test_a_redesign_changes_the_record_etag(registry, monkeypatch):
    from test_public_registry import _result
    import app as module

    registry.store_result("example.test", _result("example.test"))
    client = TestClient(module.app)
    first = client.get("/r/example.test")
    assert first.status_code == 200
    assert client.get("/r/example.test", headers={"If-None-Match": first.headers["etag"]}).status_code == 304
    monkeypatch.setattr(registry_page, "PAGE_VERSION", "next")
    again = client.get("/r/example.test", headers={"If-None-Match": first.headers["etag"]})
    assert again.status_code == 200 and again.headers["etag"] != first.headers["etag"]
