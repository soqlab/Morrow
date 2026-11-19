"""The front page's story ("/": services/home_page.py, static/home-story.js and .css).

What is checked here, without a browser (scripts/motion-smoke.js and scripts/instrument-smoke.js
check the same promises in a real one):
  - the rows of names leave out CDN, API, ad and tracking hosts, and only the rows do;
  - the wording says what was measured: "of the sites checked this week", never "websites" or
    "the internet" as a whole; the counts behind it are distinct sites, by their newest check;
  - the sector headline is written from the data (the league's spread), never typed in;
  - everything the front page linked to or did before is still reachable from "/";
  - motion: only transform and opacity move, only two named animations may repeat, and only while
    on screen; under reduced motion nothing moves and the rows scroll;
  - every API the page reads answers a visitor who is not signed in.
"""

from __future__ import annotations

import json
import os
import pathlib
import re

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import changes, home_page, infra_hosts, league, not_ready, tranco
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

BACKEND = pathlib.Path(__file__).parent
STATIC = BACKEND / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _reset():
    for mod in (_check, _grade, league):
        mod._TABLES_READY.clear()
    league._table_cache.clear()
    not_ready._ready = ""
    not_ready.clear_cache()
    changes.clear_cache()
    tranco._ready = ""
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "home.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_LEAGUE_TRANCO_SIZE", "10000")
    monkeypatch.setattr(league, "load_spec", lambda path=None: {"sectors": [
        {"id": "finance", "name": "Banks", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
         "domains": ["bank.example", "loans.example"]},
        {"id": "news", "name": "News", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
         "domains": ["paper.example"]}]})
    _reset()
    yield
    _reset()


def _grade_it(domain, grade, when):
    pq = grade in ("A", "B")
    _grade.store({"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
                  "key_exchange": {"group": "X25519MLKEM768" if pq else "X25519", "post_quantum": pq},
                  "exposure": {"recorded_traffic_at_risk": not pq, "decrypt_year_low": None if pq else 2035,
                               "decrypt_year_high": None if pq else 2040, "source_url": "https://example.org/gri"},
                  "tls": {"versions": {"1.3": True}}, "certificate": {"verified": True},
                  "rubric_version": _grade.RUBRIC_VERSION})


def _recent(days_ago: float = 1.0) -> str:
    from datetime import timedelta

    return _grade.iso(_grade.now_utc() - timedelta(days=days_ago))


def _seed():
    tranco.store(["facebook.com", "fbcdn.net", "bank.example", "a.b.fastly.net", "loans.example", "paper.example",
                  "doubleclick.net", "shop.example"], "TEST")
    _grade_it("facebook.com", "B", _recent(1))
    _grade_it("fbcdn.net", "A", _recent(1))
    _grade_it("bank.example", "C", _recent(2))
    _grade_it("a.b.fastly.net", "C", _recent(2))
    _grade_it("loans.example", "D", _recent(3))
    _grade_it("paper.example", "A", _recent(3))
    _grade_it("doubleclick.net", "D", _recent(3))
    _grade_it("shop.example", "C", _recent(4))


# ── the rows of names leave out infrastructure hosts, and only the rows ──

def test_the_infrastructure_list_is_documented_data():
    raw = json.loads((BACKEND / "data" / "infrastructure_hosts.json").read_text(encoding="utf-8"))
    assert raw["format"] == "morrow.infrastructure-hosts/v1" and "only those rows" in raw["about"].lower()
    groups = raw["categories"]
    assert set(groups) >= {"cdn_and_static", "cloud_api_and_network", "ads_analytics_tracking", "dns_time_and_certificates"}
    names = [h for hosts in groups.values() for h in hosts]
    assert len(names) == len(set(names)), "a host is listed twice"
    for host in names:
        assert host == host.strip().lower() and "." in host and not host.startswith(".") and "/" not in host, host
    for host in ("fbcdn.net", "gstatic.com", "googleapis.com", "doubleclick.net", "amazonaws.com", "windows.net",
                 "googlevideo.com", "akamaiedge.net", "fastly.net", "ntp.org"):
        assert host in names, host


@pytest.mark.parametrize("domain, infra", [
    ("fbcdn.net", True), ("static.xx.fbcdn.net", True), ("a.b.fastly.net", True), ("pool.ntp.org", True),
    ("doubleclick.net", True), ("FBCDN.NET.", True),
    ("facebook.com", False), ("notfastly.net", False), ("fastly.net.example", False), ("google.com", False), ("", False),
])
def test_a_host_and_everything_under_it_is_infrastructure(domain, infra):
    assert infra_hosts.is_infrastructure(domain) is infra


def test_the_filter_shapes_the_rows_only_and_keeps_the_counts():
    _seed()
    safe = not_ready.page(kind="ready", order="popular", limit=10, days=8, hide_infra=True)
    assert [e["domain"] for e in safe["entries"]] == ["facebook.com", "paper.example"]        # fbcdn.net left out
    assert safe["count"] == 3 and safe["matched"] == 2 and safe["hide_infra"] is True
    full = not_ready.page(kind="ready", order="popular", limit=10, days=8)
    assert [e["domain"] for e in full["entries"]] == ["facebook.com", "fbcdn.net", "paper.example"]
    below = not_ready.page(order="popular", limit=10, hide_infra=True)
    assert [e["domain"] for e in below["entries"]] == ["bank.example", "loans.example", "shop.example"]
    assert below["count"] == 5                                                                 # the list behind it
    assert "a.b.fastly.net" in [e["domain"] for e in not_ready.entries()["entries"]]          # the full list is unchanged


def test_the_routes_take_hide_infra_and_answer_as_before_without_it(monkeypatch):
    import app as application

    application.limiter.enabled = False
    _seed()
    with TestClient(application.app) as client:
        part = client.get("/api/public/not-ready?order=popular&limit=6&hide_infra=1").json()
        assert "doubleclick.net" not in [e["domain"] for e in part["entries"]] and part["count"] == 5
        plain = client.get("/api/public/not-ready").json()
        assert "doubleclick.net" in [e["domain"] for e in plain["entries"]] and "matched" not in plain
        safe = client.get("/api/public/checked-safe?order=popular&days=8&limit=6&hide_infra=1").json()
        assert [e["domain"] for e in safe["entries"]] == ["facebook.com", "paper.example"]
        assert "fbcdn.net" in [e["domain"] for e in client.get("/api/public/checked-safe?order=popular&days=8&limit=6").json()["entries"]]


def test_the_page_asks_for_the_rows_without_infrastructure():
    js = _read("home-story.js")
    assert '"/api/public/checked-safe?order=popular&days=8&limit=" + ROW + "&hide_infra=1"' in js
    assert '"/api/public/not-ready?order=popular&limit=" + ROW + "&hide_infra=1"' in js
    assert "hide_infra" not in _read("instrument-board.js"), "the full board's lists must stay unfiltered"


# ── honest wording ──

CLAIMS = (r"\bof (?:all )?(?:the )?websites\b", r"\bwebsites are\b", r"\bthe internet\b", r"\bthe web\b",
          r"\bof (?:all )?(?:the )?sites (?:are|on)\b", r"\bevery website\b")


def _visible_text(markup: str) -> str:
    return re.sub(r"<[^>]+>", " ", markup).replace("&rsquo;", "'").replace("&#8209;", "-")


def test_the_page_says_what_was_measured_and_nothing_wider():
    text = (_visible_text(home_page.HERO) + "\n" + _read("home-story.js")).lower()
    for claim in CLAIMS:
        assert not re.search(claim, text), claim
    js = _read("home-story.js")
    assert "of the sites checked this week are ready for quantum computers." in js
    assert "sites checked this week" in home_page.HERO
    # The only "website" is the visitor's own, in the question.
    assert set(re.findall(r"websites?", _visible_text(home_page.HERO).lower())) == {"website"}
    # The names keep the league's safeguards next to them.
    for part in ('href="/league#nr-correct"', 'href="/abuse"', 'href="/about-scanner"', "Not a ranking",
                 "one dated measurement", 'id="hs-all" href="/league"', "See all "):
        assert part in js, part
    for word in not_ready.BANNED_WORDS + ("worst", "best grade", "safest", "leaderboard", "laggard", "top 10", "rank "):
        assert not re.search(r"\b" + re.escape(word), js.lower()), word


def test_the_counts_are_sites_by_their_newest_check_this_week():
    _grade_it("one.example", "A", _recent(3))
    _grade_it("one.example", "C", _recent(1))            # its newest check this week is classical
    _grade_it("two.example", "B", _recent(2))
    _grade_it("old.example", "A", _recent(30))           # not this week
    s = _grade.stats()
    assert s["sites_checked_7d"] == 2 and s["sites_ready_7d"] == 1 and s["sites_ready_share_7d"] == 0.5
    assert s["public_checks_7d"] == 3                     # checks, as before
    assert "example" not in json.dumps(s)


# ── the sector headline comes from the data ──

def _sector(sid, name, share, graded=10):
    return {"id": sid, "name": name, "graded": graded, "pq_share": share}


def test_the_spread_names_the_sectors_furthest_apart():
    out = league.spread([_sector("a", "Alpha", .4), _sector("b", "Beta", .7), _sector("c", "Gamma", .2), _sector("d", "Delta", None, 0)])
    assert out["ahead"]["name"] == "Beta" and out["behind"]["name"] == "Gamma" and out["sectors"] == 3
    tie = league.spread([_sector("z", "Zulu", .5), _sector("a", "Alpha", .5), _sector("m", "Mike", .1)])
    assert tie["ahead"]["name"] == "Alpha"                                   # a tie is broken by name
    assert league.spread([_sector("a", "Alpha", .5)]) is None
    assert league.spread([_sector("a", "Alpha", .5), _sector("b", "Beta", .5)]) is None


def test_the_league_answer_carries_the_spread_and_the_page_writes_the_headline_from_it():
    _seed()
    body = league.sector_averages()
    names = {s["id"]: s["name"] for s in body["sectors"]}
    sp = body["spread"]
    assert sp and sp["ahead"]["name"] == names["news"] and sp["behind"]["name"] == names["finance"]
    js = _read("home-story.js")
    assert "sp.ahead.name" in js and "sp.behind.name" in js
    spec = json.loads((BACKEND / "league" / "sectors.json").read_text(encoding="utf-8"))
    for sector in spec["sectors"]:
        assert sector["name"] not in js, f"{sector['name']} is typed into the page"
    for word in ("Banks lead", "Telecoms trail", "Banks", "Telecom"):
        assert word not in js, word


# ── nothing that was reachable from "/" became unreachable ──

def _home_html():
    import app as application

    with TestClient(application.app) as client:
        r = client.get("/", headers={"Accept": "text/html"})
    assert r.status_code == 200
    return r.text


def test_every_link_and_feature_of_the_front_page_is_still_there():
    page = _home_html()
    story, board, instrument = _read("home-story.js"), _read("instrument-board.js"), _read("instrument.js")
    reachable = page + story + board
    # The footer, the board's lists and links, and the old home's ways in.
    for href in ("/plain", "/trust", "/legal", "/abuse", "/about-scanner", "/watching", "/support", "/ui/",
                 "/league", "/report", "/changes", "/api/public/changes.rss", "/threat", "/vendors", "/league#nr-correct",
                 "/r/"):
        assert f'href="{href}' in reachable, href
    # The first screen is in the HTML, and works without script (the plain check).
    assert '<h1 class="hs-h1" id="hs-h1">' in page and 'action="/plain/go"' in page and 'name="d"' in page
    assert 'id="home-q"' in page and 'id="home-form"' in page and 'id="hs-go"' in page and 'id="home-conn"' in page
    assert '<body class="ins hs-page"' in page and '<p class="i-say" id="say" aria-live="polite" hidden></p>' in page
    for asset in ("/ui/home-story.js", "/ui/home-story.css", "/ui/instrument-board.js", "/ui/paste.js",
                  "/ui/instrument-guided.js", "/ui/make-safe-done.js", "/ui/feel.js"):
        assert asset in page, asset
    # Paste or drop a file, Ctrl K, guided mode, the connection line, welcome back, the board, the estate.
    for part in ('id="home-pick"', 'id="home-file"', "paste.attach({ form: form, input: input", "guided.switchHtml(false)",
                 "guided.bindSwitch(form)", 'id="hs-cmd"', "i-cmd-btn", "I().connLine(c)", "MorrowBoard.mount(",
                 "MorrowBoard.welcomeBack(", "I().homeSignedIn()", 'id="home-board"', 'id="home-reading"'):
        assert part in story, part
    # The answer in place: the grade check, Done through the make-safe hook, the record.
    for part in ('"/api/public/grade/" + enc(d)', '"/api/public/make-safe/" + enc(d)', 'id="home-make-safe"',
                 'I().makeSafeRendered($("#home-make-safe"), { source: "home", domain: d',
                 "See how to fix it", "See the full record", 'aria-live="polite"'):
        assert part in story + page, part
    assert "mount(box, d.plan ? { domain: d.domain, plan: d.plan } : { domain: d.domain })" in _read("make-safe-done.js")
    # The old home view stays as the fallback, and guided mode drops the story frame first.
    assert "window.MorrowHome.mount()" in instrument and "plainHome()" in instrument
    assert "connLine: connLine" in instrument and "homeSignedIn: homeSignedIn" in instrument


def test_the_page_has_its_headings_in_order_and_labels_its_inputs():
    page = _home_html()
    assert page.count("<h1") == 1 and '<label class="sr-only" for="home-q">' in page
    story = _read("home-story.js")
    levels = [int(n) for n in re.findall(r"<h([1-6])\b", story)]
    assert levels and set(levels) == {2}, levels                     # every section is an h2 under the one h1
    assert '<label class="sr-only" for="hs-q2">' in story
    assert '<ul class="hs-track" aria-hidden="true" inert>' in story  # the moving copy is hidden and out of reach
    assert 'class="hs-g" aria-hidden="true"' in story and 'title="' in story
    assert "measured " in story and "key exchange " in story          # each pill's tooltip and title say both


def test_home_page_render_is_unchanged_when_a_marker_is_missing():
    page = _read("instrument.html")
    assert home_page.render(page).count('id="hs-hero"') == 1
    broken = page.replace('id="say"', 'id="said"')
    assert home_page.render(broken) == broken


# ── motion ──

def _strip(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def test_only_two_named_animations_may_repeat_and_only_while_on_screen():
    css = _strip(_read("home-story.css"))
    infinite = re.findall(r"animation:\s*([^;]*\binfinite\b[^;]*);", css)
    names = sorted(re.match(r"\s*([\w-]+)", decl).group(1) for decl in infinite)
    assert names == ["hs-breathe", "hs-marquee"], names
    for decl in infinite:
        assert "paused" in decl, f"{decl}: must start paused"
    assert ".hs-hero.hs-on .hs-glow { animation-play-state: running; }" in css
    assert ".hs-names.hs-on .hs-track { animation-play-state: running; }" in css
    assert ".hs-names.hs-on .hs-row:hover .hs-track, .hs-names.hs-on .hs-row:focus-within .hs-track { animation-play-state: paused; }" in css
    js = _read("home-story.js")
    assert 'en.target.classList.toggle("hs-on", en.isIntersecting)' in js
    assert 'ambient.observe($("#hs-hero")); ambient.observe($("#hs-names"));' in js
    # The shine sweeps three times and stops; everything else runs once.
    for decl in re.findall(r"animation:\s*([^;]+);", css):
        if "infinite" in decl or decl.strip().startswith("none"):
            continue
        assert re.search(r"\s(1|3)(\s|$)", decl), f"animation without a count: {decl}"


def test_only_transform_and_opacity_move():
    css = _strip(_read("home-story.css"))
    for decl in re.findall(r"transition:\s*([^;]+);", css):
        if decl.strip().startswith("none"):
            continue
        for part in re.split(r",(?![^(]*\))", decl):
            prop = part.split()[0]
            assert prop in ("transform", "opacity"), f"transition of {prop}: {decl}"
    for name, body in re.findall(r"@keyframes\s+([\w-]+)\s*\{(.*?)\}\s*\}", css, flags=re.S):
        for prop in re.findall(r"([\w-]+)\s*:", body):
            assert prop in ("transform", "opacity"), f"@keyframes {name} animates {prop}"
    js = _read("home-story.js")
    for prop in re.findall(r"\.style\.(\w+)\s*=", js):
        assert prop in ("transform", "transitionDelay"), prop
    assert "setInterval(read, POLL_MS)" in js and "document.hidden" in js and "POLL_MS = 25000" in js


def test_reduced_motion_stops_everything_and_the_rows_scroll():
    css = _read("home-story.css")
    reduced = css[css.index("@media (prefers-reduced-motion: reduce)"):]
    for part in (".hs-glow", ".hs-track", ".hs-h1 .w", ".hs-shine", "animation: none !important",
                 "transition: none !important", ".hs-row { overflow-x: auto;", '.hs-track[aria-hidden="true"] { display: none; }',
                 ".hs-rv, .hs-rv.hs-in { opacity: 1; transform: none; transition: none; }"):
        assert part in reduced, part
    js = _read("home-story.js")
    assert 'matchMedia("(prefers-reduced-motion: reduce)")' in js
    assert "if (REDUCED || !window.requestAnimationFrame) { el.textContent = fmt(to); return; }" in js
    assert "if (REDUCED || !names.length || !input) return;" in js          # no typing demo


def test_the_page_is_on_the_shared_tokens_with_aa_text_in_both_themes():
    tokens = _read("instrument.css")
    assert "@font-face" not in tokens and "woff2" not in tokens            # the system font stack only

    def lum(hex_):
        rgb = [int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    def ratio(a, b):
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    def block(selector):
        start = tokens.index(selector)
        return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", tokens[start:tokens.index("}", start)]))

    for theme in (block(":root {"), block(':root[data-theme="light"]')):
        for text in ("text", "muted", "dim", "safe", "warn"):
            for ground in ("bg", "bg-2"):
                assert ratio(theme[text], theme[ground]) >= 4.5, (text, ground, theme[text], theme[ground])
        assert ratio(theme["warn"], theme["warn-dim"]) >= 4.5
        assert ratio(theme["safe-ink"], theme["safe"]) >= 4.5
    for name in ("--r-pill", "--r-xl", "--shadow-2", "--ease", "--fs-hero", "--fs-h2", "--safe-ink", "--warn-dim", "--glow"):
        assert name in tokens, name
    css = _read("home-story.css")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", _strip(css).replace("#000 7%", "").replace("#000 93%", "")), "a fixed colour"


# ── signed out, every API the page reads answers ──

def test_every_api_the_front_page_reads_answers_without_any_sign_in(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    application.limiter.enabled = False
    _seed()
    monkeypatch.setattr(_grade, "check", lambda domain, ip, fresh=False: _grade.latest(_grade.normalize(domain)))
    with TestClient(application.app) as anonymous:
        anonymous.cookies.clear()
        for url in ("/", "/ui/home-story.js", "/ui/home-story.css", "/api/public/stats",
                    "/api/public/checked-safe?order=popular&days=8&limit=24&hide_infra=1",
                    "/api/public/not-ready?order=popular&limit=24&hide_infra=1", "/api/public/league",
                    "/api/public/grade/bank.example", "/api/public/make-safe/bank.example",
                    "/api/public/history/bank.example?limit=2", "/api/public/changes?limit=100", "/api/public/pq-ready"):
            r = anonymous.get(url, headers={"Accept": "text/html" if url == "/" else "application/json"})
            assert r.status_code == 200, (url, r.status_code, r.text[:200])
        page = anonymous.get("/", headers={"Accept": "text/html"})
        csp = page.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "style-src 'self'" in csp and "unsafe-inline" not in csp
        assert "style=" not in page.text.split("<body")[1] and "<style" not in page.text
        graded = anonymous.get("/api/public/grade/bank.example").json()
        assert graded["grade"] == "C" and graded["risk"]["sentence"]
        stats = anonymous.get("/api/public/stats").json()
        assert {"sites_checked_7d", "sites_ready_7d", "sites_ready_share_7d"} <= set(stats)
        assert anonymous.get("/scans?limit=100").status_code == 401        # the story never needs this


def test_the_story_carries_nothing_inline_and_reads_only_this_origin():
    js = _read("home-story.js")
    assert "style=" not in js and "<script" not in js
    assert not re.search(r"""(?:fetch|getJSON)\(\s*["'`](?:https?:)?//""", js)
    for path in re.findall(r"""getJSON\(\s*["']([^"']+)""", js):
        assert path.startswith("/api/public/"), path
    assert "XMLHttpRequest" not in js and "sendBeacon" not in js and "document.cookie" not in js
    css = _read("home-story.css")
    assert "@import" not in css and "url(" not in css
