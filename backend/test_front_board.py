"""The front page's live board (static/instrument-board.js) and the not-ready slice it reads.

The board must be fully public: "/" and every API it calls answer a visitor with no session and no
token. It names companies, so it keeps the league's safeguards: never ranked, dated measured
wording, the opt-out and the owner's reply one click away, opted-out domains never shown. No network.
"""

import os
import re

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import changes, league, not_ready, tranco
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
BOARD_APIS = (
    "/api/public/stats",
    "/api/public/league",
    "/api/public/changes?limit=100",
    "/api/public/pq-ready",
    "/api/public/not-ready?order=checked&limit=6",
    "/api/public/not-ready?order=checked&limit=6&sector=finance",
    "/api/public/not-ready?order=checked&limit=6&q=bank",
)


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


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
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "board.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_LEAGUE_TRANCO_SIZE", "10000")
    monkeypatch.setattr(league, "load_spec", lambda path=None: {"sectors": [
        {"id": "finance", "name": "Banks", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
         "domains": ["bank.example", "loans.example"]}]})
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


def _seed():
    tranco.store(["bank.example", "loans.example", "shop.example", "zebra.example"], "TEST")
    _grade_it("bank.example", "C", "2026-11-10T00:00:00Z")
    _grade_it("loans.example", "D", "2026-11-14T00:00:00Z")
    _grade_it("shop.example", "C", "2026-11-12T00:00:00Z")
    _grade_it("zebra.example", "A", "2026-11-13T00:00:00Z")


# ── the slice the board reads ──

def test_the_slice_counts_the_whole_list_and_returns_only_the_limit():
    _seed()
    body = not_ready.page(limit=2)
    assert body["count"] == 3 and body["matched"] == 3 and len(body["entries"]) == 2
    assert [e["domain"] for e in body["entries"]] == ["bank.example", "loans.example"]      # by name, as the list


def test_newest_check_first_is_by_date_not_by_grade():
    _seed()
    body = not_ready.page(order="checked")
    assert [e["domain"] for e in body["entries"]] == ["loans.example", "shop.example", "bank.example"]
    assert body["order"] == "checked"


def test_sector_and_search_filter_and_say_how_many_matched():
    _seed()
    body = not_ready.page(sector="finance")
    assert body["count"] == 2 and {e["domain"] for e in body["entries"]} == {"bank.example", "loans.example"}
    body = not_ready.page(q="SHOP")
    assert body["count"] == 3 and body["matched"] == 1 and body["entries"][0]["domain"] == "shop.example"
    assert not_ready.page(q="nothing-like-this")["entries"] == []


def test_an_opt_out_applies_at_once_even_to_a_kept_list(monkeypatch):
    _seed()
    assert "shop.example" in [e["domain"] for e in not_ready.page()["entries"]]
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "shop.example")
    names = [e["domain"] for e in not_ready.page()["entries"]]
    assert "shop.example" not in names and not_ready.page()["count"] == 2


def test_a_new_check_refreshes_the_kept_list():
    _seed()
    assert not_ready.page()["count"] == 3
    _grade_it("shop.example", "A", "2026-11-15T00:00:00Z")      # it moved up: it leaves the list at once
    assert [e["domain"] for e in not_ready.page()["entries"]] == ["bank.example", "loans.example"]


def test_the_route_takes_the_slice_and_keeps_the_full_list_without_it(monkeypatch):
    import app as application

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    _seed()
    with TestClient(application.app, raise_server_exceptions=False) as client:
        full = client.get("/api/public/not-ready").json()
        assert full["count"] == 3 and len(full["entries"]) == 3 and "matched" not in full
        part = client.get("/api/public/not-ready?order=checked&limit=1&sector=finance").json()
        assert part["count"] == 2 and part["matched"] == 2 and [e["domain"] for e in part["entries"]] == ["loans.example"]
        assert client.get("/api/public/not-ready?limit=100000").json()["count"] == 3        # clamped, not refused


# ── the board is public ──

def test_the_front_page_and_every_board_api_answer_without_any_sign_in(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    application.limiter.enabled = False
    _seed()
    with TestClient(application.app) as anonymous:
        anonymous.cookies.clear()
        page = anonymous.get("/", headers={"Accept": "text/html"})
        assert page.status_code == 200
        assert '<script src="/ui/instrument-board.js' in page.text and '<link rel="stylesheet" href="/ui/instrument-board.css' in page.text
        csp = page.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "style-src 'self'" in csp and "unsafe-inline" not in csp
        for asset in ("/ui/instrument-board.js", "/ui/instrument-board.css"):
            assert anonymous.get(asset).status_code == 200, asset
        for url in BOARD_APIS:
            r = anonymous.get(url)
            assert r.status_code == 200, (url, r.status_code, r.text[:200])
        assert anonymous.get("/scans?limit=100").status_code == 401        # the board never needs this


def test_the_board_reads_only_public_apis_and_needs_no_account():
    js = _read("instrument-board.js")
    calls = re.findall(r"""load\(\s*["']([^"']+)""", js) + re.findall(r'''var url = "([^"]+)''', js)
    assert calls, "no API calls found"
    for path in calls:
        assert path.startswith("/api/public/"), path
    assert "workspace(" not in js and "token" not in js and "Authorization" not in js and "/instrument/" not in js
    assert "sign in" not in js.lower()
    for api in ("/api/public/stats", "/api/public/league", "/api/public/changes?limit=100", "/api/public/pq-ready", "/api/public/not-ready?order=checked"):
        assert api in js, api


def test_home_mounts_the_board_for_everyone_signed_in_or_not():
    js = _read("instrument.js")
    home = js[js.index("function viewHome()"):js.index("function homeSignedIn()")]
    assert 'id="home-board"' in home
    mount = home.index("MorrowBoard.mount(")
    assert mount < home.index("workspace().then(")                   # not waiting for, or gated on, the workspace


# ── what the board says ──

def test_the_board_links_every_public_list_and_each_record():
    js = _read("instrument-board.js")
    for href in ('href="/league"', 'href="/report"', 'href="/changes"', 'href="/api/public/changes.rss"', 'href="/threat"',
                 'href="/vendors"', 'href="/abuse"', 'href="/about-scanner"', 'href="/league#nr-correct"'):
        assert href in js, href
    assert 'href="/report/' + "' + enc(s.id)" in js
    assert js.count('item("/r/" + enc(e.domain)') == 3                # every named row opens its permanent record
    for label in ("League", "Sector reports", "What changed", "Threat board", "Check your vendors",
                  "Just became quantum-safe", "Verified ready", "Not yet post-quantum", "See all "):
        assert label in js, label


def test_the_board_never_ranks_or_labels_anyone():
    text = _read("instrument-board.js").lower()
    for word in not_ready.BANNED_WORDS + ("worst", "best", "leaderboard", "hall of", "laggard", "top 10", "ranked #", "rank "):
        assert not re.search(r"\b" + re.escape(word), text), word
    assert "not a ranking" in text and "measured " in text
    assert ".sort(" in text
    # The only sorts: sectors by name, and sites by date checked then by name. Never by grade or share.
    for sort in re.findall(r"\.sort\(function \(a, b\) \{ return ([^}]+)\}", _read("instrument-board.js")):
        assert "grade" not in sort and "share" not in sort, sort


def test_the_board_and_its_page_carry_nothing_inline():
    html = _read("instrument.html")
    assert "<style" not in html and " style=" not in html
    js = _read("instrument-board.js")
    assert "style=" not in js and "<script" not in js
    assert not re.search(r"""(?:fetch|getJSON|load)\(\s*["'`](?:https?:)?//""", js)
    css = _read("instrument-board.css")
    assert "@import" not in css and "url(" not in css
    assert "infinite" not in css                                        # nothing moves on its own for ever
    assert "prefers-reduced-motion" in css


def test_the_board_gives_a_reason_to_come_back_from_real_data_only():
    js = _read("instrument-board.js")
    assert "Since your last visit" in js and "morrow_board_visit" in js and "new since your last visit" in js
    assert '"/api/public/history/" + enc(d) + "?limit=2"' in js            # stored checks only, never a new check
    assert "is still " in js and "moved from " in js
    assert js.count("try {") >= 4                                              # every storage access can fail quietly
    assert "prefers-reduced-motion" in js and "IntersectionObserver" in js


def test_the_home_page_leaves_a_hook_where_make_it_safe_renders():
    js = _read("instrument.js")
    assert 'id="home-make-safe"' in js and "morrow:make-safe-action" in js
    assert 'makeSafeRendered($("#home-make-safe"), { source: "home"' in js
