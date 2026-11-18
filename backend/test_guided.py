"""Guided mode: the switch on "/", three questions and one answer (services/guided.py,
static/instrument-guided.js). Public, off by default, reachable at /?guided=1. No network."""

import os
import re

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from services import guided, not_ready
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "guided.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    for mod in (_check, _grade):
        mod._TABLES_READY.clear()
    _limits.reset()
    yield


def _grade_it(domain, grade, when="2026-11-17T09:00:00Z"):
    pq = grade in ("A", "B")
    _grade.store({"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
                  "key_exchange": {"group": "X25519MLKEM768" if pq else "X25519", "post_quantum": pq},
                  "exposure": {"recorded_traffic_at_risk": not pq, "decrypt_year_low": None if pq else 2035,
                               "decrypt_year_high": None if pq else 2040, "source_url": "https://example.org/gri"},
                  "tls": {"versions": {"1.3": True}}, "certificate": {"verified": True},
                  "settings_to_fix": [] if pq else ["pq"],
                  "rubric_version": _grade.RUBRIC_VERSION})


# ── the answer and the role -> action map ──

@pytest.mark.parametrize("role,kind,label", [
    ("it", "make_safe", "Make it safe"),
    ("supplier", "note", "Send them this note"),
    ("board", "summary", "Print the one-page summary"),
])
def test_each_role_gets_exactly_one_action(role, kind, label):
    _grade_it("shop.example", "C")
    a = guided.answer("shop.example", role, "health", now=NOW)
    assert a["action"]["kind"] == kind and a["action"]["label"] == label
    assert a["role"] == role and a["grade"] == "C" and a["safe"] is False and a["record"] == "/r/shop.example"
    assert "shop.example" in a["sentence"] and a["data"]["short"] == "health"
    assert a["deadline"]["status"] in ("overdue", "due", "ahead")


def test_the_actions_say_what_they_do():
    _grade_it("shop.example", "C")
    it = guided.answer("shop.example", "it", now=NOW)["action"]
    assert it["href"] == "/shop.example#make-safe"
    note = guided.answer("shop.example", "supplier", base_url="https://m.example", now=NOW)["action"]
    assert note["text"].startswith("Subject: Post-quantum key exchange on shop.example")
    assert "https://m.example/shop.example" in note["text"] and "Morrow sends nothing" in note["detail"]
    board = guided.answer("shop.example", "board", now=NOW)["action"]
    assert "needs a free account" in board["detail"] and board["account_href"] == "/ui/"
    assert "trial" not in board["detail"].lower() and "upgrade" not in board["detail"].lower()


def test_not_sure_is_the_risk_sentences_own_default_and_an_unknown_role_is_it():
    _grade_it("shop.example", "D")
    a = guided.answer("shop.example", "nobody", "", now=NOW)
    assert a["role"] == "it" and a["data"]["assumed"] is True and a["data"]["short"] == "personal"


def test_a_safe_site_needs_no_note_and_its_deadline_is_met():
    _grade_it("safe.example", "A")
    a = guided.answer("safe.example", "supplier", now=NOW)
    assert a["safe"] is True and a["action"]["kind"] == "note_none" and a["action"]["text"] == ""
    assert a["deadline"]["status"] == "met"
    assert guided.answer("safe.example", "it", now=NOW)["action"]["href"] == "/r/safe.example"


def test_it_never_checks_and_respects_the_opt_out(monkeypatch):
    with pytest.raises(guided.GuidedError) as e:
        guided.answer("unchecked.example", "it")
    assert e.value.status_code == 404
    with pytest.raises(guided.GuidedError) as e:
        guided.answer("not a domain", "it")
    assert e.value.status_code == 400
    _grade_it("quiet.example", "C")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example")
    with pytest.raises(guided.GuidedError) as e:
        guided.answer("quiet.example", "it")
    assert e.value.status_code == 403


def test_the_words_never_label_anyone():
    _grade_it("shop.example", "F")
    for role in guided.ROLES:
        text = str(guided.answer("shop.example", role, now=NOW)).lower()
        for word in ("shame", "worst", "dangerous", "insecure", "unsafe"):
            assert not re.search(r"\b" + word, text), (role, word)


# ── it is public ──

def test_guided_mode_and_its_api_need_no_sign_in(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    application.limiter.enabled = False
    _grade_it("shop.example", "C")
    with TestClient(application.app) as anonymous:
        anonymous.cookies.clear()
        for path in ("/?guided=1", "/?guided=0", "/"):
            r = anonymous.get(path, headers={"Accept": "text/html"})
            assert r.status_code == 200, path
            assert '<script src="/ui/instrument-guided.js' in r.text and '<link rel="stylesheet" href="/ui/instrument-guided.css' in r.text
            assert "unsafe-inline" not in r.headers["content-security-policy"]
        for asset in ("/ui/instrument-guided.js", "/ui/instrument-guided.css"):
            assert anonymous.get(asset).status_code == 200
        for role in ("it", "supplier", "board"):
            r = anonymous.get(f"/api/public/guided/shop.example?role={role}&data=financial")
            assert r.status_code == 200, r.text
            assert r.json()["action"]["kind"] in ("make_safe", "note", "summary")
        assert anonymous.get("/api/public/guided/unchecked.example").status_code == 404
        assert anonymous.get("/api/public/guided/not..valid").status_code == 400


# ── the page ──

def test_the_switch_is_on_the_home_page_and_off_by_default():
    js = _read("instrument-guided.js")
    assert "Browse everything" in js and "Just answer 3 questions" in js
    assert 'return stored() === "1";' in js                         # nothing stored: off
    assert 'p === "1"' in js and 'p === "0"' in js                     # /?guided=1 starts it, /?guided=0 ends it
    home = _read("instrument.js")
    view = home[home.index("function viewHome()"):home.index("function homeSignedIn()")]
    assert "guided.on()" in view and "guided.start(main)" in view and "guided.switchHtml(false)" in view
    assert view.index("guided.on()") < view.index('main.innerHTML = \'<form class="i-safe"')


def test_the_page_maps_roles_to_the_same_actions_as_the_server():
    js = _read("instrument-guided.js")
    for role, action in guided.ROLE_ACTIONS.items():
        assert re.search(r'id: "' + role + r'"[^}]*action: "' + re.escape(action["label"]) + '"', js), role
    for short, label, _hint in guided.DATA_CHOICES:
        assert 'id: "' + short + '", label: "' + label + '"' in js, label


def test_three_questions_each_skippable_with_back_and_focus():
    js = _read("instrument-guided.js")
    for q in ("What&rsquo;s your website or company domain?", "Who are you?", "What does it carry?"):
        assert q in js, q
    assert js.count("nav(") >= 4 and "Skip: I run it" in js and "Skip: not sure" in js and '"Skip: use "' in js
    assert "&larr; Back" in js and ".focus(" in js and 'aria-live="polite"' in js
    assert "/api/public/grade/" in js and "/api/public/guided/" in js
    calls = re.findall(r"getJSON\(\s*([^,]+)", js)
    assert calls and all(c.strip().startswith('"/api/public/') for c in calls), calls
    assert "morrow_token" not in js and "Authorization" not in js and "auth:" not in js and "style=" not in js
    css = _read("instrument-guided.css")
    assert "prefers-reduced-motion" in css and "@media print" in css and "url(" not in css


def test_the_banned_words_stay_out_of_the_page():
    text = _read("instrument-guided.js").lower()
    for word in not_ready.BANNED_WORDS + ("worst", "trial", "upgrade"):
        assert not re.search(r"\b" + re.escape(word) + r"\b", text), word


def test_the_answer_leaves_a_hook_where_make_it_safe_renders_and_moves_with_care():
    js = _read("instrument-guided.js")
    assert '"gd-make-safe"' in js and 'makeSafeRendered($("#gd-make-safe"), { source: "guided"' in js
    css = _read("instrument-guided.css")
    assert ".25s" in css and "gd-reveal" in css and "infinite" not in css
    reduced = css[css.index("@media (prefers-reduced-motion: reduce) {"):]
    assert "animation: none" in reduced
