"""The instrument views: the address is the interface, nothing but this origin is contacted, and
the plain pages answer without a script. No network: the grade check is replaced."""

import os
import re
from html.parser import HTMLParser

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from routers import instrument
from services import public_grade as _grade

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
INSTRUMENT_FILES = ("instrument.html", "instrument.js", "instrument-data.js", "instrument.css")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "instrument.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    _grade._TABLES_READY.clear()
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.parametrize("segment,expected", [
    ("example.com", "example.com"), ("Example.COM.", "example.com"), ("www.bbc.co.uk", "www.bbc.co.uk"),
    ("wp-login.php", None), ("robots.txt", None), (".env", None), ("config.yml", None),
    ("localhost", None), ("1.2.3.4", None), ("a.b", None), ("league", None), ("foo.zip", "foo.zip"),
])
def test_a_path_segment_is_a_domain_only_when_it_looks_like_one(segment, expected):
    assert instrument.domain_segment(segment) == expected


@pytest.mark.parametrize("path", ["/", "/example.com", "/league", "/atlas", "/algorithms", "/algorithms/ml-kem", "/trust",
                                  "/estate", "/estate/scan/0b6e", "/estate/asset/example.com:443"])
def test_every_view_is_the_instrument_page_under_the_strictest_policy(client, path):
    r = client.get(path, headers={"Accept": "text/html"})
    assert r.status_code == 200, path
    assert '<script src="/ui/instrument.js' in r.text
    csp = r.headers["content-security-policy"]
    assert csp == instrument.CSP
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    for directive in csp.split(";"):
        sources = directive.split()[1:]
        assert all(s in ("'self'", "'none'", "data:") for s in sources), directive


def test_the_views_need_no_account(client, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    for path in ("/", "/example.com", "/league", "/trust", "/algorithms/x25519", "/plain", "/plain/league"):
        assert client.get(path).status_code == 200, path


def test_the_apps_own_dotted_routes_are_not_domain_views(client, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    assert not instrument.is_public_path("/cbom.csv", application.app)
    assert client.get("/cbom.csv").status_code == 401
    assert "instrument.js" not in client.get("/robots.txt").text
    # Not domains, so not public: the auth gate answers them like any unknown path.
    assert not instrument.is_public_path("/wp-login.php", application.app)
    assert client.get("/wp-login.php").status_code == 401


def test_an_unknown_path_is_still_not_found(client):
    assert client.get("/wp-login.php").status_code == 404
    assert client.get("/no-dots-here").status_code == 404
    assert client.get("/a/b.example.com").status_code == 404


def test_a_bad_algorithm_id_is_not_found(client):
    assert client.get("/algorithms/..%2f..%2fetc").status_code == 404


class _Refs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs, self.inline_scripts, self.inline_styles = [], 0, 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ("src", "href", "action"):
            if a.get(key):
                self.refs.append(a[key])
        if "style" in a:
            self.inline_styles += 1
        if tag == "script" and not a.get("src"):
            self._in_script = True
        if tag == "style":
            self.inline_styles += 1

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_scripts += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False


def test_the_page_loads_nothing_from_another_origin_and_nothing_inline():
    with open(os.path.join(STATIC, "instrument.html"), encoding="utf-8") as fh:
        parser = _Refs()
        parser.feed(fh.read())
    assert parser.refs
    assert all((ref.startswith("/") and not ref.startswith("//")) or ref.startswith("#") for ref in parser.refs), parser.refs
    assert parser.inline_scripts == 0 and parser.inline_styles == 0


def test_the_scripts_only_fetch_this_origin():
    """Every fetch()/getJSON() in the instrument's scripts takes a path, never a full URL. A link a
    person clicks (the NVD, a source document) is navigation they choose, not a request the page makes."""
    for name in ("instrument.js", "instrument-data.js"):
        with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
            text = fh.read()
        calls = re.findall(r"\b(?:fetch|getJSON)\(\s*([^,)]+)", text)
        assert calls or name != "instrument.js"
        for arg in calls:
            assert not re.match(r"""\s*["'`](?:https?:)?//""", arg), (name, arg)
        assert "XMLHttpRequest" not in text and "sendBeacon" not in text and "WebSocket" not in text
        assert "document.cookie" not in text
        assert "new Image(" not in text


def test_the_stylesheet_imports_nothing_from_elsewhere():
    with open(os.path.join(STATIC, "instrument.css"), encoding="utf-8") as fh:
        css = fh.read()
    for target in re.findall(r"url\(\s*['\"]?([^'\")]+)", css):
        assert target.startswith("/ui/"), target
    assert "@import" not in css


def test_the_plain_pages_run_no_script(client, monkeypatch):
    result = {"domain": "example.com", "scanned_at": "2026-11-01T00:00:00Z", "grade": "C", "summary": "s",
              "summaries": {"executive": "Recorded traffic could be read later."},
              "key_exchange": {"group": "X25519", "post_quantum": False}, "tls": {"negotiated": "TLSv1.3", "versions": {"1.3": True}},
              "certificate": {}, "exposure": {"recorded_traffic_at_risk": True, "decrypt_year_low": 2035,
                                              "decrypt_year_high": 2040, "source_url": "https://example.org/src"},
              "fixes": [{"title": "nginx", "snippet": "ssl_ecdh_curve X25519MLKEM768:X25519;", "requires": "nginx 1.27",
                         "notes": "", "applies_to": "nginx"}], "reasons": ["Classical key exchange."], "rubric_version": "t"}
    seen = {}

    def fake_check(domain, ip="", fresh=False, **_):
        seen["fresh"] = fresh
        return dict(result, domain=domain)

    monkeypatch.setattr(_grade, "check", fake_check)
    r = client.get("/plain/example.com")
    assert r.status_code == 200
    assert "<script" not in r.text and "<link" not in r.text and "style=" not in r.text
    assert "2035" in r.text and "X25519MLKEM768" in r.text and "Recorded traffic could be read later." in r.text
    assert "script-src 'none'" in r.headers["content-security-policy"]
    assert seen["fresh"] is False
    client.get("/plain/example.com?fresh=1")
    assert seen["fresh"] is True
    go = client.get("/plain/go?d=https://Example.com/path", follow_redirects=False)
    assert go.status_code == 303 and go.headers["location"] == "/plain/example.com"
    assert client.get("/plain/go?d=not a domain").status_code == 400
    home = client.get("/plain")
    assert home.status_code == 200 and "<script" not in home.text


def test_a_refused_grade_is_shown_plainly(client, monkeypatch):
    def refuse(domain, ip="", fresh=False, **_):
        raise _grade.GradeError(403, "refused_optout", f"{domain} has asked not to be checked by this service.")

    monkeypatch.setattr(_grade, "check", refuse)
    r = client.get("/plain/example.com")
    assert r.status_code == 403 and "asked not to be checked" in r.text


def test_every_algorithm_the_recognizer_links_to_has_a_reference_entry():
    with open(os.path.join(STATIC, "instrument-data.js"), encoding="utf-8") as fh:
        data = fh.read()
    ids = set(re.findall(r'id: "([a-z0-9-]+)"', data)) | {f"rsa-{b}" for b in (2048, 3072, 4096)} | {"aes-128", "aes-256"}
    for related in re.findall(r'related: \[([^\]]*)\]', data):
        for ref in re.findall(r'"([a-z0-9-]+)"', related):
            assert ref in ids, ref
    for history_refs in re.findall(r'\ba: \[([^\]]*)\]', data):
        for ref in re.findall(r'"([a-z0-9-]+)"', history_refs):
            assert ref in ids, ref


def test_suggestion_rows_never_show_a_raw_status():
    """Remediation states reach the recognizer and Ctrl+K as words. The server's values come from
    db.py and app.py (suggested, pending, open, approved, rejected, in_progress, pr_created, merged,
    validated, verified, verified_closed, closed); every one needs a phrase, and the rows must not
    print the server's own subtitle, which carries the raw value."""
    with open(os.path.join(STATIC, "instrument.js"), encoding="utf-8") as fh:
        js = fh.read()
    table = re.search(r"var FIX_STATUS = \{(.*?)\};", js, re.S).group(1)
    words = dict(re.findall(r"(\w+): \"([^\"]+)\"", table))
    for status in ("suggested", "pending", "open", "approved", "rejected", "in_progress", "pr_created", "merged",
                   "validated", "verified", "verified_closed", "closed"):
        assert status in words, status
        assert "_" not in words[status] and words[status][0].isupper(), words[status]
    assert words["verified_closed"] == "Fixed and verified"
    search = js[js.index("function searchMine("):js.index("function startScan(")]
    assert "subtitle" not in search
    assert 'fixStatus(d.status)' in search and '"Status recorded"' in js
