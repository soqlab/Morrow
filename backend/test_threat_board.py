"""The quantum threat board: a reviewed, cited dataset, the estimate Morrow quotes everywhere read
from it, the /threat page and its feed, and the file reaching the hosted image. No network."""

import copy
import hashlib
import json
import os
import re
import shutil
from xml.etree import ElementTree

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import decrypt_window, risk_sentence
from services import threat_board as tb

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
STATIC = os.path.join(HERE, "static")


def _doc():
    with open(os.path.join(tb.DATA_DIR, tb.DATA_FILE), "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def _copy(tmp_path):
    d = tmp_path / "threat-board"
    shutil.copytree(tb.DATA_DIR, d)
    return d


# ── the dataset ──────────────────────────────────────────────────────────────

def test_the_dataset_matches_its_published_and_pinned_checksum():
    with open(os.path.join(tb.DATA_DIR, tb.DATA_FILE), "rb") as fh:
        data = fh.read()
    with open(os.path.join(tb.DATA_DIR, tb.DATA_FILE + ".sha256"), encoding="ascii") as fh:
        published = fh.read().split()[0]
    assert hashlib.sha256(data).hexdigest() == published == tb.EXPECTED_SHA256
    assert tb.dataset() is not None and tb.load_error() is None


def test_the_dataset_follows_its_schema():
    import jsonschema

    with open(os.path.join(tb.DATA_DIR, tb.SCHEMA_FILE), encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(_doc())
    assert tb.validate(_doc(), schema) == []


def test_every_entry_has_a_source_and_its_dates():
    doc = _doc()
    ids = [e["id"] for e in doc["entries"]]
    assert len(ids) == len(set(ids))
    for e in doc["entries"]:
        assert e["source_url"].startswith("https://"), e["id"]
        assert e["source_title"].strip(), e["id"]
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", e["date_checked"]), e["id"]
        if e["verified"]:
            assert e["quote"] and len(e["quote"]) >= 20, e["id"]
            assert re.match(r"^\d{4}-\d{2}(-\d{2})?$", e["date_published"]), e["id"]
        else:
            # Listed, never charted, never quoted as a number.
            assert not e.get("chart") and e["quote"] is None and e.get("note"), e["id"]
            assert "deadline" not in e and "physical_qubits" not in e, e["id"]
    for section in tb.SECTIONS:
        assert any(e["section"] == section and e["verified"] for e in doc["entries"]), section


def test_vendor_announcements_are_labelled_as_claims():
    doc = _doc()
    by_id = {e["id"]: e for e in doc["entries"]}
    for ident in ("ibm-condor-2023", "quantinuum-helios-2025", "microsoft-majorana-1-2025", "atom-computing-1180-2023"):
        assert by_id[ident]["claim"] == "vendor_claim", ident
    assert by_id["ibm-starling-roadmap-2025"]["claim"] == "roadmap" and not by_id["ibm-starling-roadmap-2025"]["chart"]
    # The contested topological-qubit claim is listed with its dispute and kept off the chart.
    assert not by_id["microsoft-majorana-1-2025"]["chart"] and "Disputed" in by_id["microsoft-majorana-1-2025"]["note"]
    # Preprints say so.
    assert by_id["pinnacle-2026"]["claim"] == "preprint" and by_id["gidney-2025"]["claim"] == "preprint"


def test_a_changed_byte_is_refused(tmp_path):
    d = _copy(tmp_path)
    data = (d / tb.DATA_FILE).read_bytes()
    (d / tb.DATA_FILE).write_bytes(data.replace(b'"experts": 26', b'"experts": 27', 1))
    with pytest.raises(tb.DatasetError, match="does not match"):
        tb.load(str(d))


def test_a_regenerated_checksum_does_not_launder_an_edit(tmp_path):
    d = _copy(tmp_path)
    data = (d / tb.DATA_FILE).read_bytes().replace(b'"low": 28', b'"low": 60', 1)
    (d / tb.DATA_FILE).write_bytes(data)
    (d / (tb.DATA_FILE + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "  threat-board.json\n", encoding="ascii")
    with pytest.raises(tb.DatasetError, match="pinned"):
        tb.load(str(d))


def test_an_entry_without_a_quote_or_a_source_is_refused(tmp_path):
    doc = _doc()
    doc["entries"][0]["quote"] = ""
    doc["entries"][1]["source_url"] = "http://example.com/"
    d = _copy(tmp_path)
    data = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    (d / tb.DATA_FILE).write_bytes(data)
    (d / (tb.DATA_FILE + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "\n", encoding="ascii")
    with pytest.raises(tb.DatasetError, match="not valid"):
        tb.load(str(d), expected=None)
    errors = tb.validate(doc)
    assert any("no quote" in e for e in errors) and any("source_url" in e for e in errors)


def test_the_estimate_must_come_from_a_verified_survey():
    doc = _doc()
    doc["estimate"]["survey"] = "ibm-condor-2023"
    assert any("verified survey" in e for e in tb.validate(doc))
    doc = _doc()
    doc["estimate"]["likely_horizon_years"] = 20
    assert any("likely_horizon_years" in e for e in tb.validate(doc))


# ── the estimate is the dataset's ───────────────────────────────────────────

def test_the_estimate_is_read_from_the_cited_survey():
    doc = _doc()
    survey = next(e for e in doc["entries"] if e["id"] == doc["estimate"]["survey"])
    assert survey["section"] == "surveys" and survey["verified"]
    assert survey["source_url"] == "https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/"
    est = tb.expert_estimate()
    assert est["low"] == survey["survey_year"] + doc["estimate"]["low_horizon_years"] == 2035
    assert est["likely"] == survey["survey_year"] + doc["estimate"]["likely_horizon_years"] == 2040
    assert est["high"] == 2045 and est["low_probability"] == "28-49%" and est["likely_probability"] == "51-70%"


def test_a_new_edition_moves_the_estimate():
    doc = copy.deepcopy(tb.dataset())
    survey = next(e for e in doc["entries"] if e["id"] == doc["estimate"]["survey"])
    survey["survey_year"] = 2027
    est = tb.estimate_from(doc)
    assert (est["low"], est["likely"], est["high"]) == (2037, 2042, 2047)


def test_the_decrypt_window_risk_sentence_and_harvest_clock_use_the_dataset():
    est = tb.expert_estimate()
    assert decrypt_window.ESTIMATE_FROM_DATASET is True
    assert (decrypt_window.DECRYPT_YEAR_LOW, decrypt_window.DECRYPT_YEAR_HIGH) == (est["low"], est["likely"])
    assert decrypt_window.CRQC_ESTIMATE["low"] == est["low"] and decrypt_window.CRQC_ESTIMATE["high"] == est["high"]
    assert decrypt_window.CRQC_ESTIMATE["board_url"] == "/threat"
    assert decrypt_window.EXPOSURE_SOURCE_URL == est["source_url"]
    assert f"about {est['low']} to {est['likely']}" in decrypt_window.EXPOSURE_BASIS
    clock = decrypt_window.harvest(True, False, 20)
    assert clock["crqc_year"] == est["low"] and clock["crqc_estimate"]["likely"] == est["likely"]
    basis = decrypt_window.basis()
    assert basis["from_dataset"] is True and basis["board_url"] == "/threat"
    r = risk_sentence.build("example.com", "at_risk", 1, None, None)
    assert f"could be read from about {est['low']} (expert estimates: {est['low']} to {est['likely']})" in r["sentence"]
    assert r["estimate"]["board_url"] == "/threat" and r["estimate"]["low"] == est["low"]


def test_the_headline_says_both_years_and_why():
    b = tb.board()
    assert b["headline"]["sentence"] == ("Experts put it at more likely than not by about 2040, "
                                         "and quite possible by about 2035.")
    why = b["headline"]["why"]
    assert "Morrow says about 2035" in why and "26 experts" in why and "28-49%" in why and "51-70%" in why


def test_the_board_lists_unverified_entries_apart():
    b = tb.board()
    assert {u["id"] for u in b["unverified"]} == {e["id"] for e in _doc()["entries"] if not e["verified"]}
    for section in b["sections"].values():
        assert all(e["verified"] for e in section)
    assert all(not e["stale"] for s in b["sections"].values() for e in s) or b["stale"]


def test_an_old_check_is_flagged_stale():
    from datetime import date

    b = tb.board(today=date(2028, 1, 1))
    assert b["stale"] and all(e["stale"] for s in b["sections"].values() for e in s)


# ── the page, the API and the feed ───────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "threat.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_the_page_is_public_and_carries_the_board(client):
    from routers import instrument

    r = client.get("/threat", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert '<script src="/ui/instrument-threat.js' in r.text and '<link rel="stylesheet" href="/ui/instrument-threat.css' in r.text
    assert r.headers["content-security-policy"] == instrument.CSP
    assert client.get("/ui/instrument-threat.js").status_code == 200
    assert client.get("/ui/instrument-threat.css").status_code == 200


def test_the_api_returns_the_data_the_page_draws(client):
    r = client.get("/api/public/threat")
    assert r.status_code == 200
    b = r.json()
    assert b["estimate"]["low"] == 2035 and b["estimate"]["likely"] == 2040
    assert "about 2040" in b["headline"]["sentence"]
    m = b["sections"]["machines"]
    assert any(e["chart"] and e["physical_qubits"] for e in m) and any(e["chart"] and e["logical_qubits"] for e in m)
    assert any(e["chart"] and e["physical_qubits"] for e in b["sections"]["attack_cost"])
    assert len(b["sections"]["deadlines"]) >= 10
    assert b["sha256"] == tb.EXPECTED_SHA256


def test_the_dataset_and_schema_are_downloadable_exactly(client):
    r = client.get("/api/public/threat/dataset.json")
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == tb.EXPECTED_SHA256
    assert r.headers["x-content-sha256"] == tb.EXPECTED_SHA256
    assert client.get("/api/public/threat/schema.json").json()["title"] == "Morrow quantum threat board dataset"


def test_the_feed_has_one_entry_per_edition(client):
    r = client.get("/api/public/threat.atom")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/atom+xml")
    root = ElementTree.fromstring(r.content)
    ns = {"a": "http://www.w3.org/2005/Atom"}
    entries = root.findall("a:entry", ns)
    assert len(entries) == len(_doc()["changes"])
    assert entries[0].find("a:id", ns).text == "urn:morrow:threat-board:" + _doc()["version"]


def test_a_broken_dataset_answers_503_not_a_guess(client, monkeypatch):
    monkeypatch.setitem(tb._cache, "doc", None)
    monkeypatch.setitem(tb._cache, "error", "test: refused")
    r = client.get("/api/public/threat")
    assert r.status_code == 503 and r.json()["error"] == "threat_board_unavailable"


# ── the links into it, and the old view ──────────────────────────────────────

def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


def test_the_old_q_day_view_forwards_to_the_board():
    console = _read("index.html")
    view = console[console.index("VIEWS.qday = async"):]
    view = view[:view.index("\n};") + 3]
    assert 'location.replace("/threat")' in view and "/qday-forecast" not in view
    with open(os.path.join(STATIC, "index.html"), "rb") as a, open(os.path.join(REPO_ROOT, "frontend", "index.html"), "rb") as b:
        assert a.read() == b.read()


def test_why_it_matters_quotes_the_board():
    console = _read("index.html")
    why = console[console.index("function whyItMatters("):console.index('return sec("Why it matters"')]
    assert "TB.headline.sentence" in why and "estimates?.median" not in why
    assert '"/api/public/threat"' in console[console.index("VIEWS.overview = async"):console.index("VIEWS.overview = async") + 1500]


def test_the_instrument_routes_links_and_palette_reach_the_board():
    js = _read("instrument.js")
    assert 'if (s0 === "threat" && window.MorrowThreat) return window.MorrowThreat.view();' in js
    assert 'h: "/threat"' in js  # Ctrl K
    assert "function riskSay(" in js and 'a.href = est.board_url + "#why"' in js
    board = _read("instrument-threat.js")
    assert 'getJSON("/api/public/threat"' in board
    # The page contacts nothing else: no fetch of its own, no other origin.
    assert "fetch(" not in board and "XMLHttpRequest" not in board
    assert 'id: "why"' in board  # the anchor the risk sentence links to
    assert "<desc" in board or '"desc"' in board  # charts carry a text alternative


def test_the_board_is_in_the_sitemap_and_public_path_list(client):
    assert "/threat</loc>" in client.get("/sitemap.xml").text


# ── the hosted image ─────────────────────────────────────────────────────────

def _dockerignore_keeps(path: str) -> bool:
    """Docker's rule: the last pattern matching the path (or one of its parent directories) wins."""
    with open(os.path.join(REPO_ROOT, ".dockerignore"), encoding="utf-8") as fh:
        patterns = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
    keep = True
    parts = path.split("/")
    candidates = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for pattern in patterns:
        negate = pattern.startswith("!")
        pat = pattern[1:] if negate else pattern
        pat = pat.strip("/")
        rx = "^" + re.escape(pat).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
        if any(re.match(rx, c) for c in candidates):
            keep = negate
    return keep


def test_the_hosted_image_keeps_the_dataset():
    # The hosted build (render.yaml: deploy/render-hosted/Dockerfile, context ".") copies backend/
    # through the root .dockerignore, which drops every data/ directory unless it is let back in.
    assert not _dockerignore_keeps("backend/data/somewhere-else/x.db")
    for name in (tb.DATA_FILE, tb.DATA_FILE + ".sha256", tb.SCHEMA_FILE):
        assert os.path.exists(os.path.join(tb.DATA_DIR, name)), name
        assert _dockerignore_keeps("backend/data/threat-board/" + name), name
    with open(os.path.join(REPO_ROOT, ".gitattributes"), encoding="utf-8") as fh:
        assert "backend/data/threat-board/** -text" in fh.read()
    with open(os.path.join(REPO_ROOT, "deploy", "render-hosted", "Dockerfile"), encoding="utf-8") as fh:
        assert "COPY --chown=appuser:appuser backend/ /app/" in fh.read()
    with open(os.path.join(REPO_ROOT, "scripts", "test-production-image.py"), encoding="utf-8") as fh:
        assert '"/api/public/threat"' in fh.read()
