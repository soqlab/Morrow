"""What changed and the sector reports: who may be named, opt-outs, crossing B, percentages and the
trend on fixtures, CSV, feeds and the routes. No network."""

import os
import xml.etree.ElementTree as ET

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import changes, league, not_ready, sector_report, tranco
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

ATOM = "{http://www.w3.org/2005/Atom}"
SPEC = {"sectors": [
    {"id": "finance", "name": "Banks", "method": "named banks", "sources": ["annual reports"], "suffixes": [],
     "suffix_patterns": [], "domains": ["bank1.example", "bank2.example", "bank3.example", "bank4.example"]},
    {"id": "news", "name": "News", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
     "domains": ["paper.example"]}]}


def _reset():
    for mod in (_check, _grade, league):
        mod._TABLES_READY.clear()
    league._table_cache.clear()
    not_ready._ready = ""
    tranco._ready = ""
    changes.clear_cache()
    sector_report.clear_cache()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "cr.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_LEAGUE_TRANCO_SIZE", "10000")
    monkeypatch.setattr(league, "load_spec", lambda path=None: SPEC)
    _reset()
    yield
    _reset()


def _g(domain, grade, when, group=None):
    pq = grade in ("A", "B")
    _grade.store({"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
                  "key_exchange": {"group": group or ("X25519MLKEM768" if pq else "x25519"), "post_quantum": pq},
                  "exposure": {}, "tls": {"versions": {"1.3": True}}, "certificate": {"verified": True},
                  "rubric_version": _grade.RUBRIC_VERSION})


def _now_minus(days):
    from datetime import timedelta
    return _grade.iso(_grade.now_utc() - timedelta(days=days))


# ── the change feed ──────────────────────────────────────────────────────────


def test_tranco_sites_are_named_when_they_cross_b_in_either_direction():
    tranco.store(["acme.example", "flip.example", "steady.example"], "T")
    _g("acme.example", "C", _now_minus(20))
    _g("acme.example", "A", _now_minus(10))
    _g("flip.example", "A", _now_minus(20))
    _g("flip.example", "C", _now_minus(5))
    _g("steady.example", "C", _now_minus(20))
    _g("steady.example", "D", _now_minus(3))           # within C-F: not a change
    out = changes.feed()
    named = [(e["domain"], e["kind"]) for e in out["events"] if e["named"]]
    assert named == [("flip.example", "not_ready"), ("acme.example", "ready")]
    titles = [e["title"] for e in out["events"]]
    assert titles[1].startswith("acme.example became post-quantum ready: grade C to A")
    assert "flip.example dropped below B: grade A to C; key exchange x25519 only" in titles[0]
    for word in not_ready.BANNED_WORDS:
        assert word not in " ".join(titles).lower(), word


def test_a_first_grade_is_not_a_change_and_typed_domains_are_never_named():
    tranco.store(["new.example"], "T")
    _g("new.example", "C", _now_minus(2))
    _g("someone-typed.example", "C", _now_minus(9))
    _g("someone-typed.example", "A", _now_minus(1))
    assert changes.feed()["events"] == []


def test_opted_out_domains_never_appear(monkeypatch):
    tranco.store(["quiet.example"], "T")
    _g("quiet.example", "C", _now_minus(9))
    _g("quiet.example", "A", _now_minus(1))
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example")
    changes.clear_cache()
    assert "quiet.example" not in changes.atom("https://m.example")
    assert "quiet.example" not in changes.rss("https://m.example")
    assert changes.feed()["count"] == 0


def test_sector_lists_are_counted_never_named():
    _g("bank1.example", "C", _now_minus(30))
    _g("bank1.example", "A", _now_minus(2))
    _g("bank2.example", "C", _now_minus(30))
    _g("bank2.example", "B", _now_minus(2))
    out = changes.feed("finance")
    assert [e["kind"] for e in out["events"]] == ["sector"]
    e = out["events"][0]
    assert e["became_ready"] == 2 and not e["named"] and "bank1" not in e["title"] and e["page"] == "/report/finance"
    assert e["title"].startswith("2 sites in Banks became post-quantum ready in the week of")


def test_a_self_listed_domain_is_named_only_as_listed(monkeypatch):
    from services import pq_ready

    monkeypatch.setattr(pq_ready, "public_list", lambda order="name": {"entries": [
        {"domain": "proud.example", "sector": "unclassified", "sector_name": "Other", "grade": "A",
         "checked_at": _now_minus(1), "joined_at": _now_minus(1)}]})
    _g("proud.example", "A", _now_minus(9))
    _g("proud.example", "C", _now_minus(1))               # not in Tranco: its drop is never named
    kinds = [(e.get("domain"), e["kind"]) for e in changes.feed()["events"]]
    assert kinds == [("proud.example", "listed")]


def test_owner_replies_travel_with_named_changes(monkeypatch):
    monkeypatch.setattr(not_ready, "_replies", lambda: {"flip.example": {"text": "Fixed on Monday", "at": _now_minus(1)}})
    tranco.store(["flip.example"], "T")
    _g("flip.example", "A", _now_minus(20))
    _g("flip.example", "C", _now_minus(5))
    e = changes.feed()["events"][0]
    assert e["reply"]["text"] == "Fixed on Monday"
    assert "Fixed on Monday" in changes.atom("https://m.example")


def test_feeds_are_well_formed_and_filter_by_sector():
    tranco.store(["acme.example"], "T")
    _g("acme.example", "C", _now_minus(20))
    _g("acme.example", "A", _now_minus(10))
    root = ET.fromstring(changes.atom("https://m.example"))
    entries = root.findall(ATOM + "entry")
    assert len(entries) == 1 and entries[0].find(ATOM + "link").get("href") == "https://m.example/acme.example"
    rss = ET.fromstring(changes.rss("https://m.example"))
    assert rss.find("channel/item/link").text == "https://m.example/acme.example"
    assert changes.feed("finance")["count"] == 0


# ── sector reports ───────────────────────────────────────────────────────────


def test_report_percentages_trend_and_comparison_on_fixtures():
    old = "2026-08-04T00:00:00Z"   # a Tuesday in August
    for d in ("bank1.example", "bank2.example", "bank3.example", "bank4.example"):
        _g(d, "C", old)
    _g("bank1.example", "A", "2026-11-03T00:00:00Z")
    _g("bank2.example", "B", "2026-11-03T00:00:00Z")
    _g("bank3.example", "D", "2026-11-03T00:00:00Z")
    r = sector_report.report("finance")
    assert r["ready"] == 2 and r["ready_share"] == 0.5 and r["sample"]["graded"] == 4 and r["sample"]["listed"] == 4
    assert r["grades"] == {"A": 1, "B": 1, "C": 1, "D": 1, "E": 0, "F": 0}
    assert [p["week"] for p in r["trend"]] == ["2026-08-03", "2026-11-02"]
    assert [p["share"] for p in r["trend"]] == [0.0, 0.5]
    assert r["comparison"]["month"] == "August 2026" and r["comparison"]["change"] == 0.5
    assert r["headline"]["plain"] == "50% of the Banks sites Morrow watches are post-quantum ready, up from 0% in August 2026."
    assert r["as_of"] == "2026-11-03T00:00:00Z"
    assert r["methodology"]["not_measured"] and r["methodology"]["sources"] == ["annual reports"]
    csv_text = sector_report.to_csv(r)
    assert csv_text.split("\r\n")[0].startswith("sector,week_start,graded,ready,ready_share_percent,A,B,C,D,E,F")
    assert "finance,2026-11-02,4,2,50.0,1,1,1,1,0,0" in csv_text


def test_report_sample_states_unreachable_unknown_and_opted_out(monkeypatch):
    _g("bank1.example", "A", "2026-11-03T00:00:00Z")
    league.record_miss("bank2.example", "2026-11-04T00:00:00Z", "unreachable")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "bank4.example")
    r = sector_report.report("finance")
    assert r["sample"] == {"listed": 3, "graded": 1, "unreachable": 1, "not_graded_yet": 1, "opted_out_left_out": 1}
    assert r["comparison"] is None and "no earlier week" in r["headline"]["expert"]


def test_an_unknown_sector_is_a_404_and_the_index_lists_every_sector():
    with pytest.raises(sector_report.ReportError):
        sector_report.report("nope")
    _g("paper.example", "A", "2026-11-03T00:00:00Z")
    sector_report.clear_cache()                          # reports are cached for five minutes
    idx = sector_report.index()
    assert [s["id"] for s in idx["sectors"]] == ["finance", "news"]
    assert idx["ready_share"] == 1.0 and idx["summary"].startswith("100% of the 1 sites")


# ── routes ───────────────────────────────────────────────────────────────────


def test_the_routes_and_their_rate_limit(monkeypatch):
    import app as application

    application.limiter.enabled = False
    _g("bank1.example", "A", "2026-11-03T00:00:00Z")
    with TestClient(application.app, raise_server_exceptions=False) as client:
        assert client.get("/api/public/changes").json()["title"] == "What changed"
        assert client.get("/api/public/changes.atom").headers["content-type"].startswith("application/atom+xml")
        assert client.get("/api/public/changes.rss").headers["content-type"].startswith("application/rss+xml")
        assert client.get("/api/public/report").json()["sectors"][0]["id"] == "finance"
        assert client.get("/api/public/report/finance").json()["ready"] == 1
        c = client.get("/api/public/report/finance.csv")
        assert c.headers["content-type"].startswith("text/csv") and "morrow-finance-" in c.headers["content-disposition"]
        assert client.get("/api/public/report/nope").status_code == 404
        for path in ("/changes", "/report", "/report/finance", "/plain/changes", "/plain/report", "/plain/report/finance"):
            assert client.get(path).status_code == 200, path
        assert "50%" not in client.get("/plain/report/finance").text
        monkeypatch.setenv("MORROW_PUBLIC_REPORTS_IP_PER_MINUTE", "2")
        _limits.reset()
        codes = [client.get("/api/public/report").status_code for _ in range(3)]
        assert codes == [200, 200, 429]
