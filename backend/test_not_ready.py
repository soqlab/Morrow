"""The public "Not yet post-quantum" list: Tranco sites only, measured wording, never ranked, opt-outs
never listed, right of reply for verified owners, corrections recorded. No network."""

import json
import os
import xml.etree.ElementTree as ET

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from db_feature_store import feature_conn
from services import domain_verification, league, not_ready, postgres_rls, tenant_scope, tranco
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

ATOM = "{http://www.w3.org/2005/Atom}"


def _reset():
    for mod in (_check, _grade, league):
        mod._TABLES_READY.clear()
    league._table_cache.clear()
    not_ready._ready = ""
    tranco._ready = ""
    domain_verification._ready = ""
    domain_verification._cache.clear()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "nr.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_LEAGUE_TRANCO_SIZE", "10000")
    monkeypatch.setattr(league, "load_spec", lambda path=None: {"sectors": [
        {"id": "finance", "name": "Banks", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
         "domains": ["bank.example"]}]})
    _reset()
    yield
    _reset()


def _grade_it(domain, grade, when="2026-11-01T00:00:00Z", group="X25519"):
    pq = grade in ("A", "B")
    _grade.store({"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
                  "key_exchange": {"group": "X25519MLKEM768" if pq else group, "post_quantum": pq},
                  "exposure": {"recorded_traffic_at_risk": not pq, "decrypt_year_low": None if pq else 2035,
                               "decrypt_year_high": None if pq else 2040, "source_url": "https://example.org/gri"},
                  "tls": {"versions": {"1.3": True}}, "certificate": {"verified": True},
                  "rubric_version": _grade.RUBRIC_VERSION})


def _tranco(*domains):
    tranco.store(list(domains), "TEST")


def test_only_tranco_domains_appear():
    _tranco("bank.example", "shop.example")
    _grade_it("bank.example", "C")
    _grade_it("shop.example", "D")
    _grade_it("someone-typed-this.example", "C")      # a public check, not in the list
    names = [e["domain"] for e in not_ready.entries()["entries"]]
    assert names == ["bank.example", "shop.example"] or sorted(names) == ["bank.example", "shop.example"]
    assert "someone-typed-this.example" not in json.dumps(not_ready.entries())


def test_the_wording_is_measured_facts_never_labels():
    _tranco("bank.example")
    _grade_it("bank.example", "C", "2026-11-13T09:00:00Z")
    entry = not_ready.entries()["entries"][0]
    assert entry["statement"] == ("bank.example: traffic recorded today could be decrypted around 2035-2040 "
                                  "(checked 2026-11-13). Key exchange: X25519 only.")
    text = json.dumps(not_ready.entries()).lower()
    for word in not_ready.BANNED_WORDS:
        assert word not in text.replace("source_url", ""), word
    assert entry["source_url"] and entry["checked_at"] == "2026-11-13T09:00:00Z"


def test_a_domain_leaves_when_its_grade_improves():
    _tranco("bank.example")
    _grade_it("bank.example", "C", "2026-11-01T00:00:00Z")
    assert not_ready.entries()["count"] == 1
    _grade_it("bank.example", "A", "2026-11-08T00:00:00Z")
    assert not_ready.entries()["count"] == 0
    events = not_ready.changes()
    assert [e["event"] for e in events] == ["left", "joined"]


def test_an_opted_out_domain_never_appears(monkeypatch):
    _tranco("bank.example", "quiet.example")
    _grade_it("bank.example", "C")
    _grade_it("quiet.example", "C")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example")
    names = [e["domain"] for e in not_ready.entries()["entries"]]
    assert names == ["bank.example"]
    assert "quiet.example" not in not_ready.atom("https://m.example")


def test_sorted_by_sector_then_name_and_filterable():
    _tranco("zeta.example", "bank.example", "alpha.example")
    for d in ("zeta.example", "bank.example", "alpha.example"):
        _grade_it(d, "D")
    out = not_ready.entries()
    assert [(e["sector_name"], e["domain"]) for e in out["entries"]] == [
        ("Banks", "bank.example"), ("Other popular sites", "alpha.example"), ("Other popular sites", "zeta.example")]
    assert [e["domain"] for e in not_ready.entries("finance")["entries"]] == ["bank.example"]
    assert "not ranked" in out["methodology"]["not_a_ranking"]
    assert out["methodology"]["rubric_version"] == _grade.RUBRIC_VERSION


def _verify(org, domain):
    domain_verification.add_domain(org, domain)
    with feature_conn() as conn:
        conn.execute("UPDATE org_verified_domains SET status = 'verified' WHERE org_id = ? AND domain = ?", (org, domain))
        conn.commit()
    domain_verification._invalidate(org)


def test_the_right_of_reply_needs_verification_and_is_plain_and_short():
    _tranco("bank.example")
    _grade_it("bank.example", "C")
    with pytest.raises(not_ready.ReplyError) as exc:
        not_ready.set_reply("org-x", "bank.example", "Migration underway")
    assert exc.value.code == "not_verified"
    _verify("org-x", "bank.example")
    with pytest.raises(not_ready.ReplyError):
        not_ready.set_reply("org-x", "bank.example", "x" * 281)
    out = not_ready.set_reply("org-x", "bank.example", "Migration underway,\x00 due Q2 2027\n\n")
    assert out["text"] == "Migration underway, due Q2 2027"
    entry = not_ready.entries()["entries"][0]
    assert entry["reply"]["text"] == "Migration underway, due Q2 2027" and entry["reply"]["at"]
    assert not_ready.delete_reply("org-x", "bank.example") is True
    assert not_ready.entries()["entries"][0]["reply"] is None


def test_the_public_read_of_replies_goes_through_platform_scope(monkeypatch):
    seen = []
    real = tenant_scope.platform_scope

    def spy(reason, actor=""):
        seen.append(reason)
        return real(reason, actor)

    monkeypatch.setattr(tenant_scope, "platform_scope", spy)
    _tranco("bank.example")
    _grade_it("bank.example", "C")
    not_ready.entries()
    assert any("not-yet-post-quantum" in r for r in seen)


def test_replies_are_under_tenant_isolation():
    assert "not_ready_replies" in postgres_rls.ORG_SCOPED_TABLES
    assert postgres_rls.TENANT_COLUMNS["not_ready_replies"] == "org_id"
    assert "not_ready_replies" in postgres_rls.build_rls_sql(tables=["not_ready_replies"])


def test_corrections_are_recorded_and_rate_limited():
    out = not_ready.request_correction("bank.example", "The grade is from before our change.", "ops@bank.example", "203.0.113.9")
    assert out["received"]
    with feature_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM public_correction_requests").fetchone()["n"] == 1
    with pytest.raises(not_ready.ReplyError):
        not_ready.request_correction("bank.example", "short", "x", "203.0.113.9")
    for _ in range(4):
        not_ready.request_correction("bank.example", "Another reason, long enough.", "a@b.example", "203.0.113.9")
    with pytest.raises(not_ready.ReplyError) as exc:
        not_ready.request_correction("bank.example", "Another reason, long enough.", "a@b.example", "203.0.113.9")
    assert exc.value.status_code == 429


def test_the_feed_is_atom_per_sector():
    _tranco("bank.example", "shop.example")
    _grade_it("bank.example", "C")
    _grade_it("shop.example", "D")
    root = ET.fromstring(not_ready.atom("https://m.example", "finance"))
    entries = root.findall(ATOM + "entry")
    assert len(entries) == 1 and "bank.example" in entries[0].find(ATOM + "title").text


def test_the_tranco_list_is_fetched_weekly_and_parsed():
    calls = []

    def fake(url):
        calls.append(url)
        if url == tranco.API:
            return json.dumps({"available": True, "failed": False, "list_id": "L1"}).encode()
        return b"1,Google.com\n2,bad domain\n3,example.org.\n"

    meta = tranco.refresh_if_stale(fetch=fake)
    assert meta["list_id"] == "L1" and tranco.domains() == ["google.com", "example.org"]
    tranco.refresh_if_stale(fetch=fake)
    assert len(calls) == 2                                  # fresh: not fetched again within a week


def test_the_routes(monkeypatch):
    import app as application

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    from db import current_organization_id

    _tranco("bank.example")
    _grade_it("bank.example", "C")
    with TestClient(application.app, raise_server_exceptions=False) as client:
        body = client.get("/api/public/not-ready").json()
        assert body["title"] == "Not yet post-quantum" and body["entries"][0]["domain"] == "bank.example"
        assert client.get("/api/public/not-ready.atom").headers["content-type"].startswith("application/atom+xml")
        r = client.post("/api/public/corrections", json={"domain": "bank.example", "reason": "Please re-check after our change.",
                                                         "contact": "ops@bank.example"})
        assert r.status_code == 201
        org = current_organization_id()
        assert client.put("/instrument/replies/bank.example", json={"text": "Due Q2 2027"},
                          headers={"x-user-role": "admin"}).status_code == 403
        _verify(org, "bank.example")
        assert client.put("/instrument/replies/bank.example", json={"text": "Due Q2 2027"},
                          headers={"x-user-role": "viewer"}).status_code == 403
        ok = client.put("/instrument/replies/bank.example", json={"text": "Due Q2 2027"}, headers={"x-user-role": "admin"})
        assert ok.status_code == 200, ok.text
        assert client.get("/api/public/not-ready").json()["entries"][0]["reply"]["text"] == "Due Q2 2027"


def test_the_list_is_public_and_replies_are_not(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/not-ready").status_code == 200
        assert anonymous.get("/instrument/replies").status_code == 401
        assert anonymous.put("/instrument/replies/x.example", json={"text": "hi"}).status_code == 401
