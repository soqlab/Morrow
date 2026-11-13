"""The opt-in public post-quantum ready list: nobody is listed without choosing it, only verified
domains graded A or B can be, and a grade drop takes an entry off the list. No network."""

import os
import xml.etree.ElementTree as ET

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from db_feature_store import feature_conn
from services import domain_verification, league, postgres_rls, pq_ready
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

ORG = "org-ready-1"
OTHER = "org-ready-2"
ATOM = "{http://www.w3.org/2005/Atom}"


def _reset():
    _check._TABLES_READY.clear()
    _grade._TABLES_READY.clear()
    league._TABLES_READY.clear()
    league._table_cache.clear()
    pq_ready._ready = ""
    domain_verification._ready = ""
    domain_verification._cache.clear()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "ready.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    _reset()
    yield
    _reset()


def _verify(org, domain):
    domain_verification.add_domain(org, domain)
    with feature_conn() as conn:
        conn.execute("UPDATE org_verified_domains SET status = 'verified', verified_at = '2026-11-01T00:00:00Z' "
                     "WHERE org_id = ? AND domain = ?", (org, domain))
        conn.commit()
    domain_verification._invalidate(org)


def _grade_it(domain, grade, when="2026-11-01T00:00:00Z"):
    _grade.store({"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
                  "key_exchange": {"group": "X25519MLKEM768", "post_quantum": grade in ("A", "B")},
                  "rubric_version": _grade.RUBRIC_VERSION})


def test_a_verified_domain_graded_a_can_opt_in_and_appears_publicly():
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "A")
    assert pq_ready.public_list()["entries"] == []          # verified and A, but not chosen: not listed
    out = pq_ready.opt_in(ORG, "ready.example", "admin-1")
    assert out["listed"] and out["grade"] == "A"
    entries = pq_ready.public_list()["entries"]
    assert [e["domain"] for e in entries] == ["ready.example"]
    assert set(entries[0]) == {"domain", "sector", "sector_name", "grade", "checked_at", "joined_at"}


def test_opting_out_removes_the_entry_at_once():
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "B")
    pq_ready.opt_in(ORG, "ready.example")
    pq_ready.opt_out(ORG, "ready.example")
    assert pq_ready.public_list()["entries"] == []
    mine = pq_ready.for_org(ORG)[0]
    assert mine["listed"] is False and "Opted out" in mine["removed_reason"]


def test_an_unverified_domain_is_refused():
    _grade_it("someone-else.example", "A")
    with pytest.raises(pq_ready.ListingError) as exc:
        pq_ready.opt_in(ORG, "someone-else.example")
    assert exc.value.code == "not_verified"
    _verify(OTHER, "theirs.example")
    _grade_it("theirs.example", "A")
    with pytest.raises(pq_ready.ListingError):
        pq_ready.opt_in(ORG, "theirs.example")              # verified by another organisation only
    assert pq_ready.public_list()["entries"] == []


@pytest.mark.parametrize("grade", ["C", "D", "E", "F"])
def test_grade_c_or_worse_is_refused(grade):
    _verify(ORG, "weak.example")
    _grade_it("weak.example", grade)
    with pytest.raises(pq_ready.ListingError) as exc:
        pq_ready.opt_in(ORG, "weak.example")
    assert exc.value.code == "grade_too_low" and exc.value.status_code == 409


def test_an_ungraded_domain_is_refused():
    _verify(ORG, "new.example")
    with pytest.raises(pq_ready.ListingError) as exc:
        pq_ready.opt_in(ORG, "new.example")
    assert exc.value.code == "not_graded"


def test_a_grade_drop_removes_the_entry_on_the_weekly_recheck_and_says_why():
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "A", "2026-11-01T00:00:00Z")
    pq_ready.opt_in(ORG, "ready.example")
    _grade_it("ready.example", "C", "2026-11-08T00:00:00Z")
    assert pq_ready.refresh() == {"kept": 0, "removed": 1}
    assert pq_ready.public_list()["entries"] == []
    mine = pq_ready.for_org(ORG)[0]
    assert mine["listed"] is False and "graded it C" in mine["removed_reason"] and "2026-11-08" in mine["removed_reason"]


def test_losing_verification_removes_the_entry():
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "A")
    pq_ready.opt_in(ORG, "ready.example")
    domain_verification.remove_domain(ORG, "ready.example")
    assert pq_ready.refresh()["removed"] == 1
    assert pq_ready.public_list()["entries"] == []


def test_the_weekly_tick_regrades_listed_domains_and_rechecks(monkeypatch):
    monkeypatch.setattr(league, "load_spec", lambda path=None: {"sectors": []})
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "A", "2026-10-01T00:00:00Z")
    pq_ready.opt_in(ORG, "ready.example")
    calls = []

    def fake_grade_one(domain, timeout=8.0):
        calls.append(domain)
        return {"domain": domain, "scanned_at": _grade.iso(_grade.now_utc()), "cached": False, "grade": "D",
                "key_exchange": {"group": "X25519", "post_quantum": False}, "rubric_version": _grade.RUBRIC_VERSION}

    monkeypatch.setattr(_grade, "grade_one", fake_grade_one)
    run = league.tick(5)
    assert calls == ["ready.example"]
    assert run["pq_ready"] == {"kept": 0, "removed": 1}
    assert pq_ready.public_list()["entries"] == []


def test_the_list_is_alphabetical_or_by_date_joined_never_ranked():
    for name, when in (("b.example", "A"), ("a.example", "B"), ("c.example", "A")):
        _verify(ORG, name)
        _grade_it(name, when)
        pq_ready.opt_in(ORG, name)
    names = [e["domain"] for e in pq_ready.public_list("name")["entries"]]
    assert names == ["a.example", "b.example", "c.example"]
    joined = pq_ready.public_list("joined")
    assert joined["order"] == "joined" and len(joined["entries"]) == 3
    assert "Not a ranking" in joined["about"]


def test_the_feed_is_atom_and_lists_only_opted_in_domains():
    _verify(ORG, "ready.example")
    _grade_it("ready.example", "A")
    _verify(ORG, "quiet.example")
    _grade_it("quiet.example", "A")
    pq_ready.opt_in(ORG, "ready.example")
    root = ET.fromstring(pq_ready.atom("https://morrow.example"))
    entries = root.findall(ATOM + "entry")
    assert len(entries) == 1
    assert entries[0].find(ATOM + "link").get("href") == "https://morrow.example/ready.example"
    assert "quiet.example" not in pq_ready.atom("https://morrow.example")


def test_the_table_is_under_tenant_isolation():
    assert "pq_ready_listings" in postgres_rls.ORG_SCOPED_TABLES
    assert postgres_rls.TENANT_COLUMNS["pq_ready_listings"] == "org_id"
    sql = postgres_rls.build_rls_sql(tables=["pq_ready_listings"])
    assert "pq_ready_listings" in sql and "org_id" in sql
    assert "pq_ready_listings" in postgres_rls.build_rls_plan()["tables"]


def test_the_routes(monkeypatch):
    import app as application

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    from db import current_organization_id

    with TestClient(application.app, raise_server_exceptions=False) as client:
        org = current_organization_id()
        _verify(org, "ready.example")
        _grade_it("ready.example", "A")
        assert client.get("/api/public/pq-ready").json()["entries"] == []
        # A viewer cannot list; an admin can.
        assert client.put("/instrument/pq-ready/ready.example", json={"listed": True},
                          headers={"x-user-role": "viewer"}).status_code == 403
        r = client.put("/instrument/pq-ready/ready.example", json={"listed": True}, headers={"x-user-role": "admin"})
        assert r.status_code == 200, r.text
        assert [e["domain"] for e in client.get("/api/public/pq-ready").json()["entries"]] == ["ready.example"]
        assert client.get("/api/public/pq-ready.atom").headers["content-type"].startswith("application/atom+xml")
        mine = client.get("/instrument/pq-ready", headers={"x-user-role": "viewer"}).json()["domains"]
        assert mine[0]["listed"] is True
        refused = client.put("/instrument/pq-ready/not-mine.example", json={"listed": True}, headers={"x-user-role": "admin"})
        assert refused.status_code == 403 and "not verified" in refused.json()["detail"]
        assert client.put("/instrument/pq-ready/ready.example", json={"listed": False},
                          headers={"x-user-role": "admin"}).status_code == 200
        assert client.get("/api/public/pq-ready").json()["entries"] == []


def test_the_public_list_needs_no_account_and_the_admin_routes_do(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/pq-ready").status_code == 200
        assert anonymous.get("/api/public/pq-ready.atom").status_code == 200
        assert anonymous.get("/instrument/pq-ready").status_code == 401
        assert anonymous.put("/instrument/pq-ready/x.example", json={"listed": True}).status_code == 401
