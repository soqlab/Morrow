"""The instrument's public evidence: decrypt basis, build, deploy log, page file list, league
and per-domain feeds. No network: grade_one and the probe are replaced."""

import importlib.util
import json
import os
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

import policy
from services import build_info, decrypt_window, deploy_log, league, page_manifest
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("verify_deploy", os.path.join(REPO_ROOT, "scripts", "verify-deploy.py"))
verify_deploy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_deploy)

SHA_A = "a" * 40
SHA_B = "b" * 40
ATOM = "{http://www.w3.org/2005/Atom}"


def _reset():
    _check._TABLES_READY.clear()
    _grade._TABLES_READY.clear()
    deploy_log._TABLES_READY.clear()
    deploy_log._RECORDED.clear()
    league._TABLES_READY.clear()
    league._table_cache.clear()
    page_manifest.reset_cache_for_tests()
    _limits.reset()


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    db = tmp_path / "public-instrument.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    for name in build_info.COMMIT_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    _reset()
    yield db
    _reset()


@pytest.fixture
def client(isolated_store, monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def _result(domain, grade="A", scanned_at="2026-11-01T00:00:00Z", pq=True, group="X25519MLKEM768"):
    return {"domain": domain, "scanned_at": scanned_at, "cached": False, "grade": grade,
            "key_exchange": {"group": group, "post_quantum": pq, "hybrid": pq},
            "rubric_version": _grade.RUBRIC_VERSION}


# ── decrypt window ───────────────────────────────────────────────────────────


def test_a_scan_with_ml_kem_is_protected():
    out = decrypt_window.for_scan_result({"scan_status": "ok", "key_exchange_observed": True,
                                          "key_exchange_family": "pq_hybrid", "key_exchange": "X25519MLKEM768"})
    assert out["status"] == "protected" and out["readable_from"] is None
    assert out["key_exchange"] == "X25519MLKEM768" and out["source_url"] == decrypt_window.PQ_SOURCE_URL


def test_a_classical_scan_is_at_risk_from_the_cited_years():
    out = decrypt_window.for_scan_result({"scan_status": "ok", "key_exchange_observed": True,
                                          "key_exchange_family": "classical", "key_exchange": "x25519"})
    assert out["status"] == "at_risk"
    assert (out["readable_from"], out["readable_by"]) == (decrypt_window.DECRYPT_YEAR_LOW, decrypt_window.DECRYPT_YEAR_HIGH)
    assert out["notes"] == []


def test_an_unobserved_key_exchange_is_treated_as_classical_and_says_so():
    out = decrypt_window.for_scan_result({"scan_status": "ok", "key_exchange_observed": False,
                                          "key_exchange_family": "pq_hybrid"})
    assert out["status"] == "at_risk" and out["notes"][0] == decrypt_window.UNOBSERVED_NOTE


def test_a_failed_scan_is_unknown():
    for facts in ({"scan_status": "timeout"}, {"scan_status": "ok", "error": "refused"}):
        out = decrypt_window.for_scan_result(facts)
        assert out["status"] == "unknown" and out["readable_from"] is None


def test_rsa_key_transport_adds_the_static_rsa_note_but_ecdhe_does_not():
    base = {"scan_status": "ok", "key_exchange_observed": True, "key_exchange_family": "classical"}
    rsa = decrypt_window.for_scan_result({**base, "tls12_accepted_ciphers": ["AES128-GCM-SHA256"]})
    assert decrypt_window.STATIC_RSA_NOTE in rsa["notes"]
    fs = decrypt_window.for_scan_result({**base, "tls12_accepted_ciphers": ["ECDHE-RSA-AES128-GCM-SHA256",
                                                                            "DHE-RSA-AES128-GCM-SHA256"]})
    assert fs["notes"] == []


def test_secret_outlives():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert decrypt_window.secret_outlives(None) is None
    assert decrypt_window.secret_outlives("x") is None
    long = decrypt_window.secret_outlives(30, now)
    assert long == {"secret_until": 2056, "earliest_decrypt": 2035, "exposed": True, "years_exposed": 21}
    short = decrypt_window.secret_outlives(1, now)
    assert short["exposed"] is False and short["years_exposed"] == 0


def test_the_console_scan_result_carries_the_decrypt_window():
    facts = {"scan_status": "ok", "key_exchange_observed": True, "key_exchange_family": "classical",
             "key_exchange": "x25519", "key_type": "RSA", "tls_version": "TLSv1.3"}
    out = policy.derive_quantum_readiness(facts, [])
    assert out["decrypt_window"] == decrypt_window.for_scan_result(facts)
    assert "harvest_now_decrypt_later_risk" in out


def test_the_public_grade_exposure_is_the_decrypt_window_one():
    assert _grade.DECRYPT_YEAR_LOW == decrypt_window.DECRYPT_YEAR_LOW
    assert _grade.EXPOSURE_BASIS == decrypt_window.EXPOSURE_BASIS
    facts = _grade.empty_facts("example.com", "93.184.216.34")
    facts.update({"tls": True, "kx_family": "classical", "certificate_verified": True,
                  "tls_versions": {"1.3": True}})
    assert _grade.grade_from_facts(facts)["exposure"] == decrypt_window.exposure(True, False)


def test_basis_route(client):
    response = client.get("/api/public/basis")
    assert response.status_code == 200 and response.json() == decrypt_window.basis()


# ── build info ───────────────────────────────────────────────────────────────


def test_the_commit_comes_from_the_first_set_variable_and_is_never_invented(monkeypatch):
    assert build_info.commit_and_source() == (None, None)
    monkeypatch.setenv("GIT_COMMIT", SHA_B)
    assert build_info.commit_and_source() == (SHA_B, "GIT_COMMIT")
    monkeypatch.setenv("RENDER_GIT_COMMIT", SHA_A)
    assert build_info.commit_and_source() == (SHA_A, "RENDER_GIT_COMMIT")
    monkeypatch.setenv("MORROW_GIT_COMMIT", "not-a-sha")
    assert build_info.commit_and_source() == (None, None)
    monkeypatch.setenv("MORROW_GIT_COMMIT", "ABCDEF1")  # upper case is not what git prints
    assert build_info.commit() is None
    monkeypatch.setenv("MORROW_GIT_COMMIT", "abc12")  # too short
    assert build_info.commit() is None


def test_build_route(client, monkeypatch):
    body = client.get("/api/public/build").json()
    assert body["commit"] is None and body["commit_url"] is None and body["source"] is None
    monkeypatch.setenv("RENDER_GIT_COMMIT", SHA_A)
    body = client.get("/api/public/build").json()
    assert set(body) == {"commit", "commit_short", "source", "repository", "commit_url", "started_at",
                         "rubric_version", "python"}
    assert body["commit"] == SHA_A and body["commit_short"] == SHA_A[:12] and body["source"] == "RENDER_GIT_COMMIT"
    assert body["commit_url"] == "https://github.com/soqlab/Morrow/commit/" + SHA_A
    assert body["rubric_version"] == _grade.RUBRIC_VERSION and body["python"].count(".") == 2


# ── deploy log ───────────────────────────────────────────────────────────────


def test_the_deploy_log_appends_only_when_the_commit_changes():
    assert deploy_log.record(commit=None) is None  # no commit known: nothing
    first = deploy_log.record(SHA_A, now="2026-11-01T00:00:00Z")
    assert first["seq"] == 1 and first["prev_hash"] == deploy_log.GENESIS_HASH
    assert deploy_log.record(SHA_A) is None  # a restart of the same commit
    second = deploy_log.record(SHA_B, now="2026-11-02T00:00:00Z")
    assert second["seq"] == 2 and second["prev_hash"] == first["entry_hash"]
    third = deploy_log.record(SHA_A, now="2026-11-03T00:00:00Z")  # a rollback is a new entry
    assert third["seq"] == 3
    listing = deploy_log.listing()
    assert [e["seq"] for e in listing["entries"]] == [3, 2, 1]
    assert listing["head_hash"] == third["entry_hash"] and listing["chain_ok"] is True and listing["count"] == 3
    assert deploy_log.listing(limit=1)["entries"][0]["seq"] == 3


def test_the_entry_hash_is_sha256_of_canonical_json():
    import hashlib

    entry = deploy_log.record(SHA_A, now="2026-11-01T00:00:00Z")
    raw = json.dumps({"commit": SHA_A, "first_seen": "2026-11-01T00:00:00Z", "prev_hash": "0" * 64, "seq": 1},
                     separators=(",", ":"), sort_keys=True).encode()
    assert entry["entry_hash"] == hashlib.sha256(raw).hexdigest()


def test_an_edited_row_breaks_the_chain():
    from db_feature_store import feature_conn

    deploy_log.record(SHA_A, now="2026-11-01T00:00:00Z")
    deploy_log.record(SHA_B, now="2026-11-02T00:00:00Z")
    with feature_conn() as conn:
        conn.execute("UPDATE public_deploy_log SET first_seen = '2026-10-01T00:00:00Z' WHERE seq = 1")
        conn.commit()
    assert deploy_log.listing()["chain_ok"] is False


def test_two_replicas_starting_together_append_once(monkeypatch):
    """Both read the same newest row; the primary key on seq lets one win, the other re-reads."""
    deploy_log.record(SHA_A, now="2026-11-01T00:00:00Z")
    real_last = deploy_log._last
    stale = {"row": None, "calls": 0}

    def racing_last(conn):
        stale["calls"] += 1
        if stale["calls"] == 1:
            stale["row"] = real_last(conn)
            deploy_log.record(SHA_B, now="2026-11-02T00:00:00Z", attempts=1)  # the other replica wins
            return stale["row"]
        return real_last(conn)

    monkeypatch.setattr(deploy_log, "_last", racing_last)
    assert deploy_log.record(SHA_B) is None
    monkeypatch.setattr(deploy_log, "_last", real_last)
    listing = deploy_log.listing()
    assert listing["count"] == 2 and listing["chain_ok"] is True


def test_concurrent_records_of_one_commit_leave_one_row():
    deploy_log.init_tables()
    threads = [threading.Thread(target=deploy_log.record, args=(SHA_A,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert deploy_log.listing()["count"] == 1


def test_startup_records_the_running_commit_once(isolated_store, monkeypatch):
    monkeypatch.setenv("MORROW_GIT_COMMIT", SHA_A)
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    with TestClient(application.app) as c:
        body = c.get("/api/public/deploys").json()
    assert body["count"] == 1 and body["entries"][0]["commit"] == SHA_A and body["chain_ok"] is True
    deploy_log._RECORDED.clear()
    with TestClient(application.app) as c:  # a restart of the same commit
        assert c.get("/api/public/deploys").json()["count"] == 1
    assert set(body) >= {"entries", "head_hash", "chain_ok", "count"}


def test_the_verifier_checks_the_chain_the_same_way():
    for sha, day in ((SHA_A, 1), (SHA_B, 2), (SHA_A, 3)):
        deploy_log.record(sha, now=f"2026-11-0{day}T00:00:00Z")
    listing = deploy_log.listing()
    assert verify_deploy.check_chain(listing["entries"], listing["count"], listing["head_hash"]) == []
    partial = deploy_log.listing(limit=2)  # the newest two: links and hashes, not genesis
    assert verify_deploy.check_chain(partial["entries"], partial["count"], partial["head_hash"]) == []
    tampered = [dict(e) for e in listing["entries"]]
    tampered[1]["commit"] = "c" * 40
    assert verify_deploy.check_chain(tampered, listing["count"], listing["head_hash"])
    assert verify_deploy.check_chain(listing["entries"][:2], 2, listing["head_hash"])  # genesis missing


# ── page file list ─────────────────────────────────────────────────────


@pytest.fixture
def static_dir(tmp_path):
    root = tmp_path / "static"
    (root / "fonts").mkdir(parents=True)
    (root / ".hidden").mkdir()
    (root / "index.html").write_bytes(b"<!doctype html>\n<p>hello</p>\n")
    (root / "fonts" / "a.woff2").write_bytes(b"\x00\x01font")
    (root / ".DS_Store").write_bytes(b"junk")
    (root / ".hidden" / "x.js").write_bytes(b"junk")
    return root



def test_the_manifest_lists_every_file_including_fonts_and_skips_dotfiles(static_dir):
    import hashlib

    files = page_manifest.files(str(static_dir))
    assert [f["path"] for f in files] == ["/ui/fonts/a.woff2", "/ui/index.html"]
    assert files[1]["sha256"] == hashlib.sha256(b"<!doctype html>\n<p>hello</p>\n").hexdigest()
    assert files[1]["bytes"] == len(b"<!doctype html>\n<p>hello</p>\n")


def test_the_manifest_names_the_running_commit_and_carries_no_signature(static_dir, monkeypatch):
    monkeypatch.setenv("MORROW_GIT_COMMIT", SHA_A)
    m = page_manifest.manifest(str(static_dir))
    assert m["format"] == "morrow.page-files/v1" and m["commit"] == SHA_A
    assert set(m) == {"format", "commit", "generated_at", "files"}


def test_manifest_route_covers_the_real_static_directory(client):
    response = client.get("/api/public/manifest")
    assert response.status_code == 200 and "max-age=60" in response.headers["cache-control"]
    body = response.json()
    assert set(body) == {"format", "commit", "generated_at", "files"}
    on_disk = page_manifest.compute_files(page_manifest.STATIC_DIR)
    assert body["files"] == on_disk and any(f["path"].startswith("/ui/fonts/") for f in on_disk)


def test_the_verifier_compares_files_with_the_commit(static_dir):
    files = page_manifest.compute_files(str(static_dir))
    blobs = {"index.html": b"<!doctype html>\n<p>hello</p>\n", "fonts/a.woff2": b"\x00\x01font"}
    assert verify_deploy.check_files(files, blobs.get, list(blobs)) == []
    changed = dict(blobs, **{"index.html": b"<p>other</p>"})
    assert any("sha256" in p for p in verify_deploy.check_files(files, changed.get, list(changed)))
    assert any("not in the commit" in p for p in verify_deploy.check_files(files, {"index.html": blobs["index.html"]}.get))
    assert any("missing from the manifest" in p
               for p in verify_deploy.check_files(files, blobs.get, list(blobs) + ["new.js"]))
    assert verify_deploy.check_files([{"path": "/etc/passwd", "sha256": "", "bytes": 0}], blobs.get)


# ── league ───────────────────────────────────────────────────────────────────


def test_the_classifier_never_guesses():
    c = league.Classifier(league.load_spec())
    assert c.classify("paypal.com") == "finance"
    assert c.classify("www.paypal.com") == "finance"
    assert c.classify("medicare.gov") == "healthcare"  # exact beats the .gov suffix
    assert c.classify("irs.gov") == "government"
    assert c.classify("ox.ac.uk") == "education"
    assert c.classify("bank-of-example.com") == "unclassified"
    assert c.classify("governmentnews.com") == "unclassified"


def test_the_league_list_is_every_explicit_domain_once():
    spec = league.load_spec()
    domains = league.league_list(spec)
    assert len(domains) == len(set(domains))
    explicit = {d.lower() for s in spec["sectors"] for d in s["domains"]}
    assert set(domains) == explicit and len(domains) >= 800


@pytest.fixture
def small_league(monkeypatch):
    spec = {"sectors": [
        {"id": "finance", "name": "Banks", "method": "named", "sources": ["s"], "suffixes": [], "suffix_patterns": [],
         "domains": ["bank.example", "pay.example", "optout.example"]},
        {"id": "tech", "name": "Tech", "method": "named", "sources": [], "suffixes": [], "suffix_patterns": [],
         "domains": ["cloud.example", "bank.example"]},
    ]}
    monkeypatch.setattr(league, "load_spec", lambda path=None: spec)
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "optout.example")
    calls = []
    outcomes = {"bank.example": "A", "pay.example": "C", "cloud.example": None}

    def fake_grade_one(domain, timeout=8.0):
        calls.append(domain)
        now = _grade.iso(_grade.now_utc())
        if outcomes.get(domain) is None:
            return {"domain": domain, "scanned_at": now, "error": "unreachable", "detail": "no answer"}
        return _result(domain, outcomes[domain], now, pq=outcomes[domain] in ("A", "B"))

    monkeypatch.setattr(_grade, "grade_one", fake_grade_one)
    return {"calls": calls, "outcomes": outcomes, "spec": spec}


def test_a_tick_grades_due_domains_once_a_week_and_skips_opt_outs(small_league):
    run = league.tick(10)
    assert sorted(small_league["calls"]) == ["bank.example", "cloud.example", "pay.example"]
    assert run["graded"] == 2 and run["failed"] == 1 and run["skipped"] == 1
    assert _grade.history("bank.example")[0]["grade"] == "A"  # stored like any public grade
    small_league["calls"].clear()
    again = league.tick(10)
    assert small_league["calls"] == [] and again["graded"] == 0  # nothing is due for a week, misses included
    assert league.last_run()["finished_at"]


def test_a_tick_is_bounded(small_league):
    league.tick(1)
    assert len(small_league["calls"]) == 1


def test_a_domain_is_due_again_after_seven_days(small_league):
    old = _grade.iso(_grade.now_utc() - timedelta(days=8))
    _grade.store(_result("bank.example", "A", old))
    _grade.store(_result("pay.example", "C", _grade.iso(_grade.now_utc())))
    league.record_miss("cloud.example", _grade.iso(_grade.now_utc()), "unreachable")
    assert league.due_domains(10) == ["optout.example", "bank.example"]  # never tried first; tick skips opt-outs


def test_the_table_reports_stored_data_only(small_league):
    _grade.store(_result("bank.example", "C", "2026-10-01T00:00:00Z", pq=False, group="x25519"))
    _grade.store(_result("bank.example", "C", "2026-10-08T00:00:00Z", pq=False, group="x25519"))
    _grade.store(_result("bank.example", "A", "2026-10-15T00:00:00Z"))
    _grade.store(_result("bank.example", "A", "2026-10-22T00:00:00Z"))
    league.record_miss("cloud.example", "2026-10-22T00:00:00Z", "unreachable")
    body = league.table()
    assert body["list_size"] == 3 and body["graded"] == 1 and body["total"] == 3  # opt-out left out
    rows = {r["domain"]: r for r in body["rows"]}
    assert rows["bank.example"] == {"domain": "bank.example", "sector": "finance", "grade": "A",
                                    "previous_grade": "C", "changed_at": "2026-10-15T00:00:00Z",
                                    "group": "X25519MLKEM768", "post_quantum": True,
                                    "scanned_at": "2026-10-22T00:00:00Z", "miss": None}
    assert rows["cloud.example"]["grade"] is None and rows["cloud.example"]["miss"] == "unreachable"
    assert rows["cloud.example"]["sector"] == "tech"
    assert rows["pay.example"]["grade"] is None and rows["pay.example"]["miss"] is None
    finance = next(s for s in body["sectors"] if s["id"] == "finance")
    assert finance["count"] == 2 and finance["graded"] == 1 and finance["grades"]["A"] == 1
    assert finance["pq_share"] == 1.0 and finance["sources"] == ["s"]
    tech = next(s for s in body["sectors"] if s["id"] == "tech")
    assert tech["pq_share"] is None
    assert body["last_run"] is None and body["rubric_version"] == _grade.RUBRIC_VERSION


def test_the_table_filters_sorts_and_pages(small_league):
    _grade.store(_result("bank.example", "A", "2026-10-22T00:00:00Z"))
    _grade.store(_result("pay.example", "D", "2026-10-21T00:00:00Z", pq=False))
    assert [r["domain"] for r in league.table(sort="grade")["rows"]] == ["bank.example", "pay.example", "cloud.example"]
    assert [r["domain"] for r in league.table(sort="grade", direction="desc")["rows"]] == \
        ["pay.example", "bank.example", "cloud.example"]
    assert [r["domain"] for r in league.table(sort="scanned")["rows"]] == ["pay.example", "bank.example", "cloud.example"]
    assert [r["domain"] for r in league.table(sort="domain", direction="desc")["rows"]] == \
        ["pay.example", "cloud.example", "bank.example"]
    assert [r["domain"] for r in league.table(sector="tech")["rows"]] == ["cloud.example"]
    assert [r["domain"] for r in league.table(q="pay")["rows"]] == ["pay.example"]
    paged = league.table(sort="domain", limit=1, offset=1)
    assert [r["domain"] for r in paged["rows"]] == ["cloud.example"] and paged["total"] == 3


def test_league_route_and_cli(client, small_league, capsys):
    assert league.main(["--tick", "--max", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["graded"] == 2
    league._table_cache.clear()
    # Public: sector averages and their trend only. No site is named, whatever the parameters say.
    body = client.get("/api/public/league?sector=finance&sort=domain&limit=600").json()
    assert set(body) == {"generated_at", "rubric_version", "list_size", "graded", "sectors", "last_run",
                         "names_published"}
    assert body["names_published"] is False and "rows" not in body
    text = json.dumps(body)
    assert "bank.example" not in text and "pay.example" not in text and "cloud.example" not in text
    finance = next(s for s in body["sectors"] if s["id"] == "finance")
    assert finance["graded"] == 2 and finance["trend"] and finance["trend"][-1]["graded"] == 2
    assert body["last_run"]["graded"] == 2


def test_the_celery_task_honours_the_switch(monkeypatch, small_league):
    tasks = pytest.importorskip("tasks")
    assert "league-tick-every-15m" in (tasks.celery_app.conf.beat_schedule or {})
    monkeypatch.setenv("MORROW_LEAGUE_SCAN", "0")
    assert tasks.league_tick_task.run() == {"disabled": True}
    assert small_league["calls"] == []
    monkeypatch.setenv("MORROW_LEAGUE_SCAN", "1")
    assert tasks.league_tick_task.run(2)["graded"] == 2


# ── per-domain history detail and feed ───────────────────────────────────────


def _seed_history():
    for when, grade in (("2026-10-01T00:00:00Z", "C"), ("2026-10-08T00:00:00Z", "C"),
                        ("2026-10-15T00:00:00Z", "A"), ("2026-10-22T00:00:00Z", "B")):
        _grade.store(_result("example.com", grade, when, pq=grade != "C"))


def test_history_detail_includes_each_full_result(client):
    _seed_history()
    plain = client.get("/api/public/history/example.com").json()
    assert "result" not in plain[0]
    detail = client.get("/api/public/history/example.com?detail=1&limit=500").json()
    assert len(detail) == 4 and detail[0]["result"]["grade"] == "B" and detail[0]["result"]["domain"] == "example.com"


def test_the_atom_feed_has_one_entry_per_change_newest_first(client):
    _seed_history()
    response = client.get("/api/public/history/example.com.atom")
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/atom+xml")
    root = ET.fromstring(response.content)
    assert root.tag == ATOM + "feed" and root.find(ATOM + "id").text and root.find(ATOM + "updated").text
    entries = root.findall(ATOM + "entry")
    assert [e.find(ATOM + "updated").text for e in entries] == \
        ["2026-10-22T00:00:00Z", "2026-10-15T00:00:00Z", "2026-10-01T00:00:00Z"]
    ids = [e.find(ATOM + "id").text for e in entries]
    assert len(set(ids)) == 3 and all(e.find(ATOM + "title").text for e in entries)
    assert "A to B" in entries[0].find(ATOM + "title").text
    assert root.find(ATOM + "updated").text == "2026-10-22T00:00:00Z"


def test_an_empty_feed_is_still_valid(client):
    root = ET.fromstring(client.get("/api/public/history/never.example.atom").content)
    assert root.findall(ATOM + "entry") == [] and root.find(ATOM + "updated").text


def test_the_feed_respects_the_opt_out(client, monkeypatch):
    _seed_history()
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    assert client.get("/api/public/history/example.com.atom").status_code == 403
    assert client.get("/api/public/history/www.example.com.atom").status_code == 403
    assert client.get("/api/public/history/example.com").status_code == 403


def test_the_new_public_routes_are_anonymous(isolated_store, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        for path in ("/api/public/basis", "/api/public/build", "/api/public/deploys", "/api/public/manifest",
                     "/api/public/league", "/api/public/history/example.com.atom"):
            assert anonymous.get(path).status_code == 200, path


def test_the_new_tables_carry_no_organization_column(isolated_store):
    import sqlite3

    deploy_log.init_tables()
    league.init_tables()
    conn = sqlite3.connect(str(isolated_store))
    try:
        for table in ("public_deploy_log", "public_league_misses", "public_league_runs"):
            columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            assert columns and not columns & {"organization_id", "org_id"}, table
    finally:
        conn.close()


def test_verify_deploy_end_to_end_against_this_server(static_dir, monkeypatch):
    """run() with the HTTP fetches answered by the app's own services and git replaced by a dict."""
    import io

    monkeypatch.setenv("MORROW_GIT_COMMIT", SHA_A)
    deploy_log.record(SHA_A)
    blobs = {"index.html": b"<!doctype html>\n<p>hello</p>\n", "fonts/a.woff2": b"\x00\x01font"}
    answers = {
        "/api/public/build": build_info.info(),
        "/api/public/manifest": page_manifest.manifest(str(static_dir)),
        "/api/public/deploys?limit=500": deploy_log.listing(500),
    }
    monkeypatch.setattr(verify_deploy, "fetch_json", lambda url, timeout=20.0: json.loads(json.dumps(
        answers[url[len("https://morrow.example"):]])))
    monkeypatch.setattr(verify_deploy, "git_static_names", lambda repo, commit: list(blobs))
    monkeypatch.setattr(verify_deploy, "git_blob_reader", lambda repo, commit: blobs.get)
    out = io.StringIO()
    assert verify_deploy.run("https://morrow.example/", ".", out=out) == 0, out.getvalue()
    blobs["index.html"] = b"<p>changed</p>"
    out = io.StringIO()
    assert verify_deploy.run("https://morrow.example", ".", out=out) == 1 and "sha256" in out.getvalue()


def test_an_organisation_sees_its_own_rank_privately(client, small_league, monkeypatch):
    league.tick(10)
    league._table_cache.clear()
    # A verified domain of the organisation that has a public grade is ranked within its sector.
    rank = league.private_rank(["pay.example", "never-graded.example"])
    pay = rank["domains"][0]
    assert pay["sector"] == "finance" and pay["grade"] == "C"
    assert pay["compared_with"] == 1 and (pay["better"], pay["same"], pay["worse"]) == (1, 0, 0)
    assert rank["domains"][1]["grade"] is None and "better" not in rank["domains"][1]
    from services import domain_verification

    monkeypatch.setattr(domain_verification, "verified_domains", lambda org_id: ["pay.example"])
    body = client.get("/instrument/rank").json()
    assert body["verified_domains"] == 1 and body["domains"][0]["domain"] == "pay.example"
    # Only the organisation's own domains appear; no other site is named.
    assert "bank.example" not in json.dumps(body)


def test_the_private_rank_is_not_public(isolated_store, monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/instrument/rank").status_code == 401
