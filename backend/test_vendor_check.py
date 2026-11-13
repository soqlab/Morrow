"""Vendor check: parsing and caps, the SSRF guard, job progress, the report link (valid, expired,
revoked), CSV, the answer sentence and notes, rate limits, saved lists and their routes. No network."""

import json
import os
import time

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from db_feature_store import feature_conn
from services import alert_routing, postgres_rls, tenant_scope, vendor_check
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade


def _reset():
    for mod in (_check, _grade):
        mod._TABLES_READY.clear()
    vendor_check._ready = ""
    vendor_check._active.clear()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "vc.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    # The rate limits under test count in this process: with REDIS_URL or CELERY_BROKER_URL set
    # (as in CI) they would count in Redis, which org_rate_limits.reset() does not clear.
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    _reset()
    yield
    _reset()


def _result(domain, grade, when=None, group=None, fs=True, verified=True, versions=None):
    pq = grade in ("A", "B")
    return {"domain": domain, "scanned_at": when or _grade.iso(_grade.now_utc()), "cached": False, "grade": grade,
            "key_exchange": {"group": group or ("X25519MLKEM768" if pq else "x25519"), "post_quantum": pq},
            "exposure": {"recorded_traffic_at_risk": not pq, "decrypt_year_low": None if pq else 2035,
                         "decrypt_year_high": None if pq else 2040},
            "tls": {"versions": versions if versions is not None else {"1.3": True, "1.2": True}},
            "certificate": {"verified": verified}, "forward_secrecy": fs, "rubric_version": _grade.RUBRIC_VERSION}


FAKE = {
    "payroll.example": _result("payroll.example", "F", fs=False, versions={"1.2": True}),
    "crm.example": _result("crm.example", "C"),
    "mail.example": _result("mail.example", "A"),
}


@pytest.fixture
def fake_check(monkeypatch):
    calls = []

    def check(host, client_ip="", fresh=False, charge=True, cache_only=False):
        calls.append(host)
        if host in FAKE:
            return dict(FAKE[host])
        raise _grade.GradeError(504, "unreachable", f"{host} did not accept a connection on port 443 in time.")

    monkeypatch.setattr(_grade, "check", check)
    monkeypatch.setattr(vendor_check, "kick", lambda report_id: False)
    return calls


# ── parsing ──────────────────────────────────────────────────────────────────


def test_parse_takes_hosts_and_urls_dedupes_and_skips_the_rest():
    text = ("Vendor,Website,Contact\nPayroll Co,https://Payroll.example/login?x=1,ops@payroll.example\n"
            "CRM,crm.example:443,\nCRM again,www.crm.example,\nDup,payroll.example,\nWild,*.mail.example,\n"
            "IP,203.0.113.4,\nfile,report.pdf,\n")
    out = vendor_check.parse(text, 50)
    assert out["domains"] == ["payroll.example", "crm.example", "www.crm.example", "mail.example"]
    assert out["duplicates"] == 1
    reasons = {s["value"]: s["reason"] for s in out["skipped"]}
    assert "e-mail" in reasons["ops@payroll.example"]
    assert "IP address" in reasons["203.0.113.4"]
    assert reasons["report.pdf"] == "not a domain name"


def test_parse_plain_lines_and_idn():
    out = vendor_check.parse("a.example\n\nb.example  c.example\nbücher.example\n", 50)
    assert out["domains"] == ["a.example", "b.example", "c.example", "xn--bcher-kva.example"]


def test_caps_refuse_a_long_list_and_are_env_tunable(monkeypatch):
    many = "\n".join(f"v{i}.example" for i in range(51))
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.parse(many, vendor_check.max_domains(False))
    assert exc.value.error == "too_many" and "51" in exc.value.detail and "without an account" in exc.value.detail
    assert len(vendor_check.parse(many, vendor_check.max_domains(True))["domains"]) == 51
    monkeypatch.setenv("MORROW_VENDOR_MAX_ANON", "60")
    assert vendor_check.max_domains(False) == 60
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.parse("no domains here", 50)
    assert exc.value.error == "no_domains"


# ── grading one vendor ───────────────────────────────────────────────────────


def test_a_vendor_on_a_private_address_is_refused_and_never_probed(monkeypatch):
    monkeypatch.setattr(alert_routing, "resolve_host", lambda host, port: ["10.0.0.7"])
    monkeypatch.setattr(_grade, "probe", lambda *a, **k: pytest.fail("probed an internal address"))
    entry = vendor_check.grade_vendor("intranet.example")
    assert entry["status"] == "refused" and entry["grade"] is None
    assert "10.0.0.7" in entry["detail"] and "public internet" in entry["detail"]


def test_an_opted_out_vendor_is_not_checked(monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example")
    monkeypatch.setattr(_grade, "probe", lambda *a, **k: pytest.fail("probed an opted-out domain"))
    entry = vendor_check.grade_vendor("www.quiet.example")
    assert entry["status"] == "refused"


def test_a_recent_stored_grade_is_reused(monkeypatch):
    _grade.store(_result("crm.example", "C"))
    monkeypatch.setattr(_grade, "check", lambda *a, **k: pytest.fail("checked again"))
    entry = vendor_check.grade_vendor("crm.example")
    assert entry["grade"] == "C" and entry["why"] == "classical key exchange (x25519)" and entry["exposed"] is True


def test_budgets_are_waited_out_then_left_for_the_next_recheck(monkeypatch):
    attempts = []

    def busy_then_ok(host, client_ip="", fresh=False, charge=True, cache_only=False):
        attempts.append(host)
        if len(attempts) == 1:
            raise _grade.GradeError(429, "rate_limited", "later", retry_after=5)
        return _result(host, "A")

    monkeypatch.setattr(_grade, "check", busy_then_ok)
    slept = []
    entry = vendor_check.grade_vendor("ok.example", stop_at=time.monotonic() + 600, sleep=slept.append)
    assert entry["grade"] == "A" and slept == [5.0]

    monkeypatch.setattr(_grade, "check", lambda *a, **k: (_ for _ in ()).throw(
        _grade.GradeError(429, "rate_limited", "later", retry_after=30)))
    entry = vendor_check.grade_vendor("late.example", stop_at=time.monotonic() + 1, sleep=lambda s: None)
    assert entry["status"] == "not_checked" and "next re-check" in entry["detail"]


def test_the_global_vendor_budget_applies_to_uncached_probes(monkeypatch, fake_check):
    monkeypatch.setenv("MORROW_VENDOR_GLOBAL_PROBES_PER_HOUR", "1")
    assert vendor_check.grade_vendor("crm.example", stop_at=time.monotonic() + 0.5, sleep=lambda s: None)["grade"] == "C"
    out = vendor_check.grade_vendor("mail.example", stop_at=time.monotonic() + 0.5, sleep=lambda s: None)
    assert out["status"] == "not_checked" and fake_check == ["crm.example"]


# ── the job and the report ───────────────────────────────────────────────────


def test_job_progress_is_written_after_each_vendor(monkeypatch, fake_check):
    monkeypatch.setenv("MORROW_VENDOR_WORKERS", "1")
    made = vendor_check.create("payroll.example\ncrm.example\nmail.example\ngone.example", client_ip="198.51.100.1",
                               start=False)
    assert made["total"] == 4 and made["manage_key"] and made["report_url"] == "/vendors/r/" + made["token"]
    first = vendor_check.read(made["token"])
    assert first["status"] == "queued" and first["done"] == 0 and first["pending"] == 4
    assert first["summaries"]["plain"] == "Checking your 4 vendors."
    seen = []
    real = vendor_check.grade_vendor

    def spy(domain, client_ip="", stop_at=0.0, sleep=time.sleep):
        seen.append(vendor_check.read(made["token"])["done"])
        return real(domain, client_ip, stop_at, sleep)

    monkeypatch.setattr(vendor_check, "grade_vendor", spy)
    vendor_check.run(made["id"])
    assert seen == [0, 1, 2, 3]
    report = vendor_check.read(made["token"], "https://morrow.example")
    assert report["status"] == "done" and report["done"] == 4 and report["exposed"] == 2 and report["graded"] == 3
    assert [v["domain"] for v in report["vendors"]] == ["payroll.example", "crm.example", "mail.example", "gone.example"]
    assert report["summaries"]["plain"] == ("2 of your 3 checked vendors would let today's traffic be read later. "
                                            "Worst: payroll.example (RSA key exchange). 1 could not be checked.")
    assert report["history"][-1]["exposed"] == 2


def test_the_answer_counts_every_vendor_when_all_were_checked(fake_check):
    made = vendor_check.create("payroll.example crm.example mail.example", start=False)
    vendor_check.run(made["id"])
    s = vendor_check.read(made["token"])["summaries"]
    assert s["plain"] == "2 of your 3 vendors would let today's traffic be read later. Worst: payroll.example (RSA key exchange)."
    assert s["expert"].startswith("2/3 graded below B")


def test_notes_link_to_the_vendor_page_and_use_measured_words(fake_check):
    made = vendor_check.create("payroll.example crm.example mail.example", start=False)
    vendor_check.run(made["id"])
    report = vendor_check.read(made["token"], "https://morrow.example")
    notes = {v["domain"]: v.get("note") for v in report["vendors"]}
    assert notes["mail.example"] is None
    assert "https://morrow.example/crm.example" in notes["crm.example"]
    assert "https://morrow.example/crm.example#w-claim" in notes["crm.example"]      # the owner's claim flow
    assert "negotiates x25519, a classical key exchange only" in notes["crm.example"]
    assert "RSA key exchange, which has no forward secrecy" in notes["payroll.example"]
    text = json.dumps(report).lower()
    for word in vendor_check.BANNED_WORDS:
        assert word not in text, word
    assert "sends nothing" in report["sends_nothing"].lower()


def test_csv_export_and_formula_cells(fake_check):
    made = vendor_check.create("crm.example mail.example", start=False)
    vendor_check.run(made["id"])
    report = vendor_check.read(made["token"])
    report["vendors"][0]["detail"] = "=HYPERLINK(\"x\")"
    body = vendor_check.to_csv(report)
    lines = body.split("\r\n")
    assert lines[0] == "domain,grade,post_quantum,key_exchange,why,readable_from,checked_at,status,detail,page"
    assert lines[1].startswith("crm.example,C,no,x25519,")
    assert "'=HYPERLINK" in lines[1]


def test_link_expired_and_revoked(fake_check):
    made = vendor_check.create("crm.example", start=False)
    assert vendor_check.read(made["token"])["total"] == 1
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.read("not-a-real-token-xxxxxxxxx")
    assert exc.value.status_code == 404
    with pytest.raises(vendor_check.VendorError):
        vendor_check.revoke_anonymous(made["token"], "wrong-key")
    assert vendor_check.revoke_anonymous(made["token"], made["manage_key"]) == {"revoked": True}
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.read(made["token"])
    assert exc.value.status_code == 410 and exc.value.error == "revoked"

    other = vendor_check.create("crm.example", start=False)
    with feature_conn() as conn:
        conn.execute("UPDATE vendor_check_reports SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?", (other["id"],))
        conn.commit()
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.read(other["token"])
    assert exc.value.error == "expired"


def test_tokens_are_unguessable_and_stored_hashed_for_anonymous_reports(fake_check):
    made = vendor_check.create("crm.example", start=False)
    assert len(made["token"]) >= 24
    with feature_conn() as conn:
        row = conn.execute("SELECT token, token_hash, manage_hash FROM vendor_check_reports").fetchone()
    assert row["token"] == "" and row["token_hash"] == vendor_check.hash_token(made["token"])
    assert made["token"] not in json.dumps(dict(row)) and made["manage_key"] not in json.dumps(dict(row))


def test_anonymous_lists_are_rate_limited_per_address(fake_check):
    for _ in range(vendor_check.ip_lists_per_hour()):
        vendor_check.create("crm.example", client_ip="198.51.100.9", start=False)
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.create("crm.example", client_ip="198.51.100.9", start=False)
    assert exc.value.status_code == 429 and exc.value.retry_after
    vendor_check.create("crm.example", client_ip="198.51.100.10", start=False)


def test_domains_per_day_are_capped_per_address(monkeypatch, fake_check):
    monkeypatch.setenv("MORROW_VENDOR_IP_DOMAINS_PER_DAY", "3")
    vendor_check.create("a.example b.example", client_ip="198.51.100.20", start=False)
    with pytest.raises(vendor_check.VendorError) as exc:
        vendor_check.create("c.example d.example", client_ip="198.51.100.20", start=False)
    assert exc.value.status_code == 429


def test_reading_by_link_crosses_tenants_in_a_named_scope(monkeypatch, fake_check):
    seen = []
    real = tenant_scope.platform_scope

    def spy(reason, actor=""):
        seen.append(reason)
        return real(reason, actor)

    monkeypatch.setattr(tenant_scope, "platform_scope", spy)
    made = vendor_check.create("crm.example", org_id="org-a", start=False)
    vendor_check.read(made["token"])
    assert any(r.startswith("vendor check: a shared report") for r in seen)


def test_the_table_is_under_tenant_isolation():
    assert "vendor_check_reports" in postgres_rls.ORG_SCOPED_TABLES
    assert postgres_rls.TENANT_COLUMNS["vendor_check_reports"] == "org_id"
    assert "vendor_check_reports" in postgres_rls.build_rls_sql(tables=["vendor_check_reports"])


# ── saved lists ──────────────────────────────────────────────────────────────


def test_saved_lists_are_rechecked_under_the_same_link(monkeypatch, fake_check):
    made = vendor_check.create("crm.example", org_id="org-a", saved=True, interval_days=7, start=False)
    vendor_check.run(made["id"])
    assert vendor_check.recheck_due() == {"due": 0, "started": 0}
    with feature_conn() as conn:
        conn.execute("UPDATE vendor_check_reports SET next_check_at = '2020-01-01T00:00:00Z' WHERE id = ?", (made["id"],))
        conn.commit()
    kicked = []
    monkeypatch.setattr(vendor_check, "kick", lambda rid: kicked.append(rid) or True)
    assert vendor_check.recheck_due() == {"due": 1, "started": 1} and kicked == [made["id"]]
    FAKE["crm.example"] = _result("crm.example", "A")
    try:
        vendor_check.run(made["id"])
    finally:
        FAKE["crm.example"] = _result("crm.example", "C")
    report = vendor_check.read(made["token"])
    assert report["vendors"][0]["grade"] == "A" and len(report["history"]) == 2
    assert report["saved"] and report["next_check_at"] > _grade.iso(_grade.now_utc())


def test_org_lists_new_link_revoke_and_isolation(fake_check):
    made = vendor_check.create("crm.example", org_id="org-a", saved=True, start=False)
    assert made["manage_key"] is None
    assert [r["id"] for r in vendor_check.for_org("org-a")] == [made["id"]]
    assert vendor_check.for_org("org-b") == []
    with pytest.raises(vendor_check.VendorError):
        vendor_check.org_update("org-b", made["id"], revoke=True)
    out = vendor_check.org_update("org-a", made["id"], revoke=True)
    assert out["revoked"] and out["report_url"] is None
    with pytest.raises(vendor_check.VendorError):
        vendor_check.read(made["token"])
    fresh = vendor_check.org_update("org-a", made["id"], new_link=True)
    new_token = fresh["report_url"].rsplit("/", 1)[1]
    assert new_token != made["token"] and vendor_check.read(new_token)["total"] == 1
    assert vendor_check.org_delete("org-b", made["id"]) is False
    assert vendor_check.org_delete("org-a", made["id"]) is True


def test_a_stopped_runner_is_resumed_on_read(monkeypatch):
    made = vendor_check.create("crm.example", start=False)
    monkeypatch.setattr(_grade, "check", lambda *a, **k: _result("crm.example", "C"))
    with feature_conn() as conn:
        conn.execute("UPDATE vendor_check_reports SET status = 'running', runner = 'gone', heartbeat_at = "
                     "'2020-01-01T00:00:00Z' WHERE id = ?", (made["id"],))
        conn.commit()
    vendor_check.read(made["token"])
    for _ in range(100):
        if vendor_check.read(made["token"])["status"] == "done":
            break
        time.sleep(0.05)
    assert vendor_check.read(made["token"])["vendors"][0]["grade"] == "C"
    # The runner thread must not outlive this test: it reads MORROW_SCANNER_DB on every write.
    for _ in range(100):
        if not vendor_check._active:
            break
        time.sleep(0.05)
    assert not vendor_check._active


# ── the routes ───────────────────────────────────────────────────────────────


def test_the_public_routes(monkeypatch, fake_check):
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as client:
        assert client.post("/api/public/vendors/check", content="domains=a.example",
                           headers={"content-type": "application/x-www-form-urlencoded"}).status_code == 415
        r = client.post("/api/public/vendors/check", json={"domains": "crm.example\nmail.example\n"})
        assert r.status_code == 202, r.text
        made = r.json()
        assert r.headers["cache-control"] == "no-store"
        bad = client.post("/api/public/vendors/check", json={"domains": "\n".join(f"v{i}.example" for i in range(51))})
        assert bad.status_code == 400 and bad.json()["error"] == "too_many"
        vendor_check.run(made["id"])
        body = client.get("/api/public/vendors/report/" + made["token"]).json()
        assert body["status"] == "done" and body["vendors"][0]["domain"] == "crm.example"
        csv_r = client.get("/api/public/vendors/report/" + made["token"] + ".csv")
        assert csv_r.headers["content-type"].startswith("text/csv") and "attachment" in csv_r.headers["content-disposition"]
        page = client.get("/vendors/r/" + made["token"])
        assert page.status_code == 200 and "noindex" in page.headers["x-robots-tag"]
        assert client.get("/vendors").status_code == 200
        assert client.delete("/api/public/vendors/report/" + made["token"], headers={"x-manage-key": "nope"}).status_code == 404
        assert client.delete("/api/public/vendors/report/" + made["token"],
                             headers={"x-manage-key": made["manage_key"]}).status_code == 200
        assert client.get("/api/public/vendors/report/" + made["token"]).status_code == 410


def test_the_signed_in_routes(monkeypatch, fake_check):
    import app as application

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as client:
        r = client.post("/instrument/vendor-checks", json={"domains": "crm.example", "name": "Payroll", "save": True,
                                                            "interval_days": 14}, headers={"x-user-role": "viewer"})
        assert r.status_code == 403
        r = client.post("/instrument/vendor-checks", json={"domains": "crm.example", "name": "Payroll", "save": True,
                                                            "interval_days": 14}, headers={"x-user-role": "admin"})
        assert r.status_code == 202, r.text
        made = r.json()
        listed = client.get("/instrument/vendor-checks", headers={"x-user-role": "viewer"}).json()
        assert listed["max_domains"] == 500 and listed["reports"][0]["name"] == "Payroll"
        assert listed["reports"][0]["interval_days"] == 14 and listed["reports"][0]["saved"]
        p = client.patch("/instrument/vendor-checks/" + made["id"], json={"revoke": True}, headers={"x-user-role": "admin"})
        assert p.status_code == 200 and p.json()["revoked"]
        assert client.get("/api/public/vendors/report/" + made["token"]).status_code == 410
        assert client.delete("/instrument/vendor-checks/" + made["id"], headers={"x-user-role": "admin"}).status_code == 200


def test_signed_in_routes_need_a_sign_in(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/instrument/vendor-checks").status_code == 401
        assert anonymous.post("/instrument/vendor-checks", json={"domains": "a.example"}).status_code == 401
        assert anonymous.get("/vendors").status_code == 200
