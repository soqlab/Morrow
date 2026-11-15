"""The live safe badge (services/safe_badge.py): only claimed domains, never a false or stale claim,
re-checked by the watch tick, served without cookies or tracking. No network: DNS and probes are
replaced."""

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from db_feature_store import feature_conn
from services import domain_verification, not_ready, postgres_rls, public_check, public_grade, safe_badge, watch
from services import org_rate_limits as _limits

ORG, OTHER = "org-badge-1", "org-badge-2"


def _reset():
    public_check._TABLES_READY.clear()
    public_grade._TABLES_READY.clear()
    watch._ready = ""
    safe_badge._ready = ""
    safe_badge.reset_cache()
    not_ready._ready = ""
    domain_verification._ready = ""
    domain_verification._cache.clear()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "badge.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://morrow.example")
    monkeypatch.setenv("MORROW_WATCH_THIRD_PARTY", "0")
    for name in ("MORROW_WATCH_INTERVAL_HOURS", "MORROW_WATCH_TICK_MAX", "MORROW_WATCH_MAX_PER_USER"):
        monkeypatch.delenv(name, raising=False)
    _reset()
    yield
    _reset()


class _DNS:
    def __init__(self):
        self.values = {}

    def __call__(self, name):
        return list(self.values.get(name, []))


@pytest.fixture
def dns(monkeypatch):
    fake = _DNS()
    monkeypatch.setattr(domain_verification, "_txt_values", fake)
    return fake


def _claim(dns, org, domain, user="alice"):
    rec = watch.start_claim(org, domain)["record"]
    dns.values.setdefault(rec["name"], []).append(rec["value"])
    return watch.claim(org, user, domain)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _result(domain, grade="A", pq=True, when=None):
    when = when or _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    return {"domain": domain, "scanned_at": when, "cached": False, "grade": grade, "rubric_version": public_grade.RUBRIC_VERSION,
            "key_exchange": {"group": "X25519MLKEM768" if pq else "x25519", "post_quantum": pq},
            "certificate": {"key_type": "EC", "verified": True}, "reasons": [f"Grade {grade}."]}


# ── who may turn it on ───────────────────────────────────────────────────────


def test_only_the_claimant_turns_it_on(dns):
    with pytest.raises(watch.WatchError) as exc:
        safe_badge.enable(ORG, "alice", "unclaimed.example")
    assert exc.value.code == "not_claimed"
    _claim(dns, ORG, "acme.example")
    with pytest.raises(watch.WatchError):
        safe_badge.enable(OTHER, "bob", "acme.example")
    view = safe_badge.enable(ORG, "alice", "acme.example")
    assert view["enabled"] is True
    assert view["snippet"] == ('<a href="https://morrow.example/acme.example"><img src="https://morrow.example/api/public/safe-badge/'
                               'acme.example.svg" alt="Morrow quantum-safety check for acme.example" height="20" '
                               'referrerpolicy="no-referrer"></a>')
    assert safe_badge.active_domains() == ["acme.example"]


def test_without_a_claim_or_the_switch_the_badge_claims_nothing(dns):
    public_grade.store(_result("nobody.example"))
    st = safe_badge.status("nobody.example")
    assert st["state"] == "neutral" and st["reason"] == "off" and st["verified_at"] is None
    _claim(dns, ORG, "acme.example")
    public_grade.store(_result("acme.example"))
    assert safe_badge.status("acme.example", use_cache=False)["state"] == "neutral"  # claimed, switch off
    safe_badge.enable(ORG, "alice", "acme.example")
    assert safe_badge.status("acme.example", use_cache=False)["state"] == "safe"
    safe_badge.disable(ORG, "acme.example")
    assert safe_badge.status("acme.example", use_cache=False)["state"] == "neutral"


def test_a_claim_that_moves_takes_the_badge_with_it(dns):
    _claim(dns, ORG, "moved.example")
    safe_badge.enable(ORG, "alice", "moved.example")
    public_grade.store(_result("moved.example"))
    assert safe_badge.status("moved.example", use_cache=False)["state"] == "safe"
    dns.values.clear()  # the domain changed hands: the first organization's record is gone
    _claim(dns, OTHER, "moved.example", user="bob")
    assert safe_badge.status("moved.example", use_cache=False)["state"] == "neutral"
    assert safe_badge.active_domains() == []
    watch.release(OTHER, "moved.example")
    assert safe_badge.status("moved.example", use_cache=False)["state"] == "neutral"


# ── never a false or stale claim ─────────────────────────────────────────────


def test_evaluate_needs_a_fresh_post_quantum_check():
    now = datetime(2026, 11, 15, 12, tzinfo=timezone.utc)
    fresh = _result("x.example", when=_iso(now - timedelta(hours=3)))
    assert safe_badge.evaluate(True, fresh, now)["state"] == "safe"
    assert safe_badge.evaluate(True, fresh, now)["verified_at"] == fresh["scanned_at"]
    assert safe_badge.evaluate(True, _result("x.example", "B", True, _iso(now)), now)["state"] == "safe"
    assert safe_badge.evaluate(True, _result("x.example", "C", False, _iso(now)), now)["reason"] == "not_safe"
    assert safe_badge.evaluate(True, _result("x.example", "F", True, _iso(now)), now)["reason"] == "not_safe"  # bad certificate
    old = _result("x.example", when=_iso(now - timedelta(hours=safe_badge.FRESH_HOURS + 1)))
    assert safe_badge.evaluate(True, old, now)["reason"] == "stale"
    assert safe_badge.evaluate(True, None, now)["reason"] == "no_check"
    assert safe_badge.evaluate(False, fresh, now)["reason"] == "off"


def test_safe_since_is_the_start_of_the_current_safe_run(dns):
    _claim(dns, ORG, "run.example")
    safe_badge.enable(ORG, "alice", "run.example")
    now = datetime.now(timezone.utc)
    public_grade.store(_result("run.example", "A", True, _iso(now - timedelta(days=9))))
    public_grade.store(_result("run.example", "C", False, _iso(now - timedelta(days=5))))
    public_grade.store(_result("run.example", "A", True, _iso(now - timedelta(days=3))))
    public_grade.store(_result("run.example", "B", True, _iso(now - timedelta(hours=2))))
    st = safe_badge.status("run.example", use_cache=False)
    assert st["state"] == "safe" and st["safe_since"] == _iso(now - timedelta(days=3))
    assert "ML-KEM" in st["explanation"]


def test_an_opted_out_domain_claims_nothing(dns, monkeypatch):
    _claim(dns, ORG, "quiet.example")
    safe_badge.enable(ORG, "alice", "quiet.example")
    public_grade.store(_result("quiet.example"))
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "quiet.example")
    assert safe_badge.status("quiet.example", use_cache=False)["state"] == "neutral"


# ── the daily re-check reuses the watch tick ─────────────────────────────────


def test_a_badged_domain_is_due_daily_even_when_nobody_watches_it(dns, monkeypatch):
    monkeypatch.setenv("MORROW_WATCH_INTERVAL_HOURS", "72")
    _claim(dns, ORG, "daily.example")
    watch.unwatch(ORG, "alice", "daily.example")
    assert watch.due_domains(10) == []  # claimed, not watched, no badge: nothing to check
    safe_badge.enable(ORG, "alice", "daily.example")
    assert watch.due_domains(10) == ["daily.example"]
    seen = []
    run = watch.tick(grade=lambda d: seen.append(d) or _result(d, when=_iso(datetime.now(timezone.utc))))
    assert run["checked"] == 1 and seen == ["daily.example"]
    assert safe_badge.status("daily.example")["state"] == "safe"
    assert watch.due_domains(10) == []  # just checked
    with feature_conn() as conn:  # 25 hours later it is due again, though the watch interval is 72
        watch._save_state(conn, "daily.example", _iso(datetime.now(timezone.utc) - timedelta(hours=25)), {"grade": "A"})
        conn.commit()
    assert watch.due_domains(10) == ["daily.example"]


def test_a_failed_check_turns_the_badge_neutral_once_the_last_answer_is_stale(dns):
    _claim(dns, ORG, "flaky.example")
    safe_badge.enable(ORG, "alice", "flaky.example")
    old = datetime.now(timezone.utc) - timedelta(hours=safe_badge.FRESH_HOURS + 2)
    public_grade.store(_result("flaky.example", when=_iso(old)))
    out = watch.check_domain("flaky.example", grade=lambda d: {"error": "unreachable", "detail": "timeout"})
    assert out["ok"] is False
    assert safe_badge.status("flaky.example", use_cache=False)["reason"] == "stale"


def test_a_tick_that_finds_it_unsafe_flips_the_badge_at_once(dns):
    _claim(dns, ORG, "flip.example")
    safe_badge.enable(ORG, "alice", "flip.example")
    public_grade.store(_result("flip.example"))
    assert safe_badge.status("flip.example")["state"] == "safe"  # now cached
    watch.check_domain("flip.example", grade=lambda d: _result(d, "C", False, _iso(datetime.now(timezone.utc))), deliver=False)
    assert safe_badge.status("flip.example")["state"] == "neutral"  # the tick dropped the cached answer


# ── the image and the routes ─────────────────────────────────────────────────


def test_the_svg_is_self_contained_and_says_only_what_holds():
    safe = safe_badge.svg({"state": "safe", "verified_at": "2026-11-15T06:00:00Z"})
    assert "Quantum-safe" in safe and "verified 2026-11-15" in safe
    neutral = safe_badge.svg({"state": "neutral"})
    assert "Quantum-safe" not in neutral and "quantum check" in neutral
    for svg in (safe, neutral):
        assert svg.startswith("<svg") and "href" not in svg and "<script" not in svg and "url(" in svg  # url(#r) only
        assert "http://www.w3.org/2000/svg" in svg and svg.count("http") == 1


def test_the_tables_are_in_the_rls_plan():
    assert "safe_badges" in postgres_rls.ORG_SCOPED_TABLES
    assert postgres_rls.TENANT_COLUMNS["safe_badges"] == "org_id"


def test_the_routes(monkeypatch, dns):
    import app as application

    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    application.limiter.enabled = False
    events = []
    monkeypatch.setattr(application, "_record_traffic_event", lambda *a, **k: events.append(a[0].url.path) or None)
    with TestClient(application.app, raise_server_exceptions=False) as client:
        viewer = {"x-user-role": "viewer", "x-user-id": "viewer-1"}
        admin = {"x-user-role": "admin", "x-user-id": "admin-1"}
        assert client.put("/instrument/claims/route.example/badge", headers=admin).status_code == 403  # not claimed
        rec = client.post("/instrument/claims/route.example", headers=admin).json()["record"]
        dns.values[rec["name"]] = [rec["value"]]
        assert client.post("/instrument/claims/route.example/check", headers=admin).status_code == 200
        assert client.put("/instrument/claims/route.example/badge", headers=viewer).status_code == 403  # admins only
        on = client.put("/instrument/claims/route.example/badge", headers=admin)
        assert on.status_code == 200 and on.json()["enabled"] is True and "safe-badge/route.example.svg" in on.json()["snippet"]
        assert client.get("/instrument/claims/route.example/badge", headers=viewer).json()["enabled"] is True
        public_grade.store(_result("route.example"))
        safe_badge.reset_cache()
        img = client.get("/api/public/safe-badge/route.example.svg")
        assert img.status_code == 200 and img.headers["content-type"].startswith("image/svg+xml")
        assert "Quantum-safe" in img.text
        assert img.headers["cache-control"] == "public, max-age=3600"
        assert img.headers["cross-origin-resource-policy"] == "cross-origin"
        assert "set-cookie" not in {k.lower() for k in img.headers}
        assert "/api/public/safe-badge/route.example.svg" not in events  # not in the traffic monitor
        st = client.get("/api/public/safe-badge/route.example").json()
        assert st["state"] == "safe" and st["page"] == "https://morrow.example/route.example" and "org" not in str(st)
        claim = client.get("/api/public/claim/route.example").json()
        assert claim["badge"]["state"] == "safe" and ORG not in str(claim)
        assert "quantum check" in client.get("/api/public/safe-badge/other.example.svg").text
        assert client.get("/api/public/safe-badge/not a domain.svg").status_code == 200  # neutral, never broken
        assert client.delete("/instrument/claims/route.example/badge", headers=admin).json()["removed"] is True
        assert "quantum check" in client.get("/api/public/safe-badge/route.example.svg").text


def test_the_public_badge_needs_no_account(monkeypatch):
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/safe-badge/example.com.svg").status_code == 200
        assert anonymous.get("/api/public/safe-badge/example.com").status_code == 200
        assert anonymous.get("/instrument/claims/example.com/badge").status_code == 401
