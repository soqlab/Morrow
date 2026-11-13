"""The harvest clock (decrypt_window.harvest) and "who else is exposing you" (services/third_party.py).

No network. The harvest arithmetic is pure; discovery is tested on fixture HTML and a fake DNS;
the guard with services.alert_routing.resolve_host replaced (the seam the public grade's tests
use), and every socket and ClientHello probe replaced so a refused host is provably never contacted.
"""

import os
import socket
import threading
import time
from datetime import datetime, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

import scanner
from services import alert_routing as _alert_routing
from services import decrypt_window as _dw
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade
from services import third_party as _tp

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "exposure.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.setattr(_grade, "own_addresses", lambda: frozenset({"203.0.113.250"}))
    monkeypatch.setattr(_tp, "_dns", lambda name, rtype: [])
    _check._TABLES_READY.clear()
    _grade._TABLES_READY.clear()
    _limits.reset()
    _tp.clear_cache()
    yield
    _tp.clear_cache()
    _limits.reset()


# ── the harvest clock ────────────────────────────────────────────────────────


def test_classical_key_exchange_is_harvestable_and_short_by_the_gap():
    h = _dw.harvest(True, False, shelf_years=15, crqc_year=2035, now=NOW)
    assert h["harvestable"] is True
    assert h["readable_from"] == 2035
    assert h["secret_until"] == 2041
    assert h["years_short"] == 6 and h["exposed"] is True and h["margin_years"] == 0
    assert h["mosca"] == {"x": 15, "y": 0, "z": 9, "exposed": True}


def test_classical_with_enough_margin_is_not_short():
    h = _dw.harvest(True, False, shelf_years=2, crqc_year=2040, now=NOW)
    assert h["harvestable"] is True and h["exposed"] is False
    assert h["years_short"] == 0 and h["margin_years"] == 12


def test_migration_time_moves_the_last_exposed_secret():
    h = _dw.harvest(True, False, shelf_years=5, crqc_year=2035, migration_years=4, now=NOW)
    assert h["exposed"] is False  # today's traffic (2031) is fine...
    assert h["last_exposed_secret_until"] == 2035 and h["years_short_after_migration"] == 0
    h = _dw.harvest(True, False, shelf_years=5, crqc_year=2035, migration_years=6, now=NOW)
    assert h["mosca"]["exposed"] is True  # ...but x + y > z
    assert h["years_short_after_migration"] == 2


def test_hybrid_key_exchange_is_not_harvestable_whatever_the_dials_say():
    for shelf in (0, 25, 75):
        h = _dw.harvest(True, True, shelf_years=shelf, crqc_year=2030, migration_years=10, now=NOW)
        assert h["harvestable"] is False and h["exposed"] is False
        assert h["readable_from"] is None and h["years_short"] == 0
        assert h["mosca"]["exposed"] is False
        assert "ML-KEM" in h["basis"]


def test_no_tls_is_readable_now():
    h = _dw.harvest(False, False, shelf_years=3, crqc_year=2040, now=NOW)
    assert h["readable_from"] == 2026 and h["years_short"] == 3


def test_the_dials_are_clamped_to_the_estimate_and_sane_lifetimes():
    h = _dw.harvest(True, False, shelf_years=500, crqc_year=1999, migration_years=-3, now=NOW)
    assert h["shelf_years"] == _dw.SHELF_YEARS_MAX
    assert h["crqc_year"] == 2026 and h["migration_years"] == 0
    h = _dw.harvest(True, False, shelf_years="x", crqc_year=None, now=NOW)
    assert h["shelf_years"] == 0 and h["crqc_year"] == _dw.CRQC_ESTIMATE["low"]


def test_the_estimate_is_labelled_as_one_and_served_with_its_source():
    est = _dw.basis()["crqc_estimate"]
    assert est["is_estimate"] is True
    assert est["low"] == _dw.DECRYPT_YEAR_LOW and est["likely"] == _dw.DECRYPT_YEAR_HIGH
    assert est["low"] < est["likely"] < est["high"]
    assert "not a survey answer" in est["high_label"]
    assert "globalriskinstitute.org" in _dw.basis()["source_url"]


def test_the_browser_mirrors_the_reference_arithmetic():
    """instrument.js computes the clock as the dials move; it must use the same rule (x + y > z)."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "static", "instrument.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert "function harvestClock(" in js
    assert "secretUntil - z" in js and "x + y > z - year" in js


# ── discovery ────────────────────────────────────────────────────────────────

PAGE = """<!doctype html><html><head>
<base href="https://shop.example.com/">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
<link rel="preconnect" href="https://api.segment.io">
<link rel="canonical" href="https://other.example.org/">
<link rel="alternate" hreflang="de" href="https://de.example.net/">
<script src="https://js.stripe.com/v3/"></script>
<script src="//cdn.jsdelivr.net/npm/x@1/x.js"></script>
<script src="/local.js"></script>
<script src="https://static.example.com/app.js"></script>
</head><body>
<img src="http://tracker.example.org/p.gif" srcset="https://img.cdn-provider.net/a.png 2x">
<iframe src="https://www.youtube-nocookie.com/embed/x"></iframe>
<form action="https://checkout.paymentco.example/pay"><input></form>
<a href="https://linked-only.example.org/">a link is not a dependency</a>
<img src="data:image/png;base64,AAAA"><script src="javascript:void(0)"></script>
<script src="https://10.0.0.7/internal.js"></script>
<script src="https://[::1]/x.js"></script>
</body></html>"""


def test_the_homepage_parser_finds_every_origin_the_page_loads_or_posts_to():
    refs = {r["host"]: r for r in _tp.parse_html(PAGE, "https://example.com/")}
    assert set(refs) == {"fonts.googleapis.com", "api.segment.io", "js.stripe.com", "cdn.jsdelivr.net",
                         "shop.example.com", "static.example.com", "tracker.example.org", "img.cdn-provider.net",
                         "www.youtube-nocookie.com", "checkout.paymentco.example"}
    assert refs["checkout.paymentco.example"]["role"] == "form"
    assert refs["api.segment.io"]["via"] == "link rel=preconnect"
    assert refs["tracker.example.org"]["via"].endswith("(plain http)")
    # <base href> moves relative URLs onto its host.
    assert "shop.example.com" in refs


def test_links_ip_literals_and_pseudo_urls_are_not_dependencies():
    refs = {r["host"] for r in _tp.parse_html(PAGE, "https://example.com/")}
    assert "linked-only.example.org" not in refs and "other.example.org" not in refs and "de.example.net" not in refs
    assert not any(h.startswith(("10.", "[")) or h == "::1" for h in refs)


def test_discover_drops_the_sites_own_names_and_classifies_known_services():
    found = {e["host"]: e for e in _tp.discover("example.com", PAGE, "https://example.com/")}
    assert "static.example.com" not in found and "shop.example.com" not in found
    assert found["js.stripe.com"]["role"] == "payment" and found["js.stripe.com"]["vendor"] == "Stripe"
    assert found["cdn.jsdelivr.net"]["role"] == "library"
    assert found["fonts.googleapis.com"]["role"] == "fonts"
    assert found["checkout.paymentco.example"]["role"] == "form"


def test_site_of_keeps_two_label_suffixes_together():
    assert _tp.site_of("www.shop.example.co.uk") == "example.co.uk"
    assert _tp.site_of("a.b.example.com") == "example.com"
    assert _tp.same_site("login.example.com", "example.com")
    assert not _tp.same_site("example.co.uk", "other.co.uk")


def test_dns_finds_the_cdn_mail_and_a_hosted_checkout(monkeypatch):
    answers = {
        ("www.example.com", "CNAME"): ["example.com.cdn.cloudflare.net"],
        ("checkout.example.com", "CNAME"): ["shops.myshopify.com"],
        ("login.example.com", "CNAME"): ["login.example.com.internal.example.com"],  # same site: not counted
        ("example.com", "MX"): ["aspmx.l.google.com", "alt1.aspmx.l.google.com", "mx.example.com"],
    }
    monkeypatch.setattr(_tp, "_dns", lambda name, rtype: answers.get((name, rtype), []))
    found = {e["host"]: e for e in _tp.dns_services("example.com")}
    assert found["www.example.com"]["role"] == "cdn" and found["www.example.com"]["vendor"] == "Cloudflare"
    assert found["www.example.com"]["same_edge"] is False
    assert found["checkout.example.com"]["role"] == "payment" and found["checkout.example.com"]["hosted_name"]
    assert "login.example.com" not in found
    mail = [e for e in found.values() if e["role"] == "mail"]
    assert {m["vendor"] for m in mail} == {"Google Workspace", "example.com"}
    google = [m for m in mail if m["vendor"] == "Google Workspace"][0]
    assert google["via"] == "MX (2 hosts)"


# ── the guard, the caps and the deadline ─────────────────────────────────────


@pytest.fixture
def no_sockets(monkeypatch):
    """Every outbound connection and ClientHello is recorded and answered from ``state``."""
    state = {"connected": [], "hello": [], "kx": {}, "delay": 0.0}

    def create_connection(addr, *args, **kwargs):
        state["connected"].append(addr)
        raise OSError("no network in tests")

    def kx(host, port, timeout=0, address="", groups=None):
        state["hello"].append((host, address))
        if state["delay"]:
            time.sleep(state["delay"])
        family, group = state["kx"].get(host, ("classical", "x25519"))
        return {"key_exchange": group, "key_exchange_family": family, "key_exchange_observed": True}

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(scanner, "_probe_key_exchange_group", kx)
    return state


def test_a_discovered_host_that_resolves_privately_is_refused_and_never_contacted(monkeypatch, no_sockets):
    addresses = {"intranet.example.org": ["10.1.2.3"], "sneaky.example.org": ["93.184.216.34", "127.0.0.1"],
                 "mapped.example.org": ["::ffff:192.168.0.1"], "self.example.org": ["203.0.113.250"],
                 "ok.example.org": ["93.184.216.34"]}
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: addresses[host])
    for host in ("intranet.example.org", "sneaky.example.org", "mapped.example.org", "self.example.org"):
        result = _tp.probe_host(host)
        assert result["status"] == "refused", (host, result)
    assert no_sockets["connected"] == [] and no_sockets["hello"] == []
    assert _tp.probe_host("ok.example.org")["status"] == "classical"
    assert no_sockets["hello"] == [("ok.example.org", "93.184.216.34")]


def test_a_redirect_to_an_internal_name_is_not_followed(monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host",
                        lambda host, port: {"example.com": ["93.184.216.34"], "admin.example.com": ["10.0.0.9"]}[host])
    calls = []

    def fake_get(address, host, path, timeout, max_bytes=0, deadline=None):
        calls.append((address, host))
        return {"status": 302, "headers": {"location": "https://admin.example.com/"}, "body": b""}

    monkeypatch.setattr(_tp, "_http_get", fake_get)
    page = _tp.fetch_homepage("example.com")
    assert calls == [("93.184.216.34", "example.com")]
    assert page["html"] == "" and any("not on the public internet" in n or "10.0.0.9" in n for n in page["notes"])


def test_an_opted_out_host_is_skipped(monkeypatch, no_sockets):
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "vendor.example.org")
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["93.184.216.34"])
    assert _tp.probe_host("api.vendor.example.org")["status"] == "skipped"
    assert no_sockets["hello"] == []


def _page_with(n):
    return "".join(f'<script src="https://s{i}.vendor{i}.example.org/a.js"></script>' for i in range(n))


def _run_with_page(monkeypatch, html):
    monkeypatch.setattr(_tp, "fetch_homepage",
                        lambda host, deadline=None: {"final_host": host, "url": f"https://{host}/", "html": html, "notes": []})
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["93.184.216.34"])


def test_probing_is_capped_and_the_rest_are_listed_not_checked(monkeypatch, no_sockets):
    monkeypatch.setenv("MORROW_EXPOSURE_MAX_HOSTS", "3")
    _run_with_page(monkeypatch, _page_with(8))
    result = _tp.run("example.com", {"grade": "A", "key_exchange": {"post_quantum": True, "group": "X25519MLKEM768"}})
    assert len(no_sockets["hello"]) == 3
    statuses = [s["status"] for s in result["services"]]
    assert statuses.count("not_checked") == 5 and result["counts"]["over_cap"] == 5
    assert all("limit of 3" in s["fix"] for s in result["services"] if s["status"] == "not_checked")


def test_concurrency_is_bounded(monkeypatch, no_sockets):
    monkeypatch.setenv("MORROW_EXPOSURE_WORKERS", "2")
    _run_with_page(monkeypatch, _page_with(6))
    live, peak, lock = [0], [0], threading.Lock()
    real = scanner._probe_key_exchange_group

    def counting(*args, **kwargs):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        try:
            return real(*args, **kwargs)
        finally:
            with lock:
                live[0] -= 1

    monkeypatch.setattr(scanner, "_probe_key_exchange_group", counting)
    _tp.run("example.com", {})
    assert peak[0] <= 2


def test_the_whole_run_stops_at_its_deadline(monkeypatch, no_sockets):
    monkeypatch.setenv("MORROW_EXPOSURE_DEADLINE", "2")
    monkeypatch.setenv("MORROW_EXPOSURE_WORKERS", "1")
    no_sockets["delay"] = 0.8
    _run_with_page(monkeypatch, _page_with(6))
    started = time.monotonic()
    result = _tp.run("example.com", {})
    assert time.monotonic() - started < 3.5
    assert any(s["status"] == "skipped" and "out of time" in s["fix"] for s in result["services"])


def test_the_worst_comes_first_and_the_answer_names_it(monkeypatch, no_sockets):
    html = ('<script src="https://cdn.jsdelivr.net/x.js"></script><script src="https://js.stripe.com/v3/"></script>'
            '<script src="https://www.googletagmanager.com/gtm.js"></script>')
    _run_with_page(monkeypatch, html)
    no_sockets["kx"] = {"cdn.jsdelivr.net": ("pq_hybrid", "X25519MLKEM768")}
    result = _tp.run("example.com", {"grade": "A", "key_exchange": {"post_quantum": True, "group": "X25519MLKEM768"}})
    hosts = [s["host"] for s in result["services"]]
    assert hosts == ["js.stripe.com", "www.googletagmanager.com", "cdn.jsdelivr.net"]
    assert result["summaries"]["plain"] == "You're ready, but your payment provider isn't (js.stripe.com) and 1 more."
    assert "Ask Stripe" in result["services"][0]["fix"]
    assert result["services"][0]["readable_from"] == _dw.DECRYPT_YEAR_LOW
    assert result["services"][-1]["status"] == "pq" and result["services"][-1]["readable_from"] is None


def test_a_tls12_only_vendor_is_classical(monkeypatch):
    monkeypatch.setattr(_alert_routing, "resolve_host", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "_probe_key_exchange_group",
                        lambda *a, **k: {"key_exchange_observed": False, "key_exchange_unobservable_reason": "alert"})
    monkeypatch.setattr(_grade, "_handshake", lambda *a, **k: {"version": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"})
    result = _tp.probe_host("old.example.org")
    assert result["status"] == "classical" and "TLSv1.2" in result["detail"]


# ── the API ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def test_the_endpoint_is_public_rate_limited_and_cached(client, monkeypatch, no_sockets):
    monkeypatch.setenv("MORROW_EXPOSURE_IP_PER_MINUTE", "3")
    monkeypatch.setattr(_tp, "_own_grade", lambda host, ip: {"grade": "C", "key_exchange": {"post_quantum": False, "group": "x25519"}})
    runs = []
    monkeypatch.setattr(_tp, "run", lambda host, own=None: runs.append(host) or {
        "domain": host, "services": [], "probed": 0, "summaries": {"plain": "p", "standard": "s", "expert": "e"}})
    first = client.get("/api/public/exposure/example.com")
    assert first.status_code == 200 and first.json()["domain"] == "example.com"
    second = client.get("/api/public/exposure/example.com")
    assert second.status_code == 200 and second.json()["cached"] is True
    assert runs == ["example.com"]
    third = client.get("/api/public/exposure/example.com")
    assert third.status_code == 200
    limited = client.get("/api/public/exposure/example.com")
    assert limited.status_code == 429 and limited.headers.get("Retry-After")


def test_the_endpoint_refuses_what_the_grade_refuses(client, monkeypatch):
    assert client.get("/api/public/exposure/localhost").status_code == 400
    assert client.get("/api/public/exposure/10.0.0.1").status_code == 400
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "example.com")
    assert client.get("/api/public/exposure/www.example.com").status_code == 403
