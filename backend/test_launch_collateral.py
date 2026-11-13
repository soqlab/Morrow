import pathlib

from fastapi.testclient import TestClient

from app import app

#: The free checker's public documents. The service must not be switched on for the public
#: without them, so they are enumerated once and every test below works from this one set. The old
#: scanner-identity page (/scanner) redirects to /about-scanner, which is the instrument's own view.
CHECKER_DOCUMENTS = (
    "/public-check/terms",
    "/public-check/acceptable-use",
    "/public-check/privacy",
    "/abuse",
)

#: The traditional website's pages that the instrument replaced, and where each address lands now.
RETIRED_PAGES = {
    "/trial": "/ui/",
    "/trial-request": "/ui/",
    "/scanner": "/about-scanner",
    "/check": "/",
}

#: Every public document that now wears the instrument's chrome instead of the marketing navigation.
DOCUMENT_FILES = (
    "terms.html", "privacy.html", "dpa.html", "security.html", "support.html", "data-boundary.html",
    "check-terms.html", "check-acceptable-use.html", "check-privacy.html", "check-abuse.html",
    "pricing.html", "pilot.html", "airlock-deployment.html", "enterprise-admin.html",
    "trust-passport-demo.html", "ai-trust.html",
)


def test_public_launch_pages_are_served():
    client = TestClient(app)
    routes = {
        "/enterprise-admin": "Enterprise Control Center",
        "/admin-page": "Enterprise Control Center",
        # The passport page explains a real passport; it no longer presents itself as a demo.
        "/trust-passport-demo": "Proof a buyer can actually review.",
        "/security": "minimum customer access",
        # No personal inbox is published until a company contact is confirmed.
        "/support": "How to reach us",
        "/privacy": "Privacy Policy",
        "/terms": "Terms of Service",
        # The service is free, so the page that used to list editions now says there is nothing to
        # pay and what that does and does not mean. The caveat is load-bearing: free with no SLA is
        # only honest if the page says there is no SLA.
        "/pricing": "Morrow is free",
        "/pilot": "6-8 week",
        "/data-boundary": "Platform traffic metadata",
        "/airlock-deployment": "Validate one collection",
        "/dpa": "Contract review required",
        # The checker's public documents. The free checker must not be switched on publicly
        # without them, so a missing one is a launch blocker and not a cosmetic gap. Each phrase is
        # load-bearing: the terms bind on use, the acceptable-use policy names the prohibition that
        # separates this from a reconnaissance tool, the privacy notice has two subjects, the abuse
        # page promises an opt-out before DNS.
        "/public-check/terms": "they bind on use",
        "/public-check/acceptable-use": "Mapping someone else's attack surface",
        "/public-check/privacy": "If You Are The Party Being Checked",
        "/abuse": "Never check my domain again",
    }

    # The old product overview was retired with its decorative scenes; its addresses land on the
    # live instrument at /.
    for old in ("/launch", "/landing"):
        moved = client.get(old, follow_redirects=False)
        assert moved.status_code == 308 and moved.headers["location"] == "/", old
    assert "/ui/instrument.js" in client.get("/").text

    for path, phrase in routes.items():
        response = client.get(path)
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert phrase in response.text

    css = client.get("/ui/public.css")
    assert css.status_code == 200
    assert "proof-panel" in css.text

    # The documents' sheet, and the record pages' own: both served from this origin. The record
    # pages at /r/{domain} are server-rendered; without registry.css they are unstyled for every
    # visitor and every crawler.
    for asset, marker in (("/ui/doc.css", ".doc .doc-section"),
                          ("/ui/registry.css", "registry-page")):
        response = client.get(asset)
        assert response.status_code == 200, asset
        assert marker in response.text, asset


def test_public_information_remains_accessible_with_production_auth(monkeypatch):
    import app as module

    monkeypatch.setattr(module, "AUTH_REQUIRED", True)
    monkeypatch.setattr(module, "AUTH_MODE", "jwt")
    with TestClient(module.app) as client:
        for path in module._PUBLIC_INFO_PAGES:
            response = client.get(path)
            assert response.status_code == 200, path
            assert "must-revalidate" in response.headers["cache-control"]
        assert client.get("/assets").status_code in {401, 403}


def test_access_policy_matches_landing_route():
    client = TestClient(app)
    policy = client.get("/auth/access-policy").json()
    paths = {item["path"] for item in policy["public_no_login"]}
    assert "/" in paths
    assert "/" not in policy["login_required"]
    # The free checker is no-login by design, so the published policy has to say so.
    assert "/check" in paths
    assert "/api/public-check" in paths
    # Its documents too: a domain owner who found one of our handshakes in their logs has no
    # account and never will, so /scanner and /abuse above all have to answer without one.
    for path in CHECKER_DOCUMENTS:
        assert path in paths, path


def test_the_checker_documents_are_reachable_without_authentication():
    import app as module

    for path in CHECKER_DOCUMENTS:
        assert module._auth_public_path(path), path
    # No inline script, no inline handler, no off-origin asset on any of them, so they belong on
    # the strict Content-Security-Policy with /check rather than the permissive one.
    for path in CHECKER_DOCUMENTS:
        assert module._csp_for(path) == module._CSP_STRICT_VALUE, path


def test_the_retired_pages_redirect_and_never_404():
    """Old addresses keep working: a bookmark or a README link lands on what replaced the page."""
    client = TestClient(app)
    for path, target in RETIRED_PAGES.items():
        for method in ("GET", "HEAD"):
            moved = client.request(method, path, follow_redirects=False)
            assert moved.status_code == 308, (method, path, moved.status_code)
            assert moved.headers["location"] == target, (path, moved.headers["location"])
    # The old checker's pre-filled form becomes that domain's page; nonsense lands on the input.
    assert client.get("/check?domain=Example.COM", follow_redirects=False).headers["location"] == "/example.com"
    assert client.get("/check?domain=not%20a%20host", follow_redirects=False).headers["location"] == "/"
    moved = client.get("/scanner?host=corp.example", follow_redirects=False)
    assert moved.headers["location"] == "/about-scanner?host=corp.example"
    # And none of them is a login wall.
    import app as module

    for path in RETIRED_PAGES:
        assert module._auth_public_path(path), path


def test_the_sitemap_no_longer_lists_the_retired_pages(monkeypatch):
    import re

    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://airlock.test")
    body = TestClient(app).get("/sitemap.xml").text
    paths = {loc.replace("https://airlock.test", "") for loc in re.findall(r"<loc>([^<]+)</loc>", body)}
    for path in RETIRED_PAGES:
        assert path not in paths, path
    assert "/about-scanner" in paths and "/abuse" in paths


def test_no_public_page_keeps_the_old_marketing_navigation_or_a_trial_link():
    static = pathlib.Path(__file__).parent / "static"
    for path in sorted(static.glob("*.html")):
        body = path.read_text(encoding="utf-8")
        assert 'aria-label="Public navigation"' not in body, path.name
        assert 'href="/trial' not in body, path.name
        assert 'href="/scanner"' not in body, path.name
    for name in ("instrument.js", "instrument-watch.js", "oops.js"):
        body = (static / name).read_text(encoding="utf-8")
        for stale in ('href="/trial', 'href="/check"', 'h: "/check"', 'href: "/check"', '["/check"', 'href="/scanner"'):
            assert stale not in body, (name, stale)
    # The console copy and its frontend twin say how an account is made now, and stay identical.
    console = (static / "index.html").read_bytes()
    assert console == (pathlib.Path(__file__).parent.parent / "frontend" / "index.html").read_bytes()
    assert b'href="/trial"' not in console


def test_the_documents_wear_the_instrument_chrome_and_link_the_opt_out():
    """Terms, policies and the checker's documents: the instrument's header and footer around
    the unchanged text, and the opt-out one click away from every one of them."""
    static = pathlib.Path(__file__).parent / "static"
    for name in DOCUMENT_FILES:
        body = (static / name).read_text(encoding="utf-8")
        assert '<body class="ins doc"' in body, name
        assert '<a class="i-mark" href="/">MORROW</a>' in body, name
        assert "/ui/instrument.css" in body and "/ui/doc.css" in body, name
        assert "/ui/public.css" not in body, name
        footer = body[body.index('<footer class="i-foot">'):]
        assert 'href="/abuse"' in footer and 'href="/about-scanner"' in footer, name
    for name in ("pricing.html", "instrument.html"):
        body = (static / name).read_text(encoding="utf-8")
        footer = body[body.index("<footer"):]
        assert 'href="/about-scanner"' in footer and 'href="/abuse"' in footer, name


def test_every_checker_document_links_the_others_and_says_it_is_a_draft():
    client = TestClient(app)
    for path in CHECKER_DOCUMENTS:
        body = client.get(path).text
        for other in CHECKER_DOCUMENTS:
            if other != path:
                assert f'href="{other}"' in body, f"{path} does not link {other}"
        assert 'href="/"' in body, f"{path} does not link the instrument itself"
        assert "qualified lawyer" in body, (
            f"{path} must say plainly that it is a draft for a lawyer to review")


def test_nothing_invents_an_abuse_address_when_none_is_configured(monkeypatch):
    """An unset abuse contact has to read as unset, not as a plausible-looking address."""
    for name in ("MORROW_PUBLIC_CHECK_ABUSE_CONTACT", "MORROW_SUPPORT_EMAIL", "MORROW_SECURITY_CONTACT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(app)
    assert client.get("/api/public-check/config").json()["acceptable_use"]["abuse_contact"] == ""

    static = pathlib.Path(__file__).parent / "static"
    for name in ("check-abuse.html", "check-terms.html", "check-acceptable-use.html",
                 "check-privacy.html"):
        body = (static / name).read_text(encoding="utf-8")
        assert "mailto:" not in body, f"{name} ships an address in its markup"
        assert "data-abuse-contact" in body, f"{name} has no slot for the published address"
        assert "no abuse address is configured" in body.lower(), name

    # The address is filled in from the live config, from this origin, with no inline script.
    script = client.get("/ui/check-pages.js")
    assert script.status_code == 200
    assert "/api/public-check/config" in script.text


def test_about_scanner_publishes_what_the_certificate_check_actually_sends():
    """/scanner used to describe the certificate-transparency check; /about-scanner does now."""
    from services import public_check

    client = TestClient(app)
    moved = client.get("/scanner", follow_redirects=False)
    assert moved.status_code == 308 and moved.headers["location"] == "/about-scanner"

    facts = client.get("/api/public/scanner").json()
    record = [w for w in facts["what"] if "certificate-transparency" in w["part"].lower()]
    assert len(record) == 1, facts["what"]
    sends = record[0]["sends"]
    assert f"port {public_check.PORT}" in sends
    assert "at most two TLS connections" in sends
    # No HTTP request is made to the target, so the page must not suggest one.
    assert "No HTTP request to your host" in sends
    assert "not from your server" in sends


def test_the_public_checker_declares_its_boundaries_on_its_own_page():
    """The acceptable-use statement is on the result page, not buried in the terms."""
    client = TestClient(app)
    config = client.get("/api/public-check/config")
    assert config.status_code == 200
    body = config.json()

    use = body["acceptable_use"]
    assert use["summary"]
    assert any("port 443" in line or "443" in line for line in use["does"])
    joined = " ".join(use["does_not"]).lower()
    for promise in ("no port scanning", "no subdomain", "no vulnerability probing", "no crawling"):
        assert promise in joined, promise

    # A caller that never sees the page -- the API, the command line -- still has to be able to
    # find the documents, and every one of them has to be served.
    documents = use["documents"]
    assert set(CHECKER_DOCUMENTS) <= set(documents.values())
    for path in documents.values():
        assert client.get(path).status_code == 200, path

    guardrails = body["guardrails"]
    assert guardrails["port"] == 443
    assert guardrails["cache_seconds"] >= 600
    assert guardrails["checks_per_domain_per_hour"] >= 1
    assert guardrails["max_queued_checks"] >= 1
    assert body["limits"] and body["what_a_full_assessment_adds"]


def test_the_sitemap_lists_only_pages_that_answer(monkeypatch):
    """A sitemap advertising a 404 is worse than no sitemap: it is submitted to search engines."""
    import re

    import app as application

    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://airlock.test")
    with TestClient(application.app) as client:
        sitemap = client.get("/sitemap.xml")
        assert sitemap.status_code == 200
        assert sitemap.headers["content-type"].startswith("application/xml")

        locations = re.findall(r"<loc>([^<]+)</loc>", sitemap.text)
        assert len(locations) >= 10, "the sitemap is suspiciously short"
        # A sitemap needs absolute URLs on the canonical hostname, not request-relative ones.
        assert all(loc.startswith("https://airlock.test/") for loc in locations), locations

        for loc in locations:
            path = loc.replace("https://airlock.test", "") or "/"
            assert client.get(path).status_code == 200, f"{path} is in the sitemap but does not answer"

        # Nothing behind a login belongs here, and robots.txt disallows these anyway.
        for forbidden in ("/ui/", "/vendor-admin", "/platform/", "/api/"):
            assert not any(forbidden in loc for loc in locations), forbidden


def test_robots_names_the_sitemap_with_an_absolute_url(monkeypatch):
    """A relative Sitemap: line is silently ignored by crawlers, so the route expands it."""
    import app as application

    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://airlock.test")
    with TestClient(application.app) as client:
        body = client.get("/robots.txt").text
    lines = [line for line in body.splitlines() if line.startswith("Sitemap:")]
    assert lines == ["Sitemap: https://airlock.test/sitemap.xml"], lines
