import pathlib

from fastapi.testclient import TestClient

from app import app

#: The free checker's five public documents. The service must not be switched on for the public
#: without them, so they are enumerated once and every test below works from this one set.
CHECKER_DOCUMENTS = (
    "/public-check/terms",
    "/public-check/acceptable-use",
    "/public-check/privacy",
    "/abuse",
    "/scanner",
)


def test_public_launch_pages_are_served():
    client = TestClient(app)
    routes = {
        "/launch": "Prove quantum readiness without deep customer access.",
        "/landing": "Prove quantum readiness without deep customer access.",
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
        "/pricing": "Airlock Command is free",
        "/pilot": "6-8 week",
        "/data-boundary": "Platform traffic metadata",
        "/airlock-deployment": "Validate one collection",
        "/dpa": "Contract review required",
        # The free public readiness checker: the shop window, and the only public page that
        # contacts anything, so its acceptable-use statement is on the page itself.
        "/check": "Is your TLS quantum",
        # The only route a stranger has to an account. A broken /trial is a silent failure: the
        # site works, nobody can ask for access, and the symptom is no requests arriving.
        "/trial": "Ask for a trial",
        # The checker's five public documents. The free checker must not be switched on publicly
        # without them, so a missing one is a launch blocker and not a cosmetic gap. Each phrase is
        # load-bearing: the terms bind on use, the acceptable-use policy names the prohibition that
        # separates this from a reconnaissance tool, the privacy notice has two subjects, the abuse
        # page promises an opt-out before DNS, and the scanner page exists for an operator reading
        # their own logs.
        "/public-check/terms": "they bind on use",
        "/public-check/acceptable-use": "Mapping someone else's attack surface",
        "/public-check/privacy": "If You Are The Party Being Checked",
        "/abuse": "Never check my domain again",
        "/scanner": "You found us in your logs",
    }

    for path, phrase in routes.items():
        response = client.get(path)
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert phrase in response.text

    css = client.get("/ui/public.css")
    assert css.status_code == 200
    assert "proof-panel" in css.text

    # The checker's own assets, which the page needs and which must be served from this origin.
    for asset, marker in (("/ui/check.css", "prefers-color-scheme: light"),
                          ("/ui/check.js", "/api/public-check"),
                          # The record pages at /r/{domain} are server-rendered and load this one
                          # sheet of their own; without it they are unstyled for every visitor and
                          # every crawler.
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


def test_the_checker_links_its_documents_where_they_are_actually_needed():
    """Terms that bind on use have to be at the point of use, not only in a footer."""
    client = TestClient(app)
    page = client.get("/check").text
    for href in CHECKER_DOCUMENTS:
        assert f'href="{href}"' in page, href

    form = page[page.index('id="check-form"'):page.index("</form>")]
    for href in ("/public-check/terms", "/public-check/acceptable-use", "/abuse"):
        assert href in form, (
            f"{href} must be linked beside the input box: there is no account and no "
            "click-through, so acceptance happens where the visitor presses the button")

    # What a domain owner sees when somebody sends them a permalink.
    result = page[page.index('id="check-result"'):page.index('id="acceptable-use"')]
    for href in ("/public-check/privacy", "/abuse", "/scanner"):
        assert href in result, f"the result page does not link {href}"

    # The public footer, on a page a stranger reaches from anywhere on the site.
    for name in ("pricing.html", "landing.html"):
        body = (pathlib.Path(__file__).parent / "static" / name).read_text(encoding="utf-8")
        footer = body[body.index("<footer"):]
        assert 'href="/scanner"' in footer and 'href="/abuse"' in footer, name


def test_every_checker_document_links_the_others_and_says_it_is_a_draft():
    client = TestClient(app)
    for path in CHECKER_DOCUMENTS:
        body = client.get(path).text
        for other in CHECKER_DOCUMENTS:
            if other != path:
                assert f'href="{other}"' in body, f"{path} does not link {other}"
        assert 'href="/check"' in body, f"{path} does not link the checker itself"
        assert "qualified lawyer" in body, (
            f"{path} must say plainly that it is a draft for a lawyer to review")


def test_nothing_invents_an_abuse_address_when_none_is_configured(monkeypatch):
    """An unset abuse contact has to read as unset, not as a plausible-looking address."""
    for name in ("PQC_PUBLIC_CHECK_ABUSE_CONTACT", "PQC_SUPPORT_EMAIL", "PQC_SECURITY_CONTACT_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(app)
    assert client.get("/api/public-check/config").json()["acceptable_use"]["abuse_contact"] == ""

    static = pathlib.Path(__file__).parent / "static"
    for name in ("check-abuse.html", "check-terms.html", "check-acceptable-use.html",
                 "check-privacy.html", "check-scanner.html"):
        body = (static / name).read_text(encoding="utf-8")
        assert "mailto:" not in body, f"{name} ships an address in its markup"
        assert "data-abuse-contact" in body, f"{name} has no slot for the published address"
        assert "no abuse address is configured" in body.lower(), name

    # The address is filled in from the live config, from this origin, with no inline script.
    script = client.get("/ui/check-pages.js")
    assert script.status_code == 200
    assert "/api/public-check/config" in script.text


def test_the_scanner_identity_page_publishes_what_the_code_actually_sends():
    from services import public_check

    body = TestClient(app).get("/scanner").text
    source = (pathlib.Path(__file__).parent / "services" / "public_check.py").read_text(encoding="utf-8")

    agent = "airlock-public-check/1.0"
    assert agent in body, "the identity page does not state the User-Agent"
    assert f'"User-Agent": "{agent}"' in source, (
        "the identity page publishes a User-Agent the code no longer sends")
    # It is sent to the Certificate Transparency service, not to the checked host, because no HTTP
    # request is ever made to the target. Saying otherwise would send an operator looking for a
    # string that cannot appear in their logs.
    assert "not to you" in body
    assert str(public_check.PORT) in body
    # The egress addresses are the operator's to supply, and are marked as missing until they do.
    assert "PLACEHOLDER" in body


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
    assert set(documents.values()) == set(CHECKER_DOCUMENTS)
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

    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://airlock.test")
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

    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://airlock.test")
    with TestClient(application.app) as client:
        body = client.get("/robots.txt").text
    lines = [line for line in body.splitlines() if line.startswith("Sitemap:")]
    assert lines == ["Sitemap: https://airlock.test/sitemap.xml"], lines
