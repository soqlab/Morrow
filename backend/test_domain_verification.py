"""Verified domains and self sign-up (services/domain_verification, routers/trial_requests).

With MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS=1 an organization scans only hosts under domains it has
verified with a DNS TXT record. Reuses the real-stack fixture from test_invite_landing, which
refuses every real network connection, so a scan that is *allowed* fails on the network instead
of with NOT_PERMITTED, and that difference is what these tests read.
"""

from types import SimpleNamespace

import pytest

from test_invite_landing import PASSWORD, api, make_org  # noqa: F401  (api is a fixture)

from services import domain_verification as dv


@pytest.fixture
def enforced(api, monkeypatch):
    monkeypatch.setenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", "1")
    monkeypatch.delenv("MORROW_SCAN_UNRESTRICTED_ORGS", raising=False)
    monkeypatch.setattr(dv, "_ready", False)  # each test has its own database file
    dv._cache.clear()
    yield api
    dv._cache.clear()


def bearer(client, app, email="admin@acme.example", org="org-acme", role="admin"):
    with app._db() as db:
        app._issuer_create_user(db, email, PASSWORD, "", role, org)
    token = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
    return {"Authorization": "Bearer " + token}


def verify(monkeypatch, org, domain):
    row = dv.add_domain(org, domain)
    monkeypatch.setattr(dv, "_txt_values", lambda name: [row["record_value"]] if name == row["record_name"] else [])
    assert dv.verify_domain(org, domain)["status"] == "verified"


@pytest.mark.parametrize("typed,expected", [
    ("Example.COM", "example.com"), ("https://www.example.com/path?q=1", "www.example.com"),
    ("example.com:8443", "example.com"), ("*.example.com", "example.com"), ("example.com.", "example.com"),
])
def test_normalize_domain(typed, expected):
    assert dv.normalize_domain(typed) == expected


@pytest.mark.parametrize("typed", ["10.0.0.1", "[2001:db8::1]", "localhost", "not a domain", "", "-bad-.com"])
def test_normalize_domain_refuses(typed):
    with pytest.raises(dv.DomainError):
        dv.normalize_domain(typed)


def test_only_verified_domains_and_their_subdomains_are_scannable(enforced, monkeypatch):
    verify(monkeypatch, "org-acme", "acme.example")
    assert dv.refusal("org-acme", "acme.example") == ""
    assert dv.refusal("org-acme", "vpn.eu.acme.example") == ""
    assert dv.refusal("org-acme", "VPN.Acme.Example.") == ""
    assert dv.refusal("org-acme", "notacme.example")          # look-alike suffix
    assert dv.refusal("org-acme", "acme.example.evil.test")   # verified name as a prefix
    assert dv.refusal("org-acme", "93.184.216.34")            # IP addresses can't be verified
    assert dv.refusal("org-other", "acme.example")            # another organization's domain


def test_unverified_pending_domain_does_not_count(enforced, monkeypatch):
    row = dv.add_domain("org-acme", "acme.example")
    monkeypatch.setattr(dv, "_txt_values", lambda name: ["morrow-verify=a-different-token"])
    result = dv.verify_domain("org-acme", "acme.example")
    assert result["status"] == "pending" and result["verified_now"] is False
    assert row["record_value"] in result["last_error"]
    assert dv.refusal("org-acme", "acme.example")


def test_default_org_is_refused_and_listed_orgs_are_not_restricted(enforced, monkeypatch):
    client, app = enforced
    assert dv.refusal(app.DEFAULT_ORG_ID, "acme.example")      # a context that lost its organization
    monkeypatch.setenv("MORROW_SCAN_UNRESTRICTED_ORGS", "org-pilot")
    assert dv.refusal("org-pilot", "anything.example") == ""


def test_scanners_refuse_before_opening_a_socket(enforced):
    import socket
    from db import reset_current_organization_id, set_current_organization_id
    from scanner import scan_host
    from ssh_scanner import scan_ssh

    token = set_current_organization_id("org-acme")
    try:
        tls = scan_host("unverified.example", 443)
        ssh = scan_ssh("unverified.example", 22)
    finally:
        reset_current_organization_id(token)
    # The fixture makes socket.create_connection raise; reaching it would be a different error.
    assert tls["error_code"] == "NOT_PERMITTED" and tls["scan_status"] == "not_permitted"
    assert ssh["error_code"] == "NOT_PERMITTED"
    assert socket.create_connection.__name__ == "no_network"


def test_scan_worker_threads_keep_the_organization(enforced, monkeypatch):
    client, app = enforced
    verify(monkeypatch, "org-acme", "acme.example")
    seen = []

    def fake_scan(host, port):
        seen.append(dv.refusal_for_current_org(host))
        return {"host": host, "port": port, "findings": []}

    monkeypatch.setattr(app, "scan_host", fake_scan)
    app._scan_worker("scan-ctx-1", ["vpn.acme.example", "mail.acme.example"], "org-acme")
    assert seen == ["", ""]


def test_api_adds_verifies_and_gates_scans(enforced, monkeypatch):
    client, app = enforced
    make_org(client, "org-acme", "Acme")
    auth = bearer(client, app)
    added = client.post("/domains", json={"domain": "https://Acme.example/"}, headers=auth)
    assert added.status_code == 200, added.text
    record = added.json()["domain"]
    assert record["record_name"] == "_morrow-verify.acme.example" and record["status"] == "pending"

    refused = client.post("/scan", json={"targets": ["vpn.acme.example"]}, headers=auth)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "domain_not_verified"

    monkeypatch.setattr(dv, "_txt_values", lambda name: [record["record_value"]])
    assert client.post("/domains/acme.example/verify", headers=auth).json()["domain"]["status"] == "verified"
    listed = client.get("/domains", headers=auth).json()
    assert listed["enforced"] is True and [d["domain"] for d in listed["domains"]] == ["acme.example"]

    allowed = client.post("/scan", json={"targets": ["vpn.acme.example"]}, headers=auth)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["results"][0]["error_code"] != "NOT_PERMITTED"
    assert client.post("/scan", json={"targets": ["1.1.1.1"]}, headers=auth).status_code == 403


def test_viewer_cannot_add_domains(enforced):
    client, app = enforced
    make_org(client, "org-acme", "Acme")
    auth = bearer(client, app, email="viewer@acme.example", role="viewer")
    assert client.post("/domains", json={"domain": "acme.example"}, headers=auth).status_code == 403
    assert client.get("/domains", headers=auth).status_code == 200


class InlineThread:
    def __init__(self, target=None, **kwargs):
        self.target = target

    def start(self):
        self.target()


def test_self_signup_creates_the_org_and_emails_the_invitation(enforced, monkeypatch):
    client, app = enforced
    from routers import trial_requests as trial_router
    from services import platform_mail

    sent = []
    monkeypatch.setenv("MORROW_SELF_SIGNUP", "1")
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://app.example")
    monkeypatch.setattr(platform_mail, "configured", lambda: True)
    monkeypatch.setattr(platform_mail, "send_text",
                        lambda to, subject, body, timeout=20.0: sent.append((to, subject, body)) or {"ok": True})
    monkeypatch.setattr(trial_router, "threading", SimpleNamespace(Thread=InlineThread))
    res = client.post("/api/trial-request", json={"email": "founder@newco.example", "name": "Founder", "company": "NewCo",
                                                  "domain": "newco.example", "use_case": "Self sign-up test."})
    assert res.status_code == 200 and res.json()["self_serve"] is True
    invite = [m for m in sent if m[0] == ["founder@newco.example"]]
    assert len(invite) == 1 and "https://app.example/invite#token=" in invite[0][2]


def test_self_signup_needs_verified_domain_enforcement(api, monkeypatch):
    client, app = api
    from services import platform_mail

    monkeypatch.setenv("MORROW_SELF_SIGNUP", "1")
    monkeypatch.delenv("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", raising=False)
    monkeypatch.setenv("MORROW_PUBLIC_BASE_URL", "https://app.example")
    monkeypatch.setattr(platform_mail, "configured", lambda: True)
    res = client.post("/api/trial-request", json={"email": "x@newco.example", "name": "X", "company": "NewCo",
                                                  "domain": "newco.example", "use_case": "Should wait for a person."})
    assert res.status_code == 200 and res.json()["self_serve"] is False
