"""Inbound Jira / ServiceNow ticket sync (services/ticket_sync.py, routers/ticket_sync.py).

Payloads are recorded deliveries kept under fixtures/ticket_sync/. Their timestamps are re-stamped to
"now" before signing, because the receiver refuses events older than its replay window.
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
import db
from services import ticket_sync, ticketing

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ticket_sync")
ORG_A = "org-tickets-alpha"
ORG_B = "org-tickets-bravo"


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def _jira(name, ts=None):
    payload = _fixture(name)
    payload["timestamp"] = int((ts or time.time()) * 1000)
    return payload


def _snow(name, ts=None, **overrides):
    payload = _fixture(name)
    payload["sys_updated_on"] = datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    payload.update(overrides)
    return payload


def _body(payload):
    return json.dumps(payload).encode("utf-8")


def _jira_sig(secret, body):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture(scope="module")
def env():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    previous = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = tmp.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    db.init_db()
    with TestClient(fastapi_app.app) as client:
        yield client
    if previous is None:
        os.environ.pop("MORROW_SCANNER_DB", None)
    else:
        os.environ["MORROW_SCANNER_DB"] = previous


def _admin(org):
    return {"x-org-id": org, "x-user-id": "admin-1", "x-user-role": "admin"}


def _remediation(org, asset="api.acme.example:443", status="approved"):
    token = db.set_current_organization_id(org)
    try:
        row = db.create_remediation(asset, 0, "infra/tls.tf", "rsa-2048 key exchange", "use ML-KEM hybrid", status=status)
    finally:
        db.reset_current_organization_id(token)
    return int(row["id"])


def _link(org, provider, ticket_id, remediation_id, external_id=""):
    with closing(db.get_connection()) as conn:
        ticketing.init_tables(conn)
        conn.execute(
            """INSERT INTO auto_tickets (organization_id, provider, finding_ref, finding_type, ticket_url, ticket_id,
                   severity, title, created_at, external_id)
               VALUES (?, ?, ?, 'remediation', ?, ?, 'high', 'pq', ?, ?)""",
            (org, provider, str(remediation_id), f"https://tickets.example/{ticket_id}", ticket_id,
             datetime.now(timezone.utc).isoformat(), external_id),
        )
        conn.commit()


def _status(org, remediation_id):
    token = db.set_current_organization_id(org)
    try:
        return db.get_remediation(remediation_id)["status"]
    finally:
        db.reset_current_organization_id(token)


def _secret(client, org, provider):
    r = client.post("/tickets/sync/secret", json={"provider": provider}, headers=_admin(org))
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def _clear_ticket(org, provider, ticket_id):
    with closing(db.get_connection()) as conn:
        conn.execute("DELETE FROM auto_tickets WHERE organization_id=? AND provider=? AND ticket_id=?", (org, provider, ticket_id))
        conn.execute("DELETE FROM ticket_sync_state WHERE organization_id=? AND provider=? AND ticket_id=?", (org, provider, ticket_id))
        conn.commit()


def _audit_actions(org):
    token = db.set_current_organization_id(org)
    try:
        rows = db.list_audit_logs(limit=500)
    finally:
        db.reset_current_organization_id(token)
    return [r.get("action") for r in rows]


def _post_jira(client, org, secret, payload, **headers):
    body = _body(payload)
    h = {"Content-Type": "application/json", "X-Hub-Signature": _jira_sig(secret, body),
         "X-Atlassian-Webhook-Identifier": "8f0b1c4e", "X-Atlassian-Webhook-Flow": "Primary"}
    h.update(headers)
    return client.post(f"/integrations/tickets/inbound/jira/{org}", content=body, headers=h)


# ── Signature primitives ────────────────────────────────────────────────────


def test_jira_signature_matches_atlassian_test_vector():
    headers = {"x-hub-signature": "sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9"}
    assert ticket_sync.verify_jira("It's a Secret to Everybody", b"Hello World!", headers)
    assert not ticket_sync.verify_jira("It's a Secret to Everybody", b"Hello World?", headers)
    # An unknown method fails closed rather than being ignored.
    assert not ticket_sync.verify_jira("It's a Secret to Everybody", b"Hello World!",
                                       {"x-hub-signature": "sha1=a4771c39fbe90f317c7824e83ddef3caae9cb3d9"})


def test_inbound_paths_are_reachable_without_a_user_session():
    assert fastapi_app._auth_public_path("/integrations/tickets/inbound/jira/org-1")
    assert fastapi_app._auth_public_path("/v1/integrations/tickets/inbound/servicenow/org-1")
    assert not fastapi_app._auth_public_path("/tickets/sync/settings")


def test_status_rules():
    d = ticket_sync._decide
    assert d("approved", "", "", "resolved") == ("awaiting_verification", "awaiting_verification", "approved")
    assert d("verified_closed", "", "", "resolved")[0] == ""
    assert d("awaiting_verification", "resolved", "approved", "open") == ("approved", "reopened", "")
    assert d("verified_closed", "resolved", "", "open")[1] == "reopen_conflict_verified_closed"
    assert d("approved", "", "", "closed_without_fix")[0] == ""


# ── Jira ────────────────────────────────────────────────────────────────────


def test_jira_resolve_then_reopen_round_trip(env):
    client = env
    rid = _remediation(ORG_A)
    _link(ORG_A, "jira", "SEC-142", rid, external_id="10427")
    secret = _secret(client, ORG_A, "jira")

    r = _post_jira(client, ORG_A, secret, _jira("jira_issue_updated_resolved.json", ts=time.time() - 60))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "awaiting_verification"
    # A resolved ticket is a claim, not evidence: the finding is not closed by it.
    assert _status(ORG_A, rid) == "awaiting_verification"
    assert r.json()["rescan"]["queued"] is False  # no broker in the test run; reason is reported

    sync = client.get(f"/remediations/{rid}/ticket-sync", headers=_admin(ORG_A)).json()
    assert sync["tickets"][0]["external_state"] == "resolved"
    assert sync["tickets"][0]["last_outcome"] == "awaiting_verification"

    r = _post_jira(client, ORG_A, secret, _jira("jira_issue_updated_reopened.json"))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "reopened"
    assert _status(ORG_A, rid) == "approved"  # back to what it was before the ticket was resolved

    actions = _audit_actions(ORG_A)
    assert "ticket_sync.awaiting_verification" in actions and "ticket_sync.reopened" in actions
    assert "ticket_sync.reopened" not in _audit_actions(ORG_B)  # journaled in the ticket's own tenant only


def test_jira_bad_signature_is_refused_and_changes_nothing(env):
    client = env
    rid = _remediation(ORG_A)
    _clear_ticket(ORG_A, "jira", "SEC-142")
    _link(ORG_A, "jira", "SEC-142", rid)
    secret = _secret(client, ORG_A, "jira")
    payload = _jira("jira_issue_updated_resolved.json")

    r = _post_jira(client, ORG_A, secret, payload, **{"X-Hub-Signature": _jira_sig(secret + "x", _body(payload))})
    assert r.status_code == 401
    r = _post_jira(client, ORG_A, secret, payload, **{"X-Hub-Signature": ""})
    assert r.status_code == 401
    # Tampered body under the original signature.
    body = _body(payload)
    sig = _jira_sig(secret, body)
    r = client.post(f"/integrations/tickets/inbound/jira/{ORG_A}", content=body.replace(b"Done", b"Dune", 1),
                    headers={"X-Hub-Signature": sig, "Content-Type": "application/json"})
    assert r.status_code == 401
    assert _status(ORG_A, rid) == "approved"
    jira = [p for p in client.get("/tickets/sync/settings", headers=_admin(ORG_A)).json()["providers"] if p["provider"] == "jira"][0]
    assert jira["rejected_auth_count"] >= 3
    assert "secret" not in jira


def test_jira_wrong_org_cannot_touch_another_tenant(env):
    client = env
    rid_a = _remediation(ORG_A)
    _clear_ticket(ORG_A, "jira", "SEC-142")
    _link(ORG_A, "jira", "SEC-142", rid_a)
    secret_a = _secret(client, ORG_A, "jira")
    secret_b = _secret(client, ORG_B, "jira")
    payload = _jira("jira_issue_updated_resolved.json")

    # Org A's secret does not open org B's endpoint.
    assert _post_jira(client, ORG_B, secret_a, payload).status_code == 401
    # Org B's valid secret cannot name org A's ticket: it is unknown in org B.
    r = _post_jira(client, ORG_B, secret_b, payload)
    assert r.status_code == 404
    # An org with no secret at all answers the same as a bad signature.
    assert _post_jira(client, "org-tickets-nobody", secret_a, payload).status_code == 401
    assert _status(ORG_A, rid_a) == "approved"


def test_jira_replay_is_a_no_op(env):
    client = env
    rid = _remediation(ORG_A)
    _clear_ticket(ORG_A, "jira", "SEC-142")
    _link(ORG_A, "jira", "SEC-142", rid)
    secret = _secret(client, ORG_A, "jira")
    resolved = _jira("jira_issue_updated_resolved.json", ts=time.time() - 120)
    resolved["changelog"]["id"] = "replay-1"
    reopened = _jira("jira_issue_updated_reopened.json")
    reopened["changelog"]["id"] = "replay-2"

    assert _post_jira(client, ORG_A, secret, resolved).json()["outcome"] == "awaiting_verification"
    assert _post_jira(client, ORG_A, secret, reopened).json()["outcome"] == "reopened"
    replay = _post_jira(client, ORG_A, secret, resolved)  # byte-identical, validly signed
    assert replay.status_code == 200 and replay.json()["duplicate"] is True
    assert _status(ORG_A, rid) == "approved"

    # A captured delivery replayed after the window is refused outright.
    old = _jira("jira_issue_updated_resolved.json", ts=time.time() - 30 * 86400)
    old["changelog"]["id"] = "replay-old"
    assert _post_jira(client, ORG_A, secret, old).status_code == 400
    assert _status(ORG_A, rid) == "approved"


def test_jira_wont_do_is_not_a_fix(env):
    client = env
    rid = _remediation(ORG_A)
    _link(ORG_A, "jira", "SEC-145", rid)
    secret = _secret(client, ORG_A, "jira")
    r = _post_jira(client, ORG_A, secret, _jira("jira_issue_updated_wont_do.json"))
    assert r.status_code == 200 and r.json()["outcome"] == "closed_without_fix"
    assert _status(ORG_A, rid) == "approved"


def test_clean_rescan_closes_and_reopen_never_downgrades_verified(env):
    client = env
    rid = _remediation(ORG_A, asset="pay.acme.example:443")
    _link(ORG_A, "jira", "SEC-150", rid)
    secret = _secret(client, ORG_A, "jira")
    resolved = _jira("jira_issue_updated_resolved.json", ts=time.time() - 60)
    resolved["issue"]["key"], resolved["issue"]["id"], resolved["changelog"]["id"] = "SEC-150", "10450", "v-1"
    assert _post_jira(client, ORG_A, secret, resolved).json()["outcome"] == "awaiting_verification"

    token = db.set_current_organization_id(ORG_A)
    try:
        # A dirty scan does not close it.
        db.auto_close_merged_remediations("scan-dirty", [{"host": "pay.acme.example", "port": 443, "risk": "high",
                                                          "findings": [{"id": "rsa"}]}])
        assert db.get_remediation(rid)["status"] == "awaiting_verification"
        out = db.auto_close_merged_remediations("scan-clean", [{"host": "pay.acme.example", "port": 443, "findings": []}])
        assert out["closed"] == 1
        assert db.get_remediation(rid)["status"] == "verified_closed"
    finally:
        db.reset_current_organization_id(token)

    reopened = _jira("jira_issue_updated_reopened.json")
    reopened["issue"]["key"], reopened["issue"]["id"], reopened["changelog"]["id"] = "SEC-150", "10450", "v-2"
    r = _post_jira(client, ORG_A, secret, reopened)
    assert r.json()["outcome"] == "reopen_conflict_verified_closed"
    assert _status(ORG_A, rid) == "verified_closed"


def test_resolve_queues_a_verification_rescan_once(env, monkeypatch):
    rid = _remediation(ORG_A, asset="mail.acme.example:443")
    _link(ORG_A, "jira", "SEC-160", rid)
    dispatched = []
    monkeypatch.setattr(ticket_sync, "_dispatch_rescan", lambda org, asset: dispatched.append((org, asset)) or "scan-42")
    event = ticket_sync.normalize_jira(_jira("jira_issue_updated_resolved.json"), {}, b"")
    event["keys"], event["event_id"] = ["SEC-160"], "rescan-1"
    out = ticket_sync.apply_event(ORG_A, event, broker_ready=lambda: True)
    assert out["rescan"] == {"queued": True, "scan_id": "scan-42"}
    assert dispatched == [(ORG_A, "mail.acme.example:443")]
    event["event_id"] = "rescan-2"
    out = ticket_sync.apply_event(ORG_A, event, broker_ready=lambda: True)
    assert out["rescan"]["queued"] is False and len(dispatched) == 1  # debounced


# ── ServiceNow ──────────────────────────────────────────────────────────────


def test_servicenow_token_resolve_reopen_and_replay(env):
    client = env
    rid = _remediation(ORG_A, status="pr_created")
    _link(ORG_A, "servicenow", "INC0010023", rid, external_id="9d385017c611228701d22104cc95c371")
    secret = _secret(client, ORG_A, "servicenow")
    url = f"/integrations/tickets/inbound/servicenow/{ORG_A}"
    good = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}

    body = _body(_snow("servicenow_incident_resolved.json", ts=time.time() - 60))
    assert client.post(url, content=body, headers={**good, "Authorization": "Bearer wrong"}).status_code == 401
    assert client.post(url, content=body, headers={"Content-Type": "application/json"}).status_code == 401
    assert client.post(f"{url}?token={secret}", content=body, headers={"Content-Type": "application/json"}).status_code == 401
    assert _status(ORG_A, rid) == "pr_created"

    r = client.post(url, content=body, headers=good)
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "awaiting_verification"
    assert _status(ORG_A, rid) == "awaiting_verification"
    assert client.post(url, content=body, headers=good).json()["duplicate"] is True

    # An out-of-order retry of an older revision (lower sys_mod_count) is not applied.
    older = _body(_snow("servicenow_incident_reopened.json", sys_mod_count="5"))
    assert client.post(url, content=older, headers=good).json()["outcome"] == "stale"
    assert _status(ORG_A, rid) == "awaiting_verification"

    reopened = _body(_snow("servicenow_incident_reopened.json"))
    r = client.post(url, content=reopened, headers=good)
    assert r.json()["outcome"] == "reopened"
    assert _status(ORG_A, rid) == "pr_created"


def test_servicenow_hmac_signature_and_wrong_org(env):
    client = env
    rid = _remediation(ORG_A)
    _link(ORG_A, "servicenow", "INC0010099", rid, external_id="aa11")
    secret = _secret(client, ORG_A, "servicenow")
    secret_b = _secret(client, ORG_B, "servicenow")
    body = _body(_snow("servicenow_incident_resolved.json", number="INC0010099", sys_id="aa11"))
    mac = hmac.new(secret.encode(), body, hashlib.sha256).digest()

    bad = "sha256=" + base64.b64encode(hmac.new(b"nope", body, hashlib.sha256).digest()).decode()
    assert client.post(f"/integrations/tickets/inbound/servicenow/{ORG_A}", content=body,
                       headers={"X-Morrow-Signature": bad}).status_code == 401
    # A bad signature is not rescued by also sending a valid token.
    assert client.post(f"/integrations/tickets/inbound/servicenow/{ORG_A}", content=body,
                       headers={"X-Morrow-Signature": bad, "Authorization": f"Bearer {secret}"}).status_code == 401
    # Org B's token cannot reach org A's incident.
    assert client.post(f"/integrations/tickets/inbound/servicenow/{ORG_B}", content=body,
                       headers={"Authorization": f"Bearer {secret_b}"}).status_code == 404
    assert _status(ORG_A, rid) == "approved"

    # GlideCertificateEncryption.generateMac returns base64; hex is accepted too.
    r = client.post(f"/integrations/tickets/inbound/servicenow/{ORG_A}", content=body,
                    headers={"X-Morrow-Signature": "sha256=" + base64.b64encode(mac).decode()})
    assert r.status_code == 200 and r.json()["outcome"] == "awaiting_verification"


def test_unknown_ticket_is_refused(env):
    client = env
    secret = _secret(client, ORG_A, "servicenow")
    body = _body(_snow("servicenow_incident_resolved.json", number="INC9999999", sys_id="ffff"))
    r = client.post(f"/integrations/tickets/inbound/servicenow/{ORG_A}", content=body,
                    headers={"Authorization": f"Bearer {secret}"})
    assert r.status_code == 404


# ── Polling fallback, settings, outbound link ───────────────────────────────


def test_polling_is_off_by_default_and_applies_when_enabled(env, monkeypatch):
    monkeypatch.delenv("MORROW_TICKET_SYNC_POLL", raising=False)
    assert ticket_sync.poll_all()["skipped"] is True

    rid = _remediation(ORG_B)
    _link(ORG_B, "servicenow", "INC0020001", rid, external_id="9d385017c611228701d22104cc95c371")
    with closing(db.get_connection()) as conn:
        ticketing.save_config(conn, ORG_B, "servicenow", {"instance": "acme.service-now.com", "user": "svc", "password": "pw"})
    ticket_sync.set_poll_enabled(ORG_B, "servicenow", True)
    monkeypatch.setenv("MORROW_TICKET_SYNC_POLL", "1")
    monkeypatch.setenv("MORROW_TICKET_SYNC_ALLOW_PRIVATE_HOSTS", "1")  # no DNS in the suite
    seen = []

    def fetch(url, headers):
        seen.append(url)
        assert headers["Authorization"].startswith("Basic ")
        return _fixture("servicenow_table_api_record.json")

    out = ticket_sync.poll_all(fetch=fetch, broker_ready=lambda: False)
    assert out["organizations"] >= 1
    assert any("/api/now/table/incident/9d385017c611228701d22104cc95c371" in u for u in seen)
    assert _status(ORG_B, rid) == "awaiting_verification"
    # Polling again sees the same revision and changes nothing.
    ticket_sync.poll_all(fetch=fetch, broker_ready=lambda: False)
    assert _status(ORG_B, rid) == "awaiting_verification"


def test_settings_show_setup_but_never_the_secret(env):
    client = env
    _secret(client, ORG_A, "jira")
    view = client.get("/tickets/sync/settings", headers=_admin(ORG_A)).json()
    jira = [p for p in view["providers"] if p["provider"] == "jira"][0]
    assert jira["webhook_url"].endswith(f"/integrations/tickets/inbound/jira/{ORG_A}")
    assert jira["configured"] is True and jira["secret_hint"].startswith("…")
    with closing(sqlite3.connect(os.environ["MORROW_SCANNER_DB"])) as conn:
        sealed = conn.execute("SELECT secret_sealed FROM ticket_sync_settings WHERE organization_id=? AND provider='jira'",
                              (ORG_A,)).fetchone()[0]
    assert sealed.startswith("fernet:")
    viewer = {"x-org-id": ORG_A, "x-user-id": "v", "x-user-role": "viewer"}
    assert client.post("/tickets/sync/secret", json={"provider": "jira"}, headers=viewer).status_code == 403


def test_create_ticket_records_servicenow_link(env, monkeypatch):
    calls = []

    def fake_post(url, payload, headers, timeout=20):
        calls.append(url)
        return 201, {"result": {"sys_id": "bb22", "number": "INC0030001"}}

    monkeypatch.setattr(ticketing, "_http_post", fake_post)
    with closing(db.get_connection()) as conn:
        ticketing.init_tables(conn)
        ticketing.save_config(conn, ORG_A, "servicenow", {"instance": "acme.service-now.com", "user": "u", "password": "p"})
        out = ticketing.create_ticket(conn, ORG_A, "servicenow", "77", "remediation", "Rotate RSA", "body", "high")
        row = conn.execute("SELECT ticket_id, external_id FROM auto_tickets WHERE organization_id=? AND finding_ref='77'",
                           (ORG_A,)).fetchone()
    assert out["ticket_id"] == "INC0030001"
    assert tuple(row) == ("INC0030001", "bb22")
    assert calls[0].endswith("/api/now/table/incident")
