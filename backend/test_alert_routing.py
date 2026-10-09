"""Alert routing: channel API, secret handling, SSRF refusal, the dispatcher and test sends.

No test touches the network: DNS (alert_routing.resolve_host), the pinned HTTPS connection
(alert_routing.open_connection), PagerDuty's urlopen and smtplib.SMTP are all replaced, and a guard
makes any real socket connection fail the test.
"""

import json
import socket
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from services import alert_routing as ar

LEGACY = "alert-routing-tests-platform-key-0123456789abcdef"
SLACK_URL = "https://hooks.slack.test/services/T000/B000/secretvalue1234"
PD_KEY = "abcdefghijklmnopqrstuvwxyz012345"
PUBLIC_IP = "93.184.216.34"


def headers(role=None):
    h = {"x-platform-key": LEGACY}
    if role:
        h["x-platform-admin-role"] = role
    return h


class FakeResponse:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body


class Network:
    """Records outbound webhook, PagerDuty and SMTP traffic instead of sending it."""

    def __init__(self):
        self.webhooks, self.pagerduty, self.emails, self.connections = [], [], [], []
        self.webhook_status = 200
        self.dns = {}
        self.raise_on_send = None

    # DNS
    def resolve(self, host, port):
        if host in self.dns:
            return self.dns[host]
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
            return [host]
        except OSError:
            return [PUBLIC_IP]

    # webhook connection
    def open_connection(self, host, port, address, timeout):
        net = self

        class Conn:
            def request(self, method, path, body=None, headers=None):
                if net.raise_on_send:
                    raise net.raise_on_send
                net.connections.append((host, port, address))
                net.webhooks.append({"host": host, "address": address, "path": path, "json": json.loads(body)})

            def getresponse(self):
                return FakeResponse(net.webhook_status, b"ok" if net.webhook_status == 200 else b"error")

            def close(self):
                pass
        return Conn()

    # PagerDuty (services/alerting.py uses urllib.request.urlopen)
    def urlopen(self, req, timeout=10):
        payload = json.loads(req.data.decode())
        assert req.full_url == "https://events.pagerduty.com/v2/enqueue"
        self.pagerduty.append(payload)

        class Resp:
            status = 202

            def read(self):
                return json.dumps({"status": "success", "dedup_key": payload.get("dedup_key"), "message": "Event processed"}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Resp()

    # SMTP
    def smtp(self, host, port, timeout=None):
        net = self

        class Server:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self):
                pass

            def login(self, user, password):
                pass

            def send_message(self, msg, from_addr=None, to_addrs=None):
                net.emails.append({"to": to_addrs, "subject": msg["Subject"], "body": msg.get_content()})
        return Server()


@pytest.fixture
def net(monkeypatch):
    fake = Network()
    monkeypatch.setattr(ar, "resolve_host", fake.resolve)
    monkeypatch.setattr(ar, "open_connection", fake.open_connection)
    from services import alerting
    import smtplib
    monkeypatch.setattr(alerting.urllib.request, "urlopen", fake.urlopen)
    monkeypatch.setattr(smtplib, "SMTP", fake.smtp)

    def no_network(*args, **kwargs):
        raise AssertionError("a test tried to open a real network connection")
    monkeypatch.setattr(socket, "create_connection", no_network)
    return fake


@pytest.fixture
def api(tmp_path, monkeypatch, net):
    import app

    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.delenv("PQC_PLATFORM_OPERATORS", raising=False)
    monkeypatch.delenv("PQC_PLATFORM_ADMIN_KEY_ROLE", raising=False)
    for name in ("PQC_ALERT_RATE_CAP", "PQC_ALERT_RENOTIFY_HOURS", "PQC_ALERT_RATE_WINDOW_MINUTES", "PQC_SMTP_HOST", "PQC_PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(app, "_PLATFORM_ADMIN_KEY", LEGACY)
    monkeypatch.setattr(app, "PRODUCTION_ENVIRONMENT", False)
    monkeypatch.setattr(app, "RATE_LIMIT_MAX_REQUESTS", 100000)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app.init_db()
    client = TestClient(app.app, client=("192.0.2.30", 40000))
    yield client, app
    client.close()


def make_channel(client, **overrides):
    body = {"kind": "slack_webhook", "name": "On-call Slack", "target": SLACK_URL, "min_severity": "warn", "reason": "route alerts"}
    body.update(overrides)
    res = client.post("/platform/alert-channels", headers=headers("operator"), json=body)
    assert res.status_code == 200, res.text
    return res.json()["channel"]


def admin_events(app):
    from contextlib import closing
    from db import get_connection
    with closing(get_connection()) as conn:
        return [(r[0], r[1], json.loads(r[2] or "{}")) for r in
                conn.execute("SELECT action, reason, details_json FROM platform_admin_events ORDER BY id").fetchall()]


def item(id_, severity="critical", kind="sla_breach", title=None, created_at="2026-09-16T10:00:00Z"):
    return {"id": id_, "severity": severity, "kind": kind, "title": title or f"Alert {id_}", "detail": "detail text",
            "created_at": created_at, "route": "#/notifications"}


def snapshot(items, unavailable=None, total=None):
    return lambda: {"items": list(items), "unavailable": unavailable or [],
                    "counts": {"total": total if total is not None else len(items)}}


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


# ── Channel API ──────────────────────────────────────────────────────────────


def test_channel_crud_needs_the_right_roles_and_is_audited(api):
    client, app = api
    body = {"kind": "slack_webhook", "name": "Slack", "target": SLACK_URL, "reason": "route alerts"}
    assert client.get("/platform/alert-channels").status_code == 403
    assert client.get("/platform/alert-channels", headers=headers("auditor")).status_code == 200
    assert client.post("/platform/alert-channels", headers=headers("auditor"), json=body).status_code == 403
    assert client.post("/platform/alert-channels", headers=headers("support"), json=body).status_code == 403
    no_reason = dict(body)
    no_reason.pop("reason")
    assert client.post("/platform/alert-channels", headers=headers("operator"), json=no_reason).status_code == 422

    channel = make_channel(client)
    cid = channel["id"]
    assert client.put(f"/platform/alert-channels/{cid}", headers=headers("auditor"), json={"enabled": False, "reason": "x-y-z"}).status_code == 403
    updated = client.put(f"/platform/alert-channels/{cid}", headers=headers("owner"),
                         json={"enabled": False, "min_severity": "critical", "kinds": ["sla_breach"], "reason": "quieter"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["channel"]["enabled"] is False and updated.json()["channel"]["kinds"] == ["sla_breach"]
    assert set(updated.json()["changed"]) >= {"enabled", "min_severity", "kinds"}
    assert client.delete(f"/platform/alert-channels/{cid}", headers=headers("operator")).status_code == 422
    assert client.delete(f"/platform/alert-channels/{cid}?reason=cleanup", headers=headers("auditor")).status_code == 403
    assert client.delete(f"/platform/alert-channels/{cid}?reason=cleanup", headers=headers("operator")).status_code == 200
    assert client.delete(f"/platform/alert-channels/{cid}?reason=cleanup", headers=headers("operator")).status_code == 404
    assert client.put("/platform/alert-channels/0000000000000000", headers=headers("operator"), json={"reason": "nope"}).status_code == 404

    actions = [(a, r) for a, r, _ in admin_events(app) if a.startswith("platform.alert_channel")]
    assert actions == [("platform.alert_channel_created", "route alerts"), ("platform.alert_channel_updated", "quieter"),
                       ("platform.alert_channel_deleted", "cleanup")]
    assert SLACK_URL not in json.dumps(admin_events(app))


def test_secrets_are_encrypted_at_rest_and_never_returned(api):
    client, app = api
    slack = make_channel(client)
    pd = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY)
    listing = client.get("/platform/alert-channels", headers=headers("auditor"))
    assert listing.status_code == 200 and listing.headers["cache-control"] == "no-store"
    text = listing.text
    assert SLACK_URL not in text and PD_KEY not in text and "secretvalue" not in text
    hints = {c["name"]: c for c in listing.json()["items"]}
    assert hints["On-call Slack"]["target_hint"] == "https://hooks.slack.test/…1234" and hints["On-call Slack"]["target_encrypted"]
    assert hints["PD"]["target_hint"] == "routing key …2345"

    from db_feature_store import feature_conn
    with feature_conn() as conn:
        stored = {r[0]: r[1] for r in conn.execute("SELECT id, target_sealed FROM platform_alert_channels").fetchall()}
    assert stored[slack["id"]].startswith("fernet:") and SLACK_URL not in stored[slack["id"]]
    assert PD_KEY not in stored[pd["id"]]
    assert ar.unseal(stored[slack["id"]]) == SLACK_URL

    # Editing without a target keeps the stored secret.
    res = client.put(f"/platform/alert-channels/{slack['id']}", headers=headers("operator"), json={"name": "Renamed", "reason": "rename"})
    assert res.status_code == 200 and SLACK_URL not in res.text
    with feature_conn() as conn:
        again = conn.execute("SELECT target_sealed FROM platform_alert_channels WHERE id = ?", (slack["id"],)).fetchone()[0]
    assert ar.unseal(again) == SLACK_URL


def test_secret_channels_need_the_vault_key(api, monkeypatch):
    client, _ = api
    monkeypatch.delenv("PQC_VAULT_MASTER_KEY", raising=False)
    res = client.post("/platform/alert-channels", headers=headers("operator"),
                      json={"kind": "slack_webhook", "name": "S", "target": SLACK_URL, "reason": "route"})
    assert res.status_code == 503 and "PQC_VAULT_MASTER_KEY" in res.json()["detail"]
    email = client.post("/platform/alert-channels", headers=headers("operator"),
                        json={"kind": "email", "name": "Mail", "target": ["oncall@example.com"], "reason": "route"})
    assert email.status_code == 200, email.text


@pytest.mark.parametrize("url", [
    "http://hooks.slack.test/services/x",          # not https
    "https://10.0.0.5/hook",                       # private literal
    "https://127.0.0.1/hook",                      # loopback
    "https://169.254.169.254/latest/meta-data",    # link-local metadata service
    "https://[::1]/hook",                          # IPv6 loopback
    "https://[::ffff:10.0.0.1]/hook",              # IPv4-mapped private
    "https://100.64.0.1/hook",                     # carrier-grade NAT
    "https://internal.corp.test/hook",             # resolves to a private address
    "https://rebind.test/hook",                    # one public, one private answer
    "https://user:pass@hooks.slack.test/x",        # credentials in the URL
    "ftp://hooks.slack.test/x",
    "not a url",
])
def test_webhook_urls_must_be_https_and_public(api, net, url):
    client, _ = api
    net.dns["internal.corp.test"] = ["10.1.2.3"]
    net.dns["rebind.test"] = [PUBLIC_IP, "192.168.1.10"]
    for kind in ("slack_webhook", "generic_webhook"):
        res = client.post("/platform/alert-channels", headers=headers("operator"),
                          json={"kind": kind, "name": "Hook", "target": url, "reason": "route"})
        assert res.status_code == 400, (kind, url, res.text)
    assert net.webhooks == []


def test_send_time_resolution_refuses_a_host_that_now_points_inward(api, net):
    client, _ = api
    channel = make_channel(client)
    net.dns["hooks.slack.test"] = ["127.0.0.1"]   # DNS changed after the channel was saved
    res = client.post(f"/platform/alert-channels/{channel['id']}/test", headers=headers("operator"), json={})
    assert res.status_code == 200 and res.json()["ok"] is False
    assert "public address" in res.json()["error"]
    assert net.connections == []


def test_invalid_channel_fields_are_rejected(api):
    client, _ = api
    bad = [
        {"kind": "pagerduty", "name": "PD", "target": "short"},
        {"kind": "email", "name": "Mail", "target": ["not-an-email"]},
        {"kind": "email", "name": "Mail", "target": [f"u{i}@example.com" for i in range(21)]},
        {"kind": "slack_webhook", "name": "S", "target": SLACK_URL, "kinds": ["made_up_kind"]},
        {"kind": "slack_webhook", "name": "S", "target": SLACK_URL, "quiet_hours": {"start": "25:00", "end": "07:00"}},
        {"kind": "slack_webhook", "name": "S", "target": SLACK_URL, "quiet_hours": {"start": "22:00", "end": "07:00", "timezone": "Mars/Base"}},
        {"kind": "sms", "name": "S", "target": "x"},
    ]
    for body in bad:
        res = client.post("/platform/alert-channels", headers=headers("operator"), json={**body, "reason": "route"})
        assert res.status_code in (400, 422), (body, res.text)


# ── Dispatcher ───────────────────────────────────────────────────────────────


def test_dispatcher_dedupes_and_renotifies_after_the_window(api, net):
    client, _ = api
    make_channel(client)
    items = [item("sla_breach:1"), item("feedback:9", severity="info", kind="feedback")]
    first = ar.run_once(snapshot(items), "https://portal.example", now=NOW)
    assert first["status"] == "ok" and first["sent"] == 1          # info is below the channel's warn threshold
    assert len(net.webhooks) == 1
    message = net.webhooks[0]["json"]
    assert "Alert sla_breach:1" in message["text"] and net.webhooks[0]["address"] == PUBLIC_IP
    assert "https://portal.example/vendor-admin/#/notifications" in json.dumps(message)

    ar.run_once(snapshot(items), now=NOW + timedelta(minutes=1))
    ar.run_once(snapshot(items), now=NOW + timedelta(hours=23))
    assert len(net.webhooks) == 1, "an open item is not re-sent inside the renotify window"

    later = ar.run_once(snapshot(items), now=NOW + timedelta(hours=24, minutes=1))
    assert later["sent"] == 1 and len(net.webhooks) == 2
    assert net.webhooks[1]["json"]["text"].startswith("Still open: ")
    events = [d["event"] for d in ar.list_deliveries()]
    assert sorted(events) == ["renotify", "trigger"]


def test_renotify_window_is_configurable(api, net, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_ALERT_RENOTIFY_HOURS", "2")
    make_channel(client)
    items = [item("sla_breach:1")]
    ar.run_once(snapshot(items), now=NOW)
    ar.run_once(snapshot(items), now=NOW + timedelta(hours=1))
    assert len(net.webhooks) == 1
    ar.run_once(snapshot(items), now=NOW + timedelta(hours=2, minutes=1))
    assert len(net.webhooks) == 2


def test_a_resolved_item_that_returns_is_sent_again(api, net):
    client, _ = api
    make_channel(client)
    ar.run_once(snapshot([item("x:1")]), now=NOW)
    ar.run_once(snapshot([]), now=NOW + timedelta(minutes=1))
    ar.run_once(snapshot([item("x:1")]), now=NOW + timedelta(minutes=2))
    assert len(net.webhooks) == 2


def test_pagerduty_triggers_with_the_notification_id_and_resolves_when_it_clears(api, net):
    client, _ = api
    make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="critical")
    items = [item("sla_breach:7"), item("maintenance:2026", severity="warn", kind="maintenance")]
    ar.run_once(snapshot(items), now=NOW)
    assert len(net.pagerduty) == 1
    trigger = net.pagerduty[0]
    assert trigger["event_action"] == "trigger" and trigger["dedup_key"] == "sla_breach:7"
    assert trigger["routing_key"] == PD_KEY and trigger["payload"]["severity"] == "critical"

    # A source that failed to load is not "cleared": nothing resolves.
    ar.run_once(snapshot([], unavailable=[{"metric": "sla_breach", "reason": "Query failed"}]), now=NOW + timedelta(minutes=1))
    # A truncated list is not "cleared" either.
    ar.run_once(snapshot([], total=80), now=NOW + timedelta(minutes=2))
    assert len(net.pagerduty) == 1

    ar.run_once(snapshot([]), now=NOW + timedelta(minutes=3))
    assert len(net.pagerduty) == 2
    resolve = net.pagerduty[1]
    assert resolve == {"routing_key": PD_KEY, "dedup_key": "sla_breach:7", "event_action": "resolve"}
    ar.run_once(snapshot([]), now=NOW + timedelta(minutes=4))
    assert len(net.pagerduty) == 2, "a resolve is sent once"
    log = ar.list_deliveries()
    assert [d["event"] for d in log] == ["resolve", "trigger"] and all(d["status"] == "sent" for d in log)
    assert log[1]["http_status"] == 202 and log[1]["latency_ms"] is not None and log[1]["notification_id"] == "sla_breach:7"


def pd_resolves(net):
    return [p for p in net.pagerduty if p.get("event_action") == "resolve"]


def fail_resolves(net, monkeypatch, failing=True):
    """Make PagerDuty reject resolve events (trigger events still succeed)."""
    real = net.urlopen

    def urlopen(req, timeout=10):
        if failing and json.loads(req.data.decode()).get("event_action") == "resolve":
            raise OSError("pagerduty is down")
        return real(req, timeout)
    from services import alerting
    monkeypatch.setattr(alerting.urllib.request, "urlopen", urlopen)


def test_deleting_a_pagerduty_channel_resolves_its_open_incidents(api, net):
    client, app = api
    channel = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn")
    items = [item("sla_breach:7"), item("incident:api_error:3", kind="incident", severity="warn")]
    ar.run_once(snapshot(items), now=NOW)
    assert len(net.pagerduty) == 2 and not pd_resolves(net)

    res = client.delete(f"/platform/alert-channels/{channel['id']}?reason=decommission", headers=headers("operator"))
    assert res.status_code == 200, res.text
    body = res.json()
    assert {(p["dedup_key"], p["routing_key"]) for p in pd_resolves(net)} == {("sla_breach:7", PD_KEY), ("incident:api_error:3", PD_KEY)}
    assert body["incidents"]["open"] == 2 and body["incidents"]["resolved"] == 2 and body["incidents"]["failed"] == 0
    assert {i["notification_id"]: i["resolved"] for i in body["incidents"]["items"]} == {"sla_breach:7": True, "incident:api_error:3": True}
    assert body["note"].startswith("Resolved 2 open PagerDuty incident")
    resolves = ar.list_deliveries(event="resolve")
    assert len(resolves) == 2 and all(d["status"] == "sent" and d["channel_kind"] == "pagerduty" for d in resolves)
    assert ar.pending_resolves() == []
    assert client.get("/platform/alert-channels", headers=headers("auditor")).json()["items"] == []
    deleted = [d for a, _, d in admin_events(app) if a == "platform.alert_channel_deleted"][0]
    assert (deleted["incidents_open"], deleted["incidents_resolved"], deleted["incidents_failed"]) == (2, 2, 0)
    assert PD_KEY not in json.dumps(admin_events(app)) and PD_KEY not in res.text


def test_a_resolve_that_fails_on_delete_is_retried_by_the_dispatcher(api, net, monkeypatch):
    client, app = api
    channel = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn")
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW)
    fail_resolves(net, monkeypatch)
    body = client.delete(f"/platform/alert-channels/{channel['id']}?reason=decommission", headers=headers("operator")).json()
    assert body["incidents"]["resolved"] == 0 and body["incidents"]["retrying"] == 1
    assert "retried by the dispatcher" in body["note"]
    assert [d["status"] for d in ar.list_deliveries(event="resolve")] == ["failed"]
    waiting = ar.pending_resolves()
    assert len(waiting) == 1 and waiting[0]["notification_id"] == "sla_breach:7" and waiting[0]["attempts"] == 1
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        sealed = conn.execute("SELECT target_sealed FROM platform_alert_pending_resolves").fetchone()[0]
    assert sealed.startswith("fernet:") and PD_KEY not in sealed and ar.unseal(sealed) == PD_KEY
    assert json.dumps(ar.pending_resolves()) .count(PD_KEY) == 0

    # The channel is gone, so the dispatcher has nothing else to do and still retries the resolve.
    fail_resolves(net, monkeypatch, failing=False)
    later = ar.now_utc() + timedelta(minutes=5)  # the delete ran on the real clock, so the retry does too
    result = ar.run_once(snapshot([]), now=later)
    assert result["resolved"] == 1
    assert [(p["dedup_key"], p["event_action"]) for p in pd_resolves(net)] == [("sla_breach:7", "resolve")]
    assert ar.pending_resolves() == []
    assert [d["status"] for d in ar.list_deliveries(event="resolve")] == ["sent", "failed"]
    assert ar.job_state(now=later)["pending_resolves"] == 0


def test_a_resolve_is_given_up_on_after_the_attempt_limit(api, net, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_ALERT_RESOLVE_MAX_ATTEMPTS", "2")
    channel = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn")
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW)
    fail_resolves(net, monkeypatch)
    client.delete(f"/platform/alert-channels/{channel['id']}?reason=decommission", headers=headers("operator"))
    assert len(ar.pending_resolves()) == 1
    assert ar.job_state(now=NOW)["pending_resolves"] == 1 and "waiting to be retried" in ar.job_state(now=NOW)["detail"]
    ar.run_once(snapshot([]), now=ar.now_utc() + timedelta(hours=2))
    assert ar.pending_resolves() == []  # attempt 2 of 2 failed: the operator is told to close it in PagerDuty
    last = ar.list_deliveries(event="resolve")[0]
    assert last["status"] == "failed" and "Gave up after 2 attempt" in last["error"]


def test_disabling_a_pagerduty_channel_resolves_and_re_enabling_triggers_again(api, net):
    client, app = api
    channel = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn")
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW)
    res = client.put(f"/platform/alert-channels/{channel['id']}", headers=headers("operator"),
                     json={"enabled": False, "reason": "muting on-call"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["incidents"]["resolved"] == 1 and body["note"].startswith("Resolved 1 open PagerDuty incident")
    assert [p["dedup_key"] for p in pd_resolves(net)] == ["sla_breach:7"]
    updated = [d for a, _, d in admin_events(app) if a == "platform.alert_channel_updated"][0]
    assert updated["incidents_resolved"] == 1 and updated["enabled"] is False
    # Disabled: the dispatcher sends nothing more for it.
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW + timedelta(minutes=1))
    assert len(net.pagerduty) == 2
    client.put(f"/platform/alert-channels/{channel['id']}", headers=headers("operator"), json={"enabled": True, "reason": "back on"})
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW + timedelta(minutes=2))
    assert [(p["event_action"], p["dedup_key"]) for p in net.pagerduty][-1] == ("trigger", "sla_breach:7")


def test_a_queued_resolve_never_closes_an_incident_that_was_raised_again(api, net, monkeypatch):
    client, _ = api
    channel = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn")
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW)
    fail_resolves(net, monkeypatch)
    client.put(f"/platform/alert-channels/{channel['id']}", headers=headers("operator"),
               json={"enabled": False, "reason": "muting on-call"})
    assert len(ar.pending_resolves()) == 1
    client.put(f"/platform/alert-channels/{channel['id']}", headers=headers("operator"), json={"enabled": True, "reason": "back on"})
    fail_resolves(net, monkeypatch, failing=False)
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW + timedelta(minutes=2))
    assert ar.pending_resolves() == [], "the retrigger dropped the queued resolve"
    assert not pd_resolves(net) and [p["event_action"] for p in net.pagerduty] == ["trigger", "trigger"]


@pytest.mark.parametrize("kind,target", [("slack_webhook", SLACK_URL), ("generic_webhook", SLACK_URL)])
def test_deleting_a_non_pagerduty_channel_resolves_nothing(api, net, kind, target):
    client, _ = api
    channel = make_channel(client, kind=kind, name=kind, target=target, min_severity="warn")
    ar.run_once(snapshot([item("sla_breach:7")]), now=NOW)
    body = client.delete(f"/platform/alert-channels/{channel['id']}?reason=cleanup", headers=headers("operator")).json()
    assert body["note"] == "" and body["incidents"]["resolved"] == 0 and body["incidents"]["items"] == []
    assert net.pagerduty == [] and ar.pending_resolves() == []
    assert ar.list_deliveries(event="resolve") == []


def test_rate_cap_sends_one_digest_for_the_overflow(api, net, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_ALERT_RATE_CAP", "5")
    make_channel(client)
    items = [item(f"security_finding:{i}", severity="critical" if i < 3 else "warn", kind="security_finding",
                  created_at=f"2026-09-16T10:{i:02d}:00Z") for i in range(12)]
    result = ar.run_once(snapshot(items), now=NOW)
    assert result["sent"] == 5 and result["digested"] == 8
    assert len(net.webhooks) == 5
    individual = [w["json"]["text"] for w in net.webhooks[:4]]
    assert all("[CRITICAL]" in t for t in individual[:3]), "the most severe items get their own messages"
    digest = net.webhooks[4]["json"]
    assert "8 more alerts" in digest["text"]
    ar.run_once(snapshot(items), now=NOW + timedelta(minutes=1))
    assert len(net.webhooks) == 5, "digested items are in the ledger and not re-sent"

    more = items + [item(f"security_finding:new{i}") for i in range(3)]
    held = ar.run_once(snapshot(more), now=NOW + timedelta(minutes=2))
    assert held["rate_limited"] == 3 and len(net.webhooks) == 5
    ar.run_once(snapshot(more), now=NOW + timedelta(minutes=3))
    suppressed = ar.list_deliveries(event="rate_limited")
    assert len(suppressed) == 1 and suppressed[0]["status"] == "suppressed"
    ar.run_once(snapshot(more), now=NOW + timedelta(minutes=11))
    assert len(net.webhooks) == 8, "held items go out once the window frees"


def test_failures_are_logged_retried_and_never_raise(api, net, monkeypatch):
    client, _ = api
    make_channel(client)
    net.webhook_status = 500
    first = ar.run_once(snapshot([item("incident:api_error:3", kind="incident")]), now=NOW)
    assert first["status"] == "error" and first["failed"] == 1
    failed = ar.list_deliveries(status="failed")
    assert len(failed) == 1 and failed[0]["http_status"] == 500 and failed[0]["error"] == "HTTP 500"

    net.webhook_status = 200
    retry = ar.run_once(snapshot([item("incident:api_error:3", kind="incident")]), now=NOW + timedelta(minutes=1))
    assert retry["sent"] == 1, "a failed send is retried on the next run"

    net.raise_on_send = ConnectionResetError("boom")
    crashed = ar.run_once(snapshot([item("incident:api_error:4", kind="incident")]), now=NOW + timedelta(minutes=2))
    assert crashed["failed"] == 1 and "ConnectionResetError" in ar.list_deliveries(status="failed")[0]["error"]

    def broken_snapshot():
        raise RuntimeError("notifications exploded")
    assert ar.run_once(broken_snapshot, now=NOW + timedelta(minutes=3))["status"] == "error"

    def exploding_send(*args, **kwargs):
        raise ValueError("sender bug")
    monkeypatch.setattr(ar, "_dispatch_channel", exploding_send)
    assert ar.run_once(snapshot([item("x:9")]), now=NOW + timedelta(minutes=4))["status"] == "error"
    state = ar.job_state(now=NOW + timedelta(minutes=4))
    assert state["status"] == "error" and "ValueError" in state["last_error"]


def test_error_text_never_carries_the_webhook_url(api, net, monkeypatch):
    client, _ = api
    make_channel(client)

    def leaky(url, payload, timeout=10.0):
        return {"ok": False, "http_status": None, "error": f"failed posting to {url}", "body": ""}
    monkeypatch.setattr(ar, "post_json", leaky)
    ar.run_once(snapshot([item("x:1")]), now=NOW)
    assert SLACK_URL not in json.dumps(ar.list_deliveries())


def test_quiet_hours_hold_non_critical_items(api, net):
    client, _ = api
    make_channel(client, quiet_hours={"start": "11:00", "end": "13:00", "timezone": "UTC", "allow_critical": True})
    items = [item("warn:1", severity="warn", kind="abuse"), item("crit:1")]
    result = ar.run_once(snapshot(items), now=NOW)
    assert result["sent"] == 1 and result["quiet"] == 1
    ar.run_once(snapshot(items), now=NOW + timedelta(hours=2))
    assert len(net.webhooks) == 2


def test_kinds_filter_and_disabled_channels(api, net):
    client, _ = api
    make_channel(client, kinds=["failed_login_spike"])
    make_channel(client, name="Off", enabled=False)
    ar.run_once(snapshot([item("sla_breach:1"), item("failed_login_spike:2026-09-16T11", kind="failed_login_spike")]), now=NOW)
    assert len(net.webhooks) == 1 and "failed_login_spike" in json.dumps(ar.list_deliveries())


def test_email_channel_sends_a_plain_message(api, net, monkeypatch):
    client, _ = api
    monkeypatch.setenv("PQC_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("PQC_SMTP_FROM", "alerts@example.test")
    make_channel(client, kind="email", name="Mail", target=["oncall@example.com", "sec@example.com"])
    ar.run_once(snapshot([item("sla_breach:1")]), now=NOW)
    assert len(net.emails) == 1
    assert net.emails[0]["to"] == ["oncall@example.com", "sec@example.com"]
    assert net.emails[0]["subject"].startswith("[PQC Scanner] [CRITICAL]")


def test_no_channels_means_no_snapshot_work(api, net):
    calls = []

    def counting():
        calls.append(1)
        return {"items": []}
    assert ar.run_once(counting, now=NOW)["status"] == "idle"
    assert calls == []


# ── Test send and jobs ───────────────────────────────────────────────────────


def test_test_send_endpoint_labels_the_message_and_logs_it(api, net):
    client, app = api
    slack = make_channel(client)
    assert client.post(f"/platform/alert-channels/{slack['id']}/test", headers=headers("auditor"), json={}).status_code == 403
    res = client.post(f"/platform/alert-channels/{slack['id']}/test", headers=headers("operator"), json={"reason": "check"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True and body["http_status"] == 200 and body["latency_ms"] is not None
    assert SLACK_URL not in res.text
    assert "[TEST]" in net.webhooks[0]["json"]["text"]
    net.webhook_status = 404
    failed = client.post(f"/platform/alert-channels/{slack['id']}/test", headers=headers("operator"), json={}).json()
    assert failed["ok"] is False and failed["http_status"] == 404

    log = client.get(f"/platform/alert-deliveries?channel_id={slack['id']}&limit=10", headers=headers("auditor"))
    assert log.status_code == 200
    assert [(d["event"], d["status"]) for d in log.json()["items"]] == [("test", "failed"), ("test", "sent")]
    assert client.get("/platform/alert-deliveries?status=bogus", headers=headers("auditor")).status_code == 422
    assert "platform.alert_channel_tested" in [a for a, _, _ in admin_events(app)]

    pd = make_channel(client, kind="pagerduty", name="PD", target=PD_KEY)
    assert client.post(f"/platform/alert-channels/{pd['id']}/test", headers=headers("operator"), json={}).json()["ok"] is True
    assert [p["event_action"] for p in net.pagerduty] == ["trigger", "resolve"]
    assert net.pagerduty[0]["payload"]["summary"].startswith("[TEST]")

    for _ in range(3):
        client.post(f"/platform/alert-channels/{slack['id']}/test", headers=headers("operator"), json={})
    assert client.post(f"/platform/alert-channels/{slack['id']}/test", headers=headers("operator"), json={}).status_code == 429
    assert client.post("/platform/alert-channels/ffffffffffffffff/test", headers=headers("operator"), json={}).status_code == 404


def test_jobs_endpoint_lists_the_dispatcher(api, net):
    client, _ = api
    make_channel(client)
    net.webhook_status = 500
    ar.run_once(snapshot([item("x:1")]))
    from services import platform_analytics
    platform_analytics.clear_cache()
    jobs = client.get("/platform/jobs", headers=headers("auditor")).json()["jobs"]
    dispatcher = next(j for j in jobs if j["key"] == "alert_dispatcher")
    assert dispatcher["status"] == "error" and dispatcher["last_run_at"] and "failed" in dispatcher["last_error"]


def test_dispatcher_snapshot_reads_real_notifications(api):
    _, app = api
    data = app._alert_notifications_snapshot()
    assert "items" in data and "unavailable" in data and data["counts"]["total"] == len(data["items"])


# ── Kind catalogue: one source of truth ──────────────────────────────────────


def _emitted_kinds_and_metrics():
    """Parse services/platform_analytics.notifications(): every kind passed to item(...) and every c.run metric."""
    import ast
    import inspect
    import textwrap

    from services import platform_analytics

    tree = ast.parse(textwrap.dedent(inspect.getsource(platform_analytics.notifications)))
    kinds, metrics, dynamic = set(), set(), []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, (ast.Name, ast.Attribute)):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "item":
            arg = node.args[2]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                kinds.add(arg.value)
            else:
                dynamic.append(ast.dump(arg))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run" and node.args and isinstance(node.args[0], ast.Constant):
            metrics.add(node.args[0].value)
    return kinds, metrics, dynamic


def test_every_emitted_notification_kind_is_a_selectable_channel_kind(api):
    client, _ = api
    kinds, metrics, dynamic = _emitted_kinds_and_metrics()
    assert not dynamic, "notification kinds must be string literals so this test can enumerate them"
    assert {"break_glass", "support_session"} <= kinds
    assert kinds == set(ar.NOTIFICATION_KINDS), "platform_analytics.NOTIFICATION_KIND_CATALOG is out of date"
    # Every kind maps to the collector metric that produces it, so a failed source never resolves its items.
    assert set(ar.NOTIFICATION_KINDS.values()) <= metrics
    body = client.get("/platform/alert-channels", headers=headers("auditor")).json()
    assert set(body["notification_kinds"]) == kinds
    assert set(body["notification_kind_labels"]) == kinds and all(body["notification_kind_labels"].values())
    channel = make_channel(client, kinds=sorted(kinds))
    assert set(channel["kinds"]) == kinds


def test_admin_portal_reads_the_kind_list_from_the_server():
    import pathlib

    js = (pathlib.Path(__file__).resolve().parent / "static_admin" / "admin-alerts.js").read_text(encoding="utf-8")
    assert "notification_kinds" in js and "notification_kind_labels" in js
    for kind in ar.NOTIFICATION_KINDS:
        assert f'"{kind}"' not in js and f"'{kind}'" not in js, f"admin-alerts.js hardcodes the kind {kind}"


@pytest.mark.parametrize("kind,severity", [("break_glass", "critical"), ("support_session", "warn")])
def test_pagerduty_filters_triggers_and_resolves_break_glass_and_support_items(api, net, kind, severity):
    client, _ = api
    make_channel(client, kind="pagerduty", name="PD", target=PD_KEY, min_severity="warn", kinds=[kind])
    ar.run_once(snapshot([item(f"{kind}:1", severity=severity, kind=kind), item("sla_breach:9")]), now=NOW)
    assert [(p["event_action"], p["dedup_key"]) for p in net.pagerduty] == [("trigger", f"{kind}:1")]
    # The producing source failed: not cleared.
    ar.run_once(snapshot([], unavailable=[{"metric": kind, "reason": "Query failed"}]), now=NOW + timedelta(minutes=1))
    assert len(net.pagerduty) == 1
    ar.run_once(snapshot([]), now=NOW + timedelta(minutes=2))
    assert net.pagerduty[1] == {"routing_key": PD_KEY, "dedup_key": f"{kind}:1", "event_action": "resolve"}
