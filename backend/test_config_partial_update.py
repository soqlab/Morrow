"""Saving part of a configuration must not reset the rest.

The console posts partial bodies -- its Slack Save sends only webhook_url and
channel (static/index.html) -- while these endpoints wrote every field of the
request model. Anything the client omitted arrived as the model's default and
was written over the stored value.

The user-visible result: an operator narrows Slack alerting to critical only,
later edits the webhook URL, and min_severity silently returns to "high". They
start receiving alerts they deliberately turned off, and the response said
"saved". The same shape reset a configured SMTP host and port.

These tests set a full configuration, save a realistic partial update, and
assert the untouched fields survive.
"""

import os
import tempfile

import pytest

ORG = "00000000-0000-0000-0000-000000000001"


@pytest.fixture()
def client():
    os.environ["MORROW_SCANNER_DB"] = os.path.join(tempfile.mkdtemp(), "cfg.db")
    os.environ.setdefault("MORROW_AUTH_MODE", "header")
    os.environ.setdefault("MORROW_DEFAULT_ROLE", "admin")
    import importlib
    import db
    importlib.reload(db)
    import app as application
    from fastapi.testclient import TestClient

    was_enabled = getattr(application.limiter, "enabled", True)
    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as c:
        c.headers.update({"x-org-id": ORG, "x-actor-role": "admin", "x-user-id": "cfg@test"})
        yield c
    application.limiter.enabled = was_enabled


def test_slack_partial_save_keeps_the_severity_threshold(client):
    client.post("/integrations/slack/settings", json={
        "webhook_url": "https://hooks.slack.test/original",
        "min_severity": "critical",
        "enabled": True,
    })
    # Exactly what the console's Save button sends.
    client.post("/integrations/slack/settings", json={
        "webhook_url": "https://hooks.slack.test/updated",
        "channel": "#alerts",
    })

    after = client.get("/integrations/slack/settings").json()
    assert after["webhook_url"] == "https://hooks.slack.test/updated", "the edit should apply"
    assert after["min_severity"] == "critical", "an omitted threshold must not reset"
    assert after["enabled"] is True


def test_slack_empty_body_does_not_wipe_the_webhook(client):
    client.post("/integrations/slack/settings", json={
        "webhook_url": "https://hooks.slack.test/keepme", "min_severity": "high", "enabled": True,
    })
    client.post("/integrations/slack/settings", json={})

    after = client.get("/integrations/slack/settings").json()
    assert after["webhook_url"] == "https://hooks.slack.test/keepme", (
        "an empty save erased a working integration and reported success"
    )


def test_notification_partial_save_keeps_host_and_port(client):
    client.post("/notifications/config", json={
        "smtp_host": "smtp.example.com", "smtp_port": 2525,
        "smtp_from": "alerts@example.com", "smtp_enabled": True,
    })
    # Change one unrelated field.
    client.post("/notifications/config", json={"smtp_from": "noc@example.com"})

    cfg = client.get("/notifications/config").json()["config"]
    assert cfg["smtp_from"] == "noc@example.com", "the edit should apply"
    assert cfg["smtp_host"] == "smtp.example.com", "an omitted host must not reset"
    assert int(cfg["smtp_port"]) == 2525, "an omitted port must not fall back to 587"


def test_notification_empty_body_changes_nothing_but_the_timestamp(client):
    client.post("/notifications/config", json={
        "smtp_host": "smtp.example.com", "smtp_port": 2525, "smtp_enabled": True,
    })
    before = client.get("/notifications/config").json()["config"]
    client.post("/notifications/config", json={})
    after = client.get("/notifications/config").json()["config"]

    changed = {k for k in before if before[k] != after.get(k)} - {"updated_at"}
    assert not changed, f"an empty save altered {sorted(changed)}"
