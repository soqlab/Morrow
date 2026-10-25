"""Tests for Wave 15: Ticketing, SLA, Webhooks, KMS, Policy Engine."""


# ── Ticketing ──────────────────────────────────────────────────────────────────

class TestTicketing:
    def test_get_config_empty(self, client, auth):
        r = client.get("/v1/tickets/config", headers=auth)
        assert r.status_code == 200
        assert "configs" in r.json()

    def test_save_jira_config(self, client, auth):
        r = client.post("/v1/tickets/config", json={
            "provider": "jira",
            "config": {
                "base_url": "https://test.atlassian.net",
                "email": "test@example.com",
                "api_token": "fake-token",
                "project_key": "post-quantum",
                "issue_type": "Bug",
            }
        }, headers=auth)
        assert r.status_code == 200
        assert r.json().get("status") == "saved"

    def test_get_config_after_save(self, client, auth):
        r = client.get("/v1/tickets/config", headers=auth)
        assert r.status_code == 200
        configs = r.json().get("configs", [])
        providers = [c["provider"] for c in configs]
        assert "jira" in providers

    def test_list_tickets_empty(self, client, auth):
        r = client.get("/v1/tickets", headers=auth)
        assert r.status_code == 200
        assert "tickets" in r.json()

    def test_create_ticket_no_config_fails(self, client, auth):
        r = client.post("/v1/tickets/create", json={
            "provider": "github",
            "finding_ref": "rem-001",
            "finding_type": "remediation",
            "title": "Test finding",
            "body": "Description",
            "severity": "high",
        }, headers=auth)
        # Should fail (no github config) OR return error field — both acceptable
        data = r.json() if r.status_code == 200 else {}
        assert r.status_code in (400, 422, 500) or "error" in data or "detail" in data


# ── SLA Engine ─────────────────────────────────────────────────────────────────

class TestSLA:
    def test_get_default_config(self, client, auth):
        r = client.get("/v1/sla/config", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert "config" in data
        cfg = data["config"]
        assert "critical" in cfg

    def test_save_sla_config(self, client, auth):
        r = client.post("/v1/sla/config", json={
            "critical": 3,
            "high": 14,
            "medium": 60,
            "low": 120,
            "info": 365,
        }, headers=auth)
        assert r.status_code == 200
        assert r.json().get("status") == "saved"

    def test_config_persists(self, client, auth):
        r = client.get("/v1/sla/config", headers=auth)
        assert r.status_code == 200
        cfg = r.json()["config"]
        assert cfg.get("critical") == 3

    def test_sla_status(self, client, auth):
        r = client.get("/v1/sla/status", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert "summary" in data
        assert "breached" in data
        assert "at_risk" in data

    def test_sla_breaches(self, client, auth):
        r = client.get("/v1/sla/breaches", headers=auth)
        assert r.status_code == 200
        assert "breaches" in r.json()


# ── Webhooks ───────────────────────────────────────────────────────────────────

class TestWebhooks:
    def test_get_events_list(self, client, auth):
        r = client.get("/v1/webhooks/events", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert len(data["events"]) > 0
        assert "scan.completed" in data["events"]

    def test_list_webhooks_empty(self, client, auth):
        r = client.get("/v1/webhooks", headers=auth)
        assert r.status_code == 200
        assert "webhooks" in r.json()

    def test_create_webhook(self, client, auth):
        r = client.post("/v1/webhooks", json={
            "name": "Test Webhook",
            "url": "https://example.com/hook",
            "events": ["scan.completed", "finding.critical"],
            "secret": "my-secret",
        }, headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data.get("name") == "Test Webhook"
        assert "id" in data
        return data["id"]

    def test_list_webhooks_after_create(self, client, auth):
        r = client.get("/v1/webhooks", headers=auth)
        assert r.status_code == 200
        webhooks = r.json()["webhooks"]
        names = [w["name"] for w in webhooks]
        assert "Test Webhook" in names

    def test_update_webhook(self, client, auth):
        # Get webhook id first
        whs = client.get("/v1/webhooks", headers=auth).json()["webhooks"]
        wh = next((w for w in whs if w["name"] == "Test Webhook"), None)
        if wh:
            r = client.put(f"/v1/webhooks/{wh['id']}", json={"enabled": False}, headers=auth)
            assert r.status_code == 200
            assert r.json().get("enabled") is False

    def test_delete_webhook(self, client, auth):
        whs = client.get("/v1/webhooks", headers=auth).json()["webhooks"]
        wh = next((w for w in whs if w["name"] == "Test Webhook"), None)
        if wh:
            r = client.delete(f"/v1/webhooks/{wh['id']}", headers=auth)
            assert r.status_code == 200
            # Verify gone
            whs2 = client.get("/v1/webhooks", headers=auth).json()["webhooks"]
            assert all(w["name"] != "Test Webhook" for w in whs2)


# ── KMS Health ─────────────────────────────────────────────────────────────────

class TestKMS:
    def test_kms_history_empty(self, client, auth):
        r = client.get("/v1/kms/history", headers=auth)
        assert r.status_code == 200
        assert "results" in r.json()

    def test_kms_check_bad_credentials(self, client, auth):
        r = client.post("/v1/kms/check", json={
            "provider": "aws_kms",
            "aws_access_key": "AKIAFAKE",
            "aws_secret_key": "fakesecret",
            "aws_region": "us-east-1",
        }, headers=auth)
        # Should return 200 with error field (graceful failure), not 500
        assert r.status_code == 200
        data = r.json()
        assert "error" in data or "risk_level" in data


# ── Policy Engine ──────────────────────────────────────────────────────────────

class TestPolicyEngine:
    def test_get_templates(self, client, auth):
        r = client.get("/v1/policies/templates", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert "templates" in data
        assert len(data["templates"]) >= 5

    def test_list_policies_empty(self, client, auth):
        r = client.get("/v1/policies", headers=auth)
        assert r.status_code == 200
        assert "policies" in r.json()

    def test_create_policy(self, client, auth):
        r = client.post("/v1/policies", json={
            "name": "Test Policy",
            "description": "Unit test policy",
            "definition": {
                "rules": [{
                    "id": "test-rule",
                    "description": "Test rule",
                    "field": "tls_version",
                    "operator": "equals",
                    "value": "TLSv1.3",
                    "severity": "high",
                }]
            },
            "enabled": True,
        }, headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data.get("name") == "Test Policy"
        assert "id" in data

    def test_list_policies_after_create(self, client, auth):
        r = client.get("/v1/policies", headers=auth)
        assert r.status_code == 200
        policies = r.json()["policies"]
        names = [p["name"] for p in policies]
        assert "Test Policy" in names

    def test_evaluate_policy(self, client, auth):
        policies = client.get("/v1/policies", headers=auth).json()["policies"]
        pol = next((p for p in policies if p["name"] == "Test Policy"), None)
        if pol:
            r = client.post(f"/v1/policies/{pol['id']}/evaluate", headers=auth)
            assert r.status_code == 200
            data = r.json()
            assert "passed" in data
            assert "violation_count" in data
            assert "asset_count" in data

    def test_policy_results_history(self, client, auth):
        r = client.get("/v1/policies/results/history", headers=auth)
        assert r.status_code == 200
        assert "results" in r.json()

    def test_delete_policy(self, client, auth):
        policies = client.get("/v1/policies", headers=auth).json()["policies"]
        pol = next((p for p in policies if p["name"] == "Test Policy"), None)
        if pol:
            r = client.delete(f"/v1/policies/{pol['id']}", headers=auth)
            assert r.status_code == 200
