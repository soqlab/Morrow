from fastapi.testclient import TestClient
import pytest

import app as fastapi_app


def test_platform_readiness_requires_admin_key(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/readiness")
    assert res.status_code == 403


def test_platform_admin_key_query_string_disabled(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(fastapi_app, "_ALLOW_PLATFORM_KEY_QUERY", False)
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/readiness?platform_key=test-key")
    assert res.status_code == 403


def test_platform_admin_wrong_key_rejected(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/readiness", headers={"x-platform-key": "wrong-key"})
    assert res.status_code == 403
    assert "Invalid or missing" in res.json()["detail"]


def test_platform_readiness_reports_blockers(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(fastapi_app, "postgres_main_db_requested", lambda: False)
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/readiness", headers={"x-platform-key": "test-key"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "blocked"
    keys = {item["key"] for item in body["checks"]}
    assert {"auth_mode", "rls", "platform_admin_key", "postgres"}.issubset(keys)


def test_platform_go_live_gate_blocks_unsafe_config(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(fastapi_app, "postgres_main_db_requested", lambda: False)
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/go-live-gate", headers={"x-platform-key": "test-key"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "no_go"
    assert body["go_live_allowed"] is False
    failed_keys = {item["key"] for item in body["failed_required_checks"]}
    assert {"auth_mode", "postgres", "rls"}.issubset(failed_keys)
    assert body["manual_exit_criteria"]


def test_security_headers_present(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_CSP_ENABLED", True)
    with TestClient(fastapi_app.app) as client:
        res = client.get("/status")
    assert res.status_code == 200
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors" in res.headers["content-security-policy"]


def test_admin_and_platform_responses_are_not_cached(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        admin = client.get("/vendor-admin/")
        platform = client.get("/platform/readiness", headers={"x-platform-key": "test-key"})
    assert admin.status_code == 200
    assert platform.status_code == 200
    assert "no-store" in admin.headers["cache-control"]
    assert "no-store" in platform.headers["cache-control"]


def test_platform_admin_mode_and_retention_policy(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        mode = client.get("/platform/admin-mode", headers={"x-platform-key": "test-key"})
        policy = client.get("/platform/retention/policy", headers={"x-platform-key": "test-key"})
    assert mode.status_code == 200
    assert mode.json()["security"]["csp_enabled"] in {True, False}
    assert policy.status_code == 200
    assert policy.json()["defaults"]["dry_run"] is True


def test_retention_run_dry_run(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(
        fastapi_app,
        "_run_platform_retention",
        lambda req: {"api_version": "v1", "dry_run": req.dry_run, "items": [{"table": "scans", "matched": 0, "deleted": 0}]},
    )
    monkeypatch.setattr(fastapi_app, "_record_platform_admin_event", lambda *args, **kwargs: None)
    with TestClient(fastapi_app.app) as client:
        res = client.post("/platform/retention/run", headers={"x-platform-key": "test-key"}, json={"dry_run": True})
    assert res.status_code == 200
    assert res.json()["dry_run"] is True


def test_feature_flag_guard_strict(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_FEATURE_FLAGS_STRICT", True)
    monkeypatch.setattr(fastapi_app, "_platform_feature_flags", lambda organization_id="": [])
    with pytest.raises(fastapi_app.HTTPException) as exc:
        fastapi_app._require_org_feature("org-a", "write_path", "Write path")
    assert exc.value.status_code == 403


def test_feature_flag_guard_blocks_explicit_disabled_flag(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_FEATURE_FLAGS_STRICT", False)
    monkeypatch.setattr(
        fastapi_app,
        "_platform_feature_flags",
        lambda organization_id="": [{"organization_id": organization_id, "flag_key": "github_pr_creation", "enabled": False}],
    )
    with pytest.raises(fastapi_app.HTTPException) as exc:
        fastapi_app._require_org_feature("org-a", "github_pr_creation", "GitHub PR creation")
    assert exc.value.status_code == 403
    assert "github_pr_creation" in exc.value.detail


def test_viewer_blocked_from_remediation_candidates(monkeypatch):
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "headers")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", False)
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/v1/remediation-candidates",
            headers={"x-user-role": "viewer", "x-user-id": "viewer-1"},
            json={"asset_keys": [], "create_records": False, "limit": 1},
        )
    assert res.status_code == 403
    assert "viewer" in res.json()["detail"]


def test_remediation_candidates_feature_flag_blocks_operator(monkeypatch):
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "headers")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", False)
    monkeypatch.setattr(
        fastapi_app,
        "_platform_feature_flags",
        lambda organization_id="": [{"organization_id": organization_id, "flag_key": "remediation_candidates", "enabled": False}],
    )
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/v1/remediation-candidates",
            headers={"x-user-role": "operator", "x-user-id": "operator-1"},
            json={"asset_keys": [], "create_records": False, "limit": 1},
        )
    assert res.status_code == 403
    assert "remediation_candidates" in res.json()["detail"]


def test_production_startup_guard_blocks_unsafe_config(monkeypatch):
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "headers")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", False)
    monkeypatch.setattr(fastapi_app, "DEFAULT_USER_ROLE", "admin")
    monkeypatch.setattr(fastapi_app, "postgres_main_db_requested", lambda: False)
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "")
    monkeypatch.delenv("MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP", raising=False)
    with pytest.raises(RuntimeError) as exc:
        fastapi_app._assert_production_startup_safe()
    msg = str(exc.value)
    assert "MORROW_AUTH_MODE must be jwt" in msg
    assert "Managed Postgres is required" in msg


def test_production_startup_guard_allows_safe_config(monkeypatch):
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "jwt")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", True)
    monkeypatch.setattr(fastapi_app, "DEFAULT_USER_ROLE", "viewer")
    monkeypatch.setattr(fastapi_app, "AUTH_JWT_ISSUER", "https://issuer.example/")
    monkeypatch.setattr(fastapi_app, "AUTH_JWT_AUDIENCE", "pq-api")
    monkeypatch.setattr(fastapi_app, "AUTH_JWT_JWKS_URL", "https://issuer.example/.well-known/jwks.json")
    monkeypatch.setattr(fastapi_app, "AUTH_JWT_ALGORITHMS", ["RS256"])
    monkeypatch.setattr(fastapi_app, "CORS_ORIGINS", ["https://app.example.com"])
    monkeypatch.setattr(fastapi_app, "_ALLOWED_HOSTS", ["app.example.com", "api.example.com"])
    monkeypatch.setattr(fastapi_app, "postgres_main_db_requested", lambda: True)
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "x" * 40)
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_MIN_KEY_LENGTH", 32)
    monkeypatch.setattr(fastapi_app, "_ALLOW_PLATFORM_KEY_QUERY", False)
    monkeypatch.setattr(fastapi_app, "_ALLOW_DEMO_IN_PRODUCTION", False)
    monkeypatch.setattr(fastapi_app, "_TRAFFIC_PERSIST_TO_DB", True)
    monkeypatch.setattr(fastapi_app, "_CSP_ENABLED", True)
    monkeypatch.setattr(fastapi_app, "_CSP_VALUE", "default-src 'self'")
    monkeypatch.setenv("MORROW_PRODUCT_DATABASE_URL", "postgresql://user:pass@db/pq")
    monkeypatch.setenv("CELERY_BROKER_URL", "redis://:pass@redis:6379/0")
    monkeypatch.setenv("CELERY_RESULT_BACKEND", "redis://:pass@redis:6379/1")
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", "vault-master-key")
    monkeypatch.setenv("MORROW_AIRLOCK_SIGNING_KEY", "a" * 64)
    monkeypatch.setenv("MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    assert fastapi_app._assert_production_startup_safe() == []


def test_platform_metrics_accepts_admin_key(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(
        fastapi_app,
        "_platform_customer_stats",
        lambda: [
            {
                "organization_id": "org-a",
                "name": "Org A",
                "plan_type": "starter",
                "last_login_at": "",
                "scan_count": 0,
                "asset_count": 2,
                "remediation_count": 1,
                "active_users_7d": 0,
                "risk_score": 85,
            }
        ],
    )
    monkeypatch.setattr(fastapi_app, "_platform_login_events", lambda **kwargs: [])
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/metrics", headers={"x-platform-key": "test-key"})
    assert res.status_code == 200
    assert res.json()["customers_total"] == 1


def test_platform_enterprise_ops_endpoints_require_admin_key(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        for path in ["/platform/observability", "/platform/incidents", "/platform/abuse"]:
            res = client.get(path)
            assert res.status_code == 403


def test_platform_observability_and_incidents(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    fastapi_app._REQUEST_OBSERVATIONS.clear()
    fastapi_app._RATE_LIMIT_OBSERVATIONS.clear()
    fastapi_app._REQUEST_OBSERVATIONS.append(
        {
            "organization_id": "org-a",
            "method": "GET",
            "path": "/boom",
            "status_code": 500,
            "duration_ms": 2000,
            "created_at": "2026-01-01T00:00:00Z",
        }
    )
    fastapi_app._RATE_LIMIT_OBSERVATIONS.append(
        {"organization_id": "org-a", "path": "/scan", "source": "memory", "created_at": "2026-01-01T00:00:01Z"}
    )
    monkeypatch.setattr(fastapi_app, "_platform_login_events", lambda **kwargs: [])
    with TestClient(fastapi_app.app) as client:
        obs = client.get("/platform/observability", headers={"x-platform-key": "test-key"})
        inc = client.get("/platform/incidents", headers={"x-platform-key": "test-key"})
        abuse = client.get("/platform/abuse", headers={"x-platform-key": "test-key"})
    assert obs.status_code == 200
    assert obs.json()["recent_errors"]
    assert inc.status_code == 200
    assert inc.json()["incident_count"] >= 1
    assert abuse.status_code == 200
    assert abuse.json()["rate_limited_by_org"]["org-a"] == 1


def test_tenant_isolation_probe_endpoint(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(
        fastapi_app,
        "_run_tenant_isolation_probe",
        lambda: {"generated_at": "now", "status": "pass", "checks": [{"key": "org_a_cannot_see_org_b", "status": "pass"}]},
    )
    monkeypatch.setattr(fastapi_app, "_record_platform_admin_event", lambda *args, **kwargs: None)
    with TestClient(fastapi_app.app) as client:
        res = client.post("/platform/tenant-isolation/verify", headers={"x-platform-key": "test-key", "x-platform-admin-role": "operator"})
    assert res.status_code == 200
    assert res.json()["status"] == "pass"


def test_customer_onboarding_checklist_and_audit_package(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(
        fastapi_app,
        "_platform_customer_stats",
        lambda: [
            {
                "organization_id": "org-a",
                "name": "Org A",
                "plan_type": "starter",
                "subscription_status": "active",
                "last_login_at": "",
                "scan_count": 1,
                "asset_count": 2,
                "remediation_count": 0,
                "user_count": 1,
                "active_users_7d": 0,
                "risk_score": 20,
            }
        ],
    )
    monkeypatch.setattr(fastapi_app, "_build_audit_package", lambda organization_id: b"PK\x03\x04fakezip")
    monkeypatch.setattr(fastapi_app, "_record_platform_admin_event", lambda *args, **kwargs: None)
    with TestClient(fastapi_app.app) as client:
        checklist = client.get("/platform/customers/org-a/onboarding-checklist", headers={"x-platform-key": "test-key"})
        package = client.get("/platform/customers/org-a/audit-package", headers={"x-platform-key": "test-key"})
    assert checklist.status_code == 200
    assert checklist.json()["checklist"]["checks"]
    assert package.status_code == 200
    assert package.headers["content-type"] == "application/zip"


def test_customer_feature_flags(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    monkeypatch.setattr(
        fastapi_app,
        "_platform_customer_stats",
        lambda: [{"organization_id": "org-a", "name": "Org A", "plan_type": "starter", "scan_count": 0, "asset_count": 0, "remediation_count": 0}],
    )
    monkeypatch.setattr(
        fastapi_app,
        "_upsert_platform_feature_flag",
        lambda organization_id, req: {"organization_id": organization_id, "flag_key": req.flag_key, "enabled": req.enabled, "reason": req.reason},
    )
    monkeypatch.setattr(fastapi_app, "_platform_feature_flags", lambda organization_id="": [{"organization_id": organization_id, "flag_key": "guided_agent", "enabled": True}])
    monkeypatch.setattr(fastapi_app, "_record_platform_admin_event", lambda *args, **kwargs: None)
    with TestClient(fastapi_app.app) as client:
        put = client.put(
            "/platform/customers/org-a/feature-flags",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={"flag_key": "guided_agent", "enabled": True, "reason": "pilot"},
        )
        get = client.get("/platform/customers/org-a/feature-flags", headers={"x-platform-key": "test-key"})
    assert put.status_code == 200
    assert put.json()["item"]["enabled"] is True
    assert get.status_code == 200
    assert get.json()["items"][0]["flag_key"] == "guided_agent"


def test_demo_lab_seed_blocked_in_production(monkeypatch):
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(fastapi_app, "_ALLOW_DEMO_IN_PRODUCTION", False)
    monkeypatch.setenv("MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP", "1")
    with TestClient(fastapi_app.app) as client:
        res = client.post("/demo/lab/seed", json={"target": "example.com:443"})
    assert res.status_code == 403


def test_cloudflare_mock_apply_blocked_in_production(monkeypatch):
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", True)
    monkeypatch.setattr(fastapi_app, "_ALLOW_DEMO_IN_PRODUCTION", False)
    monkeypatch.setenv("MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP", "1")
    with TestClient(fastapi_app.app) as client:
        res = client.post(
            "/integrations/cloudflare/zones/mock/apply-policy",
            headers={"x-user-role": "operator", "x-user-id": "operator-1"},
            json={},
        )
    assert res.status_code == 403
    assert "mock apply is disabled" in res.json()["detail"]


def test_cloudflare_policy_apply_requires_operator(monkeypatch):
    monkeypatch.setattr(fastapi_app, "AUTH_MODE", "headers")
    monkeypatch.setattr(fastapi_app, "AUTH_REQUIRED", False)
    with TestClient(fastapi_app.app) as client:
        viewer = client.post("/integrations/cloudflare/zones/zone-a/apply-policy?dry_run=1", headers={"x-user-role": "viewer"})
        operator = client.post(
            "/integrations/cloudflare/zones/zone-a/apply-policy?dry_run=1",
            headers={"x-user-role": "operator", "x-user-id": "operator-1"},
        )
    assert viewer.status_code == 403
    assert operator.status_code == 200
    assert operator.json()["dry_run"] is True


def test_suspended_customer_is_blocked(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_ORG_STATUS_CACHE", {"expires_at": 0.0, "statuses": {}})
    monkeypatch.setattr(
        fastapi_app,
        "list_organizations",
        lambda limit=2000: [{"id": "org-suspended", "subscription_status": "suspended"}],
    )
    with TestClient(fastapi_app.app) as client:
        res = client.get("/repositories", headers={"x-org-id": "org-suspended"})
    assert res.status_code == 403
    assert "suspended" in res.json()["detail"].lower()


def test_autopatch_requires_key(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        res = client.get("/platform/autopatches")
    assert res.status_code == 403


def test_autopatch_create_approve_prepare_pr(monkeypatch):
    monkeypatch.setattr(fastapi_app, "_PLATFORM_ADMIN_KEY", "test-key")
    with TestClient(fastapi_app.app) as client:
        created = client.post(
            "/platform/autopatches",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={
                "issue_type": "ci_failure",
                "severity": "medium",
                "title": "Fix failing platform test",
                "source": "unit-test",
                "logs": "AssertionError: expected status 200",
                "affected_files": ["backend/app.py"],
            },
        )
        assert created.status_code == 200
        item = created.json()
        assert item["status"] == "needs_review"
        assert item["patch_plan"]["mode"] == "draft_pr_only"

        blocked = client.post(
            f"/platform/autopatches/{item['id']}/prepare-pr",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={"base_branch": "main"},
        )
        assert blocked.status_code == 409

        approved = client.post(
            f"/platform/autopatches/{item['id']}/approve",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={"reason": "safe draft PR only"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        prepared = client.post(
            f"/platform/autopatches/{item['id']}/prepare-pr",
            headers={"x-platform-key": "test-key", "x-platform-admin-role": "owner"},
            json={"base_branch": "main"},
        )
        assert prepared.status_code == 200
        body = prepared.json()
        assert body["status"] == "pr_ready"
        assert body["branch_name"].startswith("autopatch/")
        assert "must be reviewed" in body["pr_body"]
