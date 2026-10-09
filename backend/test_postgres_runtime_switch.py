import db
from datetime import datetime


def _with_org(org_id: str):
    token = db.set_current_organization_id(org_id)
    try:
        yield
    finally:
        db.reset_current_organization_id(token)


def test_repository_org_and_github_installation_delegate_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "pg_upsert_repository", lambda org_id, name, html_url: calls.setdefault("repo_upsert", (org_id, name, html_url)) or {"id": 1, "name": name, "html_url": html_url})
    monkeypatch.setattr(db, "pg_list_repositories", lambda org_id, limit=2000: calls.setdefault("repo_list", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_get_repository_by_name", lambda org_id, name: calls.setdefault("repo_by_name", (org_id, name)) or {"id": 1, "name": name})
    monkeypatch.setattr(db, "pg_get_repository_by_id", lambda org_id, repo_id: calls.setdefault("repo_by_id", (org_id, repo_id)) or {"id": repo_id})
    monkeypatch.setattr(db, "pg_upsert_organization", lambda oid, name, plan_type="starter", subscription_status="active": calls.setdefault("org_upsert", (oid, name, plan_type, subscription_status)) or {"id": oid, "name": name})
    monkeypatch.setattr(db, "pg_list_organizations", lambda limit=200, offset=0: calls.setdefault("org_list", (limit, offset)) or [])
    monkeypatch.setattr(db, "pg_upsert_github_installation", lambda org_id, installation_id, account_login, **kwargs: calls.setdefault("gh_upsert", (org_id, installation_id, account_login, kwargs)) or {"installation_id": installation_id})
    monkeypatch.setattr(db, "pg_list_github_installations", lambda org_id, limit=2000: calls.setdefault("gh_list", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_get_github_installation", lambda org_id, installation_id: calls.setdefault("gh_get", (org_id, installation_id)) or {"installation_id": installation_id})

    token = db.set_current_organization_id("org-pg")
    try:
        db.upsert_repository("acme/repo", "https://github.com/acme/repo")
        db.list_repositories(limit=25)
        db.get_repository_by_name("acme/repo")
        db.get_repository_by_id(7)
        db.upsert_organization("org-z", "Org Z", plan_type="growth", subscription_status="trial")
        db.list_organizations(limit=15, offset=30)
        db.upsert_github_installation(42, "acme")
        db.list_github_installations(limit=11)
        db.get_github_installation(42)
    finally:
        db.reset_current_organization_id(token)

    assert calls["repo_upsert"] == ("org-pg", "acme/repo", "https://github.com/acme/repo")
    assert calls["repo_list"] == ("org-pg", 25)
    assert calls["repo_by_name"] == ("org-pg", "acme/repo")
    assert calls["repo_by_id"] == ("org-pg", 7)
    assert calls["org_upsert"] == ("org-z", "Org Z", "growth", "trial")
    assert calls["org_list"] == (15, 30)
    assert calls["gh_upsert"][0:3] == ("org-pg", 42, "acme")
    assert calls["gh_list"] == ("org-pg", 11)
    assert calls["gh_get"] == ("org-pg", 42)


def test_init_db_uses_postgres_bootstrap_without_sqlite(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "ensure_postgres_core_schema", lambda: calls.setdefault("schema", True) or None)
    monkeypatch.setattr(
        db,
        "ensure_postgres_default_org",
        lambda name="Default Organization": calls.setdefault("default_org", name) or {"id": db.DEFAULT_ORG_ID},
    )

    def _unexpected_sqlite():
        raise AssertionError("sqlite bootstrap should not run in postgres mode")

    monkeypatch.setattr(db, "get_connection", _unexpected_sqlite)
    db.init_db()

    assert calls["schema"] is True
    assert calls["default_org"] == "Default Organization"


def test_asset_runtime_switch_delegates_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(
        db,
        "pg_upsert_asset",
        lambda org_id, asset_key_str, **kwargs: calls.setdefault("asset_upsert", (org_id, asset_key_str, kwargs)) or {"asset_key": asset_key_str},
    )
    monkeypatch.setattr(db, "pg_get_asset", lambda org_id, asset_key_str: calls.setdefault("asset_get", (org_id, asset_key_str)) or {"asset_key": asset_key_str})
    monkeypatch.setattr(db, "pg_list_assets", lambda org_id, **kwargs: calls.setdefault("asset_list", (org_id, kwargs)) or [])
    monkeypatch.setattr(db, "pg_list_tags", lambda org_id, limit=2000: calls.setdefault("tags", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_list_assets_by_repository", lambda org_id, repo_id, limit=5000: calls.setdefault("asset_by_repo", (org_id, repo_id, limit)) or [])
    monkeypatch.setattr(db, "pg_link_asset_repository", lambda org_id, asset_key_str, repository_id: calls.setdefault("asset_link", (org_id, asset_key_str, repository_id)) or None)
    monkeypatch.setattr(db, "pg_set_asset_metadata", lambda org_id, asset_key_str, metadata: calls.setdefault("asset_meta", (org_id, asset_key_str, metadata)) or None)
    monkeypatch.setattr(db, "pg_latest_scan_result_for_asset", lambda org_id, asset_key_str: calls.setdefault("asset_latest", (org_id, asset_key_str)) or None)

    token = db.set_current_organization_id("org-assets")
    try:
        db.upsert_asset("example.com:443", owner="sec", tags=["prod"], metadata={"x": 1}, repository_id=9)
        db.get_asset("example.com:443")
        db.list_assets(owner="sec", tag="prod", limit=55)
        db.list_tags(limit=12)
        db.list_assets_by_repository(9, limit=88)
        db.link_asset_repository("example.com:443", 10)
        db.set_asset_metadata("example.com:443", {"env": "prod"})
        db.latest_scan_result_for_asset("example.com:443")
    finally:
        db.reset_current_organization_id(token)

    assert calls["asset_upsert"][0:2] == ("org-assets", "example.com:443")
    assert calls["asset_upsert"][2]["owner"] == "sec"
    assert calls["asset_get"] == ("org-assets", "example.com:443")
    assert calls["asset_list"][0] == "org-assets"
    assert calls["asset_list"][1]["owner"] == "sec"
    assert calls["asset_list"][1]["tag"] == "prod"
    assert calls["asset_list"][1]["limit"] == 55
    assert calls["tags"] == ("org-assets", 12)
    assert calls["asset_by_repo"] == ("org-assets", 9, 88)
    assert calls["asset_link"] == ("org-assets", "example.com:443", 10)
    assert calls["asset_meta"] == ("org-assets", "example.com:443", {"env": "prod"})
    assert calls["asset_latest"] == ("org-assets", "example.com:443")



def test_remediation_and_audit_runtime_switch_delegate_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "pg_create_remediation", lambda org_id, asset_key_str, repo_id, file_path, vulnerability, suggested_fix, **kwargs: calls.setdefault("rem_create", (org_id, asset_key_str, repo_id, file_path, vulnerability, suggested_fix, kwargs)) or {"id": 3})
    monkeypatch.setattr(db, "pg_get_remediation", lambda org_id, remediation_id: calls.setdefault("rem_get", (org_id, remediation_id)) or {"id": remediation_id})
    monkeypatch.setattr(db, "pg_list_remediations", lambda org_id, **kwargs: calls.setdefault("rem_list", (org_id, kwargs)) or [])
    monkeypatch.setattr(db, "pg_update_remediation_status", lambda org_id, remediation_id, status, review_note="": calls.setdefault("rem_update", (org_id, remediation_id, status, review_note)) or {"id": remediation_id})
    monkeypatch.setattr(db, "pg_set_remediation_pr", lambda org_id, remediation_id, pr_url, status="pr_created", **kwargs: calls.setdefault("rem_pr", (org_id, remediation_id, pr_url, status, kwargs)) or {"id": remediation_id})
    monkeypatch.setattr(db, "pg_mark_remediation_merged", lambda org_id, remediation_id, merged_at_iso="": calls.setdefault("rem_merged", (org_id, remediation_id, merged_at_iso)) or {"id": remediation_id})
    monkeypatch.setattr(db, "pg_mark_remediation_merged_by_pr_url", lambda pr_url, merged_at_iso="", organization_id=None: calls.setdefault("rem_by_pr", (pr_url, merged_at_iso, organization_id)) or {"matched": 1})
    monkeypatch.setattr(db, "pg_auto_close_merged_remediations", lambda org_id, scan_id, results: calls.setdefault("rem_auto_close", (org_id, scan_id, results)) or {"closed": 1})
    monkeypatch.setattr(db, "pg_append_audit_log", lambda org_id, **kwargs: calls.setdefault("audit_append", (org_id, kwargs)) or {"id": 5})
    monkeypatch.setattr(db, "pg_list_audit_logs", lambda org_id, **kwargs: calls.setdefault("audit_list", (org_id, kwargs)) or [])

    token = db.set_current_organization_id("org-rem")
    try:
        db.create_remediation("example.com:443", 9, "main.tf", "Upgrade TLS", "diff", original_content="before")
        db.get_remediation(3)
        db.list_remediations(status="pending", repo_id=9, asset_key_str="example.com:443", limit=25)
        db.update_remediation_status(3, "approved", review_note="ok")
        db.set_remediation_pr(3, "https://github.com/acme/repo/pull/1")
        db.mark_remediation_merged(3, merged_at_iso="2026-04-24T12:00:00Z")
        db.mark_remediation_merged_by_pr_url("https://github.com/acme/repo/pull/1", merged_at_iso="", organization_id="org-rem")
        db.auto_close_merged_remediations("scan-1", [{"host": "example.com", "port": 443, "findings": []}])
        db.append_audit_log("user-1", "admin", "audit.list", "audit_log", details={"k": "v"})
        db.list_audit_logs(limit=10, actor_id="user-1", action="audit.list", decision="allow")
    finally:
        db.reset_current_organization_id(token)

    assert calls["rem_create"][0:6] == ("org-rem", "example.com:443", 9, "main.tf", "Upgrade TLS", "diff")
    assert calls["rem_get"] == ("org-rem", 3)
    assert calls["rem_list"][0] == "org-rem"
    assert calls["rem_list"][1]["status"] == "pending"
    assert calls["rem_update"] == ("org-rem", 3, "approved", "ok")
    assert calls["rem_pr"][0:4] == ("org-rem", 3, "https://github.com/acme/repo/pull/1", "pr_created")
    assert calls["rem_pr"][4]["github_credential_id"] == 0
    assert calls["rem_merged"] == ("org-rem", 3, "2026-04-24T12:00:00Z")
    assert calls["rem_by_pr"] == ("https://github.com/acme/repo/pull/1", "", "org-rem")
    assert calls["rem_auto_close"][0:2] == ("org-rem", "scan-1")
    assert calls["audit_append"][0] == "org-rem"
    assert calls["audit_append"][1]["actor_id"] == "user-1"
    assert calls["audit_list"][0] == "org-rem"
    assert calls["audit_list"][1]["limit"] == 10


def test_validation_runtime_switch_delegates_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "pg_create_validation_job", lambda org_id, remediation_id, **kwargs: calls.setdefault("val_create", (org_id, remediation_id, kwargs)) or {"id": 7})
    monkeypatch.setattr(db, "pg_get_validation_job", lambda org_id, validation_job_id: calls.setdefault("val_get", (org_id, validation_job_id)) or {"id": validation_job_id})
    monkeypatch.setattr(db, "pg_list_validation_jobs", lambda org_id, **kwargs: calls.setdefault("val_list", (org_id, kwargs)) or [])
    monkeypatch.setattr(db, "pg_get_latest_validation_job_for_remediation", lambda org_id, remediation_id, passed_only=False: calls.setdefault("val_latest", (org_id, remediation_id, passed_only)) or None)
    monkeypatch.setattr(db, "pg_update_validation_job", lambda org_id, validation_job_id, **kwargs: calls.setdefault("val_update", (org_id, validation_job_id, kwargs)) or {"id": validation_job_id})

    token = db.set_current_organization_id("org-val")
    try:
        db.create_validation_job(11, validator_type="terraform", git_ref="main", status="queued", details={"timeout_seconds": 60})
        db.get_validation_job(7)
        db.list_validation_jobs(remediation_id=11, status="passed", limit=5)
        db.get_latest_validation_job_for_remediation(11, passed_only=True)
        db.update_validation_job(7, status="passed", exit_code=0, finished=True)
    finally:
        db.reset_current_organization_id(token)

    assert calls["val_create"][0:2] == ("org-val", 11)
    assert calls["val_create"][2]["validator_type"] == "terraform"
    assert calls["val_get"] == ("org-val", 7)
    assert calls["val_list"][0] == "org-val"
    assert calls["val_list"][1]["remediation_id"] == 11
    assert calls["val_list"][1]["status"] == "passed"
    assert calls["val_latest"] == ("org-val", 11, True)
    assert calls["val_update"][0:2] == ("org-val", 7)
    assert calls["val_update"][2]["status"] == "passed"
    assert calls["val_update"][2]["exit_code"] == 0


def test_webhook_runtime_switch_delegates_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "pg_list_webhooks", lambda org_id, limit=200, include_secret=False: calls.setdefault("webhooks", (org_id, limit, include_secret)) or [])
    monkeypatch.setattr(db, "pg_list_webhooks_public", lambda org_id, limit=200: calls.setdefault("webhooks_public", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_upsert_webhook", lambda **kwargs: calls.setdefault("webhook_upsert", kwargs) or {"id": 1})
    monkeypatch.setattr(db, "pg_delete_webhook", lambda org_id, webhook_id: calls.setdefault("webhook_delete", (org_id, webhook_id)) or None)
    monkeypatch.setattr(db, "pg_record_webhook_event", lambda **kwargs: calls.setdefault("event_record", kwargs) or 5)
    monkeypatch.setattr(db, "pg_bump_webhook_attempt", lambda org_id, event_row_id: calls.setdefault("event_bump", (org_id, event_row_id)) or None)
    monkeypatch.setattr(db, "pg_update_webhook_event", lambda **kwargs: calls.setdefault("event_update", kwargs) or None)
    monkeypatch.setattr(db, "pg_list_webhook_events", lambda org_id, limit=50: calls.setdefault("events", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_list_pending_webhook_events", lambda org_id, limit=100, max_attempts=5: calls.setdefault("pending", (org_id, limit, max_attempts)) or [])
    monkeypatch.setattr(db, "pg_list_due_webhook_events", lambda org_id, limit=100, max_attempts=5, now_iso=None: calls.setdefault("due", (org_id, limit, max_attempts, now_iso)) or [])
    monkeypatch.setattr(db, "pg_get_webhook_public", lambda org_id, webhook_id: calls.setdefault("webhook_public", (org_id, webhook_id)) or {"id": webhook_id})
    monkeypatch.setattr(
        db,
        "pg_claim_due_webhook_events",
        lambda org_id, limit=100, max_attempts=5, now_iso=None, worker_id=None, lease_seconds=600: calls.setdefault(
            "claim", (org_id, limit, max_attempts, now_iso, worker_id, lease_seconds)
        )
        or [],
    )
    monkeypatch.setattr(db, "pg_rotate_webhook_secret", lambda org_id, webhook_id: calls.setdefault("rotate", (org_id, webhook_id)) or {"id": webhook_id})

    db.list_webhooks(limit=9, include_secret=True)
    db.list_webhooks_public(limit=8)
    db.upsert_webhook("wh1", "https://example.com/hook", secret="s", credential_id=7, events=["*"], enabled=False, webhook_id=11)
    db.delete_webhook(11)
    db.record_webhook_event(11, "scan.done", "dedupe-1", {"ok": True}, max_attempts=4)
    db.bump_webhook_attempt(5)
    db.update_webhook_event(5, "failed", http_status=500, error_text="boom", response_excerpt="x", next_attempt_at="2026-04-25T12:00:00Z")
    db.list_webhook_events(limit=7)
    db.list_pending_webhook_events(limit=6, max_attempts=3)
    db.list_due_webhook_events(limit=5, max_attempts=2, now_iso="2026-04-25T12:00:00Z")
    db.get_webhook_public(11)
    db.claim_due_webhook_events(limit=4, max_attempts=2, now_iso="2026-04-25T12:00:00Z", worker_id="w1", lease_seconds=30)
    db.rotate_webhook_secret(11)

    org_id = db.DEFAULT_ORG_ID
    assert calls["webhooks"] == (org_id, 9, True)
    assert calls["webhooks_public"] == (org_id, 8)
    assert calls["webhook_upsert"]["name"] == "wh1"
    assert calls["webhook_upsert"]["credential_id"] == 7
    assert calls["webhook_delete"] == (org_id, 11)
    assert calls["event_record"]["webhook_id"] == 11
    assert calls["event_record"]["max_attempts"] == 4
    assert calls["event_bump"] == (org_id, 5)
    assert calls["event_update"]["http_status"] == 500
    assert calls["events"] == (org_id, 7)
    assert calls["pending"] == (org_id, 6, 3)
    assert calls["due"] == (org_id, 5, 2, "2026-04-25T12:00:00Z")
    assert calls["webhook_public"] == (org_id, 11)
    assert calls["claim"] == (org_id, 4, 2, "2026-04-25T12:00:00Z", "w1", 30)
    assert calls["rotate"] == (org_id, 11)


def test_collection_schedule_and_event_rule_runtime_switch_delegate_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}

    monkeypatch.setattr(db, "pg_upsert_collection", lambda org_id, name, targets_text: calls.setdefault("collection_upsert", (org_id, name, targets_text)) or {"id": 1})
    monkeypatch.setattr(db, "pg_list_collections", lambda org_id: calls.setdefault("collection_list", org_id) or [])
    monkeypatch.setattr(db, "pg_get_collection", lambda org_id, collection_id: calls.setdefault("collection_get", (org_id, collection_id)) or {"id": collection_id})
    monkeypatch.setattr(db, "pg_delete_collection", lambda org_id, collection_id: calls.setdefault("collection_delete", (org_id, collection_id)) or None)
    monkeypatch.setattr(db, "pg_create_schedule", lambda org_id, collection_id, interval_minutes, enabled=True: calls.setdefault("schedule_create", (org_id, collection_id, interval_minutes, enabled)) or {"id": 2})
    monkeypatch.setattr(db, "pg_list_schedules", lambda org_id: calls.setdefault("schedule_list", org_id) or [])
    monkeypatch.setattr(db, "pg_get_schedule", lambda org_id, schedule_id: calls.setdefault("schedule_get", (org_id, schedule_id)) or {"id": schedule_id})
    monkeypatch.setattr(db, "pg_update_schedule", lambda org_id, schedule_id, interval_minutes=None, enabled=None: calls.setdefault("schedule_update", (org_id, schedule_id, interval_minutes, enabled)) or {"id": schedule_id})
    monkeypatch.setattr(db, "pg_delete_schedule", lambda org_id, schedule_id: calls.setdefault("schedule_delete", (org_id, schedule_id)) or None)
    monkeypatch.setattr(db, "pg_due_schedules", lambda org_id, now_iso: calls.setdefault("schedule_due", (org_id, now_iso)) or [])
    monkeypatch.setattr(db, "pg_mark_schedule_ran", lambda org_id, schedule_id, run_at_iso, interval_minutes, last_scan_id: calls.setdefault("schedule_ran", (org_id, schedule_id, run_at_iso, interval_minutes, last_scan_id)) or None)
    monkeypatch.setattr(db, "pg_get_integration_setting", lambda key, default="": calls.setdefault("setting_get", (key, default)) or default)
    monkeypatch.setattr(db, "pg_set_integration_setting", lambda key, value: calls.setdefault("setting_set", (key, value)) or None)
    monkeypatch.setattr(db, "pg_get_event_rule_fire", lambda org_id, rule_id, fingerprint: calls.setdefault("rule_fire_get", (org_id, rule_id, fingerprint)) or None)
    monkeypatch.setattr(db, "pg_upsert_event_rule_fire", lambda org_id, rule_id, fingerprint, fired_at_iso: calls.setdefault("rule_fire_upsert", (org_id, rule_id, fingerprint, fired_at_iso)) or None)
    monkeypatch.setattr(db, "pg_should_fire_event_rule", lambda org_id, rule_id, fingerprint, cooldown_minutes, fire_mode: calls.setdefault("rule_fire_should", (org_id, rule_id, fingerprint, cooldown_minutes, fire_mode)) or True)
    monkeypatch.setattr(db, "pg_list_event_rules", lambda org_id, limit=200: calls.setdefault("rule_list", (org_id, limit)) or [])
    monkeypatch.setattr(db, "pg_upsert_event_rule", lambda **kwargs: calls.setdefault("rule_upsert", kwargs) or {"id": 3})
    monkeypatch.setattr(db, "pg_delete_event_rule", lambda org_id, rule_id: calls.setdefault("rule_delete", (org_id, rule_id)) or None)

    db.upsert_collection("c1", "example.com")
    db.list_collections()
    db.get_collection(1)
    db.delete_collection(1)
    db.create_schedule(1, 30, enabled=False)
    db.list_schedules()
    db.get_schedule(2)
    db.update_schedule(2, interval_minutes=45, enabled=True)
    db.delete_schedule(2)
    db.due_schedules("2026-04-25T12:00:00Z")
    db.mark_schedule_ran(2, "2026-04-25T12:00:00Z", 45, "scan-1")
    db.get_integration_setting("record_suppressed_events", "0")
    db.set_integration_setting("record_suppressed_events", "1")
    db.get_event_rule_fire(3, "fp-1")
    db.upsert_event_rule_fire(3, "fp-1", "2026-04-25T12:00:00Z")
    db.should_fire_event_rule(3, "fp-1", 60, "cooldown")
    db.list_event_rules(limit=9)
    db.upsert_event_rule(
        name="rule1",
        webhook_ids=[1],
        event_types=["scan.complete"],
        enabled=False,
        min_severity="high",
        rule_ids=["R1"],
        quantum_score_min=5.0,
        environments=["prod"],
        teams=["sec"],
        criticalities=["high"],
        tags=["tls"],
        cooldown_minutes=15,
        rule_id=4,
        fire_mode="cooldown",
    )
    db.delete_event_rule(4)

    org_id = db.DEFAULT_ORG_ID
    assert calls["collection_upsert"] == (org_id, "c1", "example.com")
    assert calls["collection_list"] == org_id
    assert calls["collection_get"] == (org_id, 1)
    assert calls["collection_delete"] == (org_id, 1)
    assert calls["schedule_create"] == (org_id, 1, 30, False)
    assert calls["schedule_list"] == org_id
    assert calls["schedule_get"] == (org_id, 2)
    assert calls["schedule_update"] == (org_id, 2, 45, True)
    assert calls["schedule_delete"] == (org_id, 2)
    assert calls["schedule_due"] == (org_id, "2026-04-25T12:00:00Z")
    assert calls["schedule_ran"] == (org_id, 2, "2026-04-25T12:00:00Z", 45, "scan-1")
    assert calls["setting_get"] == ("record_suppressed_events", "0")
    assert calls["setting_set"] == ("record_suppressed_events", "1")
    assert calls["rule_fire_get"] == (org_id, 3, "fp-1")
    assert calls["rule_fire_upsert"] == (org_id, 3, "fp-1", "2026-04-25T12:00:00Z")
    assert calls["rule_fire_should"] == (org_id, 3, "fp-1", 60, "cooldown")
    assert calls["rule_list"] == (org_id, 9)
    assert calls["rule_upsert"]["name"] == "rule1"
    assert calls["rule_upsert"]["fire_mode"] == "cooldown"
    assert calls["rule_delete"] == (org_id, 4)


def test_scan_baseline_and_history_runtime_switch_delegate_to_postgres(monkeypatch):
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "postgres")
    calls = {}
    baseline_sets = []
    loaded_scan = {
        "id": "scan-1",
        "status": "completed",
        "created_at": datetime(2026, 4, 25, 12, 0, 0),
        "progress": {"percent": 100},
        "error": "",
        "results": [
            {"host": "a.example", "port": 443},
            {"host": "b.example", "port": 8443},
        ],
        "summary": {"assets": 2},
        "job_id": "job-1",
    }

    monkeypatch.setattr(
        db,
        "pg_save_scan_row",
        lambda org_id, scan_id, status, created_at, progress, error_text, results, summary: calls.setdefault(
            "scan_save", (org_id, scan_id, status, created_at, progress, error_text, results, summary)
        )
        or None,
    )
    monkeypatch.setattr(
        db,
        "pg_update_scan_progress",
        lambda org_id, scan_id, progress, status="running", error_text="": calls.setdefault(
            "scan_progress", (org_id, scan_id, progress, status, error_text)
        )
        or None,
    )
    monkeypatch.setattr(
        db,
        "pg_save_scan_results",
        lambda org_id, scan_id, results, summary, status="completed", error_text="": calls.setdefault(
            "scan_results", (org_id, scan_id, results, summary, status, error_text)
        )
        or None,
    )
    def _pg_load_scan_row(org_id, scan_id):
        calls["scan_load"] = (org_id, scan_id)
        row = dict(loaded_scan)
        row["id"] = scan_id
        return row

    monkeypatch.setattr(db, "pg_load_scan_row", _pg_load_scan_row)
    monkeypatch.setattr(db, "pg_list_scan_rows", lambda org_id, limit=20: calls.setdefault("scan_list", (org_id, limit)) or [])
    monkeypatch.setattr(
        db,
        "pg_update_scan_job",
        lambda org_id, scan_id, job_id="", job_state="", started_at_iso="", finished_at_iso="": calls.setdefault(
            "scan_job", (org_id, scan_id, job_id, job_state, started_at_iso, finished_at_iso)
        )
        or None,
    )
    monkeypatch.setattr(
        db,
        "pg_set_baseline",
        lambda org_id, asset_key_str, baseline_scan_id, set_at=None: baseline_sets.append(
            (org_id, asset_key_str, baseline_scan_id, set_at)
        )
        or None,
    )
    monkeypatch.setattr(
        db,
        "pg_get_baseline",
        lambda org_id, asset_key_str: calls.setdefault("baseline_get", (org_id, asset_key_str))
        or {"asset_key": asset_key_str, "baseline_scan_id": "scan-1", "set_at": "2026-04-25T12:00:00Z"},
    )
    monkeypatch.setattr(
        db,
        "pg_list_baselines",
        lambda org_id, limit=500: calls.setdefault("baseline_list", (org_id, limit)) or [],
    )
    monkeypatch.setattr(
        db,
        "pg_save_scan_asset_summaries",
        lambda org_id, scan_id, scanned_at_iso, results: calls.setdefault(
            "asset_summaries", (org_id, scan_id, scanned_at_iso, results)
        )
        or None,
    )
    monkeypatch.setattr(
        db,
        "pg_get_asset_history",
        lambda org_id, asset_key_str, limit=50: calls.setdefault("asset_history", (org_id, asset_key_str, limit)) or [],
    )
    monkeypatch.setattr(
        db,
        "pg_list_scan_results",
        lambda org_id, scan_id, owner="", team="", environment="", criticality="", limit=5000: calls.setdefault(
            "scan_results_list", (org_id, scan_id, owner, team, environment, criticality, limit)
        )
        or [],
    )
    monkeypatch.setattr(
        db,
        "pg_list_scan_results_since",
        lambda org_id, since_iso, limit=200000: calls.setdefault("scan_results_since", (org_id, since_iso, limit)) or [],
    )

    created_at = datetime(2026, 4, 25, 12, 0, 0)
    token = db.set_current_organization_id("org-scan")
    try:
        db.save_scan_row("scan-1", "queued", created_at, {"percent": 0}, "", [], {})
        db.update_scan_progress("scan-1", {"percent": 50}, status="running", error_text="")
        db.save_scan_results("scan-1", [{"host": "a.example", "port": 443}], {"assets": 1}, status="completed")
        db.load_scan_row("scan-1")
        db.list_scan_rows(limit=13)
        db.update_scan_job("scan-1", job_id="job-7", job_state="STARTED", started_at_iso="2026-04-25T12:00:00Z")
        db.set_baseline("a.example:443", "scan-1")
        db.get_baseline("a.example:443")
        db.list_baselines(limit=17)
        outcome = db.set_baselines_from_scan("scan-1")
        db.save_scan_asset_summaries("scan-1", "2026-04-25T12:30:00Z", [{"host": "a.example", "port": 443}])
        db.get_asset_history("a.example:443", limit=19)
        db.list_scan_results("scan-1", owner="sec", team="pqc", environment="prod", criticality="high", limit=27)
        db.list_scan_results_since("2026-04-25T00:00:00Z", limit=29)
    finally:
        db.reset_current_organization_id(token)

    assert calls["scan_save"][0:3] == ("org-scan", "scan-1", "queued")
    assert calls["scan_progress"] == ("org-scan", "scan-1", {"percent": 50}, "running", "")
    assert calls["scan_results"][0:2] == ("org-scan", "scan-1")
    assert calls["scan_load"] == ("org-scan", "scan-1")
    assert calls["scan_list"] == ("org-scan", 13)
    assert calls["scan_job"] == ("org-scan", "scan-1", "job-7", "STARTED", "2026-04-25T12:00:00Z", "")
    assert calls["baseline_get"] == ("org-scan", "a.example:443")
    assert calls["baseline_list"] == ("org-scan", 17)
    assert len(baseline_sets) == 3
    assert baseline_sets[0][0:3] == ("org-scan", "a.example:443", "scan-1")
    assert baseline_sets[1][0:3] == ("org-scan", "a.example:443", "scan-1")
    assert baseline_sets[2][0:3] == ("org-scan", "b.example:8443", "scan-1")
    assert outcome["updated"] == 2
    assert calls["asset_summaries"][0:3] == ("org-scan", "scan-1", "2026-04-25T12:30:00Z")
    assert calls["asset_history"] == ("org-scan", "a.example:443", 19)
    assert calls["scan_results_list"] == ("org-scan", "scan-1", "sec", "pqc", "prod", "high", 27)
    assert calls["scan_results_since"] == ("org-scan", "2026-04-25T00:00:00Z", 29)
