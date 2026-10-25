from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _count(items: Iterable[Dict[str, Any]], predicate) -> int:
    return sum(1 for item in items if predicate(item))


def _item(item_id: str, title: str, ready: bool, evidence: str, next_action: str, *, warn: bool = False) -> Dict[str, Any]:
    status = "ready" if ready else ("warning" if warn else "blocked")
    return {
        "id": item_id,
        "title": title,
        "status": status,
        "ready": bool(ready),
        "evidence": evidence,
        "next_action": next_action if not ready else "Continue to next step.",
    }


def build_e2e_readiness(
    *,
    auth_configured: bool,
    repositories: List[Dict[str, Any]],
    github_installations: List[Dict[str, Any]],
    scans: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    remediations: List[Dict[str, Any]],
    validations: List[Dict[str, Any]],
    pr_events: List[Dict[str, Any]],
    audit_events: List[Dict[str, Any]],
    webhook_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    completed_scans = _count(scans, lambda s: str(s.get("status") or "").lower() == "completed")
    linked_assets = _count(assets, lambda a: int(a.get("repository_id") or 0) > 0 or bool(a.get("repository_name")))
    approved = _count(remediations, lambda r: str(r.get("status") or "").lower() == "approved")
    pr_created = _count(remediations, lambda r: str(r.get("status") or "").lower() in {"pr_created", "merged", "verified_closed"} or bool(r.get("pr_url")))
    merged = _count(remediations, lambda r: str(r.get("status") or "").lower() in {"merged", "verified_closed"} or bool(r.get("merged_at")))
    verified = _count(remediations, lambda r: str(r.get("status") or "").lower() == "verified_closed")
    drift_checked = _count(remediations, lambda r: bool(r.get("last_drift_checked_at")) or str(r.get("drift_status") or "").strip())
    drift_followups = _count(remediations, lambda r: int(r.get("parent_remediation_id") or 0) > 0 or int(r.get("drift_followup_remediation_id") or 0) > 0)
    validation_passed = _count(validations, lambda v: str(v.get("status") or "").lower() == "passed")
    validation_failed = _count(validations, lambda v: str(v.get("status") or "").lower() == "failed")
    audit_count = len(audit_events)
    webhook_delivery_count = len(webhook_events)
    pr_event_count = len(pr_events)

    items = [
        _item("environment", "Environment / startup", True, "API readiness endpoint is responding.", "Keep Docker/API/worker/beat running."),
        _item("regression", "Automated regression suite", False, "Test files exist, but this endpoint has no fresh release-bound execution evidence.", "Run and review the release regression suite; repository presence is not a passing result.", warn=True),
        _item("auth", "Auth / login", auth_configured, "Hosted/Auth0 config detected." if auth_configured else "No hosted auth provider configured.", "Configure Auth0/hosted JWT settings or use dev headers only locally."),
        _item("rbac", "RBAC", False, f"{audit_count} audit event(s) show activity, not verified authorization boundaries.", "Exercise viewer/operator/admin deny and allow paths.", warn=True),
        _item("multi_tenancy", "Multi-tenancy / org isolation", False, "Inventory presence is not evidence of tenant isolation.", "Run org-isolation tests with Org A and Org B data and the production database role.", warn=True),
        _item("vault", "Vault / credentials", False, "Integration records do not verify credential encryption or vault access controls.", "Test vault encryption, access control, key rotation, and recovery.", warn=True),
        _item("github_app", "GitHub App integration", bool(github_installations and repositories), f"{len(github_installations)} installation(s), {len(repositories)} repo(s).", "Sync installations and repositories."),
        _item("scan", "Scan lifecycle", completed_scans > 0, f"{completed_scans} completed scan(s).", "Run a scan to completion."),
        _item("assets", "Asset inventory / asset views", len(assets) > 0, f"{len(assets)} asset(s) in inventory.", "Create/classify assets from scan or runtime evidence."),
        _item("correlation", "Correlation", linked_assets > 0, f"{linked_assets} asset(s) linked to repositories.", "Link asset records to synced repositories."),
        _item("compliance_gate", "Compliance gate", bool(scans and remediations), f"{len(remediations)} remediation/finding workflow item(s).", "Run compliance gate on a repo with linked findings."),
        _item("suggestion", "Remediation suggestion", len(remediations) > 0, f"{len(remediations)} remediation(s).", "Generate a remediation from repo + asset evidence."),
        _item("approval", "Remediation approval / rejection", approved > 0 or pr_created > 0 or verified > 0, f"{approved} approved remediation(s).", "Approve or reject at least one remediation."),
        _item("validation", "Validation sandbox", validation_passed > 0, f"{validation_passed} passed, {validation_failed} failed validation job(s).", "Run sandbox validation until one remediation passes."),
        _item("pr_creation", "PR creation", pr_created > 0, f"{pr_created} remediation(s) with PR state/url.", "Create a PR from a validated remediation."),
        _item("merge_webhook", "Merge webhook", merged > 0 or pr_event_count > 0, f"{merged} merged remediation(s), {pr_event_count} PR webhook event(s).", "Merge a PR and confirm webhook reaches the API."),
        _item("verify_close", "Verify-close loop", verified > 0, f"{verified} verified-closed remediation(s).", "Run verification scan after merge."),
        _item("drift_detection", "Drift detection", drift_checked > 0, f"{drift_checked} remediation(s) with drift check state.", "Run drift detection against merged/verified fixes."),
        _item("drift_response", "Drift response", drift_followups > 0, f"{drift_followups} drift follow-up linkage(s).", "Create/acknowledge/revalidate a drift follow-up."),
        _item("notifications", "Notifications", webhook_delivery_count > 0, f"{webhook_delivery_count} webhook delivery event(s).", "Register a webhook and trigger validation/merge/drift events."),
        _item("report", "Compliance report JSON", bool(assets or remediations or scans), "Report has data sources available.", "Open /org/compliance-report?format=json."),
        _item("dashboard", "Dashboard UI", True, "Dashboard and queue UI routes are available.", "Open UI and refresh dashboard widgets."),
        _item("persistence", "Persistence / restart safety", False, "Existing rows do not establish backup/restore or restart safety.", "Restart containers/redeploy and perform a restore drill.", warn=True),
        _item("security_negative", "Security / negative tests", False, "Audit activity is not a passing negative-security test report.", "Run missing/invalid token and wrong-role tests.", warn=True),
        _item("money_flow", "Final end-to-end money flow", all([auth_configured, repositories, completed_scans, linked_assets, approved or pr_created, validation_passed, pr_created, merged, verified]), "Aggregated from login, repo, scan, correlate, approve, validate, PR, merge, verify.", "Complete every blocked item above in order."),
    ]

    ready = _count(items, lambda i: i["status"] == "ready")
    warnings = _count(items, lambda i: i["status"] == "warning")
    blocked = len(items) - ready - warnings
    return {
        "ok": True,
        "scope": "Workflow progress only, not production security approval. Unverified security controls remain warnings.",
        "summary": {
            "total": len(items),
            "ready": ready,
            "warning": warnings,
            "blocked": blocked,
            "readiness_percent": round((ready / len(items)) * 100) if items else 0,
        },
        "items": items,
        "source_counts": {
            "repositories": len(repositories),
            "github_installations": len(github_installations),
            "scans": len(scans),
            "completed_scans": completed_scans,
            "assets": len(assets),
            "linked_assets": linked_assets,
            "remediations": len(remediations),
            "validations": len(validations),
            "passed_validations": validation_passed,
            "pr_events": pr_event_count,
            "audit_events": audit_count,
            "webhook_events": webhook_delivery_count,
        },
    }


def compact_readiness_handoff(readiness: Dict[str, Any]) -> Dict[str, Any]:
    items = list(readiness.get("items") or [])
    blocked = [i for i in items if str(i.get("status") or "") == "blocked"]
    warnings = [i for i in items if str(i.get("status") or "") == "warning"]
    ready = [i for i in items if str(i.get("status") or "") == "ready"]
    return {
        "ok": True,
        "summary": readiness.get("summary") or {},
        "source_counts": readiness.get("source_counts") or {},
        "blocked": blocked,
        "warnings": warnings,
        "ready_count": len(ready),
        "next_blocker": blocked[0] if blocked else None,
    }


def readiness_handoff_markdown(readiness: Dict[str, Any]) -> str:
    handoff = compact_readiness_handoff(readiness)
    summary = handoff.get("summary") or {}
    source_counts = handoff.get("source_counts") or {}
    lines = [
        "# Post-Quantum Platform E2E Readiness Handoff",
        "",
        f"- Readiness: {summary.get('readiness_percent', 0)}%",
        f"- Ready: {summary.get('ready', 0)}/{summary.get('total', 0)}",
        f"- Warnings: {summary.get('warning', 0)}",
        f"- Blocked: {summary.get('blocked', 0)}",
        "",
        "## Source Counts",
    ]
    for key in sorted(source_counts):
        lines.append(f"- {key}: {source_counts.get(key)}")
    lines.extend(["", "## Blockers"])
    blocked = handoff.get("blocked") or []
    if blocked:
        for item in blocked:
            lines.append(f"- [{item.get('id')}] {item.get('title')}: {item.get('next_action')} Evidence: {item.get('evidence')}")
    else:
        lines.append("- None")
    lines.extend(["", "## Warnings"])
    warnings = handoff.get("warnings") or []
    if warnings:
        for item in warnings:
            lines.append(f"- [{item.get('id')}] {item.get('title')}: {item.get('next_action')} Evidence: {item.get('evidence')}")
    else:
        lines.append("- None")
    next_blocker = handoff.get("next_blocker")
    if next_blocker:
        lines.extend([
            "",
            "## Next Action",
            f"Work on `{next_blocker.get('id')}`: {next_blocker.get('next_action')}",
        ])
    return "\n".join(lines) + "\n"
