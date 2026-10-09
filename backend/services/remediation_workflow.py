from __future__ import annotations

from datetime import datetime, timezone
import os
import re
from typing import Any, Callable, Dict, Optional, Tuple
import uuid


GUARDRAIL_FORBIDDEN_PATTERNS = [
    (r"\biam\b", "IAM changes are not allowed by remediation guardrail"),
    (r"aws_iam_[a-z0-9_]+", "AWS IAM resource changes are not allowed by remediation guardrail"),
    (r"google_.*iam", "GCP IAM changes are not allowed by remediation guardrail"),
    (r"\bfirewall\b", "Firewall changes are not allowed by remediation guardrail"),
    (r"google_compute_firewall", "GCP firewall resource changes are not allowed by remediation guardrail"),
    (r"aws_security_group", "AWS security group changes are not allowed by remediation guardrail"),
]


def guardrail_reason(text: str) -> str:
    payload = str(text or "")
    for pattern, reason in GUARDRAIL_FORBIDDEN_PATTERNS:
        if re.search(pattern, payload, flags=re.IGNORECASE):
            return reason
    return ""


def remediation_safety_label(file_path: str) -> Dict[str, str]:
    file_name = str(file_path or "")
    if re.search(r"\.(tf|hcl|yaml|yml|json|conf|properties)$", file_name, flags=re.IGNORECASE):
        return {"label": "Safe config path", "level": "safe_config", "ui_class": "ok"}
    if re.search(r"\.(java|kt|go|py|js|ts|c|cc|cpp|h|hpp|cs|rb|php)$", file_name, flags=re.IGNORECASE):
        return {"label": "Migration task", "level": "app_code", "ui_class": "warn"}
    return {"label": "Review required", "level": "manual_review", "ui_class": "warn"}


def remediation_next_action(row: Dict[str, Any]) -> str:
    status = str(row.get("status") or "").lower()
    origin = str(row.get("origin_kind") or "")
    file_path = str(row.get("file_path") or "")
    safety = remediation_safety_label(file_path)
    if status == "candidate":
        if origin == "repo_crypto_discovery" and safety["level"] == "app_code":
            return "Create a migration task for engineering review. Do not auto-rewrite complex app crypto blindly."
        if safety["level"] == "safe_config":
            return "Review candidate, then promote through approval and sandbox validation."
        return "Review ownership, repo, and file path before generating a fix."
    if status == "suggested":
        return "Human review required. Approve only if the proposed change is narrow and understandable."
    if status == "approved":
        return "Run sandbox validation before creating a pull request."
    if status in {"validated", "validation_passed"}:
        return "Create a pull request for normal engineering review."
    if status == "pr_created":
        return "Track merge, then rescan to verify closure."
    if status == "merged":
        return "Run or wait for verification scan to prove the issue is actually closed."
    if status == "verified_closed":
        return "Monitor drift so the fix does not get silently undone."
    if status == "rejected":
        return "No action unless the finding is reopened with a safer approach."
    return "Inspect details and choose the next safe workflow action."


def remediation_queue_column(row: Dict[str, Any]) -> str:
    status = str(row.get("status") or "").lower()
    drift = str(row.get("drift_status") or "").lower()
    if drift == "drifted" or status == "verified_closed":
        return "verified"
    if status in {"pr_created", "merged"}:
        return "pr"
    if status in {"approved", "validation_failed"}:
        return "validate"
    if status in {"suggested", "pending_review", "rejected"}:
        return "review"
    return "candidate"


def pr_readiness(
    remediation: Dict[str, Any],
    latest_validation: Optional[Dict[str, Any]],
    *,
    allow_unvalidated: bool = False,
    actor_role: str = "",
) -> Dict[str, Any]:
    status = str((remediation or {}).get("status") or "").lower()
    if status != "approved":
        return {"ok": False, "status_code": 400, "reason": "remediation must be approved before creating a PR"}
    validation_status = str((latest_validation or {}).get("status") or "").lower()
    if validation_status != "passed":
        if not bool(allow_unvalidated):
            return {"ok": False, "status_code": 400, "reason": "remediation must pass validation before creating a PR"}
        if str(actor_role or "").lower() != "admin":
            return {"ok": False, "status_code": 403, "reason": "only admin can override remediation validation"}
    return {"ok": True, "reason": "ready"}

def split_owner_repo(repo_name: str) -> Tuple[str, str]:
    clean = str(repo_name or "").strip()
    if "/" not in clean:
        raise ValueError("repository name must be owner/repo")
    owner, repo = clean.split("/", 1)
    owner = owner.strip()
    repo = repo.strip()
    if not owner or not repo:
        raise ValueError("repository name must be owner/repo")
    return owner, repo


def build_remediation_branch_name(branch_prefix: str, remediation_id: int) -> str:
    prefix = (branch_prefix or "fix/pqc-remediation").strip().rstrip("/")
    prefix = re.sub(r"\s+", "-", prefix)
    prefix = prefix[:180].rstrip("/.-") or "fix/pqc-remediation"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}-{int(remediation_id)}-{stamp}-{suffix}"


def build_remediation_commit_message(remediation: Dict[str, Any]) -> str:
    return f"PQC remediation: {remediation.get('asset_key') or ''}".strip() or "PQC remediation"


def build_remediation_pr_title(remediation: Dict[str, Any], requested_title: str = "") -> str:
    title = str(requested_title or "").strip()
    if title:
        return title[:120]
    vulnerability = str(remediation.get("vulnerability") or "").strip()
    title = f"Security Fix: {remediation.get('asset_key') or ''}".strip()
    if vulnerability:
        title = f"{title} ({vulnerability})"
    return title[:120]


def remediation_link_url(remediation_id: int, app_base_url: str = "") -> str:
    base = str(app_base_url or os.getenv("PQC_APP_BASE_URL") or os.getenv("PQC_PUBLIC_APP_URL") or "").strip().rstrip("/")
    return f"{base}/ui/?remediation_id={int(remediation_id)}" if base else ""


def build_remediation_pr_body(
    remediation: Dict[str, Any],
    file_path: str,
    remediation_id: int,
    requested_body: str = "",
    app_base_url: str = "",
) -> str:
    body = str(requested_body or "").strip()
    if not body:
        body = (
            "Automated remediation generated by PQC Scanner.\n\n"
            f"- Asset: {remediation.get('asset_key')}\n"
            f"- Vulnerability: {remediation.get('vulnerability')}\n"
            f"- File: `{file_path}`\n"
        )
    url = remediation_link_url(int(remediation_id), app_base_url=app_base_url)
    if url and "remediation_id=" not in body:
        body = f"{body.rstrip()}\n\nPQC Scanner remediation: {url}\n"
    return body


def resolve_remediation_updated_content(
    remediation: Dict[str, Any],
    latest_validation: Optional[Dict[str, Any]],
    original_content: str,
    apply_diff: Callable[[str, str], str],
) -> str:
    validation_details = (latest_validation or {}).get("details") or {}
    updated_content = str(validation_details.get("normalized_content") or remediation.get("suggested_content") or "")
    if updated_content.strip():
        return updated_content
    diff_text = str(remediation.get("suggested_fix") or "")
    return apply_diff(original_content, diff_text)
