from typing import Any, Dict, Iterable, List, Optional


CLOSED_REMEDIATION_STATUSES = {"rejected", "verified_closed"}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _risk_label(remediation: Dict[str, Any]) -> str:
    haystack = " ".join(
        [
            _text(remediation.get("vulnerability")),
            _text(remediation.get("suggested_fix")),
            _text(remediation.get("review_note")),
        ]
    ).lower()
    for label in ("critical", "high", "medium", "low"):
        if label in haystack:
            return label
    return "unknown"


def _risk_priority(label: str) -> int:
    return {"critical": 95, "high": 85, "medium": 65, "low": 40}.get(str(label or "").lower(), 55)


def _validation_state(validation: Optional[Dict[str, Any]]) -> str:
    if not validation:
        return "missing"
    return _text(validation.get("status")).lower() or "unknown"


def _remediation_column(status: str, validation_state: str, drift_status: str, pr_url: str) -> str:
    if drift_status and drift_status not in {"clean", "none"}:
        return "verified_drift"
    if status in {"pending", "candidate", "suggested"}:
        return "candidates"
    if status in {"approved"}:
        return "pull_request" if validation_state == "passed" else "validate"
    if status in {"validation_failed", "failed_validation"}:
        return "validate"
    if status in {"pr_created", "pr_open"} or pr_url:
        return "pull_request"
    if status in {"merged", "verified_closed"}:
        return "verified_drift"
    if status == "rejected":
        return "closed"
    return "review"


def _remediation_next_action(status: str, validation_state: str, column: str, pr_url: str) -> str:
    if column == "candidates":
        return "approve"
    if column == "validate":
        return "validate"
    if column == "pull_request":
        if pr_url or status in {"pr_created", "pr_open"}:
            return "track_pr"
        return "create_pr" if validation_state == "passed" else "validate"
    if column == "verified_drift":
        return "drift_check"
    if column == "closed":
        return "review_closed"
    return "review"


def _remediation_action_url(remediation_id: int, next_action: str) -> str:
    if next_action == "approve":
        return f"/remediations/{remediation_id}/approve"
    if next_action == "validate":
        return f"/remediations/{remediation_id}/validate"
    if next_action == "create_pr":
        return f"/remediations/{remediation_id}/create-pr"
    if next_action == "drift_check":
        return f"/remediations/{remediation_id}/drift/check"
    return f"/remediations/{remediation_id}"


def build_remediation_card(remediation: Dict[str, Any], validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    remediation_id = _as_int(remediation.get("id"))
    status = _text(remediation.get("status")).lower() or "pending"
    drift_status = _text(remediation.get("drift_status")).lower()
    pr_url = _text(remediation.get("pr_url"))
    validation_status = _validation_state(validation)
    column = _remediation_column(status, validation_status, drift_status, pr_url)
    next_action = _remediation_next_action(status, validation_status, column, pr_url)
    risk_label = _risk_label(remediation)
    blocked = next_action == "create_pr" and validation_status != "passed"
    if status in {"rejected"}:
        blocked = True
    blockers: List[str] = []
    if blocked and validation_status != "passed":
        blockers.append("latest validation has not passed")
    if status == "rejected":
        blockers.append("remediation was rejected")

    return {
        "id": f"remediation:{remediation_id}",
        "source_id": remediation_id,
        "kind": "remediation",
        "title": _text(remediation.get("vulnerability")) or f"Remediation {remediation_id}",
        "asset_key": _text(remediation.get("asset_key")),
        "repository": _text(remediation.get("repository_name")),
        "repo_id": _as_int(remediation.get("repo_id")),
        "file_path": _text(remediation.get("file_path")),
        "status": status,
        "column": column,
        "priority": _risk_priority(risk_label),
        "risk_label": risk_label,
        "next_action": next_action,
        "action_url": _remediation_action_url(remediation_id, next_action),
        "safe_to_apply": next_action in {"approve", "validate", "create_pr"} and not blocked,
        "blocked": blocked,
        "blockers": blockers,
        "validation_status": validation_status,
        "pr_url": pr_url,
        "drift_status": drift_status or "none",
        "created_at": _text(remediation.get("created_at")),
        "updated_at": _text(remediation.get("updated_at")),
    }


def _migration_next_action(status: str) -> str:
    if status in {"open", "planned"}:
        return "plan_migration"
    if status == "in_progress":
        return "continue_migration"
    if status == "done":
        return "review_acceptance"
    if status == "accepted_risk":
        return "accepted_risk"
    return "review"


def build_migration_task_card(task: Dict[str, Any]) -> Dict[str, Any]:
    task_id = _as_int(task.get("id"))
    status = _text(task.get("status")).lower() or "open"
    next_action = _migration_next_action(status)
    confidence = _text(task.get("confidence")).lower() or "medium"
    priority = {"high": 80, "medium": 60, "low": 35}.get(confidence, 60)
    return {
        "id": f"migration_task:{task_id}",
        "source_id": task_id,
        "kind": "migration_task",
        "title": _text(task.get("legacy_dependency")) or _text(task.get("rule_id")) or f"Migration task {task_id}",
        "asset_key": _text(task.get("asset_key")),
        "repository": _text(task.get("repository_name")),
        "repo_id": _as_int(task.get("repo_id")),
        "file_path": _text(task.get("file_path")),
        "status": status,
        "column": "migration_tasks",
        "priority": priority,
        "risk_label": "medium" if confidence == "medium" else confidence,
        "next_action": next_action,
        "action_url": f"/migration-tasks/{task_id}",
        "safe_to_apply": False,
        "blocked": status == "accepted_risk",
        "blockers": ["risk accepted; no active migration action"] if status == "accepted_risk" else [],
        "migration_target": _text(task.get("migration_target")),
        "safety_class": _text(task.get("safety_class")) or "migration_task",
        "confidence": confidence,
        "created_at": _text(task.get("created_at")),
        "updated_at": _text(task.get("updated_at")),
    }


def _matches(value: str, requested: str) -> bool:
    if not requested:
        return True
    return requested.lower() in value.lower()


def filter_cards(
    cards: Iterable[Dict[str, Any]],
    *,
    include_closed: bool = False,
    asset_key: str = "",
    repository: str = "",
    kind: str = "",
) -> List[Dict[str, Any]]:
    clean_kind = _text(kind).lower()
    out: List[Dict[str, Any]] = []
    for card in cards:
        if clean_kind and _text(card.get("kind")).lower() != clean_kind:
            continue
        if not include_closed and _text(card.get("column")).lower() == "closed":
            continue
        if not _matches(_text(card.get("asset_key")), _text(asset_key)):
            continue
        if not _matches(_text(card.get("repository")), _text(repository)):
            continue
        out.append(card)
    return out


def summarize_feed(cards: List[Dict[str, Any]]) -> Dict[str, Any]:
    columns: Dict[str, int] = {}
    for card in cards:
        column = _text(card.get("column")) or "unknown"
        columns[column] = columns.get(column, 0) + 1
    return {
        "total": len(cards),
        "columns": columns,
        "safe_to_apply": sum(1 for c in cards if c.get("safe_to_apply") is True),
        "blocked": sum(1 for c in cards if c.get("blocked") is True),
        "high_priority": sum(1 for c in cards if _as_int(c.get("priority")) >= 80),
    }
