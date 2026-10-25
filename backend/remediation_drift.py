from __future__ import annotations

import base64
import difflib
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db import (
    append_audit_log,
    create_remediation,
    get_latest_validation_job_for_remediation,
    get_remediation,
    get_repository_by_id,
    list_remediations,
    set_remediation_drift_followup,
    update_remediation_drift_state,
)
from integrations.github_app import resolve_github_repo_token
from vault_db import list_credentials


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _github_api(method: str, url: str, token: str, timeout_s: int = 30) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pq-remediation-drift",
    }
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {}
            return {"ok": True, "http_status": int(getattr(resp, "status", 200) or 200), "json": payload, "raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        return {"ok": False, "http_status": int(getattr(e, "code", 0) or 0), "json": payload, "raw": raw}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _safe_relative_path(file_path: str) -> str:
    normalized = str(file_path or "").replace("\\", "/").strip().lstrip("/")
    if not normalized:
        raise RuntimeError("remediation file_path is empty")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise RuntimeError("remediation file_path is unsafe")
    return "/".join(parts)


def _normalize_content(text: str) -> str:
    s = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not s:
        return ""
    return s.rstrip("\n") + "\n"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(_normalize_content(text).encode("utf-8", errors="ignore")).hexdigest()


def _build_unified_diff(file_path: str, before_text: str, after_text: str) -> str:
    before_lines = _normalize_content(before_text).splitlines(keepends=True)
    after_lines = _normalize_content(after_text).splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=str(file_path or "before"),
            tofile=str(file_path or "after"),
        )
    ).strip()


def _github_get_file(owner: str, repo: str, file_path: str, git_ref: str, token: str) -> Dict[str, Any]:
    repo_path = f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
    path_part = "/".join(urllib.parse.quote(part, safe="") for part in _safe_relative_path(file_path).split("/"))
    url = f"https://api.github.com/repos/{repo_path}/contents/{path_part}"
    if str(git_ref or "").strip():
        url += f"?ref={urllib.parse.quote(str(git_ref or '').strip(), safe='')}"
    r = _github_api("GET", url, token)
    if not r.get("ok"):
        return r
    payload = r.get("json") or {}
    content_b64 = str(payload.get("content") or "")
    encoding = str(payload.get("encoding") or "").strip().lower()
    decoded = ""
    if content_b64 and encoding == "base64":
        try:
            decoded = base64.b64decode(content_b64.encode("utf-8"), validate=False).decode("utf-8")
        except Exception as e:
            return {"ok": False, "error": f"failed to decode GitHub content: {e}", "github": r}
    else:
        decoded = str(content_b64 or "")
    return {
        "ok": True,
        "content": decoded,
        "sha": str(payload.get("sha") or "").strip(),
        "ref": str(git_ref or "").strip(),
        "github": r,
    }


def _credential_candidates(preferred_credential_id: int = 0) -> List[int]:
    seen: set[int] = set()
    out: List[int] = []
    if int(preferred_credential_id or 0) > 0:
        out.append(int(preferred_credential_id))
        seen.add(int(preferred_credential_id))
    try:
        creds = list_credentials() or []
    except Exception:
        creds = []
    for provider in ("github_app", "github"):
        for row in creds:
            try:
                cred_id = int(row.get("id") or 0)
            except Exception:
                continue
            if cred_id < 1 or cred_id in seen:
                continue
            if str(row.get("provider") or "").strip().lower() != provider:
                continue
            seen.add(cred_id)
            out.append(cred_id)
    return out


def _resolve_repo_token(repo_name: str, preferred_credential_id: int = 0) -> Tuple[int, str]:
    last_error = ""
    for cred_id in _credential_candidates(preferred_credential_id):
        resolved = resolve_github_repo_token(int(cred_id), repo_name)
        if resolved.get("ok"):
            token = str(resolved.get("token") or "").strip()
            if token:
                return int(cred_id), token
            last_error = "resolved token was empty"
            continue
        last_error = str(resolved.get("error") or resolved)
    raise RuntimeError(last_error or "no GitHub credential could access repository")


def _expected_content_for_remediation(remediation: Dict[str, Any]) -> Tuple[str, str]:
    remediation_id = int(remediation.get("id") or 0)
    latest_validation = get_latest_validation_job_for_remediation(remediation_id, passed_only=True) or {}
    details = latest_validation.get("details") or {}
    normalized = str(details.get("normalized_content") or "")
    git_ref = str(latest_validation.get("git_ref") or details.get("git_ref") or "main").strip() or "main"
    if normalized:
        return normalized, git_ref
    return str(remediation.get("suggested_content") or ""), git_ref


def _drift_event_payload(remediation: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "remediation_id": int(remediation.get("id") or 0),
        "asset_key": str(remediation.get("asset_key") or "").strip(),
        "repo_id": int(remediation.get("repo_id") or 0),
        "repository": str(remediation.get("repository_name") or "").strip(),
        "file_path": str(remediation.get("file_path") or "").strip(),
        "status": str(remediation.get("status") or "").strip().lower(),
        "pr_url": str(remediation.get("pr_url") or "").strip(),
        "drift_status": "drifted",
        "drift_details": details,
    }


def _open_followup_for_parent(parent_remediation_id: int) -> Optional[Dict[str, Any]]:
    rows = list_remediations(
        parent_remediation_id=int(parent_remediation_id or 0),
        origin_kind="drift_followup",
        limit=50,
    )
    for row in rows:
        status = str(row.get("status") or "").strip().lower()
        if status not in ("verified_closed", "rejected"):
            return row
    return None


def _create_drift_followup(
    remediation: Dict[str, Any],
    current_content: str,
    expected_content: str,
    details: Dict[str, Any],
) -> Dict[str, Any]:
    existing = _open_followup_for_parent(int(remediation.get("id") or 0))
    if existing:
        return existing
    file_path = str(remediation.get("file_path") or "").strip()
    suggested_fix = _build_unified_diff(file_path, current_content, expected_content)
    if not suggested_fix:
        suggested_fix = f"Restore validated content for {file_path}"
    followup = create_remediation(
        str(remediation.get("asset_key") or "").strip(),
        int(remediation.get("repo_id") or 0),
        file_path,
        str(remediation.get("vulnerability") or "").strip(),
        suggested_fix,
        original_content=current_content,
        suggested_content=expected_content,
        status="pending",
        review_note=f"Auto-created from drift on remediation #{int(remediation.get('id') or 0)}",
        parent_remediation_id=int(remediation.get("id") or 0),
        origin_kind="drift_followup",
    )
    set_remediation_drift_followup(int(remediation.get("id") or 0), int(followup.get("id") or 0))
    append_audit_log(
        actor_id="pq-drift",
        actor_role="system",
        action="remediation.drift_followup_created",
        resource_type="remediation",
        resource_id=str(followup.get("id") or ""),
        decision="allow",
        reason="auto-created follow-up remediation for detected drift",
        details={
            "parent_remediation_id": int(remediation.get("id") or 0),
            "file_path": file_path,
            "repository": str(remediation.get("repository_name") or "").strip(),
            "current_sha256": details.get("current_sha256"),
            "expected_sha256": details.get("expected_sha256"),
        },
    )
    try:
        from events import emit_platform_event

        emit_platform_event(
            "remediation.drift_followup_created",
            {
                "remediation_id": int(remediation.get("id") or 0),
                "followup_remediation_id": int(followup.get("id") or 0),
                "asset_key": str(remediation.get("asset_key") or "").strip(),
                "repository": str(remediation.get("repository_name") or "").strip(),
                "file_path": file_path,
                "status": "pending",
                "drift_details": details,
            },
            dedupe_key=hashlib.sha256(
                f"remediation.drift_followup_created:{int(remediation.get('id') or 0)}:{details.get('current_sha256')}".encode("utf-8")
            ).hexdigest(),
        )
    except Exception:
        pass
    return followup


def check_remediation_drift(remediation_id: int, github_credential_id: int = 0) -> Dict[str, Any]:
    remediation = get_remediation(int(remediation_id)) or {}
    if not remediation:
        raise RuntimeError("remediation not found")

    status = str(remediation.get("status") or "").strip().lower()
    if status not in ("merged", "verified_closed"):
        raise RuntimeError("remediation is not eligible for drift checks")

    repo_id = int(remediation.get("repo_id") or 0)
    repo_row = get_repository_by_id(repo_id) if repo_id else None
    if not repo_row:
        raise RuntimeError("repository not found for remediation")
    repo_name = str(repo_row.get("name") or "").strip()
    if "/" not in repo_name:
        raise RuntimeError("repository name must be owner/repo")
    owner, repo = repo_name.split("/", 1)

    expected_content, git_ref = _expected_content_for_remediation(remediation)
    if not str(expected_content or "").strip():
        raise RuntimeError("remediation has no expected content for drift comparison")

    checked_at = _utc_now_iso()
    previous_status = str(remediation.get("drift_status") or "").strip().lower()
    cred_id, token = _resolve_repo_token(repo_name, preferred_credential_id=int(github_credential_id or 0))
    current = _github_get_file(owner, repo, str(remediation.get("file_path") or ""), git_ref, token)
    if not current.get("ok"):
        raise RuntimeError(f"failed to fetch repository file: {current}")

    current_content = str(current.get("content") or "")
    expected_hash = _sha256_text(expected_content)
    current_hash = _sha256_text(current_content)
    drifted = _normalize_content(expected_content) != _normalize_content(current_content)
    drift_status = "drifted" if drifted else "clean"
    details = {
        "repository": repo_name,
        "file_path": str(remediation.get("file_path") or "").strip(),
        "git_ref": git_ref,
        "credential_id": int(cred_id),
        "github_sha": str(current.get("sha") or "").strip(),
        "expected_sha256": expected_hash,
        "current_sha256": current_hash,
    }
    updated = update_remediation_drift_state(
        int(remediation_id),
        drift_status,
        details=details,
        checked_at_iso=checked_at,
        detected_at_iso=checked_at if drifted else "",
    ) or {"id": int(remediation_id), "drift_status": drift_status}

    followup: Dict[str, Any] | None = None

    if drifted:
        followup = _create_drift_followup(remediation, current_content=current_content, expected_content=expected_content, details=details)
        if followup:
            updated = get_remediation(int(remediation_id)) or updated

    if drifted and previous_status != "drifted":
        append_audit_log(
            actor_id="pq-drift",
            actor_role="system",
            action="remediation.drifted",
            resource_type="remediation",
            resource_id=str(remediation_id),
            decision="allow",
            reason="repository content diverged from validated remediation output",
            details=details,
        )
        try:
            from events import emit_platform_event

            emit_platform_event(
                "remediation.drifted",
                _drift_event_payload(updated, details),
                dedupe_key=hashlib.sha256(f"remediation.drifted:{remediation_id}:{current_hash}".encode("utf-8")).hexdigest(),
            )
        except Exception:
            pass
    elif (not drifted) and previous_status == "drifted":
        append_audit_log(
            actor_id="pq-drift",
            actor_role="system",
            action="remediation.drift_cleared",
            resource_type="remediation",
            resource_id=str(remediation_id),
            decision="allow",
            reason="repository content matches validated remediation output again",
            details=details,
        )
    return {
        "ok": True,
        "remediation_id": int(remediation_id),
        "drift_status": drift_status,
        "previous_status": previous_status,
        "details": details,
        "followup_remediation_id": int((followup or {}).get("id") or updated.get("drift_followup_remediation_id") or 0),
        "remediation": updated,
    }


def check_all_remediation_drift(limit: int = 200, github_credential_id: int = 0) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 200), 2000))
    merged = list_remediations(status="merged", limit=limit)
    verified = list_remediations(status="verified_closed", limit=limit)
    rows: List[Dict[str, Any]] = []
    seen: set[int] = set()
    for row in merged + verified:
        rid = int(row.get("id") or 0)
        if rid < 1 or rid in seen:
            continue
        seen.add(rid)
        rows.append(row)

    checked = 0
    drifted = 0
    failed = 0
    results: List[Dict[str, Any]] = []
    for row in rows:
        rid = int(row.get("id") or 0)
        try:
            outcome = check_remediation_drift(rid, github_credential_id=int(github_credential_id or 0))
            checked += 1
            if str(outcome.get("drift_status") or "") == "drifted":
                drifted += 1
            results.append({
                "remediation_id": rid,
                "drift_status": outcome.get("drift_status"),
            })
        except Exception as e:
            failed += 1
            checked_at = _utc_now_iso()
            update_remediation_drift_state(
                rid,
                "check_failed",
                details={"error": str(e)},
                checked_at_iso=checked_at,
            )
            results.append({
                "remediation_id": rid,
                "drift_status": "check_failed",
                "error": str(e),
            })
            append_audit_log(
                actor_id="pq-drift",
                actor_role="system",
                action="remediation.drift_check_failed",
                resource_type="remediation",
                resource_id=str(rid),
                decision="deny",
                reason=str(e),
                details={"checked_at": checked_at},
            )
    return {
        "ok": True,
        "eligible": len(rows),
        "checked": checked,
        "drifted": drifted,
        "failed": failed,
        "items": results,
    }
