from __future__ import annotations

import os
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from celery import Celery

from db import (
    save_scan_results,
    update_scan_progress,
    update_scan_job,
    load_scan_row,
    save_scan_asset_summaries,
    auto_close_merged_remediations,
    list_assets,
    list_repositories,
    link_asset_repository,
    set_current_organization_id,
    reset_current_organization_id,
    update_validation_job,
    list_organizations,
)
from policy import summarize_results
from events import deliver_events_for_scan, drain_webhook_delivery_queue
from vault_db import get_credential
from integrations.gcp import sync_gcp_assets
from integrations.github import sync_github_repos
from integrations.github_app import sync_github_app_installations, sync_github_app_repositories
from remediation_validation import execute_validation_job
from remediation_drift import check_all_remediation_drift
from remediation_branch_cleanup import cleanup_verified_closed_branches
from observability import capture_exception


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default

def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


_redis_pw = os.getenv("REDIS_PASSWORD", "").strip()
_default_redis_url = "redis://localhost:6379/0" if not _redis_pw else f"redis://:{_redis_pw}@localhost:6379/0"
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", _default_redis_url)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)

celery_app = Celery("pqc", broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

# Reasonable production defaults for reliable async delivery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # Fail fast when the broker is unreachable.
    #
    # By default a .delay() from inside a web request retries the connection for roughly 100
    # seconds before raising, so any endpoint that enqueues work simply hangs when Redis is down —
    # and each hung request holds a worker thread. Measured: POST /scans took 108s, and
    # /remediations/drift/check and /remediations/branches/cleanup never returned at all.
    #
    # A short, bounded retry keeps the durable path intact when a broker exists while letting
    # callers get a prompt error (or take a fallback) when one does not. Applies to every
    # publish site, so new .delay() calls inherit it.
    broker_connection_retry=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=2,
    broker_transport_options={
        "socket_timeout": 2.0,
        "socket_connect_timeout": 2.0,
        "max_retries": 2,
        "interval_start": 0,
        "interval_step": 0.2,
        "interval_max": 0.5,
    },
    result_backend_transport_options={
        "socket_timeout": 2.0,
        "socket_connect_timeout": 2.0,
        "retry_policy": {"timeout": 3.0},
    },
)

# Periodic drain: keeps deliveries flowing even if no scan recently finished
try:
    from celery.schedules import crontab

    _beat = {
        "drain-webhook-queue-every-30s": {
            "task": "pqc.drain_webhook_queue",
            "schedule": 30.0,
            "args": (),
        },
        "check-remediation-drift-every-5m": {
            "task": "pqc.check_remediation_drift",
            "schedule": 300.0,
            "args": (),
        },
        "cleanup-remediation-branches-daily": {
            "task": "pqc.cleanup_remediation_branches",
            "schedule": crontab(minute=45, hour=3),
            "args": (),
        },
    }

    # Optional: daily GitHub repo sync
    _gh_cred = _env_str("GITHUB_SYNC_CREDENTIAL_ID")
    if _gh_cred:
        _gh_org = _env_str("GITHUB_SYNC_ORG", "")
        _gh_vis = _env_str("GITHUB_SYNC_VISIBILITY", "all") or "all"
        try:
            _gh_cred_int = int(_gh_cred)
            _beat["github-sync-daily"] = {
                "task": "pqc.sync_github_repos",
                "schedule": crontab(minute=0, hour=3),  # daily at 03:00 UTC
                "args": (_gh_cred_int, _gh_org or None, _gh_vis),
            }
            _beat["correlate-daily"] = {
                "task": "pqc.correlate_assets",
                "schedule": crontab(minute=15, hour=3),  # shortly after GitHub sync
                "args": (_gh_cred_int, _env_int("CORRELATE_ASSET_LIMIT", 500)),
            }
        except Exception:
            pass

    # Optional: daily GCP asset sync
    _gcp_cred = _env_str("GCP_SYNC_CREDENTIAL_ID")
    if _gcp_cred:
        _gcp_project = _env_str("GCP_SYNC_PROJECT_ID", "") or None
        try:
            _gcp_cred_int = int(_gcp_cred)
            _beat["gcp-sync-daily"] = {
                "task": "pqc.sync_gcp_assets",
                "schedule": crontab(minute=30, hour=3),  # after GitHub/correlate
                "args": (_gcp_cred_int, _gcp_project),
            }
        except Exception:
            pass

    celery_app.conf.beat_schedule = _beat
except Exception:
    pass


def _progress(total: int, done: int) -> Dict[str, int]:
    total = max(0, int(total))
    done = max(0, int(done))
    pct = int((done / total) * 100) if total > 0 else 0
    return {"total": total, "done": done, "percent": max(0, min(100, pct))}


@celery_app.task(name="pqc.drain_webhook_queue")
def drain_webhook_queue_task(limit: int | None = None, max_attempts: int | None = None) -> Dict[str, Any]:
    """Dedicated async worker for webhook delivery.

    - backoff + jitter (via next_attempt_at)
    - per-webhook rate limiting
    - captures http status + response excerpt

    Safe to call frequently; it only processes due rows.
    """
    lim = int(limit or _env_int("PQC_WEBHOOK_DRAIN_LIMIT", 200))
    ma = int(max_attempts or _env_int("PQC_WEBHOOK_MAX_ATTEMPTS", 5))
    return drain_webhook_delivery_queue(limit=lim, max_attempts=ma)


@celery_app.task(bind=True, name="pqc.run_scan_task")
def run_scan_task(self, scan_id: str, targets: List[str], organization_id: str = "") -> Dict[str, Any]:
    """Run a scan (asynchronously) and enqueue webhook deliveries.

    This task intentionally does NOT perform HTTP webhook delivery.
    On completion it enqueues events and triggers the dedicated delivery worker.
    """
    org_token = set_current_organization_id(organization_id)
    try:
        started_iso = _utc_now_iso()
        update_scan_job(scan_id, job_state="STARTED", started_at_iso=started_iso)

        # Lazy imports so unit tests can focus on integrations even without scanner module.
        try:
            from scanner import scan_host, parse_target
        except Exception as e:
            raise RuntimeError(
                "scanner module is not available. Ensure scanner.py is present in your project."  # noqa
            ) from e

        results: List[Dict[str, Any]] = []
        total = len(targets or [])
        done = 0

        update_scan_progress(scan_id, status="running", progress=_progress(total, 0), error_text="")

        for t in targets or []:
            host, port = parse_target(t)
            res = scan_host(host, port)
            results.append(res)
            done += 1
            prog = _progress(total, done)
            update_scan_progress(scan_id, status="running", progress=prog, error_text="")
            save_scan_results(scan_id, results=results, summary={}, status="running")

        summary = summarize_results(results)
        update_scan_progress(scan_id, status="completed", progress=_progress(total, total), error_text="")
        save_scan_results(scan_id, results=results, summary=summary, status="completed")

        # Persist per-asset summaries for history (best-effort).
        #
        # isoformat()+"Z" on a timezone-aware datetime yields "...+00:00Z", which Postgres rejects
        # as invalid timestamptz. SQLite accepted it as text, so this only failed on Postgres — and
        # the bare except hid it, leaving scan_results empty and every report blank.
        try:
            scan = load_scan_row(scan_id) or {}
            ca = scan.get("created_at")
            if hasattr(ca, "isoformat"):
                if ca.tzinfo is None:
                    ca = ca.replace(tzinfo=timezone.utc)
                scanned_at_iso = ca.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            else:
                scanned_at_iso = started_iso or _utc_now_iso()
            save_scan_asset_summaries(scan_id, scanned_at_iso=scanned_at_iso, results=results)
        except Exception:
            logging.exception("[TASK] failed to persist per-asset summaries for %s", scan_id)

        # Verify loop: if a remediation PR was merged and the next scan is clean, auto-close it.
        verify_stats: Dict[str, Any] = {"closed": 0}
        try:
            verify_stats = auto_close_merged_remediations(scan_id, results=results)
        except Exception:
            verify_stats = {"closed": 0}

        # Enqueue deliveries only
        enqueue_stats = deliver_events_for_scan(scan_id)

        # Trigger the dedicated delivery worker (idempotent)
        try:
            drain_webhook_queue_task.delay()
        except Exception:
            # Beat will pick it up anyway.
            pass

        finished_iso = _utc_now_iso()
        update_scan_job(scan_id, job_state="SUCCESS", finished_at_iso=finished_iso)

        return {
            "scan_id": scan_id,
            "targets": total,
            "results": len(results),
            "enqueue": enqueue_stats,
            "verify": verify_stats,
        }
    except Exception as exc:
        capture_exception(exc, {"task": "pqc.run_scan_task", "scan_id": scan_id, "organization_id": organization_id})
        raise
    finally:
        reset_current_organization_id(org_token)


@celery_app.task(name="pqc.sync_gcp_assets")
def sync_gcp_assets_task(credential_id: int, project_id: str | None = None, organization_id: str = "") -> Dict[str, Any]:
    """Background wrapper to sync GCP assets using a Vault-stored service account."""
    token = set_current_organization_id(organization_id)
    try:
        return sync_gcp_assets(credential_id=credential_id, project_id=project_id)
    except Exception as exc:
        capture_exception(
            exc,
            {"task": "pqc.sync_gcp_assets", "credential_id": credential_id, "organization_id": organization_id},
        )
        raise
    finally:
        reset_current_organization_id(token)


@celery_app.task(name="pqc.sync_github_repos")
def sync_github_repos_task(
    credential_id: int,
    org: str | None = None,
    visibility: str = "all",
    organization_id: str = "",
) -> Dict[str, Any]:
    """Background wrapper to sync GitHub repositories using a Vault-stored PAT."""
    token = set_current_organization_id(organization_id)
    try:
        return sync_github_repos(credential_id=credential_id, org=org, visibility=visibility)
    finally:
        reset_current_organization_id(token)


@celery_app.task(name="pqc.sync_github_app_installations")
def sync_github_app_installations_task(credential_id: int, organization_id: str = "") -> Dict[str, Any]:
    token = set_current_organization_id(organization_id)
    try:
        return sync_github_app_installations(credential_id=credential_id)
    finally:
        reset_current_organization_id(token)


@celery_app.task(name="pqc.sync_github_app_repositories")
def sync_github_app_repositories_task(
    credential_id: int,
    installation_id: int,
    organization_id: str = "",
) -> Dict[str, Any]:
    token = set_current_organization_id(organization_id)
    try:
        return sync_github_app_repositories(
            credential_id=credential_id,
            installation_id=installation_id,
        )
    finally:
        reset_current_organization_id(token)


@celery_app.task(bind=True, name="pqc.validate_remediation")
def validate_remediation_task(
    self,
    validation_job_id: int,
    remediation_id: int,
    github_credential_id: int,
    organization_id: str = "",
    git_ref: str = "",
    validator_type: str = "auto",
    timeout_seconds: int = 180,
) -> Dict[str, Any]:
    token = set_current_organization_id(organization_id)
    try:
        update_validation_job(
            int(validation_job_id),
            job_id=str(getattr(self.request, "id", "") or ""),
        )
        return execute_validation_job(
            int(validation_job_id),
            int(remediation_id),
            int(github_credential_id),
            git_ref=str(git_ref or "").strip(),
            validator_type=str(validator_type or "auto").strip().lower() or "auto",
            timeout_seconds=int(timeout_seconds or 180),
        )
    except Exception as exc:
        capture_exception(
            exc,
            {
                "task": "pqc.validate_remediation",
                "validation_job_id": validation_job_id,
                "remediation_id": remediation_id,
                "organization_id": organization_id,
            },
        )
        raise
    finally:
        reset_current_organization_id(token)


@celery_app.task(name="pqc.check_remediation_drift")
def check_remediation_drift_task(
    limit_per_org: int | None = None,
    github_credential_id: int | None = None,
    organization_id: str = "",
    remediation_id: int | None = None,
) -> Dict[str, Any]:
    limit_val = int(limit_per_org or _env_int("PQC_DRIFT_CHECK_LIMIT", 200))
    github_cred_val = int(github_credential_id or _env_int("PQC_GITHUB_DRIFT_CREDENTIAL_ID", 0))
    remediation_id_val = int(remediation_id or 0)
    org_filter = str(organization_id or "").strip()
    orgs = []
    if org_filter:
        orgs = [{"id": org_filter}]
    else:
        orgs = list_organizations(limit=1000) or []

    stats: Dict[str, Any] = {"organizations": 0, "eligible": 0, "checked": 0, "drifted": 0, "failed": 0, "items": []}
    for org in orgs:
        org_id = str((org or {}).get("id") or "").strip()
        if not org_id:
            continue
        token = set_current_organization_id(org_id)
        try:
            if remediation_id_val > 0:
                from remediation_drift import check_remediation_drift

                outcome = check_remediation_drift(remediation_id_val, github_credential_id=github_cred_val)
                res = {
                    "ok": True,
                    "eligible": 1,
                    "checked": 1,
                    "drifted": 1 if str(outcome.get("drift_status") or "") == "drifted" else 0,
                    "failed": 0,
                    "items": [outcome],
                }
            else:
                res = check_all_remediation_drift(limit=limit_val, github_credential_id=github_cred_val)
            stats["organizations"] += 1
            stats["eligible"] += int(res.get("eligible") or 0)
            stats["checked"] += int(res.get("checked") or 0)
            stats["drifted"] += int(res.get("drifted") or 0)
            stats["failed"] += int(res.get("failed") or 0)
            stats["items"].append({"organization_id": org_id, **res})
        finally:
            reset_current_organization_id(token)
    return stats


@celery_app.task(name="pqc.cleanup_remediation_branches")
def cleanup_remediation_branches_task(
    limit_per_org: int | None = None,
    github_credential_id: int | None = None,
    organization_id: str = "",
) -> Dict[str, Any]:
    limit_val = int(limit_per_org or _env_int("PQC_BRANCH_CLEANUP_LIMIT", 100))
    github_cred_val = int(github_credential_id or 0)
    org_filter = str(organization_id or "").strip()
    orgs = [{"id": org_filter}] if org_filter else (list_organizations(limit=1000) or [])

    stats: Dict[str, Any] = {"organizations": 0, "checked": 0, "processed": 0, "deleted": 0, "failed": 0, "items": []}
    for org in orgs:
        org_id = str((org or {}).get("id") or "").strip()
        if not org_id:
            continue
        token = set_current_organization_id(org_id)
        try:
            res = cleanup_verified_closed_branches(limit=limit_val, github_credential_id=github_cred_val)
            stats["organizations"] += 1
            stats["checked"] += int(res.get("checked") or 0)
            stats["processed"] += int(res.get("processed") or 0)
            stats["deleted"] += int(res.get("deleted") or 0)
            stats["failed"] += int(res.get("failed") or 0)
            stats["items"].append({"organization_id": org_id, **res})
        finally:
            reset_current_organization_id(token)
    return stats


_IAC_EXTS = ("tf", "tfvars", "yaml", "yml", "json")
_TFSTATE_EXT = "tfstate"


def _is_hex(s: str) -> bool:
    if not s:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{4,}", s))


def _strip_random_suffix(name: str) -> str:
    parts = name.split("-")
    if len(parts) > 1 and _is_hex(parts[-1]):
        return "-".join(parts[:-1])
    return name


def _normalize_candidate(name: str) -> str:
    # Handle DNS names by only normalizing the first label
    if "." in name:
        labels = name.split(".")
        labels[0] = _strip_random_suffix(labels[0])
        return ".".join(labels)
    return _strip_random_suffix(name)


def _candidate_variants(asset_key: str) -> List[str]:
    """Generate safer candidate strings for matching."""
    out: List[str] = []
    ak = (asset_key or "").strip()
    if not ak:
        return out
    out.append(ak)
    if ":" in ak:
        host = ak.split(":", 1)[0]
        if host and host not in out:
            out.append(host)
    norm = _normalize_candidate(out[-1]) if out else _normalize_candidate(ak)
    if norm and norm not in out:
        out.append(norm)
    return out


def _strip_comments(text: str, ext: str) -> str:
    if not text:
        return ""
    s = text
    if ext in ("tf", "tfvars"):
        # strip /* ... */ blocks
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
        lines = []
        for line in s.splitlines():
            raw = line
            # remove full-line comments
            if raw.lstrip().startswith("#") or raw.lstrip().startswith("//"):
                continue
            # remove inline comments if not inside quotes
            cut = len(raw)
            for marker in ("//", "#"):
                idx = raw.find(marker)
                if idx == -1:
                    continue
                prefix = raw[:idx]
                if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                    cut = min(cut, idx)
            lines.append(raw[:cut])
        return "\n".join(lines)
    if ext in ("yaml", "yml"):
        lines = []
        for line in s.splitlines():
            raw = line
            if raw.lstrip().startswith("#"):
                continue
            idx = raw.find("#")
            if idx != -1:
                prefix = raw[:idx]
                if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                    raw = raw[:idx]
            lines.append(raw)
        return "\n".join(lines)
    # json: no comments
    return s


def _file_contains_candidate(text: str, candidate: str, ext: str) -> bool:
    if not text or not candidate:
        return False
    cleaned = _strip_comments(text, ext)
    return candidate.lower() in cleaned.lower()


def _read_repo_file(repo, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
    try:
        cf = repo.get_contents(path)
        if isinstance(cf, list):
            return None
        if getattr(cf, "size", 0) > max_bytes:
            return None
        data = cf.decoded_content
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="ignore")
        return str(data)
    except Exception:
        return None


def _file_ext(path: str) -> str:
    _, ext = os.path.splitext(path or "")
    return ext.lstrip(".").lower()


def _iter_repo_files(repo, max_files: int = 400, max_depth: int = 6) -> List[str]:
    """Best-effort file listing for small repos; avoids reliance on code search indexing."""
    files: List[str] = []
    queue: List[tuple[str, int]] = [("", 0)]
    seen = set()
    while queue and len(files) < max_files:
        path, depth = queue.pop(0)
        if (path, depth) in seen:
            continue
        seen.add((path, depth))
        try:
            items = repo.get_contents(path)
        except Exception:
            continue
        if not isinstance(items, list):
            items = [items]
        for it in items:
            if len(files) >= max_files:
                break
            it_type = getattr(it, "type", "")
            it_path = getattr(it, "path", "")
            if it_type == "dir" and depth < max_depth:
                queue.append((it_path, depth + 1))
            elif it_type == "file":
                ext = _file_ext(it_path)
                if ext in _IAC_EXTS or ext == _TFSTATE_EXT:
                    files.append(it_path)
    return files


def _deep_scan_repo(repo, candidates: List[str]) -> bool:
    max_files = _env_int("CORRELATE_DEEP_SCAN_MAX_FILES", 400)
    max_depth = _env_int("CORRELATE_DEEP_SCAN_MAX_DEPTH", 6)
    paths = _iter_repo_files(repo, max_files=max_files, max_depth=max_depth)
    if not paths:
        return False
    for p in paths:
        ext = _file_ext(p)
        text = _read_repo_file(repo, p, max_bytes=2_000_000 if ext == _TFSTATE_EXT else 1_000_000)
        if not text:
            continue
        if ext == _TFSTATE_EXT:
            try:
                data = json.loads(text)
            except Exception:
                continue
            flat = _iter_tfstate_strings(data)
            for cand in candidates:
                for s in flat:
                    if cand.lower() in s.lower():
                        return True
            continue
        for cand in candidates:
            if _file_contains_candidate(text, cand, ext):
                return True
    return False


def _should_deep_scan(repo) -> bool:
    if _env_str("CORRELATE_DEEP_SCAN", "").lower() in ("1", "true", "yes"):
        return True
    try:
        # repo.size is KB
        max_kb = _env_int("CORRELATE_DEEP_SCAN_MAX_KB", 5000)
        return int(getattr(repo, "size", 0)) <= max_kb
    except Exception:
        return False


def _search_repo_iac(gh, repo, candidate: str) -> bool:
    repo_name = repo.full_name
    for ext in _IAC_EXTS:
        try:
            q = f"\"{candidate}\" repo:{repo_name} extension:{ext}"
            results = gh.search_code(query=q)
            checked = 0
            for r in results:
                checked += 1
                if checked > 10:
                    break
                text = _read_repo_file(repo, r.path)
                if _file_contains_candidate(text or "", candidate, ext):
                    return True
        except Exception:
            continue
    return False


def _iter_tfstate_strings(obj: Any) -> List[str]:
    out: List[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_iter_tfstate_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_iter_tfstate_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _search_repo_tfstate(gh, repo, candidate: str) -> bool:
    repo_name = repo.full_name
    try:
        q = f"\"{candidate}\" repo:{repo_name} extension:tfstate"
        results = gh.search_code(query=q)
        checked = 0
        for r in results:
            checked += 1
            if checked > 5:
                break
            text = _read_repo_file(repo, r.path, max_bytes=2_000_000)
            if not text:
                continue
            try:
                data = json.loads(text)
            except Exception:
                continue
            for s in _iter_tfstate_strings(data):
                if candidate.lower() in s.lower():
                    return True
    except Exception:
        return False
    return False


@celery_app.task(name="pqc.correlate_assets")
def correlate_assets(credential_id: int, asset_limit: int = 500, organization_id: str = "") -> Dict[str, Any]:
    """
    Heuristic matcher: map discovered assets to repositories by searching code for asset names.
    The credential_id should reference a GitHub PAT stored in the Vault.
    """
    token_ctx = set_current_organization_id(organization_id)
    try:
        try:
            from github import Github
        except Exception as e:
            return {"ok": False, "error": f"PyGithub missing: {e}"}

        cred = get_credential(int(credential_id), reveal=True)
        if not cred:
            return {"ok": False, "error": "credential not found"}

        token = cred.get("secret") or ""
        gh = Github(token)

        repos = list_repositories(limit=2000)
        assets = list_assets(limit=asset_limit)

        linked = 0
        checked = 0
        errors: List[str] = []

        for a in assets:
            checked += 1
            ak = a.get("asset_key") or ""
            if not ak:
                continue
            candidates = _candidate_variants(ak)
            for repo in repos:
                try:
                    repo_obj = gh.get_repo(repo["name"])
                except Exception:
                    continue
                matched = False
                for cand in candidates:
                    if _search_repo_iac(gh, repo_obj, cand):
                        matched = True
                        break
                    # Optional tfstate parsing for harder cases
                    if _search_repo_tfstate(gh, repo_obj, cand):
                        matched = True
                        break
                if not matched and _should_deep_scan(repo_obj):
                    if _deep_scan_repo(repo_obj, candidates):
                        matched = True
                if matched:
                    link_asset_repository(ak, repo.get("id"))
                    linked += 1
                    break  # next asset

        return {
            "ok": len(errors) == 0,
            "assets_checked": checked,
            "linked": linked,
            "errors": errors,
        }
    finally:
        reset_current_organization_id(token_ctx)
