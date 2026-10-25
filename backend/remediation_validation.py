from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from db import (
    append_audit_log,
    get_remediation,
    get_repository_by_id,
    update_validation_job,
)
from integrations.github_app import resolve_github_repo_token
from iac_security import evaluate_iac_security_content

VALIDATION_ISOLATION_MODE = str(os.getenv("MORROW_VALIDATION_ISOLATION_MODE", "workspace") or "workspace").strip().lower()
# OpenTofu by default: Terraform's BUSL-1.1 licence bars redistribution, and the published image
# must stay open source. Both CLIs take the same arguments, so an operator may point this at
# hashicorp/terraform instead if their own licence position allows it.
VALIDATION_DOCKER_IMAGE = str(os.getenv("MORROW_VALIDATION_DOCKER_IMAGE", "ghcr.io/opentofu/opentofu:1.8.6") or "").strip()
VALIDATION_DOCKER_CPUS = str(os.getenv("MORROW_VALIDATION_DOCKER_CPUS", "1") or "1").strip()
VALIDATION_DOCKER_MEMORY = str(os.getenv("MORROW_VALIDATION_DOCKER_MEMORY", "512m") or "512m").strip()
VALIDATION_TIMEOUT_MAX_SECONDS = int(os.getenv("MORROW_VALIDATION_TIMEOUT_MAX_SECONDS", "900") or "900")
VALIDATION_STDOUT_LIMIT = int(os.getenv("MORROW_VALIDATION_STDOUT_LIMIT", "20000") or "20000")


def validation_sandbox_profile() -> Dict[str, Any]:
    isolation_mode = VALIDATION_ISOLATION_MODE if VALIDATION_ISOLATION_MODE in ("workspace", "docker") else "workspace"
    docker_available = bool(shutil.which("docker"))
    return {
        "isolation_mode": isolation_mode,
        "docker_mode_available": docker_available,
        "docker_image": VALIDATION_DOCKER_IMAGE if isolation_mode == "docker" else "",
        "docker_cpus": VALIDATION_DOCKER_CPUS if isolation_mode == "docker" else "",
        "docker_memory": VALIDATION_DOCKER_MEMORY if isolation_mode == "docker" else "",
        "timeout_max_seconds": VALIDATION_TIMEOUT_MAX_SECONDS,
        "stdout_limit": VALIDATION_STDOUT_LIMIT,
        "network": "none" if isolation_mode == "docker" else "host",
        "environment_scrubbed": True,
        "archive_path_traversal_protection": True,
        "file_path_traversal_protection": True,
        "secrets_exposed_to_subprocess": False,
        "security_boundary": "per-job docker container" if isolation_mode == "docker" else "temporary workspace inside worker container",
        "production_recommendation": "docker mode with --network none is recommended for production validation",
    }


def validation_evidence_package(job: Dict[str, Any]) -> Dict[str, Any]:
    details = job.get("details") if isinstance(job.get("details"), dict) else {}
    sandbox = details.get("sandbox_profile") or details.get("validation_environment") or validation_sandbox_profile()
    return {
        "validation_job_id": int(job.get("id") or 0),
        "remediation_id": int(job.get("remediation_id") or 0),
        "status": str(job.get("status") or ""),
        "validator_type": str(job.get("validator_type") or ""),
        "git_ref": str(job.get("git_ref") or ""),
        "exit_code": int(job.get("exit_code") or 0),
        "created_at": str(job.get("created_at") or ""),
        "updated_at": str(job.get("updated_at") or ""),
        "finished_at": str(job.get("finished_at") or ""),
        "sandbox": sandbox,
        "commands": details.get("commands") or [],
        "iac_security": details.get("iac_security") or {},
        "evidence": {
            "secrets_scrubbed": bool((details.get("validation_environment") or {}).get("secrets_env_scrubbed", True)),
            "path_traversal_checked": True,
            "archive_extraction_checked": True,
            "timeout_enforced": True,
            "stdout_stderr_captured": True,
        },
    }


def _github_api(method: str, url: str, token: str, body: Optional[Dict[str, Any]] = None, timeout_s: int = 30) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pq-remediation-validator",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=data, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                payload = None
            return {"ok": True, "http_status": int(getattr(resp, "status", 200) or 200), "json": payload, "raw_bytes": raw}
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = None
        return {"ok": False, "http_status": int(getattr(e, "code", 0) or 0), "json": payload, "raw_bytes": raw}
    except Exception as e:
        return {"ok": False, "error": str(e), "raw_bytes": b""}


def _repo_default_branch(owner: str, repo: str, token: str) -> str:
    r = _github_api("GET", f"https://api.github.com/repos/{owner}/{repo}", token)
    if not r.get("ok"):
        raise RuntimeError(f"failed to fetch repo metadata: {r}")
    meta = r.get("json") or {}
    return str(meta.get("default_branch") or "main").strip() or "main"


def _download_repo_archive(owner: str, repo: str, git_ref: str, token: str, temp_dir: str) -> str:
    r = _github_api("GET", f"https://api.github.com/repos/{owner}/{repo}/zipball/{git_ref}", token, timeout_s=60)
    if not r.get("ok"):
        raise RuntimeError(f"failed to download repo archive: {r}")
    raw = r.get("raw_bytes") or b""
    if not raw:
        raise RuntimeError("empty repository archive response")

    archive_root = ""
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        _safe_extract_zip(zf, temp_dir)
        names = [n for n in zf.namelist() if n and not n.endswith("/")]
        if not names:
            raise RuntimeError("repository archive did not contain files")
        archive_root = names[0].split("/", 1)[0]
    repo_root = os.path.join(temp_dir, archive_root)
    if not os.path.isdir(repo_root):
        raise RuntimeError("failed to extract repository archive")
    return repo_root


def _safe_extract_zip(zf: zipfile.ZipFile, temp_dir: str) -> None:
    temp_root = Path(temp_dir).resolve()
    for member in zf.infolist():
        member_name = str(member.filename or "").replace("\\", "/")
        if not member_name or member_name.startswith("/") or "\x00" in member_name:
            raise RuntimeError("repository archive contains an unsafe path")
        target = (temp_root / member_name).resolve()
        if temp_root != target and temp_root not in target.parents:
            raise RuntimeError("repository archive contains path traversal")
    zf.extractall(temp_dir)


def _safe_relative_path(file_path: str) -> str:
    normalized = str(file_path or "").replace("\\", "/").strip().lstrip("/")
    if not normalized:
        raise RuntimeError("remediation file_path is empty")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise RuntimeError("remediation file_path is unsafe")
    return "/".join(parts)


def _detect_validator(file_path: str, requested: str) -> str:
    requested = str(requested or "auto").strip().lower() or "auto"
    if requested != "auto":
        return requested
    suffix = Path(file_path).suffix.lower()
    if suffix in (".tf", ".tfvars", ".hcl"):
        return "terraform"
    return "generic"


def _minimal_validation_env() -> Dict[str, str]:
    env: Dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tempfile.gettempdir(),
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    # Windows subprocesses need these system variables to launch reliably.
    for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _run_command(cmd: List[str], cwd: str, timeout_s: int) -> Dict[str, Any]:
    timeout = max(10, min(int(timeout_s or 180), VALIDATION_TIMEOUT_MAX_SECONDS))
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=_minimal_validation_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "cwd": cwd,
            "exit_code": int(proc.returncode),
            "stdout": (proc.stdout or "")[:VALIDATION_STDOUT_LIMIT],
            "stderr": (proc.stderr or "")[:VALIDATION_STDOUT_LIMIT],
            "timeout_seconds": timeout,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "cwd": cwd,
            "exit_code": 124,
            "stdout": str(exc.stdout or "")[:VALIDATION_STDOUT_LIMIT],
            "stderr": f"validation command timed out after {timeout} seconds",
            "timeout_seconds": timeout,
            "timed_out": True,
        }


def _image_entrypoint() -> str:
    """The CLI name inside VALIDATION_DOCKER_IMAGE: OpenTofu ships "tofu", Terraform ships "terraform"."""
    return "terraform" if "terraform" in VALIDATION_DOCKER_IMAGE.lower() else "tofu"


def _run_docker_terraform_command(repo_root: str, work_dir: str, terraform_args: List[str], timeout_s: int) -> Dict[str, Any]:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return {
            "cmd": ["docker", "run", *terraform_args],
            "cwd": work_dir,
            "exit_code": 127,
            "stdout": "",
            "stderr": "docker binary is not installed; cannot run isolated validation container",
        }
    if not VALIDATION_DOCKER_IMAGE:
        return {
            "cmd": ["docker", "run", *terraform_args],
            "cwd": work_dir,
            "exit_code": 127,
            "stdout": "",
            "stderr": "MORROW_VALIDATION_DOCKER_IMAGE is empty",
        }

    rel_work = os.path.relpath(work_dir, repo_root).replace("\\", "/")
    container_workdir = "/workspace" if rel_work in ("", ".") else f"/workspace/{rel_work}"
    cmd = [
        docker_bin,
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--cpus",
        VALIDATION_DOCKER_CPUS,
        "--memory",
        VALIDATION_DOCKER_MEMORY,
        "--pids-limit",
        "128",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-e",
        "TF_IN_AUTOMATION=1",
        "-e",
        "CHECKPOINT_DISABLE=1",
        "-v",
        f"{os.path.abspath(repo_root)}:/workspace:rw",
        "-w",
        container_workdir,
        "--entrypoint",
        _image_entrypoint(),
        VALIDATION_DOCKER_IMAGE,
        *terraform_args,
    ]
    return _run_command(cmd, cwd=repo_root, timeout_s=timeout_s)


def _run_generic_validation(file_path: str, updated_content: str) -> Dict[str, Any]:
    errors: List[str] = []
    if not str(updated_content or "").strip():
        errors.append("updated content is empty")
    if "-----BEGIN FILE-----" in updated_content or "-----END FILE-----" in updated_content:
        errors.append("wrapper markers remain in updated content")
    if "\x00" in updated_content:
        errors.append("updated content contains NUL bytes")
    policy_result = evaluate_iac_security_content(updated_content, file_path=file_path)
    if policy_result.get("findings"):
        errors.append("general IaC security policy failed")
    return {
        "status": "passed" if not errors else "failed",
        "exit_code": 0 if not errors else 1,
        "stdout": f"generic validation completed for {file_path}",
        "stderr": "\n".join(errors),
        "commands": [],
        "iac_security": policy_result,
    }


def _run_terraform_validation(repo_root: str, file_abspath: str, timeout_s: int) -> Dict[str, Any]:
    work_dir = os.path.dirname(file_abspath) or repo_root
    isolation_mode = VALIDATION_ISOLATION_MODE if VALIDATION_ISOLATION_MODE in ("workspace", "docker") else "workspace"
    # "tofu" is what the image ships; "terraform" is honoured for an operator who installed it.
    terraform_bin = shutil.which("tofu") or shutil.which("terraform")
    binary_name = os.path.basename(terraform_bin) if terraform_bin else "tofu"
    if isolation_mode == "workspace" and not terraform_bin:
        return {
            "status": "failed",
            "exit_code": 127,
            "stdout": "",
            "stderr": "no OpenTofu (tofu) or Terraform binary is installed in the runtime image",
            "commands": [],
            "isolation_mode": isolation_mode,
        }

    commands = [
        ["fmt", "-no-color", os.path.basename(file_abspath)],
        ["init", "-backend=false", "-input=false", "-no-color"],
        ["validate", "-no-color"],
    ]
    stdout_parts: List[str] = []
    stderr_parts: List[str] = []
    executed: List[Dict[str, Any]] = []
    for args in commands:
        if isolation_mode == "docker":
            res = _run_docker_terraform_command(repo_root, work_dir, args, timeout_s)
            display_cmd = ["docker", "run", "--network", "none", VALIDATION_DOCKER_IMAGE, _image_entrypoint(), *args]
        else:
            display_cmd = [terraform_bin or binary_name, *args]
            res = _run_command(display_cmd, cwd=work_dir, timeout_s=timeout_s)
        executed.append({"cmd": display_cmd, "exit_code": res["exit_code"]})
        stdout_parts.append(f"$ {' '.join(display_cmd)}\n{res['stdout']}".strip())
        stderr_parts.append(f"$ {' '.join(display_cmd)}\n{res['stderr']}".strip())
        if int(res["exit_code"] or 0) != 0:
            return {
                "status": "failed",
                "exit_code": int(res["exit_code"] or 1),
                "stdout": "\n\n".join([p for p in stdout_parts if p.strip()]),
                "stderr": "\n\n".join([p for p in stderr_parts if p.strip()]),
                "commands": executed,
                "isolation_mode": isolation_mode,
            }
    normalized_content = ""
    try:
        with open(file_abspath, "r", encoding="utf-8") as fh:
            normalized_content = fh.read()
    except Exception:
        normalized_content = ""
    policy_result = evaluate_iac_security_content(
        normalized_content,
        file_path=os.path.relpath(file_abspath, repo_root).replace(os.sep, "/"),
    )
    if policy_result.get("findings"):
        return {
            "status": "failed",
            "exit_code": 1,
            "stdout": "\n\n".join([p for p in stdout_parts if p.strip()]),
            "stderr": "general IaC security policy failed",
            "commands": executed,
            "normalized_content": normalized_content,
            "isolation_mode": isolation_mode,
            "iac_security": policy_result,
        }
    return {
        "status": "passed",
        "exit_code": 0,
        "stdout": "\n\n".join([p for p in stdout_parts if p.strip()]),
        "stderr": "\n\n".join([p for p in stderr_parts if p.strip()]),
        "commands": executed,
        "normalized_content": normalized_content,
        "isolation_mode": isolation_mode,
        "iac_security": policy_result,
    }


def execute_validation_job(
    validation_job_id: int,
    remediation_id: int,
    github_credential_id: int,
    *,
    git_ref: str = "",
    validator_type: str = "auto",
    timeout_seconds: int = 180,
) -> Dict[str, Any]:
    update_validation_job(
        int(validation_job_id),
        status="running",
        git_ref=str(git_ref or "").strip(),
        validator_type=str(validator_type or "auto").strip().lower() or "auto",
        stdout="",
        stderr="",
        exit_code=-1,
        finished=False,
    )

    try:
        remediation = get_remediation(int(remediation_id)) or {}
        if not remediation:
            raise RuntimeError("remediation not found")
        repo_id = int(remediation.get("repo_id") or 0)
        repo_row = get_repository_by_id(repo_id) if repo_id else None
        if not repo_row:
            raise RuntimeError("repository not found for remediation")
        repo_name = str(repo_row.get("name") or "").strip()
        if "/" not in repo_name:
            raise RuntimeError("repository name must be owner/repo")
        owner, repo = repo_name.split("/", 1)

        resolved = resolve_github_repo_token(int(github_credential_id), repo_name)
        if not resolved.get("ok"):
            raise RuntimeError(f"failed to resolve github repository token: {resolved}")
        token = str(resolved.get("token") or "").strip()
        if not token:
            raise RuntimeError("github credential resolved to an empty token")

        requested_ref = str(git_ref or "").strip()
        effective_ref = requested_ref or _repo_default_branch(owner, repo, token)
        file_rel = _safe_relative_path(str(remediation.get("file_path") or ""))
        updated_content = str(remediation.get("suggested_content") or "")
        actual_validator = _detect_validator(file_rel, validator_type)

        with tempfile.TemporaryDirectory(prefix="pq-remediation-validate-") as tmpdir:
            repo_root = _download_repo_archive(owner, repo, effective_ref, token, tmpdir)
            target_path = os.path.join(repo_root, *file_rel.split("/"))
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(updated_content)

            if actual_validator == "terraform":
                result = _run_terraform_validation(repo_root, target_path, timeout_seconds)
            else:
                result = _run_generic_validation(file_rel, updated_content)

        details = {
            "repository": repo_name,
            "file_path": file_rel,
            "git_ref": effective_ref,
            "validator_type": actual_validator,
            "requested_validator_type": str(validator_type or "auto").strip().lower() or "auto",
            "commands": result.get("commands") or [],
            "sandbox_profile": validation_sandbox_profile(),
            "isolation_mode": str(result.get("isolation_mode") or ("workspace" if actual_validator != "terraform" else VALIDATION_ISOLATION_MODE)),
            "validation_environment": {
                "secrets_env_scrubbed": True,
                "network": "none" if str(result.get("isolation_mode") or "") == "docker" else "host",
                "security_boundary": "per-job docker container" if str(result.get("isolation_mode") or "") == "docker" else "temporary workspace inside worker container",
                "timeout_max_seconds": VALIDATION_TIMEOUT_MAX_SECONDS,
                "stdout_limit": VALIDATION_STDOUT_LIMIT,
            },
        }
        if result.get("iac_security"):
            details["iac_security"] = result.get("iac_security")
        normalized_content = str(result.get("normalized_content") or "")
        if normalized_content:
            details["normalized_content"] = normalized_content
        updated = update_validation_job(
            int(validation_job_id),
            status=str(result.get("status") or "failed").strip().lower(),
            validator_type=actual_validator,
            git_ref=effective_ref,
            stdout=str(result.get("stdout") or "")[:VALIDATION_STDOUT_LIMIT],
            stderr=str(result.get("stderr") or "")[:VALIDATION_STDOUT_LIMIT],
            exit_code=int(result.get("exit_code") or 0),
            details=details,
            finished=True,
        ) or {"id": int(validation_job_id), "status": str(result.get("status") or "failed")}
        if str(updated.get("status") or "").strip().lower() == "failed":
            notify_payload = {
                "validation_job_id": int(updated.get("id") or validation_job_id),
                "remediation_id": int(remediation_id),
                "asset_key": str(remediation.get("asset_key") or "").strip(),
                "repository": repo_name,
                "file_path": file_rel,
                "git_ref": effective_ref,
                "validator_type": actual_validator,
                "exit_code": int(updated.get("exit_code") or 1),
            }
            try:
                append_audit_log(
                    actor_id="pq-validator",
                    actor_role="system",
                    action="validation.failed",
                    resource_type="validation_job",
                    resource_id=str(updated.get("id") or validation_job_id),
                    decision="deny",
                    reason=str(updated.get("stderr") or "")[:512],
                    details=notify_payload,
                )
            except Exception:
                pass
            try:
                from events import emit_platform_event

                emit_platform_event(
                    "validation.failed",
                    notify_payload,
                    dedupe_key=f"validation.failed:{int(updated.get('id') or validation_job_id)}",
                )
            except Exception:
                pass
        return updated
    except Exception as e:
        updated = update_validation_job(
            int(validation_job_id),
            status="failed",
            stdout="",
            stderr=str(e)[:20000],
            exit_code=1,
            details={"validator_type": str(validator_type or "auto").strip().lower() or "auto", "git_ref": str(git_ref or "").strip()},
            finished=True,
        ) or {"id": int(validation_job_id), "status": "failed"}
        try:
            append_audit_log(
                actor_id="pq-validator",
                actor_role="system",
                action="validation.failed",
                resource_type="validation_job",
                resource_id=str(updated.get("id") or validation_job_id),
                decision="deny",
                reason=str(e)[:512],
                details={
                    "validation_job_id": int(updated.get("id") or validation_job_id),
                    "remediation_id": int(remediation_id),
                    "validator_type": str(validator_type or "auto").strip().lower() or "auto",
                    "git_ref": str(git_ref or "").strip(),
                    "exit_code": int(updated.get("exit_code") or 1),
                },
            )
        except Exception:
            pass
        try:
            from events import emit_platform_event

            emit_platform_event(
                "validation.failed",
                {
                    "validation_job_id": int(updated.get("id") or validation_job_id),
                    "remediation_id": int(remediation_id),
                    "asset_key": "",
                    "repository": "",
                    "file_path": "",
                    "git_ref": str(git_ref or "").strip(),
                    "validator_type": str(validator_type or "auto").strip().lower() or "auto",
                    "exit_code": int(updated.get("exit_code") or 1),
                },
                dedupe_key=f"validation.failed:{int(updated.get('id') or validation_job_id)}",
            )
        except Exception:
            pass
        return updated
