"""
GitHub PR Inline Annotations

Posts inline review comments and a Check Run to a GitHub PR
when the CI/CD Crypto Gate finds quantum-vulnerable patterns.

Unlike the gate YAML (which generates a workflow file), this module
calls the GitHub API *directly* from the Morrow backend
to annotate a PR immediately — no GitHub Actions runner needed.

Flow:
  1. Receive a webhook payload (push / pull_request event)
  2. Fetch the PR diff from GitHub
  3. Run the cicd_gate scanner on added lines
  4. Create / update a GitHub Check Run with annotations
  5. Optionally post a summary PR review comment

All via urllib — no PyGithub needed.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List


# ── GitHub API helpers ─────────────────────────────────────────────────────────

_GH_API = "https://api.github.com"


def _gh_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization":        f"Bearer {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type":         "application/json",
    }


def _gh_get(path: str, token: str, accept: str = "") -> Any:
    hdrs = _gh_headers(token)
    if accept:
        hdrs["Accept"] = accept
    url = f"{_GH_API}{path}" if path.startswith("/") else path
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            ct = r.headers.get("Content-Type","")
            body = r.read()
            return json.loads(body) if "json" in ct else body.decode(errors="replace")
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:400]
        except Exception: pass
        raise RuntimeError(f"GitHub API {e.code}: {body}") from e


def _gh_post(path: str, token: str, payload: Dict[str, Any]) -> Any:
    url = f"{_GH_API}{path}" if path.startswith("/") else path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=_gh_headers(token), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:400]
        except Exception: pass
        raise RuntimeError(f"GitHub API {e.code}: {body}") from e


def _gh_patch(path: str, token: str, payload: Dict[str, Any]) -> Any:
    url = f"{_GH_API}{path}" if path.startswith("/") else path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=_gh_headers(token), method="PATCH")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:400]
        except Exception: pass
        raise RuntimeError(f"GitHub API {e.code}: {body}") from e


# ── Diff parsing ───────────────────────────────────────────────────────────────

def _parse_diff_for_annotations(diff_text: str) -> List[Dict[str, Any]]:
    """
    Parse a unified diff and extract per-file, per-line additions.

    Returns list of {"path": str, "line": int, "content": str}
    """
    additions = []
    current_file = None
    current_line = 0

    for raw in diff_text.splitlines():
        line = raw
        if line.startswith("diff --git"):
            m = re.search(r"b/(.+)$", line)
            current_file = m.group(1) if m else None
            current_line = 0
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            current_line = int(m.group(1)) - 1 if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            if current_file:
                additions.append({
                    "path":    current_file,
                    "line":    current_line,
                    "content": line[1:],
                })
        elif not line.startswith("-"):
            current_line += 1

    return additions


# ── Check Run management ───────────────────────────────────────────────────────

def _create_check_run(
    token: str,
    owner: str,
    repo: str,
    head_sha: str,
    check_name: str = "PQC Crypto Gate",
) -> int:
    """Create a new in-progress Check Run; return its ID."""
    payload = {
        "name":       check_name,
        "head_sha":   head_sha,
        "status":     "in_progress",
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    resp = _gh_post(f"/repos/{owner}/{repo}/check-runs", token, payload)
    return resp.get("id", 0)


def _complete_check_run(
    token: str,
    owner: str,
    repo: str,
    check_run_id: int,
    conclusion: str,   # "success" | "failure" | "neutral"
    title: str,
    summary: str,
    annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Update a Check Run with conclusion + inline annotations."""
    output: Dict[str, Any] = {
        "title":   title,
        "summary": summary,
    }
    if annotations:
        output["annotations"] = annotations[:50]   # GitHub cap per request = 50

    payload = {
        "status":       "completed",
        "conclusion":   conclusion,
        "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output":       output,
    }
    return _gh_patch(f"/repos/{owner}/{repo}/check-runs/{check_run_id}", token, payload)


# ── PR review comment ──────────────────────────────────────────────────────────

def _post_pr_review(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
    event: str = "COMMENT",   # "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
) -> Dict[str, Any]:
    return _gh_post(f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews", token, {
        "body":  body,
        "event": event,
    })


# ── Public API ─────────────────────────────────────────────────────────────────

def review_pr(
    github_token: str,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    block_on_critical: bool = True,
    post_review_comment: bool = True,
    check_name: str = "PQC Crypto Gate",
) -> Dict[str, Any]:
    """
    Fetch the PR diff, run the crypto gate, and post inline annotations
    + a GitHub Check Run result.

    Returns a result dict with {check_run_id, conclusion, findings_count, ...}.
    """
    from services.cicd_gate import scan_diff

    # 1. Fetch diff
    try:
        diff_text = _gh_get(
            f"/repos/{owner}/{repo}/pulls/{pr_number}",
            github_token,
            accept="application/vnd.github.diff",
        )
    except Exception as ex:
        return {"ok": False, "error": f"Failed to fetch PR diff: {ex}"}

    # 2. Run gate
    gate_result = scan_diff(diff_text)
    findings    = gate_result.get("findings", [])
    gate_passed = gate_result.get("gate_passed", True)

    # 3. Create Check Run
    check_run_id = 0
    try:
        check_run_id = _create_check_run(github_token, owner, repo, head_sha, check_name)
    except Exception as ex:
        return {"ok": False, "error": f"Failed to create check run: {ex}"}

    # 4. Build annotations (GitHub format)
    annotations = []
    for f in findings[:50]:
        ann_level = "failure" if f.get("severity") in ("critical","high") else "warning"
        annotations.append({
            "path":             f.get("file",""),
            "start_line":       f.get("line", 1),
            "end_line":         f.get("line", 1),
            "annotation_level": ann_level,
            "title":            f"[{f.get('severity','').upper()}] {f.get('pattern_id','')}",
            "message":          f.get("description","Quantum-vulnerable crypto pattern detected."),
            "raw_details":      f"Pattern: `{f.get('pattern','')}` matched on line {f.get('line','')}.\n\n"
                                f"**Fix:** {f.get('fix','Replace with a NIST-approved PQC algorithm (ML-KEM-768, ML-DSA-65).')}",
        })

    # 5. Determine conclusion
    crit_count = sum(1 for f in findings if f.get("severity") in ("critical","high"))
    if block_on_critical and crit_count > 0:
        conclusion = "failure"
    elif findings:
        conclusion = "neutral"
    else:
        conclusion = "success"

    title   = f"PQC Gate: {'BLOCKED' if conclusion=='failure' else 'PASSED' if conclusion=='success' else 'WARNINGS'} — {len(findings)} finding(s)"
    summary = _build_summary(findings, gate_passed)

    # 6. Complete Check Run
    try:
        check_resp = _complete_check_run(
            github_token, owner, repo, check_run_id, conclusion, title, summary, annotations
        )
    except Exception as ex:
        check_resp = {"error": str(ex)}

    # 7. Optional PR review comment
    review_resp = {}
    if post_review_comment:
        try:
            comment_event = "REQUEST_CHANGES" if conclusion == "failure" else "COMMENT"
            review_resp = _post_pr_review(github_token, owner, repo, pr_number, summary, comment_event)
        except Exception as ex:
            review_resp = {"error": str(ex)}

    return {
        "ok": True,
        "check_run_id":    check_run_id,
        "conclusion":      conclusion,
        "findings_count":  len(findings),
        "critical_count":  crit_count,
        "gate_passed":     gate_passed,
        "annotations_posted": len(annotations),
        "check_response":  check_resp,
        "review_response": review_resp,
    }


def _build_summary(findings: List[Dict], gate_passed: bool) -> str:
    if not findings:
        return ("## ✅ PQC Crypto Gate — Passed\n\n"
                "No quantum-vulnerable cryptographic patterns were detected in this PR.\n\n"
                "_Checked by Morrow_")

    critical = [f for f in findings if f.get("severity") in ("critical","high")]
    medium   = [f for f in findings if f.get("severity") in ("medium",)]
    low      = [f for f in findings if f.get("severity") in ("low","info")]

    icon = "🚫" if critical else "⚠️"
    header = f"## {icon} PQC Crypto Gate — {'BLOCKED' if critical else 'WARNINGS'}\n\n"
    body = f"**{len(findings)} quantum-vulnerable pattern(s) detected** in this PR.\n\n"

    if critical:
        body += f"**{len(critical)} critical/high-severity finding(s)** will block this merge:\n\n"
        for f in critical[:5]:
            body += f"- `{f.get('file','')}:{f.get('line','')}` — **{f.get('pattern_id','')}** ({f.get('severity','').upper()})\n"
    if medium:
        body += f"\n**{len(medium)} medium-severity finding(s):**\n"
        for f in medium[:3]:
            body += f"- `{f.get('file','')}:{f.get('line','')}` — {f.get('pattern_id','')}\n"
    if low:
        body += f"\n{len(low)} low-severity finding(s) (see annotations for details).\n"

    body += (
        "\n\n### Remediation\n"
        "Replace quantum-vulnerable algorithms with NIST-approved PQC alternatives:\n"
        "- **Key Encapsulation:** ML-KEM-768 (formerly Kyber-768)\n"
        "- **Digital Signatures:** ML-DSA-65 (formerly Dilithium3) or SLH-DSA\n"
        "- **TLS:** Enable `X25519Kyber768` or `P256Kyber768` hybrid key exchange\n\n"
        "_Checked by Morrow_"
    )
    return header + body


def get_pr_diff(
    github_token: str,
    owner: str,
    repo: str,
    pr_number: int,
) -> str:
    """Return raw unified diff for a PR (useful for testing)."""
    return _gh_get(
        f"/repos/{owner}/{repo}/pulls/{pr_number}",
        github_token,
        accept="application/vnd.github.diff",
    )


def preview_pr_annotations(
    github_token: str,
    owner: str,
    repo: str,
    pr_number: int,
) -> Dict[str, Any]:
    """
    Dry-run: fetch + scan the PR but do NOT post anything to GitHub.
    Returns what would have been annotated.
    """
    from services.cicd_gate import scan_diff

    try:
        diff_text = get_pr_diff(github_token, owner, repo, pr_number)
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

    gate_result = scan_diff(diff_text)
    findings    = gate_result.get("findings", [])

    return {
        "ok": True,
        "dry_run": True,
        "pr": f"{owner}/{repo}#{pr_number}",
        "findings_count": len(findings),
        "findings": findings[:25],
        "gate_passed": gate_result.get("gate_passed", True),
        "summary_preview": _build_summary(findings, gate_result.get("gate_passed", True)),
    }
