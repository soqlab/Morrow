from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _risk_from_asset(asset: Dict[str, Any]) -> int:
    criticality = _text(asset.get("criticality")).lower()
    lifetime = _text(asset.get("confidentiality_lifetime")).lower()
    score = 35
    if criticality in {"critical", "high"}:
        score += 30
    elif criticality == "medium":
        score += 15
    if "long" in lifetime or "years" in lifetime:
        score += 20
    if asset.get("repository_id"):
        score += 5
    return max(0, min(score, 100))


def _intent_keywords(intent: str) -> Dict[str, bool]:
    lower = intent.lower()
    return {
        "pqc": any(k in lower for k in ("pqc", "quantum", "rsa", "ecc", "tls", "crypto", "certificate")),
        "public_storage": any(k in lower for k in ("public bucket", "public storage", "s3", "blob public")),
        "iam": any(k in lower for k in ("iam", "admin role", "permission", "offboard", "identity", "okta", "azure ad")),
        "vendor": any(k in lower for k in ("vendor", "supplier", "attestation", "third party", "third-party")),
        "ai_guardrail": any(k in lower for k in ("copilot", "ai", "agent", "guardrail", "truth api")),
    }


def evaluate_security_intent(
    intent: str,
    *,
    assets: Iterable[Dict[str, Any]],
    repositories: Iterable[Dict[str, Any]],
    remediations: Iterable[Dict[str, Any]],
    audit_events: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Convert a natural-language intent into an enforceable plan.

    This is intentionally deterministic: enterprise buyers need explainable policy
    translation before any future LLM-assisted expansion.
    """
    intent = _text(intent)
    keys = _intent_keywords(intent)
    assets_l = list(assets)
    repos_l = list(repositories)
    rem_l = list(remediations)
    audits_l = list(audit_events)

    controls: List[Dict[str, Any]] = []
    if keys["pqc"] or not any(keys.values()):
        controls.append({
            "id": "pqc.crypto_agility",
            "title": "Cryptographic agility baseline",
            "check": "Flag critical or long-lived assets without verified PQC migration evidence.",
            "write_path": "Open validated remediation PRs for TLS/certificate policy and crypto inventory ownership.",
        })
    if keys["public_storage"]:
        controls.append({
            "id": "infra.no_public_storage",
            "title": "No public storage exposure",
            "check": "Detect infrastructure changes that expose storage publicly.",
            "write_path": "Generate revert/hardening PR with public access blocked and explicit exception workflow.",
        })
    if keys["iam"]:
        controls.append({
            "id": "identity.least_privilege",
            "title": "Identity-centric least privilege",
            "check": "Detect admin IAM grants, stale owners, and offboarding gaps.",
            "write_path": "Generate access-removal PRs and route owner approval before merge.",
        })
    if keys["vendor"]:
        controls.append({
            "id": "vendor.pqc_attestation",
            "title": "Vendor PQC attestation credibility",
            "check": "Score vendor claims against evidence, dates, standards, and customer asset dependency.",
            "write_path": "Create follow-up evidence requests and risk exceptions when proof is missing.",
        })
    if keys["ai_guardrail"]:
        controls.append({
            "id": "ai.security_truth_gate",
            "title": "AI Security Truth gate",
            "check": "Validate AI-generated code before merge against policy and known risk.",
            "write_path": "Block unsafe changes or return a safer patch plan to the calling agent.",
        })

    targets: List[Dict[str, Any]] = []
    for asset in assets_l[:100]:
        score = _risk_from_asset(asset)
        if score >= 55 or keys["pqc"]:
            targets.append({
                "kind": "asset",
                "key": _text(asset.get("asset_key")),
                "owner": _text(asset.get("owner")) or "unassigned",
                "repository_id": asset.get("repository_id") or 0,
                "risk_score": score,
                "reason": "critical/long-lived asset needs governed migration evidence",
            })

    if keys["ai_guardrail"]:
        for repo in repos_l[:50]:
            targets.append({
                "kind": "repository",
                "key": _text(repo.get("name")),
                "risk_score": 60,
                "reason": "repository should require Security Truth API validation before AI-authored changes merge",
            })

    open_remediations = [r for r in rem_l if _text(r.get("status")).lower() not in {"verified_closed", "rejected"}]
    drifted = [r for r in rem_l if _text(r.get("drift_status")).lower() in {"drifted", "check_failed"}]

    evidence_id = hashlib.sha256(f"{intent}|{len(assets_l)}|{len(repos_l)}|{len(rem_l)}".encode("utf-8")).hexdigest()[:16]
    return {
        "api_version": "v1",
        "generated_at": _now(),
        "intent": intent,
        "intent_id": evidence_id,
        "controls": controls,
        "targets": targets[:75],
        "summary": {
            "controls": len(controls),
            "candidate_targets": len(targets),
            "repositories": len(repos_l),
            "assets": len(assets_l),
            "open_remediations": len(open_remediations),
            "drifted_remediations": len(drifted),
            "audit_events_sampled": len(audits_l),
        },
        "next_actions": [
            "Review translated controls with security owner.",
            "Run Security Truth validation for proposed infrastructure/code changes.",
            "Promote approved controls into CI merge gates.",
            "Create remediation PRs only after sandbox validation passes.",
        ],
    }


def build_security_graph(
    *,
    assets: Iterable[Dict[str, Any]],
    repositories: Iterable[Dict[str, Any]],
    remediations: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    assets_l = list(assets)
    repos_l = list(repositories)
    rem_l = list(remediations)
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for repo in repos_l[:500]:
        rid = int(repo.get("id") or 0)
        node_id = f"repo:{rid or _text(repo.get('name'))}"
        nodes.append({"id": node_id, "type": "repository", "label": _text(repo.get("name")), "url": _text(repo.get("html_url"))})

    for asset in assets_l[:1000]:
        key = _text(asset.get("asset_key"))
        node_id = f"asset:{key}"
        nodes.append({
            "id": node_id,
            "type": "asset",
            "label": key,
            "owner": _text(asset.get("owner")),
            "risk_score": _risk_from_asset(asset),
        })
        rid = int(asset.get("repository_id") or 0)
        if rid:
            edges.append({"from": node_id, "to": f"repo:{rid}", "type": "controlled_by"})

    for remediation in rem_l[:1000]:
        rid = int(remediation.get("id") or 0)
        node_id = f"remediation:{rid}"
        nodes.append({
            "id": node_id,
            "type": "remediation",
            "label": f"remediation {rid}",
            "status": _text(remediation.get("status")),
            "drift_status": _text(remediation.get("drift_status")),
        })
        asset_key = _text(remediation.get("asset_key"))
        if asset_key:
            edges.append({"from": f"asset:{asset_key}", "to": node_id, "type": "has_work"})

    return {
        "api_version": "v1",
        "generated_at": _now(),
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "assets": len(assets_l),
            "repositories": len(repos_l),
            "remediations": len(rem_l),
        },
    }


def validate_security_truth(change: str, *, intent: str = "") -> Dict[str, Any]:
    text = _text(change)
    lower = text.lower()
    findings: List[Dict[str, Any]] = []
    adapters: List[Dict[str, Any]] = []
    if any(k in lower for k in ("resource \"aws_", "resource \"azurerm_", "resource \"google_", "terraform", "provider \"")):
        adapters.append({"name": "terraform", "status": "inspected", "integration": "plan-json/OPA-compatible export ready"})
    if any(k in lower for k in ("apiversion:", "kind:", "rbac.authorization.k8s.io", "clusterrole", "deployment")):
        adapters.append({"name": "kubernetes", "status": "inspected", "integration": "admission-controller/OPA-compatible export ready"})
    if any(k in lower for k in ("iam", "policy_document", "administratoraccess", "\"action\"", "\"resource\"")):
        adapters.append({"name": "iam", "status": "inspected", "integration": "least-privilege diff review"})
    rules = [
        ("infra.public_storage", r"public-read|acl\s*=\s*[\"']public|block_public_acls\s*=\s*false|allow_blob_public_access\s*=\s*true", "Public storage exposure"),
        ("identity.admin_grant", r"administratoraccess|owner\s*=|\\*:\\*|actions\s*:\s*\\*", "Broad administrative permission"),
        ("crypto.weak_rsa", r"rsa[_-]?1024|rsa[_-]?2048|tls[_-]?1[._-]0|tls[_-]?1[._-]1|sha1", "Legacy crypto baseline"),
        ("secret.inline", r"api[_-]?key\\s*=|secret\\s*=|private[_-]?key", "Possible inline secret"),
        ("kubernetes.privileged", r"privileged:\s*true|hostnetwork:\s*true|hostpid:\s*true", "Privileged Kubernetes workload"),
        ("iam.wildcard_resource", r"\"resource\"\s*:\s*\"\\*\"|resource\s*=\s*\"\\*\"", "Wildcard IAM resource"),
    ]
    for rule_id, pattern, title in rules:
        if re.search(pattern, lower, flags=re.IGNORECASE):
            findings.append({"rule_id": rule_id, "severity": "high", "title": title, "action": "block until remediated or explicitly excepted"})

    decision = "allow" if not findings else "block"
    return {
        "api_version": "v1",
        "generated_at": _now(),
        "decision": decision,
        "intent": intent,
        "adapters": adapters or [{"name": "generic", "status": "inspected", "integration": "text heuristic"}],
        "findings": findings,
        "safe_next_step": "Proceed to sandbox validation." if decision == "allow" else "Generate a safer patch and resubmit to the Security Truth API.",
    }


def score_vendor_attestation(attestation: Dict[str, Any], *, dependent_assets: int = 0) -> Dict[str, Any]:
    answers = {str(k).lower(): _text(v) for k, v in (attestation or {}).items()}
    text = " ".join(answers.values()).lower()
    score = 40
    evidence_gaps: List[str] = []
    if any(k in text for k in ("pqc", "post-quantum", "nist", "ml-kem", "kyber")):
        score += 20
    else:
        evidence_gaps.append("No explicit PQC/NIST migration language.")
    if any(k in text for k in ("roadmap", "date", "2026", "2027", "timeline")):
        score += 15
    else:
        evidence_gaps.append("No dated migration roadmap.")
    if any(k in text for k in ("evidence", "audit", "certificate", "report", "sbom", "cbom")):
        score += 15
    else:
        evidence_gaps.append("No attached audit/evidence artifact.")
    if dependent_assets > 0:
        score -= min(20, dependent_assets * 2)
    score = max(0, min(score, 100))
    return {
        "api_version": "v1",
        "generated_at": _now(),
        "vendor_score": score,
        "risk_level": "low" if score >= 75 else "medium" if score >= 50 else "high",
        "dependent_assets": dependent_assets,
        "evidence_gaps": evidence_gaps,
        "required_follow_up": [
            "Request dated PQC migration plan.",
            "Request algorithm inventory/CBOM.",
            "Map vendor dependency to customer critical assets.",
        ][: max(1, len(evidence_gaps))],
    }
