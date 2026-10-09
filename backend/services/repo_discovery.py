from __future__ import annotations

import re
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any, Dict, List, Optional

from db import list_assets, list_repositories, link_asset_repository


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
CRYPTO_MIGRATION_RECIPES: List[Dict[str, Any]] = [
    {
        "id": "rsa_encrypt_or_oaep",
        "patterns": [r"\bRSA\b", r"RSA/ECB/OAEP", r"public_encrypt", r"private_decrypt", r"PKCS1_OAEP"],
        "severity": "high",
        "legacy_dependency": "RSA encryption/key transport",
        "migration_target": "ML-KEM/Kyber hybrid key encapsulation through a vetted crypto library",
        "safe_next_step": "Create an adapter layer first, then migrate call sites behind the adapter and validate interoperability.",
    },
    {
        "id": "rsa_signature",
        "patterns": [r"SHA256withRSA", r"RSASSA", r"rsa\.Sign", r"RSA_sign", r"jwt.*RS256"],
        "severity": "medium",
        "legacy_dependency": "RSA signatures",
        "migration_target": "Hybrid signature plan using ML-DSA/Dilithium where ecosystem support exists; otherwise inventory and isolate.",
        "safe_next_step": "Inventory signing boundary, token consumers, certificate chains, and rollout compatibility before replacing signatures.",
    },
    {
        "id": "ecdh_or_ecdsa",
        "patterns": [r"\bECDH\b", r"\bECDSA\b", r"secp256r1", r"prime256v1", r"nistp256"],
        "severity": "medium",
        "legacy_dependency": "Elliptic-curve key exchange/signatures",
        "migration_target": "Hybrid PQC plus classical mode while client/provider support matures.",
        "safe_next_step": "Mark as crypto-agility work and prepare hybrid-capable configuration paths.",
    },
    {
        "id": "static_tls_policy",
        "patterns": [r"TLSv1\.0", r"TLSv1\.1", r"ssl_policy", r"min_tls", r"cipher_suite", r"ssl_protocols"],
        "severity": "medium",
        "legacy_dependency": "Static TLS policy/configuration",
        "migration_target": "Policy-as-code with modern TLS baseline and provider PQC/hybrid capability tracking.",
        "safe_next_step": "Move TLS policy into IaC, validate, open PR, then rescan for evidence.",
    },
    {
        "id": "java_keystore_or_jks",
        "patterns": [r"\bKeyStore\.getInstance\s*\(\s*[\"']JKS[\"']", r"\.jks\b", r"\bkeytool\b", r"\btruststore\b", r"\bkeystore\b"],
        "severity": "medium",
        "legacy_dependency": "Java keystore/truststore crypto boundary",
        "migration_target": "Inventory certificate/key material and prepare crypto-agile keystore/certificate rotation plan.",
        "safe_next_step": "Create a migration task to inventory aliases, certificate chains, key algorithms, rotation ownership, and client compatibility.",
    },
    {
        "id": "openssl_legacy_usage",
        "patterns": [r"\bopenssl\s+(rsautl|genrsa|rsa)\b", r"\bRSA_new\b", r"\bPEM_read_.*RSA", r"\bEVP_PKEY_RSA\b", r"\bSSL_CTX_set_cipher_list\b"],
        "severity": "high",
        "legacy_dependency": "OpenSSL RSA/TLS implementation usage",
        "migration_target": "Upgrade library path and isolate OpenSSL crypto calls behind a tested adapter.",
        "safe_next_step": "Create an engineering migration task; identify runtime OpenSSL version, supported algorithms, clients, and test vectors.",
    },
    {
        "id": "jwt_weak_or_legacy_alg",
        "patterns": [r"\balg\s*[:=]\s*[\"']none[\"']", r"\bHS256\b", r"\bRS256\b", r"\bES256\b", r"jsonwebtoken|jwt\.sign|jwt\.verify"],
        "severity": "medium",
        "legacy_dependency": "JWT signing/verification algorithm dependency",
        "migration_target": "Inventory token issuers/consumers and plan algorithm agility with key rotation and compatibility controls.",
        "safe_next_step": "Create a migration task for token boundary review; do not change algorithms without consumer rollout.",
    },
    {
        "id": "certificate_or_private_key_material",
        "patterns": [r"BEGIN (RSA )?PRIVATE KEY", r"BEGIN CERTIFICATE", r"\.pem\b", r"\.crt\b", r"\.key\b", r"\.p12\b", r"\.pfx\b"],
        "severity": "high",
        "legacy_dependency": "Certificate/private-key material in repository",
        "migration_target": "Move secrets out of source control and inventory certificate/key algorithm and rotation path.",
        "safe_next_step": "Treat as sensitive evidence: rotate exposed key material if real, move to secret manager, and create certificate migration task.",
    },
]


def _repo_crypto_safety_class(path: str, rule_id: str) -> Dict[str, str]:
    p = str(path or "").lower()
    rid = str(rule_id or "").lower()
    config_ext = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".conf", ".properties", ".toml", ".ini")
    code_ext = (".java", ".kt", ".go", ".py", ".js", ".ts", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php")
    if rid == "certificate_or_private_key_material":
        return {
            "safety_class": "manual_review",
            "confidence": "high",
            "safety_reason": "Repository may contain certificate or private-key material; this needs sensitive handling and possible rotation.",
            "recommended_workflow": "Open a security review, rotate real exposed material, move secrets to a vault, then plan certificate migration.",
            "can_create_candidate": "false",
        }
    if rid in {"java_keystore_or_jks", "openssl_legacy_usage", "jwt_weak_or_legacy_alg"}:
        return {
            "safety_class": "migration_task",
            "confidence": "high" if rid in {"openssl_legacy_usage", "jwt_weak_or_legacy_alg"} else "medium",
            "safety_reason": "This touches application identity, token, keystore, or crypto-library behavior and requires tests plus rollout planning.",
            "recommended_workflow": "Create an engineering migration task with owners, compatibility checks, test vectors, and staged rollout.",
            "can_create_candidate": "false",
        }
    if p.endswith(config_ext) or "tls" in p or "nginx" in p or "terraform" in p:
        return {
            "safety_class": "safe_config_candidate",
            "confidence": "high" if rid == "static_tls_policy" else "medium",
            "safety_reason": "Configuration or IaC change can usually be reviewed as a narrow diff and validated in the sandbox.",
            "recommended_workflow": "Create candidate, human-review the diff, run sandbox validation, then open PR.",
            "can_create_candidate": "true",
        }
    if p.endswith(code_ext):
        return {
            "safety_class": "migration_task",
            "confidence": "medium",
            "safety_reason": "Application crypto changes can break interoperability and must be handled through a migration recipe and tests.",
            "recommended_workflow": "Create an engineering migration task; do not auto-rewrite blindly.",
            "can_create_candidate": "false",
        }
    return {
        "safety_class": "manual_review",
        "confidence": "low",
        "safety_reason": "File type or context is ambiguous, so an engineer should review before remediation.",
        "recommended_workflow": "Review manually, then decide whether this is a config fix or migration task.",
        "can_create_candidate": "false",
    }


def _repo_service_name(path: str) -> str:
    parts = [p for p in str(path or "").replace("\\", "/").split("/") if p]
    if not parts:
        return "repository-root"
    markers = {"src", "app", "apps", "services", "service", "packages", "infra", "terraform", "modules", "config", "configs"}
    if parts[0] in markers and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    if len(parts) >= 2 and parts[0] in {"backend", "frontend", "api", "web"}:
        return parts[0]
    return parts[0]


def _repo_crypto_boundary(path: str, rule_id: str) -> str:
    p = str(path or "").lower()
    rid = str(rule_id or "").lower()
    if "keystore" in rid or "truststore" in p or "cert" in p:
        return "certificate-keystore-boundary"
    if "jwt" in rid or "token" in p or "auth" in p:
        return "identity-token-boundary"
    if "openssl" in rid:
        return "native-crypto-library-boundary"
    if "tls" in rid or "nginx" in p or "haproxy" in p or "envoy" in p:
        return "tls-edge-configuration-boundary"
    if "rsa" in rid or "ecdh" in rid or "ecdsa" in rid:
        return "application-crypto-boundary"
    return "general-crypto-boundary"


def _discover_crypto_legacy_usage(files: List[Dict[str, str]], limit: int = 200) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    scanned = 0
    for f in files[: max(1, min(int(limit or 200), 2000))]:
        path = str(f.get("path") or f.get("file_path") or "unknown").strip() or "unknown"
        content = str(f.get("content") or "")
        scanned += 1
        lines = content.splitlines()
        seen_matches: set[tuple[str, int]] = set()
        for recipe in CRYPTO_MIGRATION_RECIPES:
            for pattern in recipe["patterns"]:
                rx = re.compile(pattern, re.IGNORECASE)
                for idx, line in enumerate(lines, start=1):
                    if rx.search(line):
                        match_key = (str(recipe["id"]), int(idx))
                        if match_key in seen_matches:
                            break
                        seen_matches.add(match_key)
                        safety = _repo_crypto_safety_class(path, recipe["id"])
                        findings.append({
                            "rule_id": recipe["id"],
                            "severity": recipe["severity"],
                            "path": path,
                            "line": idx,
                            "service": _repo_service_name(path),
                            "crypto_boundary": _repo_crypto_boundary(path, recipe["id"]),
                            "evidence": line.strip()[:240],
                            "legacy_dependency": recipe["legacy_dependency"],
                            "migration_target": recipe["migration_target"],
                            "safe_next_step": recipe["safe_next_step"],
                            **safety,
                        })
                        break
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top = max((severity_rank.get(str(x.get("severity")), 0) for x in findings), default=0)
    max_sev = next((k for k, v in severity_rank.items() if v == top), "none")
    safety_counts: Dict[str, int] = {}
    services: Dict[str, Dict[str, Any]] = {}
    boundaries: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = str(finding.get("safety_class") or "manual_review")
        safety_counts[key] = safety_counts.get(key, 0) + 1
        svc = str(finding.get("service") or "repository-root")
        services.setdefault(svc, {"service": svc, "findings_total": 0, "rules": {}, "max_severity": "none"})
        services[svc]["findings_total"] += 1
        services[svc]["rules"][str(finding.get("rule_id") or "unknown")] = services[svc]["rules"].get(str(finding.get("rule_id") or "unknown"), 0) + 1
        if severity_rank.get(str(finding.get("severity")), 0) > severity_rank.get(str(services[svc].get("max_severity")), 0):
            services[svc]["max_severity"] = str(finding.get("severity") or "none")
        boundary = str(finding.get("crypto_boundary") or "general-crypto-boundary")
        boundaries.setdefault(boundary, {"boundary": boundary, "findings_total": 0, "services": {}, "rules": {}})
        boundaries[boundary]["findings_total"] += 1
        boundaries[boundary]["services"][svc] = boundaries[boundary]["services"].get(svc, 0) + 1
        boundaries[boundary]["rules"][str(finding.get("rule_id") or "unknown")] = boundaries[boundary]["rules"].get(str(finding.get("rule_id") or "unknown"), 0) + 1
    service_groups = sorted(services.values(), key=lambda x: (-int(x.get("findings_total") or 0), str(x.get("service") or "")))
    boundary_groups = sorted(boundaries.values(), key=lambda x: (-int(x.get("findings_total") or 0), str(x.get("boundary") or "")))
    return {
        "status": "migration_needed" if findings else "no_legacy_crypto_detected",
        "files_scanned": scanned,
        "findings_total": len(findings),
        "max_severity": max_sev,
        "safety_class_counts": safety_counts,
        "service_groups": service_groups,
        "crypto_boundaries": boundary_groups,
        "findings": findings,
        "recommended_factory_mode": "adapter_then_pr" if findings else "monitor",
        "migration_factory_steps": [
            "discover legacy crypto call sites",
            "group findings by crypto boundary",
            "create adapter abstraction",
            "generate PQC/hybrid candidate patch",
            "run sandbox validation and tests",
            "open PR with rollout notes",
        ] if findings else ["keep scanning repository changes through CI gate"],
    }


def _domain_tokens(asset_key_str: str) -> List[str]:
    host = str(asset_key_str or "").split(":")[0].lower()
    parts = [p for p in re.split(r"[^a-z0-9]+", host) if p and p not in {"www", "com", "net", "org", "io", "co", "app", "api"}]
    return parts


def _repo_file_index(repository_files: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    out: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for item in repository_files or []:
        repo = str((item or {}).get("repository") or (item or {}).get("repo") or "").strip().lower()
        file_path = str((item or {}).get("file_path") or (item or {}).get("path") or "").strip()
        content = str((item or {}).get("content") or "")
        if repo and content:
            out[repo].append({"file_path": file_path, "content": content})
    return out


def _repo_discovery_scores(
    asset_keys: List[str],
    repository_names: List[str],
    repository_files: Optional[List[Dict[str, str]]] = None,
    link_high_confidence: bool = False,
    threshold: float = 0.82,
) -> Dict[str, Any]:
    assets = list_assets(limit=10000)
    repos = list_repositories(limit=10000)
    file_index = _repo_file_index(repository_files or [])
    if asset_keys:
        wanted = {str(x).strip() for x in asset_keys}
        assets = [a for a in assets if str(a.get("asset_key") or "").strip() in wanted]
    if repository_names:
        wanted_repos = {str(x).strip().lower() for x in repository_names}
        repos = [r for r in repos if str(r.get("name") or "").strip().lower() in wanted_repos]
    results = []
    for asset in assets:
        ak = str(asset.get("asset_key") or "")
        tokens = set(_domain_tokens(ak))
        candidates = []
        for repo in repos:
            name = str(repo.get("name") or "").lower()
            repo_tokens = set(p for p in re.split(r"[^a-z0-9]+", name) if p)
            overlap = tokens.intersection(repo_tokens)
            score = 0.0
            reasons = []
            host = ak.split(":")[0].lower()
            root = ".".join(host.split(".")[-2:]) if "." in host else host
            files = file_index.get(name, [])
            content_hits = []
            for file_item in files:
                content_l = str(file_item.get("content") or "").lower()
                if host and host in content_l:
                    content_hits.append(file_item.get("file_path") or "(content)")
                    score += 0.55
                elif root and root in content_l:
                    content_hits.append(file_item.get("file_path") or "(content)")
                    score += 0.30
            if host and host.replace(".", "-") in name:
                score += 0.55
                reasons.append("hostname slug appears in repository name")
            if root and root.split(".")[0] in repo_tokens:
                score += 0.25
                reasons.append("root domain token appears in repository name")
            if overlap:
                score += min(0.30, 0.10 * len(overlap))
                reasons.append(f"token overlap: {', '.join(sorted(overlap))}")
            if str(asset.get("team") or "").lower() and str(asset.get("team") or "").lower() in repo_tokens:
                score += 0.20
                reasons.append("asset team appears in repository name")
            if content_hits:
                reasons.append(f"hostname/domain appears in repo content: {', '.join(sorted(set(content_hits))[:5])}")
            score = min(1.0, round(score, 2))
            confidence = "high" if score >= 0.82 else ("medium" if score >= 0.45 else ("low" if score > 0 else "none"))
            if score > 0:
                candidates.append({"repository": repo, "score": score, "confidence": confidence, "reasons": reasons})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        best = candidates[0] if candidates else None
        if link_high_confidence and best and best["score"] >= float(threshold or 0.82):
            try:
                link_asset_repository(ak, int(best["repository"].get("id") or 0))
                best["linked"] = True
            except Exception as e:
                best["link_error"] = str(e)
        results.append(
            {
                "asset_key": ak,
                "current_repository_id": asset.get("repository_id") or 0,
                "best_match": best,
                "candidates": candidates[:5],
                "decision": "auto_linked" if best and best.get("linked") else ("manual_review_required" if not best or best["confidence"] != "high" else "high_confidence_match"),
            }
        )
    return {
        "generated_at": _now_iso(),
        "assets_checked": len(results),
        "repositories_checked": len(repos),
        "repository_files_checked": sum(len(v) for v in file_index.values()),
        "results": results,
    }
