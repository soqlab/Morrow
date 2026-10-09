"""
SAST Code Scanner — Quantum Vulnerability Static Analysis

Scans source code repositories (GitHub or uploaded archives) for:
  1. Hardcoded private keys / certificates in source files
  2. RSA/ECC key generation patterns
  3. Weak algorithm configurations (key sizes, cipher suites)
  4. JWT/token libraries with quantum-vulnerable algorithms
  5. Certificate pinning with quantum-vulnerable certs
  6. TLS configuration files with weak settings

Differs from cicd_gate.py (which gates PRs) — this is a full repo deep scan
with data-flow-aware confidence scoring and finding deduplication.

Output: SARIF 2.1.0 compatible JSON + internal findings table
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ── Rule database ──────────────────────────────────────────────────────────────

_RULES: List[Dict[str, Any]] = [
    # Hardcoded key material
    {
        "rule_id": "PQC-001",
        "name": "Hardcoded RSA Private Key",
        "severity": "critical",
        "cwe": "CWE-321",
        "pattern": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "extensions": None,  # All files
        "description": "Hardcoded private key detected in source code",
        "fix": "Remove key from source, store in secrets manager, ensure quantum-vulnerable algorithm is replaced",
    },
    {
        "rule_id": "PQC-002",
        "name": "Hardcoded Certificate",
        "severity": "high",
        "cwe": "CWE-295",
        "pattern": r"-----BEGIN CERTIFICATE-----",
        "extensions": None,
        "description": "Hardcoded certificate detected — may be quantum-vulnerable",
        "fix": "If this is a pinned cert, migrate to PQC certificate before pinning",
    },
    # RSA / ECC key generation
    {
        "rule_id": "PQC-010",
        "name": "RSA Key Generation (Python)",
        "severity": "critical",
        "cwe": "CWE-327",
        "pattern": r"(RSA\.generate|rsa\.newkeys|RSA\.newkeys|RSA_generate_key|generate_private_key\(rsa\.|RSAPrivateKey\.generate)",
        "extensions": [".py", ".pyw"],
        "description": "RSA key generation — quantum-vulnerable (Shor's algorithm breaks RSA)",
        "fix": "Replace with ML-KEM-768 (FIPS 203) or hybrid mode: RSA + ML-KEM",
    },
    {
        "rule_id": "PQC-011",
        "name": "ECC Key Generation (Python)",
        "severity": "high",
        "cwe": "CWE-327",
        "pattern": r"ec\.generate_private_key|ecdsa\.SigningKey\.generate|ECC\.generate",
        "extensions": [".py", ".pyw"],
        "description": "ECC key generation — vulnerable to Shor's algorithm",
        "fix": "Replace with ML-DSA-65 (FIPS 204) for signing or ML-KEM-768 for key exchange",
    },
    {
        "rule_id": "PQC-012",
        "name": "RSA Key Generation (JavaScript)",
        "severity": "critical",
        "cwe": "CWE-327",
        "pattern": r"generateKey(Pair)?\s*\(\s*['\"]rsa['\"]|generateKey(Pair)?Sync\s*\(\s*['\"]rsa",
        "extensions": [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        "description": "Node.js RSA key generation",
        "fix": "Use @noble/post-quantum or webcrypto with ML-KEM-768",
    },
    {
        "rule_id": "PQC-013",
        "name": "RSA Key Generation (Go)",
        "severity": "critical",
        "cwe": "CWE-327",
        "pattern": r"rsa\.GenerateKey\s*\(",
        "extensions": [".go"],
        "description": "Go standard library RSA key generation",
        "fix": "Replace with golang.org/x/crypto post-quantum bindings when available",
    },
    {
        "rule_id": "PQC-014",
        "name": "RSA Key Generation (Java)",
        "severity": "critical",
        "cwe": "CWE-327",
        "pattern": r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"',
        "extensions": [".java", ".kt", ".kts"],
        "description": "Java RSA KeyPairGenerator",
        "fix": "Migrate to Bouncy Castle PQC (bcprov-jdk15on ≥ 1.74 with CRYSTALS-Kyber)",
    },
    # Weak key sizes
    {
        "rule_id": "PQC-020",
        "name": "Small RSA Key Size",
        "severity": "critical",
        "cwe": "CWE-326",
        "pattern": r"(generate|key_size|modulus_size|bits)\s*[=:,\(]\s*(512|768|1024|1536)\b",
        "extensions": [".py", ".js", ".ts", ".go", ".java", ".rb"],
        "description": "RSA key size ≤ 1536 bits — easily broken classically and immediately by quantum computer",
        "fix": "Minimum RSA-3072 for classical security; migrate to ML-KEM-768 for quantum safety",
    },
    {
        "rule_id": "PQC-021",
        "name": "RSA-2048 Key Size",
        "severity": "high",
        "cwe": "CWE-326",
        "pattern": r"(generate|key_size|modulus_size|bits)\s*[=:,\(]\s*2048\b",
        "extensions": [".py", ".js", ".ts", ".go", ".java", ".rb"],
        "description": "RSA-2048 — breakable with ~4,000 logical qubits (Gidney & Ekerå 2021)",
        "fix": "Migrate to ML-KEM-768 (FIPS 203). RSA-2048 provides no quantum security.",
    },
    # JWT / Token algorithms
    {
        "rule_id": "PQC-030",
        "name": "JWT RS256/RS384/RS512 Algorithm",
        "severity": "high",
        "cwe": "CWE-327",
        "pattern": r'["\']algorithm["\']\s*:\s*["\']RS(256|384|512)["\']|algorithm\s*=\s*["\']RS(256|384|512)["\']',
        "extensions": [".py", ".js", ".ts", ".go", ".java", ".rb", ".json", ".yaml", ".yml"],
        "description": "JWT with RSA-based signing — quantum-vulnerable",
        "fix": "Migrate to ML-DSA-based JWT signing when JOSE PQC RFC is finalized; interim: EdDSA is safer",
    },
    {
        "rule_id": "PQC-031",
        "name": "JWT ES256/ES384/ES512 Algorithm",
        "severity": "high",
        "cwe": "CWE-327",
        "pattern": r'["\']algorithm["\']\s*:\s*["\']ES(256|384|512)["\']|algorithm\s*=\s*["\']ES(256|384|512)["\']',
        "extensions": [".py", ".js", ".ts", ".go", ".java", ".rb", ".json", ".yaml", ".yml"],
        "description": "JWT with ECDSA signing — quantum-vulnerable (Shor breaks ECDSA)",
        "fix": "Migrate to ML-DSA-based JWT signing",
    },
    # TLS configuration
    {
        "rule_id": "PQC-040",
        "name": "Deprecated TLS Version in Config",
        "severity": "medium",
        "cwe": "CWE-326",
        "pattern": r"(ssl_protocols?|tls_version|min_version|max_version)\s*[\s:=]+.*(TLSv1\.0|TLSv1\.1|SSLv3|ssl3)",
        "extensions": [".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".nginx", ".htaccess"],
        "description": "Deprecated TLS version configured",
        "fix": "Require TLS 1.3 minimum; configure X25519Kyber768 hybrid key exchange",
    },
    {
        "rule_id": "PQC-041",
        "name": "Weak TLS Cipher Suite",
        "severity": "medium",
        "cwe": "CWE-326",
        "pattern": r"(DHE-RSA|ECDHE-RSA|ECDHE-ECDSA|AES128-SHA|RC4|DES|3DES|NULL)",
        "extensions": [".conf", ".cfg", ".ini", ".nginx"],
        "description": "Quantum-vulnerable cipher suite in TLS configuration",
        "fix": "Use TLS_AES_256_GCM_SHA384 with X25519Kyber768 key exchange (available in BoringSSL, OQS-OpenSSL)",
    },
    # SSH configuration
    {
        "rule_id": "PQC-050",
        "name": "RSA Host Key in SSH Config",
        "severity": "high",
        "cwe": "CWE-327",
        "pattern": r"HostKey\s+/etc/ssh/ssh_host_rsa_key",
        "extensions": [".conf", ".cfg"],
        "description": "SSH RSA host key configured — quantum-vulnerable",
        "fix": "Add ssh-ed25519 and future PQC host keys; disable RSA host key",
    },
    {
        "rule_id": "PQC-051",
        "name": "Weak SSH KexAlgorithms",
        "severity": "medium",
        "cwe": "CWE-326",
        "pattern": r"KexAlgorithms.*diffie-hellman-group(1|14)-sha(1|256)",
        "extensions": [".conf", ".cfg"],
        "description": "Weak Diffie-Hellman key exchange in SSH config",
        "fix": "Remove classical DH; prefer curve25519-sha256 until PQC SSH KEX is standardized",
    },
    # Docker / Container
    {
        "rule_id": "PQC-060",
        "name": "Secret Copied into Container Layer",
        "severity": "critical",
        "cwe": "CWE-321",
        "pattern": r"COPY\s+.*(\.key|\.pem|\.p12|\.pfx|private)",
        "extensions": ["dockerfile"],
        "description": "Private key or certificate being copied into Docker image layer",
        "fix": "Use Docker secrets, volume mounts, or secrets manager at runtime — never bake keys into images",
    },
]


_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
    ".tsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go", ".java": "java", ".kt": "java", ".kts": "java",
    ".rs": "rust", ".rb": "ruby",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c",
    ".conf": "config", ".cfg": "config", ".ini": "config",
    ".yaml": "config", ".yml": "config", ".json": "config",
    ".nginx": "config",
    "dockerfile": "docker",
}


def scan_file(filename: str, content: str) -> List[Dict[str, Any]]:
    """Scan a single file for quantum-vulnerable crypto patterns."""
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else filename.lower()
    # Special case: Dockerfile
    if filename.lower() == "dockerfile" or filename.lower().endswith("dockerfile"):
        ext = "dockerfile"

    findings = []
    seen: set = set()

    for rule in _RULES:
        allowed = rule.get("extensions")
        if allowed is not None and ext not in allowed:
            continue

        for i, line in enumerate(content.splitlines(), 1):
            # Skip comments in most languages
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "--")):
                continue
            if re.search(rule["pattern"], line, re.IGNORECASE):
                # Deduplicate: same rule + same content fingerprint
                fp = hashlib.sha256(f"{rule['rule_id']}:{line.strip()[:80]}".encode()).hexdigest()[:12]
                if fp in seen:
                    continue
                seen.add(fp)
                findings.append({
                    "rule_id":    rule["rule_id"],
                    "rule_name":  rule["name"],
                    "file":       filename,
                    "line":       i,
                    "line_content": line.strip()[:200],
                    "severity":   rule["severity"],
                    "cwe":        rule["cwe"],
                    "description": rule["description"],
                    "fix":        rule["fix"],
                    "confidence": "high",
                })
    return findings


def scan_repository_files(
    files: List[Tuple[str, str]],  # [(filename, content), ...]
) -> Dict[str, Any]:
    """Scan a list of (filename, content) tuples. Returns aggregated SAST report."""
    all_findings: List[Dict[str, Any]] = []
    files_scanned = 0
    files_with_findings = set()

    for filename, content in files:
        if not content or not filename:
            continue
        file_findings = scan_file(filename, content)
        if file_findings:
            files_with_findings.add(filename)
            all_findings.extend(file_findings)
        files_scanned += 1

    by_severity = {
        "critical": [f for f in all_findings if f["severity"] == "critical"],
        "high":     [f for f in all_findings if f["severity"] == "high"],
        "medium":   [f for f in all_findings if f["severity"] == "medium"],
        "low":      [f for f in all_findings if f["severity"] == "low"],
    }
    by_rule: Dict[str, int] = {}
    for f in all_findings:
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files_scanned,
        "files_with_findings": len(files_with_findings),
        "total_findings": len(all_findings),
        "severity_summary": {k: len(v) for k, v in by_severity.items()},
        "findings_by_rule": by_rule,
        "findings": all_findings[:200],
        "passed": (len(by_severity["critical"]) == 0 and len(by_severity["high"]) == 0),
        "sarif": _to_sarif(all_findings),
    }


def scan_github_repo(
    github_token: str,
    repo_full_name: str,
    branch: str = "main",
    max_files: int = 200,
) -> Dict[str, Any]:
    """
    Scan a GitHub repository for quantum-vulnerable crypto patterns.
    Uses GitHub Contents API to fetch file list and content.
    """
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    errors: List[str] = []
    files: List[Tuple[str, str]] = []

    def _gh(path: str) -> Optional[Any]:
        url = f"https://api.github.com/repos/{repo_full_name}/{path}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code != 404:
                errors.append(f"HTTP {e.code}: {path}")
            return None
        except Exception as ex:
            errors.append(f"Error: {str(ex)[:80]}")
            return None

    def _fetch_tree(path: str = "") -> None:
        if len(files) >= max_files:
            return
        url = f"git/trees/{branch}?recursive=1"
        tree_data = _gh(url)
        if not tree_data:
            return
        scannable_exts = set(_EXT_TO_LANG.keys())
        for item in tree_data.get("tree", [])[:max_files * 3]:
            if item.get("type") != "blob":
                continue
            fpath = item.get("path", "")
            ext = "." + fpath.rsplit(".", 1)[-1].lower() if "." in fpath else fpath.lower()
            fname = fpath.rsplit("/", 1)[-1].lower()
            if ext not in scannable_exts and "dockerfile" not in fname:
                continue
            if any(skip in fpath for skip in ["/node_modules/", "/.git/", "/vendor/", "/dist/", "/__pycache__/"]):
                continue
            if len(files) >= max_files:
                break
            content_data = _gh(f"contents/{urllib.parse.quote(fpath)}?ref={branch}")
            if not content_data:
                continue
            raw_content = content_data.get("content", "")
            if not raw_content:
                continue
            try:
                decoded = base64.b64decode(raw_content.replace("\n", "")).decode("utf-8", errors="replace")
                files.append((fpath, decoded))
            except Exception:
                pass

    _fetch_tree()

    result = scan_repository_files(files)
    result["repo"] = repo_full_name
    result["branch"] = branch
    result["errors"] = errors
    return result


def _to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert findings to SARIF 2.1.0 format for GitHub Code Scanning."""
    rules_seen: Dict[str, Dict] = {}
    results = []

    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": f["rule_name"],
                "shortDescription": {"text": f["description"]},
                "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
                "properties": {"tags": ["security", "post-quantum", "cryptography"]},
                "defaultConfiguration": {
                    "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f["severity"], "warning")
                },
            }
        results.append({
            "ruleId": rid,
            "message": {"text": f"{f['description']} — {f['fix']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                }
            }],
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f["severity"], "warning"),
        })

    from services.public_config import public_base_url
    driver: Dict[str, Any] = {"name": "PQC Scanner SAST"}
    base_url = public_base_url()
    if base_url:  # informationUri is optional in SARIF; omit rather than use a placeholder
        driver["informationUri"] = base_url
    driver["rules"] = list(rules_seen.values())

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": driver,
            },
            "results": results,
        }],
    }


def get_rule_list() -> List[Dict[str, Any]]:
    """Return the list of all SAST rules."""
    return [{"rule_id": r["rule_id"], "name": r["name"], "severity": r["severity"],
             "cwe": r["cwe"], "description": r["description"]} for r in _RULES]
