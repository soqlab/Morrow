"""
CI/CD Crypto Regression Gate

Generates GitHub Actions YAML that fails any PR introducing new quantum-vulnerable
cryptographic operations into the codebase. Also exposes a webhook endpoint that
GitHub can call on PR events to run the gate check server-side.

Detection patterns (by language):
  Python — RSA.generate, ec.generate_private_key, rsa.newkeys, Crypto.PublicKey.RSA
  JavaScript/TypeScript — crypto.generateKeyPair with 'rsa'/'ec', jose HS256/RS256
  Go — rsa.GenerateKey, ecdsa.GenerateKey, elliptic.P256
  Java — KeyPairGenerator.getInstance("RSA"/"EC"), RSAKeyGenParameterSpec
  Rust — rsa::RsaPrivateKey::new, p256::SecretKey
  C/C++ — RSA_generate_key, EC_KEY_new_by_curve_name

The gate generates:
  1. A GitHub Actions workflow YAML (`.github/workflows/pqc-gate.yml`)
  2. A standalone gate script (`scripts/pqc-crypto-gate.py`) that can run locally
  3. A server-side webhook endpoint that processes GitHub PR payloads directly
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List


# ── Detection patterns ─────────────────────────────────────────────────────────

_PATTERNS: List[Dict[str, Any]] = [
    # Python
    {"lang": "python", "pattern": r"RSA\.generate\s*\(",             "severity": "critical", "description": "PyCryptodome RSA key generation"},
    {"lang": "python", "pattern": r"rsa\.newkeys\s*\(",              "severity": "critical", "description": "python-rsa key generation"},
    {"lang": "python", "pattern": r"ec\.generate_private_key\s*\(",  "severity": "high",     "description": "cryptography library ECC key generation"},
    {"lang": "python", "pattern": r"PublicKey\.RSA\.generate",       "severity": "critical", "description": "PyCrypto RSA generation"},
    {"lang": "python", "pattern": r"jwt\.encode.*algorithm\s*=\s*['\"]RS",  "severity": "high", "description": "JWT with RSA signing"},
    {"lang": "python", "pattern": r"jwt\.encode.*algorithm\s*=\s*['\"]ES",  "severity": "high", "description": "JWT with ECDSA signing"},
    {"lang": "python", "pattern": r"jwt\.encode.*algorithm\s*=\s*['\"]HS256", "severity": "medium", "description": "JWT with HMAC-SHA256 (only 128-bit quantum security)"},
    {"lang": "python", "pattern": r"paramiko\.RSAKey\.generate",     "severity": "critical", "description": "Paramiko RSA key generation"},
    {"lang": "python", "pattern": r"serialization\.Encoding\.PEM.*RSA", "severity": "medium", "description": "RSA PEM serialization"},
    # JavaScript / TypeScript
    {"lang": "javascript", "pattern": r"generateKeyPair\s*\(\s*['\"]rsa['\"]",  "severity": "critical", "description": "Node.js RSA key generation"},
    {"lang": "javascript", "pattern": r"generateKeyPair\s*\(\s*['\"]ec['\"]",   "severity": "high",     "description": "Node.js EC key generation"},
    {"lang": "javascript", "pattern": r"generateKeyPairSync\s*\(\s*['\"]rsa",   "severity": "critical", "description": "Node.js sync RSA key generation"},
    {"lang": "javascript", "pattern": r"algorithm\s*:\s*['\"]RS256['\"]",        "severity": "high",     "description": "JWT RS256 algorithm"},
    {"lang": "javascript", "pattern": r"algorithm\s*:\s*['\"]ES256['\"]",        "severity": "high",     "description": "JWT ES256 algorithm"},
    {"lang": "javascript", "pattern": r"forge\.pki\.rsa\.generateKeyPair",       "severity": "critical", "description": "node-forge RSA generation"},
    {"lang": "javascript", "pattern": r"new\s+NodeRSA\s*\(",                     "severity": "critical", "description": "node-rsa key generation"},
    {"lang": "javascript", "pattern": r"elliptic\s*\.\s*ec\s*\(",               "severity": "high",     "description": "elliptic library EC key operations"},
    # Go
    {"lang": "go", "pattern": r"rsa\.GenerateKey\s*\(",             "severity": "critical", "description": "Go stdlib RSA key generation"},
    {"lang": "go", "pattern": r"ecdsa\.GenerateKey\s*\(",           "severity": "high",     "description": "Go stdlib ECDSA key generation"},
    {"lang": "go", "pattern": r"elliptic\.(P256|P384|P521)\s*\(",  "severity": "high",     "description": "Go elliptic curve (quantum-vulnerable)"},
    {"lang": "go", "pattern": r"x509\.MarshalPKCS1PrivateKey",      "severity": "medium",   "description": "RSA PKCS1 marshaling"},
    # Java / Kotlin
    {"lang": "java", "pattern": r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"',  "severity": "critical", "description": "Java RSA key pair generation"},
    {"lang": "java", "pattern": r'KeyPairGenerator\.getInstance\s*\(\s*"EC"',   "severity": "high",     "description": "Java EC key pair generation"},
    {"lang": "java", "pattern": r'KeyPairGenerator\.getInstance\s*\(\s*"DSA"',  "severity": "high",     "description": "Java DSA key pair generation"},
    {"lang": "java", "pattern": r"RSAKeyGenParameterSpec",          "severity": "critical", "description": "Java RSA key parameter specification"},
    {"lang": "java", "pattern": r"ECGenParameterSpec",              "severity": "high",     "description": "Java EC parameter specification"},
    # Rust
    {"lang": "rust", "pattern": r"RsaPrivateKey::new\s*\(",        "severity": "critical", "description": "rsa crate RSA key generation"},
    {"lang": "rust", "pattern": r"p256::SecretKey",                 "severity": "high",     "description": "p256 crate (quantum-vulnerable ECC)"},
    {"lang": "rust", "pattern": r"k256::SecretKey",                 "severity": "high",     "description": "k256/secp256k1 crate (quantum-vulnerable)"},
    {"lang": "rust", "pattern": r"ed25519_dalek::SecretKey",        "severity": "high",     "description": "ed25519-dalek (quantum-vulnerable)"},
    # C / C++
    {"lang": "c", "pattern": r"RSA_generate_key\s*\(",             "severity": "critical", "description": "OpenSSL RSA_generate_key (deprecated)"},
    {"lang": "c", "pattern": r"RSA_generate_key_ex\s*\(",          "severity": "critical", "description": "OpenSSL RSA key generation"},
    {"lang": "c", "pattern": r"EC_KEY_new_by_curve_name\s*\(",     "severity": "high",     "description": "OpenSSL EC key creation"},
    {"lang": "c", "pattern": r"EC_KEY_generate_key\s*\(",          "severity": "high",     "description": "OpenSSL EC key generation"},
]

_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript", ".mjs": "javascript",
    ".go": "go",
    ".java": "java", ".kt": "java", ".kts": "java",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c",
}

# PQC-safe patterns that suppress false positives (lines containing these are ok)
_SAFE_SUPPRESSORS: List[str] = [
    "pqc_gate_ignore",
    "ml-kem", "ml_kem", "kyber", "mlkem",
    "ml-dsa", "ml_dsa", "dilithium",
    "slh-dsa", "slh_dsa", "sphincs",
    "# noqa: PQC", "// pqc-ok", "/* pqc-ok */",
]


def scan_file_content(filename: str, content: str) -> List[Dict[str, Any]]:
    """Scan a file's content for quantum-vulnerable crypto patterns."""
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lang = _EXT_TO_LANG.get(ext)
    if not lang:
        return []

    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        # Skip suppressed lines
        if any(s in line.lower() for s in _SAFE_SUPPRESSORS):
            continue
        for p in _PATTERNS:
            if p["lang"] != lang:
                continue
            if re.search(p["pattern"], line, re.IGNORECASE):
                findings.append({
                    "file": filename,
                    "line": i,
                    "line_content": line.strip()[:200],
                    "pattern": p["pattern"],
                    "severity": p["severity"],
                    "description": p["description"],
                    "lang": lang,
                    "pqc_replacement": _suggest_replacement(p["description"]),
                })
    return findings


def _suggest_replacement(description: str) -> str:
    desc = description.lower()
    if "rsa" in desc: return "Use ML-KEM-768 (FIPS 203) or Kyber — replace with pqcrypto/kyber library"
    if "ec" in desc or "ecdsa" in desc or "ecdh" in desc: return "Use ML-DSA-65 (FIPS 204) or SLH-DSA for signing"
    if "hs256" in desc: return "Upgrade to HMAC-SHA512 (HS512) as interim; migrate to ML-DSA for long-term tokens"
    if "rs256" in desc or "jwt" in desc: return "Migrate to ML-DSA-based JWT signing (JOSE PQC draft)"
    if "dsa" in desc: return "Replace with ML-DSA-65 (FIPS 204 — Module-Lattice Digital Signature)"
    return "Replace with NIST-approved PQC algorithm (FIPS 203/204/205)"


def scan_diff(diff_text: str) -> List[Dict[str, Any]]:
    """
    Scan a git unified diff for new quantum-vulnerable crypto patterns.
    Only flags added lines (+ prefix), not removed lines.
    """
    findings = []
    current_file = "unknown"
    current_line = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git"):
            # Extract filename from "diff --git a/path b/path"
            parts = raw_line.split(" b/")
            if len(parts) >= 2:
                current_file = parts[-1].strip()
            current_line = 0
        elif raw_line.startswith("@@"):
            # Extract line number from @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", raw_line)
            current_line = int(m.group(1)) - 1 if m else 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            line_content = raw_line[1:]  # Strip leading +
            ext = "." + current_file.rsplit(".", 1)[-1].lower() if "." in current_file else ""
            lang = _EXT_TO_LANG.get(ext)
            if not lang:
                continue
            if any(s in line_content.lower() for s in _SAFE_SUPPRESSORS):
                continue
            for p in _PATTERNS:
                if p["lang"] != lang:
                    continue
                if re.search(p["pattern"], line_content, re.IGNORECASE):
                    findings.append({
                        "file": current_file,
                        "line": current_line,
                        "line_content": line_content.strip()[:200],
                        "pattern": p["pattern"],
                        "severity": p["severity"],
                        "description": p["description"],
                        "lang": lang,
                        "pqc_replacement": _suggest_replacement(p["description"]),
                    })
        elif not raw_line.startswith("-"):
            current_line += 1

    return findings


def generate_gate_yaml(org_name: str = "your-org") -> str:
    """Generate a GitHub Actions workflow YAML for the PQC crypto regression gate."""
    from services.public_config import public_base_url
    base_url = public_base_url()
    generated_by = f"# Generated by Morrow — {base_url}\n" if base_url else "# Generated by Morrow\n"
    return "# PQC Crypto Regression Gate\n" + generated_by + """# This workflow fails any PR that introduces new quantum-vulnerable cryptographic operations.

name: PQC Crypto Regression Gate

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  pqc-gate:
    name: Quantum-Safe Crypto Check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run PQC Crypto Gate
        id: pqc-check
        run: |
          git diff origin/${{ github.base_ref }}...HEAD > /tmp/pr.diff
          python scripts/pqc-crypto-gate.py /tmp/pr.diff > /tmp/pqc-report.json
          echo "exit_code=$?" >> $GITHUB_OUTPUT

      - name: Post PR comment
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('/tmp/pqc-report.json', 'utf8'));
            const body = [
              '## ❌ PQC Crypto Regression Detected',
              '',
              `Found ${report.critical_count} critical and ${report.high_count} high severity quantum-vulnerable crypto patterns in this PR.`,
              '',
              '| File | Line | Severity | Issue | PQC Replacement |',
              '|------|------|----------|-------|-----------------|',
              ...report.findings.slice(0, 20).map(f =>
                `| ${f.file} | ${f.line} | **${f.severity.toUpperCase()}** | ${f.description} | ${f.pqc_replacement} |`
              ),
              '',
              '> Add `# pqc_gate_ignore` to suppress false positives.',
              '> See [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) for migration guidance.',
            ].join('\\n');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });

      - name: Gate decision
        run: |
          if [ "${{ steps.pqc-check.outputs.exit_code }}" != "0" ]; then
            echo "::error::PR introduces quantum-vulnerable cryptographic operations. See PQC gate report."
            exit 1
          fi
          echo "✓ No quantum-vulnerable crypto regressions detected."
"""


def generate_gate_script() -> str:
    """Generate the standalone pqc-crypto-gate.py script."""
    patterns_json = json.dumps(_PATTERNS, indent=2)
    ext_map_json = json.dumps(_EXT_TO_LANG, indent=2)
    safe_json = json.dumps(_SAFE_SUPPRESSORS, indent=2)
    return f'''#!/usr/bin/env python3
"""
PQC Crypto Regression Gate — standalone script
Generated by Morrow. Run against a git diff to detect quantum-vulnerable crypto.

Usage:
    git diff main...HEAD | python scripts/pqc-crypto-gate.py -
    python scripts/pqc-crypto-gate.py /path/to/file.diff
    python scripts/pqc-crypto-gate.py --scan-file src/crypto.py
"""
import json, re, sys

PATTERNS = {patterns_json}
EXT_TO_LANG = {ext_map_json}
SAFE_SUPPRESSORS = {safe_json}

def suggest(desc):
    desc = desc.lower()
    if "rsa" in desc: return "Use ML-KEM-768 (FIPS 203)"
    if "ec" in desc: return "Use ML-DSA-65 (FIPS 204)"
    return "Use NIST-approved PQC algorithm"

def scan_diff(diff):
    findings, current_file, line_no = [], "unknown", 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git"):
            parts = raw.split(" b/")
            current_file = parts[-1].strip() if len(parts) >= 2 else "unknown"
            line_no = 0
        elif raw.startswith("@@"):
            m = re.search(r"\\+(\\d+)", raw)
            line_no = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            line_no += 1
            content = raw[1:]
            ext = "." + current_file.rsplit(".", 1)[-1].lower() if "." in current_file else ""
            lang = EXT_TO_LANG.get(ext)
            if not lang or any(s in content.lower() for s in SAFE_SUPPRESSORS): continue
            for p in PATTERNS:
                if p["lang"] != lang: continue
                if re.search(p["pattern"], content, re.IGNORECASE):
                    findings.append({{"file": current_file, "line": line_no,
                        "line_content": content.strip()[:200], "severity": p["severity"],
                        "description": p["description"], "pqc_replacement": suggest(p["description"])}})
        elif not raw.startswith("-"):
            line_no += 1
    return findings

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    diff = open(src).read() if src != "-" else sys.stdin.read()
    findings = scan_diff(diff)
    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    report = {{"findings": findings, "total": len(findings), "critical_count": critical, "high_count": high}}
    print(json.dumps(report, indent=2))
    if findings:
        print(f"\\n❌ PQC Gate FAILED: {{len(findings)}} findings ({{critical}} critical, {{high}} high)", file=sys.stderr)
        sys.exit(1)
    print("\\n✓ PQC Gate PASSED", file=sys.stderr)
    sys.exit(0)
'''


def _db():
    from db import get_connection
    return get_connection()


def _ensure_tables() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cicd_gate_scans (
                id          TEXT PRIMARY KEY,
                org_id      TEXT NOT NULL,
                repo        TEXT NOT NULL DEFAULT '',
                pr_number   INTEGER DEFAULT 0,
                scanned_at  TEXT NOT NULL,
                total       INTEGER NOT NULL DEFAULT 0,
                critical_ct INTEGER NOT NULL DEFAULT 0,
                high_ct     INTEGER NOT NULL DEFAULT 0,
                passed      INTEGER NOT NULL DEFAULT 1,
                findings_json TEXT NOT NULL DEFAULT '[]'
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cicd_org ON cicd_gate_scans(org_id, scanned_at)"
        )
        conn.commit()


def process_webhook_payload(
    payload: Dict[str, Any],
    org_id: str,
    diff_text: str = "",
) -> Dict[str, Any]:
    """
    Process a GitHub PR webhook payload. If diff_text is provided (fetched via
    GitHub API), scans the diff. Returns gate result.
    """
    _ensure_tables()
    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {}).get("full_name", "")
    pr_number = int(pr.get("number", 0))

    findings = scan_diff(diff_text) if diff_text else []

    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    passed = (critical == 0 and high == 0)

    scan_id = "GATE-" + hashlib.sha256(f"{org_id}:{repo}:{pr_number}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:12].upper()

    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO cicd_gate_scans
               (id, org_id, repo, pr_number, scanned_at, total, critical_ct, high_ct, passed, findings_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, org_id, repo, pr_number, datetime.now(timezone.utc).isoformat(),
             len(findings), critical, high, 1 if passed else 0, json.dumps(findings[:50])),
        )
        conn.commit()

    return {
        "scan_id": scan_id,
        "repo": repo,
        "pr_number": pr_number,
        "passed": passed,
        "total_findings": len(findings),
        "critical_count": critical,
        "high_count": high,
        "findings": findings[:20],
        "gate_status": "PASS" if passed else "FAIL",
        "gate_message": (
            "No quantum-vulnerable crypto regressions detected." if passed
            else f"Found {critical} critical and {high} high quantum-vulnerable crypto patterns."
        ),
    }


def list_gate_scans(org_id: str, limit: int = 30) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, repo, pr_number, scanned_at, total, critical_ct, high_ct, passed
               FROM cicd_gate_scans WHERE org_id = ? ORDER BY scanned_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
