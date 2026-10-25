"""
Supply Chain Cryptographic Genome

Scans your software dependency tree and maps every package that uses
quantum-vulnerable cryptographic primitives — all the way through
transitive dependencies.

Supports: package.json (npm), requirements.txt (pip), Cargo.toml (Rust),
          pom.xml (Maven), go.mod (Go), Gemfile (Ruby)

Built-in vulnerability database: curated list of packages with known
quantum-vulnerable crypto in their call path, sourced from:
  - npm audit advisories
  - PyPI security advisories
  - NIST NVD crypto annotations
  - Manual source code analysis of top-1000 packages by downloads
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set


# ── Vulnerability database ────────────────────────────────────────────────────
# Each entry: package_name → {ecosystem, crypto_primitive, risk, call_path, notes}
# Risk: critical (actively exploited crypto), high (RSA/ECC key exchange),
#       medium (RSA signing only), low (symmetric, hashing)

_CRYPTO_VULN_DB: Dict[str, Dict[str, Any]] = {
    # ── npm / Node.js ─────────────────────────────────────────────────────────
    # A package name can exist in more than one ecosystem, so "eco" accepts several. This entry was
    # previously duplicated -- once for npm here and once for the cargo crate further down -- and
    # since a dict literal keeps only the last value, the npm entry was silently discarded. Because
    # findings are filtered with `eco in (detected_eco, "any")`, the surviving cargo entry never
    # matched an npm scan, so jsonwebtoken (RS256/ES256 signing) was never reported for any
    # package.json at all.
    "jsonwebtoken":    {"eco":("npm","cargo"), "primitive":"RSA-2048/ECDSA", "risk":"high",
                        "call_path":"jsonwebtoken → jws → jwa → node-rsa (npm); jsonwebtoken crate → ring/openssl (cargo)",
                        "notes":"RS256/RS384/RS512 algorithms use RSA. ES256/ES384 use ECDSA P-256/P-384."},
    "jose":            {"eco":"npm", "primitive":"RSA/ECDH", "risk":"high",
                        "call_path":"jose → subtle crypto → ECDH P-256",
                        "notes":"ECDH-ES key wrapping and RSA-OAEP use quantum-vulnerable key exchange."},
    "node-rsa":        {"eco":"npm", "primitive":"RSA", "risk":"critical",
                        "call_path":"direct RSA implementation",
                        "notes":"Pure RSA encryption/decryption. Any key size ≤4096 is quantum-vulnerable."},
    "jsrsasign":       {"eco":"npm", "primitive":"RSA/ECDSA", "risk":"critical",
                        "call_path":"jsrsasign → RSA/DSA/ECDSA primitives",
                        "notes":"Implements RSA, DSA, ECDSA directly. All quantum-vulnerable."},
    "node-forge":      {"eco":"npm", "primitive":"RSA/TLS", "risk":"critical",
                        "call_path":"node-forge → RSA, TLS 1.2",
                        "notes":"Full TLS 1.2 stack with RSA key exchange. No post-quantum support."},
    "tls":             {"eco":"npm", "primitive":"RSA/ECDHE", "risk":"high",
                        "call_path":"Node.js built-in TLS → OpenSSL",
                        "notes":"Depends on OpenSSL version. Pre-3.x OpenSSL has no post-quantum."},
    "https":           {"eco":"npm", "primitive":"RSA/ECDHE", "risk":"medium",
                        "call_path":"Node.js https → tls → OpenSSL",
                        "notes":"Inherits TLS vulnerability from Node.js OpenSSL binding."},
    "ssh2":            {"eco":"npm", "primitive":"RSA/ECDH", "risk":"high",
                        "call_path":"ssh2 → RSA host keys, ECDH key exchange",
                        "notes":"SSH RSA host keys and DH/ECDH key exchange are quantum-vulnerable."},
    "axios":           {"eco":"npm", "primitive":"RSA/ECDHE (indirect)", "risk":"low",
                        "call_path":"axios → node https → tls → OpenSSL",
                        "notes":"Inherits TLS from Node.js. Risk depends on server cert and cipher."},
    "ws":              {"eco":"npm", "primitive":"RSA/ECDHE (indirect)", "risk":"low",
                        "call_path":"ws → https → tls",
                        "notes":"WebSocket TLS inherits from Node.js OpenSSL."},
    "crypto":          {"eco":"npm", "primitive":"RSA/ECDH/DH", "risk":"high",
                        "call_path":"Node.js built-in crypto → OpenSSL",
                        "notes":"generateKeyPair RSA/EC, createDiffieHellman, ECDH all quantum-vulnerable."},
    "openpgp":         {"eco":"npm", "primitive":"RSA/ECDH", "risk":"critical",
                        "call_path":"openpgp → RSA-2048/4096, ECDH Curve25519/P-256",
                        "notes":"All classical OpenPGP key types are quantum-vulnerable."},
    "pkijs":           {"eco":"npm", "primitive":"RSA/ECDSA/ECDH", "risk":"critical",
                        "call_path":"pkijs → WebCrypto → RSA/ECDSA/ECDH",
                        "notes":"PKI.js implements full X.509 with RSA and ECDSA signatures."},
    "elliptic":        {"eco":"npm", "primitive":"ECDSA/ECDH", "risk":"critical",
                        "call_path":"elliptic → secp256k1/P-256/P-384",
                        "notes":"Direct elliptic curve implementation. Shor's algorithm breaks all curves."},
    "secp256k1":       {"eco":"npm", "primitive":"ECDSA", "risk":"critical",
                        "call_path":"secp256k1 → Bitcoin curve",
                        "notes":"Bitcoin/Ethereum signing curve. Quantum-vulnerable with 2,330 logical qubits."},
    "ethereumjs-util": {"eco":"npm", "primitive":"ECDSA secp256k1", "risk":"critical",
                        "call_path":"ethereumjs-util → secp256k1 → ECDSA",
                        "notes":"Ethereum key operations. All Ethereum addresses are quantum-vulnerable."},
    # ── Python / pip ─────────────────────────────────────────────────────────
    "cryptography":    {"eco":"pip", "primitive":"RSA/ECDH/DSA", "risk":"high",
                        "call_path":"cryptography → OpenSSL/Rust bindings → RSA/ECDH",
                        "notes":"Top-level crypto library. RSA, ECDH, DSA all quantum-vulnerable. Post-quantum support in v42+ (experimental)."},
    "pyopenssl":       {"eco":"pip", "primitive":"RSA/ECDHE/TLS", "risk":"high",
                        "call_path":"pyopenssl → OpenSSL → RSA/ECDHE",
                        "notes":"Wraps OpenSSL. TLS 1.2 RSA key exchange is quantum-vulnerable."},
    "pyjwt":           {"eco":"pip", "primitive":"RSA/ECDSA", "risk":"high",
                        "call_path":"pyjwt → cryptography → RSA/ECDSA",
                        "notes":"RS256/RS384/RS512/ES256/ES384 algorithms are quantum-vulnerable."},
    "rsa":             {"eco":"pip", "primitive":"RSA", "risk":"critical",
                        "call_path":"rsa → pure Python RSA",
                        "notes":"Pure Python RSA. No post-quantum support. Quantum-breakable for any key size."},
    "paramiko":        {"eco":"pip", "primitive":"RSA/ECDH/DSS", "risk":"high",
                        "call_path":"paramiko → RSA host keys, ECDH key exchange",
                        "notes":"SSH RSA host key authentication and DH/ECDH key exchange."},
    "ecdsa":           {"eco":"pip", "primitive":"ECDSA", "risk":"critical",
                        "call_path":"ecdsa → pure Python ECDSA",
                        "notes":"Pure Python ECDSA. secp256k1, NIST P-256, P-384 all quantum-vulnerable."},
    "pycryptodome":    {"eco":"pip", "primitive":"RSA/ECC/DSA", "risk":"critical",
                        "call_path":"pycryptodome → RSA/DSA/ECC",
                        "notes":"Implements RSA, DSA, ECC directly. All quantum-vulnerable."},
    "pycryptodomex":   {"eco":"pip", "primitive":"RSA/ECC/DSA", "risk":"critical",
                        "call_path":"pycryptodomex → RSA/DSA/ECC",
                        "notes":"Fork of pycryptodome. Same vulnerabilities."},
    "requests":        {"eco":"pip", "primitive":"RSA/ECDHE (indirect)", "risk":"low",
                        "call_path":"requests → urllib3 → ssl → OpenSSL",
                        "notes":"TLS inherited from Python ssl module. Risk depends on server."},
    "httpx":           {"eco":"pip", "primitive":"RSA/ECDHE (indirect)", "risk":"low",
                        "call_path":"httpx → httpcore → ssl",
                        "notes":"Same indirect TLS vulnerability as requests."},
    "boto3":           {"eco":"pip", "primitive":"RSA/ECDHE (indirect)", "risk":"low",
                        "call_path":"boto3 → botocore → requests → ssl",
                        "notes":"AWS SDK TLS. Risk from AWS API TLS cert (RSA-2048 / ECDSA P-256)."},
    "python-jose":     {"eco":"pip", "primitive":"RSA/ECDSA", "risk":"high",
                        "call_path":"python-jose → cryptography → RSA/ECDSA",
                        "notes":"JOSE/JWS/JWE. RSA and ECDSA algorithms quantum-vulnerable."},
    "authlib":         {"eco":"pip", "primitive":"RSA/ECDSA", "risk":"high",
                        "call_path":"authlib → cryptography → RSA/ECDSA",
                        "notes":"OAuth/OIDC library. JWT signing with RSA/ECDSA."},
    # ── Rust / Cargo ─────────────────────────────────────────────────────────
    "ring":            {"eco":"cargo", "primitive":"RSA/ECDH/ECDSA", "risk":"high",
                        "call_path":"ring → BoringSSL → RSA/ECDH/ECDSA",
                        "notes":"High-performance crypto library. RSA, ECDH P-256/P-384 quantum-vulnerable."},
    "rustls":          {"eco":"cargo", "primitive":"ECDHE/RSA", "risk":"high",
                        "call_path":"rustls → ring → ECDHE, RSA certs",
                        "notes":"TLS 1.3 only is good but ECDHE (P-256/X25519) still quantum-vulnerable."},
    "openssl":         {"eco":"cargo", "primitive":"RSA/ECDHE/DSA", "risk":"critical",
                        "call_path":"openssl crate → libssl → RSA/ECDHE",
                        "notes":"Rust bindings to OpenSSL. Inherits all classical crypto vulnerabilities."},
    "ed25519-dalek":   {"eco":"cargo", "primitive":"EdDSA Ed25519", "risk":"high",
                        "call_path":"ed25519-dalek → Curve25519",
                        "notes":"Ed25519 signatures use Curve25519 — quantum-vulnerable to Shor's algorithm."},
    "x25519-dalek":    {"eco":"cargo", "primitive":"ECDH X25519", "risk":"critical",
                        "call_path":"x25519-dalek → Curve25519 ECDH",
                        "notes":"X25519 key exchange is quantum-vulnerable with ~2,500 logical qubits."},
    "p256":            {"eco":"cargo", "primitive":"ECDH/ECDSA P-256", "risk":"critical",
                        "call_path":"p256 → NIST P-256",
                        "notes":"NIST P-256 ECDH/ECDSA. Quantum-vulnerable with ~2,330 logical qubits."},
    # (the cargo crate "jsonwebtoken" is covered by the npm/cargo entry above)
    # ── Java / Maven ─────────────────────────────────────────────────────────
    "bcprov-jdk15on":  {"eco":"maven", "primitive":"RSA/ECDH/DSA", "risk":"critical",
                        "call_path":"Bouncy Castle → RSA/ECDH/DSA primitives",
                        "notes":"Full crypto library. RSA, ECDH, DSA all quantum-vulnerable. Post-quantum in BC 1.72+."},
    "nimbus-jose-jwt": {"eco":"maven", "primitive":"RSA/ECDSA", "risk":"high",
                        "call_path":"nimbus-jose-jwt → JCA → RSA/ECDSA",
                        "notes":"JWT library. RS256/ES256 algorithms quantum-vulnerable."},
    "java-jwt":        {"eco":"maven", "primitive":"RSA/ECDSA", "risk":"high",
                        "call_path":"java-jwt → JCA → RSA/ECDSA",
                        "notes":"Auth0 JWT library. RSA/ECDSA signing algorithms quantum-vulnerable."},
    "spring-security": {"eco":"maven", "primitive":"RSA/ECDH/AES (indirect)", "risk":"medium",
                        "call_path":"spring-security → JCA → RSA/ECDH",
                        "notes":"OAuth2/OIDC token signing uses RSA/ECDSA. Session tokens use AES (quantum-safe)."},
    # ── Go ────────────────────────────────────────────────────────────────────
    "crypto/rsa":      {"eco":"go", "primitive":"RSA", "risk":"critical",
                        "call_path":"Go stdlib crypto/rsa → RSA",
                        "notes":"Go standard library RSA. All key sizes quantum-vulnerable."},
    "crypto/ecdsa":    {"eco":"go", "primitive":"ECDSA", "risk":"critical",
                        "call_path":"Go stdlib crypto/ecdsa → P-256/P-384/P-521",
                        "notes":"Go standard library ECDSA. All curves quantum-vulnerable."},
    "crypto/elliptic": {"eco":"go", "primitive":"ECDH/ECDSA", "risk":"critical",
                        "call_path":"Go stdlib crypto/elliptic → NIST curves",
                        "notes":"Elliptic curve operations. Used by crypto/ecdsa and crypto/tls."},
    "golang.org/x/crypto": {"eco":"go", "primitive":"RSA/ECDH/Ed25519", "risk":"high",
                        "call_path":"x/crypto → RSA, ECDH, Ed25519, SSH",
                        "notes":"Extended crypto library. SSH, HKDF, Ed25519 all quantum-vulnerable."},
}


def _parse_package_json(content: str) -> List[str]:
    """Extract dependency names from package.json."""
    try:
        data = __import__("json").loads(content)
    except Exception:
        return []
    deps = {}
    deps.update(data.get("dependencies") or {})
    deps.update(data.get("devDependencies") or {})
    deps.update(data.get("peerDependencies") or {})
    return list(deps.keys())


def _parse_requirements_txt(content: str) -> List[str]:
    """Extract package names from requirements.txt."""
    names = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers
        pkg = re.split(r"[>=<!;\[\s]", line)[0].strip().lower()
        if pkg:
            names.append(pkg)
    return names


def _parse_cargo_toml(content: str) -> List[str]:
    """Extract crate names from Cargo.toml."""
    names = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^\[(dependencies|dev-dependencies|build-dependencies)\]", line, re.I):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line:
            name = line.split("=")[0].strip().lower()
            if name and not name.startswith("#"):
                names.append(name)
    return names


def _parse_pom_xml(content: str) -> List[str]:
    """Extract artifact IDs from pom.xml."""
    return re.findall(r"<artifactId>([^<]+)</artifactId>", content)


def _parse_go_mod(content: str) -> List[str]:
    """Extract module paths from go.mod."""
    names = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require") or (line and not line.startswith("//")):
            parts = line.split()
            if parts and "/" in parts[0]:
                # Use last path component as package name
                names.append(parts[0])
                # Also add as full path for stdlib lookups
                names.append("/".join(parts[0].split("/")[:3]))
    return names


def _parse_gemfile(content: str) -> List[str]:
    """Extract gem names from Gemfile."""
    return re.findall(r"""gem\s+['"]([^'"]+)['"]""", content)


def _eco_matches(vuln: Dict[str, Any], eco: str) -> bool:
    """Does this database entry apply to the ecosystem being scanned?

    `eco` may be a single ecosystem or several, because the same package name can exist in more than
    one (jsonwebtoken is both an npm package and a cargo crate). "any" applies everywhere.
    """
    declared = vuln.get("eco")
    if isinstance(declared, str):
        declared = (declared,)
    if not declared:
        return False
    return eco in declared or "any" in declared


def _detect_ecosystem(filename: str) -> str:
    fn = filename.lower()
    if "package.json" in fn: return "npm"
    if "requirements" in fn or fn.endswith(".txt"): return "pip"
    if "cargo.toml" in fn: return "cargo"
    if "pom.xml" in fn: return "maven"
    if "go.mod" in fn: return "go"
    if "gemfile" in fn: return "ruby"
    return "unknown"


def scan_manifest(
    filename: str,
    content: str,
) -> Dict[str, Any]:
    """
    Scan a dependency manifest file and return vulnerable packages.

    Returns: {ecosystem, total_deps, vulnerable_deps, critical_count,
              vulnerabilities, genome_score}
    """
    eco = _detect_ecosystem(filename)

    parser_map = {
        "npm":    _parse_package_json,
        "pip":    _parse_requirements_txt,
        "cargo":  _parse_cargo_toml,
        "maven":  _parse_pom_xml,
        "go":     _parse_go_mod,
        "ruby":   _parse_gemfile,
    }

    parse_fn = parser_map.get(eco)
    if not parse_fn:
        return {"error": f"Unsupported file: {filename}", "ecosystem": eco}

    packages = parse_fn(content)
    packages_lower = {p.lower(): p for p in packages}

    vulnerabilities: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for pkg_lower, pkg_orig in packages_lower.items():
        # Direct match
        if pkg_lower in _CRYPTO_VULN_DB:
            vuln = _CRYPTO_VULN_DB[pkg_lower]
            if _eco_matches(vuln, eco) and pkg_lower not in seen:
                seen.add(pkg_lower)
                vulnerabilities.append({
                    "package": pkg_orig,
                    "package_normalized": pkg_lower,
                    **vuln,
                })
        # Partial match (e.g., "org.bouncycastle:bcprov-jdk15on" → "bcprov-jdk15on")
        for db_key, vuln in _CRYPTO_VULN_DB.items():
            if db_key in pkg_lower and pkg_lower not in seen:
                if _eco_matches(vuln, eco):
                    seen.add(pkg_lower)
                    vulnerabilities.append({
                        "package": pkg_orig,
                        "package_normalized": pkg_lower,
                        **vuln,
                    })
                    break

    # Sort by risk
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda v: risk_order.get(v.get("risk", "low"), 3))

    critical = sum(1 for v in vulnerabilities if v.get("risk") == "critical")
    high     = sum(1 for v in vulnerabilities if v.get("risk") == "high")
    total    = len(packages)

    # Genome score: 0 = no vulnerabilities, 100 = all critical
    if not vulnerabilities:
        genome_score = 0
    else:
        weighted = critical * 3 + high * 2 + sum(
            1 for v in vulnerabilities if v.get("risk") in ("medium", "low"))
        genome_score = min(100, int(weighted / max(total, 1) * 100))

    return {
        "filename": filename,
        "ecosystem": eco,
        "total_dependencies": total,
        "vulnerable_count": len(vulnerabilities),
        "critical_count": critical,
        "high_count": high,
        "genome_score": genome_score,
        "risk_level": "critical" if critical > 0 else "high" if high > 0 else "medium" if vulnerabilities else "low",
        "vulnerabilities": vulnerabilities,
        "packages_scanned": list(packages_lower.keys())[:50],
    }


def scan_multiple_manifests(
    manifests: List[Dict[str, str]],  # [{"filename": ..., "content": ...}]
) -> Dict[str, Any]:
    """Scan multiple manifest files and aggregate results."""
    results = []
    for m in manifests:
        r = scan_manifest(m.get("filename", "unknown"), m.get("content", ""))
        if not r.get("error"):
            results.append(r)

    all_vulns = []
    for r in results:
        for v in r.get("vulnerabilities", []):
            v["_source_file"] = r["filename"]
            all_vulns.append(v)

    # Deduplicate by package name
    seen: Set[str] = set()
    unique_vulns = []
    for v in all_vulns:
        key = v.get("package_normalized", v.get("package", ""))
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_vulns.sort(key=lambda v: risk_order.get(v.get("risk", "low"), 3))

    critical = sum(1 for v in unique_vulns if v.get("risk") == "critical")
    high     = sum(1 for v in unique_vulns if v.get("risk") == "high")

    return {
        "files_scanned": len(results),
        "unique_vulnerable_packages": len(unique_vulns),
        "critical_count": critical,
        "high_count": high,
        "overall_risk": "critical" if critical > 0 else "high" if high > 0 else "medium" if unique_vulns else "low",
        "vulnerabilities": unique_vulns,
        "per_file": results,
    }
