"""Transitive Dependency Scanner — parse lockfiles and flag OSS packages using classical crypto."""
import json
import re
import time

# Known packages that bundle classical-only crypto (no PQC support)
_CLASSICAL_SIGS = {
    # Python
    "pycryptodome": {"severity": "HIGH", "reason": "RSA/AES-only, no PQC"},
    "pycrypto": {"severity": "CRITICAL", "reason": "Unmaintained, RSA/DES, no PQC"},
    "cryptography": {"severity": "MEDIUM", "reason": "Classical by default; PQC via OpenSSL 3.x only"},
    "paramiko": {"severity": "MEDIUM", "reason": "SSH using RSA/ECDSA; no PQC KEX"},
    "pyopenssl": {"severity": "MEDIUM", "reason": "Wraps OpenSSL; PQC depends on version"},
    # "rsa" is both the Python package and the Rust crate. This lookup is keyed by name only, and a
    # dict literal keeps the last duplicate, so the Rust entry below used to win and a Python
    # dependency was reported with the reason "RSA crate, classical only". One entry, worded for both.
    "rsa": {"severity": "HIGH", "reason": "Pure RSA implementation (Python rsa package / Rust rsa crate), no PQC"},
    "ecdsa": {"severity": "HIGH", "reason": "Pure ECDSA, no PQC path"},
    "jwcrypto": {"severity": "MEDIUM", "reason": "JWK/JWE using classical algorithms"},
    # Node / npm
    "node-forge": {"severity": "HIGH", "reason": "RSA/AES/TLS classical only"},
    "jsrsasign": {"severity": "HIGH", "reason": "RSA/ECDSA signing, no PQC"},
    "elliptic": {"severity": "HIGH", "reason": "ECDSA/ECDH classical curves only"},
    "node-rsa": {"severity": "HIGH", "reason": "RSA-only library"},
    "crypto-js": {"severity": "MEDIUM", "reason": "AES/SHA classical, no asymmetric PQC"},
    "jose": {"severity": "MEDIUM", "reason": "JWT/JWK; classical algorithms by default"},
    "jsonwebtoken": {"severity": "MEDIUM", "reason": "RS256/ES256 classical signing"},
    "bcrypt": {"severity": "LOW", "reason": "bcrypt is quantum-resistant for passwords"},
    "ssh2": {"severity": "MEDIUM", "reason": "SSH using RSA/ECDSA; no PQC KEX"},
    # Java (Maven artifact IDs)
    "bcprov-jdk15on": {"severity": "MEDIUM", "reason": "Bouncy Castle classical; PQC via bcpqc jar"},
    "bcprov-jdk18on": {"severity": "MEDIUM", "reason": "Bouncy Castle classical; PQC via bcpqc jar"},
    # Go modules
    "golang.org/x/crypto": {"severity": "LOW", "reason": "Mostly classical; ML-KEM in newer versions"},
    "github.com/cloudflare/circl": {"severity": "LOW", "reason": "Has PQC — verify version ≥1.3"},
    # Rust crates ("rsa" is covered by the shared entry above)
    "p256": {"severity": "HIGH", "reason": "ECDSA P-256, no PQC"},
    "ring": {"severity": "MEDIUM", "reason": "Classical TLS crypto; no PQC"},
}

_LOW = {"LOW", "MEDIUM"}
_HIGH = {"HIGH", "CRITICAL"}


def _parse_npm_lock(content: str) -> list[str]:
    """Extract package names from package-lock.json."""
    try:
        data = json.loads(content)
        packages = data.get("packages", data.get("dependencies", {}))
        names = []
        for key in packages:
            name = key.lstrip("/").split("node_modules/")[-1]
            if name and not name.startswith("."):
                names.append(name)
        return names
    except Exception:
        return []


def _parse_requirements(content: str) -> list[str]:
    """Extract package names from requirements.txt or Pipfile.lock."""
    names = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip version specifiers
        pkg = re.split(r"[>=<!;\[]", line)[0].strip().lower()
        if pkg:
            names.append(pkg)
    return names


def _parse_pipfile_lock(content: str) -> list[str]:
    try:
        data = json.loads(content)
        names = []
        for section in ("default", "develop"):
            names.extend(data.get(section, {}).keys())
        return [n.lower() for n in names]
    except Exception:
        return []


def _parse_go_sum(content: str) -> list[str]:
    names = set()
    for line in content.splitlines():
        parts = line.split()
        if parts:
            mod = parts[0].split("@")[0]
            names.add(mod)
    return list(names)


def _parse_cargo_lock(content: str) -> list[str]:
    names = []
    for line in content.splitlines():
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            names.append(m.group(1))
    return names


def _parse_pom(content: str) -> list[str]:
    return re.findall(r"<artifactId>([^<]+)</artifactId>", content)


_PARSERS = {
    "package-lock.json": _parse_npm_lock,
    "yarn.lock": lambda c: [m.group(1) for m in re.finditer(r'^"?([^@\s"][^@"]+)@', c, re.M)],
    "requirements.txt": _parse_requirements,
    "Pipfile.lock": _parse_pipfile_lock,
    "go.sum": _parse_go_sum,
    "Cargo.lock": _parse_cargo_lock,
    "pom.xml": _parse_pom,
}


def scan_lockfile(filename: str, content: str) -> dict:
    """Scan a lockfile string and return findings."""
    parser = _PARSERS.get(filename)
    if not parser:
        return {"error": f"Unsupported lockfile: {filename}", "findings": []}

    packages = parser(content)
    findings = []
    for pkg in packages:
        sig = _CLASSICAL_SIGS.get(pkg) or _CLASSICAL_SIGS.get(pkg.lower())
        if sig:
            # Exact name match → Confirmed; case-folded match → Probable
            exact = pkg in _CLASSICAL_SIGS
            evidence_quality = "confirmed" if exact else "probable"
            findings.append({
                "package": pkg,
                "severity": sig["severity"],
                "reason": sig["reason"],
                "lockfile": filename,
                "evidence_quality": evidence_quality,
                "detection_basis": (
                    "Exact package name match against classical-crypto signature database"
                    if exact else
                    "Case-insensitive package name match — verify manually"
                ),
            })

    high = sum(1 for f in findings if f["severity"] in _HIGH)
    return {
        "filename": filename,
        "packages_scanned": len(packages),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high_critical": high,
            "medium_low": len(findings) - high,
        },
    }


def scan_multiple(files: dict[str, str]) -> dict:
    """Scan multiple lockfiles. files = {filename: content}."""
    all_findings = []
    results = []
    for fname, content in files.items():
        r = scan_lockfile(fname, content)
        results.append(r)
        all_findings.extend(r.get("findings", []))

    high = sum(1 for f in all_findings if f["severity"] in _HIGH)
    return {
        "scanned_at": int(time.time()),
        "files": results,
        "aggregate": {
            "total_findings": len(all_findings),
            "high_critical": high,
            "risk_level": "HIGH" if high > 0 else ("MEDIUM" if all_findings else "LOW"),
        },
        "findings": all_findings,
    }
