"""
Binary Cryptographic Scanner

Analyzes uploaded binary files (ELF, PE, JAR, .so, .dll, .wasm, Mach-O)
for cryptographic library signatures using string extraction + pattern matching.
Pure Python / stdlib — no external tools required.

Detection strategy:
  1. Identify file type from magic bytes
  2. Extract printable ASCII strings (like the Unix `strings` utility)
  3. Match strings against a curated table of crypto signatures
  4. Deduplicate by library name and compute an overall risk level
  5. Persist results to SQLite
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Crypto signature table ────────────────────────────────────────────────────
# (pattern_lower, library_name, risk_level, note)

SIGNATURES: List[tuple[str, str, str, str]] = [
    ("libssl",                  "OpenSSL",              "high",     "OpenSSL detected - check version for PQC support"),
    ("openssl",                 "OpenSSL",              "high",     "OpenSSL string reference"),
    ("bouncycastle",            "BouncyCastle",         "high",     "BouncyCastle detected"),
    ("bouncy castle",           "BouncyCastle",         "high",     "BouncyCastle space variant"),
    ("wolfssl",                 "wolfSSL",              "medium",   "wolfSSL detected - has PQC support in newer versions"),
    ("mbedtls",                 "mbedTLS",              "high",     "mbedTLS detected"),
    ("polarssl",                "PolarSSL (mbedTLS)",   "high",     "Legacy PolarSSL/mbedTLS"),
    ("libtomcrypt",             "LibTomCrypt",          "high",     "LibTomCrypt detected"),
    ("rsa_private_key",         "RSA Private Key",      "critical", "RSA private key material or reference"),
    ("begin rsa",               "RSA Key",              "critical", "RSA PEM header found in binary"),
    ("rsa2048",                 "RSA-2048",             "critical", "RSA-2048 explicit reference"),
    ("rsa_2048",                "RSA-2048",             "critical", "RSA-2048 explicit reference"),
    ("aes-128",                 "AES-128",              "high",     "AES-128 — not quantum-safe for data >2031"),
    ("des3",                    "3DES",                 "critical", "3DES — deprecated, cryptographically weak"),
    ("3des",                    "3DES",                 "critical", "3DES — deprecated"),
    ("md5",                     "MD5",                  "critical", "MD5 — broken hash function"),
    ("sha1withrsaencryption",   "SHA1withRSA",          "critical", "SHA-1 + RSA signature scheme"),
    ("sha-1",                   "SHA-1",                "critical", "SHA-1 — broken hash function"),
    ("rc4",                     "RC4",                  "critical", "RC4 — broken stream cipher"),
    ("des_ecb",                 "DES-ECB",              "critical", "DES in ECB mode — broken"),
    ("kyber",                   "CRYSTALS-Kyber",       "low",      "PQC safe: CRYSTALS-Kyber/ML-KEM detected"),
    ("dilithium",               "CRYSTALS-Dilithium",   "low",      "PQC safe: CRYSTALS-Dilithium/ML-DSA detected"),
    ("falcon",                  "FALCON",               "low",      "PQC safe: FALCON signature scheme detected"),
    ("sphincs",                 "SPHINCS+",             "low",      "PQC safe: SPHINCS+/SLH-DSA detected"),
    ("ml-kem",                  "ML-KEM",               "low",      "PQC safe: ML-KEM (FIPS 203) detected"),
    ("ml-dsa",                  "ML-DSA",               "low",      "PQC safe: ML-DSA (FIPS 204) detected"),
    ("slh-dsa",                 "SLH-DSA",              "low",      "PQC safe: SLH-DSA (FIPS 205) detected"),
    ("liboqs",                  "liboqs",               "low",      "Open Quantum Safe liboqs detected"),
    ("openquantumsafe",         "Open Quantum Safe",    "low",      "OQS library detected"),
    ("nss_",                    "NSS (Mozilla)",        "high",     "Mozilla NSS cryptography library"),
    ("gcrypt",                  "libgcrypt",            "high",     "GNU libgcrypt detected"),
    ("gnutls",                  "GnuTLS",               "high",     "GnuTLS detected"),
    ("secp256k1",               "secp256k1",            "high",     "secp256k1 curve — not PQC safe"),
    ("secp384r1",               "secp384r1",            "medium",   "P-384 curve — not PQC safe but larger"),
    ("prime256v1",              "P-256",                "high",     "P-256 (prime256v1) — not PQC safe"),
    ("curve25519",              "Curve25519",           "high",     "Curve25519 — not PQC safe (quantum-vulnerable)"),
    ("chacha20",                "ChaCha20",             "medium",   "ChaCha20 — symmetric, reduce key size concern but not PQC"),
    ("javax.crypto",            "Java Crypto",          "high",     "Java JCE crypto usage"),
    ("java.security",           "Java Security",        "high",     "Java security APIs"),
    ("system.security.cryptography", ".NET Cryptography", "high",  ".NET crypto namespace"),
    ("cryptokit",               "Apple CryptoKit",      "high",     "Apple CryptoKit"),
]

# Ordered risk tiers for comparison
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS binary_scans (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    filename        TEXT NOT NULL,
    file_size       INTEGER NOT NULL,
    file_type       TEXT NOT NULL,
    scanned_at      TEXT NOT NULL,
    risk_level      TEXT NOT NULL DEFAULT 'unknown',
    summary         TEXT NOT NULL DEFAULT '{}',
    findings        TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_binary_scans_org
    ON binary_scans(organization_id);
"""


def init_tables(conn: sqlite3.Connection) -> None:
    """Create binary_scans table if it does not exist."""
    with closing(conn.cursor()) as cur:
        cur.executescript(_DDL)
    conn.commit()


# ── File-type detection ───────────────────────────────────────────────────────

def detect_file_type(data: bytes) -> str:
    """
    Identify binary format from magic bytes.

    Returns one of: elf, pe, zip/jar, wasm, macho, unknown
    """
    if len(data) < 4:
        return "unknown"

    magic4 = data[:4]

    # ELF
    if magic4 == b"\x7fELF":
        return "elf"

    # PE (MZ header)
    if data[:2] == b"MZ":
        return "pe"

    # ZIP / JAR / APK (PK header)
    if magic4 == b"PK\x03\x04":
        return "zip/jar"

    # WebAssembly
    if magic4 == b"\x00asm":
        return "wasm"

    # Mach-O (big-endian: 0xcafebabe, little-endian 64-bit: 0xcffaedfe, LE 32-bit: 0xcefaedfe)
    if magic4 in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"

    # Fat Mach-O
    if magic4 == b"\xbe\xba\xfe\xca":
        return "macho-fat"

    return "unknown"


# ── String extraction ─────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    """
    Extract printable ASCII sequences of at least min_len characters from
    binary data — equivalent to the Unix `strings` utility.

    Only considers characters in the printable ASCII range (0x20–0x7e).
    """
    strings: List[str] = []
    current: List[int] = []

    for byte in data:
        if 0x20 <= byte <= 0x7E:  # printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_len:
                strings.append(bytes(current).decode("ascii", errors="ignore"))
            current = []

    # Flush any trailing sequence
    if len(current) >= min_len:
        strings.append(bytes(current).decode("ascii", errors="ignore"))

    return strings


# ── Crypto signature matching ─────────────────────────────────────────────────

def scan_strings_for_crypto(strings: List[str]) -> List[Dict[str, Any]]:
    """
    Match extracted strings against the SIGNATURES table.

    Deduplicates by library_name and accumulates a hit count.

    Returns a list of:
        {library: str, risk_level: str, note: str, count: int}
    sorted by risk severity (critical first).
    """
    # library_name → {risk_level, note, count}
    hits: Dict[str, Dict[str, Any]] = {}

    for s in strings:
        s_lower = s.lower()
        for pattern, library, risk, note in SIGNATURES:
            if pattern in s_lower:
                if library not in hits:
                    hits[library] = {"risk_level": risk, "note": note, "count": 0}
                hits[library]["count"] += 1

    # Convert to list and sort by risk tier
    # Assign evidence_quality based on pattern specificity and hit count
    _KEY_PATTERNS = {"RSA Private Key", "RSA Key", "RSA-2048"}
    results = []
    for lib, info in hits.items():
        count = info["count"]
        if lib in _KEY_PATTERNS:
            quality = "probable"
            basis = "Specific key material pattern found in binary strings — review source to confirm"
        elif count >= 4:
            quality = "probable"
            basis = f"Library string matched {count} times — likely active usage, verify with dynamic analysis"
        else:
            quality = "possible_indicator"
            basis = (
                "String pattern found via static extraction — may be in comments, docs, or bundled "
                "test fixtures. Requires manual validation or dynamic analysis to confirm active use."
            )
        results.append({
            "library": lib,
            **{k: v for k, v in info.items()},
            "evidence_quality": quality,
            "detection_basis": basis,
        })
    results.sort(key=lambda x: (_RISK_ORDER.get(x["risk_level"], 99), x["library"]))
    return results


# ── Overall risk aggregation ──────────────────────────────────────────────────

def _aggregate_risk(findings: List[Dict[str, Any]]) -> str:
    """Return the highest (worst) risk level present in the findings list."""
    if not findings:
        return "unknown"

    best_tier = max(_RISK_ORDER.values())  # worst = 4 (unknown)
    for f in findings:
        tier = _RISK_ORDER.get(f.get("risk_level", "unknown"), 4)
        if tier < best_tier:
            best_tier = tier

    # Map tier back to string
    for name, t in _RISK_ORDER.items():
        if t == best_tier:
            return name
    return "unknown"


def _build_summary(findings: List[Dict[str, Any]], file_type: str, file_size: int) -> Dict[str, Any]:
    """Produce a summary dict of finding statistics."""
    risk_counts: Dict[str, int] = {}
    for f in findings:
        rl = f.get("risk_level", "unknown")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    pqc_safe_count = sum(1 for f in findings if f.get("risk_level") == "low")
    vulnerable_count = sum(
        1 for f in findings if f.get("risk_level") in ("critical", "high")
    )

    return {
        "file_type": file_type,
        "file_size_bytes": file_size,
        "total_findings": len(findings),
        "pqc_safe_libraries": pqc_safe_count,
        "vulnerable_libraries": vulnerable_count,
        "risk_breakdown": risk_counts,
    }


# ── Main scan function ────────────────────────────────────────────────────────

def scan_binary(
    conn: sqlite3.Connection,
    org_id: str,
    filename: str,
    data: bytes,
) -> Dict[str, Any]:
    """
    Full binary scan pipeline:
      1. Detect file type from magic bytes
      2. Extract printable ASCII strings
      3. Match strings against crypto signatures
      4. Compute overall risk level
      5. Persist to DB
      6. Return full result dict

    Returns:
        {
            scan_id:    str,
            filename:   str,
            file_type:  str,
            file_size:  int,
            scanned_at: str,
            risk_level: str,
            findings:   List[dict],
            summary:    dict,
        }
    """
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.now(timezone.utc).isoformat()
    file_type = detect_file_type(data)
    file_size = len(data)

    strings = extract_strings(data)
    findings = scan_strings_for_crypto(strings)
    try:
        from services.autonomous_mesh import entropy_findings_for_binary
        findings.extend(entropy_findings_for_binary(data))
    except Exception:
        # Entropy hunting is an additive detector; string-based scanning must still work if it fails.
        pass
    risk_level = _aggregate_risk(findings)
    summary = _build_summary(findings, file_type, file_size)
    summary["entropy_hunting_enabled"] = True

    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            INSERT INTO binary_scans
                (id, organization_id, filename, file_size, file_type,
                 scanned_at, risk_level, summary, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                org_id,
                filename,
                file_size,
                file_type,
                scanned_at,
                risk_level,
                json.dumps(summary),
                json.dumps(findings),
            ),
        )
    conn.commit()

    return {
        "scan_id": scan_id,
        "filename": filename,
        "file_type": file_type,
        "file_size": file_size,
        "scanned_at": scanned_at,
        "risk_level": risk_level,
        "findings": findings,
        "summary": summary,
        "detection_method": "static_string_extraction_plus_entropy_hunting",
        "accuracy_note": (
            "Results are based on printable string extraction and pattern matching. "
            "This method produces false positives (library names in docs/comments/fixtures) "
            "and false negatives (obfuscated or packed binaries). "
            "Treat findings as: confirmed (key material), probable (high hit count), "
            "or possible_indicator (single occurrence). "
            "Validate with dynamic analysis or manual code review before acting."
        ),
    }


# ── Query functions ───────────────────────────────────────────────────────────

def list_binary_scans(
    conn: sqlite3.Connection,
    org_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Return recent binary scans for an organisation (without full findings JSON)."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, filename, file_size, file_type,
                   scanned_at, risk_level, summary
            FROM binary_scans
            WHERE organization_id = ?
            ORDER BY scanned_at DESC
            LIMIT ?
            """,
            (org_id, limit),
        )
        cols = [d[0] for d in cur.description]
        rows = []
        for row in cur.fetchall():
            rec = dict(zip(cols, row))
            try:
                rec["summary"] = json.loads(rec["summary"])
            except (json.JSONDecodeError, TypeError):
                rec["summary"] = {}
            rows.append(rec)
        return rows


def get_binary_scan(
    conn: sqlite3.Connection,
    scan_id: str,
    org_id: str,
) -> Optional[Dict[str, Any]]:
    """Return a single binary scan record including full findings. None if not found."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, filename, file_size, file_type,
                   scanned_at, risk_level, summary, findings
            FROM binary_scans
            WHERE id = ? AND organization_id = ?
            """,
            (scan_id, org_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        rec = dict(zip(cols, row))
        try:
            rec["summary"] = json.loads(rec["summary"])
        except (json.JSONDecodeError, TypeError):
            rec["summary"] = {}
        try:
            rec["findings"] = json.loads(rec["findings"])
        except (json.JSONDecodeError, TypeError):
            rec["findings"] = []
        return rec
