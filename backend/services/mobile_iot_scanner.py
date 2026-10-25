"""
Mobile & IoT Crypto Scanner.
Scans Android APKs, iOS IPAs, embedded firmware, and RTOS images for
vulnerable or quantum-unsafe cryptographic library usage.
Extends binary_scanner with mobile/IoT-specific file handling and signatures.
"""
from __future__ import annotations
import io
import json
import sqlite3
import struct
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_DDL = """CREATE TABLE IF NOT EXISTS mobile_iot_scans (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    platform TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL DEFAULT '[]',
    finding_count INTEGER NOT NULL DEFAULT 0,
    pq_unsafe_count INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'unknown',
    embedded_certs TEXT NOT NULL DEFAULT '[]',
    cert_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
)"""

# ── Platform signatures ────────────────────────────────────────────────────────
# Each entry: (pattern_bytes_or_str, library_name, algorithm, pq_safe, description)

_IOT_SIGNATURES: List[Tuple[str, str, str, bool, str]] = [
    # --- Embedded TLS stacks ---
    ("mbedtls_",        "mbedTLS",          "TLS/AES/RSA",   False, "ARM mbedTLS (formerly PolarSSL)"),
    ("MBEDTLS_",        "mbedTLS",          "TLS/AES/RSA",   False, "ARM mbedTLS config macro"),
    ("polarssl_",       "PolarSSL",         "TLS/RSA",       False, "Legacy PolarSSL (deprecated)"),
    ("wolfSSL_",        "wolfSSL",          "TLS/RSA/ECC",   False, "wolfSSL embedded TLS"),
    ("wolfssl_",        "wolfSSL",          "TLS/RSA/ECC",   False, "wolfSSL embedded TLS"),
    ("CyaSSL_",         "CyaSSL",           "TLS/RSA",       False, "CyaSSL (legacy wolfSSL name)"),
    ("matrixSsl",       "MatrixSSL",        "TLS/RSA",       False, "MatrixSSL embedded TLS"),
    ("MATRIX_SSL",      "MatrixSSL",        "TLS/RSA",       False, "MatrixSSL config"),
    ("cyclone_ssl",     "CycloneSSL",       "TLS/ECC",       False, "CycloneSSL (Oryx Embedded)"),
    ("tinydtls_",       "tinydtls",         "DTLS/AES",      False, "tinyDTLS (Contiki IoT)"),
    ("lwip_ssl",        "lwIPSSL",          "TLS/AES",       False, "lwIP SSL layer"),

    # --- Crypto libraries ---
    ("libtomcrypt",     "LibTomCrypt",      "RSA/AES/ECC",   False, "LibTomCrypt portable crypto"),
    ("ltc_",            "LibTomCrypt",      "RSA/AES",       False, "LibTomCrypt API prefix"),
    ("nettle_",         "Nettle",           "RSA/AES/ECC",   False, "GNU Nettle crypto library"),
    ("gcry_",           "libgcrypt",        "RSA/AES/ECC",   False, "libgcrypt (GnuPG backend)"),
    ("miracl_",         "MIRACL",           "RSA/ECC",       False, "MIRACL crypto SDK"),
    ("mpin_",           "MIRACL",           "RSA/ECC",       False, "MIRACL M-Pin protocol"),
    ("crypto_sign",     "NaCl/libsodium",   "Ed25519",       True,  "NaCl signature (likely Ed25519)"),
    ("crypto_box",      "NaCl/libsodium",   "X25519/Salsa20", True, "NaCl box (X25519 + Salsa20)"),
    ("sodium_init",     "libsodium",        "Modern",        True,  "libsodium initialised"),
    ("botan_",          "Botan",            "RSA/ECC/XMSS",  False, "Botan C++ crypto"),

    # --- Classical crypto functions in firmware ---
    ("RSA_public_encrypt",  "OpenSSL/RSA",  "RSA",           False, "RSA encryption (OpenSSL)"),
    ("RSA_private_decrypt", "OpenSSL/RSA",  "RSA",           False, "RSA decryption (OpenSSL)"),
    ("ECDSA_sign",          "OpenSSL/ECDSA","ECDSA",         False, "ECDSA sign (OpenSSL)"),
    ("DES_ecb_encrypt",     "OpenSSL/DES",  "3DES",          False, "3DES encryption - deprecated"),
    ("MD5_Init",            "OpenSSL/MD5",  "MD5",           False, "MD5 hash - broken"),
    ("SHA1_Init",           "OpenSSL/SHA1", "SHA-1",         False, "SHA-1 - weak"),
    ("AES_encrypt",         "OpenSSL/AES",  "AES",           False, "AES encryption (OpenSSL)"),
    ("EVP_CIPHER_CTX",      "OpenSSL/EVP",  "AES/RSA",       False, "OpenSSL EVP (cipher context)"),
    ("BN_mod_exp",          "OpenSSL/BN",   "RSA/DH",        False, "Big-number modexp (RSA/DH)"),
    ("PKCS5_PBKDF2_HMAC",   "OpenSSL",      "PBKDF2",        False, "PBKDF2 key derivation"),

    # --- RTOS / bootloader crypto ---
    ("FreeRTOS",        "FreeRTOS",         "RTOS",          False, "FreeRTOS marker"),
    ("xSemaphoreGive",  "FreeRTOS",         "RTOS",          False, "FreeRTOS primitive"),
    ("Contiki",         "ContikiOS",        "RTOS/IoT",      False, "Contiki IoT OS marker"),
    ("RIOT",            "RIOT-OS",          "RTOS/IoT",      False, "RIOT embedded OS marker"),
    ("u-boot",          "U-Boot",           "Bootloader",    False, "U-Boot bootloader"),
    ("U-Boot",          "U-Boot",           "Bootloader",    False, "U-Boot bootloader"),
    ("Zephyr",          "ZephyrRTOS",       "RTOS",          False, "Zephyr RTOS marker"),
    ("SECURE_BOOT",     "SecureBoot",       "Boot integrity", False, "Secure Boot marker"),
    ("secure_boot",     "SecureBoot",       "Boot integrity", False, "Secure Boot marker"),
    ("TrustZone",       "TrustZone",        "TEE",           False, "ARM TrustZone (may use RSA)"),
    ("OP-TEE",          "OP-TEE",           "TEE/RSA",       False, "OP-TEE trusted execution env"),

    # --- Android-specific ---
    ("android.security.keystore",  "AndroidKeystore", "RSA/ECC", False, "Android Keystore system"),
    ("javax.crypto",               "JavaCrypto",      "RSA/AES",  False, "Android javax.crypto"),
    ("Cipher.getInstance",         "JavaCrypto",      "AES/RSA",  False, "Android Cipher.getInstance"),
    ("KeyPairGenerator",           "JavaCrypto",      "RSA/EC",   False, "Android KeyPairGenerator"),
    ("PKCS12",                     "PKCS12",          "RSA/cert", False, "PKCS#12 keystore"),

    # --- iOS / Apple ---
    ("SecKeyCreateWithData",       "AppleSecurity",   "RSA/ECC", False, "Apple Security framework key"),
    ("SecKeyRawSign",              "AppleSecurity",   "RSA/ECDSA", False, "Apple raw signing"),
    ("CCRSACryptorCreate",         "CommonCrypto",    "RSA",      False, "Apple CommonCrypto RSA"),
    ("CCKeyDerivationPBKDF",       "CommonCrypto",    "PBKDF2",   False, "Apple PBKDF2"),
    ("kSecAttrKeyTypeRSA",         "AppleSecurity",   "RSA",      False, "Apple RSA key attribute"),
    ("kSecAttrKeyTypeECSECPrime",  "AppleSecurity",   "ECDSA/P-256", False, "Apple EC P-256 key"),

    # --- quantum-safe signals ---
    ("CRYSTALS-Kyber",  "Kyber/ML-KEM",     "ML-KEM",        True, "NIST post-quantum: ML-KEM (Kyber)"),
    ("Kyber768",        "Kyber/ML-KEM",     "ML-KEM-768",    True, "ML-KEM-768"),
    ("CRYSTALS-Dilithium", "Dilithium",     "ML-DSA",        True, "NIST post-quantum: ML-DSA (Dilithium)"),
    ("SPHINCS",         "SPHINCS+",         "SLH-DSA",       True, "NIST post-quantum: SLH-DSA (SPHINCS+)"),
    ("liboqs",          "liboqs",           "Post-quantum suite",     True, "Open Quantum Safe library"),
    ("OQS_SIG",         "liboqs",           "Post-quantum signatures", True, "liboqs post-quantum signature"),
    ("OQS_KEM",         "liboqs",           "Post-quantum KEM",       True, "liboqs post-quantum KEM"),
    ("pqcrypto",        "pqcrypto",         "Post-quantum suite",     True, "pqcrypto library"),
    ("NTRU",            "NTRU",             "NTRU-KEM",      True, "NTRU post-quantum KEM"),
    ("FALCON",          "Falcon",           "Falcon-DSA",    True, "Falcon post-quantum signature"),
]


def init_tables(conn: sqlite3.Connection) -> None:
    conn.execute(_DDL)
    conn.commit()


# ── Platform detection ─────────────────────────────────────────────────────────

def detect_platform(filename: str, data: bytes) -> str:
    """Classify the uploaded file into a platform category."""
    fname = filename.lower()

    # Android APK: ZIP file containing classes.dex
    if fname.endswith(".apk") or (data[:2] == b"PK" and _zip_has_entry(data, "classes.dex")):
        return "android_apk"

    # iOS IPA: ZIP file with Payload/ directory containing Mach-O
    if fname.endswith(".ipa") or (data[:2] == b"PK" and _zip_has_prefix(data, "Payload/")):
        return "ios_ipa"

    # Generic ZIP/AAR/AAB (Android archive)
    if fname.endswith((".aar", ".aab")):
        return "android_archive"

    # ELF binary (Linux firmware / RTOS)
    if data[:4] == b"\x7fELF":
        # Distinguish RTOS vs bare-metal by string content
        strings = _extract_strings_fast(data[:65536])
        joined = " ".join(strings)
        if any(x in joined for x in ("FreeRTOS", "Zephyr", "RIOT", "Contiki")):
            return "rtos_firmware"
        if any(x in joined for x in ("U-Boot", "u-boot", "bootcmd")):
            return "bootloader"
        return "linux_firmware"

    # Mach-O (iOS binary)
    if len(data) >= 4 and struct.unpack(">I", data[:4])[0] in (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE):
        return "macho_binary"

    # PE (Windows IoT / embedded Windows)
    if data[:2] == b"MZ":
        return "pe_windows_iot"

    # Raw firmware heuristic: high entropy binary without a known magic
    if len(data) > 1024:
        return "raw_firmware"

    return "unknown"


def _zip_has_entry(data: bytes, entry: str) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return entry in zf.namelist()
    except Exception:
        return False


def _zip_has_prefix(data: bytes, prefix: str) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return any(n.startswith(prefix) for n in zf.namelist())
    except Exception:
        return False


def _extract_strings_fast(data: bytes, min_len: int = 6) -> List[str]:
    """Fast printable-ASCII string extractor."""
    results, buf = [], []
    for byte in data:
        if 32 <= byte <= 126:
            buf.append(chr(byte))
        else:
            if len(buf) >= min_len:
                results.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        results.append("".join(buf))
    return results


# ── APK / IPA inner scanning ───────────────────────────────────────────────────

def _scan_zip_contents(data: bytes, max_inner_bytes: int = 8 * 1024 * 1024) -> List[str]:
    """Extract strings from all interesting files inside a ZIP (APK/IPA)."""
    strings: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                name = info.filename.lower()
                # Target executable / library files
                if any(name.endswith(ext) for ext in (".dex", ".so", ".dylib", ".o", ".a", ".jar", ".class")):
                    if info.file_size > max_inner_bytes:
                        continue
                    try:
                        inner = zf.read(info.filename)
                        strings.extend(_extract_strings_fast(inner))
                    except Exception:
                        pass
    except Exception:
        pass
    return strings


# ── Certificate extraction ─────────────────────────────────────────────────────

def _extract_pem_certs(strings: List[str]) -> List[Dict]:
    """Find embedded PEM certificate blocks and classify them."""
    certs: List[Dict] = []
    pem_data = "\n".join(strings)
    import re
    # Look for BEGIN CERTIFICATE blocks
    pattern = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL)
    for match in pattern.finditer(pem_data):
        b64 = match.group(1).replace("\n", "").replace(" ", "").strip()
        try:
            import base64
            der = base64.b64decode(b64 + "==")
            # Quick parse: look for RSA/EC OIDs in the DER
            algo = "unknown"
            if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01" in der:
                algo = "RSA"
            elif b"\x2a\x86\x48\xce\x3d" in der:
                algo = "EC"
            certs.append({"algorithm": algo, "pq_safe": False, "size_bytes": len(der)})
        except Exception:
            certs.append({"algorithm": "unknown", "pq_safe": False, "size_bytes": 0})
    return certs[:50]  # cap to avoid huge result sets


# ── Main scan ─────────────────────────────────────────────────────────────────

def _match_signatures(strings: List[str]) -> List[Dict]:
    """Match strings against IoT signature list. Deduplicates by library name."""
    string_blob = "\n".join(strings)
    seen: Dict[str, Dict] = {}
    for pattern, library, algorithm, pq_safe, description in _IOT_SIGNATURES:
        if pattern in string_blob and library not in seen:
            risk = "safe" if pq_safe else ("critical" if "RSA" in algorithm or "DES" in algorithm or "MD5" in algorithm else "high")
            seen[library] = {
                "library": library,
                "algorithm": algorithm,
                "pq_safe": pq_safe,
                "risk_level": risk,
                "description": description,
                "matched_pattern": pattern,
            }
    return list(seen.values())


def _overall_risk(findings: List[Dict]) -> str:
    if not findings:
        return "unknown"
    unsafe = [f for f in findings if not f.get("pq_safe")]
    if not unsafe:
        return "low"
    risk_scores = [f.get("risk_level", "high") for f in unsafe]
    if "critical" in risk_scores:
        return "critical"
    if "high" in risk_scores:
        return "high"
    return "medium"


def scan_mobile_iot(conn: sqlite3.Connection, org_id: str,
                    filename: str, data: bytes) -> Dict[str, Any]:
    platform = detect_platform(filename, data)

    # Collect strings based on platform type
    if platform in ("android_apk", "ios_ipa", "android_archive"):
        strings = _scan_zip_contents(data)
        # Also scan the outer ZIP's string table
        strings += _extract_strings_fast(data[:4096])
    else:
        # Raw binary / ELF / Mach-O / PE
        strings = _extract_strings_fast(data)

    findings = _match_signatures(strings)
    certs = _extract_pem_certs(strings)
    risk = _overall_risk(findings)
    pq_unsafe = sum(1 for f in findings if not f.get("pq_safe"))

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO mobile_iot_scans
           (id, organization_id, filename, platform, file_size, findings, finding_count,
            pq_unsafe_count, risk_level, embedded_certs, cert_count, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, org_id, filename, platform, len(data),
         json.dumps(findings), len(findings),
         pq_unsafe, risk,
         json.dumps(certs), len(certs), now),
    )
    conn.commit()

    return {
        "id": scan_id,
        "organization_id": org_id,
        "filename": filename,
        "platform": platform,
        "file_size": len(data),
        "findings": findings,
        "finding_count": len(findings),
        "pq_unsafe_count": pq_unsafe,
        "risk_level": risk,
        "embedded_certs": certs,
        "cert_count": len(certs),
        "created_at": now,
    }


def list_scans(conn: sqlite3.Connection, org_id: str, limit: int = 100) -> List[Dict]:
    rows = conn.execute(
        """SELECT id, organization_id, filename, platform, file_size, finding_count,
                  pq_unsafe_count, risk_level, cert_count, created_at
           FROM mobile_iot_scans WHERE organization_id=? ORDER BY created_at DESC LIMIT ?""",
        (org_id, limit),
    ).fetchall()
    cols = ["id", "organization_id", "filename", "platform", "file_size",
            "finding_count", "pq_unsafe_count", "risk_level", "cert_count", "created_at"]
    return [dict(zip(cols, r)) for r in rows]


def get_scan(conn: sqlite3.Connection, scan_id: str, org_id: str) -> Optional[Dict]:
    row = conn.execute(
        """SELECT id, organization_id, filename, platform, file_size, findings, finding_count,
                  pq_unsafe_count, risk_level, embedded_certs, cert_count, created_at
           FROM mobile_iot_scans WHERE id=? AND organization_id=?""",
        (scan_id, org_id),
    ).fetchone()
    if not row:
        return None
    cols = ["id", "organization_id", "filename", "platform", "file_size", "findings",
            "finding_count", "pq_unsafe_count", "risk_level", "embedded_certs",
            "cert_count", "created_at"]
    d = dict(zip(cols, row))
    d["findings"] = json.loads(d["findings"])
    d["embedded_certs"] = json.loads(d["embedded_certs"])
    return d


def delete_scan(conn: sqlite3.Connection, scan_id: str, org_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM mobile_iot_scans WHERE id=? AND organization_id=?", (scan_id, org_id)
    )
    conn.commit()
    return cur.rowcount > 0


def get_platform_stats(conn: sqlite3.Connection, org_id: str) -> Dict:
    try:
        rows = conn.execute(
            """SELECT platform, COUNT(*) as cnt, AVG(pq_unsafe_count) as avg_unsafe
               FROM mobile_iot_scans WHERE organization_id=?
               GROUP BY platform ORDER BY cnt DESC""",
            (org_id,),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM mobile_iot_scans WHERE organization_id=?", (org_id,)
        ).fetchone()[0]
        return {
            "total_scans": total or 0,
            "by_platform": [{"platform": r[0], "count": r[1], "avg_pq_unsafe": round(r[2] or 0, 1)} for r in rows],
        }
    except Exception:
        return {"total_scans": 0, "by_platform": []}
