"""
SBOM Import — CycloneDX JSON Parser & Crypto Component Extractor

Parses CycloneDX SBOM JSON (v1.4 / v1.5 spec) uploaded by a user.
Extracts cryptographic components (type="cryptographic-asset" or whose
name/description matches known crypto library names), classifies each for
Post-quantum safety and risk level, and persists the import + findings to SQLite.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Known crypto library name fragments (case-insensitive) ────────────────────

_CRYPTO_LIBS = [
    "openssl", "bouncycastle", "bouncy", "nss", "cryptography",
    "pycryptodome", "crypto", "mbedtls", "wolfssl", "bearssl",
    "libtomcrypt", "nettle", "gcrypt", "gnutls", "polarssl",
    "jsencrypt", "node-forge", "webcrypto",
]

# quantum-safe algorithm name fragments
_MORROW_SAFE_FRAGMENTS = [
    "kyber", "dilithium", "falcon", "sphincs",
    "ml-kem", "ml-dsa", "slh-dsa",
]


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS sbom_imports (
    id                    TEXT PRIMARY KEY,
    organization_id       TEXT NOT NULL,
    filename              TEXT NOT NULL,
    sbom_format           TEXT,
    sbom_version          TEXT,
    component_count       INTEGER DEFAULT 0,
    crypto_component_count INTEGER DEFAULT 0,
    imported_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sbom_crypto_components (
    id             TEXT PRIMARY KEY,
    import_id      TEXT NOT NULL REFERENCES sbom_imports(id) ON DELETE CASCADE,
    name           TEXT,
    version        TEXT,
    algorithm      TEXT,
    key_length     INTEGER,
    pq_safe       INTEGER NOT NULL DEFAULT 0,
    risk_level     TEXT NOT NULL DEFAULT 'unknown',
    component_type TEXT,
    supplier       TEXT,
    description    TEXT
);

CREATE INDEX IF NOT EXISTS idx_sbom_imports_org
    ON sbom_imports(organization_id);
CREATE INDEX IF NOT EXISTS idx_sbom_components_import
    ON sbom_crypto_components(import_id);
"""


def init_tables(conn: sqlite3.Connection) -> None:
    """Create SBOM tables if they do not exist."""
    with closing(conn.cursor()) as cur:
        cur.executescript(_DDL)
    conn.commit()


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_cyclonedx_json(json_bytes: bytes) -> Dict[str, Any]:
    """
    Parse a CycloneDX JSON SBOM (v1.4 / v1.5).

    Returns:
        {
            "components": [...],   # flat list of component dicts from the SBOM
            "metadata":  {...},    # top-level metadata block (or {})
            "version":   str,      # specVersion string
        }

    Raises ValueError on malformed JSON or missing required fields.
    """
    try:
        doc = json.loads(json_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError("SBOM root must be a JSON object")

    spec_version: str = doc.get("specVersion", "unknown")
    metadata: Dict[str, Any] = doc.get("metadata", {})

    # Components can live at root or nested inside metadata (v1.5 compositions)
    components: List[Dict[str, Any]] = []

    def _collect(comp_list: Any) -> None:
        if not isinstance(comp_list, list):
            return
        for item in comp_list:
            if not isinstance(item, dict):
                continue
            components.append(item)
            # Recurse into nested components
            _collect(item.get("components", []))

    _collect(doc.get("components", []))

    return {
        "components": components,
        "metadata": metadata,
        "version": spec_version,
    }


# ── Classification ────────────────────────────────────────────────────────────

def _is_crypto_component(comp: Dict[str, Any]) -> bool:
    """Return True if this component is crypto-related."""
    if comp.get("type", "").lower() == "cryptographic-asset":
        return True

    name = (comp.get("name") or "").lower()
    desc = (comp.get("description") or "").lower()
    combined = f"{name} {desc}"
    return any(lib in combined for lib in _CRYPTO_LIBS)


def _extract_algorithm(comp: Dict[str, Any]) -> tuple[str, int | None]:
    """
    Extract (algorithm, key_length) from a CycloneDX component.

    Checks (in order):
      1. cryptoProperties block (v1.5)
      2. properties[] list looking for 'algorithm' / 'keyLength' / 'keySize'
      3. name heuristics
    """
    algorithm = ""
    key_length: Optional[int] = None

    # 1. cryptoProperties (CycloneDX v1.5)
    crypto_props = comp.get("cryptoProperties", {})
    if isinstance(crypto_props, dict):
        algorithm = crypto_props.get("algorithmProperties", {}).get("primitive", "") or ""
        if not algorithm:
            algorithm = crypto_props.get("name", "") or ""
        kl = crypto_props.get("algorithmProperties", {}).get("parameterSetIdentifier", "")
        if kl and kl.isdigit():
            key_length = int(kl)

    # 2. properties[] list
    properties = comp.get("properties", []) or []
    if isinstance(properties, list):
        for prop in properties:
            if not isinstance(prop, dict):
                continue
            pname = (prop.get("name") or "").lower()
            pval = prop.get("value", "") or ""
            if pname in ("algorithm", "algorithmprimitive", "cipher") and pval:
                if not algorithm:
                    algorithm = pval
            if pname in ("keylength", "keysize", "keylen") and pval:
                try:
                    key_length = int(str(pval).strip())
                except ValueError:
                    pass

    # 3. Fall back to component name
    if not algorithm:
        algorithm = (comp.get("name") or "").strip()

    return algorithm, key_length


def classify_crypto_component(comp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a CycloneDX component dict, return a classification dict:

        {
            name:         str,
            version:      str,
            algorithm:    str,
            key_length:   int | None,
            pq_safe:     bool,
            risk_level:   str,   # critical / high / medium / low / unknown
            component_type: str,
            supplier:     str,
            description:  str,
        }
    """
    name: str = (comp.get("name") or "").strip()
    version: str = (comp.get("version") or "").strip()
    comp_type: str = (comp.get("type") or "library").strip()
    description: str = (comp.get("description") or "").strip()

    # Supplier
    supplier_block = comp.get("supplier") or comp.get("manufacturer") or {}
    if isinstance(supplier_block, dict):
        supplier = supplier_block.get("name", "")
    else:
        supplier = str(supplier_block)

    algorithm, key_length = _extract_algorithm(comp)

    # Post-quantum safety check
    algo_lower = algorithm.lower()
    name_lower = name.lower()
    pq_safe = any(f in algo_lower or f in name_lower for f in _MORROW_SAFE_FRAGMENTS)

    # Risk classification
    risk_level = _classify_risk(algorithm, key_length, name_lower)

    return {
        "name": name,
        "version": version,
        "algorithm": algorithm,
        "key_length": key_length,
        "pq_safe": pq_safe,
        "risk_level": risk_level,
        "component_type": comp_type,
        "supplier": supplier,
        "description": description,
    }


def _classify_risk(algorithm: str, key_length: Optional[int], name_lower: str) -> str:
    """
    Derive risk level from algorithm name + key length.

    critical : RSA < 4096 bits, DES, 3DES, MD5, SHA-1
    high     : AES-128, RSA-2048, ECC-256
    medium   : AES-256, RSA-3072
    low      : post-quantum algorithms, or unknown / no algorithm
    """
    algo = algorithm.lower()
    combined = f"{algo} {name_lower}"

    # Broken algorithms — always critical
    for broken in ("des3", "3des", "des_", " des", "md5", "sha-1", "sha1", "rc4"):
        if broken in combined:
            return "critical"

    # RSA key-length aware
    if "rsa" in combined:
        bits = key_length or _guess_key_bits_from_name(combined)
        if bits and bits < 4096:
            if bits <= 2048:
                return "critical"
            return "medium"  # RSA-3072 = medium
        if bits and bits >= 4096:
            return "medium"
        return "critical"  # RSA without known key size — assume worst

    # ECC / ECDSA / ECDH
    if any(x in combined for x in ("ecdsa", "ecdh", "ecc", "elliptic", "p-256", "p256", "secp256")):
        bits = key_length or 256
        if bits <= 256:
            return "high"
        return "medium"

    # AES
    if "aes-128" in combined or "aes128" in combined:
        return "high"
    if "aes-256" in combined or "aes256" in combined or "aes-192" in combined:
        return "medium"
    if "aes" in combined:
        return "high"  # unspecified AES treated as potentially weak

    # Post-quantum safe algorithms
    if any(f in combined for f in _MORROW_SAFE_FRAGMENTS):
        return "low"

    return "unknown"


def _guess_key_bits_from_name(text: str) -> Optional[int]:
    """Try to extract a numeric key size from a name like 'rsa-2048' or 'rsa2048'."""
    import re
    m = re.search(r"(\d{3,5})", text)
    if m:
        val = int(m.group(1))
        # Plausible key sizes
        if val in (512, 1024, 2048, 3072, 4096, 8192):
            return val
    return None


# ── Database operations ───────────────────────────────────────────────────────

def import_sbom(
    conn: sqlite3.Connection,
    org_id: str,
    filename: str,
    json_bytes: bytes,
) -> Dict[str, Any]:
    """
    Full import flow:
      1. Parse CycloneDX JSON
      2. Filter + classify crypto components
      3. Persist import record and all components
      4. Return summary dict

    Raises ValueError on parse errors.
    """
    parsed = parse_cyclonedx_json(json_bytes)

    components = parsed["components"]
    parsed["metadata"]
    spec_version = parsed["version"]

    # Determine SBOM format from bomFormat field (default CycloneDX)
    raw_doc = json.loads(json_bytes)
    sbom_format = raw_doc.get("bomFormat", "CycloneDX")

    import_id = str(uuid.uuid4())
    imported_at = datetime.now(timezone.utc).isoformat()

    # Filter to crypto-relevant components and classify each
    crypto_rows: List[Dict[str, Any]] = []
    for comp in components:
        if _is_crypto_component(comp):
            classified = classify_crypto_component(comp)
            classified["id"] = str(uuid.uuid4())
            classified["import_id"] = import_id
            crypto_rows.append(classified)

    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            INSERT INTO sbom_imports
                (id, organization_id, filename, sbom_format, sbom_version,
                 component_count, crypto_component_count, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                org_id,
                filename,
                sbom_format,
                spec_version,
                len(components),
                len(crypto_rows),
                imported_at,
            ),
        )

        cur.executemany(
            """
            INSERT INTO sbom_crypto_components
                (id, import_id, name, version, algorithm, key_length,
                 pq_safe, risk_level, component_type, supplier, description)
            VALUES (:id, :import_id, :name, :version, :algorithm, :key_length,
                    :pq_safe, :risk_level, :component_type, :supplier, :description)
            """,
            [
                {
                    **row,
                    "pq_safe": 1 if row["pq_safe"] else 0,
                }
                for row in crypto_rows
            ],
        )

    conn.commit()

    risk_counts: Dict[str, int] = {}
    for row in crypto_rows:
        rl = row["risk_level"]
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    return {
        "import_id": import_id,
        "filename": filename,
        "sbom_format": sbom_format,
        "sbom_version": spec_version,
        "component_count": len(components),
        "crypto_component_count": len(crypto_rows),
        "imported_at": imported_at,
        "risk_summary": risk_counts,
        "components": crypto_rows,
    }


def list_imports(
    conn: sqlite3.Connection,
    org_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Return recent SBOM imports for an organisation."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, filename, sbom_format, sbom_version,
                   component_count, crypto_component_count, imported_at
            FROM sbom_imports
            WHERE organization_id = ?
            ORDER BY imported_at DESC
            LIMIT ?
            """,
            (org_id, limit),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def get_import_components(
    conn: sqlite3.Connection,
    import_id: str,
    org_id: str,
) -> List[Dict[str, Any]]:
    """Return all crypto components for a specific import (scoped to org)."""
    with closing(conn.cursor()) as cur:
        # Verify the import belongs to this org
        cur.execute(
            "SELECT id FROM sbom_imports WHERE id = ? AND organization_id = ?",
            (import_id, org_id),
        )
        if cur.fetchone() is None:
            return []

        cur.execute(
            """
            SELECT id, import_id, name, version, algorithm, key_length,
                   pq_safe, risk_level, component_type, supplier, description
            FROM sbom_crypto_components
            WHERE import_id = ?
            ORDER BY risk_level, name
            """,
            (import_id,),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        # Convert pq_safe back to bool
        for row in rows:
            row["pq_safe"] = bool(row["pq_safe"])
        return rows


def delete_import(
    conn: sqlite3.Connection,
    import_id: str,
    org_id: str,
) -> bool:
    """Delete an import record and all its components. Returns True if deleted."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT id FROM sbom_imports WHERE id = ? AND organization_id = ?",
            (import_id, org_id),
        )
        if cur.fetchone() is None:
            return False

        # Components cascade on delete via FK, but SQLite FK enforcement
        # may be off — delete explicitly to be safe.
        cur.execute(
            "DELETE FROM sbom_crypto_components WHERE import_id = ?",
            (import_id,),
        )
        cur.execute(
            "DELETE FROM sbom_imports WHERE id = ? AND organization_id = ?",
            (import_id, org_id),
        )

    conn.commit()
    return True
