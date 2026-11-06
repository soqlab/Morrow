"""
SBOM Import — CycloneDX JSON Parser & Crypto Component Extractor

Parses CycloneDX SBOM JSON (v1.4 / v1.5 spec) uploaded by a user.
Extracts cryptographic components (type="cryptographic-asset" or whose
name/description matches known crypto library names), classifies each for
Post-quantum safety and risk level, and persists the import + findings to SQLite.

CBOM import (import_cbom) reads CycloneDX 1.6 Cryptography Bills of Materials, such as those
produced by IBM's CBOMkit (https://github.com/cbomkit/cbomkit). It validates the document
against the vendored CycloneDX 1.6 schema (schemas/cyclonedx/), reads the four cryptographic
asset types (algorithm, protocol, certificate, related-crypto-material) with their evidence
occurrences and the document's dependency graph, and records each in the import tables above.

Both import paths also feed crypto_inventory: one row per distinct cryptographic asset per
organization, deduplicated across imports and sources by a normalized identity (see
_inventory_key). Re-importing the same CBOM, or a CBOM and an SBOM that name the same
algorithm, updates the existing row's sources, occurrences and last_seen instead of adding
another.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
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

CREATE TABLE IF NOT EXISTS crypto_inventory (
    organization_id   TEXT NOT NULL,
    inventory_key     TEXT NOT NULL,
    asset_type        TEXT NOT NULL,
    name              TEXT NOT NULL,
    algorithm         TEXT,
    primitive         TEXT,
    oid               TEXT,
    key_length        INTEGER,
    nist_pq_category  INTEGER,
    pq_safe          INTEGER NOT NULL DEFAULT 0,
    quantum_vulnerable INTEGER NOT NULL DEFAULT 0,
    risk_level        TEXT NOT NULL DEFAULT 'unknown',
    sources_json      TEXT NOT NULL DEFAULT '[]',
    import_ids_json   TEXT NOT NULL DEFAULT '[]',
    occurrences_json  TEXT NOT NULL DEFAULT '[]',
    occurrence_count  INTEGER NOT NULL DEFAULT 0,
    depends_on_json   TEXT NOT NULL DEFAULT '[]',
    details_json      TEXT NOT NULL DEFAULT '{}',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    PRIMARY KEY (organization_id, inventory_key)
);

CREATE INDEX IF NOT EXISTS idx_crypto_inventory_org_type
    ON crypto_inventory(organization_id, asset_type);
"""


def init_tables(conn: sqlite3.Connection) -> None:
    """Create SBOM tables if they do not exist."""
    with closing(conn.cursor()) as cur:
        cur.executescript(_DDL)
        cols = {row[1] for row in cur.execute("PRAGMA table_info(sbom_imports)").fetchall()}
        if "source" not in cols:
            try:
                cur.execute("ALTER TABLE sbom_imports ADD COLUMN source TEXT NOT NULL DEFAULT 'sbom'")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
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
    _check_size(json_bytes)
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

        for row in crypto_rows:
            _upsert_inventory(cur, org_id, import_id, "sbom", imported_at, {
                "asset_type": "library" if row["component_type"] != "cryptographic-asset" else "algorithm",
                "name": row["name"] or row["algorithm"],
                "algorithm": row["algorithm"],
                "key_length": row["key_length"],
                "pq_safe": row["pq_safe"],
                "risk_level": row["risk_level"],
                "details": {"version": row["version"], "supplier": row["supplier"]},
            })

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
                   component_count, crypto_component_count, imported_at, source
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


# ── Size limits ───────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


#: Largest accepted upload, in bytes. CBOMkit output for a large repository is a few MB; the
#: keycloak example in the CBOMkit repository is 60 KB.
MAX_IMPORT_BYTES = _env_int("MORROW_BOM_IMPORT_MAX_BYTES", 10 * 1024 * 1024)
#: Largest number of components (after flattening nested components) accepted in one document.
MAX_IMPORT_COMPONENTS = _env_int("MORROW_BOM_IMPORT_MAX_COMPONENTS", 20000)
#: Evidence occurrences kept per inventory row; the total is still counted.
MAX_OCCURRENCES_PER_ASSET = 50


class ImportTooLarge(ValueError):
    """The upload exceeds MAX_IMPORT_BYTES or MAX_IMPORT_COMPONENTS (HTTP 413)."""


class SchemaInvalid(ValueError):
    """The document is not valid CycloneDX 1.6 (HTTP 422)."""

    def __init__(self, message: str, errors: List[Dict[str, str]]):
        super().__init__(message)
        self.errors = errors


def _check_size(json_bytes: bytes) -> None:
    if len(json_bytes) > MAX_IMPORT_BYTES:
        raise ImportTooLarge(
            f"Document is {len(json_bytes)} bytes; the limit is {MAX_IMPORT_BYTES} bytes "
            "(MORROW_BOM_IMPORT_MAX_BYTES)."
        )


# ── CycloneDX 1.6 schema validation ───────────────────────────────────────────

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "cyclonedx"


@lru_cache(maxsize=1)
def _cyclonedx_validator():
    """Draft-7 validator for the vendored CycloneDX 1.6 schema, with its $refs resolved offline."""
    import jsonschema

    schema = json.loads((_SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((_SCHEMA_DIR / "spdx.schema.json").read_text(encoding="utf-8")),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((_SCHEMA_DIR / "jsf-0.82.schema.json").read_text(encoding="utf-8")),
    }
    try:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7

        registry = Registry().with_resources(
            (uri, Resource.from_contents(doc, default_specification=DRAFT7)) for uri, doc in store.items()
        )
        return jsonschema.Draft7Validator(schema, registry=registry)
    except ImportError:  # jsonschema < 4.18
        resolver = jsonschema.RefResolver.from_schema(schema, store=store)
        return jsonschema.Draft7Validator(schema, resolver=resolver)


def validate_cyclonedx_16(doc: Dict[str, Any]) -> None:
    """Raise SchemaInvalid unless doc validates against CycloneDX 1.6.

    Fails closed: if the validator cannot be loaded, the document is not imported.
    """
    if str(doc.get("specVersion") or "") != "1.6":
        raise SchemaInvalid(
            f"CBOM import requires CycloneDX specVersion 1.6 (got {doc.get('specVersion')!r}).", [])
    try:
        validator = _cyclonedx_validator()
    except Exception as exc:
        raise SchemaInvalid(f"CycloneDX schema validator unavailable ({exc.__class__.__name__}).", [])
    errors = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        detail = [
            {"path": "/".join(str(p) for p in e.absolute_path) or "<root>", "message": e.message[:300]}
            for e in errors[:20]
        ]
        raise SchemaInvalid(
            f"Document violates CycloneDX 1.6 ({len(errors)} error(s)); first: "
            f"{detail[0]['path']}: {detail[0]['message']}",
            detail,
        )


# ── CBOM classification ───────────────────────────────────────────────────────

_CBOM_ASSET_TYPES = ("algorithm", "protocol", "certificate", "related-crypto-material")
_ASYMMETRIC_PRIMITIVES = frozenset({"pke", "signature", "key-agree"})


def _canonicalise(name: str, param: str) -> Optional[str]:
    """services.cbom canonical key for a CBOM algorithm name such as 'EC-secp384r1' or 'AES128-GCM'."""
    from services.cbom import canonical_algorithm

    raw = (name or "").strip()
    upper = raw.upper()
    if upper.startswith("EC-"):
        raw = raw[3:]
    bits = int(param) if str(param or "").isdigit() else 0
    if bits and not re.search(r"\d", raw):
        candidate = canonical_algorithm(f"{raw}-{bits}", bits)
        if candidate:
            return candidate
    return canonical_algorithm(raw, bits)


def _classify_cbom_algorithm(name: str, primitive: str, param: str, mode: str = "") -> Dict[str, Any]:
    """Quantum and classical risk for one CBOM algorithm, from services.cbom's knowledge base
    (NIST post-quantum category) with this module's _classify_risk as the classical check."""
    from services.cbom import _ALG

    canonical = _canonicalise(name, param)
    entry = _ALG.get(canonical or "")
    # canonical_algorithm() fills in CBC when an AES name carries no mode. The knowledge-base entry
    # still gives the right quantum category, but the inventory must not claim a mode the CBOM
    # never stated: "AES" with parameterSetIdentifier 128 is recorded as AES-128.
    if canonical and canonical.endswith("-CBC") and "cbc" not in f"{name} {mode}".lower():
        canonical = canonical[: -len("-CBC")]
    nist = int(entry["nist"]) if entry else None
    prim = (primitive or (entry or {}).get("primitive") or "").lower()
    lowered = f"{name} {canonical or ''}".lower()
    pq_safe = any(f in lowered for f in _MORROW_SAFE_FRAGMENTS) or (prim == "kem" and nist not in (None, 0))
    if pq_safe:
        quantum_vulnerable = False
    elif entry:
        quantum_vulnerable = nist == 0 and prim in _ASYMMETRIC_PRIMITIVES
    else:
        # Unknown name: an asymmetric primitive that is not a recognised PQ scheme is Shor-breakable.
        quantum_vulnerable = prim in _ASYMMETRIC_PRIMITIVES
    key_length = int(param) if str(param or "").isdigit() else None
    risk = _classify_risk(canonical or name, key_length, name.lower())
    if pq_safe:
        risk = "low"
    elif risk == "unknown":
        if quantum_vulnerable:
            risk = "high"
        elif nist is not None and nist >= 1:
            risk = "low"
        elif nist == 0:
            risk = "critical"  # classically broken symmetric/hash (SHA-1, MD5, RC4, 3DES)
    return {
        "algorithm": canonical or name,
        "nist_pq_category": nist,
        "primitive": prim or None,
        "pq_safe": pq_safe,
        "quantum_vulnerable": quantum_vulnerable,
        "risk_level": risk,
        "key_length": key_length,
    }


def _occurrences(comp: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for occ in ((comp.get("evidence") or {}).get("occurrences") or []):
        if not isinstance(occ, dict):
            continue
        item = {k: occ[k] for k in ("location", "line", "offset", "symbol", "additionalContext") if k in occ}
        if item:
            out.append(item)
    return out


def _norm(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _inventory_key(asset: Dict[str, Any]) -> str:
    """Normalized identity used to deduplicate inventory rows across imports and sources.

    Algorithms collapse to their canonical name (SHA256, SHA-256 and OID 2.16.840.1.101.3.4.2.1 are
    one asset). Keys and other related material collapse to type + algorithm + size, because CBOMkit
    emits one key@<uuid> component per code location and the uuid identifies nothing. Protocols use
    type + version; certificates use subject, issuer and expiry.
    """
    t = asset["asset_type"]
    if t == "algorithm":
        ident = asset.get("algorithm") or asset.get("oid") or asset["name"]
        return f"algorithm:{_norm(ident)}"
    if t == "related-crypto-material":
        d = asset.get("details") or {}
        return "related-crypto-material:" + ":".join(
            _norm(x) for x in (d.get("material_type"), asset.get("algorithm"), asset.get("key_length") or ""))
    if t == "protocol":
        d = asset.get("details") or {}
        return f"protocol:{_norm(d.get('protocol_type') or asset['name'])}:{_norm(d.get('version'))}"
    if t == "certificate":
        d = asset.get("details") or {}
        if not (d.get("subject") or d.get("issuer")):
            return f"certificate:{_norm(asset['name'])}"
        return "certificate:" + "|".join(_norm(d.get(k)) for k in ("subject", "issuer", "not_valid_after"))
    return f"{t}:{_norm(asset['name'])}@{_norm((asset.get('details') or {}).get('version'))}"


def _upsert_inventory(cur, org_id: str, import_id: str, source: str, seen_at: str,
                      asset: Dict[str, Any]) -> str:
    """Insert asset into crypto_inventory, or merge it into the existing row with the same key."""
    key = _inventory_key(asset)
    occurrences = asset.get("occurrences") or []
    depends = sorted(set(asset.get("depends_on") or []))
    row = cur.execute(
        "SELECT sources_json, import_ids_json, occurrences_json, occurrence_count, depends_on_json, details_json "
        "FROM crypto_inventory WHERE organization_id = ? AND inventory_key = ?",
        (org_id, key),
    ).fetchone()
    if row is None:
        cur.execute(
            """
            INSERT INTO crypto_inventory
                (organization_id, inventory_key, asset_type, name, algorithm, primitive, oid, key_length,
                 nist_pq_category, pq_safe, quantum_vulnerable, risk_level, sources_json, import_ids_json,
                 occurrences_json, occurrence_count, depends_on_json, details_json, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, key, asset["asset_type"], asset["name"][:500], asset.get("algorithm"),
             asset.get("primitive"), asset.get("oid"), asset.get("key_length"),
             asset.get("nist_pq_category"), 1 if asset.get("pq_safe") else 0,
             1 if asset.get("quantum_vulnerable") else 0, asset.get("risk_level") or "unknown",
             json.dumps([source]), json.dumps([import_id]),
             json.dumps(occurrences[:MAX_OCCURRENCES_PER_ASSET]), len(occurrences),
             json.dumps(depends), json.dumps(asset.get("details") or {}), seen_at, seen_at),
        )
        return key

    sources = json.loads(row[0] or "[]")
    import_ids = json.loads(row[1] or "[]")
    kept = json.loads(row[2] or "[]")
    count = int(row[3] or 0)
    prior_depends = json.loads(row[4] or "[]")
    details = json.loads(row[5] or "{}")
    if source not in sources:
        sources.append(source)
    new_import = import_id not in import_ids
    if new_import:
        import_ids.append(import_id)
    seen = {json.dumps(o, sort_keys=True) for o in kept}
    fresh = [o for o in occurrences if json.dumps(o, sort_keys=True) not in seen]
    kept = (kept + fresh)[:MAX_OCCURRENCES_PER_ASSET]
    # Count distinct occurrences: re-importing the same document must not inflate the count.
    count += len(fresh)
    for k, v in (asset.get("details") or {}).items():
        details.setdefault(k, v)
    cur.execute(
        """
        UPDATE crypto_inventory
           SET sources_json = ?, import_ids_json = ?, occurrences_json = ?, occurrence_count = ?,
               depends_on_json = ?, details_json = ?, last_seen = ?
         WHERE organization_id = ? AND inventory_key = ?
        """,
        (json.dumps(sources), json.dumps(import_ids[-200:]), json.dumps(kept), count,
         json.dumps(sorted(set(prior_depends) | set(depends))), json.dumps(details), seen_at,
         org_id, key),
    )
    return key


def _cbom_asset(comp: Dict[str, Any], by_ref: Dict[str, Dict[str, Any]],
                deps: Dict[str, List[str]]) -> Optional[Dict[str, Any]]:
    """Normalize one cryptographic-asset component into an inventory asset (without depends_on)."""
    props = comp.get("cryptoProperties") or {}
    asset_type = str(props.get("assetType") or "")
    if asset_type not in _CBOM_ASSET_TYPES:
        return None
    name = str(comp.get("name") or "").strip() or asset_type
    oid = props.get("oid")
    asset: Dict[str, Any] = {"asset_type": asset_type, "name": name, "oid": oid,
                             "occurrences": _occurrences(comp), "details": {"bom_ref": comp.get("bom-ref")}}

    if asset_type == "algorithm":
        ap = props.get("algorithmProperties") or {}
        cls = _classify_cbom_algorithm(name, str(ap.get("primitive") or ""),
                                       str(ap.get("parameterSetIdentifier") or ""), str(ap.get("mode") or ""))
        asset.update(cls)
        asset["details"].update({k: ap[k] for k in ("mode", "padding", "curve", "cryptoFunctions",
                                                   "classicalSecurityLevel", "nistQuantumSecurityLevel")
                                 if k in ap})
        return asset

    if asset_type == "related-crypto-material":
        rp = props.get("relatedCryptoMaterialProperties") or {}
        # The algorithm a key belongs to: algorithmRef, else the dependency CBOMkit records.
        alg_ref = rp.get("algorithmRef")
        refs = [alg_ref] if alg_ref else deps.get(str(comp.get("bom-ref") or ""), [])
        algorithm = None
        cls: Dict[str, Any] = {}
        for ref in refs:
            target = by_ref.get(ref)
            if target and (target.get("cryptoProperties") or {}).get("assetType") == "algorithm":
                ap = (target["cryptoProperties"].get("algorithmProperties") or {})
                cls = _classify_cbom_algorithm(str(target.get("name") or ""), str(ap.get("primitive") or ""),
                                               str(ap.get("parameterSetIdentifier") or ""),
                                               str(ap.get("mode") or ""))
                algorithm = cls["algorithm"]
                break
        size = rp.get("size")
        material = str(rp.get("type") or "unknown")
        asset.update({
            "name": f"{material}" + (f" ({algorithm})" if algorithm else ""),
            "algorithm": algorithm,
            "key_length": int(size) if isinstance(size, int) else cls.get("key_length"),
            "pq_safe": cls.get("pq_safe", False),
            "quantum_vulnerable": cls.get("quantum_vulnerable", False),
            "nist_pq_category": cls.get("nist_pq_category"),
            "risk_level": cls.get("risk_level", "unknown"),
        })
        asset["details"].update({"material_type": material,
                                 **{k: rp[k] for k in ("state", "format", "creationDate", "expirationDate") if k in rp}})
        return asset

    if asset_type == "protocol":
        pp = props.get("protocolProperties") or {}
        suites = []
        for suite in pp.get("cipherSuites") or []:
            if isinstance(suite, dict):
                suites.append(suite.get("name") or ",".join(suite.get("identifiers") or []))
        version = str(pp.get("version") or "")
        ptype = str(pp.get("type") or name).lower()
        old = ptype in ("tls", "ssl") and version and version in ("1.0", "1.1", "2.0", "3.0")
        asset.update({"risk_level": "high" if old else "unknown"})
        asset["details"].update({"protocol_type": ptype, "version": version, "cipher_suites": suites[:100]})
        return asset

    # certificate
    cp = props.get("certificateProperties") or {}
    asset.update({"risk_level": "unknown"})
    asset["details"].update({
        "subject": cp.get("subjectName"), "issuer": cp.get("issuerName"),
        "not_valid_before": cp.get("notValidBefore"), "not_valid_after": cp.get("notValidAfter"),
        "format": cp.get("certificateFormat"),
    })
    for ref_field in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
        target = by_ref.get(str(cp.get(ref_field) or ""))
        if target:
            asset["details"][ref_field] = target.get("name")
    return asset


def import_cbom(
    conn: sqlite3.Connection,
    org_id: str,
    filename: str,
    json_bytes: bytes,
    source: str = "cbomkit",
) -> Dict[str, Any]:
    """Import a CycloneDX 1.6 CBOM (e.g. CBOMkit output) into the organization's inventory.

    Raises ImportTooLarge (413), SchemaInvalid (422) or ValueError (400).
    """
    _check_size(json_bytes)
    try:
        doc = json.loads(json_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("CBOM root must be a JSON object")
    if doc.get("bomFormat") != "CycloneDX":
        raise SchemaInvalid("Not a CycloneDX document (bomFormat must be \"CycloneDX\").", [])

    components = _flatten(doc.get("components"))
    if len(components) > MAX_IMPORT_COMPONENTS:
        raise ImportTooLarge(
            f"Document has {len(components)} components; the limit is {MAX_IMPORT_COMPONENTS} "
            "(MORROW_BOM_IMPORT_MAX_COMPONENTS)."
        )
    validate_cyclonedx_16(doc)

    by_ref: Dict[str, Dict[str, Any]] = {}
    for comp in components:
        ref = comp.get("bom-ref")
        if isinstance(ref, str) and ref:
            by_ref[ref] = comp
    deps: Dict[str, List[str]] = {}
    for dep in doc.get("dependencies") or []:
        if isinstance(dep, dict) and isinstance(dep.get("ref"), str):
            deps[dep["ref"]] = [r for r in (dep.get("dependsOn") or []) + (dep.get("provides") or [])
                                if isinstance(r, str)]

    crypto = [c for c in components if c.get("type") == "cryptographic-asset"]
    assets: Dict[str, Dict[str, Any]] = {}   # bom-ref -> normalized asset
    unreferenced: List[Dict[str, Any]] = []
    for comp in crypto:
        asset = _cbom_asset(comp, by_ref, deps)
        if asset is None:
            continue
        ref = comp.get("bom-ref")
        if isinstance(ref, str) and ref:
            assets[ref] = asset
        else:
            unreferenced.append(asset)

    # Resolve the dependency graph to inventory keys, so it survives deduplication.
    key_of = {ref: _inventory_key(a) for ref, a in assets.items()}
    for ref, asset in assets.items():
        asset["depends_on"] = [key_of[t] for t in deps.get(ref, []) if t in key_of and key_of[t] != key_of[ref]]

    import_id = str(uuid.uuid4())
    imported_at = datetime.now(timezone.utc).isoformat()
    all_assets = list(assets.values()) + unreferenced
    keys: Dict[str, Dict[str, Any]] = {}
    with closing(conn.cursor()) as cur:
        existing = {r[0] for r in cur.execute(
            "SELECT inventory_key FROM crypto_inventory WHERE organization_id = ?", (org_id,)).fetchall()}
        cur.execute(
            """
            INSERT INTO sbom_imports
                (id, organization_id, filename, sbom_format, sbom_version,
                 component_count, crypto_component_count, imported_at, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (import_id, org_id, filename[:255], "CycloneDX-CBOM", "1.6", len(components),
             len(all_assets), imported_at, source),
        )
        rows = []
        for asset in all_assets:
            key = _upsert_inventory(cur, org_id, import_id, source, imported_at, asset)
            keys.setdefault(key, asset)
            rows.append({
                "id": str(uuid.uuid4()), "import_id": import_id, "name": asset["name"][:500],
                "version": "", "algorithm": asset.get("algorithm") or "",
                "key_length": asset.get("key_length"), "pq_safe": 1 if asset.get("pq_safe") else 0,
                "risk_level": asset.get("risk_level") or "unknown", "component_type": asset["asset_type"],
                "supplier": "", "description": key,
            })
        cur.executemany(
            """
            INSERT INTO sbom_crypto_components
                (id, import_id, name, version, algorithm, key_length,
                 pq_safe, risk_level, component_type, supplier, description)
            VALUES (:id, :import_id, :name, :version, :algorithm, :key_length,
                    :pq_safe, :risk_level, :component_type, :supplier, :description)
            """,
            rows,
        )
    conn.commit()

    by_type: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}
    for key, asset in keys.items():
        by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
        risk_counts[asset.get("risk_level") or "unknown"] = risk_counts.get(asset.get("risk_level") or "unknown", 0) + 1
    metadata = doc.get("metadata") or {}
    props = {p.get("name"): p.get("value") for p in (metadata.get("properties") or []) if isinstance(p, dict)}
    return {
        "import_id": import_id,
        "filename": filename,
        "source": source,
        "sbom_format": "CycloneDX-CBOM",
        "sbom_version": "1.6",
        "schema_valid": True,
        "component_count": len(components),
        "crypto_component_count": len(all_assets),
        "inventory_assets": len(keys),
        "new_inventory_assets": len([k for k in keys if k not in existing]),
        "deduplicated_inventory_assets": len([k for k in keys if k in existing]),
        "assets_by_type": by_type,
        "risk_summary": risk_counts,
        "quantum_vulnerable": sorted({a["name"] for a in keys.values() if a.get("quantum_vulnerable")}),
        "pq_safe": sorted({a["name"] for a in keys.values() if a.get("pq_safe")}),
        "repository": {k: props[k] for k in ("gitUrl", "revision", "commit") if props.get(k)},
        "imported_at": imported_at,
    }


def _flatten(comp_list: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    stack = [comp_list]
    while stack:
        items = stack.pop()
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                out.append(item)
                if len(out) > MAX_IMPORT_COMPONENTS:
                    return out
                stack.append(item.get("components"))
    return out


def list_inventory(
    conn: sqlite3.Connection,
    org_id: str,
    *,
    source: str = "",
    asset_type: str = "",
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """The organization's deduplicated cryptographic inventory, optionally filtered."""
    sql = ("SELECT inventory_key, asset_type, name, algorithm, primitive, oid, key_length, nist_pq_category, "
           "pq_safe, quantum_vulnerable, risk_level, sources_json, occurrences_json, occurrence_count, "
           "depends_on_json, details_json, first_seen, last_seen FROM crypto_inventory WHERE organization_id = ?")
    args: List[Any] = [org_id]
    if asset_type:
        sql += " AND asset_type = ?"
        args.append(asset_type)
    if source:
        sql += " AND sources_json LIKE ?"
        args.append(f'%"{source}"%')
    sql += " ORDER BY quantum_vulnerable DESC, risk_level, name LIMIT ?"
    args.append(max(1, min(int(limit), 5000)))
    with closing(conn.cursor()) as cur:
        cur.execute(sql, args)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["pq_safe"] = bool(r["pq_safe"])
        r["quantum_vulnerable"] = bool(r["quantum_vulnerable"])
        for field in ("sources", "occurrences", "depends_on", "details"):
            r[field] = json.loads(r.pop(f"{field}_json") or ("{}" if field == "details" else "[]"))
    return rows
