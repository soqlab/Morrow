"""Continuous passive-discovery ingest: tokens, payload decoding, deduplicated storage.

A log shipper (Fluent Bit, Vector, Logstash) posts batches of proxy log lines to
POST /v1/runtime/passive/ingest with ``Authorization: Bearer mpi_...``. The token belongs to
exactly one organization; the organization is taken from the token, never from a header.

Tokens: ``mpi_<12 hex prefix>_<secret>``. Only a salted HMAC-SHA256 of the full token is stored,
next to the public prefix used to find the row; the secret is shown once, at creation. Revocation
takes effect on the next request (there is no verification cache).

Storage keeps one row per (organization, host, port, group, cipher) with first_seen, last_seen
and a count. Nothing else from the line is stored: no client address, path, query string, user
agent or raw line.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import threading
import time
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db_feature_store import feature_conn
from services import json_limits, passive_discovery

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "mpi_"
_TOKEN_RE = re.compile(r"^mpi_([0-9a-f]{12})_([A-Za-z0-9_-]{32,128})$")
PASSIVE_TAG = "passive-discovered"


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)) or default)
    except ValueError:
        value = default
    return max(low, min(high, value))


def max_body_bytes() -> int:
    """Largest request body accepted on the wire (compressed size when gzip is used)."""
    return _env_int("MORROW_PASSIVE_MAX_BODY_BYTES", 2 * 1024 * 1024, 1024, 64 * 1024 * 1024)


def max_decoded_bytes() -> int:
    """Largest body after decompression: the zip-bomb ceiling."""
    return _env_int("MORROW_PASSIVE_MAX_DECODED_BYTES", 8 * 1024 * 1024, 1024, 256 * 1024 * 1024)


def max_lines() -> int:
    return _env_int("MORROW_PASSIVE_MAX_LINES", 5000, 1, 100_000)


def rate_limit_per_minute() -> int:
    """Ingest requests per token per minute (0 disables)."""
    return _env_int("MORROW_PASSIVE_RATE_PER_MINUTE", 120, 0, 100_000)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── Schema ────────────────────────────────────────────────────────────────────────────────────

_TABLES_READY: set = set()
_TABLE_LOCK = threading.Lock()


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}"


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLE_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS passive_ingest_tokens (
                    id              TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    prefix          TEXT NOT NULL,
                    salt            TEXT NOT NULL,
                    token_hash      TEXT NOT NULL,
                    default_format  TEXT NOT NULL DEFAULT '',
                    created_by      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL,
                    last_used_at    TEXT NOT NULL DEFAULT '',
                    revoked_at      TEXT NOT NULL DEFAULT '',
                    revoked_by      TEXT NOT NULL DEFAULT ''
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_passive_tokens_prefix ON passive_ingest_tokens(prefix);
                CREATE INDEX IF NOT EXISTS idx_passive_tokens_org ON passive_ingest_tokens(organization_id);
                CREATE TABLE IF NOT EXISTS passive_tls_endpoints (
                    organization_id     TEXT NOT NULL,
                    host                TEXT NOT NULL,
                    port                INTEGER NOT NULL,
                    kx_group            TEXT NOT NULL DEFAULT '',
                    cipher              TEXT NOT NULL DEFAULT '',
                    tls_version         TEXT NOT NULL DEFAULT '',
                    source_format       TEXT NOT NULL DEFAULT '',
                    group_observed      INTEGER NOT NULL DEFAULT 0,
                    group_loggable      INTEGER NOT NULL DEFAULT 1,
                    key_exchange_family TEXT NOT NULL DEFAULT '',
                    pq_status           TEXT NOT NULL DEFAULT 'unknown',
                    hndl_risk           TEXT NOT NULL DEFAULT 'unknown',
                    reasons             TEXT NOT NULL DEFAULT '',
                    token_id            TEXT NOT NULL DEFAULT '',
                    first_seen          TEXT NOT NULL,
                    last_seen           TEXT NOT NULL,
                    observation_count   INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (organization_id, host, port, kx_group, cipher)
                );
                CREATE INDEX IF NOT EXISTS idx_passive_endpoints_last_seen ON passive_tls_endpoints(organization_id, last_seen);
                """
            )
            conn.commit()
        _TABLES_READY.add(identity)


# ── Tokens ────────────────────────────────────────────────────────────────────────────────────

_TOKEN_COLUMNS = ("id, organization_id, name, prefix, default_format, created_by, created_at, "
                  "last_used_at, revoked_at, revoked_by")


def _hash(salt_hex: str, token: str) -> str:
    return hmac.new(bytes.fromhex(salt_hex), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _public_token(row: Any) -> Dict[str, Any]:
    item = dict(row)
    return {
        "id": item.get("id"),
        "organization_id": item.get("organization_id"),
        "name": item.get("name") or "",
        "prefix": f"{TOKEN_PREFIX}{item.get('prefix')}",
        "default_format": item.get("default_format") or "",
        "status": "revoked" if item.get("revoked_at") else "active",
        "created_by": item.get("created_by") or "",
        "created_at": item.get("created_at") or "",
        "last_used_at": item.get("last_used_at") or "",
        "revoked_at": item.get("revoked_at") or "",
        "revoked_by": item.get("revoked_by") or "",
    }


def create_token(organization_id: str, name: str, default_format: str = "", created_by: str = "") -> Tuple[Dict[str, Any], str]:
    org = str(organization_id or "").strip()
    if not org or len(org) > 128:
        raise ValueError("organization_id is required.")
    label = str(name or "").strip()
    if not label or len(label) > 80:
        raise ValueError("name must be 1-80 characters.")
    fmt = str(default_format or "").strip().lower()
    if fmt and fmt not in passive_discovery.FORMATS:
        raise ValueError(f"default_format must be one of: {', '.join(passive_discovery.FORMATS)}.")
    init_tables()
    token_id = "pit_" + secrets.token_hex(8)
    prefix = secrets.token_hex(6)
    token = f"{TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    salt = secrets.token_hex(16)
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO passive_ingest_tokens (id, organization_id, name, prefix, salt, token_hash, default_format, "
            "created_by, created_at, last_used_at, revoked_at, revoked_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '')",
            (token_id, org, label, prefix, salt, _hash(salt, token), fmt, str(created_by or "")[:160], _now_iso()),
        )
        conn.commit()
    return get_token(token_id, org) or {}, token


def get_token(token_id: str, organization_id: str) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            f"SELECT {_TOKEN_COLUMNS} FROM passive_ingest_tokens WHERE id = ? AND organization_id = ?",  # nosec B608  # _TOKEN_COLUMNS is a module constant; values are bound
            (str(token_id or ""), str(organization_id or "")),
        ).fetchone()
    return _public_token(row) if row else None


def list_tokens(organization_id: str) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            f"SELECT {_TOKEN_COLUMNS} FROM passive_ingest_tokens WHERE organization_id = ? ORDER BY created_at DESC LIMIT 500",  # nosec B608  # _TOKEN_COLUMNS is a module constant; values are bound
            (str(organization_id or ""),),
        ).fetchall()
    return [_public_token(r) for r in rows]


def revoke_token(token_id: str, organization_id: str, revoked_by: str = "") -> Optional[Dict[str, Any]]:
    current = get_token(token_id, organization_id)
    if not current:
        return None
    if current["status"] != "revoked":
        with feature_conn() as conn:
            conn.execute(
                "UPDATE passive_ingest_tokens SET revoked_at = ?, revoked_by = ? "
                "WHERE id = ? AND organization_id = ? AND revoked_at = ''",
                (_now_iso(), str(revoked_by or "")[:160], str(token_id), str(organization_id)),
            )
            conn.commit()
    return get_token(token_id, organization_id)


_LAST_TOUCH: Dict[str, float] = {}


def verify_token(token: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(token record, error). Never logs or stores the presented token."""
    text = str(token or "").strip()
    match = _TOKEN_RE.match(text)
    if not match:
        return None, "Missing or malformed ingest token."
    # The token's organization is the answer to this lookup, so it cannot run tenant-scoped; it is
    # an indexed lookup by public prefix followed by a constant-time HMAC comparison.
    from services.tenant_scope import platform_scope

    init_tables()
    with platform_scope("passive ingest token verification: lookup precedes tenant identity"):
        with feature_conn() as conn:
            row = conn.execute(
                "SELECT id, organization_id, name, prefix, salt, token_hash, default_format, revoked_at "
                "FROM passive_ingest_tokens WHERE prefix = ?",
                (match.group(1),),
            ).fetchone()
            if not row or not hmac.compare_digest(_hash(str(row["salt"]), text), str(row["token_hash"])):
                return None, "Invalid ingest token."
            if str(row["revoked_at"] or ""):
                return None, "Ingest token has been revoked."
            now = time.monotonic()
            if now - _LAST_TOUCH.get(str(row["id"]), 0.0) >= 60:
                _LAST_TOUCH[str(row["id"])] = now
                try:
                    conn.execute("UPDATE passive_ingest_tokens SET last_used_at = ? WHERE id = ?", (_now_iso(), row["id"]))
                    conn.commit()
                except Exception as exc:  # pragma: no cover - best effort bookkeeping
                    logger.debug("[passive-ingest] last_used update failed: %s", exc.__class__.__name__)
    return {"id": str(row["id"]), "organization_id": str(row["organization_id"]),
            "default_format": str(row["default_format"] or "")}, ""


# ── Payload decoding ──────────────────────────────────────────────────────────────────────────

class PayloadError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _decompress(body: bytes, encoding: str) -> bytes:
    encoding = str(encoding or "").strip().lower()
    if encoding in ("", "identity"):
        return body
    limit = max_decoded_bytes()
    if encoding in ("gzip", "x-gzip"):
        stream: Any = gzip.GzipFile(fileobj=io.BytesIO(body))
    elif encoding == "deflate":
        try:
            out = zlib.decompressobj().decompress(body, limit + 1)
        except zlib.error:
            raise PayloadError(400, "Body could not be decompressed.")
        if len(out) > limit:
            raise PayloadError(413, f"Decompressed body exceeds {limit} bytes.")
        return out
    else:
        raise PayloadError(415, f"Unsupported Content-Encoding {encoding!r}; use gzip, deflate or none.")
    try:
        data = stream.read(limit + 1)
    except (OSError, EOFError, zlib.error):
        raise PayloadError(400, "Body could not be decompressed.")
    if len(data) > limit:
        raise PayloadError(413, f"Decompressed body exceeds {limit} bytes.")
    return data


def _unwrap(record: Any) -> Any:
    """A shipper record -> the log line. Fluent Bit puts a tailed line in "log", Vector and
    Logstash in "message"; a record with neither is taken to be the already-structured line."""
    if isinstance(record, dict):
        for key in ("log", "message"):
            value = record.get(key)
            if isinstance(value, str) and len(record) <= 8 and not any(
                k.lower() in ("ssl_protocol", "downstream_tls_version", "version", "ssl_fc_protocol") for k in record
            ):
                return value
        return record
    if isinstance(record, (str, bytes)):
        return record.decode("utf-8", "replace") if isinstance(record, bytes) else record
    return json.dumps(record)


def decode_records(body: bytes, content_type: str = "", content_encoding: str = "") -> List[Any]:
    """Accepts a JSON array, a JSON object with "lines"/"records"/"logs", NDJSON, or plain text
    (one log line per line). Returns records (str lines or dicts), at most max_lines()."""
    data = _decompress(body, content_encoding)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", "replace")
    ctype = str(content_type or "").split(";", 1)[0].strip().lower()
    records: List[Any] = []
    stripped = text.strip()
    parsed_whole = False
    if ctype in ("application/json", "") and stripped[:1] in ("[", "{"):
        try:
            whole = json_limits.loads(stripped)
            parsed_whole = True
        except ValueError:
            whole = None
        if parsed_whole:
            if isinstance(whole, list):
                records = list(whole)
            elif isinstance(whole, dict):
                inner = next((whole[k] for k in ("lines", "records", "logs") if isinstance(whole.get(k), list)), None)
                records = list(inner) if inner is not None else [whole]
            else:
                raise PayloadError(400, "JSON body must be an array or an object.")
    if not parsed_whole:
        if ctype == "application/json" and stripped and "\n" not in stripped:
            raise PayloadError(400, "Body is not valid JSON.")
        ndjson = ctype in ("application/x-ndjson", "application/ndjson", "application/jsonl", "application/json")
        for raw in text.splitlines():
            if not raw.strip():
                continue
            if (ndjson or raw.lstrip().startswith("{")) and raw.lstrip().startswith("{"):
                try:
                    records.append(json_limits.loads(raw))
                    continue
                except ValueError:
                    pass                               # handed to the parser, which counts it
            records.append(raw)
    if len(records) > max_lines():
        raise PayloadError(413, f"Batch has {len(records)} lines; the limit is {max_lines()}.")
    return [_unwrap(r) for r in records]


# ── Storage ───────────────────────────────────────────────────────────────────────────────────

def _aggregate(observations: List[Dict[str, Any]]) -> Dict[Tuple[str, int, str, str], Dict[str, Any]]:
    out: Dict[Tuple[str, int, str, str], Dict[str, Any]] = {}
    for obs in observations:
        key = (obs["host"], int(obs["port"]), obs["group"], obs["cipher"])
        item = out.get(key)
        if item is None:
            out[key] = dict(obs, count=1)
        else:
            item["count"] += 1
            item["tls_version"] = obs["tls_version"]
    return out


def store_observations(organization_id: str, token_id: str, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Upsert deduplicated rows. Returns counts and the host:port keys that gained a new row."""
    init_tables()
    groups = _aggregate(observations)
    if not groups:
        return {"endpoints_touched": 0, "endpoints_new": 0, "new_asset_keys": []}
    now = _now_iso()
    org = str(organization_id)
    new_assets: set = set()
    new_rows = 0
    with feature_conn() as conn:
        for (host, port, group, cipher), obs in groups.items():
            existing = conn.execute(
                "SELECT pq_status FROM passive_tls_endpoints WHERE organization_id = ? AND host = ? AND port = ? "
                "AND kx_group = ? AND cipher = ?",
                (org, host, port, group, cipher),
            ).fetchone()
            if existing is None:
                new_rows += 1
                new_assets.add(f"{host}:{port}")
            conn.execute(
                """
                INSERT INTO passive_tls_endpoints (organization_id, host, port, kx_group, cipher, tls_version,
                    source_format, group_observed, group_loggable, key_exchange_family, pq_status, hndl_risk,
                    reasons, token_id, first_seen, last_seen, observation_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (organization_id, host, port, kx_group, cipher) DO UPDATE SET
                    tls_version = excluded.tls_version,
                    source_format = excluded.source_format,
                    key_exchange_family = excluded.key_exchange_family,
                    pq_status = excluded.pq_status,
                    hndl_risk = excluded.hndl_risk,
                    reasons = excluded.reasons,
                    token_id = excluded.token_id,
                    last_seen = excluded.last_seen,
                    observation_count = passive_tls_endpoints.observation_count + excluded.observation_count
                """,
                (org, host, port, group, cipher, obs["tls_version"], obs["format"], 1 if obs["group_observed"] else 0,
                 1 if obs["group_loggable"] else 0, obs["key_exchange_family"], obs["pq_status"], obs["hndl_risk"],
                 ",".join(obs["reasons"]), str(token_id or ""), now, now, int(obs["count"])),
            )
        conn.commit()
    return {"endpoints_touched": len(groups), "endpoints_new": new_rows, "new_asset_keys": sorted(new_assets)}


_ENDPOINT_COLUMNS = ("host, port, kx_group, cipher, tls_version, source_format, group_observed, group_loggable, "
                     "key_exchange_family, pq_status, hndl_risk, reasons, first_seen, last_seen, observation_count")


def _endpoint(row: Any) -> Dict[str, Any]:
    item = dict(row)
    return {
        "asset_key": f"{item['host']}:{int(item['port'])}",
        "host": item["host"],
        "port": int(item["port"]),
        "source": "passive",
        "source_format": item["source_format"],
        "tls_version": item["tls_version"],
        "cipher": item["cipher"],
        "key_exchange_group": item["kx_group"],
        "key_exchange_observed": bool(item["group_observed"]),
        "group_logged_by_source": bool(item["group_loggable"]),
        "key_exchange_family": item["key_exchange_family"],
        "pq_status": item["pq_status"],
        "harvest_now_decrypt_later_risk": item["hndl_risk"],
        "reasons": [r for r in str(item["reasons"] or "").split(",") if r],
        "certificate_observed": False,
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        "observation_count": int(item["observation_count"] or 0),
    }


def list_endpoints(organization_id: str, host: str = "", limit: int = 500) -> List[Dict[str, Any]]:
    init_tables()
    lim = max(1, min(int(limit or 500), 5000))
    with feature_conn() as conn:
        if host:
            rows = conn.execute(
                f"SELECT {_ENDPOINT_COLUMNS} FROM passive_tls_endpoints WHERE organization_id = ? AND host = ? "  # nosec B608  # _ENDPOINT_COLUMNS is a module constant; values are bound
                "ORDER BY last_seen DESC LIMIT ?", (str(organization_id), str(host).lower(), lim)).fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_ENDPOINT_COLUMNS} FROM passive_tls_endpoints WHERE organization_id = ? "  # nosec B608  # _ENDPOINT_COLUMNS is a module constant; values are bound
                "ORDER BY last_seen DESC LIMIT ?", (str(organization_id), lim)).fetchall()
    return [_endpoint(r) for r in rows]


_PQ_RANK = {"quantum_vulnerable": 3, "unknown": 2, "pq_safe_key_exchange": 1}


def summarize_asset(endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The worst observed posture for one host:port (any classical handshake makes it vulnerable:
    a client that can still negotiate classical key exchange is still harvestable)."""
    worst = max((e["pq_status"] for e in endpoints), key=lambda s: _PQ_RANK.get(s, 0), default="unknown")
    return {
        "passive_pq_status": worst,
        "passive_groups": sorted({e["key_exchange_group"] for e in endpoints if e["key_exchange_group"]}),
        "passive_ciphers": sorted({e["cipher"] for e in endpoints if e["cipher"]})[:20],
        "passive_tls_versions": sorted({e["tls_version"] for e in endpoints if e["tls_version"]}),
        "passive_formats": sorted({e["source_format"] for e in endpoints}),
        "passive_first_seen": min((e["first_seen"] for e in endpoints), default=""),
        "passive_last_seen": max((e["last_seen"] for e in endpoints), default=""),
        "passive_observation_count": sum(e["observation_count"] for e in endpoints),
    }


def merge_into_inventory(asset_keys: List[str], organization_id: str) -> int:
    """Create or update the inventory asset for each host:port, marked source "passive".

    Called for host:ports that gained a new (group, cipher) row, so a steady stream of identical
    handshakes does not rewrite the asset on every batch. Existing owner/team/notes are kept.
    """
    if not asset_keys:
        return 0
    from db import get_asset, upsert_asset

    updated = 0
    for key in asset_keys[:500]:
        host, _, port = key.rpartition(":")
        endpoints = [e for e in list_endpoints(organization_id, host=host, limit=200) if str(e["port"]) == port]
        if not endpoints:
            continue
        existing = get_asset(key) or {}
        meta = dict(existing.get("metadata") or {}) if isinstance(existing.get("metadata"), dict) else {}
        sources = set(meta.get("discovery_sources") or [])
        sources.add("passive")
        meta.update(summarize_asset(endpoints))
        meta["discovery_sources"] = sorted(sources)
        meta.setdefault("discovery_source", "passive")
        tags = sorted({*[str(t) for t in (existing.get("tags") or []) if str(t).strip()], PASSIVE_TAG})
        upsert_asset(
            key,
            owner=str(existing.get("owner") or ""),
            team=str(existing.get("team") or ""),
            environment=str(existing.get("environment") or ""),
            criticality=str(existing.get("criticality") or ""),
            confidentiality_lifetime=str(existing.get("confidentiality_lifetime") or ""),
            notes=str(existing.get("notes") or ""),
            tags=tags,
            metadata=meta,
            repository_id=int(existing.get("repository_id") or 0),
        )
        updated += 1
    return updated
