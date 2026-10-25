"""Per-organization provider override, stored encrypted.

A customer who wants the assistant to run on their own model and their own key
sets it here. The key and any gateway headers are sealed with the platform's
existing vault helper (`vault_crypto.encrypt_secret`), so they are at rest only
as ciphertext, and no read path ever returns the plaintext to a caller outside
this module.

Tenant isolation, per SECURITY.md and docs/SECURITY_REVIEW_SUMMARY.md: every statement is
scoped by `organization_id`, the wildcard organization is refused, and on
Postgres the row-level-security variable is set for the connection. A customer
can read and write only their own row -- there is no cross-tenant read, no
"list all overrides", and no way to pass another organization's id.

MORROW_LLM_DISABLED is not a field here. A deployment that forbids external model
calls cannot have that decision overridden by a tenant.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import db_feature_store as store
from services.llm.config import ORG_FIELDS, PROVIDER_IDS, normalise, parse_headers
from vault_crypto import decrypt_secret, encrypt_secret

_schema_lock = threading.Lock()
_ready: set = set()

#: Providers an organization may select. "custom" is absent on purpose: a
#: tenant must not be able to name a Python module for this process to import.
SELECTABLE = tuple(name for name in PROVIDER_IDS if name != "custom")


class OverrideError(ValueError):
    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def init_tables() -> None:
    identity = (store.dialect(), store._feature_dsn() if store.postgres_enabled() else store._sqlite_path())
    with _schema_lock:
        if identity in _ready:
            return
        with store.feature_conn() as conn:
            present = False
            if store.postgres_enabled():
                row = conn.execute("SELECT to_regclass('public.llm_org_provider')").fetchone()
                present = bool(row and row[0])
            if not present:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS llm_org_provider (
                        organization_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        model TEXT NOT NULL DEFAULT '',
                        base_url TEXT NOT NULL DEFAULT '',
                        api_version TEXT NOT NULL DEFAULT '',
                        deployment TEXT NOT NULL DEFAULT '',
                        key_sealed TEXT NOT NULL DEFAULT '',
                        headers_sealed TEXT NOT NULL DEFAULT '',
                        settings TEXT NOT NULL DEFAULT '{}',
                        updated_at DOUBLE PRECISION NOT NULL,
                        updated_by TEXT NOT NULL DEFAULT ''
                    );
                """)
                conn.commit()
        _ready.add(identity)


@contextmanager
def _connection(org: str, write: bool = False):
    if not org or org == "*":
        raise OverrideError("A verified organization is required", 403)
    init_tables()
    with store.feature_conn() as conn:
        if store.postgres_enabled():
            conn.execute("SELECT set_config('app.current_organization_id',?,true)", (org,))
        elif write:
            conn.execute("BEGIN IMMEDIATE")
        yield conn


def _row(conn, org: str):
    return conn.execute("SELECT * FROM llm_org_provider WHERE organization_id=?", (org,)).fetchone()


def _numeric(value: Any, low: float, high: float, integer: bool = False) -> Any:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise OverrideError("A numeric setting is not a number") from None
    number = max(low, min(high, number))
    return int(number) if integer else number


def validate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Check and normalise a submitted override. Raises OverrideError."""
    unknown = sorted(set(payload) - set(ORG_FIELDS))  # "_clear_secrets" is set here, never submitted
    if unknown:
        raise OverrideError("Unsupported provider settings: " + ", ".join(unknown))
    provider = normalise(str(payload.get("provider") or ""))
    if provider not in SELECTABLE:
        raise OverrideError("Choose one of: " + ", ".join(SELECTABLE))
    clean: Dict[str, Any] = {"provider": provider}
    for field in ("model", "base_url", "api_version", "deployment"):
        value = str(payload.get(field) or "").strip()
        if len(value) > 512:
            raise OverrideError(f"{field} is too long")
        clean[field] = value
    key = str(payload.get("api_key") or "")
    if len(key) > 4096:
        raise OverrideError("api_key is too long")
    clean["api_key"] = key
    headers = payload.get("headers")
    if headers in (None, ""):
        clean["headers"] = {}
    elif isinstance(headers, dict):
        parsed, rejected = parse_headers(json.dumps(headers))
        if rejected:
            raise OverrideError("These header names are not permitted: " + ", ".join(rejected))
        clean["headers"] = parsed
    elif isinstance(headers, str):
        parsed, rejected = parse_headers(headers)
        if rejected:
            raise OverrideError("These header names are not permitted: " + ", ".join(rejected))
        clean["headers"] = parsed
    else:
        raise OverrideError("headers must be an object or k=v,k=v text")
    if "temperature" in payload and payload["temperature"] is not None:
        clean["temperature"] = _numeric(payload["temperature"], 0.0, 2.0)
    if "max_tokens" in payload and payload["max_tokens"] is not None:
        clean["max_tokens"] = _numeric(payload["max_tokens"], 256, 200_000, integer=True)
    if "timeout" in payload and payload["timeout"] is not None:
        clean["timeout"] = _numeric(payload["timeout"], 1, 600, integer=True)
    if "context_window" in payload and payload["context_window"] is not None:
        clean["context_window"] = _numeric(payload["context_window"], 1024, 10_000_000, integer=True)
    for field in ("price_input_per_mtok", "price_output_per_mtok"):
        if field in payload and payload[field] is not None:
            clean[field] = _numeric(payload[field], 0.0, 10_000.0)
    for field in ("tools_supported", "stream_supported"):
        if field in payload and payload[field] is not None:
            if not isinstance(payload[field], bool):
                raise OverrideError(f"{field} must be true or false")
            clean[field] = payload[field]
    if provider == "builtin":
        # Selecting the built-in answerer means "no model call": a destination
        # or a key alongside it would be misleading in the console.
        clean.update(model="", base_url="", api_key="", headers={}, api_version="", deployment="",
                     _clear_secrets=True)
    return clean


def set_override(org: str, payload: Dict[str, Any], actor: str = "") -> Dict[str, Any]:
    """Store this organization's override. Returns the redacted record."""
    clean = validate(payload)
    extras = {field: clean[field] for field in
              ("temperature", "max_tokens", "timeout", "context_window", "price_input_per_mtok",
               "price_output_per_mtok", "tools_supported", "stream_supported") if field in clean}
    sealed_key = encrypt_secret(clean["api_key"]) if clean["api_key"] else ""
    sealed_headers = encrypt_secret(json.dumps(clean["headers"], sort_keys=True)) if clean["headers"] else ""
    with _connection(org, write=True) as conn:
        existing = _row(conn, org)
        clear = bool(clean.get("_clear_secrets"))
        if existing and clear:
            sealed_key = sealed_headers = ""
        elif existing and not clean["api_key"] and existing["key_sealed"]:
            # An empty key field leaves the stored one alone, so the console can
            # change a model without being handed the secret to re-submit.
            sealed_key = existing["key_sealed"]
        if existing and not clear and not clean["headers"] and existing["headers_sealed"]:
            sealed_headers = existing["headers_sealed"]
        conn.execute(
            "INSERT INTO llm_org_provider (organization_id,provider,model,base_url,api_version,deployment,"
            "key_sealed,headers_sealed,settings,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT (organization_id) DO UPDATE SET provider=excluded.provider,model=excluded.model,"
            "base_url=excluded.base_url,api_version=excluded.api_version,deployment=excluded.deployment,"
            "key_sealed=excluded.key_sealed,headers_sealed=excluded.headers_sealed,settings=excluded.settings,"
            "updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (org, clean["provider"], clean["model"], clean["base_url"], clean["api_version"],
             clean["deployment"], sealed_key, sealed_headers,
             json.dumps(extras, sort_keys=True), time.time(), str(actor)[:128]))
        conn.commit()
    return describe(org)


def clear_override(org: str) -> Dict[str, Any]:
    """Remove this organization's override; the deployment's own settings apply again."""
    with _connection(org, write=True) as conn:
        conn.execute("DELETE FROM llm_org_provider WHERE organization_id=?", (org,))
        conn.commit()
    return {"configured": False, "organization_id": org}


def load(org: str) -> Optional[Dict[str, Any]]:
    """The override as a settings dict, with secrets decrypted. Internal use only.

    Returns None when this organization has no override. A sealed value that
    cannot be decrypted (a rotated master key, say) is dropped rather than
    raised, so a stale secret degrades to "no key" instead of breaking the page.
    """
    if not org or org == "*":
        return None
    try:
        with _connection(org) as conn:
            row = _row(conn, org)
    except Exception:
        return None
    if not row:
        return None
    try:
        extras = json.loads(row["settings"] or "{}")
    except ValueError:
        extras = {}
    override: Dict[str, Any] = {
        "organization_id": org,
        "provider": row["provider"],
        "model": row["model"],
        "base_url": row["base_url"],
        "api_version": row["api_version"],
        "deployment": row["deployment"],
        **(extras if isinstance(extras, dict) else {}),
    }
    if row["key_sealed"]:
        try:
            override["api_key"] = decrypt_secret(row["key_sealed"])
        except Exception:
            override["api_key"] = ""
    if row["headers_sealed"]:
        try:
            parsed = json.loads(decrypt_secret(row["headers_sealed"]) or "{}")
            override["headers"] = parsed if isinstance(parsed, dict) else {}
        except Exception:
            override["headers"] = {}
    return override


def describe(org: str) -> Dict[str, Any]:
    """The override as the console may see it: no key, header names only."""
    if not org or org == "*":
        raise OverrideError("A verified organization is required", 403)
    with _connection(org) as conn:
        row = _row(conn, org)
    if not row:
        return {"configured": False, "organization_id": org, "selectable": list(SELECTABLE)}
    try:
        extras = json.loads(row["settings"] or "{}")
    except ValueError:
        extras = {}
    header_names: List[str] = []
    if row["headers_sealed"]:
        try:
            parsed = json.loads(decrypt_secret(row["headers_sealed"]) or "{}")
            header_names = sorted(parsed) if isinstance(parsed, dict) else []
        except Exception:
            header_names = ["<sealed with a previous master key>"]
    return {
        "configured": True, "organization_id": org, "provider": row["provider"],
        "model": row["model"], "base_url": row["base_url"], "api_version": row["api_version"],
        "deployment": row["deployment"], "api_key_present": bool(row["key_sealed"]),
        "extra_header_names": header_names, "settings": extras if isinstance(extras, dict) else {},
        "updated_at": row["updated_at"], "updated_by": row["updated_by"],
        "selectable": list(SELECTABLE),
    }
