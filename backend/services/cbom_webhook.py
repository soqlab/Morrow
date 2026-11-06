"""CBOM CI/CD webhook receiver: accepts CBOM payloads pushed from CI.

Two ways in, both org-scoped by the credential and never by a header:

  POST /v1/cbom/ingest            a signed-in operator or admin; the organization is the caller's.
  POST /v1/runtime/cbom/ingest    CI with a per-organization ingest token (``mci_...``); the
                                  organization is the token's.

Tokens: ``mci_<12 hex prefix>_<secret>``. Only a salted HMAC-SHA256 of the full token is stored,
next to the public prefix used to find the row; the secret is shown once, at creation. This is the
same scheme as the passive-discovery ingest tokens (services/passive_ingest.py), in its own table so
that a log-shipper token cannot push CBOMs and the reverse.

Signing: an organization may configure a signing key (POST /v1/cbom/webhook/signing-key, admin). Once it
has one, every ingested document must carry ``X-Morrow-Signature: sha256=<hex HMAC of the body>``;
an unsigned or wrongly signed document is refused. Nothing here creates a key implicitly: an ingest
used to create one on first use, which made signing look configured when nobody held the key.
The signing key is necessarily stored in a recoverable form (it verifies an HMAC); it is shown only
to administrators.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

TOKEN_PREFIX = "mci_"
_TOKEN_RE = re.compile(r"^mci_([0-9a-f]{12})_([A-Za-z0-9_-]{32,128})$")


def max_body_bytes() -> int:
    """Largest CBOM accepted by the ingest routes (MORROW_CBOM_INGEST_MAX_BYTES, default 10 MiB)."""
    try:
        value = int(os.getenv("MORROW_CBOM_INGEST_MAX_BYTES", "") or 10 * 1024 * 1024)
    except ValueError:
        value = 10 * 1024 * 1024
    return max(1024, min(value, 256 * 1024 * 1024))


def init_tables(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS cbom_webhook_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS cbom_webhook_ingests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            repo TEXT,
            component_count INTEGER DEFAULT 0,
            classical_count INTEGER DEFAULT 0,
            pq_count INTEGER DEFAULT 0,
            payload_json TEXT,
            sha256 TEXT,
            created_at INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS cbom_ingest_tokens (
            id              TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name            TEXT NOT NULL DEFAULT '',
            prefix          TEXT NOT NULL,
            salt            TEXT NOT NULL,
            token_hash      TEXT NOT NULL,
            created_by      TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL,
            last_used_at    TEXT NOT NULL DEFAULT '',
            revoked_at      TEXT NOT NULL DEFAULT '',
            revoked_by      TEXT NOT NULL DEFAULT ''
        )
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cbom_ingest_tokens_prefix ON cbom_ingest_tokens(prefix)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_cbom_ingest_tokens_org ON cbom_ingest_tokens(organization_id)")
    db.commit()


# ── Signing key ───────────────────────────────────────────────────────────────

def get_secret(db, org_id: str) -> Optional[str]:
    """The organization's signing key, or None when it has not configured one."""
    row = db.execute("SELECT secret FROM cbom_webhook_configs WHERE org_id=?", (org_id,)).fetchone()
    return row[0] if row else None


def get_or_create_secret(db, org_id: str) -> str:
    secret = get_secret(db, org_id)
    if secret:
        return secret
    return set_new_secret(db, org_id)


def set_new_secret(db, org_id: str) -> str:
    """Create or rotate the organization's signing key and return it (shown to the caller once)."""
    secret = secrets.token_hex(32)
    db.execute("DELETE FROM cbom_webhook_configs WHERE org_id=?", (org_id,))
    db.execute(
        "INSERT INTO cbom_webhook_configs (org_id, secret, created_at) VALUES (?,?,?)",
        (org_id, secret, int(time.time())),
    )
    db.commit()
    return secret


def delete_secret(db, org_id: str) -> bool:
    """Remove the signing key; uploads are then accepted unsigned (they still need a credential)."""
    cur = db.execute("DELETE FROM cbom_webhook_configs WHERE org_id=?", (org_id,))
    db.commit()
    return bool(cur.rowcount)


def signing_key_created_at(db, org_id: str) -> Optional[int]:
    row = db.execute("SELECT created_at FROM cbom_webhook_configs WHERE org_id=?", (org_id,)).fetchone()
    return int(row[0]) if row else None


def verify_signature(secret: str, body: bytes, sig_header: str) -> bool:
    """Verify HMAC-SHA256 signature from X-Morrow-Signature header."""
    if not sig_header:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, str(sig_header).strip())


def signature_refusal(db, org_id: str, body: bytes, sig_header: str) -> str:
    """Why this body may not be ingested for org_id on signature grounds, or ""."""
    secret = get_secret(db, org_id)
    if not secret:
        return ""
    if not sig_header:
        return "This organization requires signed CBOM uploads: send X-Morrow-Signature: sha256=<HMAC of the body>."
    if not verify_signature(secret, body, sig_header):
        return "Invalid signature."
    return ""


# ── Ingest tokens ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(salt_hex: str, token: str) -> str:
    return hmac.new(bytes.fromhex(salt_hex), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _public_token(row: Any) -> Dict[str, Any]:
    item = dict(row)
    return {
        "id": item.get("id"),
        "organization_id": item.get("organization_id"),
        "name": item.get("name") or "",
        "prefix": f"{TOKEN_PREFIX}{item.get('prefix')}",
        "status": "revoked" if item.get("revoked_at") else "active",
        "created_by": item.get("created_by") or "",
        "created_at": item.get("created_at") or "",
        "last_used_at": item.get("last_used_at") or "",
        "revoked_at": item.get("revoked_at") or "",
    }


_TOKEN_COLUMNS = "id, organization_id, name, prefix, created_by, created_at, last_used_at, revoked_at, revoked_by"


def create_token(db, organization_id: str, name: str, created_by: str = "") -> Tuple[Dict[str, Any], str]:
    org = str(organization_id or "").strip()
    if not org or len(org) > 128:
        raise ValueError("organization_id is required.")
    label = str(name or "").strip()
    if not label or len(label) > 80:
        raise ValueError("name must be 1-80 characters.")
    token_id = "cit_" + secrets.token_hex(8)
    prefix = secrets.token_hex(6)
    token = f"{TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    salt = secrets.token_hex(16)
    db.execute(
        "INSERT INTO cbom_ingest_tokens (id, organization_id, name, prefix, salt, token_hash, created_by, "
        "created_at, last_used_at, revoked_at, revoked_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', '')",
        (token_id, org, label, prefix, salt, _hash(salt, token), str(created_by or "")[:160], _now_iso()),
    )
    db.commit()
    return get_token(db, token_id, org) or {}, token


def get_token(db, token_id: str, organization_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(
        f"SELECT {_TOKEN_COLUMNS} FROM cbom_ingest_tokens WHERE id = ? AND organization_id = ?",  # nosec B608  # _TOKEN_COLUMNS is a module constant; values are bound
        (str(token_id or ""), str(organization_id or "")),
    )
    row = cur.fetchone()
    return _public_token(dict(zip([d[0] for d in cur.description], row))) if row else None


def list_tokens(db, organization_id: str) -> List[Dict[str, Any]]:
    cur = db.execute(
        f"SELECT {_TOKEN_COLUMNS} FROM cbom_ingest_tokens WHERE organization_id = ? ORDER BY created_at DESC LIMIT 500",  # nosec B608  # _TOKEN_COLUMNS is a module constant; values are bound
        (str(organization_id or ""),),
    )
    cols = [d[0] for d in cur.description]
    return [_public_token(dict(zip(cols, r))) for r in cur.fetchall()]


def revoke_token(db, token_id: str, organization_id: str, revoked_by: str = "") -> Optional[Dict[str, Any]]:
    current = get_token(db, token_id, organization_id)
    if not current:
        return None
    if current["status"] != "revoked":
        db.execute(
            "UPDATE cbom_ingest_tokens SET revoked_at = ?, revoked_by = ? "
            "WHERE id = ? AND organization_id = ? AND revoked_at = ''",
            (_now_iso(), str(revoked_by or "")[:160], str(token_id), str(organization_id)),
        )
        db.commit()
    return get_token(db, token_id, organization_id)


def verify_token(db, token: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(token record, error). Never logs or stores the presented token."""
    text = str(token or "").strip()
    match = _TOKEN_RE.match(text)
    if not match:
        return None, "Missing or malformed CBOM ingest token."
    row = db.execute(
        "SELECT id, organization_id, salt, token_hash, revoked_at FROM cbom_ingest_tokens WHERE prefix = ?",
        (match.group(1),),
    ).fetchone()
    if not row or not hmac.compare_digest(_hash(str(row[2]), text), str(row[3])):
        return None, "Invalid CBOM ingest token."
    if str(row[4] or ""):
        return None, "CBOM ingest token has been revoked."
    try:
        db.execute("UPDATE cbom_ingest_tokens SET last_used_at = ? WHERE id = ?", (_now_iso(), row[0]))
        db.commit()
    except Exception:  # pragma: no cover - best-effort bookkeeping
        pass
    return {"id": str(row[0]), "organization_id": str(row[1])}, ""


# ── Ingest ────────────────────────────────────────────────────────────────────

def parse_payload(body: bytes) -> Dict[str, Any]:
    """The JSON object in body, or ValueError."""
    if len(body) > max_body_bytes():
        raise OverflowError(f"Body exceeds {max_body_bytes()} bytes.")
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        raise ValueError("Invalid JSON")
    if not isinstance(payload, dict):
        raise ValueError("CBOM must be a JSON object")
    if not isinstance(payload.get("components", []), list):
        raise ValueError("components must be a list")
    return payload


def ingest_cbom(db, org_id: str, payload: dict) -> dict:
    """Store a CBOM payload and return a summary."""
    components = [c for c in payload.get("components", []) if isinstance(c, dict)]
    classical = [c for c in components if _is_classical(c)]
    pq = [c for c in components if _is_pq(c)]
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    component = meta.get("component") if isinstance(meta.get("component"), dict) else {}
    repo = str(component.get("name") or "unknown")[:200]
    sha = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]

    db.execute(
        "INSERT INTO cbom_webhook_ingests "
        "(org_id, repo, component_count, classical_count, pq_count, payload_json, sha256, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (org_id, repo, len(components), len(classical), len(pq),
         json.dumps(payload), sha, int(time.time())),
    )
    db.commit()

    row = db.execute(
        "SELECT id FROM cbom_webhook_ingests WHERE sha256=? AND org_id=? ORDER BY id DESC LIMIT 1",
        (sha, org_id),
    ).fetchone()

    return {
        "ingest_id": row[0] if row else None,
        "organization_id": org_id,
        "repo": repo,
        "sha256": sha,
        "summary": {
            "total_components": len(components),
            "classical_crypto": len(classical),
            "pq_ready": len(pq),
            "risk": "HIGH" if len(classical) > len(pq) else "LOW",
        },
    }


def list_ingests(db, org_id: str, limit: int = 20) -> list[dict]:
    rows = db.execute(
        "SELECT id, repo, component_count, classical_count, pq_count, sha256, created_at "
        "FROM cbom_webhook_ingests WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
        (org_id, max(1, min(int(limit), 200))),
    ).fetchall()
    return [
        {"id": r[0], "repo": r[1], "components": r[2], "classical": r[3],
         "pq": r[4], "sha256": r[5], "created_at": r[6]}
        for r in rows
    ]


def github_actions_step(base_url: str) -> str:
    """A ready-to-paste GitHub Actions step for CBOM push.

    Credentials come from repository secrets, never inline: MORROW_CBOM_INGEST_TOKEN (create one
    under CBOM > Webhook setup) and, if the organization has a signing key, MORROW_CBOM_SIGNING_KEY.
    The organization is the token's; no organization header is sent. The signature is computed over
    the exact bytes uploaded.
    """
    return f"""- name: Push CBOM to Morrow
  env:
    CBOM_FILE: ${{{{ steps.sbom.outputs.cbom_path }}}}
    MORROW_CBOM_INGEST_TOKEN: ${{{{ secrets.MORROW_CBOM_INGEST_TOKEN }}}}
    MORROW_CBOM_SIGNING_KEY: ${{{{ secrets.MORROW_CBOM_SIGNING_KEY }}}}
  run: |
    SIG="sha256=$(openssl dgst -sha256 -hmac "$MORROW_CBOM_SIGNING_KEY" -r "$CBOM_FILE" | cut -d' ' -f1)"
    curl -sf -X POST '{base_url}/v1/runtime/cbom/ingest' \\
      -H "Authorization: Bearer $MORROW_CBOM_INGEST_TOKEN" \\
      -H 'Content-Type: application/json' \\
      -H "X-Morrow-Signature: $SIG" \\
      --data-binary "@$CBOM_FILE"
"""


def _primitive(component: dict) -> str:
    props = component.get("cryptoProperties")
    alg = props.get("algorithmProperties") if isinstance(props, dict) else None
    return str(alg.get("primitive", "") if isinstance(alg, dict) else "").lower()


def _is_classical(component: dict) -> bool:
    name = str(component.get("name") or "").lower()
    algo = _primitive(component)
    classical_keywords = {"rsa", "dsa", "ecdsa", "ecdh", "dh", "des", "3des"}
    return any(k in name or k in algo for k in classical_keywords)


def _is_pq(component: dict) -> bool:
    name = str(component.get("name") or "").lower()
    algo = _primitive(component)
    pq_keywords = {"ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "falcon", "sphincs", "bike", "hqc"}
    return any(k in name or k in algo for k in pq_keywords)
