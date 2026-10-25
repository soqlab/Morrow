"""CBOM CI/CD Webhook Receiver — accepts signed CBOM payloads from GitHub Actions."""
import hashlib
import hmac
import json
import time


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
    db.commit()


def get_or_create_secret(db, org_id: str) -> str:
    row = db.execute(
        "SELECT secret FROM cbom_webhook_configs WHERE org_id=?", (org_id,)
    ).fetchone()
    if row:
        return row[0]
    import secrets as _sec
    secret = _sec.token_hex(32)
    db.execute(
        "INSERT INTO cbom_webhook_configs (org_id, secret, created_at) VALUES (?,?,?)",
        (org_id, secret, int(time.time())),
    )
    db.commit()
    return secret


def verify_signature(secret: str, body: bytes, sig_header: str) -> bool:
    """Verify HMAC-SHA256 signature from X-Morrow-Signature header."""
    if not sig_header:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def ingest_cbom(db, org_id: str, payload: dict) -> dict:
    """Store a CBOM payload and return a summary."""
    components = payload.get("components", [])
    classical = [c for c in components if _is_classical(c)]
    pq = [c for c in components if _is_pq(c)]
    repo = payload.get("metadata", {}).get("component", {}).get("name", "unknown")
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
        (org_id, limit),
    ).fetchall()
    return [
        {"id": r[0], "repo": r[1], "components": r[2], "classical": r[3],
         "pq": r[4], "sha256": r[5], "created_at": r[6]}
        for r in rows
    ]


def github_actions_step(org_id: str, base_url: str, secret: str) -> str:
    """Return a ready-to-paste GitHub Actions step for CBOM push."""
    return f"""- name: Push CBOM to Morrow
  run: |
    CBOM_FILE="${{{{ steps.sbom.outputs.cbom_path }}}}"
    BODY=$(cat "$CBOM_FILE")
    SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac '{secret}' | awk '{{print $2}}')"
    curl -sf -X POST '{base_url}/v1/cbom/ingest' \\
      -H 'Content-Type: application/json' \\
      -H "X-Morrow-Signature: $SIG" \\
      -H 'X-Org-Id: {org_id}' \\
      -d "$BODY"
"""


def _is_classical(component: dict) -> bool:
    name = (component.get("name") or "").lower()
    algo = str(component.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive", "")).lower()
    classical_keywords = {"rsa", "dsa", "ecdsa", "ecdh", "dh", "des", "3des"}
    return any(k in name or k in algo for k in classical_keywords)


def _is_pq(component: dict) -> bool:
    name = (component.get("name") or "").lower()
    algo = str(component.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive", "")).lower()
    pq_keywords = {"ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "falcon", "sphincs", "bike", "hqc"}
    return any(k in name or k in algo for k in pq_keywords)
