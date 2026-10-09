from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict

from db import current_organization_id, get_connection, postgres_main_db_requested
from db_postgres import pg_product_conn, product_database_url


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def idempotency_key_from_request(request) -> str:
    return str(request.headers.get("idempotency-key") or request.headers.get("x-idempotency-key") or "").strip()


def idempotency_fingerprint(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ensure_sqlite(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            organization_id TEXT NOT NULL,
            key TEXT NOT NULL,
            action TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            response_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, key, action)
        )
        """
    )
    conn.commit()


def _ensure_postgres() -> None:
    with pg_product_conn(product_database_url()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    organization_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (organization_id, key, action)
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_keys_org ON idempotency_keys(organization_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_keys_status ON idempotency_keys(status)")


def reserve_idempotency_key(*, key: str, action: str, request_hash: str) -> Dict[str, Any]:
    key = str(key or "").strip()
    if not key:
        return {"mode": "disabled"}
    org_id = current_organization_id()
    now = _now_iso()
    if postgres_main_db_requested():
        _ensure_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO idempotency_keys(organization_id, key, action, request_hash, status, response_json, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, 'in_progress', '{}'::jsonb, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (org_id, key, action, request_hash, now, now),
                )
                if cur.rowcount == 1:
                    return {"mode": "reserved"}
                cur.execute(
                    """
                    SELECT request_hash, status, response_json
                    FROM idempotency_keys
                    WHERE organization_id=%s AND key=%s AND action=%s
                    """,
                    (org_id, key, action),
                )
                row = cur.fetchone()
                if not row:
                    return {"mode": "reserved"}
                stored_hash, status, response = row
                if str(stored_hash or "") != request_hash:
                    return {"mode": "conflict", "reason": "same idempotency key used with a different request"}
                if str(status or "") == "completed":
                    return {"mode": "replay", "response": response or {}}
                return {"mode": "in_progress"}

    with get_connection() as conn:
        _ensure_sqlite(conn)
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO idempotency_keys(organization_id, key, action, request_hash, status, response_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'in_progress', '{}', ?, ?)
            """,
            (org_id, key, action, request_hash, now, now),
        )
        if cur.rowcount == 1:
            conn.commit()
            return {"mode": "reserved"}
        row = conn.execute(
            """
            SELECT request_hash, status, response_json
            FROM idempotency_keys
            WHERE organization_id=? AND key=? AND action=?
            """,
            (org_id, key, action),
        ).fetchone()
        if not row:
            return {"mode": "reserved"}
        if str(row[0] or "") != request_hash:
            return {"mode": "conflict", "reason": "same idempotency key used with a different request"}
        if str(row[1] or "") == "completed":
            try:
                return {"mode": "replay", "response": json.loads(row[2] or "{}")}
            except Exception:
                return {"mode": "replay", "response": {}}
        return {"mode": "in_progress"}


def complete_idempotency_key(*, key: str, action: str, response: Dict[str, Any]) -> None:
    key = str(key or "").strip()
    if not key:
        return
    org_id = current_organization_id()
    now = _now_iso()
    if postgres_main_db_requested():
        _ensure_postgres()
        with pg_product_conn(product_database_url()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE idempotency_keys
                    SET status='completed', response_json=%s::jsonb, updated_at=%s
                    WHERE organization_id=%s AND key=%s AND action=%s
                    """,
                    (json.dumps(response, default=str), now, org_id, key, action),
                )
        return
    with get_connection() as conn:
        _ensure_sqlite(conn)
        conn.execute(
            """
            UPDATE idempotency_keys
            SET status='completed', response_json=?, updated_at=?
            WHERE organization_id=? AND key=? AND action=?
            """,
            (json.dumps(response, default=str), now, org_id, key, action),
        )
        conn.commit()
