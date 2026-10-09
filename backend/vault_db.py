import os
import json
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

from db import DEFAULT_ORG_ID, current_organization_id
from vault_crypto import encrypt_secret, decrypt_secret


def _pg_conn():
    url = (os.getenv("DATABASE_URL") or "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is required for Vault (postgresql://...)")
    return psycopg2.connect(url)


def ensure_vault_tables():
    with _pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
              id BIGSERIAL PRIMARY KEY,
              organization_id TEXT NOT NULL DEFAULT '',
              name TEXT NOT NULL UNIQUE,
              provider TEXT NOT NULL,
              secret_enc TEXT NOT NULL,
              meta_json JSONB NOT NULL DEFAULT '{}'::jsonb,
              created_at TIMESTAMPTZ NOT NULL,
              updated_at TIMESTAMPTZ NOT NULL,
              last_rotated_at TIMESTAMPTZ NOT NULL
            );
            """)
            cur.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS organization_id TEXT NOT NULL DEFAULT ''")
            cur.execute("UPDATE credentials SET organization_id=%s WHERE COALESCE(organization_id, '') = ''", (DEFAULT_ORG_ID,))
            cur.execute("ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_name_key")
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_org_name ON credentials(organization_id, name)"
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_credentials_org ON credentials(organization_id)")


def _org_id() -> str:
    return str(current_organization_id() or DEFAULT_ORG_ID).strip() or DEFAULT_ORG_ID


def create_credential(name: str, provider: str, secret_plain: str, meta: dict):
    now = datetime.now(timezone.utc)
    token = encrypt_secret(secret_plain)
    meta = meta or {}
    org_id = _org_id()
    with _pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
              INSERT INTO credentials (organization_id, name, provider, secret_enc, meta_json, created_at, updated_at, last_rotated_at)
              VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)
              ON CONFLICT (organization_id, name) DO NOTHING
              RETURNING id, organization_id, name, provider, meta_json, created_at, updated_at, last_rotated_at;
            """, (org_id, name, provider, token, json.dumps(meta), now, now, now))
            return cur.fetchone()  # will be None if name already exists


def list_credentials():
    org_id = _org_id()
    with _pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
              SELECT id, organization_id, name, provider, meta_json, created_at, updated_at, last_rotated_at
              FROM credentials
              WHERE organization_id=%s
              ORDER BY id DESC
            """, (org_id,))
            return cur.fetchall()


def get_credential(cred_id: int, reveal: bool = False):
    org_id = _org_id()
    with _pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM credentials WHERE id=%s AND organization_id=%s", (cred_id, org_id))
            row = cur.fetchone()
            if not row:
                return None
            if not reveal:
                row.pop("secret_enc", None)
                return row
            row["secret"] = decrypt_secret(row["secret_enc"])
            row.pop("secret_enc", None)
            return row


def rotate_credential(cred_id: int, new_secret_plain: str):
    now = datetime.now(timezone.utc)
    token = encrypt_secret(new_secret_plain)
    org_id = _org_id()
    with _pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
              UPDATE credentials
              SET secret_enc=%s, updated_at=%s, last_rotated_at=%s
              WHERE id=%s AND organization_id=%s
              RETURNING id, organization_id, name, provider, meta_json, created_at, updated_at, last_rotated_at;
            """, (token, now, now, cred_id, org_id))
            return cur.fetchone()
