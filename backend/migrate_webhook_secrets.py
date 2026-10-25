import sqlite3
import uuid

from vault_db import create_credential, ensure_vault_tables


def main():
    ensure_vault_tables()

    db = sqlite3.connect("/data/morrow.db")
    cur = db.cursor()

    cur.execute("""
        SELECT id, name, url, secret
        FROM webhooks
        WHERE credential_id IS NULL
          AND secret IS NOT NULL
          AND length(trim(secret)) > 0
    """)

    rows = cur.fetchall()
    print("to_migrate=", len(rows))

    migrated = 0
    for wid, name, url, secret in rows:
        cred = create_credential(
            name=f"webhook::{name}::{wid}::{uuid.uuid4().hex}",
            provider="webhook",
            secret_plain=secret,
            meta={"webhook_id": wid, "webhook_name": name, "url": url},
        )
        cid = int(cred["id"])
        cur.execute(
            "UPDATE webhooks SET credential_id=?, secret=? WHERE id=?",
            (cid, "", wid),
        )
        migrated += 1

    db.commit()
    print("migrated=", migrated)


if __name__ == "__main__":
    main()
