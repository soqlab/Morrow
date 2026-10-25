import os
import sqlite3

def main():
    db = os.environ.get("MORROW_SCANNER_DB", "/data/morrow.db")
    print("DB:", db)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    cols = [r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()]
    print("webhook_events columns:", cols)

    def has(c):
        return c in cols

    select_cols = ["id"]
    for c in [
        "status",
        "attempts",
        "http_status",
        "status_code",
        "error_text",
        "last_attempt_at",
        "next_attempt_at",
        "claimed_at",
        "claimed_by",
        "webhook_id",
        "event_type",
        "created_at",
    ]:
        if has(c):
            select_cols.append(c)

    q = "SELECT " + ", ".join(select_cols) + " FROM webhook_events ORDER BY id DESC LIMIT 20"
    rows = conn.execute(q).fetchall()

    print("last 20 webhook_events:")
    for r in rows:
        print(dict(r))

    conn.close()

if __name__ == "__main__":
    main()
