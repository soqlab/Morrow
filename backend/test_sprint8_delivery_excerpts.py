import os
import socket
import threading
import time
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer


DB_FILE = os.environ.get("MORROW_SCANNER_DB", "")
if not DB_FILE:
    DB_FILE = "/tmp/morrow_test_excerpts.db"
    os.environ["MORROW_SCANNER_DB"] = DB_FILE


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class WebhookTestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # consume request body
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        if length > 0:
            try:
                self.rfile.read(length)
            except Exception:
                pass

        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok-response")
            return

        if self.path == "/fail":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"fail-body-123")
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not-found")

    def log_message(self, fmt, *args):
        # keep tests quiet
        return


def _read_row(row_id: int):
    conn = sqlite3.connect(DB_FILE)
    try:
        cur = conn.cursor()
        cur.execute(
            "select status,http_status,error_text,response_excerpt,attempts,next_attempt_at from webhook_events where id=?",
            (int(row_id),),
        )
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def main() -> None:
    # Import after env var is set so db.py picks up MORROW_SCANNER_DB at import time.
    import db
    import events

    # fresh DB
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    db.init_db()

    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), WebhookTestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    ok_url = f"http://127.0.0.1:{port}/ok"
    fail_url = f"http://127.0.0.1:{port}/fail"
    down_url = "http://127.0.0.1:1/down"  # should be connection refused fast

    wh_ok = db.upsert_webhook(name="wh_ok", url=ok_url, events=["*"], enabled=True, timeout_seconds=2)
    wh_fail = db.upsert_webhook(name="wh_fail", url=fail_url, events=["*"], enabled=True, timeout_seconds=2)
    wh_down = db.upsert_webhook(name="wh_down", url=down_url, events=["*"], enabled=True, timeout_seconds=1)

    payload = {"event_type": "unit.test", "ts": int(time.time()), "data": {"message": "hello"}}

    id_ok = db.record_webhook_event(int(wh_ok["id"]), "unit.test", "dedupe_ok", payload, status="queued", max_attempts=1)
    id_fail = db.record_webhook_event(int(wh_fail["id"]), "unit.test", "dedupe_fail", payload, status="queued", max_attempts=1)
    id_down = db.record_webhook_event(int(wh_down["id"]), "unit.test", "dedupe_down", payload, status="queued", max_attempts=1)

    assert id_ok is not None and id_fail is not None and id_down is not None

    stats = events.drain_webhook_delivery_queue(limit=50, max_attempts=1)
    assert stats["attempted"] == 3, stats

    r_ok = _read_row(id_ok)
    r_fail = _read_row(id_fail)
    r_down = _read_row(id_down)

    assert r_ok is not None and r_ok[0] == "sent" and int(r_ok[1]) == 200, r_ok
    assert "ok-response" in (r_ok[3] or ""), r_ok

    # With max_attempts=1, failures should be marked dead (no further retries)
    assert r_fail is not None and r_fail[0] == "dead" and int(r_fail[1]) == 500, r_fail
    assert "fail-body-123" in (r_fail[3] or ""), r_fail

    assert r_down is not None and r_down[0] == "dead" and int(r_down[1]) == 0, r_down
    assert (r_down[3] or "").strip() != "", r_down

    server.shutdown()

    print("OK")


if __name__ == "__main__":
    main()
