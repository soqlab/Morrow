"""Baby-step tests for Sprint 8.3 async webhook delivery.

Run:
  python test_async_delivery.py

Expected:
- First, deliver_events_for_scan(...) will enqueue rows only (no HTTP attempted yet).
- Then, draining should send events to the local listener and mark them as sent.
- One webhook intentionally fails first, gets next_attempt_at set; a second drain immediately after should skip it.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

# Ensure local imports resolve
import sys
sys.path.insert(0, ".")
sys.path.insert(0, "/mnt/data")

# Use a writable SQLite path for tests (default DB is /data/... which may not exist).
os.environ.setdefault("MORROW_SCANNER_DB", "/mnt/data/test_morrow.db")

from db import init_db, save_scan_row, list_webhook_events, list_pending_webhook_events, upsert_webhook
from events import deliver_events_for_scan, drain_webhook_delivery_queue


class _Handler(BaseHTTPRequestHandler):
    # Shared mutable state across handler instances
    hits = {"/ok": 0, "/flaky": 0}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)

        path = self.path
        _Handler.hits[path] = _Handler.hits.get(path, 0) + 1

        # Print what we got (so you can see the payload shape)
        try:
            decoded = body.decode("utf-8", "ignore")
        except Exception:
            decoded = "<decode-failed>"
        print(f"\n--- webhook received {path} hit={_Handler.hits[path]} ---")
        print(decoded[:600])

        if path == "/flaky" and _Handler.hits[path] == 1:
            # Fail first request, succeed later
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"first attempt fails")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        # Silence default server logs
        return


def _start_server(port: int) -> HTTPServer:
    httpd = HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def main() -> None:
    init_db()

    port = 9911
    srv = _start_server(port)
    base = f"http://127.0.0.1:{port}"

    # Two webhooks: one always ok, one flaky (fails first)
    w_ok = upsert_webhook(name="ok", url=base + "/ok", secret="", events=["*"], enabled=True, rate_limit_per_minute=600, timeout_seconds=5)
    w_flaky = upsert_webhook(name="flaky", url=base + "/flaky", secret="", events=["*"], enabled=True, rate_limit_per_minute=600, timeout_seconds=5)
    print("webhooks:", w_ok["id"], w_flaky["id"])

    # Create a fake completed scan with a cert.expiring_soon finding
    scan_id = f"test-scan-{int(time.time())}"
    results = [
        {
            "host": "example.com",
            "port": 443,
            "days_until_expiry": 7,
            "not_after": "2030-01-01",
            "verify_reason": "",
            "findings": [{"rule_id": "CERT_EXPIRING_SOON"}],
        }
    ]
    save_scan_row(
        scan_id=scan_id,
        status="completed",
        created_at=datetime.utcnow(),
        progress={"percent": 100},
        error_text="",
        results=results,
        summary={"assets": 1},
    )

    print("\n1) enqueue (should not do HTTP)")
    before = list_webhook_events(limit=50)
    stats = deliver_events_for_scan(scan_id)
    after = list_webhook_events(limit=50)
    print("enqueue stats:", stats)
    print("new webhook_events rows:", len(after) - len(before))

    pending = list_pending_webhook_events(limit=50)
    print("pending rows:", len(pending))
    assert len(pending) >= 1

    print("\n2) drain #1 (should deliver, flaky will fail once)")
    d1 = drain_webhook_delivery_queue(limit=50)
    print("drain stats:", d1)

    items = list_webhook_events(limit=20)
    print("latest webhook_events:")
    for it in items[:6]:
        print({k: it.get(k) for k in ("id", "webhook_id", "event_type", "status", "http_status", "attempts", "next_attempt_at", "response_excerpt")})

    print("\n3) drain #2 immediately (flaky should be skipped due to backoff)")
    d2 = drain_webhook_delivery_queue(limit=50)
    print("drain stats:", d2)

    print("\n4) wait for backoff and drain #3 (flaky should succeed now)")
    time.sleep(6)
    d3 = drain_webhook_delivery_queue(limit=50)
    print("drain stats:", d3)

    srv.shutdown()
    print("\nOK")


if __name__ == "__main__":
    main()
