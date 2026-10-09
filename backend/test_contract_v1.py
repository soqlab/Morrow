import os
import json
import shutil
import sqlite3
import tempfile
import unittest
import importlib
from datetime import datetime, timezone


def _sha256_hex(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


class TestWebhookContractV1(unittest.TestCase):
    """Contract tests for the v1 webhook payload.

    These need their own SQLite file, which means mutating PQC_SCANNER_DB and reloading db/events.
    Both are process-global: db.get_connection() re-reads PQC_SCANNER_DB on every call, so a leaked
    value redirects every later test module in the same pytest process to a database that does not
    exist. tearDown must therefore restore the previous environment and reload the modules again.
    """

    def setUp(self):
        # A real temp directory, not a hardcoded POSIX path: "/tmp/..." resolves to C:\tmp on
        # Windows, which does not exist, so sqlite3 raises "unable to open database file".
        self._tmpdir = tempfile.mkdtemp(prefix="pqc_contract_v1_")
        self.db_path = os.path.join(self._tmpdir, "pqc_contract_v1_test.db")

        # Remember the prior value so tearDown can put it back exactly (including "unset").
        self._prev_db_env = os.environ.get("PQC_SCANNER_DB")
        os.environ["PQC_SCANNER_DB"] = self.db_path

        # Reload so module-level DB_PATH picks up the env var.
        import db
        import events
        importlib.reload(db)
        importlib.reload(events)
        self.db = db
        self.events = events

        # Create a webhook
        self.webhook = self.db.upsert_webhook(
            name="unit.test",
            url="http://localhost:9999/webhook",
            secret="secret",
            events=["*"],
            enabled=True,
            rate_limit_per_minute=1000,
            timeout_seconds=1,
        )

        # Create a scan row with one result that triggers cert.expired
        scan_id = "scan_test_1"
        self.scan_id = scan_id
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        result = {
            "host": "example.com",
            "port": 443,
            "days_until_expiry": -2,
            "not_after": "2026-01-16T00:00:00Z",
            "verify_reason": "expired",
            "findings": [{"rule_id": "CERT_EXPIRED"}],
        }

        # save_scan_row exists in this codebase (used by API)
        self.db.save_scan_row(
            scan_id=scan_id,
            status="completed",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            progress={"total": 1, "done": 1, "percent": 100},
            error_text="",
            results=[result],
            summary={},
        )

    def tearDown(self):
        # Restore PQC_SCANNER_DB before reloading, so db.DB_PATH resolves back to the real database.
        if self._prev_db_env is None:
            os.environ.pop("PQC_SCANNER_DB", None)
        else:
            os.environ["PQC_SCANNER_DB"] = self._prev_db_env
        import db
        import events
        importlib.reload(db)
        importlib.reload(events)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _fetch_webhook_rows(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "select id, event_type, dedupe_key, payload_json from webhook_events order by id asc"
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    def test_enqueued_payload_is_contract_v1(self):
        stats = self.events.deliver_events_for_scan(self.scan_id)
        self.assertGreaterEqual(stats.get("queued", 0), 1)

        rows = self._fetch_webhook_rows()
        self.assertGreaterEqual(len(rows), 2, "expected scan.completed + cert.expired")

        for row_id, event_type, dedupe_key, payload_json in rows:
            payload = json.loads(payload_json)

            # Top-level contract fields
            self.assertEqual(payload.get("schema_version"), "1.0")
            self.assertEqual(payload.get("event_type"), event_type)
            self.assertEqual(payload.get("event_id"), dedupe_key)
            self.assertEqual(payload.get("delivery_id"), str(row_id))
            self.assertIn("ts", payload)
            self.assertIn("ts_iso", payload)

            # Consistent data shape
            data = payload.get("data")
            self.assertIsInstance(data, dict)
            self.assertIn("scan_id", data)
            self.assertIn("asset_key", data)
            self.assertIn("finding_summary", data)
            fs = data["finding_summary"]
            self.assertIsInstance(fs, dict)
            self.assertIn("severity", fs)
            self.assertIn("counts", fs)
            self.assertIn("total", fs)

        # Specific checks
        by_type = {et: json.loads(pj) for _, et, _, pj in rows}
        self.assertEqual(by_type["scan.completed"]["data"]["asset_key"], "")
        self.assertEqual(by_type["cert.expired"]["data"]["asset_key"], "example.com:443")
        self.assertEqual(by_type["cert.expired"]["data"]["finding_summary"]["severity"], "critical")

    def test_dedupe_is_stable_on_second_enqueue(self):
        self.events.deliver_events_for_scan(self.scan_id)
        rows1 = self._fetch_webhook_rows()
        n1 = len(rows1)

        # re-run: should not create new rows because webhook_events has UNIQUE(webhook_id, dedupe_key)
        self.events.deliver_events_for_scan(self.scan_id)
        rows2 = self._fetch_webhook_rows()
        self.assertEqual(len(rows2), n1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
