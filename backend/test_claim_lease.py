import os
import sqlite3
import tempfile
import threading
import unittest
import importlib


def _mk_db(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id INTEGER,
                created_at TEXT,
                event_type TEXT,
                dedupe_key TEXT,
                status TEXT,
                http_status INTEGER,
                error_text TEXT,
                attempts INTEGER,
                last_attempt_at TEXT,
                payload_json TEXT,
                next_attempt_at TEXT,
                response_excerpt TEXT,
                claimed_at TEXT DEFAULT '',
                claimed_by TEXT DEFAULT ''
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


class TestClaimLease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()

        # IMPORTANT: set env BEFORE importing db
        os.environ["MORROW_SCANNER_DB"] = self.tmp.name
        _mk_db(self.tmp.name)

        import db as _db
        self.db = importlib.reload(_db)

        # Insert 100 due events
        conn = sqlite3.connect(self.tmp.name)
        try:
            for i in range(100):
                conn.execute(
                    "INSERT INTO webhook_events (webhook_id, created_at, event_type, dedupe_key, status, attempts, payload_json, next_attempt_at, response_excerpt, claimed_at, claimed_by) "
                    "VALUES (1, '2026-01-01T00:00:00Z', 'unit.test', ?, 'queued', 0, '{}', '', '', '', '')",
                    (f"k{i}",),
                )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except Exception:
            pass

    def test_two_workers_do_not_overlap(self):
        claimed_a = []
        claimed_b = []

        def w(worker_id, out):
            rows = self.db.claim_due_webhook_events(limit=60, worker_id=worker_id, lease_seconds=600)
            out.extend([r["id"] for r in rows])

        t1 = threading.Thread(target=w, args=("workerA", claimed_a))
        t2 = threading.Thread(target=w, args=("workerB", claimed_b))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        sa = set(claimed_a)
        sb = set(claimed_b)

        self.assertTrue(len(sa) > 0, "workerA claimed nothing")
        self.assertTrue(len(sb) > 0, "workerB claimed nothing")
        self.assertEqual(len(sa & sb), 0, "overlap detected in claimed ids")

        # Total claimed should be <= 100
        self.assertTrue(len(sa | sb) <= 100)

    def test_stale_processing_requeues(self):
        # Claim 10 rows with a 1-second lease
        rows = self.db.claim_due_webhook_events(limit=10, worker_id="staleWorker", lease_seconds=1)
        self.assertEqual(len(rows), 10)

        ids = [r["id"] for r in rows]

        # Force these rows to look stale
        conn = sqlite3.connect(self.tmp.name)
        try:
            conn.execute(
                "UPDATE webhook_events SET status='processing', claimed_by='staleWorker', claimed_at='2000-01-01T00:00:00Z|stale' "
                f"WHERE id IN ({','.join(['?'] * len(ids))})",
                ids,
            )
            conn.commit()
        finally:
            conn.close()

        # Next claim should requeue and then claim them
        rows2 = self.db.claim_due_webhook_events(limit=10, worker_id="newWorker", lease_seconds=1)
        self.assertEqual(len(rows2), 10)


if __name__ == "__main__":
    unittest.main()
