import os
import tempfile
import unittest
from unittest.mock import Mock

from fastapi.testclient import TestClient

# Do NOT set PQC_SCANNER_DB at import time. pytest imports every test module during collection,
# before any test runs, so an import-time write here hijacks the database for the entire session
# and unrelated suites end up reading from this module's throwaway file. Scope it to the test class
# instead and restore it afterwards.
import app as app_module


class TestSprint98ExecutionPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp(prefix="pqc_scanner_test_")
        cls._prev_db = os.environ.get("PQC_SCANNER_DB")
        os.environ["PQC_SCANNER_DB"] = os.path.join(cls._tmpdir, "pqc_scanner_test.db")

    @classmethod
    def tearDownClass(cls):
        if cls._prev_db is None:
            os.environ.pop("PQC_SCANNER_DB", None)
        else:
            os.environ["PQC_SCANNER_DB"] = cls._prev_db
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = TestClient(app_module.app)

    def test_post_scans_uses_durable_async_path(self):
        resp = self.client.post("/scans", json={"targets": ["www.cloudflare.com:443"]})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn("id", body)
        self.assertIn(body["status"], ("queued", "running"))

    def test_post_scan_keeps_legacy_sync_contract(self):
        old_scan_host = app_module.scan_host
        try:
            app_module.scan_host = Mock(return_value={"host": "x", "port": 443, "findings": []})
            resp = self.client.post("/scan", json={"targets": ["x:443"]})
            self.assertEqual(resp.status_code, 200, resp.text)
            body = resp.json()
            self.assertEqual(body["count"], 1)
            self.assertIn("results", body)
            app_module.scan_host.assert_called_once()
        finally:
            app_module.scan_host = old_scan_host

    def test_collection_scan_returns_durable_scan_row(self):
        r1 = self.client.post("/collections", json={"name": "c1", "targets_text": "example.com\n"})
        self.assertEqual(r1.status_code, 200, r1.text)
        cid = int(r1.json()["id"])

        resp = self.client.post(f"/collections/{cid}/scan")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn("id", body)
        self.assertIn(body["status"], ("queued", "running"))


if __name__ == "__main__":
    unittest.main()
