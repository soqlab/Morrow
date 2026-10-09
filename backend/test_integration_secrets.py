import os
import sqlite3
import tempfile
import unittest
import importlib

from fastapi.testclient import TestClient

# Webhook secrets are written through the Vault backend, which is Fernet encryption on top of
# PostgreSQL (see /integrations/secret-backend: required_env PQC_VAULT_MASTER_KEY + DATABASE_URL).
# There is no SQLite-backed secret store, so without a Postgres URL these cases cannot run at all.
# Skip rather than fail: a suite with permanent red teaches people to ignore it.
_PG_URL = (os.getenv("DATABASE_URL") or "").strip()
_HAS_PG = _PG_URL.startswith("postgres")


@unittest.skipUnless(
    _HAS_PG,
    "Vault-backed secret storage needs DATABASE_URL=postgresql://... "
    "(set it, plus PQC_VAULT_MASTER_KEY, to run these).",
)
class TestIntegrationSecretsHardening(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.db_path = os.path.join(self.tmpdir.name, "pqc_sec_test.db")
        # Remember the previous value so tearDown can restore it; db.get_connection() re-reads this
        # on every call, so leaking it redirects later test modules to a database that is gone.
        self._prev_db_env = os.environ.get("PQC_SCANNER_DB")
        self.addCleanup(self._restore_db_environment)
        os.environ["PQC_SCANNER_DB"] = self.db_path

        # Import fresh modules using this DB path
        import db as db_mod
        importlib.reload(db_mod)
        db_mod.init_db()

        import app as app_mod
        importlib.reload(app_mod)

        self.db = db_mod
        # Startup creates the real vault schema; shutdown drains writers and closes
        # pooled SQLite handles before TemporaryDirectory cleanup on Windows.
        self.client = self.enterContext(TestClient(app_mod.app))

    def _restore_db_environment(self):
        if self._prev_db_env is None:
            os.environ.pop("PQC_SCANNER_DB", None)
        else:
            os.environ["PQC_SCANNER_DB"] = self._prev_db_env

    def _db_webhook_secret(self, webhook_id: int) -> str:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT secret FROM webhooks WHERE id=?", (int(webhook_id),)).fetchone()
        conn.close()
        return str(row[0] or "") if row else ""

    def _db_webhook_credential_id(self, webhook_id: int) -> int:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT credential_id FROM webhooks WHERE id=?", (int(webhook_id),)).fetchone()
        conn.close()
        return int(row[0] or 0) if row else 0

    def test_secret_not_returned_after_save_and_list(self):
        r = self.client.post("/integrations/webhooks", json={
            "name": "acme",
            "url": "http://example.invalid/hook",
            "secret": "s1",
            "events": ["*"],
            "enabled": True
        })
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        wh = body["webhook"]
        self.assertNotIn("secret", wh)
        self.assertTrue(wh.get("has_secret"))
        self.assertEqual(wh.get("secret_masked"), "********")

        r2 = self.client.get("/integrations/webhooks")
        self.assertEqual(r2.status_code, 200, r2.text)
        items = r2.json()
        self.assertTrue(isinstance(items, list))
        self.assertEqual(items[0]["name"], "acme")
        self.assertNotIn("secret", items[0])
        self.assertTrue(items[0].get("has_secret"))

    def test_blank_secret_does_not_wipe_existing_credential_link(self):
        r = self.client.post("/integrations/webhooks", json={
            "name": "acme2",
            "url": "http://example.invalid/hook",
            "secret": "s1",
            "events": ["*"],
            "enabled": True
        })
        wid = int(r.json()["webhook"]["id"])
        cred_id = self._db_webhook_credential_id(wid)
        self.assertGreater(cred_id, 0)
        self.assertEqual(self._db_webhook_secret(wid), "")

        # Update same webhook but do NOT provide secret (blank). Should keep s1.
        r2 = self.client.post("/integrations/webhooks", json={
            "id": wid,
            "name": "acme2",
            "url": "http://example.invalid/hook2",
            "secret": "",
            "events": ["*"],
            "enabled": True
        })
        self.assertEqual(r2.status_code, 200, r2.text)
        self.assertEqual(self._db_webhook_credential_id(wid), cred_id)
        self.assertEqual(self._db_webhook_secret(wid), "")

    def test_rotate_secret_changes_vault_reference_and_does_not_return_secret(self):
        r = self.client.post("/integrations/webhooks", json={
            "name": "acme3",
            "url": "http://example.invalid/hook",
            "secret": "s1",
            "events": ["*"],
            "enabled": True
        })
        wid = int(r.json()["webhook"]["id"])
        self.assertGreater(self._db_webhook_credential_id(wid), 0)
        self.assertEqual(self._db_webhook_secret(wid), "")

        rr = self.client.post(f"/integrations/webhooks/{wid}/rotate-secret", json={"secret": "s2"})
        self.assertEqual(rr.status_code, 200, rr.text)
        out = rr.json()["webhook"]
        self.assertNotIn("secret", out)
        self.assertTrue(out.get("has_secret"))
        self.assertEqual(self._db_webhook_secret(wid), "")

if __name__ == "__main__":
    unittest.main()
